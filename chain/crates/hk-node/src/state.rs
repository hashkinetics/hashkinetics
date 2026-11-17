//! Node-side application state: drives hk_state::State (the verified chain logic)
//! from consensus decisions.
//!
//! 0.7: the chain, mempool, and a receipt log live behind `Arc<Mutex<..>>` so the
//! RPC server (another task) can submit transactions and read state. Blocks now
//! carry a `Batch` (parent app_hash + txs); on commit the parent hash is checked
//! against this node's own `state_commitment()` before apply — divergence halts.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use eyre::{eyre, Result};
use tracing::{debug, error, info, warn};

use malachitebft_app_channel::app::streaming::{StreamContent, StreamId, StreamMessage};
use malachitebft_app_channel::app::types::core::{CommitCertificate, Round, Validity, VoteExtensions};
use malachitebft_app_channel::app::types::sync::RawDecidedValue;
use malachitebft_app_channel::app::types::{LocallyProposedValue, ProposedValue};
use malachitebft_core_types::Height as _;

use hk_consensus::rotation::RotationRules;
use hk_consensus::{
    op_seed, HkAddress, HkContext, HkHeight, HkPriv, HkProposalFin, HkProposalInit, HkProposalPart,
    HkValidatorSet, HkValue, RootSecret, RotationCert, SetChange, SetChangeCert,
};
use hk_state::tx::{SignedTx, Tx};

/// (aggregate proof bytes, expected digest) → valid? Injected by the sp1 verifier.
pub type AggVerifyFn = Arc<dyn Fn(&[u8], &[u8; 32]) -> bool + Send + Sync>;

/// Everything the node's proof layer hands the app: the per-tx verifier (into the state
/// machine) and the batch-aggregate verifier + vk hashes (used at commit, P2.3).
pub struct PoolVerifiers {
    pub pool: Arc<dyn hk_state::pool::ProofVerifier>,
    pub agg: AggVerifyFn,
    pub spend_vk_hash: [u32; 8],
    pub mint_vk_hash: [u32; 8],
}

use crate::batch::{txid, Batch, MAX_TXS_PER_BLOCK};
use crate::genesis::HkGenesis;
use crate::store::{NodeSnapshot, NodeStore, StoredBlock, ValidatorDto, SNAPSHOT_EVERY};

/// HK-R5.2: rolling apply-cost accumulators (ms), logged and reset every 100 blocks —
/// the catch-up bottleneck is MEASURED on every node, not inferred (C-plan §R5.2).
#[derive(Default)]
struct ApplyTimers {
    n: u64,
    pre_ms: u64,   // parallel envelope pre-verification (outside the state lock)
    agg_ms: u64,   // aggregate STARK verify
    apply_ms: u64, // ordered state apply
    hash_ms: u64,  // post-apply state commitment (1× per block since R5.2)
    save_ms: u64,  // block-log persist + fsync
    snap_ms: u64,  // full snapshot + fsync (every snapshot_every() blocks)
}

/// HK-R5.2: snapshot cadence, env-tunable (`HK_SNAPSHOT_EVERY`, default
/// [`SNAPSHOT_EVERY`] = 16). The full-image snapshot + fsync is a growing tax as
/// state grows; a node grinding through catch-up can widen the cadence (the only
/// cost is replaying a few more blocks after a crash). Read once — changing it
/// requires a restart, which is exactly when you'd set it.
fn snapshot_every() -> u64 {
    static V: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("HK_SNAPSHOT_EVERY")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(SNAPSHOT_EVERY)
    })
}

/// C2.8 (v0.16.0): block-log retention in heights (`HK_RETAIN_BLOCKS`, default 0 =
/// keep everything). Voters and the public gateway keep everything — a pruned node
/// serves value-sync only from its first kept height.
pub(crate) fn retain_blocks() -> u64 {
    static V: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *V.get_or_init(|| std::env::var("HK_RETAIN_BLOCKS").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0))
}

// ---------------------------------------------------------------------------------------
// R11 (v0.17.0): what this process costs, published by `hk_chainInfo.process` so the
// "RAM minimum" line in the onboarding doc is a number any operator can check, not a claim.
// ---------------------------------------------------------------------------------------

static PROCESS_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
static VERIFIER_INIT_MS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Called once when `start` begins; `uptime_secs` counts from here.
pub(crate) fn mark_process_start() {
    let _ = PROCESS_START.set(std::time::Instant::now());
}

/// Seconds since `mark_process_start` (None before it — the CLI subcommands never call it).
pub(crate) fn uptime_secs() -> Option<u64> {
    PROCESS_START.get().map(|t| t.elapsed().as_secs())
}

/// How long the verify-only STARK client took to come up, in ms (None until wired).
pub(crate) fn verifier_init_ms() -> Option<u64> {
    VERIFIER_INIT_MS.get().copied()
}

/// Set once by the verifier module when the client is up; a later call cannot overwrite.
#[cfg_attr(not(feature = "sp1-verify"), allow(dead_code))]
pub(crate) fn set_verifier_init_ms(ms: u64) {
    let _ = VERIFIER_INIT_MS.set(ms);
}

/// This process's resident set in bytes — Linux (`/proc/self/statm`, field 2 in pages) and,
/// since v0.19.4, macOS (`proc_pidinfo(PROC_PIDTASKINFO).pti_resident_size` — the first
/// native macOS/arm64 seat reported `null` here); None where the kernel does not say.
/// Cheap enough to read on every `hk_chainInfo`.
pub(crate) fn rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        // SAFETY: sysconf is a plain libc query with no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as i64;
        rss_from_statm(&statm, page)
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: proc_pidinfo writes at most `buffersize` bytes into a zeroed, correctly
        // sized `proc_taskinfo`; a return value shorter than the struct means "no data".
        let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
        let got = unsafe {
            libc::proc_pidinfo(
                std::process::id() as libc::c_int,
                libc::PROC_PIDTASKINFO,
                0,
                &mut info as *mut libc::proc_taskinfo as *mut libc::c_void,
                size,
            )
        };
        (got == size).then_some(info.pti_resident_size)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// Free bytes on the filesystem that holds `path` (what an unprivileged writer may still
/// use: `f_bavail × f_frsize`). v0.19.4, after incident #13 (2026-09-14: the block log
/// filled the disk and consensus halted 54 min) — `hk_chainInfo.process.disk_free_bytes`
/// is the number a watcher pages on. None on non-Unix targets or if statvfs fails.
pub(crate) fn disk_free_bytes(path: &std::path::Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
        // SAFETY: statvfs fills the zeroed struct we hand it and reads only the C string.
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
        (rc == 0).then(|| (st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// `/proc/self/statm` is "size resident shared text lib data dt" in pages.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn rss_from_statm(statm: &str, page_size: i64) -> Option<u64> {
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    (page_size > 0).then(|| pages.saturating_mul(page_size as u64))
}

/// S2 (v0.16.0): how often the search index is written to disk (`HK_INDEX_PERSIST_EVERY`,
/// default 4 × the snapshot cadence). Restart resumes indexing above the persisted
/// height instead of re-reading every block file.
fn index_persist_every() -> u64 {
    static V: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("HK_INDEX_PERSIST_EVERY")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(snapshot_every() * 4)
    })
}

/// S2: the `&'static str` kind names live in `tx_kind`; a persisted index carries
/// them as strings and maps them back here (an unknown name stays "unknown").
fn kind_static(s: &str) -> &'static str {
    const KINDS: [&str; 15] = [
        "transfer", "mandate_create", "mandate_spend", "mandate_revoke", "channel_open",
        "channel_settle", "channel_refund", "shield", "shielded_spend", "account_create",
        "asset_register", "asset_mint", "asset_burn", "asset_freeze", "asset_pause",
    ];
    KINDS.iter().copied().find(|k| *k == s).unwrap_or("unknown")
}
use hk_consensus::HkValidator;

/// Shared handles the RPC server holds (all cheap clones of Arc).
#[derive(Clone)]
pub struct SharedHandles {
    pub chain: Arc<Mutex<hk_state::State>>,
    pub mempool: Arc<Mutex<crate::mempool::Mempool>>,
    pub receipts: Arc<Mutex<ReceiptLog>>,
    /// Every pool commitment in insertion order, WITH its stealth payload — a node-level
    /// INDEX (derivable by anyone replaying the chain; consensus keeps only the frontier).
    /// Wallets read it to rebuild auth paths (`hk_getPoolLeaves`) and to SCAN for notes
    /// addressed to them (`hk_getPoolNotes`). Devnet: in-memory, fresh per run.
    pub pool_notes: Arc<Mutex<Vec<(hk_primitives::H256, Vec<u8>)>>>,
    /// P6: the leaf feeds of the additional per-asset pools (the legacy feed is above).
    pub pool_notes_by_asset: Arc<Mutex<std::collections::BTreeMap<hk_primitives::AssetId, Vec<(hk_primitives::H256, Vec<u8>)>>>>,
    /// P2.3: aggregation bundles submitted via `hk_submitBundle`.
    pub bundles: Arc<Mutex<Vec<(Vec<SignedTx>, Vec<u8>)>>>,
    pub chain_id: String,
    /// Genesis-gate: SHA-256(genesis.json) — the network's identity fingerprint,
    /// surfaced by `hk_chainInfo` so anyone can confirm they're on the real chain.
    pub genesis_digest: [u8; 32],
    /// P3.0/WS-B: the persistence store — RPC admission appends to the mempool WAL;
    /// the explorer endpoints read the block log from it.
    pub store: Option<Arc<NodeStore>>,
    /// P3.0b explorer surface: live validator set (rotations write through this lock).
    pub validators: Arc<Mutex<HkValidatorSet>>,
    /// G1 (v0.18.0): the genesis seats' permanent roots — `hk_getValidators` marks them and
    /// reports the bootstrap re-weight (`genesis::bootstrap_for`) + the quorum arithmetic.
    pub genesis_roots: Vec<Vec<u8>>,
    /// Deterministic chain clock epoch (block time = chain_start_time + height).
    pub chain_start_time: u64,
    /// C2.3: tx-gossip enqueue handle (`None` = gossip off; node.rs wires it when
    /// `hk_rpc.gossip_peers` is non-empty).
    pub gossip: Option<crate::gossip::GossipHandle>,
    /// R2: foreign rotation certs queued by `hk_submitRotation` — an exhausted validator
    /// can't propose its own revival cert, so any peer accepts + carries it.
    pub foreign_rotations: Arc<Mutex<Vec<RotationCert>>>,
    /// L-2 (R17, reported 2026-10-06): the height from which only chain-bound v2 rotation
    /// certificates are accepted (`HkApp::rotation_v2_from`) — `hk_submitRotation` judges a
    /// cert by the same rule commit will, and `hk_chainInfo.activations` publishes it.
    pub rotation_v2_from: u64,
    /// V1: validator-set change certificates queued by `hk_submitSetChange` — they ride
    /// this node's next proposal (re-validated against the live set at propose + commit).
    pub pending_set_changes: Arc<Mutex<Vec<SetChangeCert>>>,
    /// R4: (epoch, remaining-leaves) of this node's live consensus signer.
    pub signer_gauge: Arc<Mutex<(u64, u64)>>,
    /// v0.11.2 search: NODE-LOCAL indexes (never in C(Σ) — anyone rebuilds them by
    /// replaying the chain). txid → (height, index-in-block).
    pub tx_index: Arc<Mutex<std::collections::HashMap<[u8; 32], (u64, u32)>>>,
    /// account → its transactions (as sender OR counterparty), commit order.
    pub acct_index:
        Arc<Mutex<std::collections::HashMap<hk_primitives::AccountId, Vec<([u8; 32], u64, &'static str)>>>>,
    /// N1 (v0.15.2): this node's libp2p peer id (base58) — named in `hk_getPeers.self`.
    /// node.rs fills it after the keypair is derived; empty in tests.
    pub self_peer_id: String,
    /// HR-1 (mr-hrydarie, reported 2026-11-04; v0.19.11): `hk_rpc.accept_bundles` — whether
    /// `hk_submitBundle` is open on this node (rpc.rs `bundles_open`; HK_RPC_ACCEPT_BUNDLES=1
    /// opens it too). node.rs copies it from the config; `handles()` and tests start closed —
    /// there is no aggregator role yet, and the door is closed unless the operator opens it.
    pub accept_bundles: bool,
}

/// Bounded map of txid -> human receipt string ("ok: ..." / "rejected: ...").
pub struct ReceiptLog {
    map: HashMap<[u8; 32], String>,
    order: VecDeque<[u8; 32]>,
    cap: usize,
}

impl ReceiptLog {
    /// `pub(crate)`: `SharedHandles::for_tests` (the HR-1 tests) builds one.
    pub(crate) fn new(cap: usize) -> Self {
        Self { map: HashMap::new(), order: VecDeque::new(), cap }
    }
    fn insert(&mut self, id: [u8; 32], detail: String) {
        if self.map.insert(id, detail).is_none() {
            self.order.push_back(id);
            if self.order.len() > self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }
    pub fn get(&self, id: &[u8; 32]) -> Option<&String> {
        self.map.get(id)
    }
    /// Export in insertion order (P3.0 snapshots).
    pub fn entries(&self) -> Vec<([u8; 32], String)> {
        self.order
            .iter()
            .filter_map(|id| self.map.get(id).map(|d| (*id, d.clone())))
            .collect()
    }
    /// Refill from a snapshot export (keeps the cap discipline).
    pub fn restore(&mut self, entries: Vec<([u8; 32], String)>) {
        for (id, detail) in entries {
            self.insert(id, detail);
        }
    }
}

/// HR-1 (mr-hrydarie, reported 2026-11-04; v0.19.11), E4 — what the commit path does with a
/// block's receipts, split out of `apply_batch_to_chain` as a pure function so the wiring is
/// tested (`hr1_tests`): the receipt-log rows and the three prune sets. One txid per block tx,
/// computed here once — the refused entries and the log rows reuse it.
pub(crate) struct CommitPrune {
    /// EVERY block tx's (sender, nonce) — the bundle retain's input: a ridden bundle leaves the
    /// queue whatever its receipts.
    pub included: Vec<(hk_primitives::AccountId, u64)>,
    /// The APPLIED txs' slots: each consumed its nonce, so every pending tx there is dead —
    /// `Mempool::remove_included`.
    pub applied: Vec<(hk_primitives::AccountId, u64)>,
    /// The REFUSED txs' (slot, txid): each consumed nothing, so only an identical pending copy
    /// is dead — `Mempool::remove_refused`. Before v0.19.11 these slots were pruned like the
    /// applied ones, and a refused bundle tx naming a victim's pending slot evicted the victim's
    /// honest tx on every node (HR-1's eviction axis).
    pub refused: Vec<((hk_primitives::AccountId, u64), [u8; 32])>,
    /// (txid, "ok: N event(s)" / "rejected: <reason>") per block tx, in order — the receipt
    /// log's rows.
    pub log: Vec<([u8; 32], String)>,
}

impl CommitPrune {
    /// The two mempool prunes the commit path runs, in this order: the APPLIED slots, then the
    /// REFUSED (slot, txid) pairs. Returns (pruned by slot, pruned as identical copies).
    pub(crate) fn prune_mempool(&self, mp: &mut crate::mempool::Mempool) -> (usize, usize) {
        (mp.remove_included(&self.applied), mp.remove_refused(&self.refused))
    }
}

/// The most bytes a proposed value may carry: the pubsub frame cap of the fleet's config
/// template (32 MiB); an honest proposal is one frame. It bounds the value of a signed proposal
/// (`admit_signed_value`).
pub(crate) const MAX_PROPOSAL_BYTES: usize = 32 * 1024 * 1024;

/// v0.19.12: at most this many values are kept per (height, round) in the host's store.
/// One is the honest case. More than one exists only when the scheduled proposer signs several
/// proposals for the same round (equivocation): they are kept, so that the engine can follow
/// whichever value the network locks on. A value past the bound is refused
/// (`ValueRefusal::SlotFull`); a value already held under the same id is still answered from
/// the store.
pub(crate) const MAX_VALUES_PER_ROUND: usize = 4;

/// v0.19.12: why `admit_signed_value` does not keep a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValueRefusal {
    /// The proposal's round is `Round::Nil`. The engine refuses such a proposal before it
    /// verifies anything, so this is not expected here.
    RoundNil,
    /// The proposal is for a height this node has already committed: the engine was still
    /// closing that height when it asked. Routine.
    BelowOurHeight,
    /// The proposal is for a height above the host's. The engine hands over proposals of its
    /// own height only (a proposal for a later height waits in its buffer until that height
    /// starts), and the host's height is never behind the engine's, so this is not expected.
    AboveOurHeight,
    /// The value is larger than `MAX_PROPOSAL_BYTES`.
    OverByteCap,
    /// The (height, round) already holds `MAX_VALUES_PER_ROUND` values.
    SlotFull,
    /// The id the proposal carries is not the hash of the bytes it carries. Since v0.19.12
    /// such a proposal already fails verification in the engine
    /// (`HkSigningProvider::verify_signed_proposal`); this is the second line.
    IdMismatch,
}

impl ValueRefusal {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ValueRefusal::RoundNil => "round Nil",
            ValueRefusal::BelowOurHeight => "below our height",
            ValueRefusal::AboveOurHeight => "above our height",
            ValueRefusal::OverByteCap => "over the proposal byte cap",
            ValueRefusal::SlotFull => "too many values for this height and round",
            ValueRefusal::IdMismatch => "value id is not the hash of the bytes",
        }
    }

    /// A proposal that arrives after its height has been committed is routine. Every other
    /// refusal means that something happened which no honest node and no correct engine does.
    pub(crate) fn is_routine(self) -> bool {
        matches!(self, ValueRefusal::BelowOurHeight)
    }
}

/// v0.19.12: decide whether the value of a signed proposal enters the store of
/// undecided values, and return the proposed value the engine is answered with.
///
/// `candidate` is built from a proposal whose signature the engine has ALREADY verified under
/// the key of the proposer the schedule names for (height, round), and whose id the same
/// verification has checked against its bytes. This function trusts the first and repeats the
/// second: the id is recomputed here from the bytes, as the sync path does.
///
/// The store keeps values from verified signed proposals of the current height, at most
/// `MAX_VALUES_PER_ROUND` per round, and answers a value it does not keep with the reason
/// (`ValueRefusal`).
///
/// Every round of the current height is taken: the candidate is signed by that round's
/// scheduled proposer, and a node that is behind in rounds needs the value when it gets
/// there. A value is kept under the round of the proposal that carried it, at most
/// `MAX_VALUES_PER_ROUND` per round. Other heights are not taken: the engine never asks
/// for them.
///
/// Pure: it reads and writes the map it is given and nothing else.
pub(crate) fn admit_signed_value(
    undecided: &mut BTreeMap<(u64, i64), Vec<ProposedValue<HkContext>>>,
    current_height: u64,
    candidate: ProposedValue<HkContext>,
) -> std::result::Result<ProposedValue<HkContext>, ValueRefusal> {
    let ProposedValue { height, round, valid_round, proposer, value, .. } = candidate;

    if round.is_nil() {
        return Err(ValueRefusal::RoundNil);
    }
    let h = height.as_u64();
    if h < current_height {
        return Err(ValueRefusal::BelowOurHeight);
    }
    if h > current_height {
        return Err(ValueRefusal::AboveOurHeight);
    }
    if value.txs.len() > MAX_PROPOSAL_BYTES {
        return Err(ValueRefusal::OverByteCap);
    }

    let key = (h, round.as_i64());

    // Held already under this id: answer from the store. Every stored value's id is the hash
    // of its bytes (built here by `propose_value`, hashed below, or rebuilt by the sync arm),
    // so the stored bytes are the ones this id names.
    if let Some(held) =
        undecided.get(&key).and_then(|vs| vs.iter().find(|v| v.value.id() == value.id()))
    {
        return Ok(ProposedValue {
            height,
            round,
            valid_round,
            proposer,
            value: held.value.clone(),
            validity: Validity::Valid,
        });
    }

    if undecided.get(&key).map_or(0, |vs| vs.len()) >= MAX_VALUES_PER_ROUND {
        return Err(ValueRefusal::SlotFull);
    }

    let rebuilt = HkValue::new(value.txs.clone());
    if rebuilt.id() != value.id() {
        return Err(ValueRefusal::IdMismatch);
    }

    let proposed = ProposedValue {
        height,
        round,
        valid_round,
        proposer,
        value: rebuilt,
        validity: Validity::Valid,
    };
    undecided.entry(key).or_default().push(proposed.clone());
    Ok(proposed)
}

/// The value with this id held under ANY round of the height, as `commit` finds it.
///
/// A value is stored under the round of the proposal that first delivered it. A later
/// re-proposal of the same value is completed inside the engine, from the value it holds for
/// the earlier round, without the host being asked: the value can therefore be held under an
/// earlier round than either round a restream names. Every stored value's id is the hash of
/// its bytes, so any hit carries the right bytes.
pub(crate) fn find_value_in_height(
    undecided: &BTreeMap<(u64, i64), Vec<ProposedValue<HkContext>>>,
    height: u64,
    value_id: hk_consensus::HkValueId,
) -> Option<&ProposedValue<HkContext>> {
    undecided
        .range((height, i64::MIN)..=(height, i64::MAX))
        .flat_map(|(_, vs)| vs.iter())
        .find(|v| v.value.id() == value_id)
}

/// The part stream of one proposal: an Init, the batch, a Fin that carries the value id, and
/// the end of the stream. `proposer` is the address the Init names: this node's own when it
/// proposes, and the signer of the proposal when it restreams one (v0.19.12; for a re-proposal
/// of this node's own the two are the same, they differ when it restreams another seat's
/// proposal).
///
/// A node takes its values from signed proposals (`admit_signed_value`). It sends a stream with
/// each proposal it builds, and one when the engine asks for a restream and the host holds the
/// value, for seats on older releases.
pub(crate) fn proposal_stream(
    value: LocallyProposedValue<HkContext>,
    pol_round: Round,
    proposer: HkAddress,
) -> Vec<StreamMessage<HkProposalPart>> {
    let mut sid = Vec::with_capacity(16);
    sid.extend_from_slice(&value.height.as_u64().to_le_bytes());
    sid.extend_from_slice(&value.round.as_i64().to_le_bytes());
    let stream_id = StreamId::new(Bytes::from(sid));

    let init = HkProposalPart::Init(HkProposalInit {
        height: value.height,
        round: value.round,
        pol_round,
        proposer,
    });
    let batch = HkProposalPart::TxBatch(value.value.txs.clone());
    // The Fin carries the value id only (no consensus-key signature): the engine's
    // SignedProposal over this same id is the authenticator, and a second signer over
    // the one-time-leaf tree would reuse leaves. See docs/MAINNET-KEY-MANAGEMENT.md.
    let fin = HkProposalPart::Fin(HkProposalFin { value_id: value.value.id });

    vec![
        StreamMessage::new(stream_id.clone(), 0, StreamContent::Data(init)),
        StreamMessage::new(stream_id.clone(), 1, StreamContent::Data(batch)),
        StreamMessage::new(stream_id.clone(), 2, StreamContent::Data(fin)),
        StreamMessage::new(stream_id, 3, StreamContent::Fin),
    ]
}

/// HR-1 (E4): split a committed block's receipts — `receipts[i]` is `txs[i]`'s — into a
/// [`CommitPrune`]. Pure: reads the block and its receipts, hashes each tx once.
pub(crate) fn commit_prune_sets(txs: &[SignedTx], receipts: &[hk_state::Receipt]) -> CommitPrune {
    let mut p = CommitPrune {
        included: Vec::with_capacity(txs.len()),
        applied: Vec::new(),
        refused: Vec::new(),
        log: Vec::with_capacity(txs.len()),
    };
    for (tx, r) in txs.iter().zip(receipts.iter()) {
        let id = txid(tx);
        let slot = (tx.sender, tx.nonce);
        let detail = match &r.result {
            Ok(events) => {
                p.applied.push(slot);
                format!("ok: {} event(s)", events.len())
            }
            Err(e) => {
                p.refused.push((slot, id));
                format!("rejected: {e}")
            }
        };
        p.log.push((id, detail));
        p.included.push(slot);
    }
    p
}

/// HR-1 (v0.19.11, review item M3): the handles `rpc::dispatch` takes, for tests — a
/// `SharedHandles` otherwise needs `HkApp::new` (a genesis, a signer, a store). Everything
/// empty or closed: no store, no gossip, one placeholder validator seat, the bundle door shut
/// (the config default), the v2 rotation rule never.
#[cfg(test)]
impl SharedHandles {
    pub(crate) fn for_tests(chain: hk_state::State) -> Self {
        Self {
            chain: Arc::new(Mutex::new(chain)),
            mempool: Arc::new(Mutex::new(crate::mempool::Mempool::new(1_024))),
            receipts: Arc::new(Mutex::new(ReceiptLog::new(16))),
            pool_notes: Default::default(),
            pool_notes_by_asset: Default::default(),
            bundles: Default::default(),
            chain_id: "test".to_string(),
            genesis_digest: [0; 32],
            store: None,
            // one placeholder seat: the set type refuses to be empty, and nothing these
            // tests drive reads it (HkValidator::new stores the bytes and derives an address)
            validators: Arc::new(Mutex::new(HkValidatorSet::new([HkValidator::new(
                vec![0u8; 48],
                hk_consensus::HkPub(vec![0u8; 32]),
                1,
            )]))),
            genesis_roots: Vec::new(),
            chain_start_time: 0,
            gossip: None,
            foreign_rotations: Default::default(),
            rotation_v2_from: u64::MAX,
            pending_set_changes: Default::default(),
            signer_gauge: Arc::new(Mutex::new((0, 0))),
            tx_index: Default::default(),
            acct_index: Default::default(),
            self_peer_id: String::new(),
            accept_bundles: false,
        }
    }
}

pub struct DecidedEntry {
    pub value: HkValue,
    pub certificate: CommitCertificate<HkContext>,
}

/// R10 v2: how many decided heights stay in RAM as a serving cache (`HK_DECIDED_WINDOW`,
/// default [`DECIDED_WINDOW_DEFAULT`], 0 = unbounded). Everything older is served to
/// syncing peers straight from the on-disk block log. Read once per process.
pub const DECIDED_WINDOW_DEFAULT: u64 = 512;
pub fn decided_window() -> u64 {
    static V: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("HK_DECIDED_WINDOW")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DECIDED_WINDOW_DEFAULT)
    })
}

/// R10 v2: the lowest height of the longest CONTIGUOUS run of block files that ends at
/// the highest one on disk (`None` for an empty log). A syncing peer walks heights one
/// by one, so only a gap-free suffix is honestly advertisable as servable history —
/// a node revived by thin teleport (val-0: files from 49,929) must not claim block 1.
pub fn contiguous_suffix_min(heights_ascending: &[u64]) -> Option<u64> {
    let mut it = heights_ascending.iter().rev();
    let mut min = *it.next()?;
    for h in it {
        if *h + 1 == min {
            min = *h;
        } else {
            break;
        }
    }
    Some(min)
}

/// U4: the flat protocol fee activates at this height on staging-1 (a rolling fleet
/// upgrade must complete BEFORE any fee is charged — behavior is byte-identical to
/// v0.11 until then). Override per-network/devnet with `HK_FEE_FROM`; fee size with
/// `HK_FEE_MICRO` (0 disables). Set the real staging activation height at roll time
/// against the VOTER tips (never the RPC edge — the gateway can lag its own voters);
/// this default is deliberately a placeholder that must be overridden via HK_FEE_FROM
/// during the coordinated roll.
/// ⚠ v0.12 HISTORY: v0.12.0/0.12.1 shipped a first R10 (bounded decided window +
/// disk-served value-sync) alongside U4/R9 and it BROKE restore on a live validator
/// (engine started at height 0). v0.12.2 shipped U4 + R9 without it. v0.13.0 ships
/// R10 v2: the engine's start height comes from the CHAIN (snapshot + replay), never
/// from the shape of the block log; disk serves whatever contiguous suffix it holds.
/// v0.13.2 (H10): the placeholder default is gone — a genesis without a fee policy
/// runs fee-free unless BOTH env overrides are set. Kept as documentation of the
/// staging-1 era value; nothing reads it.
#[allow(dead_code)]
pub const FEE_ACTIVATION_HEIGHT_STAGING1: u64 = 110_000;
#[allow(dead_code)]
pub const FEE_MICRO_DEFAULT: u128 = 100;

/// R9: if we issued a rotation cert and our on-chain epoch still hasn't advanced
/// after this long, the cert evidently died in flight — re-arm and issue again
/// (acceptors are epoch-monotone, so a duplicate is refused harmlessly).
const REISSUE_AFTER: std::time::Duration = std::time::Duration::from_secs(600);

/// R18 (reported 2026-10-04): the most PayWord links the `ChannelSettle`s in ONE block
/// this node proposes may make the fleet hash — Σ [`settle_cost`] over them (the bundle
/// of P2.3 included), read against the chain as it stands when the block is built.
/// 2¹⁷ ≈ 0.1 s of SHAKE-256 on a seat, ≈ 8 % of the 1.31 s block interval: two full-width
/// settles under the consensus cap, or 131 of the whitepaper's 1,000-step reference
/// settles. The links are what `verify_settlement` hashes today (`step`, from the tip),
/// NOT the delta consensus caps from `payword_cap_from` — the delta bounds how fast a
/// channel's `step` climbs; a settle at a climbed `step` still costs `step` links until
/// the incremental path lands, and that is the number a block must be bounded by.
///
/// Sized for the FREE case (the same-day review of 2026-10-08): `do_channel_settle` has no
/// payee check, a garbage word under the delta cap passes the door and the gated cap and
/// is hashed `step` links before `BadSettlement` refunds the fee and leaves the nonce
/// alone, and the commit prunes it so the identical bytes re-admit next block — so
/// whatever this budget is, an attacker with a few faucet-funded accounts and fresh 2¹⁶
/// channels can make every honest proposer's block cost it, sustained, for nothing. The
/// first cut's 2²⁰ was ≈ 0.75 s of that per block (57 % of the interval); 2¹⁷ is the
/// number we accept until (b) — a fee burn on `BadSettlement` — is decided.
///
/// `hk_state::MAX_CHANNEL_STEPS` is pinned `≤` this at compile time (below): every
/// consensus-valid settle on a channel opened from the height fits one block, so what
/// the door admits the proposer carries. Client-side only: a block built by another node
/// is judged by consensus alone; this never changes what a block ACCEPTS. Pre-height it
/// is also the only thing that bounds an upgraded proposer's own blocks.
pub const MAX_SETTLE_LINKS_PER_BLOCK: u64 = 1 << 17;

// R18 review (2026-10-08): the invariant the door and the proposer rest on — a settle the
// consensus rule accepts on a post-height channel (`step ≤ max_steps ≤ MAX_CHANNEL_STEPS`)
// always fits an empty block's budget, so admission (`mempool.rs` `channel_settle_cap`)
// can refuse exactly what `select_batch_txs` would never pick and nothing admitted parks.
const _: () = assert!(hk_state::MAX_CHANNEL_STEPS <= MAX_SETTLE_LINKS_PER_BLOCK);

/// R18 review (2026-10-08): THE cost function — the links a `ChannelSettle { id, step }`
/// would make the fleet hash if it rode the NEXT block this chain builds. One function for
/// the proposer's budget ([`select_batch_txs`]) and the mempool's door
/// (`Mempool::channel_settle_cap`), so the two can never disagree on a tx: the door
/// refuses what this answers above [`MAX_SETTLE_LINKS_PER_BLOCK`], the proposer holds what
/// would overflow the running total.
///   * `settle_links` is `Some(step)` — the channel is open and `highest < step ≤ max_steps`
///     — the from-the-tip verifier hashes `step` links;
///   * `None` on a KNOWN channel (refunded, or a stale / over-max step): `do_channel_settle`
///     refuses it in O(1) before a link is hashed, and nothing pending ahead of it in the
///     block can change that (a channel never re-opens, `highest` never falls, `max_steps`
///     never moves) — cost 0, exactly;
///   * `None` on an UNKNOWN channel: its `ChannelOpen` may be pending ahead of it in this
///     very pool, in which case the delta IS `step` — cost `step` before the height; from
///     the height the gated delta cap refuses `step > MAX_SETTLE_DELTA` in O(1) once the
///     open lands (and `UnknownChannel` in O(1) if it never does), so the cost is at most
///     `min(step, MAX_SETTLE_DELTA)`. The height tested is the NEXT block's
///     (`apply_block` sets `height` before the gate), the earliest a pending tx can ride.
pub(crate) fn settle_cost(chain: &hk_state::State, id: &hk_primitives::ChannelId, step: u32) -> u64 {
    match chain.settle_links(id, step) {
        Some(links) => links,
        None if chain.channels.contains_key(id) => 0,
        None if chain.height.saturating_add(1) >= chain.payword_cap_from => u64::from(step).min(hk_state::MAX_SETTLE_DELTA),
        None => u64::from(step),
    }
}

pub struct HkApp {
    pub address: HkAddress,
    /// Live validator set behind a lock: consensus reads/rotates it here, and the RPC
    /// server (P3.0b explorer) reads the same truth. Single writer (the app loop).
    pub validators: Arc<Mutex<HkValidatorSet>>,

    /// THE chain — the verified deterministic state machine, shared with RPC.
    pub chain: Arc<Mutex<hk_state::State>>,
    pub mempool: Arc<Mutex<crate::mempool::Mempool>>,
    pub receipts: Arc<Mutex<ReceiptLog>>,
    /// Pool-note index for wallet path rebuilds + scanning (see SharedHandles docs).
    pub pool_notes: Arc<Mutex<Vec<(hk_primitives::H256, Vec<u8>)>>>,
    /// P6: per-asset pool feeds (see SharedHandles docs).
    pub pool_notes_by_asset: Arc<Mutex<std::collections::BTreeMap<hk_primitives::AssetId, Vec<(hk_primitives::H256, Vec<u8>)>>>>,
    /// P2.3: pending aggregation bundles (proof-less pool txs + ONE aggregate STARK);
    /// the proposer includes a whole bundle per block.
    pub bundles: Arc<Mutex<Vec<(Vec<SignedTx>, Vec<u8>)>>>,
    /// P2.3: aggregate verifier + (spend, mint) vk hashes.
    agg: Option<(AggVerifyFn, [u32; 8], [u32; 8])>,
    chain_id: String,
    /// Genesis-gate: SHA-256(genesis.json). `set_genesis_digest` binds chain_id to it.
    genesis_digest: [u8; 32],
    chain_start_time: u64,
    /// L-2 (R17, reported 2026-10-06): the first height at which rotation certificates
    /// must be signed under the chain-bound v2 domain, with `valid_from_height` enforced
    /// as a freshness window (`hk_consensus::rotation`). A chain-id fact like P6 / R17
    /// (`genesis::rotation_v2_from_for`, set by `set_genesis_digest`), but node-side
    /// rather than on `hk_state::State`: the validator set is not part of Σ and every
    /// site that judges a certificate (propose, commit, replay, `hk_submitRotation`)
    /// lives here. `u64::MAX` (never) until the genesis digest binds the chain id —
    /// restore never touches it, so replay after a restart applies the same rule as the
    /// live commit did.
    rotation_v2_from: u64,

    pub current_height: HkHeight,
    pub current_round: Round,
    pub current_proposer: Option<HkAddress>,

    /// Proposed values not decided yet, by (height, round). Every entry is one this
    /// node built itself, one taken from a proposal whose signature the engine
    /// verified (`admit_signed_value`), or one the sync arm stored after rebuilding
    /// its id from its bytes (a value the network decided; the engine matches it with its
    /// commit certificate).
    undecided: BTreeMap<(u64, i64), Vec<ProposedValue<HkContext>>>,
    /// v0.19.12: values of signed proposals refused so far for a reason that is not routine
    /// (`ValueRefusal::is_routine`); it thins the warn line out.
    values_refused: u64,
    /// R10 v2: a bounded RAM cache of the newest decided heights (`decided_window()`
    /// entries; 0 = unbounded). Value-sync requests below the window are served from
    /// the block log on disk. Restore no longer rehydrates history into this map —
    /// that rehydrate was 5.4 GB per node at 104k heights (2026-09-02 census).
    pub decided: BTreeMap<u64, DecidedEntry>,
    /// R10 v2: lowest height of the gap-free block-file suffix that reaches the tip
    /// (0 = no disk history yet). Restore measures it; a failed block write moves it
    /// past the hole. `earliest_height()` advertises min(RAM window, this) to peers.
    history_min: u64,
    /// S2 (v0.16.0): progress of the background history-index pass — the highest
    /// height it has indexed contiguously from its start; `u64::MAX` once it is done
    /// (then the live path keeps the index current and `tip` is the covered height).
    index_floor: Arc<std::sync::atomic::AtomicU64>,
    /// R9: when we last issued a rotation cert (either path). Not persisted — a
    /// restart deliberately clears it, so a wedged guard re-arms on the next trigger.
    last_issue_time: Option<std::time::Instant>,

    // ---- SCMS operational-key rotation ----
    /// This validator's 32-byte master seed (derives root + every operational tree).
    master_seed: [u8; 32],
    /// Stateless SLH-DSA root that signs our rotation certificates.
    root: RootSecret,
    /// Our root public key (matches our entry in the validator set).
    my_root_pk: Vec<u8>,
    /// G1 (v0.18.0): the permanent roots of the GENESIS seats — the ones the bootstrap
    /// re-weight names at its activation height (`genesis::bootstrap_for`).
    genesis_roots: Vec<Vec<u8>>,
    /// Epoch of our currently-live operational key (0 = genesis key).
    current_epoch: u64,
    /// Highest epoch we've already issued a cert for (avoids re-issuing).
    highest_issued_epoch: u64,
    /// Shared handle to the engine's operational signer — `rotate_to` swaps the live tree.
    op_handle: HkPriv,
    /// Node home dir, for per-epoch persisted signer state files.
    home_dir: PathBuf,
    /// Demo/ops override: if set, ALSO rotate every N committed heights (`HK_ROTATE_EVERY`).
    /// The production trigger is the R1 leaf-budget threshold — always on, no env needed.
    rotate_every: Option<u64>,
    /// R15b (v0.18.2): the block-time FLOOR. With signing at ~0.2 ms (R15) a devnet decides
    /// every ~0.11 s and a WAN fleet would run as fast as its round trips — and every block
    /// carries kilobytes of hash-based commit signatures, a restarting seat must out-run the
    /// chain to rejoin, and slow seats drop out of certificates. So a proposer at ROUND 0
    /// waits until `min_block_interval` has passed since its previous decision before it
    /// builds. Local pacing only (no consensus rule: a paced and an unpaced node agree on
    /// every block); rounds > 0 never wait; the wait is clamped to half the propose timeout
    /// so a misconfigured floor cannot cause round changes. `HK_MIN_BLOCK_INTERVAL_MS`
    /// (default 1000; 0 = unpaced, for benches).
    min_block_interval: std::time::Duration,
    /// When this node last committed a height (R15b pacing reference).
    last_decided_at: std::time::Instant,
    /// Certs we've issued but not yet seen committed (included when we next propose).
    pending_rotations: Vec<RotationCert>,
    /// R2: root-signed certs submitted by OTHER validators via `hk_submitRotation` —
    /// an exhausted validator can't propose its own revival, so peers carry it.
    /// Shared with the RPC server; drained (validated) into every batch we build.
    foreign_rotations: Arc<Mutex<Vec<RotationCert>>>,
    /// V1: set-change certificates submitted via `hk_submitSetChange` (shared with RPC).
    /// Drained (validated) into the batches we build; retired when seen committed.
    pending_set_changes: Arc<Mutex<Vec<SetChangeCert>>>,
    /// R4: (epoch, remaining-leaves) of OUR live signer, refreshed every commit — the RPC
    /// serves it so operators watch the fuse instead of discovering it at zero.
    signer_gauge: Arc<Mutex<(u64, u64)>>,
    /// v0.11.2 search indexes (node-local; see SharedHandles for semantics).
    tx_index: Arc<Mutex<std::collections::HashMap<[u8; 32], (u64, u32)>>>,
    acct_index:
        Arc<Mutex<std::collections::HashMap<hk_primitives::AccountId, Vec<([u8; 32], u64, &'static str)>>>>,
    /// P3.0/WS-B: durable store (block log + snapshots + mempool WAL). `None` = the
    /// old in-memory devnet behavior (`HK_NO_PERSIST=1`, and unit tests).
    store: Option<Arc<NodeStore>>,
    /// HK-R6: shared (with HkContext) history of `(effective_from_height, set)` —
    /// the engine verifies commit certificates against the set as of their height.
    set_history: hk_consensus::SetHistory,
    /// HK-R5.2: cached post-apply state commitment. The next block's parent-hash
    /// check reads this instead of re-walking the ENTIRE state (every account,
    /// every nullifier ever) a second time. Taken (not copied) per block: any
    /// error path leaves `None` and the next check recomputes honestly.
    last_app_hash: Option<[u8; 32]>,
    /// HK-R5.2: apply-cost window (see [`ApplyTimers`]).
    timers: ApplyTimers,
}

impl HkApp {
    pub fn new(
        address: HkAddress,
        genesis: &HkGenesis,
        master_seed: [u8; 32],
        op_handle: HkPriv,
        home_dir: PathBuf,
        set_history: hk_consensus::SetHistory,
        verifiers: Option<PoolVerifiers>,
    ) -> Result<Self> {
        let validators = genesis.validator_set()?;
        let genesis_roots: Vec<Vec<u8>> = genesis.validators.iter().map(|v| v.root_pk.clone()).collect();
        // HK-R6: seed the shared set history — the genesis set verifies from height 1.
        // (restore_from_store reseeds at the snapshot; rotations append as they commit.)
        {
            let mut hist = set_history.lock().unwrap_or_else(|e| e.into_inner());
            hist.clear();
            hist.push((1, validators.clone()));
        }
        let mut chain = hk_state::State::from_genesis(&genesis.chain_genesis())
            .map_err(|e| eyre!("chain genesis: {e}"))?;
        // U4: the fee policy. U4.b: a genesis that pins one is AUTHORITATIVE (from_genesis
        // already applied it; env overrides are refused loudly — a node must not be able
        // to talk itself onto a fork). Otherwise it is config, never snapshotted — same
        // posture as the verifier: identical fleet-wide by default, devnets override via env.
        let env_micro = std::env::var("HK_FEE_MICRO").ok().and_then(|s| s.parse::<u128>().ok());
        let env_from = std::env::var("HK_FEE_FROM").ok().and_then(|s| s.parse::<u64>().ok());
        match genesis.fee() {
            Some(f) => {
                if env_micro.is_some() || env_from.is_some() {
                    warn!(
                        genesis_micro = %f.micro,
                        genesis_from = f.from_height,
                        "HK_FEE_MICRO/HK_FEE_FROM ignored — the fee policy is bound to this genesis"
                    );
                }
                info!(micro = %f.micro, from_height = f.from_height, "fee policy is genesis-bound (U4.b)");
            }
            None => {
                // H10 (v0.13.2): a genesis that carries no fee policy gets NO fee unless the
                // operator says so explicitly — the old placeholder height (110,000) could
                // have armed a fee on a public network nobody had coordinated.
                match (env_micro, env_from) {
                    (Some(m), Some(f)) => {
                        chain.fee_micro = m;
                        chain.fee_from = f;
                        warn!(micro = %m, from_height = f, "fee policy from HK_FEE_MICRO/HK_FEE_FROM (genesis carries none) — every validator must run the same values");
                    }
                    (None, None) => {
                        chain.fee_micro = 0;
                        chain.fee_from = u64::MAX;
                        warn!("genesis carries no fee policy and HK_FEE_MICRO/HK_FEE_FROM are unset — running FEE-FREE (bind a policy into the genesis for any public network)");
                    }
                    _ => {
                        eyre::bail!("HK_FEE_MICRO and HK_FEE_FROM must be set together when the genesis carries no fee policy");
                    }
                }
            }
        }
        // WS2: inject the real STARK verifier. None ⇒ hk-state's RejectAll default stays —
        // this node refuses shielded traffic rather than trusting anything.
        let agg = verifiers.as_ref().map(|v| (v.agg.clone(), v.spend_vk_hash, v.mint_vk_hash));
        if let Some(v) = verifiers {
            chain.verifier = v.pool;
        }
        let root = RootSecret::from_seed(&master_seed);
        let my_root_pk = root.public_bytes().to_vec();
        let rotate_every = std::env::var("HK_ROTATE_EVERY")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n > 0);
        let signer_gauge = Arc::new(Mutex::new((0u64, op_handle.remaining())));
        let min_block_interval = std::time::Duration::from_millis(
            std::env::var("HK_MIN_BLOCK_INTERVAL_MS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(1000),
        );
        info!(
            min_block_interval_ms = min_block_interval.as_millis() as u64,
            "R15b block-time floor (proposer pacing at round 0; HK_MIN_BLOCK_INTERVAL_MS)"
        );
        Ok(Self {
            address,
            validators: Arc::new(Mutex::new(validators)),
            chain: Arc::new(Mutex::new(chain)),
            mempool: Arc::new(Mutex::new(crate::mempool::Mempool::default())),
            receipts: Arc::new(Mutex::new(ReceiptLog::new(4096))),
            pool_notes: Arc::new(Mutex::new(Vec::new())),
            pool_notes_by_asset: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            bundles: Arc::new(Mutex::new(Vec::new())),
            agg,
            chain_id: "hashkinetics-devnet-1".to_string(),
            genesis_digest: [0u8; 32],
            chain_start_time: genesis.chain_start_time,
            rotation_v2_from: u64::MAX, // L-2: never, until set_genesis_digest names the chain
            current_height: HkHeight::INITIAL,
            current_round: Round::Nil,
            current_proposer: None,
            undecided: BTreeMap::new(),
            values_refused: 0,
            decided: BTreeMap::new(),
            history_min: 0,
            index_floor: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
            last_issue_time: None,
            master_seed,
            root,
            my_root_pk,
            genesis_roots,
            current_epoch: 0,
            highest_issued_epoch: 0,
            op_handle,
            home_dir,
            rotate_every,
            min_block_interval,
            last_decided_at: std::time::Instant::now(),
            pending_rotations: Vec::new(),
            tx_index: Arc::new(Mutex::new(std::collections::HashMap::new())),
            acct_index: Arc::new(Mutex::new(std::collections::HashMap::new())),
            foreign_rotations: Arc::new(Mutex::new(Vec::new())),
            pending_set_changes: Arc::new(Mutex::new(Vec::new())),
            signer_gauge,
            store: None,
            set_history,
            last_app_hash: None,
            timers: ApplyTimers::default(),
        })
    }

    /// P3.0/WS-B: attach the durable store (call after `restore_from_store`).
    pub fn attach_store(&mut self, store: Arc<NodeStore>) {
        self.store = Some(store);
    }

    /// Genesis-gate: bind this node's identity to its genesis. Stores the digest
    /// (SHA-256 of genesis.json) and derives the human `chain_id` from its first 4
    /// bytes, so a node on a DIFFERENT genesis reports a different chain_id and is
    /// visibly not the canonical chain. Call once at boot (node.rs), before RPC
    /// handles are cloned. The digest also drives the libp2p peer gate.
    pub fn set_genesis_digest(&mut self, digest: [u8; 32]) {
        self.genesis_digest = digest;
        self.chain_id = format!("hashkinetics-1-{}", hex::encode(&digest[..4]));
        // P6: the multi-pool activation is a chain-id fact (config, never snapshotted).
        let from = crate::genesis::multi_pool_from_for(&self.chain_id);
        self.chain.lock().unwrap().multi_pool_from = from;
        info!(chain_id = %self.chain_id, multi_pool_from = from, "P6 multi-asset pool activation");
        // R17: the asset-bound-mandate activation, the same way (chain-id fact, config).
        let r17 = crate::genesis::mandate_asset_from_for(&self.chain_id);
        self.chain.lock().unwrap().mandate_asset_from = r17;
        info!(chain_id = %self.chain_id, mandate_asset_from = r17, "R17 asset-bound mandate activation");
        // R18: the PayWord settlement caps, the same way (chain-id fact, config). Only the
        // CONSENSUS refusal waits for it — the mempool's mirror and `build_batch`'s link
        // budget are not gated.
        let r18 = crate::genesis::payword_cap_from_for(&self.chain_id);
        self.chain.lock().unwrap().payword_cap_from = r18;
        info!(chain_id = %self.chain_id, payword_cap_from = r18, "R18 PayWord settlement-cap activation");
        // L-2: the rotation-v2 (chain-bound certificate) activation — its OWN height, never
        // R17's: the trigger here is the fleet's rotation cadence, so it is named only once
        // every seat is on the release (genesis.rs). Node-side, before restore (node.rs
        // calls this first), so replay judges every certificate by the same rule.
        self.rotation_v2_from = crate::genesis::rotation_v2_from_for(&self.chain_id);
        info!(
            chain_id = %self.chain_id,
            rotation_v2_from = self.rotation_v2_from,
            never = self.rotation_v2_from == u64::MAX,
            "L-2 chain-bound rotation certificate (v2) activation"
        );
    }

    /// L-2: the rotation rule at `height` — the commit height of the block whose
    /// certificates are being judged (the proposal height at propose; `tip + 1` at the RPC).
    fn rotation_rules(&self, height: u64) -> RotationRules<'_> {
        RotationRules::new(height, &self.chain_id, self.rotation_v2_from)
    }

    /// Clonable handles for the RPC server (call before moving self into the loop).
    pub fn handles(&self) -> SharedHandles {
        SharedHandles {
            chain: self.chain.clone(),
            mempool: self.mempool.clone(),
            receipts: self.receipts.clone(),
            pool_notes: self.pool_notes.clone(),
            pool_notes_by_asset: self.pool_notes_by_asset.clone(),
            bundles: self.bundles.clone(),
            chain_id: self.chain_id.clone(),
            genesis_digest: self.genesis_digest,
            store: self.store.clone(),
            validators: self.validators.clone(),
            genesis_roots: self.genesis_roots.clone(),
            chain_start_time: self.chain_start_time,
            gossip: None,
            foreign_rotations: self.foreign_rotations.clone(),
            rotation_v2_from: self.rotation_v2_from,
            pending_set_changes: self.pending_set_changes.clone(),
            signer_gauge: self.signer_gauge.clone(),
            tx_index: self.tx_index.clone(),
            acct_index: self.acct_index.clone(),
            self_peer_id: String::new(),
            accept_bundles: false,
        }
    }

    /// v0.11.2: record a block's transactions into the node-local search indexes.
    /// Idempotent per txid (replay/rehydrate both call it — reinserts are skipped),
    /// so an account's history never double-counts.
    fn index_txs(&self, height: u64, txs: &[SignedTx]) {
        index_txs_into(&self.tx_index, &self.acct_index, height, txs);
    }

    /// Owned snapshot of the current validator set (engine replies + RPC share it).
    pub fn validator_set(&self) -> HkValidatorSet {
        self.validators.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// R1.b: tick-based rotation-threshold check. The commit-path check (R1) is
    /// blind exactly when it matters most — a node that isn't committing
    /// (parked, wedged below tip, minority partition) never evaluates its leaf
    /// budget, and val-0 burned a fresh 32,768-leaf tree to ZERO overnight with
    /// R1 armed (2026-08-29). Every 60 s: read the live gauge; when the budget
    /// crosses the R1 threshold and the next epoch isn't already in flight,
    /// issue the root-signed cert OURSELVES and hand it to (a) our own foreign
    /// queue (drained into the next batch we build, if any) and (b) every
    /// gossip peer via `hk_submitRotation` — the R2 revival path, self-served:
    /// no commit, no human, no exhaustion. Pairs with R8 (abstain-while-behind),
    /// which preserves the leaves this tick then rotates while they still exist.
    /// Duplicate issuance vs. the commit path is harmless by construction:
    /// every acceptor is epoch-monotone (same-epoch re-submissions are refused).
    pub fn spawn_rotation_tick(&self, peers: Vec<String>) {
        // Only validators rotate: an observer's root isn't in the set, and
        // peers would (correctly) refuse its certs.
        let in_set = {
            let set = self.validators.lock().unwrap_or_else(|e| e.into_inner());
            set.validators.iter().any(|v| v.root_pk == self.my_root_pk)
        };
        if !in_set {
            info!("R1.b rotation tick not started — this node's root is not in the validator set (observer)");
            return;
        }
        let gauge = self.signer_gauge.clone();
        let foreign = self.foreign_rotations.clone();
        let my_root_pk = self.my_root_pk.clone();
        let master_seed = self.master_seed;
        let mut highest_issued = self.highest_issued_epoch;
        // L-2: the tick issues like the commit path — `valid_from_height = tip + 1` under
        // the domain the chain demands there (v0.19.4 wrote 0 here; v2 reads the field).
        let chain = self.chain.clone();
        let chain_id = self.chain_id.clone();
        let v2_from = self.rotation_v2_from;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // First tick fires immediately; skip it so a freshly-booted node
            // reads a settled gauge.
            tick.tick().await;
            let mut last_issue: Option<std::time::Instant> = None;
            loop {
                tick.tick().await;
                let (epoch, remaining) =
                    *gauge.lock().unwrap_or_else(|e| e.into_inner());
                let capacity = hk_crypto::hashsig::CONSENSUS_CAPACITY;
                if highest_issued < epoch {
                    // Rotations have applied since we last looked.
                    highest_issued = epoch;
                }
                let next_epoch = epoch + 1;
                let mine_pending = {
                    let q = foreign.lock().unwrap_or_else(|e| e.into_inner());
                    q.iter().any(|c| c.root_pk == my_root_pk && c.epoch >= next_epoch)
                };
                // R9: same staleness re-arm as the commit path — a pushed cert that
                // never applies must not gate this loop forever.
                let issue_stale =
                    last_issue.map(|t| t.elapsed() >= REISSUE_AFTER).unwrap_or(true);
                // height=0 + rotate_every=None ⇒ only the leaf-budget threshold
                // clause of the SAME production trigger can fire here.
                let (due, _) = rotation_due(
                    remaining,
                    rotation_threshold(capacity, &my_root_pk),
                    0,
                    None,
                    mine_pending,
                    next_epoch,
                    highest_issued,
                    issue_stale,
                );
                if !due {
                    continue;
                }
                warn!(
                    remaining,
                    epoch,
                    next_epoch,
                    "R1.b tick: leaf budget under threshold and no commit is carrying the trigger — issuing rotation cert out-of-band"
                );
                let root = RootSecret::from_seed(&master_seed);
                let seed = op_seed(&master_seed, next_epoch);
                let new_op_pk = HkPriv::from_seed(seed).public();
                // This node's tip: a parked seat names a height the network is past, which
                // the window allows for ROTATION_FRESHNESS_HORIZON blocks (≈ 1.5 days) —
                // and R9 re-issues at a fresher tip if the cert never lands.
                let tip = chain.lock().unwrap_or_else(|e| e.into_inner()).height;
                let cert = RotationCert::issue_for(&root, &chain_id, v2_from, new_op_pk, next_epoch, tip + 1);
                highest_issued = highest_issued.max(next_epoch);
                last_issue = Some(std::time::Instant::now());
                {
                    // Self-enqueue; a re-issue REPLACES any same-or-older own cert
                    // (R9: the old entry is what wedged us — never stack beside it).
                    let mut q = foreign.lock().unwrap_or_else(|e| e.into_inner());
                    q.retain(|x| !(x.root_pk == cert.root_pk && x.epoch <= cert.epoch));
                    q.push(cert.clone());
                }
                let body = serde_json::json!({
                    "method": "hk_submitRotation",
                    "params": { "cert": cert }
                })
                .to_string();
                for p in &peers {
                    if let Err(e) = crate::gossip::post(p, &body).await {
                        warn!(peer = %p, %e, "R1.b cert push failed (best-effort; cert stays queued locally)");
                    } else {
                        info!(peer = %p, epoch = next_epoch, "R1.b: rotation cert pushed to peer");
                    }
                }
            }
        });
    }

    /// R10 v2: the engine resumes at the CHAIN's next height — snapshot + replay decide
    /// it, never the block log's shape. (v0.12.0 derived this from disk and a validator
    /// restarted at height 0.) Genesis: chain height 0 → INITIAL.
    pub fn start_height(&self) -> HkHeight {
        HkHeight::new(self.chain.lock().unwrap_or_else(|e| e.into_inner()).height + 1)
    }

    /// R10 v2: the lowest height this node can serve to a syncing peer WITHOUT a gap up
    /// to its tip — the RAM window and the disk suffix both end at the tip, so the
    /// answer is the lower of their starts. Advertised in sync Status; an honest floor
    /// keeps peers from asking us for heights we'd answer with nothing.
    pub fn earliest_height(&self) -> HkHeight {
        let ram_min = self.decided.keys().next().copied();
        let disk_min = (self.history_min > 0).then_some(self.history_min);
        match (ram_min, disk_min) {
            (Some(a), Some(b)) => HkHeight::new(a.min(b)),
            (Some(a), None) | (None, Some(a)) => HkHeight::new(a),
            (None, None) => HkHeight::INITIAL,
        }
    }

    /// R10 v2: a decided value for value-sync — RAM window first, then the block log.
    /// A disk block is re-checked against its certificate before it is served (the
    /// value id is the content hash), so a corrupt file is refused, never propagated.
    pub fn decided_value(&self, height: u64) -> Option<RawDecidedValue<HkContext>> {
        use malachitebft_codec::Codec as _;
        if let Some(entry) = self.decided.get(&height) {
            return Some(RawDecidedValue {
                certificate: entry.certificate.clone(),
                value_bytes: crate::codec::HkCodec.encode(&entry.value).unwrap_or_default(),
            });
        }
        let store = self.store.as_ref()?;
        let sb = match store.load_block(height) {
            Ok(Some(sb)) => sb,
            Ok(None) => return None,
            Err(e) => {
                error!(%e, height, "block file unreadable — not serving it");
                return None;
            }
        };
        let value = HkValue::new(Bytes::from(sb.value_bytes));
        if certificate_value_mismatch(&sb.certificate, &value) {
            error!(height, "block file certificate != content hash — refusing to serve corrupt history");
            return None;
        }
        Some(RawDecidedValue {
            certificate: sb.certificate.into(),
            value_bytes: crate::codec::HkCodec.encode(&value).unwrap_or_default(),
        })
    }

    // ---- proposing ----

    /// Build the block payload: parent app_hash (this node's current commitment) +
    /// up to N transactions PEEKED (not removed) from the mempool. Txs are removed
    /// only on successful commit, so a round change never drops them. R18: the
    /// `ChannelSettle`s among them are bounded by [`MAX_SETTLE_LINKS_PER_BLOCK`]
    /// (`select_batch_txs`) — client-side, this node's own proposals only — and the
    /// P2.3 bundle, which rides ahead of the pool, is costed into the same budget
    /// (R18 review, 2026-10-08: `hk_submitBundle` now admits only proof-less pool txs,
    /// so the seed is 0 in practice; counting it here is belt and braces so that NO path
    /// into a block this node builds is uncosted). v0.19.12: the block's transaction
    /// bytes are budgeted the same way — the bundle's first, then the pool's
    /// (`select_batch_txs_sized`) — under `crate::batch::MAX_BATCH_TX_BYTES`, so the batch
    /// fits the one pubsub frame the signed proposal travels in.
    fn build_batch(&self, height: u64) -> Bytes {
        let parent_app_hash = self.chain.lock().unwrap().state_commitment().0;
        // P2.3: a pending aggregation bundle rides whole (proof-less txs + ONE aggregate).
        // Its txs' encoded bytes open the block's byte budget. A head bundle larger than
        // the whole budget can never ride — the bundle door refuses one
        // (`rpc::bundle_shape_verdict`) — and one found here anyway is dropped from the queue
        // with a warning rather than left at its head.
        let (mut txs, agg_proof, bundle_bytes) = {
            let mut bundles = self.bundles.lock().unwrap();
            let head = bundles.first().map(|(btxs, _)| {
                let bytes = btxs.iter().map(crate::mempool::tx_encoded_len).fold(0usize, usize::saturating_add);
                (btxs.len(), bytes)
            });
            match head {
                Some((n, bytes)) if n <= MAX_TXS_PER_BLOCK && bytes <= crate::batch::MAX_BATCH_TX_BYTES => {
                    let (btxs, aggp) = &bundles[0];
                    (btxs.clone(), aggp.clone(), bytes)
                }
                Some((n, bytes)) if bytes > crate::batch::MAX_BATCH_TX_BYTES => {
                    warn!(
                        height,
                        txs = n,
                        bytes,
                        budget_bytes = crate::batch::MAX_BATCH_TX_BYTES,
                        "the head bundle's txs exceed a block's byte budget — dropped from the queue, no block could carry it"
                    );
                    bundles.remove(0);
                    (Vec::new(), Vec::new(), 0)
                }
                _ => (Vec::new(), Vec::new(), 0),
            }
        };
        let room = MAX_TXS_PER_BLOCK - txs.len();
        {
            // R18: the per-block settle-link budget needs the chain's channel state.
            // Lock order: chain BEFORE mempool (the commit path's order; mempool.rs).
            let chain = self.chain.lock().unwrap();
            let bundle_links: u64 = txs
                .iter()
                .filter_map(|t| match &t.payload {
                    Tx::ChannelSettle { id, step, .. } => Some(settle_cost(&chain, id, *step)),
                    _ => None,
                })
                .fold(0u64, u64::saturating_add);
            if bundle_links > 0 {
                warn!(height, bundle_links, "R18: the pending bundle carries ChannelSettles — costed into this block's settle-link budget");
            }
            let mut mp = self.mempool.lock().unwrap();
            let pick = select_batch_txs_sized(&chain, mp.iter(), room, bundle_links, bundle_bytes);
            if pick.held > 0 {
                info!(
                    height,
                    held = pick.held,
                    budget_links = MAX_SETTLE_LINKS_PER_BLOCK,
                    "R18: txs left in the mempool for a later block — this block's settle-link budget is full"
                );
            }
            // The byte budget ended the selection; the rest waits, in order.
            if pick.byte_budget_full {
                info!(
                    height,
                    bytes = bundle_bytes.saturating_add(pick.bytes),
                    budget_bytes = crate::batch::MAX_BATCH_TX_BYTES,
                    "txs left in the mempool for a later block — this block's byte budget is full"
                );
            }
            // A pending tx no block can carry is dropped, not offered again every turn.
            if !pick.oversize.is_empty() {
                let dropped = mp.remove_included(&pick.oversize);
                warn!(
                    height,
                    dropped,
                    budget_bytes = crate::batch::MAX_BATCH_TX_BYTES,
                    "pending txs larger than a whole block's byte budget dropped from the mempool — no block could carry them"
                );
            }
            txs.extend(pick.picked);
        }
        // Include any rotation certs we've issued but not yet seen committed — PLUS
        // foreign certs peers submitted via `hk_submitRotation` (R2: an exhausted
        // validator can't propose its own revival; we carry it). Foreign certs are
        // re-validated against the CURRENT set here (they were checked at submit time,
        // but the set may have advanced) and — L-2 — against the rotation rule at THIS
        // height (domain, freshness window); stale ones are dropped in place. Our own
        // pending certs ride as issued: one that straddled the v2 boundary is refused at
        // commit, logged, and replaced by the R9 re-issue 600 s later.
        let mut rotations = self.pending_rotations.clone();
        {
            let validators = self.validators.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let rules = self.rotation_rules(height);
            let mut foreign = self.foreign_rotations.lock().unwrap();
            foreign.retain(|c| validators.apply_rotation(c, &rules).is_ok());
            for cert in foreign.iter() {
                if !rotations
                    .iter()
                    .any(|r| r.root_pk == cert.root_pk && r.epoch >= cert.epoch)
                {
                    rotations.push(cert.clone());
                }
            }
        }
        // V1: queued validator-set changes ride this proposal if they are valid against the
        // CURRENT set at THIS height (window + supermajority + not already applied). A cert
        // whose window has not opened stays queued; one that is stale, already applied or
        // no longer approved by a supermajority of the current seats is dropped in place.
        let set_changes = {
            let validators = self.validators.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let mut queue = self.pending_set_changes.lock().unwrap_or_else(|e| e.into_inner());
            let mut include = Vec::new();
            queue.retain(|cert| {
                if cert.body.not_before > height {
                    return true; // not yet — keep
                }
                match hk_consensus::apply_set_change(&validators, cert, height, &self.chain_id) {
                    Ok(Some(_)) => {
                        include.push(cert.clone());
                        true // keep until we SEE it committed (a lost round must not lose it)
                    }
                    Ok(None) => false, // already applied
                    Err(e) => {
                        warn!(%e, "dropping queued set change");
                        false
                    }
                }
            });
            include
        };
        Bytes::from(Batch { parent_app_hash, txs, rotations, agg_proof, set_changes }.encode())
    }

    pub fn previously_built(
        &self,
        height: HkHeight,
        round: Round,
    ) -> Option<LocallyProposedValue<HkContext>> {
        let key = (height.as_u64(), round.as_i64());
        self.undecided.get(&key).and_then(|vs| {
            vs.iter()
                .find(|v| v.proposer == self.address)
                .map(|v| LocallyProposedValue { height: v.height, round: v.round, value: v.value.clone() })
        })
    }

    pub fn propose_value(&mut self, height: HkHeight, round: Round) -> LocallyProposedValue<HkContext> {
        let value = HkValue::new(self.build_batch(height.as_u64()));
        let proposed = ProposedValue {
            height,
            round,
            valid_round: Round::Nil,
            proposer: self.address,
            value: value.clone(),
            validity: Validity::Valid,
        };
        self.store_undecided(proposed);
        LocallyProposedValue { height, round, value }
    }

    pub fn store_undecided(&mut self, v: ProposedValue<HkContext>) {
        let key = (v.height.as_u64(), v.round.as_i64());
        let entry = self.undecided.entry(key).or_default();
        if !entry.iter().any(|e| e.value.id() == v.value.id() && e.proposer == v.proposer) {
            entry.push(v);
        }
    }

    pub fn undecided_at(&self, height: HkHeight, round: Round) -> Vec<ProposedValue<HkContext>> {
        self.undecided.get(&(height.as_u64(), round.as_i64())).cloned().unwrap_or_default()
    }

    /// v0.19.12: the value with this id held under any round of the height (see
    /// `find_value_in_height`). The restream arm of `app.rs` uses it.
    pub fn find_undecided_in_height(
        &self,
        height: HkHeight,
        value_id: hk_consensus::HkValueId,
    ) -> Option<ProposedValue<HkContext>> {
        find_value_in_height(&self.undecided, height.as_u64(), value_id).cloned()
    }

    pub fn stream_proposal(
        &self,
        value: LocallyProposedValue<HkContext>,
        pol_round: Round,
    ) -> Vec<StreamMessage<HkProposalPart>> {
        proposal_stream(value, pol_round, self.address)
    }

    // ---- receiving ----

    /// v0.19.12: the value of a proposal whose signature the engine has verified under
    /// the scheduled proposer's key. Returns the proposed value the engine is answered
    /// with, or `None` when the value is not kept (`admit_signed_value` holds the rules
    /// and the reasons). While a height is open this is the door for a value that is not
    /// decided yet; the sync arm of `app.rs` is the other door, for a value the network
    /// has already decided.
    pub fn received_verified_proposal(
        &mut self,
        height: HkHeight,
        round: Round,
        valid_round: Round,
        proposer: HkAddress,
        value: HkValue,
    ) -> Option<ProposedValue<HkContext>> {
        let candidate =
            ProposedValue { height, round, valid_round, proposer, value, validity: Validity::Valid };
        match admit_signed_value(&mut self.undecided, self.current_height.as_u64(), candidate) {
            Ok(proposed) => Some(proposed),
            Err(why) if why.is_routine() => {
                debug!(%height, %round, %proposer, why = why.as_str(), "value of a signed proposal not kept");
                None
            }
            Err(why) => {
                // Say it once, then every hundredth time, so the log stays readable however
                // often the same refused proposal arrives.
                let n = self.values_refused;
                self.values_refused = n.saturating_add(1);
                if n % 100 == 0 {
                    warn!(%height, %round, %proposer, why = why.as_str(), refused_so_far = n + 1, "value of a signed proposal REFUSED");
                }
                None
            }
        }
    }

    // ---- committing ----

    /// Apply one decided batch to the chain + node indexes. Shared by the LIVE path
    /// (`commit`, `live_agg = true`: the aggregate STARK is verified here, once) and
    /// the RESTART path (`restore_from_store`, `live_agg = false`: the store's
    /// recorded verdict is installed instead — the commit certificate pins the batch
    /// bytes, the parent-hash chain pins the outcome, and a block whose aggregate
    /// was invalid live must reject the same txs on replay). Returns the aggregate
    /// verdict (true = coverage installed) for the block log.
    fn apply_batch_to_chain(
        &mut self,
        height: u64,
        batch: &Option<Batch>,
        live_agg: bool,
        recorded_agg_valid: bool,
    ) -> Result<bool> {
        let time = self.chain_start_time + height;
        let mut agg_valid = false;

        // HK-R5.2: the pure part of envelope verification (signing digest + Lamport)
        // runs in PARALLEL on the verification pool, OUTSIDE the state lock, before
        // ordered apply. For the load-test-era fat blocks this is the bulk of the
        // per-block CPU; the state-dependent checks stay ordered inside apply.
        let txs: Vec<SignedTx> = batch.as_ref().map(|b| b.txs.clone()).unwrap_or_default();
        let t_pre = std::time::Instant::now();
        let sig_verdicts: Vec<bool> =
            hk_consensus::par::par_bools(&txs, hk_state::State::verify_envelope);
        let pre_ms = t_pre.elapsed().as_millis() as u64;

        // HK-R5.2: cached post-apply commitment of the PREVIOUS block == our current
        // commitment (nothing else mutates the chain between commits). Taken, not
        // copied: every error path below leaves it `None` → honest recompute next time.
        let cached_hash = self.last_app_hash.take();

        let mut agg_ms = 0u64;
        let mut apply_ms = 0u64;
        let mut hash_ms = 0u64;
        let post_hash;
        {
            let mut chain = self.chain.lock().unwrap();

            // Consensus-fatal divergence check (0.7): the block's parent hash MUST
            // equal our own current state commitment, or our state has diverged.
            // On replay this is the integrity chain: snapshot → each block → tip.
            if let Some(b) = &batch {
                let ours = match cached_hash {
                    Some(h) => h,
                    None => chain.state_commitment().0,
                };
                if b.parent_app_hash != ours {
                    return Err(eyre!(
                        "app_hash divergence at height {height}: block parent {} != ours {}",
                        hex::encode(&b.parent_app_hash[..8]),
                        hex::encode(&ours[..8])
                    ));
                }
            }

            // P2.3: batch-level aggregation. Derive the chain-expected publics of every
            // PROOF-LESS pool tx (in order); live: verify ONE aggregate STARK over them
            // and install coverage; replay: install the recorded verdict's coverage.
            // Invalid/absent aggregate ⇒ empty coverage ⇒ those txs are rejected by the
            // state machine (deterministic on every validator).
            let t_agg = std::time::Instant::now();
            if let Some(b) = &batch {
                if !b.agg_proof.is_empty() {
                    let mut pubs: Vec<(u8, Vec<u8>)> = Vec::new();
                    let mut covers = std::collections::BTreeSet::new();
                    for tx in &b.txs {
                        match &tx.payload {
                            Tx::MintToPool { value, commitment, proof, .. }
                                if proof.is_empty() =>
                            {
                                let e = hk_state::expected_mint_public(commitment, *value);
                                let pb = bincode::serialize(&e).unwrap_or_default();
                                covers.insert(hk_state::pool::cover_key(
                                    hk_spend_circuit::agg::KIND_MINT, &pb,
                                ));
                                pubs.push((hk_spend_circuit::agg::KIND_MINT, pb));
                            }
                            Tx::ShieldedSpend {
                                anchor, nullifier, out_commitment, out2_commitment,
                                fee, credit, proof, ..
                            } if proof.is_empty() => {
                                let e = hk_state::expected_spend_public(
                                    anchor, nullifier, out_commitment, out2_commitment,
                                    *fee, credit,
                                );
                                let pb = bincode::serialize(&e).unwrap_or_default();
                                covers.insert(hk_state::pool::cover_key(
                                    hk_spend_circuit::agg::KIND_SPEND, &pb,
                                ));
                                pubs.push((hk_spend_circuit::agg::KIND_SPEND, pb));
                            }
                            _ => {}
                        }
                    }
                    if !pubs.is_empty() {
                        if live_agg {
                            if let Some((agg_verify, s_hash, m_hash)) = &self.agg {
                                let leaves: Vec<_> = pubs
                                    .iter()
                                    .map(|(kind, pb)| {
                                        let vk = if *kind == hk_spend_circuit::agg::KIND_MINT {
                                            m_hash
                                        } else {
                                            s_hash
                                        };
                                        hk_spend_circuit::agg::agg_leaf(*kind, vk, pb)
                                    })
                                    .collect();
                                let digest = hk_spend_circuit::agg::agg_digest(&leaves);
                                // RZ-1's lesson: a panic boundary around third-party proof parsing — a
                                // panic counts as an invalid aggregate, the same empty coverage every node
                                // derives, so deterministic (chain/Cargo.toml sets no `panic = "abort"`).
                                let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    agg_verify(&b.agg_proof, &digest)
                                }))
                                .unwrap_or(false);
                                if verified {
                                    info!(
                                        covered = leaves.len(),
                                        "Aggregate STARK verified — ONE verify covers this block's shielded txs"
                                    );
                                    chain.set_block_coverage(covers);
                                    agg_valid = true;
                                } else {
                                    error!("aggregate proof INVALID — its proof-less txs will be rejected");
                                }
                            } else {
                                error!("batch carries an aggregate but this node has no agg verifier");
                            }
                        } else if recorded_agg_valid {
                            info!(
                                covered = pubs.len(),
                                "Replay: recorded aggregate verdict installed (verified live at original commit)"
                            );
                            chain.set_block_coverage(covers);
                            agg_valid = true;
                        }
                    }
                }
            }

            agg_ms = t_agg.elapsed().as_millis() as u64;

            let t_apply = std::time::Instant::now();
            let receipts = chain
                .apply_block_verified(height, time, &txs, Some(&sig_verdicts))
                .map_err(|e| eyre!("apply_block failed: {e}"))?;
            apply_ms = t_apply.elapsed().as_millis() as u64;

            // Record receipts + prune the mempool and the bundle queue.
            //
            // HR-1 (mr-hrydarie, reported 2026-11-04; v0.19.11) — the prune is RECEIPT-AWARE;
            // the split is `commit_prune_sets` (pure, tested in `hr1_tests`) and the two prunes
            // are `CommitPrune::prune_mempool`. An APPLIED tx consumed its nonce, so every
            // pending tx at that (sender, nonce) is dead (`remove_included`, as before). A
            // REFUSED tx consumed nothing — a refusal ratchets no nonce and burns no nullifier
            // (`State::apply_tx_at`) — so only an identical pending tx (same txid) is dead and a
            // different pending tx at the same slot may still apply (`Mempool::remove_refused`).
            // Before v0.19.11 every block tx's slot was pruned whatever its receipt, so a refused
            // bundle tx naming a victim's pending (account, nonce) evicted the victim's honest tx
            // on every node that committed the block — HR-1's eviction axis. `included` still
            // names EVERY block tx: a ridden bundle leaves the queue whatever its receipts. The
            // store replay path (`restore_from_store`) comes through this same function.
            let mut prune = commit_prune_sets(&txs, &receipts);
            let mut rlog = self.receipts.lock().unwrap();
            for (id, detail) in prune.log.drain(..) {
                rlog.insert(id, detail);
            }
            drop(rlog);
            // v0.11.2: search indexes (live commits AND store replay both pass here).
            self.index_txs(height, &txs);
            if !prune.included.is_empty() {
                // C2.2: indexed prune — one O(mempool) pass each, O(1) membership tests.
                prune.prune_mempool(&mut self.mempool.lock().unwrap());
                // P2.3: a bundle is spent once any of its txs committed (applied or refused —
                // it rode, so it leaves the queue).
                let gone: std::collections::HashSet<(hk_primitives::AccountId, u64)> =
                    prune.included.iter().copied().collect();
                let mut bundles = self.bundles.lock().unwrap();
                bundles.retain(|(btxs, _)| {
                    !btxs.iter().any(|t| gone.contains(&(t.sender, t.nonce)))
                });
            }

            // Pool-note index: every commitment that entered a tree this block, with its
            // stealth payload, in tx order == insertion order (wallets rebuild auth paths
            // and SCAN from this). P6: one feed per pool — a shield routes by its asset, a
            // spend by its anchor (still a recent anchor of its pool: sealing is at block
            // end and the window is long), exactly as the state machine routed it.
            {
                use hk_state::tx::Tx;
                use hk_state::PoolKey;
                let mut notes = self.pool_notes.lock().unwrap();
                let mut by_asset = self.pool_notes_by_asset.lock().unwrap();
                for (tx, r) in txs.iter().zip(receipts.iter()) {
                    if r.result.is_ok() {
                        match &tx.payload {
                            Tx::MintToPool { asset, commitment, stealth_ct, .. } => {
                                match chain.pool_key_of_asset(asset) {
                                    Ok(PoolKey::Asset(a)) => by_asset
                                        .entry(a)
                                        .or_default()
                                        .push((*commitment, stealth_ct.clone())),
                                    _ => notes.push((*commitment, stealth_ct.clone())),
                                }
                            }
                            Tx::ShieldedSpend {
                                anchor,
                                out_commitment,
                                out2_commitment,
                                stealth_ct,
                                stealth_ct2,
                                ..
                            } => {
                                let feed: &mut Vec<(hk_primitives::H256, Vec<u8>)> =
                                    match chain.pool_key_of_anchor(anchor) {
                                        Some(PoolKey::Asset(a)) => by_asset.entry(a).or_default(),
                                        _ => &mut *notes,
                                    };
                                feed.push((*out_commitment, stealth_ct.clone()));
                                feed.push((*out2_commitment, stealth_ct2.clone()));
                            }
                            _ => {}
                        }
                    }
                }
            }

            // HK-R5.2: ONE post-apply commitment per block — it feeds the log line
            // AND becomes the cached parent-check value for the next block (this
            // used to be two full-state walks per block).
            let t_hash = std::time::Instant::now();
            let app_hash = chain.state_commitment();
            hash_ms = t_hash.elapsed().as_millis() as u64;
            post_hash = app_hash.0;
            let ok = receipts.iter().filter(|r| r.result.is_ok()).count();
            info!(
                height,
                txs = receipts.len(),
                ok,
                rejected = receipts.len() - ok,
                app_hash = %hex::encode(&app_hash.0[..8]),
                "Committed block"
            );
        }
        self.last_app_hash = Some(post_hash);

        // HK-R5.2: accumulate the window; one summary line per 100 blocks.
        let tm = &mut self.timers;
        tm.n += 1;
        tm.pre_ms += pre_ms;
        tm.agg_ms += agg_ms;
        tm.apply_ms += apply_ms;
        tm.hash_ms += hash_ms;
        if tm.n >= 100 {
            info!(
                blocks = tm.n,
                pre_ms = tm.pre_ms,
                agg_ms = tm.agg_ms,
                apply_ms = tm.apply_ms,
                hash_ms = tm.hash_ms,
                save_ms = tm.save_ms,
                snap_ms = tm.snap_ms,
                "R5.2 apply-cost window"
            );
            *tm = ApplyTimers::default();
        }
        Ok(agg_valid)
    }

    /// SCMS: apply operational-key rotations committed in a block. Every node updates
    /// the validator set (so it verifies the rotated validator's future votes against
    /// the new key). The validator that OWNS the rotated root also swaps its own live
    /// signer to the new tree, in lockstep. On REPLAY (restore-from-store) we only track
    /// the epoch: `adopt_epoch_signer` runs once after restore and builds the signer at
    /// the FINAL epoch directly — the per-epoch state file carries its own used-leaf
    /// counter, so resume never reuses a leaf (this closed the WS-F ledger item).
    fn apply_rotations(&mut self, height: u64, batch: &Option<Batch>, replay: bool) {
        let mut any_applied = false;
        if let Some(b) = &batch {
            for cert in &b.rotations {
                // L-2: the rule at the COMMIT height — the same answer on a live commit and
                // on replay (restore_from_store), so the set history never forks on restart.
                let applied = {
                    let rules = self.rotation_rules(height);
                    self.validators.lock().unwrap_or_else(|e| e.into_inner()).apply_rotation(cert, &rules)
                };
                match applied {
                    Ok(new_set) => {
                        *self.validators.lock().unwrap_or_else(|e| e.into_inner()) = new_set;
                        any_applied = true;
                        let mine = cert.root_pk == self.my_root_pk;
                        info!(epoch = cert.epoch, mine = mine, replay, "Applied validator key rotation");
                        if mine && cert.epoch > self.current_epoch {
                            if replay {
                                // Signer adoption happens post-restore (adopt_epoch_signer);
                                // here we only track how far our epoch advanced on-chain.
                                self.current_epoch = cert.epoch;
                            } else {
                                let seed = op_seed(&self.master_seed, cert.epoch);
                                let path = self
                                    .home_dir
                                    .join(format!("consensus_state_e{}.bin", cert.epoch));
                                let new_pk = self.op_handle.rotate_to(seed, path);
                                if new_pk != cert.new_op_pk {
                                    error!("rotation key mismatch: regenerated tree != cert pubkey");
                                }
                                self.current_epoch = cert.epoch;
                                // HR-7: the new epoch's tree attaches used up when a state file
                                // at its path is damaged or not this tree's — say which.
                                let remaining = self.op_handle.remaining();
                                if remaining == 0 {
                                    warn!(
                                        epoch = cert.epoch,
                                        remaining,
                                        "Rotated OUR operational signing key (live) — the new tree attached USED UP (a damaged or foreign state file at its path)"
                                    );
                                } else {
                                    info!(
                                        epoch = cert.epoch,
                                        remaining,
                                        "Rotated OUR operational signing key (live) — fresh tree"
                                    );
                                }
                            }
                        }
                        self.pending_rotations
                            .retain(|c| !(c.root_pk == cert.root_pk && c.epoch <= cert.epoch));
                        // R2: a committed cert also retires any queued foreign copy.
                        self.foreign_rotations
                            .lock()
                            .unwrap()
                            .retain(|c| !(c.root_pk == cert.root_pk && c.epoch <= cert.epoch));
                    }
                    Err(e) => error!(%e, height, epoch = cert.epoch, "Rejected rotation cert"),
                }
            }
        }
        // HK-R6: a rotation committed in block `height` changes the set that signs
        // height+1 onward — record it so certificate verification for any later
        // height uses the right keys (live commits AND replay both pass through here).
        if any_applied {
            let set = self.validators.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let mut hist = self.set_history.lock().unwrap_or_else(|e| e.into_inner());
            hist.push((height + 1, set));
        }
    }

    /// V1: apply validator-set changes committed in a block. Every node re-verifies each
    /// certificate against the set AS IT STANDS (sequentially — a block may carry several)
    /// and at THIS height (freshness window), so the outcome is deterministic across the
    /// network; a certificate that fails here is logged and ignored (the proposer already
    /// filtered, so this only fires on a malicious or racing proposal). A change takes
    /// effect for `height + 1` — recorded in the HK-R6 history exactly like a rotation, so
    /// commit certificates on either side of the boundary verify against the right set.
    /// Runs on live commits AND on replay (restore-from-store) — same code, same answer.
    fn apply_set_changes(&mut self, height: u64, batch: &Option<Batch>, replay: bool) {
        let mut any_applied = false;
        if let Some(b) = &batch {
            for cert in &b.set_changes {
                let current = self.validators.lock().unwrap_or_else(|e| e.into_inner()).clone();
                match hk_consensus::apply_set_change(&current, cert, height, &self.chain_id) {
                    Ok(Some(new_set)) => {
                        *self.validators.lock().unwrap_or_else(|e| e.into_inner()) = new_set.clone();
                        any_applied = true;
                        let subject = cert.body.subject_root();
                        let mine = subject == self.my_root_pk.as_slice();
                        match &cert.body.change {
                            SetChange::Admit { voting_power, .. } => {
                                info!(
                                    root = %hex::encode(&subject[..8.min(subject.len())]),
                                    power = voting_power,
                                    seats = new_set.len(),
                                    total_power = new_set.total_voting_power(),
                                    effective_from = height + 1,
                                    replay,
                                    "Validator ADMITTED"
                                );
                                if mine {
                                    info!(
                                        effective_from = height + 1,
                                        "THIS NODE now holds a voting seat — signing from the next height"
                                    );
                                }
                            }
                            SetChange::Remove { .. } => {
                                info!(
                                    root = %hex::encode(&subject[..8.min(subject.len())]),
                                    seats = new_set.len(),
                                    total_power = new_set.total_voting_power(),
                                    effective_from = height + 1,
                                    replay,
                                    "Validator REMOVED"
                                );
                                if mine {
                                    info!("THIS NODE was unseated — it keeps verifying as an observer");
                                }
                            }
                            SetChange::SetPower { voting_power, .. } => {
                                info!(
                                    root = %hex::encode(&subject[..8.min(subject.len())]),
                                    power = voting_power,
                                    seats = new_set.len(),
                                    total_power = new_set.total_voting_power(),
                                    quorum = hk_consensus::quorum_power(new_set.total_voting_power()),
                                    effective_from = height + 1,
                                    replay,
                                    "Validator RE-WEIGHTED (G1 set-power)"
                                );
                                if mine {
                                    info!(power = voting_power, "THIS NODE's voting power changed");
                                }
                            }
                        }
                    }
                    Ok(None) => info!(height, "set change already applied — no-op"),
                    Err(e) => error!(%e, height, "Rejected set change certificate"),
                }
                // Whatever happened, a committed copy retires our queued copy.
                self.pending_set_changes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .retain(|q| q.body != cert.body);
            }
        }
        // G1 (v0.18.0): the bootstrap re-weight — a rule of the binary, applied by every node
        // at the SAME height on live commits and on replay, after any certificates in that
        // block: the genesis seats' power becomes `founding_power`, effective height + 1.
        if let Some(b) = crate::genesis::bootstrap_for(&self.chain_id) {
            if height == b.height {
                let current = self.validators.lock().unwrap_or_else(|e| e.into_inner()).clone();
                match hk_consensus::reweight_roots(&current, &self.genesis_roots, b.founding_power) {
                    Some(new_set) => {
                        let founding: u64 = new_set
                            .iter()
                            .filter(|v| self.genesis_roots.contains(&v.root_pk))
                            .map(|v| v.voting_power)
                            .sum();
                        *self.validators.lock().unwrap_or_else(|e| e.into_inner()) = new_set.clone();
                        any_applied = true;
                        info!(
                            height,
                            founding_power = b.founding_power,
                            founding_total = founding,
                            total_power = new_set.total_voting_power(),
                            seats = new_set.len(),
                            quorum = hk_consensus::quorum_power(new_set.total_voting_power()),
                            effective_from = height + 1,
                            replay,
                            "G1 BOOTSTRAP GOVERNANCE ACTIVATED — genesis seats re-weighted"
                        );
                    }
                    None => info!(height, "G1 activation height reached — nothing to re-weight"),
                }
            }
        }
        if any_applied {
            let set = self.validators.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let mut hist = self.set_history.lock().unwrap_or_else(|e| e.into_inner());
            hist.push((height + 1, set));
        }
    }

    /// R2/WS-F: after restore, make the LIVE signer match the epoch the chain says we're
    /// on. Restore rebuilds the validator set (snapshot + replayed certs) but the signer
    /// was constructed at startup from the genesis-era file; if our on-chain entry moved
    /// to epoch E > current signer epoch, rebuild the tree from `op_seed(master, E)` and
    /// attach `consensus_state_e{E}.bin` — an existing file resumes its own used-leaf
    /// counter (reserve-then-sign wrote it before any signature left the box); a missing
    /// file means the tree never signed, so leaf 0 is correct (the revival case).
    pub fn adopt_epoch_signer(&mut self) {
        let (chain_epoch, expected_pk) = {
            let vals = self.validators.lock().unwrap_or_else(|e| e.into_inner());
            match vals.iter().find(|v| v.root_pk == self.my_root_pk) {
                Some(v) => (v.epoch, v.public_key.clone()),
                None => return, // not a validator on this chain (RPC-only node)
            }
        };
        if self.op_handle.public() == expected_pk {
            self.current_epoch = chain_epoch;
            self.highest_issued_epoch = self.highest_issued_epoch.max(chain_epoch);
            return; // signer already matches the registered key (epoch 0, or pre-adopted)
        }
        let seed = op_seed(&self.master_seed, chain_epoch);
        let path = if chain_epoch == 0 {
            self.home_dir.join("consensus_state.bin")
        } else {
            self.home_dir.join(format!("consensus_state_e{chain_epoch}.bin"))
        };
        // Log only: whether an entry is at the path at all — `exists()` follows a symlink and
        // reports a dangling one as absent.
        let resumed = std::fs::symlink_metadata(&path).is_ok();
        let new_pk = self.op_handle.rotate_to(seed, path);
        if new_pk != expected_pk {
            error!(
                epoch = chain_epoch,
                "adopt_epoch_signer: rebuilt tree != registered key — wrong master seed?"
            );
            return;
        }
        self.current_epoch = chain_epoch;
        self.highest_issued_epoch = self.highest_issued_epoch.max(chain_epoch);
        *self.signer_gauge.lock().unwrap() = (chain_epoch, self.op_handle.remaining());
        info!(
            epoch = chain_epoch,
            resumed,
            remaining = self.op_handle.remaining(),
            "Adopted rotated signer for our on-chain epoch (restart-after-rotation resume)"
        );
    }

    pub fn commit(
        &mut self,
        certificate: CommitCertificate<HkContext>,
        _extensions: VoteExtensions<HkContext>,
    ) -> Result<()> {
        let height = certificate.height.as_u64();

        let value = self
            .undecided
            .range((height, i64::MIN)..=(height, i64::MAX))
            .flat_map(|(_, vs)| vs.iter())
            .find(|v| v.value.id() == certificate.value_id)
            .map(|v| v.value.clone())
            .ok_or_else(|| eyre!("decided value {} not found at height {height}", certificate.value_id))?;

        let batch = Batch::decode(&value.txs);

        let agg_valid = self.apply_batch_to_chain(height, &batch, true, false)?;
        self.apply_rotations(height, &batch, false);
        self.apply_set_changes(height, &batch, false);

        // P3.0/WS-B: capture the persistent facts BEFORE the value moves into `decided`.
        let cert_dto = crate::codec::RawCommitCertificate::from(&certificate);
        let value_bytes = value.txs.to_vec();

        self.decided.insert(height, DecidedEntry { value, certificate });
        // R10 v2: keep only the newest `decided_window()` heights in RAM — older ones
        // are on disk (persisted below, BEFORE any peer can ask for them by tip).
        let window = decided_window();
        if window > 0 {
            while self.decided.len() as u64 > window {
                self.decided.pop_first();
            }
        }
        self.undecided.retain(|(h, _), _| *h > height);
        self.current_height = HkHeight::new(height + 1);

        // ---- SCMS rotation triggers (R1) + leaf-budget gauge (R4) ----------------------
        // The PRODUCTION trigger is the leaf budget itself: rotate when < 20% of the
        // tree remains (staging incident #1: a tree ran to exactly zero and halted the
        // chain — 32,768 leaves ÷ ~3 sigs/height burned in ~6 h of 2 s blocks). The
        // HK_ROTATE_EVERY interval survives as a demo/ops override, not a requirement.
        {
            let remaining = self.op_handle.remaining();
            *self.signer_gauge.lock().unwrap() = (self.current_epoch, remaining);
            let capacity = hk_crypto::hashsig::CONSENSUS_CAPACITY;
            if height % 100 == 0 {
                let pct = remaining * 100 / capacity;
                if pct < 5 {
                    error!(remaining, pct, epoch = self.current_epoch, "signer leaf budget CRITICAL");
                } else if remaining < rotation_threshold(capacity, &self.my_root_pk) {
                    warn!(remaining, pct, epoch = self.current_epoch, "signer leaf budget under this seat's rotation threshold — rotation should be in flight");
                } else {
                    info!(remaining, pct, epoch = self.current_epoch, threshold = rotation_threshold(capacity, &self.my_root_pk), "signer leaf budget");
                }
            }
            let mine_pending =
                self.pending_rotations.iter().any(|c| c.root_pk == self.my_root_pk);
            let next_epoch = self.current_epoch + 1;
            // R9: an issue with no on-chain effect after REISSUE_AFTER is presumed
            // dead — the guards below stop blocking. `None` (fresh boot) counts as
            // stale BY DESIGN: a restart clears a wedged snapshot-restored guard.
            let issue_stale = self
                .last_issue_time
                .map(|t| t.elapsed() >= REISSUE_AFTER)
                .unwrap_or(true);
            let threshold = rotation_threshold(capacity, &self.my_root_pk);
            let (due, threshold_hit) = rotation_due(
                remaining,
                threshold,
                height,
                self.rotate_every,
                mine_pending,
                next_epoch,
                self.highest_issued_epoch,
                issue_stale,
            );
            if due {
                let seed = op_seed(&self.master_seed, next_epoch);
                let new_op_pk = HkPriv::from_seed(seed).public();
                // L-2: `valid_from_height = height + 1` (as since 0.9.3), now READ by v2
                // verifiers as the freshness anchor; the domain follows the chain's rule
                // where this cert will commit (`issue_for`: v2 iff height + 1 ≥ v2_from).
                let cert = RotationCert::issue_for(
                    &self.root,
                    &self.chain_id,
                    self.rotation_v2_from,
                    new_op_pk,
                    next_epoch,
                    height + 1,
                );
                self.highest_issued_epoch = self.highest_issued_epoch.max(next_epoch);
                // R9: a re-issue replaces any stale same-or-older own cert instead of
                // stacking beside it.
                let mine = self.my_root_pk.clone();
                self.pending_rotations
                    .retain(|c| !(c.root_pk == mine && c.epoch <= next_epoch));
                self.pending_rotations.push(cert);
                self.last_issue_time = Some(std::time::Instant::now());
                info!(
                    epoch = next_epoch,
                    remaining,
                    trigger = if threshold_hit { "leaf-threshold" } else { "interval" },
                    "Issued rotation cert (applies once committed)"
                );
            } else if threshold_hit && height % 100 == 0 {
                // R9: the gauge is screaming but issuance is gated — say so instead
                // of burning silently to zero (the val-0 incident, 2026-09-02).
                warn!(
                    remaining,
                    next_epoch,
                    highest_issued = self.highest_issued_epoch,
                    mine_pending,
                    reissue_in_s = REISSUE_AFTER
                        .checked_sub(self.last_issue_time.map(|t| t.elapsed()).unwrap_or_default())
                        .unwrap_or_default()
                        .as_secs(),
                    "rotation threshold hit but issuance is gated — will re-arm"
                );
            }
        }

        // ---- P3.0/WS-B: persist. Block log every height; full snapshot + WAL reset
        // every SNAPSHOT_EVERY. Persistence failures are LOUD but non-fatal on the
        // live path: consensus safety never depends on this node's disk (a restart
        // simply replays less / value-syncs the gap).
        if let Some(store) = self.store.clone() {
            let t_save = std::time::Instant::now();
            match store.save_block(&StoredBlock { height, value_bytes, certificate: cert_dto, agg_valid })
            {
                Ok(()) => {
                    if self.history_min == 0 {
                        self.history_min = height;
                        store.set_disk_min(height);
                    }
                }
                Err(e) => {
                    error!(%e, height, "failed to persist block — restart will value-sync this height");
                    // R10 v2: the disk suffix now starts past this hole; the RAM window
                    // still covers it for `decided_window()` heights.
                    self.history_min = height + 1;
                    store.set_disk_min(height + 1);
                }
            }
            self.timers.save_ms += t_save.elapsed().as_millis() as u64;
            // HK-R5.2: cadence is env-tunable (`HK_SNAPSHOT_EVERY`) — the full-image
            // snapshot + fsync grows with state and taxes catch-up at the default 16.
            if height % snapshot_every() == 0 {
                let t_snap = std::time::Instant::now();
                let snap = self.make_snapshot();
                store.rotate_snapshot_if_configured(); // S3: HK_KEEP_PREV_SNAPSHOT=1
                match store.save_snapshot(&snap) {
                    Ok(()) => {
                        let mp = self.mempool.lock().unwrap();
                        if let Err(e) = store.wal_reset(mp.iter()) {
                            error!(%e, "failed to reset mempool WAL");
                        }
                        info!(height, "Node snapshot persisted (restart resumes here)");
                        // C2.8: everything at-or-below this snapshot may be packed into
                        // segments — one segment per snapshot, off the commit path.
                        store.compact_one_background(height);
                        // C2.8 retention: whole old segments only; the servable floor moves up.
                        match store.prune_below(height, retain_blocks()) {
                            Ok(Some(min)) => {
                                if min > self.history_min {
                                    self.history_min = min;
                                    store.set_disk_min(min);
                                    info!(height, servable_from = min, "block log: retention pruned old segments");
                                }
                            }
                            Ok(None) => {}
                            Err(e) => warn!(%e, "block log: retention prune failed"),
                        }
                    }
                    Err(e) => error!(%e, height, "failed to persist snapshot"),
                }
                self.timers.snap_ms += t_snap.elapsed().as_millis() as u64;
            }
            // S2: the search index goes to disk on its own cadence.
            if height % index_persist_every() == 0 {
                self.persist_index(&store, height);
            }
        }

        Ok(())
    }

    // ---- S2 (v0.16.0): search index persistence ----

    /// Write the search index to disk. Coverage is the tip once the history pass is
    /// done, else the pass's contiguous floor (heights above it are indexed live but
    /// a resumed pass must not skip the gap).
    fn persist_index(&self, store: &Arc<NodeStore>, tip: u64) {
        let floor = self.index_floor.load(std::sync::atomic::Ordering::Relaxed);
        let through = if floor == u64::MAX { tip } else { floor };
        if through == 0 {
            return;
        }
        let ix = {
            let ti = self.tx_index.lock().unwrap_or_else(|e| e.into_inner());
            let ai = self.acct_index.lock().unwrap_or_else(|e| e.into_inner());
            crate::store::PersistedIndex {
                through_height: through,
                tx: ti.iter().filter(|(_, (h, _))| *h <= through).map(|(id, (h, i))| (*id, *h, *i)).collect(),
                acct: ai
                    .iter()
                    .map(|(a, list)| {
                        (*a, list.iter().filter(|(_, h, _)| *h <= through).map(|(id, h, k)| (*id, *h, (*k).to_string())).collect())
                    })
                    .collect(),
            }
        };
        match store.save_index(&ix) {
            Ok(()) => info!(through, txs = ix.tx.len(), "search index persisted (S2)"),
            Err(e) => warn!(%e, "search index persist failed (rebuilt from the block log next restart)"),
        }
    }

    // ---- P3.0/WS-B: snapshot + restore ----

    /// The full persistent node image at the current height.
    fn make_snapshot(&self) -> NodeSnapshot {
        let (app_hash, height, state) = {
            let chain = self.chain.lock().unwrap();
            (chain.state_commitment().0, chain.height, chain.to_snapshot())
        };
        NodeSnapshot {
            app_hash,
            height,
            state,
            pool_notes: self.pool_notes.lock().unwrap().clone(),
            pool_notes_by_asset: self.pool_notes_by_asset.lock().unwrap().clone(),
            receipts: self.receipts.lock().unwrap().entries(),
            mempool: self.mempool.lock().unwrap().iter().cloned().collect(),
            validators: self
                .validators
                .lock()
                .unwrap()
                .iter()
                .map(|v| ValidatorDto {
                    address: v.address,
                    root_pk: v.root_pk.clone(),
                    public_key: v.public_key.clone(),
                    epoch: v.epoch,
                    voting_power: v.voting_power,
                })
                .collect(),
            current_epoch: self.current_epoch,
            highest_issued_epoch: self.highest_issued_epoch,
        }
    }

    /// Resume from disk: snapshot (verified against its recorded C(Σ) —
    /// refuse-on-mismatch, the vk-pin posture) → replay newer block files through the
    /// SAME apply path → reload WAL'd mempool admissions. Call AFTER construction
    /// (verifier already injected), BEFORE the engine asks `start_height()`.
    ///
    /// R10 v2: history at-or-below the snapshot is NOT rehydrated into RAM any more —
    /// value-sync serves it from the block log (`decided_value`), and the v0.11.2
    /// search indexes over it are rebuilt by a background pass that never blocks the
    /// engine (a validator votes seconds after restart; search fills in behind it).
    /// The engine's start height is the chain's, whatever the block log looks like.
    pub fn restore_from_store(&mut self, store: &Arc<NodeStore>) -> Result<()> {
        if let Some(snap) = store.load_snapshot()? {
            // Config survives the image swap (a snapshot must not smuggle in policy):
            // the verifier AND the U4 fee parameters are re-injected from the running
            // configuration, exactly as `HkApp::new` set them.
            let (verifier, fee_micro, fee_from, fee_asset, multi_pool_from, mandate_asset_from, payword_cap_from) = {
                let c = self.chain.lock().unwrap();
                (
                    c.verifier.clone(),
                    c.fee_micro,
                    c.fee_from,
                    c.fee_asset,
                    c.multi_pool_from,
                    c.mandate_asset_from,
                    c.payword_cap_from,
                )
            };
            let mut st = hk_state::State::from_snapshot(snap.state);
            st.verifier = verifier;
            st.fee_micro = fee_micro;
            st.fee_from = fee_from;
            st.fee_asset = fee_asset; // X1: genesis fact, config-like on restore
            st.multi_pool_from = multi_pool_from; // P6: chain-id fact, config-like on restore
            st.mandate_asset_from = mandate_asset_from; // R17: chain-id fact, config-like on restore
            st.payword_cap_from = payword_cap_from; // R18: chain-id fact, config-like on restore
            // L-2: `self.rotation_v2_from` is node-side (set by `set_genesis_digest`, which
            // node.rs calls before this), so the image swap cannot smuggle a rotation rule in.
            let got = st.state_commitment().0;
            if got != snap.app_hash {
                return Err(eyre!(
                    "snapshot integrity FAILURE at height {}: recomputed C(Σ) {} != recorded {} — \
                     refusing to run on corrupt state (wipe this node's home or restart --fresh)",
                    snap.height,
                    hex::encode(&got[..8]),
                    hex::encode(&snap.app_hash[..8])
                ));
            }
            *self.chain.lock().unwrap() = st;
            *self.pool_notes.lock().unwrap() = snap.pool_notes;
            *self.pool_notes_by_asset.lock().unwrap() = snap.pool_notes_by_asset;
            self.receipts.lock().unwrap().restore(snap.receipts);
            {
                // Rebuild WITH indexes (C2); duplicate frames in an old image are suppressed.
                // v0.19.12: a pending tx the door's field and size rules or one of the
                // pool's caps refuse is dropped (`Mempool::restore_unchecked`; still no chain
                // checks here) and the drops are reported once.
                let mut mp = self.mempool.lock().unwrap();
                let (_, dropped) = mp.restore_unchecked(snap.mempool);
                if dropped > 0 {
                    warn!(
                        dropped,
                        "snapshot restore dropped pending txs the admission field and size rules or the pool's caps refuse"
                    );
                }
            }
            if !snap.validators.is_empty() {
                *self.validators.lock().unwrap_or_else(|e| e.into_inner()) =
                    HkValidatorSet::new(snap.validators.into_iter().map(|v| HkValidator {
                        address: v.address,
                        root_pk: v.root_pk,
                        public_key: v.public_key,
                        epoch: v.epoch,
                        voting_power: v.voting_power,
                    }));
            }
            self.current_epoch = snap.current_epoch;
            self.highest_issued_epoch = snap.highest_issued_epoch;
            // HK-R6: history restarts at the snapshot — its set (which already folds
            // in every pre-snapshot rotation) is effective from the next height;
            // rotations replayed below append their own entries. Heights before the
            // snapshot are never verified by this node, so no older sets are needed.
            {
                let set = self.validators.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let mut hist = self.set_history.lock().unwrap_or_else(|e| e.into_inner());
                hist.clear();
                hist.push((snap.height + 1, set));
            }
            info!(
                height = snap.height,
                app_hash = %hex::encode(&snap.app_hash[..8]),
                "Snapshot restored — commitment verified"
            );
        }

        // Block files: one directory listing. REPLAY the gap-free run just beyond the
        // snapshot through the normal apply path (those few blocks also seed the RAM
        // window); everything at-or-below the snapshot stays on disk.
        let heights = store.block_heights()?;
        let snap_height = self.chain.lock().unwrap().height;
        let mut replayed = 0u64;
        for &h in heights.iter().filter(|h| **h > snap_height) {
            let chain_height = self.chain.lock().unwrap().height;
            if h != chain_height + 1 {
                error!(
                    height = h,
                    chain_height,
                    "gap in the block log — stopping replay here; value-sync fills the rest"
                );
                break;
            }
            let Some(sb) = store.load_block(h)? else { continue };
            let value = HkValue::new(Bytes::from(sb.value_bytes));
            if certificate_value_mismatch(&sb.certificate, &value) {
                return Err(eyre!(
                    "block file {h}: certificate value-id != content hash — refusing corrupt history"
                ));
            }
            let certificate: CommitCertificate<HkContext> = sb.certificate.into();
            let batch = Batch::decode(&value.txs);
            self.apply_batch_to_chain(h, &batch, false, sb.agg_valid)?;
            self.apply_rotations(h, &batch, true);
            self.apply_set_changes(h, &batch, true);
            self.decided.insert(h, DecidedEntry { value, certificate });
            replayed += 1;
        }
        let tip = self.chain.lock().unwrap().height;
        self.current_height = HkHeight::new(tip + 1);

        // R10 v2: what can this disk serve without a gap up to the tip? Only a suffix
        // that actually reaches the tip counts (a snapshot written AHEAD of the block
        // tail — the 08-30 transplant artifact — leaves nothing servable until the
        // next commit lands on disk).
        let disk_tip = heights.last().copied().unwrap_or(0);
        self.history_min = match contiguous_suffix_min(&heights) {
            Some(min) if disk_tip == tip => min,
            _ => tip + 1,
        };
        store.set_disk_min(self.history_min);
        let files_below = heights.iter().filter(|h| **h <= snap_height).count();
        info!(
            tip,
            disk_files = heights.len(),
            servable_from = self.history_min,
            ram_window = decided_window(),
            "R10 v2: history stays on disk (no rehydrate) — serving value-sync from the block log"
        );

        // v0.11.2 search indexes over the on-disk history, rebuilt in the BACKGROUND:
        // decode → index → drop, one file at a time, oldest first. Replayed and live
        // blocks index themselves on the apply path; `index_txs_into` is idempotent per
        // txid, so the two never double-count. `HK_INDEX_HISTORY=0` skips it (a voter
        // that serves no explorer). RSS stays O(window), not O(height).
        let index_history = std::env::var("HK_INDEX_HISTORY").map(|v| v != "0").unwrap_or(true);
        // S2 (v0.16.0): resume from the persisted index — the pass only reads heights
        // above what the last write covered (a corrupt/absent file = start from 1).
        let indexed_through = match store.load_index() {
            Some(ix) => {
                let through = ix.through_height.min(snap_height);
                {
                    let mut ti = self.tx_index.lock().unwrap_or_else(|e| e.into_inner());
                    let mut ai = self.acct_index.lock().unwrap_or_else(|e| e.into_inner());
                    for (id, h, i) in ix.tx {
                        if h <= through {
                            ti.insert(id, (h, i));
                        }
                    }
                    for (acct, list) in ix.acct {
                        let e = ai.entry(acct).or_default();
                        for (id, h, kind) in list {
                            if h <= through {
                                e.push((id, h, kind_static(&kind)));
                            }
                        }
                    }
                }
                info!(through, "search index restored from disk (S2) — resuming above it");
                through
            }
            None => 0,
        };
        let todo: Vec<u64> = heights.iter().copied().filter(|h| *h > indexed_through && *h <= snap_height).collect();
        if index_history && !todo.is_empty() {
            let store = store.clone();
            let ti = self.tx_index.clone();
            let ai = self.acct_index.clone();
            let floor = self.index_floor.clone();
            floor.store(indexed_through, std::sync::atomic::Ordering::Relaxed);
            let _detached = std::thread::Builder::new()
                .name("hk-index-history".into())
                .spawn(move || {
                    let t0 = std::time::Instant::now();
                    let (mut done, mut txs_seen) = (0u64, 0u64);
                    for h in todo {
                        match store.load_block(h) {
                            Ok(Some(sb)) => {
                                if let Some(b) = Batch::decode(&sb.value_bytes) {
                                    txs_seen += b.txs.len() as u64;
                                    index_txs_into(&ti, &ai, h, &b.txs);
                                }
                            }
                            Ok(None) => {}
                            Err(e) => warn!(%e, height = h, "index pass: unreadable block file (skipped)"),
                        }
                        floor.store(h, std::sync::atomic::Ordering::Relaxed);
                        done += 1;
                        if done % 20_000 == 0 {
                            info!(done, txs_seen, "index pass: progress");
                        }
                    }
                    floor.store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
                    info!(
                        blocks = done,
                        txs = txs_seen,
                        secs = t0.elapsed().as_secs(),
                        "index pass COMPLETE — search covers the full on-disk history"
                    );
                })
                .map_err(|e| eyre!("spawning index pass: {e}"))?;
        } else {
            // Nothing to index (or HK_INDEX_HISTORY=0: history stays unindexed and the
            // persisted coverage must not claim otherwise).
            let floor = if index_history { u64::MAX } else { indexed_through };
            self.index_floor.store(floor, std::sync::atomic::Ordering::Relaxed);
        }
        let _ = files_below;

        // C2.8 (v0.16.0): migrate the per-height block log into segments in the
        // background, oldest first — every complete span at-or-below the snapshot.
        // `HK_COMPACT_HISTORY=0` leaves the old layout alone (both are readable).
        if std::env::var("HK_COMPACT_HISTORY").map(|v| v != "0").unwrap_or(true) {
            let store = store.clone();
            let _detached = std::thread::Builder::new()
                .name("hk-compact".into())
                .spawn(move || match store.compactable_segments(snap_height) {
                    Ok(ids) if !ids.is_empty() => {
                        let t0 = std::time::Instant::now();
                        let (mut segs, mut files) = (0u64, 0usize);
                        for id in ids {
                            match store.compact_segment(id) {
                                Ok(n) => {
                                    segs += 1;
                                    files += n;
                                }
                                Err(e) => warn!(%e, segment = id, "block log: compaction failed (files kept)"),
                            }
                        }
                        info!(segments = segs, files_retired = files, secs = t0.elapsed().as_secs(), "block log: migration to segments complete");
                    }
                    Ok(_) => {}
                    Err(e) => warn!(%e, "block log: could not list segments"),
                });
        }

        // Mempool WAL: admissions since the last snapshot, re-run through the SAME
        // admission gate as live traffic (C2.1) — stale nonces, spent nullifiers and
        // duplicates all drop here for the same reasons they would at the door.
        // v0.19.12: so do frames the field and size rules or the pool's caps refuse;
        // those are counted apart (`Mempool::restore_admitted`) and reported once.
        let wal_restored = {
            let chain = self.chain.lock().unwrap();
            let mut mp = self.mempool.lock().unwrap();
            let (restored, dropped) = mp.restore_admitted(store.wal_load(), &chain);
            if dropped > 0 {
                warn!(
                    dropped,
                    "WAL replay dropped pending txs the admission field and size rules or the pool's caps refuse"
                );
            }
            restored
        };

        if tip > 0 || replayed > 0 {
            let app_hash = self.chain.lock().unwrap().state_commitment();
            info!(
                tip,
                replayed,
                on_disk_below_snapshot = files_below,
                mempool_restored = wal_restored,
                app_hash = %hex::encode(&app_hash.0[..8]),
                "PERSISTENCE RESTORE COMPLETE — resuming, not resyncing"
            );
        } else {
            info!("No persisted state — starting from genesis");
        }
        Ok(())
    }
}

/// The stored certificate must certify exactly the stored bytes (the value id is the
/// content hash, so this pins the block file to what consensus signed).
fn certificate_value_mismatch(cert: &crate::codec::RawCommitCertificate, value: &HkValue) -> bool {
    cert.value_id != value.id()
}

/// v0.11.2 search indexes, shared by the live apply path and the R10 v2 background
/// history pass. Idempotent per txid (a reinsert is skipped), so the two can overlap
/// on a height without an account's history double-counting. Locks are held per
/// block only — the RPC reads between blocks.
#[allow(clippy::type_complexity)]
fn index_txs_into(
    tx_index: &Mutex<std::collections::HashMap<[u8; 32], (u64, u32)>>,
    acct_index: &Mutex<
        std::collections::HashMap<hk_primitives::AccountId, Vec<([u8; 32], u64, &'static str)>>,
    >,
    height: u64,
    txs: &[SignedTx],
) {
    if txs.is_empty() {
        return;
    }
    let mut ti = tx_index.lock().unwrap_or_else(|e| e.into_inner());
    let mut ai = acct_index.lock().unwrap_or_else(|e| e.into_inner());
    for (i, tx) in txs.iter().enumerate() {
        let id = txid(tx);
        if ti.insert(id, (height, i as u32)).is_some() {
            continue;
        }
        let kind = tx_kind(&tx.payload);
        ai.entry(tx.sender).or_default().push((id, height, kind));
        if let Some(cp) = tx_counterparty(&tx.payload) {
            if cp != tx.sender {
                ai.entry(cp).or_default().push((id, height, kind));
            }
        }
    }
}

#[cfg(test)]
mod r10_history_tests {
    use super::contiguous_suffix_min;

    #[test]
    fn suffix_min_follows_the_gap_free_tail_only() {
        assert_eq!(contiguous_suffix_min(&[]), None, "empty log serves nothing");
        assert_eq!(contiguous_suffix_min(&[1]), Some(1));
        assert_eq!(contiguous_suffix_min(&[1, 2, 3, 4]), Some(1), "full log serves from 1");
        // val-0's shape after the thin teleport: block 1 alone, then a suffix.
        assert_eq!(contiguous_suffix_min(&[1, 49_929, 49_930, 49_931]), Some(49_929));
        // A hole inside the tail: only what is above the hole is servable.
        assert_eq!(contiguous_suffix_min(&[10, 11, 13, 14]), Some(13));
        assert_eq!(contiguous_suffix_min(&[7, 9]), Some(9));
    }
}

/// R18: pick up to `room` txs from the mempool's FIFO view for the block being built,
/// holding back every `ChannelSettle` whose links would push the block's running total
/// (starting at `links_so_far` — the P2.3 bundle that rides ahead of the pool, 0 when
/// there is none) over [`MAX_SETTLE_LINKS_PER_BLOCK`]; a held tx rides a later block, in
/// order. The links are [`settle_cost`] against the chain as it stands now — the SAME
/// function the mempool's door refuses by, so the two never disagree on a tx: a settle the
/// chain would refuse free on a known channel costs 0 (it rides, is refused in O(1) and
/// pruned at commit), an unknown channel's settle costs what a fresh channel would (its
/// open may be pending ahead of it). Once one of a sender's txs is held back, every later
/// tx of that sender is held with it: the pool is in nonce order per sender, and a
/// successor proposed without its predecessor would only burn a slot on `bad nonce` and be
/// pruned from the pool at commit, costing the sender a resubmit. A settle whose links
/// alone exceed the budget is refused at admission (`settle too costly to propose`) and
/// never reaches this pool through the door; one that does (a channel opened before the
/// height, restored from a pre-review snapshot) is simply never picked. Returns the picked
/// txs (pool order) and how many were held back.
///
/// v0.19.12: this is [`select_batch_txs_sized`] with the whole byte budget free (no
/// bundle ahead of the pool) — the form the selector tests and the mempool's door-agreement
/// tests call; `build_batch` calls the sized form. (Kept in every build, so the doc links to
/// it stay valid; only the tests call it.)
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn select_batch_txs<'a>(
    chain: &hk_state::State,
    pending: impl Iterator<Item = &'a SignedTx>,
    room: usize,
    links_so_far: u64,
) -> (Vec<SignedTx>, usize) {
    let pick = select_batch_txs_sized(chain, pending, room, links_so_far, 0);
    (pick.picked, pick.held)
}

/// v0.19.12: what [`select_batch_txs_sized`] picked for the block being built.
pub(crate) struct BatchPick {
    /// The picked txs, in pool order.
    pub(crate) picked: Vec<SignedTx>,
    /// How many txs the R18 settle-link budget held back (with their senders' later txs).
    pub(crate) held: usize,
    /// The encoded bytes of `picked` (`crate::mempool::tx_encoded_len`, summed).
    pub(crate) bytes: usize,
    /// The selection ended at a tx that does not fit the block's remaining byte budget: it
    /// and every tx behind it wait for a later block, in pool order.
    pub(crate) byte_budget_full: bool,
    /// (sender, nonce) of every tx larger than a whole block's byte budget — no block can
    /// carry one. Skipped, with its sender's later txs held behind it; `build_batch` drops
    /// them from the pool with one warning.
    pub(crate) oversize: Vec<(hk_primitives::AccountId, u64)>,
}

/// R18 and v0.19.12: the selection `select_batch_txs` documents (just above) — FIFO,
/// per-sender nonce order, the settle-link budget and its holds, unchanged — plus the block's
/// byte budget.
/// A running total of `crate::mempool::tx_encoded_len` over the picked txs, starting at
/// `bytes_so_far` (the P2.3 bundle's txs, 0 when there is none), never passes
/// `crate::batch::MAX_BATCH_TX_BYTES`: the signed proposal carries the whole batch in one
/// pubsub frame, and this budget keeps every block this node builds inside that frame. The
/// first tx that does not fit ENDS the selection — it and
/// everything behind it wait for a later block, so no sender's later nonce rides ahead of an
/// earlier one and the next block starts exactly where this one stopped. A
/// settle the link budget holds is held as before, and the byte check follows it, so the
/// R18 behaviour is unchanged. A tx larger than the whole budget is skipped:
/// its sender's later txs wait behind it, and it is reported in `oversize` for
/// `build_batch` to drop. Admission (`mempool::MAX_TX_BYTES`, below the budget)
/// and both restore paths keep such a tx out of the pool; this is the second
/// line.
pub(crate) fn select_batch_txs_sized<'a>(
    chain: &hk_state::State,
    pending: impl Iterator<Item = &'a SignedTx>,
    room: usize,
    links_so_far: u64,
    bytes_so_far: usize,
) -> BatchPick {
    let budget = crate::batch::MAX_BATCH_TX_BYTES;
    let mut pick = BatchPick { picked: Vec::new(), held: 0, bytes: 0, byte_budget_full: false, oversize: Vec::new() };
    let mut links: u64 = links_so_far;
    let mut bytes: usize = bytes_so_far;
    let mut held_senders: std::collections::BTreeSet<hk_primitives::AccountId> = Default::default();
    // Senders whose next tx no block can carry — their later txs wait behind it (not an
    // R18 hold, so not counted in `held`).
    let mut blocked_senders: std::collections::BTreeSet<hk_primitives::AccountId> = Default::default();
    for tx in pending {
        if pick.picked.len() >= room {
            break;
        }
        if blocked_senders.contains(&tx.sender) {
            continue;
        }
        if held_senders.contains(&tx.sender) {
            pick.held += 1;
            continue;
        }
        let cost = match &tx.payload {
            Tx::ChannelSettle { id, step, .. } => Some(settle_cost(chain, id, *step)),
            _ => None,
        };
        if let Some(cost) = cost {
            if links.saturating_add(cost) > MAX_SETTLE_LINKS_PER_BLOCK {
                pick.held += 1;
                held_senders.insert(tx.sender);
                continue;
            }
        }
        let size = crate::mempool::tx_encoded_len(tx);
        if size > budget {
            pick.oversize.push((tx.sender, tx.nonce));
            blocked_senders.insert(tx.sender);
            continue;
        }
        if bytes.saturating_add(size) > budget {
            pick.byte_budget_full = true;
            break;
        }
        if let Some(cost) = cost {
            links = links.saturating_add(cost);
        }
        bytes += size;
        pick.bytes += size;
        pick.picked.push(tx.clone());
    }
    pick
}

#[cfg(test)]
mod r18_batch_tests {
    use super::{select_batch_txs, settle_cost, MAX_SETTLE_LINKS_PER_BLOCK};
    use hk_primitives::{ChannelState, H256};
    use hk_state::tx::{SignedTx, Tx};
    use hk_state::{Channel, State, MAX_CHANNEL_STEPS, MAX_SETTLE_DELTA};

    fn h(b: u8) -> H256 {
        H256([b; 32])
    }

    /// A bare state with `n` open channels (ids 1..=n, `max_steps` each, nothing
    /// settled) — `settle_links` reads only the channel map, so no genesis or signatures
    /// are needed. `max_steps > MAX_CHANNEL_STEPS` is the shape of a channel opened
    /// BEFORE the height (the cap is tested at open only).
    fn chain_with_channels_of(n: u8, max_steps: u64) -> State {
        let mut st = State::default();
        for i in 1..=n {
            st.channels.insert(
                h(i),
                Channel {
                    state: ChannelState {
                        id: h(i),
                        payer: h(0xA0),
                        payee: h(0xB0),
                        asset: h(9),
                        mandate: h(0xC0),
                        tip: h(0xD0),
                        unit_price: 1,
                        max_steps,
                        highest_step_settled: 0,
                        expiry: u64::MAX,
                    },
                    escrow_remaining: max_steps as u128,
                    refunded: false,
                },
            );
        }
        st
    }

    /// `n` post-height channels: opened at exactly the consensus cap.
    fn chain_with_channels(n: u8) -> State {
        chain_with_channels_of(n, MAX_CHANNEL_STEPS)
    }

    /// Full-width settles that fill one block's budget exactly.
    const FILL: u64 = MAX_SETTLE_LINKS_PER_BLOCK / MAX_SETTLE_DELTA;

    /// Unsigned frames: the selector never looks at the envelope.
    fn tx(sender: u8, nonce: u64, payload: Tx) -> SignedTx {
        SignedTx { sender: h(sender), nonce, payload, next_auth: h(0), lamport_pk: vec![], sig: vec![] }
    }
    fn settle(sender: u8, nonce: u64, ch: u8, step: u32) -> SignedTx {
        tx(sender, nonce, Tx::ChannelSettle { id: h(ch), word: h(0), step })
    }
    fn transfer(sender: u8, nonce: u64) -> SignedTx {
        tx(sender, nonce, Tx::Transfer { to: h(0xB0), asset: h(9), amount: 1 })
    }
    fn nonces(txs: &[SignedTx]) -> Vec<(u8, u64)> {
        txs.iter().map(|t| (t.sender.0[0], t.nonce)).collect()
    }

    #[test]
    fn r18_budget_holds_the_third_full_width_settle_and_the_senders_successors() {
        // Sender 1 queues FILL + 3 full-width settles on fresh channels (2¹⁶ links each —
        // exactly the consensus cap) and then a transfer; sender 2 a transfer.
        assert_eq!(FILL, 2, "2¹⁷ / 2¹⁶: two full-width settles fill a block");
        let n = FILL as u8 + 3;
        let st = chain_with_channels(n);
        let mut pool: Vec<SignedTx> = (0..n).map(|i| settle(1, i as u64, i + 1, MAX_SETTLE_DELTA as u32)).collect();
        pool.push(transfer(1, n as u64));
        pool.push(transfer(2, 0));
        let (picked, held) = select_batch_txs(&st, pool.iter(), 1024, 0);
        // FILL settles fill the budget exactly (2 · 2¹⁶ = 2¹⁷); the next is held, and with
        // it every later tx of sender 1; sender 2's transfer rides in pool order.
        let mut want: Vec<(u8, u64)> = (0..FILL).map(|k| (1, k)).collect();
        want.push((2, 0));
        assert_eq!(nonces(&picked), want);
        assert_eq!(held, 4);
        // The held settles are the next blocks' first picks (same chain state) — nothing
        // is dropped, only deferred, in order: two more ride, then the last one + the
        // transfer.
        let rest = || pool.iter().skip(FILL as usize).filter(|t| t.sender == h(1));
        let (next, held2) = select_batch_txs(&st, rest(), 1024, 0);
        assert_eq!(nonces(&next), vec![(1, FILL), (1, FILL + 1)]);
        assert_eq!(held2, 2);
        let (last, held3) = select_batch_txs(&st, rest().skip(FILL as usize), 1024, 0);
        assert_eq!(nonces(&last), vec![(1, FILL + 2), (1, n as u64)]);
        assert_eq!(held3, 0);
    }

    #[test]
    fn r18_budget_counts_the_links_the_verifier_hashes_not_the_delta() {
        // A channel climbed to 2¹⁷ − 2¹⁶ by an earlier settle: the next full-width settle
        // has delta 2¹⁶ but costs 2¹⁷ links from the tip — it fills the budget on its own,
        // and a one-link settle on another channel after it is held.
        let mut st = chain_with_channels(2);
        st.channels.get_mut(&h(1)).unwrap().state.highest_step_settled = MAX_SETTLE_LINKS_PER_BLOCK - MAX_SETTLE_DELTA;
        let pool = [settle(1, 0, 1, MAX_SETTLE_LINKS_PER_BLOCK as u32), settle(2, 0, 2, 1)];
        assert_eq!(st.settle_delta(&h(1), MAX_SETTLE_LINKS_PER_BLOCK as u32), Some(MAX_SETTLE_DELTA));
        assert_eq!(st.settle_links(&h(1), MAX_SETTLE_LINKS_PER_BLOCK as u32), Some(MAX_SETTLE_LINKS_PER_BLOCK));
        assert_eq!(settle_cost(&st, &h(1), MAX_SETTLE_LINKS_PER_BLOCK as u32), MAX_SETTLE_LINKS_PER_BLOCK);
        let (picked, held) = select_batch_txs(&st, pool.iter(), 1024, 0);
        assert_eq!(nonces(&picked), vec![(1, 0)]);
        assert_eq!(held, 1);
        // In the other order the one-link settle rides and the 2¹⁷ one is held.
        let pool = [settle(2, 0, 2, 1), settle(1, 0, 1, MAX_SETTLE_LINKS_PER_BLOCK as u32)];
        let (picked, held) = select_batch_txs(&st, pool.iter(), 1024, 0);
        assert_eq!(nonces(&picked), vec![(2, 0)]);
        assert_eq!(held, 1);
        // One link past the budget can never ride from this node. On a post-height channel
        // that step is past `max_steps` (the cap equals the budget — the compile-time
        // assert), i.e. a free O(1) refusal costed 0 and picked; the shape that CAN cost
        // more than a block is a channel opened before the height, whose `max_steps` the
        // cap never saw: the door refuses it (`settle too costly to propose`), and here it
        // is never picked.
        let pool = [settle(1, 0, 1, MAX_SETTLE_LINKS_PER_BLOCK as u32 + 1)];
        assert_eq!(settle_cost(&st, &h(1), MAX_SETTLE_LINKS_PER_BLOCK as u32 + 1), 0);
        assert_eq!(nonces(&select_batch_txs(&st, pool.iter(), 1024, 0).0), vec![(1, 0)]);
        let mut old = chain_with_channels_of(1, u64::from(u32::MAX));
        old.channels.get_mut(&h(1)).unwrap().state.highest_step_settled = MAX_SETTLE_LINKS_PER_BLOCK - MAX_SETTLE_DELTA + 1;
        assert_eq!(settle_cost(&old, &h(1), MAX_SETTLE_LINKS_PER_BLOCK as u32 + 1), MAX_SETTLE_LINKS_PER_BLOCK + 1);
        assert_eq!(select_batch_txs(&old, pool.iter(), 1024, 0).0.len(), 0);
    }

    #[test]
    fn r18_a_settle_the_chain_refuses_free_costs_nothing_and_an_unknown_channel_costs_its_step() {
        // Unknown channel (its open may be pending ahead of it): `step` links before the
        // height, the fresh-channel cost. The reported shape — u32::MAX — is never picked
        // from a pre-height pool; a small one rides.
        let st = chain_with_channels(1);
        assert_eq!(st.payword_cap_from, u64::MAX, "a bare state never activates");
        let pool = [settle(1, 0, 0x77, u32::MAX), settle(2, 0, 0x77, 10), settle(3, 0, 1, 5)];
        assert_eq!(settle_cost(&st, &h(0x77), u32::MAX), u64::from(u32::MAX));
        let (picked, held) = select_batch_txs(&st, pool.iter(), 1024, 0);
        assert_eq!(nonces(&picked), vec![(2, 0), (3, 0)]);
        assert_eq!(held, 1);
        // From the height the gated delta cap refuses an unknown channel's settle past
        // 2¹⁶ in O(1) once its open lands (and `UnknownChannel` in O(1) if it never does),
        // so the conservative cost is `min(step, MAX_SETTLE_DELTA)`: the same u32::MAX now
        // rides to its free refusal instead of parking. The height tested is the NEXT
        // block's — the block being built.
        let mut at_height = chain_with_channels(1);
        at_height.payword_cap_from = 1;
        assert_eq!(at_height.height, 0);
        assert_eq!(settle_cost(&at_height, &h(0x77), u32::MAX), MAX_SETTLE_DELTA);
        assert_eq!(settle_cost(&at_height, &h(0x77), 10), 10);
        let (picked, held) = select_batch_txs(&at_height, pool.iter(), 1024, 0);
        assert_eq!(nonces(&picked), vec![(1, 0), (2, 0), (3, 0)]);
        assert_eq!(held, 0);
        at_height.payword_cap_from = 2;
        assert_eq!(settle_cost(&at_height, &h(0x77), u32::MAX), u64::from(u32::MAX), "one block short of the height");
        // A stale, over-max or refunded settle on a KNOWN channel is refused by the chain
        // in O(1) before any hashing, and nothing ahead of it in the block can change that
        // — costed 0 (R18 review: the first cut costed it `step` and parked it).
        let mut st = chain_with_channels(2);
        st.channels.get_mut(&h(1)).unwrap().state.highest_step_settled = 100;
        st.channels.get_mut(&h(2)).unwrap().refunded = true;
        assert_eq!(settle_cost(&st, &h(1), 50), 0, "stale");
        assert_eq!(settle_cost(&st, &h(1), u32::MAX), 0, "over max");
        assert_eq!(settle_cost(&st, &h(2), 1), 0, "refunded");
        assert_eq!(settle_cost(&st, &h(1), 101), 101, "one link past the settled step: hashed");
        let pool = [settle(1, 0, 1, 50), settle(2, 0, 1, u32::MAX), settle(3, 0, 2, 1), settle(4, 0, 1, 101)];
        let (picked, held) = select_batch_txs(&st, pool.iter(), 1024, 0);
        assert_eq!(nonces(&picked), vec![(1, 0), (2, 0), (3, 0), (4, 0)]);
        assert_eq!(held, 0);
        // `room` still bounds the batch, and non-settle txs never touch the budget.
        let pool: Vec<SignedTx> = (0..5u64).map(|n| transfer(9, n)).collect();
        let (picked, held) = select_batch_txs(&st, pool.iter(), 3, 0);
        assert_eq!(picked.len(), 3);
        assert_eq!(held, 0);
    }

    #[test]
    fn r18_the_bundle_ahead_of_the_pool_is_costed_into_the_same_budget() {
        // `build_batch` seeds the running total with the P2.3 bundle's settle links
        // (`hk_submitBundle` admits only proof-less pool txs now, so the seed is 0 in
        // practice — belt and braces): with one link of budget left, a one-link settle
        // rides and a two-link settle is held; with the budget already full, nothing
        // costed rides but transfers do.
        let st = chain_with_channels(3);
        let pool = [settle(1, 0, 1, 2), settle(2, 0, 2, 1), transfer(3, 0)];
        let (picked, held) = select_batch_txs(&st, pool.iter(), 1024, MAX_SETTLE_LINKS_PER_BLOCK - 1);
        assert_eq!(nonces(&picked), vec![(2, 0), (3, 0)]);
        assert_eq!(held, 1);
        let (picked, held) = select_batch_txs(&st, pool.iter(), 1024, MAX_SETTLE_LINKS_PER_BLOCK);
        assert_eq!(nonces(&picked), vec![(3, 0)]);
        assert_eq!(held, 2);
        // A seed past the budget (a bundle no door should have let through) saturates
        // rather than wrapping, and still only holds settles.
        let (picked, _) = select_batch_txs(&st, pool.iter(), 1024, u64::MAX);
        assert_eq!(nonces(&picked), vec![(3, 0)]);
    }

    /// v0.19.12: the block byte budget. Fat shields from two senders in pool order, then
    /// a small transfer: the selection takes the longest run that fits `MAX_BATCH_TX_BYTES` and
    /// ENDS at the first tx that does not — the transfer behind the stop waits too — and the
    /// next block resumes exactly there. A bundle already in the block shrinks the room; a full
    /// block of small txs is unaffected (the count binds first); the settle-link holds come
    /// first, as before. KILL: drop the fit check (the seventh 4 MB shield rides past the
    /// budget), or `continue` past it instead of ending the selection (the transfer behind the
    /// stop rides ahead of an earlier tx).
    #[test]
    fn the_block_byte_budget_ends_the_selection_in_pool_order() {
        use crate::batch::{MAX_BATCH_TX_BYTES, MAX_TXS_PER_BLOCK};
        use crate::mempool::tx_encoded_len;
        let st = State::default();
        let fat = |sender: u8, nonce: u64, proof_len: usize| {
            tx(sender, nonce, Tx::MintToPool {
                asset: h(9),
                value: 1,
                commitment: h(6),
                proof: vec![0xAB; proof_len],
                stealth_ct: vec![],
            })
        };
        // 4 MB proofs against the real budget: six fit, the seventh does not
        {
            let pool = vec![
                fat(1, 0, 4_000_000),
                fat(2, 0, 4_000_000),
                fat(1, 1, 4_000_000),
                fat(2, 1, 4_000_000),
                fat(1, 2, 4_000_000),
                fat(2, 2, 4_000_000),
                fat(1, 3, 4_000_000),
                transfer(3, 0),
            ];
            let size = tx_encoded_len(&pool[0]);
            assert_eq!(MAX_BATCH_TX_BYTES / size, 6, "{size} B per fat tx");
            let pick = super::select_batch_txs_sized(&st, pool.iter(), MAX_TXS_PER_BLOCK, 0, 0);
            assert_eq!(nonces(&pick.picked), vec![(1, 0), (2, 0), (1, 1), (2, 1), (1, 2), (2, 2)]);
            assert_eq!(pick.bytes, 6 * size);
            assert!(pick.bytes <= MAX_BATCH_TX_BYTES);
            assert!(pick.byte_budget_full);
            assert_eq!((pick.held, pick.oversize.len()), (0, 0));
        }
        // the same rule on a block whose room a bundle already took down to 100 kB (the
        // bundle's bytes seed the total), with 30 kB shields: the stop, the order, the resume
        let room_left = 100_000;
        let seed = MAX_BATCH_TX_BYTES - room_left;
        let pool = vec![
            fat(1, 0, 30_000),
            fat(2, 0, 30_000),
            fat(1, 1, 30_000),
            fat(2, 1, 30_000),
            transfer(3, 0),
            fat(1, 2, 30_000),
            transfer(3, 1),
        ];
        let size = tx_encoded_len(&pool[0]);
        assert_eq!(room_left / size, 3);
        let pick = super::select_batch_txs_sized(&st, pool.iter(), MAX_TXS_PER_BLOCK, 0, seed);
        assert_eq!(nonces(&pick.picked), vec![(1, 0), (2, 0), (1, 1)]);
        assert!(pick.byte_budget_full);
        assert!(seed + pick.bytes <= MAX_BATCH_TX_BYTES);
        // the rest stays pending, in order: the next block (no bundle) resumes at the stop
        let next = super::select_batch_txs_sized(&st, pool[3..].iter(), MAX_TXS_PER_BLOCK, 0, 0);
        assert_eq!(nonces(&next.picked), vec![(2, 1), (3, 0), (1, 2), (3, 1)]);
        assert!(!next.byte_budget_full);
        // small txs are unaffected: a full block of them, the count binding first
        let small: Vec<SignedTx> = (0..(MAX_TXS_PER_BLOCK as u64 + 10)).map(|n| transfer(4, n)).collect();
        let pick = super::select_batch_txs_sized(&st, small.iter(), MAX_TXS_PER_BLOCK, 0, 0);
        assert_eq!(pick.picked.len(), MAX_TXS_PER_BLOCK);
        assert!(!pick.byte_budget_full);
        // the settle-link hold comes first, as before: with the link budget full a settle is
        // held (not a stop), and the transfer behind it still rides in the bytes left
        let st = chain_with_channels(1);
        let pool = [settle(5, 0, 1, 1), transfer(6, 0)];
        let pick = super::select_batch_txs_sized(&st, pool.iter(), MAX_TXS_PER_BLOCK, MAX_SETTLE_LINKS_PER_BLOCK, seed);
        assert_eq!(nonces(&pick.picked), vec![(6, 0)]);
        assert_eq!(pick.held, 1);
        assert!(!pick.byte_budget_full);
    }

    /// v0.19.12: a tx larger than a whole block's byte budget never blocks the pool: it
    /// is skipped and reported (for `build_batch` to drop), its sender's later tx waits behind
    /// it, and every other sender's txs ride in pool order. Admission and both restore paths
    /// keep such a tx out of the pool; this is the second line. KILL: treat it as a tx that
    /// does not fit (end the selection) and nothing behind it ever rides again.
    #[test]
    fn a_tx_larger_than_any_block_is_skipped_and_reported() {
        use crate::batch::MAX_BATCH_TX_BYTES;
        let st = State::default();
        let huge = tx(1, 0, Tx::MintToPool {
            asset: h(9),
            value: 1,
            commitment: h(6),
            proof: vec![0; MAX_BATCH_TX_BYTES],
            stealth_ct: vec![],
        });
        assert!(crate::mempool::tx_encoded_len(&huge) > MAX_BATCH_TX_BYTES);
        let pool = vec![huge, transfer(1, 1), transfer(2, 0), transfer(2, 1)];
        let pick = super::select_batch_txs_sized(&st, pool.iter(), 1024, 0, 0);
        assert_eq!(nonces(&pick.picked), vec![(2, 0), (2, 1)]);
        assert_eq!(pick.oversize, vec![(h(1), 0)]);
        assert_eq!(pick.held, 0, "not a settle-link hold");
        assert!(!pick.byte_budget_full);
        // the wrapper the other tests use agrees
        assert_eq!(nonces(&select_batch_txs(&st, pool.iter(), 1024, 0).0), vec![(2, 0), (2, 1)]);
    }
}

/// v0.11.2: the kind tag the explorer shows — matches rpc.rs's tx_summary kinds.
fn tx_kind(tx: &hk_state::tx::Tx) -> &'static str {
    use hk_state::tx::Tx;
    match tx {
        Tx::Transfer { .. } => "transfer",
        Tx::MandateCreate { .. } => "mandate_create",
        Tx::MandateSpend { .. } => "mandate_spend",
        Tx::MandateRevoke { .. } => "mandate_revoke",
        Tx::ChannelOpen { .. } => "channel_open",
        Tx::ChannelSettle { .. } => "channel_settle",
        Tx::ChannelRefund { .. } => "channel_refund",
        Tx::MintToPool { .. } => "shield",
        Tx::ShieldedSpend { .. } => "shielded_spend",
        Tx::AccountCreate { .. } => "account_create",
        Tx::AssetRegister { .. } => "asset_register",
        Tx::AssetMint { .. } => "asset_mint",
        Tx::AssetBurn { .. } => "asset_burn",
        Tx::AssetFreeze { .. } => "asset_freeze",
        Tx::AssetPause { .. } => "asset_pause",
    }
}

/// v0.11.2: the transaction's primary counterparty (indexed alongside the sender so
/// an account's history includes payments RECEIVED, not just sent).
fn tx_counterparty(tx: &hk_state::tx::Tx) -> Option<hk_primitives::AccountId> {
    use hk_state::tx::Tx;
    match tx {
        Tx::Transfer { to, .. } => Some(*to),
        Tx::MandateSpend { to, .. } => Some(*to),
        Tx::ChannelOpen { payee, .. } => Some(*payee),
        Tx::AccountCreate { id, .. } => Some(*id),
        Tx::ShieldedSpend { credit, .. } => *credit,
        // X1: a mint reaches `to`; a freeze names the account it acts on.
        Tx::AssetMint { to, .. } => Some(*to),
        Tx::AssetFreeze { account, .. } => Some(*account),
        // HR-5 (v0.19.12): a mandate's designated holder — the account that spends from that
        // node and delegates under it — is indexed in its own history, so an agent (or a
        // root holder who is not the funder) finds the mandate it was handed. A node-local
        // index: it covers blocks committed or replayed by a node running this version, not
        // an `index3.bin` restored from an earlier one.
        Tx::MandateCreate { holder, .. } => Some(*holder),
        _ => None,
    }
}

#[cfg(test)]
mod hr5_tests {
    use super::tx_counterparty;
    use hk_primitives::H256;
    use hk_state::tx::Tx;

    /// HR-5 (v0.19.12): a mandate's designated holder is a counterparty of its `MandateCreate`,
    /// for a root and a child alike; the other kinds are unchanged. KILL: remove the
    /// `Tx::MandateCreate { holder, .. }` arm of `tx_counterparty` and the first two
    /// assertions see `None`.
    #[test]
    fn hr5_a_mandate_create_indexes_its_holder() {
        let holder = H256([0x42; 32]);
        let mk = |parent| Tx::MandateCreate {
            id: H256([1; 32]), parent, holder, asset: H256([9; 32]), rate_per_sec: 0, buffer_max: 1,
            per_tx_max: 1, initial_buffer: 1, expiry: 1, tier: 0,
        };
        assert_eq!(tx_counterparty(&mk(None)), Some(holder));
        assert_eq!(tx_counterparty(&mk(Some(H256([2; 32])))), Some(holder));
        assert_eq!(tx_counterparty(&Tx::MandateRevoke { target: H256([1; 32]) }), None);
        assert_eq!(tx_counterparty(&Tx::Transfer { to: holder, asset: H256([9; 32]), amount: 1 }), Some(holder));
    }
}

/// R12: the per-validator rotation threshold, in leaves. Seats whose trees start
/// together cross a fixed 20% line together (testnet-1, 2026-09-03: all four
/// rotated within eleven blocks of each other), so a rotation-path bug would hit
/// every seat in the same minute. Each seat therefore rotates somewhere in
/// [15%, 25%] of its capacity, the exact point derived from its (public, permanent)
/// root key — deterministic across restarts, different per seat, reproducible by
/// anyone. `capacity * 1500..=2500 / 10000`.
impl HkApp {
    /// R15b: remember when this node committed a height (the pacing reference).
    pub fn note_decided(&mut self) {
        self.last_decided_at = std::time::Instant::now();
    }

    /// R15b: how long a round-0 proposer should wait before building, so that consecutive
    /// blocks are at least `min_block_interval` apart on this node's clock. Zero for rounds
    /// > 0 (liveness first) and never more than half the engine's propose timeout.
    pub fn propose_wait(&self, round: Round, timeout: std::time::Duration) -> std::time::Duration {
        if round != Round::new(0) || self.min_block_interval.is_zero() {
            return std::time::Duration::ZERO;
        }
        let want = self.min_block_interval.saturating_sub(self.last_decided_at.elapsed());
        want.min(timeout / 2)
    }
}

pub fn rotation_threshold(capacity: u64, root_pk: &[u8]) -> u64 {
    let h = hk_crypto::hash::shake256_32("hk/v1/rotation-jitter", &[root_pk]);
    let jitter = u16::from_le_bytes([h[0], h[1]]) as u64 % 1001; // 0..=1000 → 15.00%..25.00%
    capacity.saturating_mul(1500 + jitter) / 10_000
}

fn rotation_due(
    remaining: u64,
    threshold: u64,
    height: u64,
    rotate_every: Option<u64>,
    mine_pending: bool,
    next_epoch: u64,
    highest_issued: u64,
    issue_stale: bool,
) -> (bool, bool) {
    let threshold_hit = remaining < threshold;
    let interval_hit = rotate_every.is_some_and(|n| height > 0 && height % n == 0);
    // R9: the pending/already-issued guards only hold while a previous issue is
    // FRESH. Once stale (or after a restart), a trigger fires again — a lost cert
    // must never wedge a validator into burning its tree to zero (val-0, 2026-09-02).
    let guards_pass = (!mine_pending && next_epoch > highest_issued) || issue_stale;
    let due = (threshold_hit || interval_hit) && guards_pass;
    (due, threshold_hit)
}

#[cfg(test)]
mod rotation_trigger_tests {
    use super::{rotation_due, rotation_threshold};
    const CAP: u64 = 32_768; // hk_crypto::hashsig::CONSENSUS_CAPACITY

    #[test]
    fn fresh_tree_never_rotates_without_interval() {
        // The staging fleet's pre-incident config (no env) must now be SAFE by default:
        for h in [1u64, 500, 10_848] {
            assert_eq!(rotation_due(CAP, CAP / 5, h, None, false, 1, 0, false), (false, false));
        }
    }

    #[test]
    fn threshold_fires_below_twenty_percent_regardless_of_height() {
        // 20% of 32,768 = 6,553; the incident's tree would have triggered ~2.2K
        // heights (>1 hour) before the halt instead of dying at leaf zero.
        assert_eq!(rotation_due(6_552, CAP / 5, 10_777, None, false, 1, 0, false), (true, true));
        assert_eq!(rotation_due(6_553, CAP / 5, 10_777, None, false, 1, 0, false), (false, false));
        assert_eq!(rotation_due(0, CAP / 5, 3, None, false, 1, 0, false), (true, true));
    }

    #[test]
    fn r1b_tick_shape_threshold_fires_without_a_height() {
        // R1.b calls rotation_due with height=0 and no interval override — a node
        // that never commits must still fire the SAME leaf-budget clause…
        assert_eq!(rotation_due(6_552, CAP / 5, 0, None, false, 1, 0, false), (true, true));
        assert_eq!(rotation_due(6_553, CAP / 5, 0, None, false, 1, 0, false), (false, false));
        // …must not re-issue when the next epoch is already in flight
        // (threshold still reports hit — the gauge is honest, the action is gated)…
        assert_eq!(rotation_due(6_552, CAP / 5, 0, None, true, 1, 0, false), (false, true));
        // …and must not re-issue an epoch it already issued.
        assert_eq!(rotation_due(6_552, CAP / 5, 0, None, false, 1, 1, false), (false, true));
    }

    #[test]
    fn interval_override_still_works() {
        assert_eq!(rotation_due(CAP, CAP / 5, 500, Some(500), false, 1, 0, false), (true, false));
        assert_eq!(rotation_due(CAP, CAP / 5, 501, Some(500), false, 1, 0, false), (false, false));
        assert_eq!(rotation_due(CAP, CAP / 5, 0, Some(500), false, 1, 0, false), (false, false));
    }

    #[test]
    fn r9_stale_issue_rearms_wedged_guards() {
        // The val-0 wedge (2026-09-02): threshold screaming, but a snapshot-restored
        // highest_issued (and/or a stale pending cert) gated issuance forever.
        // FRESH issue (stale=false): guards hold exactly as before…
        assert_eq!(rotation_due(10, CAP / 5, 100, None, true, 4, 4, false), (false, true));
        assert_eq!(rotation_due(10, CAP / 5, 100, None, false, 4, 4, false), (false, true));
        // …STALE issue (or fresh boot): the same trigger fires through both guards.
        assert_eq!(rotation_due(10, CAP / 5, 100, None, true, 4, 4, true), (true, true));
        assert_eq!(rotation_due(10, CAP / 5, 100, None, false, 4, 7, true), (true, true));
        // Staleness alone never fires without a trigger — a healthy budget stays quiet.
        assert_eq!(rotation_due(CAP, CAP / 5, 100, None, false, 4, 4, true), (false, false));
    }

    #[test]
    fn guards_suppress_double_issue() {
        // Our cert already pending → never re-issue, however low the budget runs.
        assert_eq!(rotation_due(10, CAP / 5, 100, None, true, 1, 0, false), (false, true));
        // Epoch already issued (e.g. included but we replayed past the bookkeeping).
        assert_eq!(rotation_due(10, CAP / 5, 100, None, false, 1, 1, false), (false, true));
        // After the rotation applies (fresh tree, epoch advanced), the cycle re-arms.
        assert_eq!(rotation_due(CAP, CAP / 5, 101, None, false, 2, 1, false), (false, false));
        assert_eq!(rotation_due(6_000, CAP / 5, 200, None, false, 2, 1, false), (true, true));
    }

    #[test]
    fn r12_threshold_is_per_seat_inside_15_to_25_percent() {
        // Four seats keyed together must NOT share a threshold; every threshold sits
        // in [15%, 25%] of capacity; the same key always yields the same threshold.
        let seats: Vec<Vec<u8>> = (0u8..4).map(|i| vec![i; 48]).collect();
        let ts: Vec<u64> = seats.iter().map(|pk| rotation_threshold(CAP, pk)).collect();
        for t in &ts {
            assert!(*t >= CAP * 15 / 100 && *t <= CAP * 25 / 100, "threshold {t} outside 15–25%");
        }
        let mut uniq = ts.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), ts.len(), "seats collided on a threshold: {ts:?}");
        assert_eq!(rotation_threshold(CAP, &seats[0]), ts[0]);
        // The trigger honours the per-seat line, not the old 20% constant.
        let t = ts[0];
        assert_eq!(rotation_due(t - 1, t, 0, None, false, 1, 0, false), (true, true));
        assert_eq!(rotation_due(t, t, 0, None, false, 1, 0, false), (false, false));
    }
}

#[cfg(test)]
mod r11_process_tests {
    use super::{rss_from_statm, set_verifier_init_ms, verifier_init_ms};

    #[test]
    #[cfg(unix)]
    fn v0_19_4_disk_free_bytes_answers_for_a_real_dir_and_not_for_a_missing_one() {
        let here = std::env::temp_dir();
        let free = super::disk_free_bytes(&here).expect("temp dir has a filesystem");
        assert!(free > 0, "a writable temp dir must report free space");
        let missing = here.join(format!("hk_no_such_dir_{}", std::process::id()));
        assert_eq!(super::disk_free_bytes(&missing), None);
    }

    #[test]
    fn r11_rss_is_read_from_statm_pages() {
        // "size resident shared text lib data dt" — resident is field 2, in pages.
        assert_eq!(rss_from_statm("123456 4096 300 10 0 2000 0\n", 4096), Some(4096 * 4096));
        assert_eq!(rss_from_statm("1 1", 16384), Some(16384));
        // a kernel line we cannot parse, or a bogus page size, is "unknown" — never a number
        assert_eq!(rss_from_statm("garbage", 4096), None);
        assert_eq!(rss_from_statm("1 x 3", 4096), None);
        assert_eq!(rss_from_statm("1 2 3", 0), None);
        assert_eq!(rss_from_statm("1 2 3", -1), None);
    }

    #[test]
    fn r11_verifier_init_is_recorded_once() {
        // None before the verifier is wired (a CLI subcommand never sets it)…
        let before = verifier_init_ms();
        set_verifier_init_ms(7);
        // …then the first value sticks; a second wiring attempt cannot overwrite it.
        set_verifier_init_ms(9_999);
        assert_eq!(verifier_init_ms(), Some(before.unwrap_or(7)));
    }
}

/// HR-1 (mr-hrydarie, reported 2026-11-04, confirmed 2026-11-08; v0.19.11), E4: the commit
/// prune is receipt-aware. `apply_batch_to_chain` needs an `HkApp` (a genesis, a signer, a
/// store), so the split it runs — `commit_prune_sets` and `CommitPrune::prune_mempool`, the
/// very code it calls — is driven here over blocks applied through `State::apply_block` on the
/// shared fixture (`mempool::test_fixtures`).
#[cfg(test)]
mod hr1_tests {
    use super::commit_prune_sets;
    use crate::batch::txid;
    use crate::mempool::test_fixtures::*;
    use crate::mempool::Mempool;

    /// Kill: make `commit_prune_sets` push a refused tx's slot into `applied` (the pre-v0.19.11
    /// split, where every block tx's slot was pruned whatever its receipt), or make
    /// `prune_mempool` run `remove_included(&self.included)` — and the honest (1, 0) is gone in
    /// the first scenario (`prune_mempool` returns (2, 0), not (1, 0)); the second scenario
    /// asserts that eviction on `included` directly.
    #[test]
    fn hr1_e4_a_refused_twin_prunes_nothing_and_an_applied_tx_prunes_its_slot() {
        let mut chain = mini_chain(2);
        let mut mp = Mempool::new(16);
        // pending: the victim's honest tx at (1, 0) with txid Y, and a copy of (2, 0)
        let honest = transfer(1, 0);
        let y = mp.try_admit(honest.clone(), &chain).expect("admits");
        let two = transfer(2, 0);
        let two_id = mp.try_admit(two.clone(), &chain).expect("admits");
        assert_eq!(mp.len(), 2);
        // the block: a wrong-key twin at (1, 0) → an Err receipt; (2, 0) → an Ok receipt
        let twin = sign_as(1, 2, 0, transfer_payload(5));
        assert_ne!(txid(&twin), y);
        let block = vec![twin.clone(), two.clone()];
        let receipts = chain.apply_block(1, 0, &block).expect("block applies");
        assert!(receipts[0].result.is_err(), "{:?}", receipts[0].result);
        assert!(receipts[1].result.is_ok(), "{:?}", receipts[1].result);
        assert_eq!(chain.accounts[&acct(1)].nonce, 0, "a refusal ratchets no nonce");
        assert_eq!(chain.accounts[&acct(2)].nonce, 1);
        // the split
        let p = commit_prune_sets(&block, &receipts);
        assert_eq!(p.included, vec![(acct(1), 0), (acct(2), 0)], "the bundle retain's input: every block tx");
        assert_eq!(p.applied, vec![(acct(2), 0)]);
        assert_eq!(p.refused, vec![((acct(1), 0), txid(&twin))]);
        assert_eq!(p.log.len(), 2);
        assert_eq!(p.log[0].0, txid(&twin));
        assert!(p.log[0].1.starts_with("rejected: "), "{}", p.log[0].1);
        assert_eq!(p.log[1].0, two_id);
        assert!(p.log[1].1.starts_with("ok: "), "{}", p.log[1].1);
        // the commit path's two prunes: the honest (1, 0) stays, (2, 0) is gone
        assert_eq!(p.prune_mempool(&mut mp), (1, 0));
        assert_eq!(mp.len(), 1);
        assert_eq!(mp.iter().map(txid).collect::<Vec<_>>(), vec![y]);
        // the same through the explicit pair the method stands for
        let fresh = mini_chain(2);
        let mut mp2 = Mempool::new(16);
        mp2.try_admit(honest.clone(), &fresh).unwrap();
        mp2.try_admit(two.clone(), &fresh).unwrap();
        assert_eq!(mp2.remove_included(&p.applied), 1);
        assert_eq!(mp2.remove_refused(&p.refused), 0);
        assert_eq!(mp2.iter().map(txid).collect::<Vec<_>>(), vec![y]);
        // scenario 2 — the pre-v0.19.11 prune, `remove_included(&included)`, evicts the honest tx
        let mut old = Mempool::new(16);
        old.try_admit(honest.clone(), &fresh).unwrap();
        old.try_admit(two, &fresh).unwrap();
        assert_eq!(old.remove_included(&p.included), 2, "the eviction axis: the honest tx goes with the twin");
        assert_eq!(old.len(), 0);
        // the honest tx still applies on the chain the block advanced
        let receipts = chain.apply_block(2, 0, &[honest]).expect("block applies");
        assert!(receipts[0].result.is_ok(), "{:?}", receipts[0].result);
        assert_eq!(chain.accounts[&acct(1)].nonce, 1);
    }

    /// Kill: the same reversion on the HR-1 frame itself — twins under the account's OWN key
    /// that die at dispatch: put a refused slot into `applied` (or prune `included`) and the
    /// honest tx is evicted (`prune_mempool` returns (1, 0), not (0, 0)). Pins the receipt a
    /// refused bundle tx leaves: Err, the fee refunded, the nonce not ratcheted.
    #[test]
    fn hr1_e4_own_key_twins_refused_at_dispatch_leave_the_honest_tx_pending() {
        let mut chain = mini_chain_with_fee(1, 100);
        assert_eq!(chain.balance(&acct(1), &hk_state::FEE_ASSET), 1_000);
        let mut mp = Mempool::new(16);
        let honest = transfer(1, 0);
        let y = mp.try_admit(honest.clone(), &chain).expect("admits");
        // two twins under the account's own key at (1, 0): a transfer above the balance and a
        // proof-less spend with no aggregate coverage — both pass the envelope, both die at dispatch
        let broke = sign_at(1, 0, transfer_payload(5_000));
        let uncovered = sign_at(1, 0, spend_payload(anchor(&chain), 0x10));
        let block = vec![broke.clone(), uncovered.clone()];
        let receipts = chain.apply_block(1, 0, &block).expect("block applies");
        let reason = |i: usize| receipts[i].result.as_ref().unwrap_err().clone();
        assert!(reason(0).contains("insufficient balance"), "{}", reason(0));
        assert!(reason(1).contains("pool proof rejected"), "{}", reason(1));
        // the refusals cost nothing: the fee came back, the nonce did not move
        assert_eq!(chain.accounts[&acct(1)].nonce, 0);
        assert_eq!(chain.balance(&acct(1), &hk_state::FEE_ASSET), 1_000);
        assert_eq!(chain.balance(&acct(1), &ASSET), 1_000);
        let p = commit_prune_sets(&block, &receipts);
        assert!(p.applied.is_empty());
        assert_eq!(p.refused, vec![((acct(1), 0), txid(&broke)), ((acct(1), 0), txid(&uncovered))]);
        assert_eq!(p.included, vec![(acct(1), 0), (acct(1), 0)]);
        assert!(p.log.iter().all(|(_, d)| d.starts_with("rejected: ")));
        assert_eq!(p.prune_mempool(&mut mp), (0, 0));
        assert_eq!(mp.iter().map(txid).collect::<Vec<_>>(), vec![y]);
        // the honest tx applies in the next block, paying the fee once
        let receipts = chain.apply_block(2, 0, &[honest]).expect("block applies");
        assert!(receipts[0].result.is_ok(), "{:?}", receipts[0].result);
        assert_eq!(chain.accounts[&acct(1)].nonce, 1);
        assert_eq!(chain.balance(&acct(1), &hk_state::FEE_ASSET), 900);
        assert_eq!(chain.balance(&acct(1), &ASSET), 999);
    }
}

/// v0.19.12: another node's value enters the store of undecided values from a proposal whose
/// signature the engine verified. `admit_signed_value` is the whole rule and is pure, so it is
/// driven here on a plain map, with `find_value_in_height` (the restream's lookup) and
/// `proposal_stream` (the frames this node sends). The engine's side (a verified proposal is
/// handed to the host, one that fails verification is not; the value is written to the WAL
/// when it completes its proposal) is tested in hk-consensus: `tests/r8_claims.rs` and
/// `src/provider.rs`.
///
/// Run: `cargo test --offline -p hk-node signed_value -- --nocapture`
#[cfg(test)]
mod signed_value_tests {
    use std::collections::BTreeMap;

    use bytes::Bytes;
    use hk_consensus::{HkAddress, HkContext, HkHeight, HkProposalPart, HkValue, HkValueId};
    use malachitebft_app_channel::app::streaming::StreamContent;
    use malachitebft_app_channel::app::types::core::{Round, Validity};
    use malachitebft_app_channel::app::types::{LocallyProposedValue, ProposedValue};

    use super::{
        admit_signed_value, find_value_in_height, proposal_stream, ValueRefusal,
        MAX_PROPOSAL_BYTES, MAX_VALUES_PER_ROUND,
    };

    type Store = BTreeMap<(u64, i64), Vec<ProposedValue<HkContext>>>;

    /// The height the node under test is at.
    const H: u64 = 41;

    fn addr(b: u8) -> HkAddress {
        HkAddress::new([b; 20])
    }

    fn candidate(
        height: u64,
        round: Round,
        valid_round: Round,
        proposer: HkAddress,
        value: HkValue,
    ) -> ProposedValue<HkContext> {
        ProposedValue {
            height: HkHeight::new(height),
            round,
            valid_round,
            proposer,
            value,
            validity: Validity::Valid,
        }
    }

    /// What an honest proposer signs: a fresh value whose id is the hash of its bytes.
    fn honest(height: u64, round: u32, proposer: HkAddress, txs: &'static [u8]) -> ProposedValue<HkContext> {
        candidate(height, Round::new(round), Round::Nil, proposer, HkValue::new(Bytes::from_static(txs)))
    }

    fn held(store: &Store, height: u64, round: i64) -> usize {
        store.get(&(height, round)).map_or(0, |vs| vs.len())
    }

    /// The honest case: the value is kept, and the answer carries the bytes, the id of those
    /// bytes, and the proposal's own round, proof-of-lock round and proposer.
    #[test]
    fn signed_value_is_kept_and_answered_with_the_id_of_its_bytes() {
        let mut store = Store::new();
        let v = HkValue::new(Bytes::from_static(b"batch"));
        let got = admit_signed_value(&mut store, H, honest(H, 0, addr(7), b"batch")).expect("kept");
        assert_eq!(got.value.id(), v.id());
        assert_eq!(got.value.txs, v.txs);
        assert_eq!(got.height, HkHeight::new(H));
        assert_eq!(got.round, Round::new(0));
        assert_eq!(got.valid_round, Round::Nil);
        assert_eq!(got.proposer, addr(7));
        assert_eq!(got.validity, Validity::Valid);
        assert_eq!(held(&store, H, 0), 1);
        assert_eq!(store[&(H, 0)][0].value.id(), v.id());
        assert_eq!(store[&(H, 0)][0].proposer, addr(7));
    }

    /// The second line behind the engine's check: a value whose id is not the hash of its bytes
    /// is refused, nothing is kept, and no slot is created. Kill: drop the `IdMismatch` check
    /// and this value is stored.
    #[test]
    fn signed_value_whose_id_is_not_the_hash_of_its_bytes_is_refused_and_nothing_is_kept() {
        let mut store = Store::new();
        let mut mismatched = HkValue::new(Bytes::from_static(b"the bytes"));
        mismatched.id = HkValue::new(Bytes::from_static(b"other bytes")).id();
        let got = admit_signed_value(&mut store, H, candidate(H, Round::new(0), Round::Nil, addr(7), mismatched));
        assert!(matches!(got, Err(ValueRefusal::IdMismatch)));
        assert!(store.is_empty(), "no slot is created by a refusal");
        assert!(!ValueRefusal::IdMismatch.is_routine(), "no honest proposer signs this");
    }

    /// Each round holds at most `MAX_VALUES_PER_ROUND` values of its own, and a later round of
    /// the height takes its own proposer's value.
    #[test]
    fn signed_values_are_bounded_per_round() {
        let mut store = Store::new();
        let names: [&'static [u8]; 4] = [b"w", b"x", b"y", b"z"];
        for round in 1..=20u32 {
            for txs in names.iter().take(MAX_VALUES_PER_ROUND) {
                admit_signed_value(&mut store, H, honest(H, round, addr(round as u8), txs)).expect("kept");
            }
        }
        assert_eq!(held(&store, H, 0), 0);
        let got = admit_signed_value(&mut store, H, honest(H, 0, addr(7), b"the round-0 value"));
        assert!(got.is_ok(), "round 0 takes its proposer's value");
        assert_eq!(held(&store, H, 0), 1);

        let far = admit_signed_value(&mut store, H, honest(H, 400, addr(9), b"far ahead"));
        assert!(far.is_ok(), "a later round of the height takes its value");
        assert_eq!(held(&store, H, 400), 1);
    }

    /// A proposer who signs several values for one round: they are kept up to the bound, so
    /// the engine can follow whichever the network locks on, and no further. A value already
    /// held is still answered when the slot is full.
    #[test]
    fn signed_values_of_an_equivocating_proposer_are_kept_up_to_the_bound() {
        assert!(MAX_VALUES_PER_ROUND >= 2, "both values of an equivocation must fit");
        let mut store = Store::new();
        let p = addr(7);
        let names: [&'static [u8]; 6] = [b"a", b"b", b"c", b"d", b"e", b"f"];
        for (i, txs) in names.iter().enumerate() {
            let got = admit_signed_value(&mut store, H, honest(H, 0, p, txs));
            if i < MAX_VALUES_PER_ROUND {
                assert!(got.is_ok(), "value {i} is kept");
            } else {
                assert!(matches!(got, Err(ValueRefusal::SlotFull)), "value {i} is past the bound");
            }
        }
        assert_eq!(held(&store, H, 0), MAX_VALUES_PER_ROUND);
        assert!(!ValueRefusal::SlotFull.is_routine());

        let again = admit_signed_value(&mut store, H, honest(H, 0, p, b"a")).expect("a held value is answered");
        assert_eq!(again.value.txs.as_ref(), b"a");
        assert_eq!(again.validity, Validity::Valid);
        assert_eq!(held(&store, H, 0), MAX_VALUES_PER_ROUND, "and is not stored twice");
    }

    /// The same proposal again (a republished copy) is answered from the store without a
    /// second entry, as a VALID value that carries the candidate's own proof-of-lock round and
    /// proposer. A copy that carries a held id over OTHER bytes is answered with the held bytes:
    /// the stored bytes are the ones that id names. Kill: answer `Validity::Invalid` from the
    /// shortcut and the `Validity::Valid` assertions fail.
    #[test]
    fn signed_value_with_a_held_id_is_answered_with_the_held_bytes() {
        let mut store = Store::new();
        let p = addr(7);
        let good = HkValue::new(Bytes::from_static(b"good"));
        admit_signed_value(&mut store, H, honest(H, 0, p, b"good")).expect("kept");

        let same = admit_signed_value(
            &mut store,
            H,
            candidate(H, Round::new(0), Round::new(0), addr(8), good.clone()),
        )
        .expect("answered");
        assert_eq!(same.value.txs.as_ref(), b"good");
        assert_eq!(same.validity, Validity::Valid);
        assert_eq!(same.valid_round, Round::new(0), "the candidate's proof-of-lock round");
        assert_eq!(same.proposer, addr(8), "the candidate's proposer");
        assert_eq!(held(&store, H, 0), 1);

        let mut mismatched = HkValue::new(Bytes::from_static(b"other bytes"));
        mismatched.id = good.id();
        let got = admit_signed_value(&mut store, H, candidate(H, Round::new(0), Round::Nil, p, mismatched))
            .expect("answered from the store");
        assert_eq!(got.value.id(), good.id());
        assert_eq!(got.value.txs.as_ref(), b"good", "the stored bytes, not the ones this copy carried");
        assert_eq!(got.validity, Validity::Valid);
        assert_eq!(held(&store, H, 0), 1);
    }

    /// Only the node's own height is taken, and never round Nil. A proposal for a height
    /// already committed is the routine case (the engine was still closing it); one for a
    /// later height is not expected at all, because the engine keeps such a proposal in its
    /// buffer until that height starts.
    #[test]
    fn signed_value_is_kept_for_the_current_height_only() {
        let p = addr(7);
        let mut store = Store::new();
        let below = admit_signed_value(&mut store, H, honest(H - 1, 0, p, b"late"));
        assert!(matches!(below, Err(ValueRefusal::BelowOurHeight)));
        let above = admit_signed_value(&mut store, H, honest(H + 1, 0, p, b"early"));
        assert!(matches!(above, Err(ValueRefusal::AboveOurHeight)));
        let nil = admit_signed_value(
            &mut store,
            H,
            candidate(H, Round::Nil, Round::Nil, p, HkValue::new(Bytes::from_static(b"nil"))),
        );
        assert!(matches!(nil, Err(ValueRefusal::RoundNil)));
        assert!(store.is_empty(), "none of the three left anything");

        assert!(ValueRefusal::BelowOurHeight.is_routine());
        assert!(!ValueRefusal::AboveOurHeight.is_routine());
        assert!(!ValueRefusal::RoundNil.is_routine());
        assert!(!ValueRefusal::OverByteCap.is_routine());
    }

    /// A value over the byte cap is refused before it is hashed (the id below is not its hash,
    /// and the refusal is the cap, not the id).
    #[test]
    fn signed_value_over_the_byte_cap_is_refused_before_it_is_hashed() {
        let mut store = Store::new();
        let big = HkValue {
            id: HkValueId::new([0u8; 32]),
            txs: Bytes::from(vec![0u8; MAX_PROPOSAL_BYTES + 1]),
        };
        let got = admit_signed_value(&mut store, H, candidate(H, Round::new(0), Round::Nil, addr(7), big));
        assert!(matches!(got, Err(ValueRefusal::OverByteCap)));
        assert!(store.is_empty());
    }

    /// A re-proposal (a value locked in round 0, proposed again in round 2) that reaches this
    /// node without the earlier round is kept under the round of the proposal that carried it,
    /// with its proof-of-lock round.
    #[test]
    fn signed_value_of_a_re_proposal_is_kept_under_its_own_round_with_its_valid_round() {
        let mut store = Store::new();
        let v = HkValue::new(Bytes::from_static(b"locked"));
        let got = admit_signed_value(&mut store, H, candidate(H, Round::new(2), Round::new(0), addr(9), v.clone()))
            .expect("kept");
        assert_eq!(got.round, Round::new(2));
        assert_eq!(got.valid_round, Round::new(0));
        assert_eq!(got.value.id(), v.id());
        assert_eq!(held(&store, H, 2), 1);
        assert_eq!(held(&store, H, 0), 0);
    }

    /// The restream's lookup: a value held under round 0 only is found for a restream that
    /// names rounds 1 and 2 (the engine completed the round-1 re-proposal by itself, so the
    /// host was never asked to store the value under round 1). Another height and an unknown
    /// id find nothing. Kill: look under the two rounds a restream names and the first
    /// assertion fails — seats on older releases would get no stream for that re-proposal.
    #[test]
    fn signed_value_is_found_for_a_restream_under_any_round_of_the_height() {
        let mut store = Store::new();
        let v = HkValue::new(Bytes::from_static(b"locked"));
        admit_signed_value(&mut store, H, honest(H, 0, addr(7), b"locked")).expect("kept under round 0");
        admit_signed_value(&mut store, H, honest(H, 3, addr(8), b"another value")).expect("kept under round 3");

        let found = find_value_in_height(&store, H, v.id()).expect("found under round 0");
        assert_eq!(found.value.txs.as_ref(), b"locked");
        assert_eq!(found.round, Round::new(0));

        assert!(find_value_in_height(&store, H + 1, v.id()).is_none(), "another height");
        assert!(find_value_in_height(&store, H - 1, v.id()).is_none(), "another height");
        let unknown = HkValue::new(Bytes::from_static(b"never proposed")).id();
        assert!(find_value_in_height(&store, H, unknown).is_none(), "an id nobody proposed");
    }

    /// The stream this node SENDS names the proposer it is given: its own address when it
    /// proposes, the signer of the proposal when it restreams. The frames are an Init, one
    /// batch, a Fin with the value id, and the end of the stream.
    #[test]
    fn signed_value_stream_names_the_proposer_it_is_given() {
        let value = HkValue::new(Bytes::from_static(b"batch"));
        let lpv = LocallyProposedValue {
            height: HkHeight::new(H),
            round: Round::new(2),
            value: value.clone(),
        };
        let msgs = proposal_stream(lpv, Round::new(0), addr(9));
        assert_eq!(msgs.len(), 4);
        match &msgs[0].content {
            StreamContent::Data(HkProposalPart::Init(init)) => {
                assert_eq!(init.proposer, addr(9));
                assert_eq!(init.height, HkHeight::new(H));
                assert_eq!(init.round, Round::new(2));
                assert_eq!(init.pol_round, Round::new(0));
            }
            _ => panic!("the first frame is the Init"),
        }
        match &msgs[1].content {
            StreamContent::Data(HkProposalPart::TxBatch(batch)) => assert_eq!(batch.as_ref(), b"batch"),
            _ => panic!("the second frame is the batch"),
        }
        match &msgs[2].content {
            StreamContent::Data(HkProposalPart::Fin(fin)) => assert_eq!(fin.value_id, value.id()),
            _ => panic!("the third frame is the Fin"),
        }
        assert!(matches!(msgs[3].content, StreamContent::Fin));
        assert!(msgs.iter().all(|m| m.stream_id == msgs[0].stream_id));
    }
}
