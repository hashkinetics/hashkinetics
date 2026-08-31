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
use tracing::{error, info, warn};

use malachitebft_app_channel::app::streaming::{StreamContent, StreamId, StreamMessage};
use malachitebft_app_channel::app::types::core::{CommitCertificate, Round, Validity, VoteExtensions};
use malachitebft_app_channel::app::types::{LocallyProposedValue, PeerId, ProposedValue};
use malachitebft_core_types::Height as _;

use hk_consensus::{
    op_seed, HkAddress, HkContext, HkHeight, HkPriv, HkProposalFin, HkProposalInit, HkProposalPart,
    HkValidatorSet, HkValue, RootSecret, RotationCert,
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
use crate::streaming::PartStreamsMap;
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
    /// Deterministic chain clock epoch (block time = chain_start_time + height).
    pub chain_start_time: u64,
    /// C2.3: tx-gossip enqueue handle (`None` = gossip off; node.rs wires it when
    /// `hk_rpc.gossip_peers` is non-empty).
    pub gossip: Option<crate::gossip::GossipHandle>,
    /// R2: foreign rotation certs queued by `hk_submitRotation` — an exhausted validator
    /// can't propose its own revival cert, so any peer accepts + carries it.
    pub foreign_rotations: Arc<Mutex<Vec<RotationCert>>>,
    /// R4: (epoch, remaining-leaves) of this node's live consensus signer.
    pub signer_gauge: Arc<Mutex<(u64, u64)>>,
}

/// Bounded map of txid -> human receipt string ("ok: ..." / "rejected: ...").
pub struct ReceiptLog {
    map: HashMap<[u8; 32], String>,
    order: VecDeque<[u8; 32]>,
    cap: usize,
}

impl ReceiptLog {
    fn new(cap: usize) -> Self {
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

pub struct DecidedEntry {
    pub value: HkValue,
    pub certificate: CommitCertificate<HkContext>,
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
    /// P2.3: pending aggregation bundles (proof-less pool txs + ONE aggregate STARK);
    /// the proposer includes a whole bundle per block.
    pub bundles: Arc<Mutex<Vec<(Vec<SignedTx>, Vec<u8>)>>>,
    /// P2.3: aggregate verifier + (spend, mint) vk hashes.
    agg: Option<(AggVerifyFn, [u32; 8], [u32; 8])>,
    chain_id: String,
    /// Genesis-gate: SHA-256(genesis.json). `set_genesis_digest` binds chain_id to it.
    genesis_digest: [u8; 32],
    chain_start_time: u64,

    pub current_height: HkHeight,
    pub current_round: Round,
    pub current_proposer: Option<HkAddress>,

    streams: PartStreamsMap,
    undecided: BTreeMap<(u64, i64), Vec<ProposedValue<HkContext>>>,
    pub decided: BTreeMap<u64, DecidedEntry>,

    // ---- SCMS operational-key rotation ----
    /// This validator's 32-byte master seed (derives root + every operational tree).
    master_seed: [u8; 32],
    /// Stateless SLH-DSA root that signs our rotation certificates.
    root: RootSecret,
    /// Our root public key (matches our entry in the validator set).
    my_root_pk: Vec<u8>,
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
    /// Certs we've issued but not yet seen committed (included when we next propose).
    pending_rotations: Vec<RotationCert>,
    /// R2: root-signed certs submitted by OTHER validators via `hk_submitRotation` —
    /// an exhausted validator can't propose its own revival, so peers carry it.
    /// Shared with the RPC server; drained (validated) into every batch we build.
    foreign_rotations: Arc<Mutex<Vec<RotationCert>>>,
    /// R4: (epoch, remaining-leaves) of OUR live signer, refreshed every commit — the RPC
    /// serves it so operators watch the fuse instead of discovering it at zero.
    signer_gauge: Arc<Mutex<(u64, u64)>>,
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
        // HK-R6: seed the shared set history — the genesis set verifies from height 1.
        // (restore_from_store reseeds at the snapshot; rotations append as they commit.)
        {
            let mut hist = set_history.lock().unwrap_or_else(|e| e.into_inner());
            hist.clear();
            hist.push((1, validators.clone()));
        }
        let mut chain = hk_state::State::from_genesis(&genesis.chain_genesis())
            .map_err(|e| eyre!("chain genesis: {e}"))?;
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
        Ok(Self {
            address,
            validators: Arc::new(Mutex::new(validators)),
            chain: Arc::new(Mutex::new(chain)),
            mempool: Arc::new(Mutex::new(crate::mempool::Mempool::default())),
            receipts: Arc::new(Mutex::new(ReceiptLog::new(4096))),
            pool_notes: Arc::new(Mutex::new(Vec::new())),
            bundles: Arc::new(Mutex::new(Vec::new())),
            agg,
            chain_id: "hashkinetics-devnet-1".to_string(),
            genesis_digest: [0u8; 32],
            chain_start_time: genesis.chain_start_time,
            current_height: HkHeight::INITIAL,
            current_round: Round::Nil,
            current_proposer: None,
            streams: PartStreamsMap::new(),
            undecided: BTreeMap::new(),
            decided: BTreeMap::new(),
            master_seed,
            root,
            my_root_pk,
            current_epoch: 0,
            highest_issued_epoch: 0,
            op_handle,
            home_dir,
            rotate_every,
            pending_rotations: Vec::new(),
            foreign_rotations: Arc::new(Mutex::new(Vec::new())),
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
    }

    /// Clonable handles for the RPC server (call before moving self into the loop).
    pub fn handles(&self) -> SharedHandles {
        SharedHandles {
            chain: self.chain.clone(),
            mempool: self.mempool.clone(),
            receipts: self.receipts.clone(),
            pool_notes: self.pool_notes.clone(),
            bundles: self.bundles.clone(),
            chain_id: self.chain_id.clone(),
            genesis_digest: self.genesis_digest,
            store: self.store.clone(),
            validators: self.validators.clone(),
            chain_start_time: self.chain_start_time,
            gossip: None,
            foreign_rotations: self.foreign_rotations.clone(),
            signer_gauge: self.signer_gauge.clone(),
        }
    }

    /// Owned snapshot of the current validator set (engine replies + RPC share it).
    pub fn validator_set(&self) -> HkValidatorSet {
        self.validators.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn start_height(&self) -> HkHeight {
        self.decided
            .keys()
            .next_back()
            .map(|h| HkHeight::new(h + 1))
            .unwrap_or(HkHeight::INITIAL)
    }

    pub fn earliest_height(&self) -> HkHeight {
        self.decided
            .keys()
            .next()
            .map(|h| HkHeight::new(*h))
            .unwrap_or(HkHeight::INITIAL)
    }

    // ---- proposing ----

    /// Build the block payload: parent app_hash (this node's current commitment) +
    /// up to N transactions PEEKED (not removed) from the mempool. Txs are removed
    /// only on successful commit, so a round change never drops them.
    fn build_batch(&self) -> Bytes {
        let parent_app_hash = self.chain.lock().unwrap().state_commitment().0;
        // P2.3: a pending aggregation bundle rides whole (proof-less txs + ONE aggregate).
        let (mut txs, agg_proof) = {
            let bundles = self.bundles.lock().unwrap();
            match bundles.first() {
                Some((btxs, aggp)) if btxs.len() <= MAX_TXS_PER_BLOCK => {
                    (btxs.clone(), aggp.clone())
                }
                _ => (Vec::new(), Vec::new()),
            }
        };
        let room = MAX_TXS_PER_BLOCK - txs.len();
        {
            let mp = self.mempool.lock().unwrap();
            txs.extend(mp.iter().take(room).cloned());
        }
        // Include any rotation certs we've issued but not yet seen committed — PLUS
        // foreign certs peers submitted via `hk_submitRotation` (R2: an exhausted
        // validator can't propose its own revival; we carry it). Foreign certs are
        // re-validated against the CURRENT set here (they were checked at submit time,
        // but the set may have advanced); stale ones are dropped in place.
        let mut rotations = self.pending_rotations.clone();
        {
            let validators = self.validators.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let mut foreign = self.foreign_rotations.lock().unwrap();
            foreign.retain(|c| validators.apply_rotation(c).is_ok());
            for cert in foreign.iter() {
                if !rotations
                    .iter()
                    .any(|r| r.root_pk == cert.root_pk && r.epoch >= cert.epoch)
                {
                    rotations.push(cert.clone());
                }
            }
        }
        Bytes::from(Batch { parent_app_hash, txs, rotations, agg_proof }.encode())
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
        let value = HkValue::new(self.build_batch());
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

    pub fn find_undecided(
        &self,
        height: HkHeight,
        round: Round,
        value_id: hk_consensus::HkValueId,
    ) -> Option<ProposedValue<HkContext>> {
        self.undecided
            .get(&(height.as_u64(), round.as_i64()))
            .and_then(|vs| vs.iter().find(|v| v.value.id() == value_id).cloned())
    }

    pub fn stream_proposal(
        &self,
        value: LocallyProposedValue<HkContext>,
        pol_round: Round,
    ) -> Vec<StreamMessage<HkProposalPart>> {
        let mut sid = Vec::with_capacity(16);
        sid.extend_from_slice(&value.height.as_u64().to_le_bytes());
        sid.extend_from_slice(&value.round.as_i64().to_le_bytes());
        let stream_id = StreamId::new(Bytes::from(sid));

        let init = HkProposalPart::Init(HkProposalInit {
            height: value.height,
            round: value.round,
            pol_round,
            proposer: self.address,
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

    // ---- receiving ----

    pub fn received_proposal_part(
        &mut self,
        from: PeerId,
        part: StreamMessage<HkProposalPart>,
    ) -> Option<ProposedValue<HkContext>> {
        let parts = self.streams.insert(from, part)?;

        let mut batch = Vec::new();
        for p in &parts.parts {
            if let Some(data) = p.as_tx_batch() {
                batch.extend_from_slice(data);
            }
        }
        let value = HkValue::new(Bytes::from(batch));

        // Consistency check only: the Fin's declared value id must match the reassembled
        // content. This is NOT the security boundary — the engine independently verifies
        // the proposer's SignedProposal over this id and only decides on a matching value,
        // so a self-consistent forgery from a relay is inert. See MAINNET-KEY-MANAGEMENT.md.
        let validity = match parts.fin() {
            Some(fin) if fin.value_id == value.id => Validity::Valid,
            Some(_) => {
                error!(proposer = %parts.proposer, "proposal Fin value-id mismatch");
                Validity::Invalid
            }
            None => Validity::Invalid,
        };

        let proposed = ProposedValue {
            height: parts.height,
            round: parts.round,
            valid_round: parts.pol_round,
            proposer: parts.proposer,
            value,
            validity,
        };
        self.store_undecided(proposed.clone());
        Some(proposed)
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
                                if agg_verify(&b.agg_proof, &digest) {
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

            // Record receipts + drop included txs from the mempool.
            let mut rlog = self.receipts.lock().unwrap();
            let mut included: Vec<(hk_primitives::AccountId, u64)> = Vec::new();
            for (tx, r) in txs.iter().zip(receipts.iter()) {
                let detail = match &r.result {
                    Ok(events) => format!("ok: {} event(s)", events.len()),
                    Err(e) => format!("rejected: {e}"),
                };
                rlog.insert(txid(tx), detail);
                included.push((tx.sender, tx.nonce));
            }
            drop(rlog);
            if !included.is_empty() {
                // C2.2: indexed prune — one O(mempool) pass, O(1) membership tests.
                self.mempool.lock().unwrap().remove_included(&included);
                // P2.3: a bundle is spent once any of its txs committed.
                let gone: std::collections::HashSet<(hk_primitives::AccountId, u64)> =
                    included.iter().copied().collect();
                let mut bundles = self.bundles.lock().unwrap();
                bundles.retain(|(btxs, _)| {
                    !btxs.iter().any(|t| gone.contains(&(t.sender, t.nonce)))
                });
            }

            // Pool-note index: every commitment that entered the tree this block, with its
            // stealth payload, in tx order == insertion order (wallets rebuild auth paths
            // and SCAN from this).
            {
                use hk_state::tx::Tx;
                let mut notes = self.pool_notes.lock().unwrap();
                for (tx, r) in txs.iter().zip(receipts.iter()) {
                    if r.result.is_ok() {
                        match &tx.payload {
                            Tx::MintToPool { commitment, stealth_ct, .. } => {
                                notes.push((*commitment, stealth_ct.clone()))
                            }
                            Tx::ShieldedSpend {
                                out_commitment,
                                out2_commitment,
                                stealth_ct,
                                stealth_ct2,
                                ..
                            } => {
                                notes.push((*out_commitment, stealth_ct.clone()));
                                notes.push((*out2_commitment, stealth_ct2.clone()));
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
                let applied = { self.validators.lock().unwrap_or_else(|e| e.into_inner()).apply_rotation(cert) };
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
                                info!(
                                    epoch = cert.epoch,
                                    remaining = self.op_handle.remaining(),
                                    "Rotated OUR operational signing key (live) — fresh tree"
                                );
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
                    Err(e) => error!(%e, "Rejected rotation cert"),
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
        let resumed = path.exists();
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

        // P3.0/WS-B: capture the persistent facts BEFORE the value moves into `decided`.
        let cert_dto = crate::codec::RawCommitCertificate::from(&certificate);
        let value_bytes = value.txs.to_vec();

        self.decided.insert(height, DecidedEntry { value, certificate });
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
                } else if pct < 20 {
                    warn!(remaining, pct, epoch = self.current_epoch, "signer leaf budget low — rotation should be in flight");
                } else {
                    info!(remaining, pct, epoch = self.current_epoch, "signer leaf budget");
                }
            }
            let mine_pending =
                self.pending_rotations.iter().any(|c| c.root_pk == self.my_root_pk);
            let next_epoch = self.current_epoch + 1;
            let (due, threshold_hit) = rotation_due(
                remaining,
                capacity,
                height,
                self.rotate_every,
                mine_pending,
                next_epoch,
                self.highest_issued_epoch,
            );
            if due {
                let seed = op_seed(&self.master_seed, next_epoch);
                let new_op_pk = HkPriv::from_seed(seed).public();
                let cert = RotationCert::issue(&self.root, new_op_pk, next_epoch, height + 1);
                self.highest_issued_epoch = next_epoch;
                self.pending_rotations.push(cert);
                info!(
                    epoch = next_epoch,
                    remaining,
                    trigger = if threshold_hit { "leaf-threshold" } else { "interval" },
                    "Issued rotation cert (applies once committed)"
                );
            }
        }

        // ---- P3.0/WS-B: persist. Block log every height; full snapshot + WAL reset
        // every SNAPSHOT_EVERY. Persistence failures are LOUD but non-fatal on the
        // live path: consensus safety never depends on this node's disk (a restart
        // simply replays less / value-syncs the gap).
        if let Some(store) = self.store.clone() {
            let t_save = std::time::Instant::now();
            if let Err(e) =
                store.save_block(&StoredBlock { height, value_bytes, certificate: cert_dto, agg_valid })
            {
                error!(%e, height, "failed to persist block — restart will value-sync this height");
            }
            self.timers.save_ms += t_save.elapsed().as_millis() as u64;
            // HK-R5.2: cadence is env-tunable (`HK_SNAPSHOT_EVERY`) — the full-image
            // snapshot + fsync grows with state and taxes catch-up at the default 16.
            if height % snapshot_every() == 0 {
                let t_snap = std::time::Instant::now();
                let snap = self.make_snapshot();
                match store.save_snapshot(&snap) {
                    Ok(()) => {
                        let mp = self.mempool.lock().unwrap();
                        if let Err(e) = store.wal_reset(mp.iter()) {
                            error!(%e, "failed to reset mempool WAL");
                        }
                        info!(height, "Node snapshot persisted (restart resumes here)");
                    }
                    Err(e) => error!(%e, height, "failed to persist snapshot"),
                }
                self.timers.snap_ms += t_snap.elapsed().as_millis() as u64;
            }
        }

        Ok(())
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
    /// SAME apply path → rehydrate the decided log (value-sync serves history again)
    /// → reload WAL'd mempool admissions. Call AFTER construction (verifier already
    /// injected), BEFORE the engine asks `start_height()`.
    pub fn restore_from_store(&mut self, store: &NodeStore) -> Result<()> {
        if let Some(snap) = store.load_snapshot()? {
            let verifier = self.chain.lock().unwrap().verifier.clone();
            let mut st = hk_state::State::from_snapshot(snap.state);
            st.verifier = verifier;
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
            self.receipts.lock().unwrap().restore(snap.receipts);
            {
                // Rebuild WITH indexes (C2); duplicate frames in an old image are suppressed.
                let mut mp = self.mempool.lock().unwrap();
                for tx in snap.mempool {
                    mp.insert_unchecked(tx);
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

        // Block files: rehydrate history at-or-below the snapshot (value-sync serves
        // it again); REPLAY anything beyond it through the normal apply path.
        let (mut replayed, mut rehydrated) = (0u64, 0u64);
        for h in store.block_heights()? {
            let Some(sb) = store.load_block(h)? else { continue };
            let value = HkValue::new(Bytes::from(sb.value_bytes));
            if certificate_value_mismatch(&sb.certificate, &value) {
                return Err(eyre!(
                    "block file {h}: certificate value-id != content hash — refusing corrupt history"
                ));
            }
            let certificate: CommitCertificate<HkContext> = sb.certificate.into();
            let chain_height = self.chain.lock().unwrap().height;
            if h > chain_height {
                if h != chain_height + 1 {
                    error!(
                        height = h,
                        chain_height,
                        "gap in the block log — stopping replay here; value-sync fills the rest"
                    );
                    break;
                }
                let batch = Batch::decode(&value.txs);
                self.apply_batch_to_chain(h, &batch, false, sb.agg_valid)?;
                self.apply_rotations(h, &batch, true);
                replayed += 1;
            } else {
                rehydrated += 1;
            }
            self.decided.insert(h, DecidedEntry { value, certificate });
            self.current_height = HkHeight::new(h + 1);
        }

        // Mempool WAL: admissions since the last snapshot, re-run through the SAME
        // admission gate as live traffic (C2.1) — stale nonces, spent nullifiers and
        // duplicates all drop here for the same reasons they would at the door.
        let mut wal_restored = 0usize;
        {
            let chain = self.chain.lock().unwrap();
            let mut mp = self.mempool.lock().unwrap();
            for tx in store.wal_load() {
                if mp.try_admit(tx, &chain).is_ok() {
                    wal_restored += 1;
                }
            }
        }

        let tip = self.chain.lock().unwrap().height;
        if tip > 0 || replayed > 0 || rehydrated > 0 {
            let app_hash = self.chain.lock().unwrap().state_commitment();
            info!(
                tip,
                replayed,
                rehydrated,
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

/// R1: should this validator issue a rotation cert at this commit?
/// Returns (due, threshold_hit). The PRODUCTION trigger is the leaf budget
/// (< 20% remaining); the interval is a demo/ops override. Guards: never while our
/// own cert is pending, never re-issuing an epoch at-or-below the highest issued.
fn rotation_due(
    remaining: u64,
    capacity: u64,
    height: u64,
    rotate_every: Option<u64>,
    mine_pending: bool,
    next_epoch: u64,
    highest_issued: u64,
) -> (bool, bool) {
    let threshold_hit = remaining < capacity / 5;
    let interval_hit = rotate_every.is_some_and(|n| height > 0 && height % n == 0);
    let due = (threshold_hit || interval_hit) && !mine_pending && next_epoch > highest_issued;
    (due, threshold_hit)
}

#[cfg(test)]
mod rotation_trigger_tests {
    use super::rotation_due;
    const CAP: u64 = 32_768; // hk_crypto::hashsig::CONSENSUS_CAPACITY

    #[test]
    fn fresh_tree_never_rotates_without_interval() {
        // The staging fleet's pre-incident config (no env) must now be SAFE by default:
        for h in [1u64, 500, 10_848] {
            assert_eq!(rotation_due(CAP, CAP, h, None, false, 1, 0), (false, false));
        }
    }

    #[test]
    fn threshold_fires_below_twenty_percent_regardless_of_height() {
        // 20% of 32,768 = 6,553; the incident's tree would have triggered ~2.2K
        // heights (>1 hour) before the halt instead of dying at leaf zero.
        assert_eq!(rotation_due(6_552, CAP, 10_777, None, false, 1, 0), (true, true));
        assert_eq!(rotation_due(6_553, CAP, 10_777, None, false, 1, 0), (false, false));
        assert_eq!(rotation_due(0, CAP, 3, None, false, 1, 0), (true, true));
    }

    #[test]
    fn interval_override_still_works() {
        assert_eq!(rotation_due(CAP, CAP, 500, Some(500), false, 1, 0), (true, false));
        assert_eq!(rotation_due(CAP, CAP, 501, Some(500), false, 1, 0), (false, false));
        assert_eq!(rotation_due(CAP, CAP, 0, Some(500), false, 1, 0), (false, false));
    }

    #[test]
    fn guards_suppress_double_issue() {
        // Our cert already pending → never re-issue, however low the budget runs.
        assert_eq!(rotation_due(10, CAP, 100, None, true, 1, 0), (false, true));
        // Epoch already issued (e.g. included but we replayed past the bookkeeping).
        assert_eq!(rotation_due(10, CAP, 100, None, false, 1, 1), (false, true));
        // After the rotation applies (fresh tree, epoch advanced), the cycle re-arms.
        assert_eq!(rotation_due(CAP, CAP, 101, None, false, 2, 1), (false, false));
        assert_eq!(rotation_due(6_000, CAP, 200, None, false, 2, 1), (true, true));
    }
}
