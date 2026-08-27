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
use tracing::{error, info};

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
    /// Demo trigger: if set, rotate our key every N committed heights (`HK_ROTATE_EVERY`).
    rotate_every: Option<u64>,
    /// Certs we've issued but not yet seen committed (included when we next propose).
    pending_rotations: Vec<RotationCert>,
    /// P3.0/WS-B: durable store (block log + snapshots + mempool WAL). `None` = the
    /// old in-memory devnet behavior (`HK_NO_PERSIST=1`, and unit tests).
    store: Option<Arc<NodeStore>>,
}

impl HkApp {
    pub fn new(
        address: HkAddress,
        genesis: &HkGenesis,
        master_seed: [u8; 32],
        op_handle: HkPriv,
        home_dir: PathBuf,
        verifiers: Option<PoolVerifiers>,
    ) -> Result<Self> {
        let validators = genesis.validator_set()?;
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
            store: None,
        })
    }

    /// P3.0/WS-B: attach the durable store (call after `restore_from_store`).
    pub fn attach_store(&mut self, store: Arc<NodeStore>) {
        self.store = Some(store);
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
            store: self.store.clone(),
            validators: self.validators.clone(),
            chain_start_time: self.chain_start_time,
            gossip: None,
        }
    }

    /// Owned snapshot of the current validator set (engine replies + RPC share it).
    pub fn validator_set(&self) -> HkValidatorSet {
        self.validators.lock().unwrap().clone()
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
        // Include any rotation certs we've issued but not yet seen committed.
        let rotations = self.pending_rotations.clone();
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
        {
            let mut chain = self.chain.lock().unwrap();

            // Consensus-fatal divergence check (0.7): the block's parent hash MUST
            // equal our own current state commitment, or our state has diverged.
            // On replay this is the integrity chain: snapshot → each block → tip.
            if let Some(b) = &batch {
                let ours = chain.state_commitment().0;
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

            let txs: Vec<SignedTx> = batch.as_ref().map(|b| b.txs.clone()).unwrap_or_default();
            let receipts = chain
                .apply_block(height, time, &txs)
                .map_err(|e| eyre!("apply_block failed: {e}"))?;

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

            let app_hash = chain.state_commitment();
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
        Ok(agg_valid)
    }

    /// SCMS: apply operational-key rotations committed in a block. Every node updates
    /// the validator set (so it verifies the rotated validator's future votes against
    /// the new key). The validator that OWNS the rotated root also swaps its own live
    /// signer to the new tree, in lockstep — EXCEPT on replay: resuming a rotated
    /// signer's used-leaf counter is the WS-F hardening item, so replay updates the
    /// set (vote VERIFICATION stays correct) and refuses to guess about our own tree.
    fn apply_rotations(&mut self, batch: &Option<Batch>, replay: bool) {
        if let Some(b) = &batch {
            for cert in &b.rotations {
                let applied = { self.validators.lock().unwrap().apply_rotation(cert) };
                match applied {
                    Ok(new_set) => {
                        *self.validators.lock().unwrap() = new_set;
                        let mine = cert.root_pk == self.my_root_pk;
                        info!(epoch = cert.epoch, mine = mine, replay, "Applied validator key rotation");
                        if mine && cert.epoch > self.current_epoch {
                            if replay {
                                error!(
                                    epoch = cert.epoch,
                                    "restart-after-rotation: own-signer resume is WS-F (P3 plan) — \
                                     this node's votes may mismatch until it lands; if consensus \
                                     stalls, restart this validator --fresh and let value-sync catch it up"
                                );
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
                                info!(epoch = cert.epoch, "Rotated OUR operational signing key (live)");
                            }
                        }
                        self.pending_rotations
                            .retain(|c| !(c.root_pk == cert.root_pk && c.epoch <= cert.epoch));
                    }
                    Err(e) => error!(%e, "Rejected rotation cert"),
                }
            }
        }
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
        self.apply_rotations(&batch, false);

        // P3.0/WS-B: capture the persistent facts BEFORE the value moves into `decided`.
        let cert_dto = crate::codec::RawCommitCertificate::from(&certificate);
        let value_bytes = value.txs.to_vec();

        self.decided.insert(height, DecidedEntry { value, certificate });
        self.undecided.retain(|(h, _), _| *h > height);
        self.current_height = HkHeight::new(height + 1);

        // ---- SCMS demo trigger: periodically rotate our own key (HK_ROTATE_EVERY=N) ----
        if let Some(n) = self.rotate_every {
            let next_epoch = self.current_epoch + 1;
            if height > 0
                && height % n == 0
                && self.pending_rotations.is_empty()
                && next_epoch > self.highest_issued_epoch
            {
                let seed = op_seed(&self.master_seed, next_epoch);
                let new_op_pk = HkPriv::from_seed(seed).public();
                let cert = RotationCert::issue(&self.root, new_op_pk, next_epoch, height + 1);
                self.highest_issued_epoch = next_epoch;
                self.pending_rotations.push(cert);
                info!(epoch = next_epoch, "Issued rotation cert (applies once committed)");
            }
        }

        // ---- P3.0/WS-B: persist. Block log every height; full snapshot + WAL reset
        // every SNAPSHOT_EVERY. Persistence failures are LOUD but non-fatal on the
        // live path: consensus safety never depends on this node's disk (a restart
        // simply replays less / value-syncs the gap).
        if let Some(store) = self.store.clone() {
            if let Err(e) =
                store.save_block(&StoredBlock { height, value_bytes, certificate: cert_dto, agg_valid })
            {
                error!(%e, height, "failed to persist block — restart will value-sync this height");
            }
            if height % SNAPSHOT_EVERY == 0 {
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
                *self.validators.lock().unwrap() =
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
                self.apply_rotations(&batch, true);
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
