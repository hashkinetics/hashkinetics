//! Indexed mempool (C2.1 + C2.2 + M-2) — admission pre-checks at the door, O(1)
//! membership, O(included) prune at commit.
//!
//! C1 filed two findings against the v0 mempool (a bare `VecDeque`):
//!   1. junk admission — `hk_submitTx` accepted anything that parsed; duplicates and
//!      stale-nonce txs sat in the pool, were proposed, and died at apply with a
//!      "rejected" receipt — each one burning a block slot;
//!   2. quadratic prune — commit removed included txs with
//!      `retain(|t| included.any(..))`, O(mempool × included).
//!
//! This module fixes both with one structure: the FIFO queue keeps proposal order
//! (nonce order per sender = submission order, which apply's strict nonce equality
//! requires), and three side-indexes make admission and prune cheap:
//!   - `ids`        — txids present (duplicate detection, O(1));
//!   - `keys`       — (sender, nonce) → that tx's `next_auth` (same-slot double-submit,
//!                    O(1); and the commitment the NEXT nonce's key must open — M-2);
//!   - `nullifiers` — nullifiers of PENDING ShieldedSpends (mempool-level double-spend
//!                    refusal before the chain ever sees it).
//!
//! Admission mirrors apply's own preconditions — it refuses what apply would certainly
//! refuse NOW (unknown sender, past nonce, spent/pending nullifier, expired anchor) AND,
//! since M-2 (R17, reported 2026-10-06, fixed 2026-10-06), the whole account envelope:
//! key/signature lengths, the key→account binding (`pk_commit(lamport_pk)` must open
//! the account's `auth_commit`, or — for a tx queued ahead of the chain — the
//! `next_auth` of the pending tx one nonce below it, walking the L-ratchet exactly as
//! apply will when the block lands), and the Lamport signature itself, through the
//! SAME `hk_state::State::verify_envelope` the commit path uses, so admission and
//! apply can never disagree on a signature. Before M-2 nothing here looked at the
//! signature: an UNSIGNED tx was indexed, fdatasync'd into the WAL and gossiped to every
//! peer, and — because `DuplicateSlot` refuses a second tx at a pending (sender, nonce)
//! — anyone could park an unsigned frame at a victim's next nonce and censor the
//! victim's real tx for free, on every node, until a proposer burned a slot on it.
//! Now a slot can only be held by a tx the account's own key signed.
//!
//! Admission cannot create false rejections apply would have accepted, with three
//! deliberate exceptions: `NONCE_WINDOW` bounds how far ahead of the account's current
//! nonce a tx may queue (gap txs apply fine in-block; an unbounded future is a spam
//! vector); a tx more than one nonce ahead of the chain needs its predecessor
//! PENDING here (`NonceGap`) — without it the key binding cannot be checked, and an
//! unbound slot is exactly the parking spot M-2 closes; and the two R18 PayWord caps
//! (next paragraph) are enforced here UNGATED, i.e. also before the height at which
//! consensus starts enforcing them, and against the chain's settled step rather than a
//! pending settle's. Honest clients sign and submit in nonce order (the wallet, the
//! faucet, the storm's home-node rule) and gossip is a FIFO single hop, so order
//! survives; a hole could only come from a lost push, after which the successor could
//! not have applied on that node anyway.
//!
//! R18 (reported 2026-10-04 by `secwatch-hunt`, confirmed 2026-10-08, fixed 2026-10-08):
//! a `ChannelSettle` costs apply `step` SHAKE-256 links — every link from the revealed word
//! back to the channel's tip (`hk_crypto::payword::verify_settlement`, no early exit; the
//! delta `step − highest_step_settled` is what consensus caps from R18, the climb, not
//! today's cost — hk-state `MAX_SETTLE_DELTA`), synchronously, under the chain mutex — and
//! a refusal is free (fee refunded, nonce not ratcheted) and the identical bytes replay
//! every block. Before R18 nothing bounded `step` but the channel's `max_steps`, and
//! nothing bounded `max_steps` but `!= 0`, so ONE settle at `step = u32::MAX` on a channel
//! opened at `max_steps = u32::MAX` was ≈ 4.29e9 hashes per validator per block it was
//! proposed in — and this door admitted it (no payload checks), the proposer copied it
//! blind, replay and resync paid it again. Consensus now caps both — `hk_state::MAX_SETTLE_DELTA`
//! links of climb per settle, `hk_state::MAX_CHANNEL_STEPS` per channel, height-gated by
//! `State::payword_cap_from` — and this door mirrors the two caps with NO gate, plus a
//! third refusal that keeps the door and the proposer in agreement (the same-day review):
//!   * a `ChannelOpen` whose `max_steps` exceeds `MAX_CHANNEL_STEPS` is refused by its own
//!     bytes (`ChannelTooLong`) inside [`Mempool::envelope_verdict`], next to the M-2
//!     lengths check, so neither the RPC nor the WAL loop ever hashes it;
//!   * a `ChannelSettle` more than `MAX_SETTLE_DELTA` links past the channel's
//!     `highest_step_settled` ON THIS NODE'S CHAIN (`hk_state::State::settle_delta`, the
//!     number apply caps) is refused under the lock (`SettleDeltaTooLarge`) — and so is a
//!     settle on a channel this chain does NOT know whose `step` exceeds the cap: if its
//!     open is pending ahead of it the delta IS `step`, and if the open never lands apply
//!     refuses it in O(1) either way, so the refusal is exact, not conservative;
//!   * a `ChannelSettle` the proposer would never carry — [`crate::state::settle_cost`]
//!     above [`crate::state::MAX_SETTLE_LINKS_PER_BLOCK`], the per-block budget
//!     `select_batch_txs` holds by — is refused as `SettleTooCostly`. The first cut of
//!     R18 admitted such a tx (a settle at `step` past the budget on a channel opened
//!     before the height, or any `None` the proposer then costed as `step`) and
//!     `select_batch_txs` held it in EVERY block: nothing ever pruned it (`remove_included`
//!     fires only for txs that rode a block), it held its sender's later txs with it, the
//!     WAL and every snapshot carried it across restarts, gossip spread it — so 128
//!     faucet-funded accounts × `NONCE_WINDOW` such frames filled `DEFAULT_CAP` on every
//!     upgraded node for the price of a signature, and every honest `hk_submitTx` then
//!     answered `mempool full`. The invariant now, pinned by
//!     `what_the_door_admits_the_proposer_picks`: a tx this door admits is one
//!     `select_batch_txs` picks on an empty block of the same chain.
//!   The two settle checks are two BTreeMap lookups, no hash, placed right after the
//!   three map checks — before the account, nonce and key walk, and in `try_admit` before
//!   the envelope hashes. The RPC's hoisted hashes (no lock held, ≈ 0.3 ms on the worker)
//!   are spent as for any other state-dependent refusal; the locked cost is the lookups.
//! The first two reasons are hk-state's own receipt wording (`StateError`'s Display), as
//! the M-2 ones are, so a wallet keys on one string at the door and in a receipt; the
//! third is admission wording (like `NonceGap`) because no receipt ever carries it — a
//! consensus-valid settle past the budget is refused HERE, honestly, rather than parked.
//! What the door does NOT judge: a refunded channel and a step at or below the settled one
//! or past `max_steps` on a channel the chain knows — `settle_delta` answers `None` for all
//! three, apply refuses each in O(1) before hashing a link, and the proposer costs them 0
//! — and a settle PENDING here for the same channel: the delta is taken against the chain,
//! so a second settle more than a cap past the chain's step waits for the first to land
//! (honest payees settle a channel once; the conservative refusal costs them a resubmit,
//! never a coin). The numbers live in hk-state and `state.rs` only — they are not repeated
//! here.
//!
//! Check order is cheap-first: cap, duplicates, the R18 settle cap + cost (two channel
//! lookups), lengths and the R18 open cap, account/nonce, pool lookups, then the key
//! commitment (one SHAKE over 16 KiB), then the signature (256 SHAKEs) — a flood of junk
//! is refused before it costs a hash. Nothing is indexed, and nothing reaches the WAL or
//! gossip, until every check has passed.
//!
//! The hashes are STATE-FREE (R17 review, 2026-10-06): `pk_commit` and `verify_envelope`
//! read only the tx's own bytes, so [`Mempool::envelope_verdict`] computes both with no
//! lock held and [`Mempool::try_admit_verified`] applies them at exactly the positions
//! `try_admit` would — the same split hk-state makes for the commit path (`apply_tx_at`'s
//! precomputed `pre_sig`). The first cut of M-2 ran both hashes inside `try_admit`, i.e.
//! under the chain lock AND the mempool lock that `rpc::admit_one` holds together: an
//! unauthenticated, unrate-limited `hk_submitTx` / `hk_gossipTxs` flood of right-length
//! junk then held the lock the commit path needs for ≈ 0.3 ms per request, 256 workers
//! deep (the L-6 shape, in the mempool). The RPC now hashes first, locks second; the
//! verdict set and its precedence are unchanged (pinned by
//! `hoisted_verdict_and_try_admit_agree`), and `try_admit` keeps the cheap-first order for
//! the WAL replay loop, where a cap-full or duplicate frame should still cost no hash.
//!
//! Lock discipline: callers that need both locks take `chain` BEFORE `mempool`
//! (the commit path in state.rs already does; rpc.rs follows the same order).

use std::collections::{HashMap, HashSet, VecDeque};

use hk_crypto::lamport::{self, PK_LEN, SIG_LEN};
use hk_primitives::{AccountId, H256};
use hk_state::tx::{signing_digest, SignedTx, Tx};
use hk_state::{MAX_CHANNEL_STEPS, MAX_SETTLE_DELTA};

use crate::batch::txid;
use crate::state::{settle_cost, MAX_SETTLE_LINKS_PER_BLOCK};

/// Max txs held; admissions beyond this are refused loudly. Override for storm
/// experiments with `HK_MEMPOOL_CAP`.
pub const DEFAULT_CAP: usize = 8192;

/// How far ahead of the account's current nonce a tx may queue (default).
/// Override with `HK_NONCE_WINDOW` — the window bounds the whole pipeline at
/// senders × window pending txs, so saturating big blocks in the storm harness
/// needs a wider window (measured C2.4: 5 genesis senders × 64 = 320 pending
/// could never fill a 1024-cap block).
pub const NONCE_WINDOW: u64 = 64;

fn nonce_window() -> u64 {
    static W: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *W.get_or_init(|| {
        std::env::var("HK_NONCE_WINDOW")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|n: &u64| *n > 0)
            .unwrap_or(NONCE_WINDOW)
    })
}

/// Why a tx was refused at the door. `as_str` is the wire reason (stable, lowercase).
/// The three envelope refusals (M-2) carry hk-state's own wording, so a wallet reads
/// the same reason at the door that it would have read in a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitError {
    Full,
    DuplicateTx,
    DuplicateSlot { pending_nonce: u64 },
    UnknownSender,
    StaleNonce { expected: u64, got: u64 },
    FutureNonce { current: u64, got: u64 },
    /// M-2: the tx is ahead of the chain and the nonce below it is not pending here,
    /// so there is no commitment to bind its key to. `missing` = `got - 1`.
    NonceGap { got: u64, missing: u64 },
    NullifierSpent,
    NullifierPending,
    UnknownAnchor,
    /// M-2: `lamport_pk` / `sig` are not `PK_LEN` / `SIG_LEN` bytes (or the payload
    /// cannot be encoded into a signing digest) — structurally never valid.
    BadEnvelope,
    /// M-2: `pk_commit(lamport_pk)` opens neither the account's `auth_commit` nor the
    /// `next_auth` of the pending predecessor — a key that is not this account's.
    AuthMismatch,
    /// M-2: the key is the account's, the Lamport signature over the signing digest
    /// is not.
    BadSignature,
    /// R18: a `ChannelOpen` asking for more than `hk_state::MAX_CHANNEL_STEPS` links —
    /// past the activation it can never open, and before it it is the setup for the
    /// unbounded settle. Refused by the tx's own bytes, before any hash.
    ChannelTooLong { max_steps: u32 },
    /// R18: a `ChannelSettle` whose `delta` (`hk_state::State::settle_delta`: `step` minus
    /// the channel's `highest_step_settled` on this node's chain; `step` itself on a
    /// channel the chain does not know) exceeds `hk_state::MAX_SETTLE_DELTA` — the chain
    /// would hash every link from that word to the tip under the chain mutex before apply
    /// could say yes or no (the delta is what the rule caps; the proposer budgets the
    /// links — `state.rs`). One lookup here, no hash.
    SettleDeltaTooLarge { delta: u64 },
    /// R18 review (2026-10-08): a `ChannelSettle` whose links from the tip
    /// (`crate::state::settle_cost` — what `verify_settlement` hashes today) exceed the
    /// proposer's per-block budget `crate::state::MAX_SETTLE_LINKS_PER_BLOCK`, so no block
    /// this node builds could ever carry it: refused here rather than parked forever (the
    /// pool-exhaustion vector the module doc describes). Reachable only on a channel opened
    /// before the height — the consensus cap keeps a post-height channel inside the budget.
    SettleTooCostly { links: u64 },
}

impl AdmitError {
    pub fn as_str(&self) -> String {
        match self {
            AdmitError::Full => "mempool full".into(),
            AdmitError::DuplicateTx => "duplicate: tx already in mempool".into(),
            AdmitError::DuplicateSlot { pending_nonce } => {
                format!("duplicate: a tx for this sender at nonce {pending_nonce} is already pending (replacement not supported)")
            }
            AdmitError::UnknownSender => "unknown sender account".into(),
            AdmitError::StaleNonce { expected, got } => {
                format!("stale nonce: account is at {expected}, tx has {got}")
            }
            AdmitError::FutureNonce { current, got } => {
                format!("nonce too far ahead: account is at {current}, tx has {got} (window {NONCE_WINDOW})")
            }
            AdmitError::NonceGap { got, missing } => {
                format!("nonce gap: tx has {got} but no tx at nonce {missing} is pending for this sender (submit in nonce order)")
            }
            AdmitError::NullifierSpent => "nullifier already spent on-chain".into(),
            AdmitError::NullifierPending => {
                "nullifier already pending in the mempool".into()
            }
            AdmitError::UnknownAnchor => "unknown or expired pool anchor".into(),
            AdmitError::BadEnvelope => {
                format!("malformed envelope: lamport_pk must be {PK_LEN} bytes and sig {SIG_LEN} bytes")
            }
            AdmitError::AuthMismatch => "lamport pk does not open the account auth commitment".into(),
            AdmitError::BadSignature => "bad signature".into(),
            // R18: hk-state's receipt wording, byte for byte (its Display) — the two
            // refusals read the same at the door and in a receipt, and the numbers are
            // hk-state's, not repeated here.
            AdmitError::ChannelTooLong { max_steps } => {
                hk_state::StateError::ChannelTooLong { max_steps: u64::from(*max_steps), max: MAX_CHANNEL_STEPS }.to_string()
            }
            AdmitError::SettleDeltaTooLarge { delta } => {
                hk_state::StateError::SettleDeltaTooLarge { delta: *delta, max: MAX_SETTLE_DELTA }.to_string()
            }
            // R18 review: admission wording (no receipt ever says this — the tx never
            // rides), like `NonceGap`; the number is the proposer's budget.
            AdmitError::SettleTooCostly { links } => {
                format!("settle too costly to propose ({links} links from the tip, max {MAX_SETTLE_LINKS_PER_BLOCK} per block until verification is incremental — settle in pieces)")
            }
        }
    }
}

/// What the state-free half of admission said about one envelope (R17 review, 2026-10-06):
/// the two hashes of M-2, computed by [`Mempool::envelope_verdict`] with no lock held and
/// consumed by [`Mempool::try_admit_verified`] under the locks. Carries verdicts, not
/// decisions, so the consumer applies them at the same positions `try_admit` does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeVerdict {
    /// `lamport::pk_commit(&tx.lamport_pk)` — `None` when the frame was refused before any
    /// hash: wrong lengths (M-2 (a)) or an over-cap `ChannelOpen` (R18); `signature` then
    /// carries which, and the consumer refuses exactly as `try_admit` does.
    pk_commit: Option<[u8; 32]>,
    /// M-2 (b): `Ok` when `State::verify_envelope` accepted the signature over the tx's own
    /// bytes; `BadSignature`, or `BadEnvelope` when the signing digest cannot form. With
    /// `pk_commit == None`: `BadEnvelope` or `ChannelTooLong`, the hash-free refusal.
    signature: Result<(), AdmitError>,
}

pub struct Mempool {
    q: VecDeque<SignedTx>,
    ids: HashSet<[u8; 32]>,
    /// (sender, nonce) → that pending tx's `next_auth`: the commitment the tx at
    /// nonce + 1 must open (M-2 binding walk). Membership alone is `DuplicateSlot`.
    keys: HashMap<(AccountId, u64), H256>,
    nullifiers: HashSet<[u8; 32]>,
    cap: usize,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new(
            std::env::var("HK_MEMPOOL_CAP")
                .ok()
                .and_then(|s| s.parse().ok())
                .filter(|n: &usize| *n > 0)
                .unwrap_or(DEFAULT_CAP),
        )
    }
}

impl Mempool {
    pub fn new(cap: usize) -> Self {
        Self {
            q: VecDeque::new(),
            ids: HashSet::new(),
            keys: HashMap::new(),
            nullifiers: HashSet::new(),
            cap,
        }
    }

    pub fn len(&self) -> usize {
        self.q.len()
    }

    #[allow(dead_code)] // API completeness next to len()
    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }

    /// FIFO view — proposal building (`take(room)`), snapshots, and `hk_getMempool`.
    pub fn iter(&self) -> impl Iterator<Item = &SignedTx> {
        self.q.iter()
    }

    /// C2.1 + M-2: the admission pre-check. Refuses what apply would certainly refuse
    /// now — including, since M-2, anything the account's key did not sign — admits
    /// everything else and maintains the indexes. Returns the txid on success.
    ///
    /// The envelope checks reproduce `hk_state::State::apply_tx_at` one for one:
    /// account → nonce → auth-commit binding (`lamport::pk_commit`) → signature
    /// (`State::verify_envelope`, the very function the commit path hands its verdicts
    /// from). The only admission-specific rules are the nonce window and the
    /// predecessor-must-be-pending walk, both documented at the top of the module.
    pub fn try_admit(
        &mut self,
        tx: SignedTx,
        chain: &hk_state::State,
    ) -> Result<[u8; 32], AdmitError> {
        // Cheap-first: a cap-full pool, a duplicate, or (R18) a settle too far past the
        // chain's step costs no hash (the WAL replay loop and the tests come through here).
        let id = self.gate(&tx)?;
        Self::channel_settle_cap(&tx, chain)?;
        let verdict = Self::envelope_verdict(&tx);
        self.admit_gated(tx, id, chain, &verdict)
    }

    /// The three map checks every admission starts with (cap, exact duplicate, pending
    /// slot) — O(1), no hashing beyond the txid. Returns the txid.
    fn gate(&self, tx: &SignedTx) -> Result<[u8; 32], AdmitError> {
        if self.q.len() >= self.cap {
            return Err(AdmitError::Full);
        }
        let id = txid(tx);
        if self.ids.contains(&id) {
            return Err(AdmitError::DuplicateTx);
        }
        if self.keys.contains_key(&(tx.sender, tx.nonce)) {
            return Err(AdmitError::DuplicateSlot { pending_nonce: tx.nonce });
        }
        Ok(id)
    }

    /// The state-free half of admission (R17 review, 2026-10-06): the M-2 lengths check,
    /// the key commitment (one SHAKE over 16 KiB) and the Lamport signature (256 SHAKEs)
    /// over the tx's OWN bytes — nothing here reads the chain or the pool, so
    /// `rpc::admit_one` runs it BEFORE taking the chain and mempool locks and hands the
    /// result to [`try_admit_verified`](Self::try_admit_verified). Same function as the
    /// commit path (`hk_state::State::verify_envelope`), so a verdict computed here is the
    /// one apply would reach.
    pub fn envelope_verdict(tx: &SignedTx) -> EnvelopeVerdict {
        // M-2 (a): structural envelope check, before any hashing — `lamport::verify`
        // refuses these lengths too, but refusing them here names the reason and costs
        // nothing. An empty pk/sig (the pre-M-2 parking frame) stops right here.
        if tx.lamport_pk.len() != PK_LEN || tx.sig.len() != SIG_LEN {
            return EnvelopeVerdict { pk_commit: None, signature: Err(AdmitError::BadEnvelope) };
        }
        // R18: a ChannelOpen past MAX_CHANNEL_STEPS is refused by its own bytes — state-free
        // and O(1), so it sits here with the lengths check and never reaches a hash on
        // either path (the RPC computes this verdict with no lock held).
        if let Err(e) = Self::channel_open_cap(tx) {
            return EnvelopeVerdict { pk_commit: None, signature: Err(e) };
        }
        let pk_commit = lamport::pk_commit(&tx.lamport_pk);
        let signature = if hk_state::State::verify_envelope(tx) {
            Ok(())
        } else if signing_digest(&tx.payload, &tx.sender, tx.nonce, &tx.next_auth).is_none() {
            // `verify_envelope` folds "payload would not encode" into `false`; apply
            // splits it back out as `Encode` — do the same (digest only, cheap).
            Err(AdmitError::BadEnvelope)
        } else {
            Err(AdmitError::BadSignature)
        };
        EnvelopeVerdict { pk_commit: Some(pk_commit), signature }
    }

    /// R18, the state-free cap: a `ChannelOpen` may not ask for more than
    /// `hk_state::MAX_CHANNEL_STEPS` links. Reads the payload only; `envelope_verdict`
    /// runs it before the hashes.
    fn channel_open_cap(tx: &SignedTx) -> Result<(), AdmitError> {
        match &tx.payload {
            Tx::ChannelOpen { max_steps, .. } if u64::from(*max_steps) > MAX_CHANNEL_STEPS => {
                Err(AdmitError::ChannelTooLong { max_steps: *max_steps })
            }
            _ => Ok(()),
        }
    }

    /// R18, the state-dependent checks: a `ChannelSettle` may not advance its channel by
    /// more than `hk_state::MAX_SETTLE_DELTA` links past the highest step the chain has
    /// settled — `State::settle_delta`, the very number apply caps, so the door and the
    /// receipt can never disagree on it — nor, on a channel the chain does not know, ask
    /// for more than the cap as its `step` (its open pending ahead of it would make the
    /// delta exactly `step`; without the open apply refuses it in O(1) anyway); and (R18
    /// review, 2026-10-08) it may not cost more links than one block this node builds may
    /// carry — `crate::state::settle_cost`, the proposer's own cost function, against
    /// `MAX_SETTLE_LINKS_PER_BLOCK` — because `select_batch_txs` would hold it in every
    /// block and nothing else ever removes it (module doc). Two BTreeMap lookups, no hash,
    /// run right after the three map checks on both entry points. A refunded channel and a
    /// stale or over-max step on a known channel are not the door's call — apply refuses
    /// each in O(1) before hashing and the proposer costs them 0 — and the delta is taken
    /// against the CHAIN, not against a settle pending here (module doc, "What the door
    /// does NOT judge").
    fn channel_settle_cap(tx: &SignedTx, chain: &hk_state::State) -> Result<(), AdmitError> {
        let Tx::ChannelSettle { id, step, .. } = &tx.payload else {
            return Ok(());
        };
        match chain.settle_delta(id, *step) {
            Some(delta) if delta > MAX_SETTLE_DELTA => return Err(AdmitError::SettleDeltaTooLarge { delta }),
            None if !chain.channels.contains_key(id) && u64::from(*step) > MAX_SETTLE_DELTA => {
                return Err(AdmitError::SettleDeltaTooLarge { delta: u64::from(*step) });
            }
            _ => {}
        }
        let links = settle_cost(chain, id, *step);
        if links > MAX_SETTLE_LINKS_PER_BLOCK {
            return Err(AdmitError::SettleTooCostly { links });
        }
        Ok(())
    }

    /// The state-dependent half of admission, under the locks: cap / duplicate / slot,
    /// the R18 settle cap, account and nonce window, pool lookups, the pending-ratchet
    /// binding of `verdict.pk_commit`, then `verdict.signature` — each refusal at the
    /// position `try_admit` gives it, so the two entry points can never disagree on a
    /// reason. `verdict` must have been computed from THIS `tx` (`envelope_verdict`); the
    /// RPC computes it with no lock held.
    pub fn try_admit_verified(
        &mut self,
        tx: SignedTx,
        chain: &hk_state::State,
        verdict: &EnvelopeVerdict,
    ) -> Result<[u8; 32], AdmitError> {
        let id = self.gate(&tx)?;
        Self::channel_settle_cap(&tx, chain)?;
        self.admit_gated(tx, id, chain, verdict)
    }

    /// Everything after the gate and the settle cap, shared by both entry points (each
    /// runs the two cheap steps exactly once, in the same order).
    fn admit_gated(
        &mut self,
        tx: SignedTx,
        id: [u8; 32],
        chain: &hk_state::State,
        verdict: &EnvelopeVerdict,
    ) -> Result<[u8; 32], AdmitError> {
        // M-2 (a) / R18: refused before any hash was computed — wrong lengths
        // (`BadEnvelope`) or an over-cap ChannelOpen (`ChannelTooLong`); the verdict says which.
        let Some(pk_commit) = verdict.pk_commit else {
            return Err(verdict.signature.clone().err().unwrap_or(AdmitError::BadEnvelope));
        };
        // Envelope preconditions (every tx, shielded relays included, is account-signed).
        let acc = match chain.accounts.get(&tx.sender) {
            Some(acc) => acc,
            None => return Err(AdmitError::UnknownSender),
        };
        let current = acc.nonce;
        if tx.nonce < current {
            return Err(AdmitError::StaleNonce { expected: current, got: tx.nonce });
        }
        if tx.nonce >= current + nonce_window() {
            return Err(AdmitError::FutureNonce { current, got: tx.nonce });
        }
        // Pool preconditions (set lookups — still cheap, so still before the hashes).
        if let Tx::ShieldedSpend { anchor, nullifier, .. } = &tx.payload {
            // P6: the pool is the one whose recent anchors carry `anchor` (the state
            // machine routes the same way); no pool knows it → unknown anchor.
            let pool = match chain.pool_key_of_anchor(anchor).and_then(|k| chain.pool_ref(k)) {
                Some(p) => p,
                None => return Err(AdmitError::UnknownAnchor),
            };
            if pool.nullifiers.contains(&nullifier.0) {
                return Err(AdmitError::NullifierSpent);
            }
            if self.nullifiers.contains(&nullifier.0) {
                return Err(AdmitError::NullifierPending);
            }
        }
        // M-2 (c): the key→account binding, as apply checks it. At the chain's nonce the
        // key must open the account's `auth_commit`; one or more nonces ahead it must
        // open the `next_auth` the pending predecessor committed to — the ratchet apply
        // will have advanced to by the time this tx is reached in the block. Without a
        // pending predecessor there is nothing to bind to, and an unbound slot is the
        // parking spot the attack used: refuse rather than guess.
        let expected = if tx.nonce == current {
            acc.auth_commit
        } else {
            match self.keys.get(&(tx.sender, tx.nonce - 1)) {
                Some(next_auth) => *next_auth,
                None => return Err(AdmitError::NonceGap { got: tx.nonce, missing: tx.nonce - 1 }),
            }
        };
        if pk_commit != expected.0 {
            return Err(AdmitError::AuthMismatch);
        }
        // M-2 (b): the signature — the single most expensive check, so the last one.
        // Same function as the commit path (state.rs `par_bools(.., verify_envelope)`),
        // so a tx admitted here cannot fail the signature at apply, and vice versa.
        verdict.signature.clone()?;
        self.index(&tx, id);
        self.q.push_back(tx);
        Ok(id)
    }

    /// Restore path (snapshots / WAL replay): insert WITHOUT chain checks but WITH
    /// index maintenance and duplicate suppression. Returns false if suppressed.
    pub fn insert_unchecked(&mut self, tx: SignedTx) -> bool {
        let id = txid(&tx);
        if self.ids.contains(&id) || self.q.len() >= self.cap {
            return false;
        }
        self.index(&tx, id);
        self.q.push_back(tx);
        true
    }

    fn index(&mut self, tx: &SignedTx, id: [u8; 32]) {
        self.ids.insert(id);
        self.keys.insert((tx.sender, tx.nonce), tx.next_auth);
        if let Tx::ShieldedSpend { nullifier, .. } = &tx.payload {
            self.nullifiers.insert(nullifier.0);
        }
    }

    fn unindex(&mut self, tx: &SignedTx) {
        self.ids.remove(&txid(tx));
        self.keys.remove(&(tx.sender, tx.nonce));
        if let Tx::ShieldedSpend { nullifier, .. } = &tx.payload {
            self.nullifiers.remove(&nullifier.0);
        }
    }

    /// C2.2: commit-time prune. One O(mempool) pass with O(1) membership tests
    /// (the v0 code was O(mempool × included) via nested `any`). Returns removed count.
    pub fn remove_included(&mut self, included: &[(AccountId, u64)]) -> usize {
        if included.is_empty() {
            return 0;
        }
        let gone: HashSet<(AccountId, u64)> = included.iter().copied().collect();
        let before = self.q.len();
        let mut kept = VecDeque::with_capacity(before);
        for tx in std::mem::take(&mut self.q) {
            if gone.contains(&(tx.sender, tx.nonce)) {
                self.unindex(&tx);
            } else {
                kept.push_back(tx);
            }
        }
        self.q = kept;
        before - self.q.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::{commit_at, Wallet};
    use hk_primitives::{Amount, H256};

    /// The transfer asset; unregistered, so `asset_gate` is a no-op and a funded
    /// account's transfer applies cleanly (the admission↔apply agreement test).
    const ASSET: H256 = H256([7; 32]);

    fn acct(i: u8) -> AccountId {
        H256([i; 32])
    }

    /// The L-ratchet seed of account `i` — the one secret the tests hold per account.
    fn seed(i: u8) -> Vec<u8> {
        vec![i]
    }

    /// A minimal chain with `n` genesis accounts (ids 1..=n), each at nonce 0 behind a
    /// REAL L-ratchet commitment (M-2: the door now opens it) and funded in `ASSET`.
    fn mini_chain(n: u8) -> hk_state::State {
        let accounts = (1..=n)
            .map(|i| hk_state::GenesisAccount { id: acct(i), auth_commit: commit_at(&seed(i), 0) })
            .collect();
        let alloc = (1..=n).map(|i| (acct(i), ASSET, 1_000)).collect();
        hk_state::State::from_genesis(&hk_state::Genesis { time: 0, accounts, alloc, fee: None, assets: vec![] })
            .expect("mini genesis")
    }

    fn genesis_anchor(chain: &hk_state::State) -> H256 {
        H256(*chain.pool.latest_anchor().expect("genesis seals an anchor"))
    }

    /// Sign `payload` for account `sender` at ratchet position `nonce` with the
    /// crate's own L-ratchet wallet (`demo::Wallet`, the faucet's and the account
    /// CLI's signer). Keys are deterministic in (seed, nonce), so any slot can be
    /// signed on demand and re-signed after a prune.
    fn sign_at(sender: u8, nonce: u64, payload: Tx) -> SignedTx {
        Wallet::from_seed(seed(sender), acct(sender), nonce).sign(payload)
    }

    /// Sign `payload` claiming to be `sender`, but with `signer`'s key: a VALID Lamport
    /// signature under a key that is not the account's (the wrong-key attacker).
    fn sign_as(sender: u8, signer: u8, nonce: u64, payload: Tx) -> SignedTx {
        Wallet::from_seed(seed(signer), acct(sender), nonce).sign(payload)
    }

    fn transfer_payload(amount: Amount) -> Tx {
        Tx::Transfer { to: acct(99), asset: ASSET, amount }
    }

    fn transfer(sender: u8, nonce: u64) -> SignedTx {
        sign_at(sender, nonce, transfer_payload(1))
    }

    /// The pre-M-2 parking frame: a syntactically complete tx with no key and no
    /// signature. Before M-2 the door admitted it.
    fn unsigned_transfer(sender: u8, nonce: u64) -> SignedTx {
        SignedTx {
            sender: acct(sender),
            nonce,
            payload: transfer_payload(1),
            next_auth: H256([0; 32]),
            lamport_pk: vec![],
            sig: vec![],
        }
    }

    fn spend_payload(anchor: H256, nf: u8) -> Tx {
        Tx::ShieldedSpend {
            anchor,
            nullifier: H256([nf; 32]),
            out_commitment: H256([1; 32]),
            out2_commitment: H256([2; 32]),
            fee: 0,
            credit: None,
            mandate: None,
            proof: vec![],
            stealth_ct: vec![],
            stealth_ct2: vec![],
        }
    }

    /// The signature covers the payload, so the anchor is fixed BEFORE signing.
    fn spend(sender: u8, nonce: u64, nf: u8, anchor: H256) -> SignedTx {
        sign_at(sender, nonce, spend_payload(anchor, nf))
    }

    fn assert_nothing_indexed(mp: &Mempool) {
        assert_eq!(mp.len(), 0);
        assert!(mp.ids.is_empty() && mp.keys.is_empty() && mp.nullifiers.is_empty());
    }

    #[test]
    fn admit_and_duplicate_refusal() {
        let chain = mini_chain(2);
        let mut mp = Mempool::new(16);
        let tx = transfer(1, 0);
        let id = mp.try_admit(tx.clone(), &chain).expect("first admit");
        assert_eq!(mp.len(), 1);
        // exact duplicate → DuplicateTx
        assert_eq!(mp.try_admit(tx, &chain), Err(AdmitError::DuplicateTx));
        // same (sender, nonce), different payload, properly signed → DuplicateSlot
        let tx2 = sign_at(1, 0, transfer_payload(2));
        assert_eq!(
            mp.try_admit(tx2, &chain),
            Err(AdmitError::DuplicateSlot { pending_nonce: 0 })
        );
        assert_eq!(mp.len(), 1);
        assert!(mp.ids.contains(&id));
    }

    #[test]
    fn nonce_rules() {
        let chain = mini_chain(1);
        let mut mp = Mempool::new(16);
        // gap nonces inside the window queue fine (0 then 1)
        mp.try_admit(transfer(1, 0), &chain).unwrap();
        mp.try_admit(transfer(1, 1), &chain).unwrap();
        // unknown sender
        assert_eq!(mp.try_admit(transfer(9, 0), &chain), Err(AdmitError::UnknownSender));
        // beyond window
        assert_eq!(
            mp.try_admit(transfer(1, NONCE_WINDOW), &chain),
            Err(AdmitError::FutureNonce { current: 0, got: NONCE_WINDOW })
        );
        // stale is impossible at nonce 0; simulate by admitting to a chain whose
        // account advanced: mini_chain starts at 0, so check the comparator directly.
        assert!(matches!(
            Mempool::new(4).try_admit(transfer(1, 0), &chain),
            Ok(_)
        ));
    }

    #[test]
    fn stale_nonce_refused_after_the_chain_advances() {
        let mut chain = mini_chain(1);
        let t0 = transfer(1, 0);
        let receipts = chain.apply_block(1, 0, &[t0.clone()]).expect("block applies");
        assert!(receipts[0].result.is_ok(), "{:?}", receipts[0].result);
        let mut mp = Mempool::new(16);
        assert_eq!(
            mp.try_admit(t0, &chain),
            Err(AdmitError::StaleNonce { expected: 1, got: 0 })
        );
        // and the ratcheted account's next key binds to the chain's new auth_commit
        mp.try_admit(transfer(1, 1), &chain).expect("nonce 1 binds to the ratcheted commit");
    }

    #[test]
    fn shielded_nullifier_rules() {
        let chain = mini_chain(1);
        let mut mp = Mempool::new(16);
        // genesis pool: latest root IS a recent anchor
        let anchor = genesis_anchor(&chain);
        mp.try_admit(spend(1, 0, 0x11, anchor), &chain).expect("first spend admits");
        // same nullifier, different envelope slot → NullifierPending
        assert_eq!(mp.try_admit(spend(1, 1, 0x11, anchor), &chain), Err(AdmitError::NullifierPending));
        // bogus anchor → UnknownAnchor (slot 1 is still free — the refusal above indexed nothing)
        assert_eq!(
            mp.try_admit(spend(1, 1, 0x22, H256([0xAA; 32])), &chain),
            Err(AdmitError::UnknownAnchor)
        );
    }

    #[test]
    fn cap_refusal() {
        let chain = mini_chain(1);
        let mut mp = Mempool::new(2);
        mp.try_admit(transfer(1, 0), &chain).unwrap();
        mp.try_admit(transfer(1, 1), &chain).unwrap();
        assert_eq!(mp.try_admit(transfer(1, 2), &chain), Err(AdmitError::Full));
    }

    #[test]
    fn prune_removes_only_included_and_unindexes() {
        let chain = mini_chain(3);
        let mut mp = Mempool::new(64);
        for n in 0..4 {
            mp.try_admit(transfer(1, n), &chain).unwrap();
        }
        mp.try_admit(transfer(2, 0), &chain).unwrap();
        let anchor = genesis_anchor(&chain);
        let s = spend(3, 0, 0x33, anchor);
        mp.try_admit(s.clone(), &chain).unwrap();
        assert_eq!(mp.len(), 6);

        let removed =
            mp.remove_included(&[(acct(1), 0), (acct(1), 1), (acct(3), 0), (acct(9), 7)]);
        assert_eq!(removed, 3);
        assert_eq!(mp.len(), 3);
        // freed slots re-admit (indexes were cleaned)
        mp.try_admit(transfer(1, 0), &chain).expect("slot freed after prune");
        // the pruned spend's id, slot AND nullifier are free again
        mp.try_admit(s, &chain).expect("nullifier freed after prune");
        // survivors intact, FIFO order kept
        let nonces: Vec<u64> =
            mp.iter().filter(|t| t.sender == acct(1)).map(|t| t.nonce).collect();
        assert_eq!(nonces, vec![2, 3, 0]);
    }

    #[test]
    fn insert_unchecked_suppresses_duplicates_and_indexes() {
        // The restore path takes what the WAL/snapshot holds without re-checking —
        // every frame there passed the door when it was written.
        let mut mp = Mempool::new(8);
        let tx = unsigned_transfer(1, 5);
        assert!(mp.insert_unchecked(tx.clone()));
        assert!(!mp.insert_unchecked(tx.clone()));
        assert_eq!(mp.len(), 1);
        assert_eq!(mp.keys.get(&(acct(1), 5)), Some(&tx.next_auth));
    }

    // ---- M-2 (R17, 2026-10-06): the envelope is verified at the door ----

    #[test]
    fn unsigned_tx_refused_before_anything_is_indexed() {
        let chain = mini_chain(1);
        let mut mp = Mempool::new(16);
        // (a) no key, no signature — the parking frame — stops at the length check
        assert_eq!(mp.try_admit(unsigned_transfer(1, 0), &chain), Err(AdmitError::BadEnvelope));
        // right lengths, all zero: a key that is not the account's
        let mut zeroed = unsigned_transfer(1, 0);
        zeroed.lamport_pk = vec![0; PK_LEN];
        zeroed.sig = vec![0; SIG_LEN];
        assert_eq!(mp.try_admit(zeroed, &chain), Err(AdmitError::AuthMismatch));
        // (b) the account's own key, signature zeroed
        let mut nosig = transfer(1, 0);
        nosig.sig = vec![0; SIG_LEN];
        assert_eq!(mp.try_admit(nosig, &chain), Err(AdmitError::BadSignature));
        // one flipped bit in a real signature
        let mut flipped = transfer(1, 0);
        flipped.sig[100] ^= 1;
        assert_eq!(mp.try_admit(flipped, &chain), Err(AdmitError::BadSignature));
        // the signature covers the payload …
        let mut tampered = transfer(1, 0);
        if let Tx::Transfer { amount, .. } = &mut tampered.payload {
            *amount = 999;
        }
        assert_eq!(mp.try_admit(tampered, &chain), Err(AdmitError::BadSignature));
        // … and next_auth (a swapped ratchet commitment is a different message)
        let mut swapped = transfer(1, 0);
        swapped.next_auth = H256([0xEE; 32]);
        assert_eq!(mp.try_admit(swapped, &chain), Err(AdmitError::BadSignature));
        // none of it touched the pool: nothing to WAL, nothing to gossip
        assert_nothing_indexed(&mp);
        // the real thing still admits
        mp.try_admit(transfer(1, 0), &chain).expect("signed tx admits");
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn wrong_key_tx_refused_at_chain_and_along_the_pending_ratchet() {
        let chain = mini_chain(2);
        let mut mp = Mempool::new(16);
        // a VALID Lamport signature under account 2's key, claiming to be account 1
        assert_eq!(
            mp.try_admit(sign_as(1, 2, 0, transfer_payload(1)), &chain),
            Err(AdmitError::AuthMismatch)
        );
        assert_nothing_indexed(&mp);
        // account 1's real nonce 0 goes in; now nonce 1 binds to ITS next_auth …
        mp.try_admit(transfer(1, 0), &chain).unwrap();
        // … which account 2's key at index 1 does not open
        assert_eq!(
            mp.try_admit(sign_as(1, 2, 1, transfer_payload(1)), &chain),
            Err(AdmitError::AuthMismatch)
        );
        // while account 1's own key at index 1 does
        mp.try_admit(transfer(1, 1), &chain).expect("the ratchet's next key binds");
        assert_eq!(mp.len(), 2);
    }

    #[test]
    fn unsigned_tx_cannot_hold_a_victims_slot() {
        // The R17 censorship case: before M-2 an unsigned frame at (victim, nonce) was
        // admitted, and DuplicateSlot then refused the victim's real tx for free.
        let chain = mini_chain(2);
        let mut mp = Mempool::new(16);
        let victim = 1u8;
        // attacker parks an unsigned frame at the victim's current nonce → refused
        assert_eq!(mp.try_admit(unsigned_transfer(victim, 0), &chain), Err(AdmitError::BadEnvelope));
        // attacker parks a frame signed with THEIR OWN key at the victim's nonce → refused
        assert_eq!(
            mp.try_admit(sign_as(victim, 2, 0, transfer_payload(1)), &chain),
            Err(AdmitError::AuthMismatch)
        );
        // attacker parks ahead, at nonce 2, before the victim has anything pending →
        // nothing to bind to, refused (not left unbound for DuplicateSlot to defend)
        assert_eq!(
            mp.try_admit(sign_as(victim, 2, 2, transfer_payload(1)), &chain),
            Err(AdmitError::NonceGap { got: 2, missing: 1 })
        );
        assert_nothing_indexed(&mp);
        // the victim's signed txs admit at 0 and 1 — no DuplicateSlot, no censorship
        mp.try_admit(transfer(victim, 0), &chain).expect("victim's nonce 0 admits");
        mp.try_admit(transfer(victim, 1), &chain).expect("victim's nonce 1 admits");
        // and with 1 pending the attacker still cannot take 2: wrong key for its next_auth
        assert_eq!(
            mp.try_admit(sign_as(victim, 2, 2, transfer_payload(1)), &chain),
            Err(AdmitError::AuthMismatch)
        );
        mp.try_admit(transfer(victim, 2), &chain).expect("victim's nonce 2 admits");
        let nonces: Vec<u64> = mp.iter().filter(|t| t.sender == acct(victim)).map(|t| t.nonce).collect();
        assert_eq!(nonces, vec![0, 1, 2]);
    }

    #[test]
    fn nonce_gap_refused_until_the_predecessor_is_pending() {
        let chain = mini_chain(1);
        let mut mp = Mempool::new(16);
        assert_eq!(
            mp.try_admit(transfer(1, 1), &chain),
            Err(AdmitError::NonceGap { got: 1, missing: 0 })
        );
        mp.try_admit(transfer(1, 0), &chain).unwrap();
        mp.try_admit(transfer(1, 1), &chain).expect("predecessor pending → binds");
        assert_eq!(
            mp.try_admit(transfer(1, 3), &chain),
            Err(AdmitError::NonceGap { got: 3, missing: 2 })
        );
        assert_eq!(mp.len(), 2);
    }

    #[test]
    fn what_the_door_admits_apply_accepts() {
        // The agreement M-2 rests on: every admitted envelope passes apply's own
        // account → nonce → auth-commit → signature path, in block order.
        let mut chain = mini_chain(2);
        let mut mp = Mempool::new(16);
        for tx in [transfer(1, 0), transfer(1, 1), transfer(1, 2), transfer(2, 0)] {
            mp.try_admit(tx, &chain).expect("admits");
        }
        let block: Vec<SignedTx> = mp.iter().cloned().collect();
        let receipts = chain.apply_block(1, 0, &block).expect("block applies");
        for r in &receipts {
            assert!(r.result.is_ok(), "tx {} refused at apply: {:?}", r.index, r.result);
        }
        assert_eq!(chain.accounts[&acct(1)].nonce, 3);
        assert_eq!(chain.accounts[&acct(2)].nonce, 1);
    }

    #[test]
    fn hoisted_verdict_and_try_admit_agree() {
        // R17 review (2026-10-06): the RPC hashes with no lock held
        // (`envelope_verdict`) and binds under the locks (`try_admit_verified`); the
        // WAL replay loop uses `try_admit`. Same frames, same reasons, same precedence,
        // same pool afterwards — including the frames that fail more than one check.
        let chain = mini_chain(2);
        let anchor = genesis_anchor(&chain);
        let mut zeroed = unsigned_transfer(1, 0);
        zeroed.lamport_pk = vec![0; PK_LEN];
        zeroed.sig = vec![0; SIG_LEN];
        let mut nosig = transfer(1, 0);
        nosig.sig = vec![0; SIG_LEN];
        let mut flipped = transfer(1, 1);
        flipped.sig[7] ^= 0x80;
        let frames = vec![
            unsigned_transfer(1, 0),                 // BadEnvelope (lengths)
            zeroed,                                  // AuthMismatch (wrong key, bad sig too)
            nosig,                                   // BadSignature
            sign_as(1, 2, 0, transfer_payload(1)),   // AuthMismatch (a valid foreign signature)
            transfer(1, 2),                          // NonceGap
            transfer(9, 0),                          // UnknownSender
            transfer(1, 0),                          // Ok
            transfer(1, 0),                          // DuplicateTx
            sign_at(1, 0, transfer_payload(2)),      // DuplicateSlot
            flipped,                                 // BadSignature at nonce 1 (predecessor pending)
            transfer(1, 1),                          // Ok
            sign_as(1, 2, 2, transfer_payload(1)),   // AuthMismatch along the ratchet
            spend(2, 0, 0x44, anchor),               // Ok
            spend(2, 1, 0x44, anchor),               // NullifierPending
            spend(2, 1, 0x55, H256([0xAA; 32])),     // UnknownAnchor
            transfer(2, NONCE_WINDOW),               // FutureNonce
        ];
        let mut direct = Mempool::new(4);
        let mut hoisted = Mempool::new(4);
        for (i, tx) in frames.into_iter().enumerate() {
            let verdict = Mempool::envelope_verdict(&tx);
            let a = direct.try_admit(tx.clone(), &chain);
            let b = hoisted.try_admit_verified(tx, &chain, &verdict);
            assert_eq!(a, b, "frame {i}");
            assert_eq!(direct.len(), hoisted.len(), "frame {i}");
        }
        // the cap is the one check the hoisted path can only learn under the lock
        assert_eq!(direct.len(), 3);
        let fourth = transfer(2, 1);
        let fifth = transfer(2, 2);
        assert_eq!(hoisted.try_admit_verified(fourth.clone(), &chain, &Mempool::envelope_verdict(&fourth)), direct.try_admit(fourth, &chain));
        assert_eq!(direct.try_admit(fifth.clone(), &chain), Err(AdmitError::Full));
        assert_eq!(hoisted.try_admit_verified(fifth.clone(), &chain, &Mempool::envelope_verdict(&fifth)), Err(AdmitError::Full));
        // a verdict is a pure function of the frame: wrong lengths never reach a hash
        assert_eq!(Mempool::envelope_verdict(&unsigned_transfer(1, 0)), EnvelopeVerdict { pk_commit: None, signature: Err(AdmitError::BadEnvelope) });
        let good = transfer(1, 0);
        assert_eq!(
            Mempool::envelope_verdict(&good),
            EnvelopeVerdict { pk_commit: Some(lamport::pk_commit(&good.lamport_pk)), signature: Ok(()) }
        );
        let same: Vec<u64> = direct.iter().map(|t| t.nonce).collect();
        let same2: Vec<u64> = hoisted.iter().map(|t| t.nonce).collect();
        assert_eq!(same, same2);
    }

    // ---- R18 (reported 2026-10-04, fixed 2026-10-08): the two PayWord caps at the door ----

    use hk_crypto::payword::PaywordChain;

    /// The settle tests' channel: two settle caps long, so a settle can be past the cap
    /// and still inside the channel (the case apply would hash link by link).
    const CHANNEL_LEN: u32 = 2 * MAX_SETTLE_DELTA as u32;
    const MANDATE: H256 = H256([0xA0; 32]);

    /// A `ChannelOpen` the door judges by its bytes alone (the mandate and the escrow are
    /// apply's business — and apply refuses this one on `mini_chain`, there is no mandate).
    fn open_payload(max_steps: u32) -> Tx {
        Tx::ChannelOpen {
            id: H256([0xC0; 32]),
            mandate: MANDATE,
            payee: acct(2),
            asset: ASSET,
            tip: H256([0xD0; 32]),
            unit_price: 1,
            max_steps,
            expiry: 1_000_000,
        }
    }

    fn settle_payload(id: H256, words: &PaywordChain, step: u32) -> Tx {
        Tx::ChannelSettle { id, word: H256(words.pay(step).expect("inside the chain")), step }
    }

    /// Two accounts and a live PayWord channel: account 1 funds a root mandate and opens a
    /// `CHANNEL_LEN`-link channel to account 2 under it (block 1, nonces 0 and 1), then
    /// account 2 settles the first `settled` links (block 2; skipped at 0) — so the
    /// channel's `highest_step_settled` on the chain, the number the door reads, is
    /// `settled`. Returns the chain, the channel id and the payer's word chain.
    fn channel_chain(settled: u32) -> (hk_state::State, H256, PaywordChain) {
        channel_chain_at(CHANNEL_LEN, settled)
    }

    /// `channel_chain` with the channel opened at `max_steps` — above the consensus cap
    /// this is the shape of a channel opened BEFORE the height (the genesis state never
    /// activates, `payword_cap_from = u64::MAX`, so the open takes any u32; only the
    /// revealed prefix of the word chain has to exist — `CHANNEL_LEN` words are minted).
    fn channel_chain_at(max_steps: u32, settled: u32) -> (hk_state::State, H256, PaywordChain) {
        let accounts = (1..=2)
            .map(|i| hk_state::GenesisAccount { id: acct(i), auth_commit: commit_at(&seed(i), 0) })
            .collect();
        // escrow = unit_price 1 × max_steps, drawn from the root's funder (account 1)
        let alloc = vec![(acct(1), ASSET, max_steps as Amount)];
        let mut chain = hk_state::State::from_genesis(&hk_state::Genesis { time: 0, accounts, alloc, fee: None, assets: vec![] })
            .expect("channel genesis");
        let words = PaywordChain::mint(b"r18-door", b"settle-cap", CHANNEL_LEN);
        let tip = H256(words.tip());
        // the open is account 1's nonce 1 (the root mandate is its nonce 0)
        let id = hk_state::State::derive_channel_id(&acct(1), &acct(2), &tip, 1);
        let block1 = vec![
            sign_at(1, 0, Tx::MandateCreate {
                id: MANDATE,
                parent: None,
                holder: acct(1),
                asset: ASSET,
                rate_per_sec: 0,
                buffer_max: max_steps as Amount,
                per_tx_max: max_steps as Amount,
                initial_buffer: max_steps as Amount,
                expiry: 1_000_000,
                tier: 0,
            }),
            sign_at(1, 1, Tx::ChannelOpen {
                id,
                mandate: MANDATE,
                payee: acct(2),
                asset: ASSET,
                tip,
                unit_price: 1,
                max_steps,
                expiry: 1_000_000,
            }),
        ];
        for r in chain.apply_block(1, 0, &block1).expect("block 1 applies") {
            assert!(r.result.is_ok(), "tx {} refused at apply: {:?}", r.index, r.result);
        }
        if settled > 0 {
            let r = chain
                .apply_block(2, 0, &[sign_at(2, 0, settle_payload(id, &words, settled))])
                .expect("block 2 applies");
            assert!(r[0].result.is_ok(), "{:?}", r[0].result);
        }
        assert_eq!(chain.channels[&id].state.highest_step_settled, u64::from(settled));
        (chain, id, words)
    }

    #[test]
    fn over_cap_channel_open_refused_before_any_hash() {
        let chain = mini_chain(1);
        let mut mp = Mempool::new(16);
        let too_long = MAX_CHANNEL_STEPS as u32 + 1;
        // the state-free verdict refuses it with no hash computed (no pk_commit formed) …
        assert_eq!(
            Mempool::envelope_verdict(&sign_at(1, 0, open_payload(too_long))),
            EnvelopeVerdict { pk_commit: None, signature: Err(AdmitError::ChannelTooLong { max_steps: too_long }) }
        );
        // … and both doors refuse it; u32::MAX is the report's channel
        for max_steps in [too_long, u32::MAX] {
            let tx = sign_at(1, 0, open_payload(max_steps));
            let want = Err(AdmitError::ChannelTooLong { max_steps });
            assert_eq!(mp.try_admit(tx.clone(), &chain), want);
            assert_eq!(mp.try_admit_verified(tx.clone(), &chain, &Mempool::envelope_verdict(&tx)), want);
        }
        // the lengths check comes first: an unsigned over-cap open is still BadEnvelope
        let mut unsigned = unsigned_transfer(1, 0);
        unsigned.payload = open_payload(too_long);
        assert_eq!(mp.try_admit(unsigned, &chain), Err(AdmitError::BadEnvelope));
        // the cap precedes the account walk: an unknown sender's over-cap open names the cap
        assert_eq!(
            mp.try_admit(sign_at(9, 0, open_payload(too_long)), &chain),
            Err(AdmitError::ChannelTooLong { max_steps: too_long })
        );
        // the reason a wallet reads — hk-state's receipt wording (docs/RPC.md quotes it)
        assert_eq!(
            AdmitError::ChannelTooLong { max_steps: too_long }.as_str(),
            format!("channel too long ({too_long} steps, max {MAX_CHANNEL_STEPS})")
        );
        // none of it touched the pool: nothing to WAL, nothing to gossip
        assert_nothing_indexed(&mp);
        // exactly the cap is not the door's business: admitted (apply judges the rest)
        mp.try_admit(sign_at(1, 0, open_payload(MAX_CHANNEL_STEPS as u32)), &chain).expect("a channel at the cap admits");
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn over_cap_channel_settle_refused_at_the_door_in_cap_admitted() {
        // ten links already settled on the chain — the door reads them, not zero
        let (mut chain, id, words) = channel_chain(10);
        let mut mp = Mempool::new(16);
        let cap = MAX_SETTLE_DELTA as u32;
        // one link past the cap, counted from the chain's settled step → refused by both
        // doors, nothing indexed
        let far = sign_at(2, 1, settle_payload(id, &words, 10 + cap + 1));
        let want = Err(AdmitError::SettleDeltaTooLarge { delta: u64::from(cap) + 1 });
        assert_eq!(mp.try_admit(far.clone(), &chain), want);
        assert_eq!(mp.try_admit_verified(far.clone(), &chain, &Mempool::envelope_verdict(&far)), want);
        // the door never hashes a word: the report's shape (the channel's last step, a junk
        // word — apply would hash every link before saying no) is the same refusal
        let junk = sign_at(2, 1, Tx::ChannelSettle { id, word: H256([0xBB; 32]), step: CHANNEL_LEN });
        assert_eq!(
            mp.try_admit(junk, &chain),
            Err(AdmitError::SettleDeltaTooLarge { delta: u64::from(CHANNEL_LEN) - 10 })
        );
        // the reason a wallet reads — hk-state's receipt wording (docs/RPC.md quotes it)
        assert_eq!(
            AdmitError::SettleDeltaTooLarge { delta: u64::from(cap) + 1 }.as_str(),
            format!(
                "settle delta too large ({} links past the highest settled step, max {MAX_SETTLE_DELTA} per settlement)",
                u64::from(cap) + 1
            )
        );
        // a step past max_steps or at/below the settled one on a KNOWN channel is apply's
        // O(1) refusal, not the door's: `settle_delta` answers None, the proposer costs it
        // 0, and the frame goes through (a junk word costs apply no hash either way)
        let past_max = sign_at(2, 1, Tx::ChannelSettle { id, word: H256([0xBB; 32]), step: u32::MAX });
        assert_eq!(chain.settle_delta(&id, u32::MAX), None);
        assert_eq!(settle_cost(&chain, &id, u32::MAX), 0);
        assert!(mp.try_admit(past_max, &chain).is_ok(), "past max_steps: left to apply");
        assert_eq!(mp.remove_included(&[(acct(2), 1)]), 1);
        assert_nothing_indexed(&mp);
        // exactly the cap past the settled step → admitted, and apply accepts it
        let ok = sign_at(2, 1, settle_payload(id, &words, 10 + cap));
        mp.try_admit(ok.clone(), &chain).expect("a settle at the cap admits");
        let r = chain.apply_block(3, 0, &[ok]).expect("block 3 applies");
        assert!(r[0].result.is_ok(), "{:?}", r[0].result);
        assert_eq!(chain.channels[&id].state.highest_step_settled, u64::from(10 + cap));
        assert_eq!(mp.remove_included(&[(acct(2), 1)]), 1);
        // an UNKNOWN channel (R18 review, 2026-10-08): its open may be pending ahead, so
        // the delta is `step` — at or under the cap it is admitted and apply refuses it in
        // O(1) before any hashing (the nonce is not ratcheted by a refusal); past the cap
        // it is refused at the door with the number it asked for — u32::MAX, the reported
        // shape, no longer parks (the first cut admitted it and the proposer never picked it)
        let unknown_id = H256([0xEE; 32]);
        let unknown_far = sign_at(2, 2, Tx::ChannelSettle { id: unknown_id, word: H256([0; 32]), step: u32::MAX });
        assert_eq!(mp.try_admit(unknown_far, &chain), Err(AdmitError::SettleDeltaTooLarge { delta: u64::from(u32::MAX) }));
        let unknown_edge = sign_at(2, 2, Tx::ChannelSettle { id: unknown_id, word: H256([0; 32]), step: cap + 1 });
        assert_eq!(mp.try_admit(unknown_edge, &chain), Err(AdmitError::SettleDeltaTooLarge { delta: u64::from(cap) + 1 }));
        assert_nothing_indexed(&mp);
        let unknown = sign_at(2, 2, Tx::ChannelSettle { id: unknown_id, word: H256([0; 32]), step: cap });
        mp.try_admit(unknown.clone(), &chain).expect("unknown channel at the cap: left to apply");
        let r = chain.apply_block(4, 0, &[unknown]).expect("block 4 applies");
        assert!(r[0].result.is_err());
        assert_eq!(chain.accounts[&acct(2)].nonce, 2);
        assert_eq!(mp.remove_included(&[(acct(2), 2)]), 1);
        // the chain moved, so the door's base moved with it: the rest of the channel
        // (CHANNEL_LEN − (10 + cap) = cap − 10 links) admits
        mp.try_admit(sign_at(2, 2, settle_payload(id, &words, CHANNEL_LEN)), &chain).expect("the rest of the channel admits");
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn r18_a_settle_the_proposer_would_never_pick_is_refused_at_the_door() {
        // R18 review (2026-10-08): the door refuses by the proposer's own cost function.
        // A channel opened BEFORE the height at u32::MAX steps (the cap never saw it),
        // climbed by an accepted settle to one link past `budget − cap`: the next settle at
        // `budget + 1` has a delta inside the consensus cap — consensus would accept it
        // with the right word — but costs `budget + 1` links from the tip, which no block
        // this node builds can carry; the first cut parked it forever.
        let budget = MAX_SETTLE_LINKS_PER_BLOCK as u32;
        let cap = MAX_SETTLE_DELTA as u32;
        let (chain, id, words) = channel_chain_at(u32::MAX, budget - cap + 1);
        let mut mp = Mempool::new(16);
        let too_costly = sign_at(2, 1, Tx::ChannelSettle { id, word: H256([0xBB; 32]), step: budget + 1 });
        assert_eq!(chain.settle_delta(&id, budget + 1), Some(MAX_SETTLE_DELTA), "inside the consensus cap");
        assert_eq!(settle_cost(&chain, &id, budget + 1), MAX_SETTLE_LINKS_PER_BLOCK + 1);
        let want = Err(AdmitError::SettleTooCostly { links: MAX_SETTLE_LINKS_PER_BLOCK + 1 });
        assert_eq!(mp.try_admit(too_costly.clone(), &chain), want);
        assert_eq!(mp.try_admit_verified(too_costly.clone(), &chain, &Mempool::envelope_verdict(&too_costly)), want);
        // the delta cap precedes the cost: past both, the reason is the delta
        let far = sign_at(2, 1, Tx::ChannelSettle { id, word: H256([0xBB; 32]), step: u32::MAX });
        assert_eq!(mp.try_admit(far, &chain), Err(AdmitError::SettleDeltaTooLarge { delta: u64::from(u32::MAX) - u64::from(budget - cap + 1) }));
        // none of it touched the pool: nothing to WAL, nothing to gossip
        assert_nothing_indexed(&mp);
        // the reason a wallet reads (admission wording — docs/RPC.md quotes it)
        assert_eq!(
            AdmitError::SettleTooCostly { links: MAX_SETTLE_LINKS_PER_BLOCK + 1 }.as_str(),
            format!(
                "settle too costly to propose ({} links from the tip, max {MAX_SETTLE_LINKS_PER_BLOCK} per block until verification is incremental — settle in pieces)",
                MAX_SETTLE_LINKS_PER_BLOCK + 1
            )
        );
        // exactly the budget, with the real word: admitted — and the proposer picks it on
        // an empty block (it fills the budget alone)
        let at_budget = sign_at(2, 1, settle_payload(id, &words, budget));
        mp.try_admit(at_budget.clone(), &chain).expect("a settle at the budget admits");
        let (picked, held) = crate::state::select_batch_txs(&chain, [at_budget].iter(), 1, 0);
        assert_eq!((picked.len(), held), (1, 0));
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn what_the_door_admits_the_proposer_picks() {
        // THE invariant of the R18 review: every tx `try_admit` admits is one
        // `select_batch_txs` picks on an empty block of the same chain — so nothing
        // admitted can park. Frames of every settle shape the door sees, on a channel ten
        // links in, through both doors; the admitted ones are then offered to the proposer
        // one at a time.
        let (chain, id, words) = channel_chain(10);
        let cap = MAX_SETTLE_DELTA as u32;
        let unknown = H256([0xEE; 32]);
        let frames = vec![
            sign_at(2, 1, settle_payload(id, &words, 10 + cap)),                                   // Ok: exactly the cap
            sign_at(2, 1, settle_payload(id, &words, 10 + cap + 1)),                               // SettleDeltaTooLarge
            sign_at(2, 1, Tx::ChannelSettle { id, word: H256([0xBB; 32]), step: CHANNEL_LEN }),     // SettleDeltaTooLarge (the channel's top)
            sign_at(2, 1, Tx::ChannelSettle { id, word: H256([0xBB; 32]), step: u32::MAX }),        // Ok: over max → apply's O(1) refusal, cost 0
            sign_at(2, 1, Tx::ChannelSettle { id, word: H256([0xBB; 32]), step: 10 }),              // Ok: stale → apply's O(1) refusal, cost 0
            sign_at(2, 1, Tx::ChannelSettle { id: unknown, word: H256([0; 32]), step: cap }),       // Ok: unknown at the cap, cost `step`
            sign_at(2, 1, Tx::ChannelSettle { id: unknown, word: H256([0; 32]), step: cap + 1 }),   // SettleDeltaTooLarge (unknown, past the cap)
            sign_at(2, 1, Tx::ChannelSettle { id: unknown, word: H256([0; 32]), step: u32::MAX }),  // SettleDeltaTooLarge (the reported shape)
            transfer(1, 2),                                                                         // Ok: never costed
        ];
        let mut admitted = 0;
        for (i, tx) in frames.into_iter().enumerate() {
            let mut direct = Mempool::new(4);
            let mut hoisted = Mempool::new(4);
            let a = direct.try_admit(tx.clone(), &chain);
            let b = hoisted.try_admit_verified(tx.clone(), &chain, &Mempool::envelope_verdict(&tx));
            assert_eq!(a, b, "frame {i}");
            if a.is_ok() {
                admitted += 1;
                let (picked, held) = crate::state::select_batch_txs(&chain, [tx].iter(), 1, 0);
                assert_eq!((picked.len(), held), (1, 0), "frame {i}: admitted but not proposable");
            }
        }
        assert_eq!(admitted, 5);
    }

    #[test]
    fn r18_caps_refuse_the_same_through_both_doors() {
        // The R17-review invariant (`hoisted_verdict_and_try_admit_agree`) extended to the
        // R18 frames: `try_admit` (WAL replay) and `envelope_verdict` + `try_admit_verified`
        // (RPC) give the same reason, in the same precedence, and leave the same pool.
        let (chain, id, words) = channel_chain(0);
        let cap = MAX_SETTLE_DELTA as u32;
        let too_long = MAX_CHANNEL_STEPS as u32 + 1;
        let mut unsigned_open = unsigned_transfer(1, 2);
        unsigned_open.payload = open_payload(too_long);
        let frames: Vec<(SignedTx, Result<(), AdmitError>)> = vec![
            // SettleDeltaTooLarge, counted from the chain's 0
            (sign_at(2, 0, settle_payload(id, &words, cap + 1)), Err(AdmitError::SettleDeltaTooLarge { delta: u64::from(cap) + 1 })),
            // SettleDeltaTooLarge — an unknown channel's delta is its step (R18 review)
            (sign_at(2, 0, Tx::ChannelSettle { id: H256([0xEE; 32]), word: H256([0; 32]), step: cap + 1 }), Err(AdmitError::SettleDeltaTooLarge { delta: u64::from(cap) + 1 })),
            // Ok — at the cap
            (sign_at(2, 0, settle_payload(id, &words, cap)), Ok(())),
            // SettleDeltaTooLarge — judged against the CHAIN, not the settle pending at
            // nonce 0 (the documented conservative case: it waits for the first to land)
            (sign_at(2, 1, settle_payload(id, &words, 2 * cap)), Err(AdmitError::SettleDeltaTooLarge { delta: 2 * u64::from(cap) })),
            // ChannelTooLong (account 1 is at nonce 2 after block 1)
            (sign_at(1, 2, open_payload(too_long)), Err(AdmitError::ChannelTooLong { max_steps: too_long })),
            // BadEnvelope — the lengths precede the cap
            (unsigned_open, Err(AdmitError::BadEnvelope)),
            // ChannelTooLong — the cap precedes UnknownSender
            (sign_at(9, 0, open_payload(too_long)), Err(AdmitError::ChannelTooLong { max_steps: too_long })),
            // Ok — at the cap
            (sign_at(1, 2, open_payload(MAX_CHANNEL_STEPS as u32)), Ok(())),
            // ChannelTooLong — the cap precedes the pending-ratchet walk
            (sign_at(1, 3, open_payload(too_long)), Err(AdmitError::ChannelTooLong { max_steps: too_long })),
        ];
        let mut direct = Mempool::new(8);
        let mut hoisted = Mempool::new(8);
        for (i, (tx, want)) in frames.into_iter().enumerate() {
            let verdict = Mempool::envelope_verdict(&tx);
            let a = direct.try_admit(tx.clone(), &chain);
            let b = hoisted.try_admit_verified(tx, &chain, &verdict);
            assert_eq!(a, b, "frame {i}");
            assert_eq!(a.map(|_| ()), want, "frame {i}");
            assert_eq!(direct.len(), hoisted.len(), "frame {i}");
        }
        assert_eq!(direct.len(), 2);
        let same: Vec<(AccountId, u64)> = direct.iter().map(|t| (t.sender, t.nonce)).collect();
        let same2: Vec<(AccountId, u64)> = hoisted.iter().map(|t| (t.sender, t.nonce)).collect();
        assert_eq!(same, same2);
    }
}
