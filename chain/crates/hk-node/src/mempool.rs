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
//! Admission cannot create false rejections apply would have accepted, with two
//! deliberate exceptions: `NONCE_WINDOW` bounds how far ahead of the account's current
//! nonce a tx may queue (gap txs apply fine in-block; an unbounded future is a spam
//! vector), and a tx more than one nonce ahead of the chain needs its predecessor
//! PENDING here (`NonceGap`) — without it the key binding cannot be checked, and an
//! unbound slot is exactly the parking spot M-2 closes. Honest clients sign and submit
//! in nonce order (the wallet, the faucet, the storm's home-node rule) and gossip is a
//! FIFO single hop, so order survives; a hole could only come from a lost push, after
//! which the successor could not have applied on that node anyway.
//!
//! Check order is cheap-first: cap, duplicates, lengths, account/nonce, pool lookups,
//! then the key commitment (one SHAKE over 16 KiB), then the signature (256 SHAKEs) —
//! a flood of junk is refused before it costs a hash. Nothing is indexed, and nothing
//! reaches the WAL or gossip, until every check has passed.
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

use crate::batch::txid;

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
        }
    }
}

/// What the state-free half of admission said about one envelope (R17 review, 2026-10-06):
/// the two hashes of M-2, computed by [`Mempool::envelope_verdict`] with no lock held and
/// consumed by [`Mempool::try_admit_verified`] under the locks. Carries verdicts, not
/// decisions, so the consumer applies them at the same positions `try_admit` does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeVerdict {
    /// `lamport::pk_commit(&tx.lamport_pk)` — `None` when the lengths are wrong (M-2 (a)
    /// refuses before any hash, exactly as `try_admit` does).
    pk_commit: Option<[u8; 32]>,
    /// M-2 (b): `Ok` when `State::verify_envelope` accepted the signature over the tx's own
    /// bytes; `BadSignature`, or `BadEnvelope` when the signing digest cannot form.
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
        // Cheap-first: a cap-full pool or a duplicate costs no hash (the WAL replay loop
        // and the tests come through here).
        self.gate(&tx)?;
        let verdict = Self::envelope_verdict(&tx);
        self.try_admit_verified(tx, chain, &verdict)
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

    /// The state-dependent half of admission, under the locks: cap / duplicate / slot,
    /// account and nonce window, pool lookups, the pending-ratchet binding of
    /// `verdict.pk_commit`, then `verdict.signature` — each refusal at the position
    /// `try_admit` gives it, so the two entry points can never disagree on a reason.
    /// `verdict` must have been computed from THIS `tx` (`envelope_verdict`); the RPC
    /// computes it with no lock held.
    pub fn try_admit_verified(
        &mut self,
        tx: SignedTx,
        chain: &hk_state::State,
        verdict: &EnvelopeVerdict,
    ) -> Result<[u8; 32], AdmitError> {
        let id = self.gate(&tx)?;
        // M-2 (a): wrong lengths were refused before any hash was computed.
        let Some(pk_commit) = verdict.pk_commit else {
            return Err(AdmitError::BadEnvelope);
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
}
