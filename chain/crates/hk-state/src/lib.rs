//! hk-state — the deterministic HashKinetics state machine (plan §7.3/§7.4).
//! This is what the consensus engine drives: given a block (time + ordered SignedTxs),
//! apply them and produce receipts + a state commitment.
//!
//! v0 modules wired: accounts (L-ratchet auth, leaf-index=nonce discipline),
//! balances (transparent skeleton — shielded pool replaces user balances in P2),
//! MandateTree (hk-mandate — consensus-enforced budgets), PayWord channels.
//!
//! Determinism rules: no clocks, no randomness, no iteration over unordered maps;
//! every rejection is a typed error; a failed tx mutates NOTHING (including the
//! account ratchet — replay of a failed tx is a mempool concern, documented).

pub mod pool;
pub mod tx;

#[cfg(test)]
mod tests;

use hk_crypto::hash::{shake256_32, DOM_ACCOUNT_ID, DOM_CHANNEL_ID, DOM_STATE_COMMIT};
use hk_crypto::{lamport, payword};
use hk_mandate::{MandateTree, SpendError};
use hk_primitives::{
    AccountId, Amount, AssetId, ChannelId, ChannelState, H256, MandateId, MandateNode, SigScheme,
    Timestamp,
};
use hk_spend_circuit::agg::{KIND_MINT, KIND_SPEND};
use hk_spend_circuit::{tx_binding_for, MintPublic, SpendPublic};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use crate::pool::{PoolState, ProofVerifier, RejectAllVerifier};
use crate::tx::{signing_digest, SignedTx, Tx};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub auth_commit: H256,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Channel {
    pub state: ChannelState,
    pub escrow_remaining: Amount,
    pub refunded: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisAccount {
    pub id: AccountId,
    pub auth_commit: H256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Genesis {
    pub time: Timestamp,
    pub accounts: Vec<GenesisAccount>,
    pub alloc: Vec<(AccountId, AssetId, Amount)>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Event {
    Transferred { from: AccountId, to: AccountId, asset: AssetId, amount: Amount },
    MandateCreated { id: MandateId },
    MandateRevoked { id: MandateId },
    MandateSpent { leaf: MandateId, to: AccountId, amount: Amount },
    ChannelOpened { id: ChannelId, escrow: Amount },
    ChannelSettled { id: ChannelId, upto_step: u32, paid: Amount },
    ChannelRefunded { id: ChannelId, amount: Amount },
    /// A commitment entered the pool, locking `value` (wallets scan these to track the tree).
    PoolMinted { commitment: H256, value: Amount },
    /// A hidden note was spent: nullifier burned, TWO output commitments admitted
    /// (pay + change), `fee` unshielded to `credit` (if any). Note what is ABSENT:
    /// who, how much, which note.
    PoolSpent {
        nullifier: H256,
        out_commitment: H256,
        out2_commitment: H256,
        fee: Amount,
        credit: Option<AccountId>,
    },
    /// U1: a runtime account was created (and possibly funded) by `creator`.
    /// APPENDED LAST: `Receipt.result` carries `Vec<Event>` through bincode snapshots —
    /// variant tags before this one must never shift.
    AccountCreated { id: AccountId, creator: AccountId, asset: AssetId, funded: Amount },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub index: usize,
    pub result: Result<Vec<Event>, String>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum StateError {
    #[error("unknown account")]
    UnknownAccount,
    #[error("duplicate genesis account")]
    DuplicateAccount,
    #[error("bad nonce: expected {expected}, got {got}")]
    BadNonce { expected: u64, got: u64 },
    #[error("lamport pk does not open the account auth commitment")]
    AuthMismatch,
    #[error("bad signature")]
    BadSignature,
    #[error("tx encoding failed")]
    Encode,
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: Amount, need: Amount },
    #[error("mandate: {0}")]
    Mandate(#[from] SpendError),
    #[error("unknown mandate")]
    UnknownMandate,
    #[error("duplicate mandate id")]
    DuplicateMandate,
    #[error("sender is not the required mandate holder")]
    NotHolder,
    #[error("unknown channel")]
    UnknownChannel,
    #[error("duplicate channel id")]
    DuplicateChannel,
    #[error("channel id does not match derived id")]
    ChannelIdMismatch,
    #[error("channel already refunded")]
    ChannelRefunded,
    #[error("channel not yet expired")]
    NotExpired,
    #[error("invalid payword settlement proof")]
    BadSettlement,
    #[error("settle step invalid (stale, zero, or beyond max)")]
    BadStep,
    #[error("amount overflow")]
    Overflow,
    #[error("zero amount")]
    ZeroAmount,
    #[error("block height must be parent+1")]
    BadHeight,
    #[error("block time must not go backwards")]
    TimeBackwards,
    #[error("pool proof rejected (invalid, or no verifier wired)")]
    PoolProofInvalid,
    #[error("unknown pool anchor")]
    PoolUnknownAnchor,
    #[error("nullifier already spent (double spend)")]
    PoolDoubleSpend,
    #[error("pool asset mismatch")]
    PoolAssetMismatch,
    #[error("pool value exceeds u64 range")]
    PoolValueRange,
    #[error("shielded fee requires a credit account")]
    PoolFeeNeedsCredit,
    #[error("commitment tree full")]
    PoolFull,
    #[error("account already exists")]
    AccountExists,
    #[error("account id does not match H(auth_commit)")]
    AccountIdMismatch,
    /// U4: the flat protocol fee could not be paid. Charged BEFORE dispatch and
    /// refunded on refusal, so a refused tx never costs money — this error means
    /// the sender couldn't even cover the envelope fee.
    #[error("insufficient balance for the protocol fee (have {have}, need {need})")]
    InsufficientFee { have: Amount, need: Amount },
}

/// U4: the asset the flat protocol fee is charged in (the staging USD test asset).
pub const FEE_ASSET: AssetId = H256([9u8; 32]);

pub struct State {
    pub height: u64,
    pub time: Timestamp,
    pub accounts: BTreeMap<AccountId, Account>,
    pub balances: BTreeMap<(AccountId, AssetId), Amount>,
    pub mandates: MandateTree,
    /// Root mandate id → the account that funds every spend under that tree.
    pub root_funding: BTreeMap<MandateId, AccountId>,
    pub channels: BTreeMap<ChannelId, Channel>,
    /// The shielded pool (P2.0): commitment tree, anchors, nullifiers, conservation ledger.
    pub pool: PoolState,
    /// STARK verification, injected by the node (WS2 wires the real SP1 verifier).
    /// Default = [`RejectAllVerifier`]: an unwired node REFUSES shielded traffic.
    pub verifier: Arc<dyn ProofVerifier>,
    /// P2.3 batch-level aggregation coverage: the node verifies ONE aggregate STARK per
    /// block and injects the covered (kind, expected-publics) keys here BEFORE
    /// `apply_block`; a PROOF-LESS pool tx is valid iff its key is in this set. Cleared
    /// at every block end. TRANSIENT — not part of the state commitment (all honest
    /// nodes derive the same set from the same batch, same vks).
    pub agg_cover: std::collections::BTreeSet<[u8; 32]>,
    /// U4: flat per-envelope protocol fee in micro-units of [`FEE_ASSET`]. 0 = off.
    /// CONFIG, not state — set identically fleet-wide (consensus constant), never
    /// snapshotted (a snapshot must not smuggle in a fee policy).
    pub fee_micro: Amount,
    /// U4: first height at which the fee is charged (activation boundary — lets a
    /// rolling upgrade complete before behavior diverges). u64::MAX = never.
    pub fee_from: u64,
    /// U4: running total of burned fees — REAL state (in Σ once nonzero), snapshotted.
    pub fees_burned: Amount,
}

/// The persistent image of [`State`] (P3.0/WS-B): every field that feeds the state
/// commitment, in serde form. `MandateTree` derives whole (private map included);
/// `PoolState` carries the frontier + anchor order explicitly (the commitment covers
/// only index+root, so restore-by-commitment alone would corrupt the next append).
/// Encoding: bincode (the wire codec's format) — never JSON (tuple map keys).
#[derive(Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub height: u64,
    pub time: Timestamp,
    pub accounts: BTreeMap<AccountId, Account>,
    pub balances: BTreeMap<(AccountId, AssetId), Amount>,
    pub mandates: MandateTree,
    pub root_funding: BTreeMap<MandateId, AccountId>,
    pub channels: BTreeMap<ChannelId, Channel>,
    pub pool: PoolState,
    /// U4 (snapshot format v2 — see `NodeStore`): total protocol fees burned.
    pub fees_burned: Amount,
}

impl Default for State {
    fn default() -> Self {
        Self {
            height: 0,
            time: 0,
            accounts: BTreeMap::new(),
            balances: BTreeMap::new(),
            mandates: MandateTree::default(),
            root_funding: BTreeMap::new(),
            channels: BTreeMap::new(),
            pool: PoolState::default(),
            verifier: Arc::new(RejectAllVerifier),
            agg_cover: std::collections::BTreeSet::new(),
            fee_micro: 0,
            fee_from: u64::MAX,
            fees_burned: 0,
        }
    }
}

/// The SPEND public statement the chain expects — DERIVED from tx fields + the binding
/// rule. Single source for the per-proof verifier AND the aggregation tier (P2.3).
pub fn expected_spend_public(
    anchor: &H256, nullifier: &H256, out: &H256, out2: &H256, fee: Amount,
    credit: &Option<AccountId>,
) -> SpendPublic {
    let credit_bytes = credit.map(|a| a.0).unwrap_or([0u8; 32]);
    SpendPublic {
        merkle_root: anchor.0,
        nullifier: nullifier.0,
        out_commitment: out.0,
        out2_commitment: out2.0,
        fee: fee as u64,
        tx_binding: tx_binding_for(&credit_bytes, fee as u64),
    }
}

/// The MINT public statement the chain expects.
pub fn expected_mint_public(commitment: &H256, value: Amount) -> MintPublic {
    MintPublic { commitment: commitment.0, value: value as u64 }
}

impl State {
    pub fn from_genesis(g: &Genesis) -> Result<Self, StateError> {
        let mut s = State { height: 0, time: g.time, ..Default::default() };
        for ga in &g.accounts {
            if s.accounts.insert(ga.id, Account { auth_commit: ga.auth_commit, nonce: 0 }).is_some() {
                return Err(StateError::DuplicateAccount);
            }
        }
        for (id, asset, amount) in &g.alloc {
            let e = s.balances.entry((*id, *asset)).or_insert(0);
            *e = e.saturating_add(*amount);
        }
        s.pool.seal_anchor(); // genesis anchor: the empty-tree root
        Ok(s)
    }

    pub fn balance(&self, id: &AccountId, asset: &AssetId) -> Amount {
        *self.balances.get(&(*id, *asset)).unwrap_or(&0)
    }

    /// Apply one block. Block-level violations are hard errors; per-tx failures are
    /// receipts (the "rejected by consensus" the demo shows).
    pub fn apply_block(&mut self, height: u64, time: Timestamp, txs: &[SignedTx]) -> Result<Vec<Receipt>, StateError> {
        self.apply_block_verified(height, time, txs, None)
    }

    /// HK-R5.2: `apply_block` with optional PRECOMPUTED envelope-signature verdicts
    /// (`verify_envelope`, one per tx, same order). The pure Lamport verification is
    /// the bulk of a fat transparent block's apply cost and is order-free, so the
    /// node runs it in parallel OUTSIDE the state lock and hands the verdicts in;
    /// the state-dependent checks (account, nonce, auth-commit binding) and the
    /// ratchet stay strictly ordered here. `None` = verify inline (identical to the
    /// historical behavior, and what single-tx callers and tests use).
    pub fn apply_block_verified(
        &mut self,
        height: u64,
        time: Timestamp,
        txs: &[SignedTx],
        sig_verdicts: Option<&[bool]>,
    ) -> Result<Vec<Receipt>, StateError> {
        if height != self.height + 1 {
            return Err(StateError::BadHeight);
        }
        if time < self.time {
            return Err(StateError::TimeBackwards);
        }
        if let Some(v) = sig_verdicts {
            if v.len() != txs.len() {
                return Err(StateError::BadHeight); // caller bug — refuse rather than misattribute
            }
        }
        self.height = height;
        self.time = time;
        let mut receipts = Vec::with_capacity(txs.len());
        for (i, stx) in txs.iter().enumerate() {
            let pre = sig_verdicts.map(|v| v[i]);
            let result = self.apply_tx_at(stx, pre).map_err(|e| e.to_string());
            receipts.push(Receipt { index: i, result });
        }
        // Block end: this block's pool root becomes a spendable anchor (dedup + window),
        // and any aggregation coverage expires with the block.
        self.pool.seal_anchor();
        self.agg_cover.clear();
        Ok(receipts)
    }

    /// P2.3: install this block's aggregation coverage (call BEFORE `apply_block`; the
    /// node does this only after the batch's aggregate STARK verified).
    pub fn set_block_coverage(&mut self, cover: std::collections::BTreeSet<[u8; 32]>) {
        self.agg_cover = cover;
    }

    /// Verify envelope (account, nonce, auth commitment, Lamport signature), then
    /// dispatch. Ratchets the account ONLY on success.
    pub fn apply_tx(&mut self, stx: &SignedTx) -> Result<Vec<Event>, StateError> {
        self.apply_tx_at(stx, None)
    }

    /// HK-R5.2: the pure, state-free part of envelope verification — signing digest +
    /// Lamport signature over the tx's OWN fields. Safe to evaluate in parallel for a
    /// whole block; the binding of the key to the account (`auth_commit`) remains a
    /// state-dependent check inside `apply_tx_at`, so precomputing this changes no
    /// outcome, only where the CPU time is spent.
    pub fn verify_envelope(stx: &SignedTx) -> bool {
        match signing_digest(&stx.payload, &stx.sender, stx.nonce, &stx.next_auth) {
            Some(digest) => lamport::verify(&stx.lamport_pk, &digest, &stx.sig).is_ok(),
            None => false,
        }
    }

    /// `apply_tx` with an optional precomputed `verify_envelope` verdict. Check order
    /// is IDENTICAL to the historical inline path (account → nonce → auth-commit →
    /// signature), so the success set and every receipt are byte-for-byte the same
    /// whether verdicts were precomputed or not — determinism across the fleet does
    /// not depend on which path a node took.
    fn apply_tx_at(&mut self, stx: &SignedTx, pre_sig: Option<bool>) -> Result<Vec<Event>, StateError> {
        let acc = self.accounts.get(&stx.sender).ok_or(StateError::UnknownAccount)?;
        if stx.nonce != acc.nonce {
            return Err(StateError::BadNonce { expected: acc.nonce, got: stx.nonce });
        }
        if lamport::pk_commit(&stx.lamport_pk) != acc.auth_commit.0 {
            return Err(StateError::AuthMismatch);
        }
        let sig_ok = match pre_sig {
            Some(v) => v,
            None => Self::verify_envelope(stx),
        };
        if !sig_ok {
            // Preserve the historical error split: an unencodable payload was Encode,
            // a bad signature was BadSignature. `verify_envelope` folds both into
            // `false`; distinguish them again here (cheap — digest only).
            if signing_digest(&stx.payload, &stx.sender, stx.nonce, &stx.next_auth).is_none() {
                return Err(StateError::Encode);
            }
            return Err(StateError::BadSignature);
        }

        // U4: flat envelope fee — charged FIRST (so the tx's own spend sees the
        // post-fee balance), refunded in full if dispatch refuses (a refused tx
        // never moves money — the existing atomicity contract holds). Burned on
        // success: debited, never credited anywhere.
        let fee = if self.height >= self.fee_from { self.fee_micro } else { 0 };
        if fee > 0 {
            let have = self.balance(&stx.sender, &FEE_ASSET);
            if have < fee {
                return Err(StateError::InsufficientFee { have, need: fee });
            }
            self.debit(&stx.sender, &FEE_ASSET, fee).expect("balance checked above");
        }

        let events = match self.dispatch(&stx.sender, &stx.payload) {
            Ok(ev) => ev,
            Err(e) => {
                if fee > 0 {
                    // Every dispatch arm checks before it mutates, so a refusal left
                    // the state untouched — refunding the fee restores it exactly.
                    self.credit(&stx.sender, &FEE_ASSET, fee);
                }
                return Err(e);
            }
        };
        if fee > 0 {
            self.fees_burned = self.fees_burned.saturating_add(fee);
        }

        // Ratchet (the leaf-index=nonce discipline, plan §3.3): key consumed, next committed.
        let acc = self.accounts.get_mut(&stx.sender).expect("checked above");
        acc.auth_commit = stx.next_auth;
        acc.nonce += 1;
        Ok(events)
    }

    fn dispatch(&mut self, sender: &AccountId, tx: &Tx) -> Result<Vec<Event>, StateError> {
        match tx {
            Tx::Transfer { to, asset, amount } => self.do_transfer(sender, to, asset, *amount),
            Tx::AccountCreate { id, auth_commit, asset, amount } => {
                self.do_account_create(sender, id, auth_commit, asset, *amount)
            }
            Tx::MandateCreate { id, parent, holder, asset, rate_per_sec, buffer_max, per_tx_max, initial_buffer, expiry, tier } => {
                self.do_mandate_create(sender, *id, *parent, *holder, *asset, *rate_per_sec, *buffer_max, *per_tx_max, *initial_buffer, *expiry, *tier)
            }
            Tx::MandateSpend { leaf, to, amount } => self.do_mandate_spend(sender, leaf, to, *amount),
            Tx::MandateRevoke { target } => self.do_mandate_revoke(sender, target),
            Tx::ChannelOpen { id, mandate, payee, asset, tip, unit_price, max_steps, expiry } => {
                self.do_channel_open(sender, *id, *mandate, *payee, *asset, *tip, *unit_price, *max_steps, *expiry)
            }
            Tx::ChannelSettle { id, word, step } => self.do_channel_settle(id, word, *step),
            Tx::ChannelRefund { id } => self.do_channel_refund(sender, id),
            Tx::MintToPool { asset, value, commitment, proof, .. } => {
                self.do_mint_to_pool(sender, asset, *value, commitment, proof)
            }
            Tx::ShieldedSpend {
                anchor, nullifier, out_commitment, out2_commitment, fee, credit, mandate,
                proof, ..
            } => self.do_shielded_spend(
                sender, anchor, nullifier, out_commitment, out2_commitment, *fee, credit,
                mandate, proof,
            ),
        }
    }

    // ---- balances ----

    fn debit(&mut self, id: &AccountId, asset: &AssetId, amount: Amount) -> Result<(), StateError> {
        let have = self.balance(id, asset);
        if have < amount {
            return Err(StateError::InsufficientBalance { have, need: amount });
        }
        self.balances.insert((*id, *asset), have - amount);
        Ok(())
    }

    fn credit(&mut self, id: &AccountId, asset: &AssetId, amount: Amount) {
        let e = self.balances.entry((*id, *asset)).or_insert(0);
        *e = e.saturating_add(amount);
    }

    fn do_transfer(&mut self, from: &AccountId, to: &AccountId, asset: &AssetId, amount: Amount) -> Result<Vec<Event>, StateError> {
        if amount == 0 {
            return Err(StateError::ZeroAmount);
        }
        self.debit(from, asset, amount)?;
        self.credit(to, asset, amount);
        Ok(vec![Event::Transferred { from: *from, to: *to, asset: *asset, amount }])
    }

    /// U1: runtime account creation. The id is DERIVED from the auth commitment
    /// (`H(DOM_ACCOUNT_ID ‖ auth_commit)`) — permissionless, squat-proof: only whoever
    /// holds the key material behind `auth_commit` can produce a matching id, and an
    /// existing account (genesis-named or derived) can never be overwritten. The SENDER
    /// pays the opening balance from its own funds (`amount` may be 0); check order
    /// mirrors the rest of the state machine — structural refusals before money moves,
    /// so a failed create never debits.
    fn do_account_create(
        &mut self,
        sender: &AccountId,
        id: &AccountId,
        auth_commit: &H256,
        asset: &AssetId,
        amount: Amount,
    ) -> Result<Vec<Event>, StateError> {
        let derived = H256(shake256_32(DOM_ACCOUNT_ID, &[&auth_commit.0]));
        if *id != derived {
            return Err(StateError::AccountIdMismatch);
        }
        if self.accounts.contains_key(id) {
            return Err(StateError::AccountExists);
        }
        if amount > 0 {
            self.debit(sender, asset, amount)?;
        }
        self.accounts.insert(*id, Account { auth_commit: *auth_commit, nonce: 0 });
        if amount > 0 {
            self.credit(id, asset, amount);
        }
        Ok(vec![Event::AccountCreated { id: *id, creator: *sender, asset: *asset, funded: amount }])
    }

    // ---- mandates ----

    fn holder_of(&self, id: &MandateId) -> Result<AccountId, StateError> {
        let node = self.mandates.get(id).ok_or(StateError::UnknownMandate)?;
        let bytes: [u8; 32] = node.holder_key.as_slice().try_into().map_err(|_| StateError::UnknownMandate)?;
        Ok(H256(bytes))
    }

    #[allow(clippy::too_many_arguments)]
    fn do_mandate_create(
        &mut self, sender: &AccountId, id: MandateId, parent: Option<MandateId>, holder: AccountId,
        asset: AssetId, rate_per_sec: Amount, buffer_max: Amount, per_tx_max: Amount,
        initial_buffer: Amount, expiry: Timestamp, tier: u8,
    ) -> Result<Vec<Event>, StateError> {
        if self.mandates.get(&id).is_some() {
            return Err(StateError::DuplicateMandate);
        }
        if let Some(p) = parent {
            // Child creation is a PARENT-holder act (delegation, plan §5.1).
            if self.holder_of(&p)? != *sender {
                return Err(StateError::NotHolder);
            }
        }
        let node = MandateNode {
            id,
            parent,
            holder_key: holder.0.to_vec(),
            scheme: SigScheme::LamportRatchetV0,
            asset,
            rate_per_sec,
            buffer_max,
            per_tx_max,
            expiry,
            revoked: false,
            buffer: initial_buffer.min(buffer_max),
            last_accrual: self.time,
            tier,
        };
        self.mandates.insert(node)?; // enforces attenuation (expiry/per_tx narrowing)
        if parent.is_none() {
            // Root: the creator is the funding account for the whole tree.
            self.root_funding.insert(id, *sender);
        }
        Ok(vec![Event::MandateCreated { id }])
    }

    fn do_mandate_spend(&mut self, sender: &AccountId, leaf: &MandateId, to: &AccountId, amount: Amount) -> Result<Vec<Event>, StateError> {
        if amount == 0 {
            return Err(StateError::ZeroAmount);
        }
        if self.holder_of(leaf)? != *sender {
            return Err(StateError::NotHolder);
        }
        let asset = self.mandates.get(leaf).ok_or(StateError::UnknownMandate)?.asset;
        let root = self.mandates.root_of(leaf)?;
        let funder = *self.root_funding.get(&root).ok_or(StateError::UnknownMandate)?;
        // Ordering: mandate AUTHORIZATION verdict first (read-only check), then the
        // settlement-layer balance check, then the mutating spend + fund movement.
        self.mandates.check(leaf, amount, self.time)?;
        let have = self.balance(&funder, &asset);
        if have < amount {
            return Err(StateError::InsufficientBalance { have, need: amount });
        }
        self.mandates.spend(leaf, amount, self.time)?;
        self.debit(&funder, &asset, amount).expect("balance checked above");
        self.credit(to, &asset, amount);
        Ok(vec![Event::MandateSpent { leaf: *leaf, to: *to, amount }])
    }

    fn do_mandate_revoke(&mut self, sender: &AccountId, target: &MandateId) -> Result<Vec<Event>, StateError> {
        let node = self.mandates.get(target).ok_or(StateError::UnknownMandate)?;
        let authorizer = match node.parent {
            Some(p) => self.holder_of(&p)?, // parent holder kills a child
            None => self.holder_of(target)?, // root holder kills the whole tree
        };
        if authorizer != *sender {
            return Err(StateError::NotHolder);
        }
        self.mandates.revoke(target)?;
        Ok(vec![Event::MandateRevoked { id: *target }])
    }

    // ---- channels ----

    pub fn derive_channel_id(payer: &AccountId, payee: &AccountId, tip: &H256, nonce: u64) -> ChannelId {
        H256(shake256_32(DOM_CHANNEL_ID, &[&payer.0, &payee.0, &tip.0, &nonce.to_le_bytes()]))
    }

    #[allow(clippy::too_many_arguments)]
    fn do_channel_open(
        &mut self, sender: &AccountId, id: ChannelId, mandate: MandateId, payee: AccountId,
        asset: AssetId, tip: H256, unit_price: Amount, max_steps: u32, expiry: Timestamp,
    ) -> Result<Vec<Event>, StateError> {
        if self.channels.contains_key(&id) {
            return Err(StateError::DuplicateChannel);
        }
        if unit_price == 0 || max_steps == 0 {
            return Err(StateError::ZeroAmount);
        }
        if self.holder_of(&mandate)? != *sender {
            return Err(StateError::NotHolder);
        }
        let nonce = self.accounts.get(sender).ok_or(StateError::UnknownAccount)?.nonce;
        if Self::derive_channel_id(sender, &payee, &tip, nonce) != id {
            return Err(StateError::ChannelIdMismatch);
        }
        let deposit = unit_price.checked_mul(max_steps as Amount).ok_or(StateError::Overflow)?;
        let m_asset = self.mandates.get(&mandate).ok_or(StateError::UnknownMandate)?.asset;
        if m_asset != asset {
            return Err(StateError::UnknownMandate);
        }
        let root = self.mandates.root_of(&mandate)?;
        let funder = *self.root_funding.get(&root).ok_or(StateError::UnknownMandate)?;
        // Same ordering as MandateSpend: authorization before settlement.
        self.mandates.check(&mandate, deposit, self.time)?;
        let have = self.balance(&funder, &asset);
        if have < deposit {
            return Err(StateError::InsufficientBalance { have, need: deposit });
        }
        // The mandate ancestor walk happens HERE, once, at funding (plan §6).
        self.mandates.spend(&mandate, deposit, self.time)?;
        self.debit(&funder, &asset, deposit).expect("balance checked above");
        self.channels.insert(id, Channel {
            state: ChannelState {
                id,
                payer: *sender,
                payee,
                asset,
                mandate,
                tip,
                unit_price,
                max_steps: max_steps as u64,
                highest_step_settled: 0,
                expiry,
            },
            escrow_remaining: deposit,
            refunded: false,
        });
        Ok(vec![Event::ChannelOpened { id, escrow: deposit }])
    }

    fn do_channel_settle(&mut self, id: &ChannelId, word: &H256, step: u32) -> Result<Vec<Event>, StateError> {
        let ch = self.channels.get_mut(id).ok_or(StateError::UnknownChannel)?;
        if ch.refunded {
            return Err(StateError::ChannelRefunded);
        }
        let prev = ch.state.highest_step_settled;
        if step as u64 <= prev || step as u64 > ch.state.max_steps {
            return Err(StateError::BadStep);
        }
        if !payword::verify_settlement(ch.state.tip.0, word.0, step) {
            return Err(StateError::BadSettlement);
        }
        let newly = step as u64 - prev;
        let paid = ch.state.unit_price.checked_mul(newly as Amount).ok_or(StateError::Overflow)?;
        // Escrow always covers: deposit = unit_price × max_steps and step ≤ max_steps.
        ch.state.highest_step_settled = step as u64;
        ch.escrow_remaining -= paid;
        let (payee, asset) = (ch.state.payee, ch.state.asset);
        self.credit(&payee, &asset, paid);
        Ok(vec![Event::ChannelSettled { id: *id, upto_step: step, paid }])
    }

    fn do_channel_refund(&mut self, sender: &AccountId, id: &ChannelId) -> Result<Vec<Event>, StateError> {
        let ch = self.channels.get_mut(id).ok_or(StateError::UnknownChannel)?;
        if ch.refunded {
            return Err(StateError::ChannelRefunded);
        }
        if ch.state.payer != *sender {
            return Err(StateError::NotHolder);
        }
        if self.time < ch.state.expiry {
            return Err(StateError::NotExpired);
        }
        let amount = ch.escrow_remaining;
        ch.escrow_remaining = 0;
        ch.refunded = true;
        let (payer, asset) = (ch.state.payer, ch.state.asset);
        self.credit(&payer, &asset, amount);
        Ok(vec![Event::ChannelRefunded { id: *id, amount }])
    }

    // ---- shielded pool (P2.0 — docs/P2-BUILD-PLAN.md WS1) ----

    /// SHIELD: debit `value` transparently, admit `commitment` to the tree. The mint proof
    /// guarantees the commitment opens to exactly `value` (inflation guard) — owner, rho,
    /// rcm never touch the chain.
    fn do_mint_to_pool(
        &mut self, sender: &AccountId, asset: &AssetId, value: Amount, commitment: &H256, proof: &[u8],
    ) -> Result<Vec<Event>, StateError> {
        if value == 0 {
            return Err(StateError::ZeroAmount);
        }
        if value > u64::MAX as Amount {
            return Err(StateError::PoolValueRange); // note values are u64 in-circuit
        }
        // v1: single-asset pool; the first mint pins the asset.
        if let Some(a) = self.pool.asset {
            if a != *asset {
                return Err(StateError::PoolAssetMismatch);
            }
        }
        if self.pool.tree.is_full() {
            return Err(StateError::PoolFull);
        }
        let expected = expected_mint_public(commitment, value);
        // P2.3: a PROOF-LESS tx rides on the block's verified aggregate (coverage);
        // otherwise the per-proof path verifies as always (the legal fallback).
        let ok = if proof.is_empty() {
            let pb = bincode::serialize(&expected).unwrap_or_default();
            self.agg_cover.contains(&pool::cover_key(KIND_MINT, &pb))
        } else {
            self.verifier.verify_mint(proof, &expected)
        };
        if !ok {
            return Err(StateError::PoolProofInvalid);
        }
        self.debit(sender, asset, value)?; // last fallible step — a failed tx mutates nothing
        self.pool.asset.get_or_insert(*asset);
        self.pool.tree.append(commitment.0).expect("capacity checked above");
        self.pool.total_shielded = self.pool.total_shielded.saturating_add(value);
        Ok(vec![Event::PoolMinted { commitment: *commitment, value }])
    }

    /// SHIELDED SPEND: the envelope's sender is just the RELAYER — authority comes from
    /// the proof (membership under `anchor`, fresh `nullifier`, value conservation) and
    /// the in-proof tx_binding pins the transparent effects (credit, fee) against
    /// malleability. Verified against the public inputs THE CHAIN derives, never the tx's
    /// claim of them.
    #[allow(clippy::too_many_arguments)]
    fn do_shielded_spend(
        &mut self, sender: &AccountId, anchor: &H256, nullifier: &H256, out_commitment: &H256,
        out2_commitment: &H256, fee: Amount, credit: &Option<AccountId>,
        mandate: &Option<MandateId>, proof: &[u8],
    ) -> Result<Vec<Event>, StateError> {
        if fee > u64::MAX as Amount {
            return Err(StateError::PoolValueRange);
        }
        if fee > 0 && credit.is_none() {
            return Err(StateError::PoolFeeNeedsCredit);
        }
        // P2.4 public skeleton: a mandate-bound spend is an UNSHIELD whose public amount
        // (the fee) clears the whole MandateTree ancestor chain. Authorization is the
        // ENVELOPE (the relayer must be the leaf holder) — the proof still carries the
        // note authority; the mandate adds the org's consensus-enforced cap on top.
        if let Some(m) = mandate {
            if fee == 0 {
                return Err(StateError::ZeroAmount); // the mandate must govern something
            }
            if self.holder_of(m)? != *sender {
                return Err(StateError::NotHolder);
            }
            self.mandates.check(m, fee, self.time)?; // read-only; the iconic receipt
        }
        // A fee pays out in the pool's pinned asset (no asset → nothing was ever minted).
        let asset = match (fee > 0, self.pool.asset) {
            (true, None) => return Err(StateError::PoolAssetMismatch),
            (_, a) => a,
        };
        if !self.pool.is_recent_anchor(&anchor.0) {
            return Err(StateError::PoolUnknownAnchor);
        }
        if self.pool.nullifiers.contains(&nullifier.0) {
            return Err(StateError::PoolDoubleSpend);
        }
        if !self.pool.tree.has_capacity(2) {
            return Err(StateError::PoolFull);
        }
        let expected =
            expected_spend_public(anchor, nullifier, out_commitment, out2_commitment, fee, credit);
        // P2.3: proof-less ⇒ must be covered by the block's verified aggregate;
        // otherwise per-proof verification (the legal fallback).
        let ok = if proof.is_empty() {
            let pb = bincode::serialize(&expected).unwrap_or_default();
            self.agg_cover.contains(&pool::cover_key(KIND_SPEND, &pb))
        } else {
            self.verifier.verify_spend(proof, &expected)
        };
        if !ok {
            return Err(StateError::PoolProofInvalid);
        }
        // Effects. The mandate spend runs FIRST (its checks passed above — same-args
        // re-run cannot newly fail within one tx), so a rejection never half-mutates.
        if let Some(m) = mandate {
            self.mandates.spend(m, fee, self.time)?;
        }
        // Infallible from here. BOTH outputs enter the tree, in order.
        self.pool.nullifiers.insert(nullifier.0);
        self.pool.tree.append(out_commitment.0).expect("capacity checked above");
        self.pool.tree.append(out2_commitment.0).expect("capacity checked above");
        if fee > 0 {
            let to = credit.expect("checked above");
            self.credit(&to, &asset.expect("checked above"), fee);
            self.pool.total_shielded = self.pool.total_shielded.saturating_sub(fee);
        }
        Ok(vec![Event::PoolSpent {
            nullifier: *nullifier,
            out_commitment: *out_commitment,
            out2_commitment: *out2_commitment,
            fee,
            credit: *credit,
        }])
    }

    // ---- persistence (P3.0 / WS-B) ----

    /// Export everything persistent. Excluded BY DESIGN: `verifier` (injected by the
    /// node at startup — a snapshot must never smuggle in a proof policy) and
    /// `agg_cover` (transient, cleared every block, excluded from the commitment).
    pub fn to_snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            height: self.height,
            time: self.time,
            accounts: self.accounts.clone(),
            balances: self.balances.clone(),
            mandates: self.mandates.clone(),
            root_funding: self.root_funding.clone(),
            channels: self.channels.clone(),
            pool: self.pool.clone(),
            fees_burned: self.fees_burned,
        }
    }

    /// Rebuild a `State` from a snapshot. The verifier is the REJECT-ALL default —
    /// the node injects the real one exactly as it does after `from_genesis`. Callers
    /// MUST check `state_commitment()` against the recorded app_hash and refuse to
    /// run on mismatch (same refuse-on-mismatch posture as the vk pins).
    pub fn from_snapshot(s: StateSnapshot) -> Self {
        State {
            height: s.height,
            time: s.time,
            accounts: s.accounts,
            balances: s.balances,
            mandates: s.mandates,
            root_funding: s.root_funding,
            channels: s.channels,
            pool: s.pool,
            verifier: Arc::new(RejectAllVerifier),
            agg_cover: std::collections::BTreeSet::new(),
            fee_micro: 0,
            fee_from: u64::MAX,
            fees_burned: s.fees_burned,
        }
    }

    // ---- commitment ----

    /// v0 state commitment: SHAKE-256 over a deterministic serialization of all state.
    /// TODO(P1): merkleized commitments (per-module roots) for light clients.
    pub fn state_commitment(&self) -> H256 {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.time.to_le_bytes());
        for (id, acc) in &self.accounts {
            buf.extend_from_slice(&id.0);
            buf.extend_from_slice(&acc.auth_commit.0);
            buf.extend_from_slice(&acc.nonce.to_le_bytes());
        }
        for ((id, asset), amt) in &self.balances {
            buf.extend_from_slice(&id.0);
            buf.extend_from_slice(&asset.0);
            buf.extend_from_slice(&amt.to_le_bytes());
        }
        for (id, node) in self.mandates.iter() {
            buf.extend_from_slice(&id.0);
            // MandateNode contains no maps — JSON encoding cannot fail and is
            // deterministic (fixed struct field order).
            buf.extend_from_slice(&serde_json::to_vec(node).expect("MandateNode is JSON-safe"));
        }
        for (id, ch) in &self.channels {
            buf.extend_from_slice(&id.0);
            buf.extend_from_slice(&serde_json::to_vec(ch).expect("Channel is JSON-safe"));
        }
        for (root, funder) in &self.root_funding {
            buf.extend_from_slice(&root.0);
            buf.extend_from_slice(&funder.0);
        }
        // Shielded pool: version + asset + tree (index, root) + anchors + nullifiers +
        // conservation ledger. All BTree/VecDeque iteration — deterministic.
        buf.push(self.pool.version);
        match self.pool.asset {
            Some(a) => {
                buf.push(1);
                buf.extend_from_slice(&a.0);
            }
            None => buf.push(0),
        }
        buf.extend_from_slice(&self.pool.tree.next_index().to_le_bytes());
        buf.extend_from_slice(&self.pool.tree.root());
        buf.extend_from_slice(&(self.pool.anchors().count() as u64).to_le_bytes());
        for a in self.pool.anchors() {
            buf.extend_from_slice(a);
        }
        buf.extend_from_slice(&(self.pool.nullifiers.len() as u64).to_le_bytes());
        for nf in &self.pool.nullifiers {
            buf.extend_from_slice(nf);
        }
        buf.extend_from_slice(&self.pool.total_shielded.to_le_bytes());
        // U4: fees enter the commitment ONLY once nonzero. A zero counter keeps the
        // buffer byte-identical to the pre-fee layout, so upgraded and pre-upgrade
        // nodes agree on every block until the activation height actually burns a
        // fee — a rolling fleet upgrade cannot fork before activation.
        if self.fees_burned > 0 {
            buf.push(0xFE); // fee-section tag (cannot collide: the buffer is length-structured)
            buf.extend_from_slice(&self.fees_burned.to_le_bytes());
        }
        H256(shake256_32(DOM_STATE_COMMIT, &[&buf]))
    }
}
