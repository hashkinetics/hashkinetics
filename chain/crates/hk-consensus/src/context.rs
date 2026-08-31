//! The HashKinetics consensus Context: every datatype Malachite abstracts over.
//! Mirrors crates/test/src/{address,height,value,vote,proposal,proposal_part,
//! validator_set,context}.rs from the vendored engine — same trait surfaces, our
//! encodings (SHAKE-256 + hk/v1 domain tags, no protobuf).

use core::fmt;
use std::sync::Arc;

use bytes::Bytes;

use hk_crypto::hash::shake256_32;
use malachitebft_core_types::{
    Context, NilOrVal, Round, SignedExtension, VoteType, VotingPower,
};
use crate::hashsig_scheme::{HkHashScheme, HkPub};

// Frozen v1 domain tags for consensus objects.
pub const DOM_VALIDATOR_ADDR: &str = "hk/v1/validator-address";
pub const DOM_BLOCK_VALUE: &str = "hk/v1/block-value";
pub const DOM_SIGN_VOTE: &str = "hk/v1/consensus-vote";
pub const DOM_SIGN_PROPOSAL: &str = "hk/v1/consensus-proposal";
pub const DOM_SIGN_PART: &str = "hk/v1/consensus-proposal-part";

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

/// Validator address: first 20 bytes of SHAKE-256(domain ‖ ed25519 pubkey).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct HkAddress([u8; Self::LENGTH]);

impl HkAddress {
    pub const LENGTH: usize = 20;

    pub const fn new(value: [u8; Self::LENGTH]) -> Self {
        Self(value)
    }

    pub fn from_public_key(public_key: &HkPub) -> Self {
        let hash = shake256_32(DOM_VALIDATOR_ADDR, &[&public_key.0]);
        let mut address = [0; Self::LENGTH];
        address.copy_from_slice(&hash[..Self::LENGTH]);
        Self(address)
    }

    pub fn into_inner(self) -> [u8; Self::LENGTH] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

impl fmt::Display for HkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for HkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HkAddress({self})")
    }
}

impl malachitebft_core_types::Address for HkAddress {}

// ---------------------------------------------------------------------------
// Height
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct HkHeight(u64);

impl HkHeight {
    pub const fn new(height: u64) -> Self {
        Self(height)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn increment(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl Default for HkHeight {
    fn default() -> Self {
        malachitebft_core_types::Height::ZERO
    }
}

impl fmt::Display for HkHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for HkHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HkHeight({})", self.0)
    }
}

impl malachitebft_core_types::Height for HkHeight {
    const ZERO: Self = Self(0);
    const INITIAL: Self = Self(1);

    fn increment_by(&self, n: u64) -> Self {
        Self(self.0 + n)
    }

    fn decrement_by(&self, n: u64) -> Option<Self> {
        Some(Self(self.0.saturating_sub(n)))
    }

    fn as_u64(&self) -> u64 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Value (the block payload consensus decides on)
// ---------------------------------------------------------------------------

/// 32-byte value id = SHAKE-256(domain ‖ tx bytes).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct HkValueId([u8; 32]);

impl HkValueId {
    pub const fn new(id: [u8; 32]) -> Self {
        Self(id)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for HkValueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.iter().take(8) {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The proposed block payload: opaque tx batch bytes (hk-state SignedTxs, encoded
/// by the app layer) + their digest. Consensus only ever needs the digest.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct HkValue {
    pub id: HkValueId,
    pub txs: Bytes,
}

impl HkValue {
    pub fn new(txs: Bytes) -> Self {
        let id = HkValueId(shake256_32(DOM_BLOCK_VALUE, &[&txs]));
        Self { id, txs }
    }

    pub fn id(&self) -> HkValueId {
        self.id
    }

    pub fn size_bytes(&self) -> usize {
        self.txs.len()
    }
}

impl malachitebft_core_types::Value for HkValue {
    type Id = HkValueId;

    fn id(&self) -> HkValueId {
        self.id
    }
}

// ---------------------------------------------------------------------------
// Vote
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HkVote {
    pub typ: VoteType,
    pub height: HkHeight,
    pub round: Round,
    pub value: NilOrVal<HkValueId>,
    pub validator_address: HkAddress,
    pub extension: Option<SignedExtension<HkContext>>,
}

impl HkVote {
    pub fn new_prevote(
        height: HkHeight,
        round: Round,
        value: NilOrVal<HkValueId>,
        validator_address: HkAddress,
    ) -> Self {
        Self { typ: VoteType::Prevote, height, round, value, validator_address, extension: None }
    }

    pub fn new_precommit(
        height: HkHeight,
        round: Round,
        value: NilOrVal<HkValueId>,
        validator_address: HkAddress,
    ) -> Self {
        Self { typ: VoteType::Precommit, height, round, value, validator_address, extension: None }
    }

    /// Deterministic sign-bytes. Extensions are excluded (they carry their own
    /// signature), mirroring the engine's reference behavior.
    pub fn to_sign_bytes(&self) -> Bytes {
        let mut buf = Vec::with_capacity(80);
        buf.extend_from_slice(DOM_SIGN_VOTE.as_bytes());
        buf.push(0x00);
        buf.push(match self.typ {
            VoteType::Prevote => 0,
            VoteType::Precommit => 1,
        });
        buf.extend_from_slice(&self.height.as_u64().to_le_bytes());
        buf.extend_from_slice(&self.round.as_i64().to_le_bytes());
        match &self.value {
            NilOrVal::Nil => buf.push(0),
            NilOrVal::Val(id) => {
                buf.push(1);
                buf.extend_from_slice(id.as_bytes());
            }
        }
        buf.extend_from_slice(self.validator_address.as_bytes());
        Bytes::from(buf)
    }
}

impl malachitebft_core_types::Vote<HkContext> for HkVote {
    fn height(&self) -> HkHeight {
        self.height
    }

    fn round(&self) -> Round {
        self.round
    }

    fn value(&self) -> &NilOrVal<HkValueId> {
        &self.value
    }

    fn take_value(self) -> NilOrVal<HkValueId> {
        self.value
    }

    fn vote_type(&self) -> VoteType {
        self.typ
    }

    fn validator_address(&self) -> &HkAddress {
        &self.validator_address
    }

    fn extension(&self) -> Option<&SignedExtension<HkContext>> {
        self.extension.as_ref()
    }

    fn take_extension(&mut self) -> Option<SignedExtension<HkContext>> {
        self.extension.take()
    }

    fn extend(self, extension: SignedExtension<HkContext>) -> Self {
        Self { extension: Some(extension), ..self }
    }
}

// ---------------------------------------------------------------------------
// Proposal
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HkProposal {
    pub height: HkHeight,
    pub round: Round,
    pub value: HkValue,
    pub pol_round: Round,
    pub validator_address: HkAddress,
}

impl HkProposal {
    pub fn new(
        height: HkHeight,
        round: Round,
        value: HkValue,
        pol_round: Round,
        validator_address: HkAddress,
    ) -> Self {
        Self { height, round, value, pol_round, validator_address }
    }

    pub fn to_sign_bytes(&self) -> Bytes {
        let mut buf = Vec::with_capacity(96 + self.value.txs.len());
        buf.extend_from_slice(DOM_SIGN_PROPOSAL.as_bytes());
        buf.push(0x00);
        buf.extend_from_slice(&self.height.as_u64().to_le_bytes());
        buf.extend_from_slice(&self.round.as_i64().to_le_bytes());
        buf.extend_from_slice(&self.pol_round.as_i64().to_le_bytes());
        buf.extend_from_slice(self.value.id.as_bytes());
        buf.extend_from_slice(&(self.value.txs.len() as u64).to_le_bytes());
        buf.extend_from_slice(&self.value.txs);
        buf.extend_from_slice(self.validator_address.as_bytes());
        Bytes::from(buf)
    }
}

impl malachitebft_core_types::Proposal<HkContext> for HkProposal {
    fn height(&self) -> HkHeight {
        self.height
    }

    fn round(&self) -> Round {
        self.round
    }

    fn value(&self) -> &HkValue {
        &self.value
    }

    fn take_value(self) -> HkValue {
        self.value
    }

    fn pol_round(&self) -> Round {
        self.pol_round
    }

    fn validator_address(&self) -> &HkAddress {
        &self.validator_address
    }
}

// ---------------------------------------------------------------------------
// Proposal parts (streamed proposals)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HkProposalInit {
    pub height: HkHeight,
    pub round: Round,
    pub pol_round: Round,
    pub proposer: HkAddress,
}

/// Closes a streamed proposal. It carries the value id for a cheap reassembly
/// consistency check — NOT a consensus signature. Proposal authenticity comes from
/// the engine's `SignedProposal` over this same id (the value id is a hash of the
/// content), so a second signature here would be redundant AND would force a second
/// advancing signer over the one-time-leaf tree (leaf reuse). See
/// docs/MAINNET-KEY-MANAGEMENT.md — "one key, one signer".
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HkProposalFin {
    pub value_id: HkValueId,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HkProposalPart {
    Init(HkProposalInit),
    /// A chunk of the tx batch.
    TxBatch(Bytes),
    Fin(HkProposalFin),
}

impl HkProposalPart {
    pub fn get_type(&self) -> &'static str {
        match self {
            Self::Init(_) => "init",
            Self::TxBatch(_) => "tx-batch",
            Self::Fin(_) => "fin",
        }
    }

    pub fn as_init(&self) -> Option<&HkProposalInit> {
        match self {
            Self::Init(init) => Some(init),
            _ => None,
        }
    }

    pub fn as_tx_batch(&self) -> Option<&Bytes> {
        match self {
            Self::TxBatch(data) => Some(data),
            _ => None,
        }
    }

    pub fn as_fin(&self) -> Option<&HkProposalFin> {
        match self {
            Self::Fin(fin) => Some(fin),
            _ => None,
        }
    }

    pub fn to_sign_bytes(&self) -> Bytes {
        let mut buf = Vec::new();
        buf.extend_from_slice(DOM_SIGN_PART.as_bytes());
        buf.push(0x00);
        match self {
            Self::Init(init) => {
                buf.push(0);
                buf.extend_from_slice(&init.height.as_u64().to_le_bytes());
                buf.extend_from_slice(&init.round.as_i64().to_le_bytes());
                buf.extend_from_slice(&init.pol_round.as_i64().to_le_bytes());
                buf.extend_from_slice(init.proposer.as_bytes());
            }
            Self::TxBatch(data) => {
                buf.push(1);
                buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
                buf.extend_from_slice(data);
            }
            Self::Fin(fin) => {
                buf.push(2);
                buf.extend_from_slice(fin.value_id.as_bytes());
            }
        }
        Bytes::from(buf)
    }
}

impl malachitebft_core_types::ProposalPart<HkContext> for HkProposalPart {
    fn is_first(&self) -> bool {
        matches!(self, Self::Init(_))
    }

    fn is_last(&self) -> bool {
        matches!(self, Self::Fin(_))
    }
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HkValidator {
    pub address: HkAddress,
    /// Permanent SLH-DSA-192s root identity (48 bytes) — the anchor that certifies this
    /// validator's operational-key rotations. Fixed for life. The address is derived from
    /// the genesis operational key and is likewise stable across rotations.
    pub root_pk: Vec<u8>,
    /// Current operational (consensus) public key — swapped when a RotationCert is applied.
    pub public_key: HkPub,
    /// Last accepted rotation epoch (0 = the genesis operational key, no cert yet).
    pub epoch: u64,
    pub voting_power: VotingPower,
}

impl HkValidator {
    /// Build a validator from its permanent root identity + its genesis operational key.
    /// The address is derived from the operational key once and never recomputed.
    pub fn new(root_pk: Vec<u8>, public_key: HkPub, voting_power: VotingPower) -> Self {
        Self {
            address: HkAddress::from_public_key(&public_key),
            root_pk,
            public_key,
            epoch: 0,
            voting_power,
        }
    }
}

impl PartialOrd for HkValidator {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HkValidator {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
    }
}

impl malachitebft_core_types::Validator<HkContext> for HkValidator {
    fn address(&self) -> &HkAddress {
        &self.address
    }

    fn public_key(&self) -> &HkPub {
        &self.public_key
    }

    fn voting_power(&self) -> VotingPower {
        self.voting_power
    }
}

/// Validator set, deterministically ordered CometBFT-style:
/// voting power descending, then address ascending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HkValidatorSet {
    pub validators: Arc<Vec<HkValidator>>,
}

impl HkValidatorSet {
    /// # Panics
    /// If the validator set is empty.
    pub fn new(validators: impl IntoIterator<Item = HkValidator>) -> Self {
        let mut validators: Vec<_> = validators.into_iter().collect();
        assert!(!validators.is_empty());
        validators.sort_by(|a, b| {
            b.voting_power.cmp(&a.voting_power).then_with(|| a.address.cmp(&b.address))
        });
        Self { validators: Arc::new(validators) }
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, HkValidator> {
        self.validators.iter()
    }

    pub fn total_voting_power(&self) -> VotingPower {
        self.validators.iter().map(|v| v.voting_power).sum()
    }

    pub fn get_by_address(&self, address: &HkAddress) -> Option<&HkValidator> {
        self.validators.iter().find(|v| &v.address == address)
    }

    pub fn get_by_index(&self, index: usize) -> Option<&HkValidator> {
        self.validators.get(index)
    }

    /// Return a new set with `address`'s operational (consensus) public key replaced by
    /// `new_op_pk`, preserving the validator's address and voting power. The address is the
    /// stable identity and is NOT recomputed, so a rotation never changes who's who or the
    /// set ordering. This is the validator-set side of SCMS rotation: when a root-signed
    /// `RotationCert` is accepted (see `crate::rotation`), the engine is handed the rotated
    /// set for subsequent heights and verifies that validator's votes against the new key.
    pub fn rotate_operational_key(&self, address: &HkAddress, new_op_pk: HkPub) -> HkValidatorSet {
        let validators = self
            .validators
            .iter()
            .map(|v| {
                if &v.address == address {
                    HkValidator {
                        address: v.address,
                        root_pk: v.root_pk.clone(),
                        public_key: new_op_pk.clone(),
                        epoch: v.epoch,
                        voting_power: v.voting_power,
                    }
                } else {
                    v.clone()
                }
            })
            .collect::<Vec<_>>();
        HkValidatorSet { validators: Arc::new(validators) }
    }

    /// Apply a root-signed `RotationCert`: find the validator whose registered root matches,
    /// verify the certificate (signature + identity + strictly newer epoch), and return a new
    /// set with that validator's operational key + epoch advanced. `Err` if no validator owns
    /// the cert's root or the cert is invalid/stale — the caller (commit) then ignores it.
    pub fn apply_rotation(
        &self,
        cert: &crate::rotation::RotationCert,
    ) -> Result<HkValidatorSet, String> {
        let target = self
            .validators
            .iter()
            .find(|v| v.root_pk == cert.root_pk)
            .ok_or_else(|| "rotation cert: no validator with that root identity".to_string())?;
        if !cert.verify_against(&target.root_pk, Some(target.epoch)) {
            return Err(format!(
                "rotation cert: invalid or stale (cert epoch {}, current {})",
                cert.epoch, target.epoch
            ));
        }
        let addr = target.address;
        let validators = self
            .validators
            .iter()
            .map(|v| {
                if v.address == addr {
                    HkValidator {
                        address: v.address,
                        root_pk: v.root_pk.clone(),
                        public_key: cert.new_op_pk.clone(),
                        epoch: cert.epoch,
                        voting_power: v.voting_power,
                    }
                } else {
                    v.clone()
                }
            })
            .collect::<Vec<_>>();
        Ok(HkValidatorSet { validators: Arc::new(validators) })
    }
}

impl malachitebft_core_types::ValidatorSet<HkContext> for HkValidatorSet {
    fn count(&self) -> usize {
        self.validators.len()
    }

    fn total_voting_power(&self) -> VotingPower {
        self.total_voting_power()
    }

    fn get_by_address(&self, address: &HkAddress) -> Option<&HkValidator> {
        self.get_by_address(address)
    }

    fn get_by_index(&self, index: usize) -> Option<&HkValidator> {
        self.validators.get(index)
    }
}

// ---------------------------------------------------------------------------
// The Context
// ---------------------------------------------------------------------------

/// HK-R6: shared validator-set history — entries of `(effective_from_height, set)`,
/// ascending. The set that verifies a commit certificate for height `h` is the last
/// entry with `effective_from <= h`. Rotations are rare (a handful per epoch-cycle),
/// so this stays tiny; the node seeds it at genesis/restore and appends on every
/// committed rotation (live AND replay).
pub type SetHistory = std::sync::Arc<std::sync::Mutex<Vec<(u64, HkValidatorSet)>>>;

#[derive(Clone, Debug, Default)]
pub struct HkContext {
    /// `None` (e.g. plain `HkContext::new()` in tests) disables per-height lookup —
    /// the engine then falls back to the current set, the pre-R6 behavior.
    set_history: Option<SetHistory>,
}

impl HkContext {
    /// HK-R6: a context that answers `validator_set_at` from the shared history.
    pub fn with_history(history: SetHistory) -> Self {
        Self { set_history: Some(history) }
    }

    pub fn new() -> Self {
        Self::default()
    }
}

impl Context for HkContext {
    type Address = HkAddress;
    type Height = HkHeight;
    type ProposalPart = HkProposalPart;
    type Proposal = HkProposal;
    type Validator = HkValidator;
    type ValidatorSet = HkValidatorSet;
    type Value = HkValue;
    type Vote = HkVote;
    type Extension = Bytes;
    type SigningScheme = HkHashScheme;

    /// HK-R6: answer per-height validator-set lookups from the shared history so
    /// the engine verifies commit certificates against the set that SIGNED them.
    /// `None` when no history is attached or the height predates the first entry
    /// (a node never needs sets older than its own restore point).
    fn validator_set_at(&self, height: HkHeight) -> Option<HkValidatorSet> {
        let hist = self.set_history.as_ref()?;
        let hist = hist.lock().unwrap_or_else(|e| e.into_inner());
        let h = height.as_u64();
        hist.iter()
            .rev()
            .find(|(from, _)| *from <= h)
            .map(|(_, set)| set.clone())
    }

    /// Deterministic round-robin over (height, round) — same rule as the engine's
    /// reference context. Weighted/leader-lease selection is a later refinement.
    fn select_proposer<'a>(
        &self,
        validator_set: &'a Self::ValidatorSet,
        height: Self::Height,
        round: Round,
    ) -> &'a Self::Validator {
        assert!(!validator_set.is_empty());
        assert!(round != Round::Nil && round.as_i64() >= 0);

        let proposer_index = {
            let height = height.as_u64() as usize;
            let round = round.as_i64() as usize;
            (height.saturating_sub(1) + round) % validator_set.len()
        };

        validator_set.get_by_index(proposer_index).expect("proposer_index is valid")
    }

    fn new_proposal(
        &self,
        height: HkHeight,
        round: Round,
        value: HkValue,
        pol_round: Round,
        address: HkAddress,
    ) -> HkProposal {
        HkProposal::new(height, round, value, pol_round, address)
    }

    fn new_prevote(
        &self,
        height: HkHeight,
        round: Round,
        value_id: NilOrVal<HkValueId>,
        address: HkAddress,
    ) -> HkVote {
        HkVote::new_prevote(height, round, value_id, address)
    }

    fn new_precommit(
        &self,
        height: HkHeight,
        round: Round,
        value_id: NilOrVal<HkValueId>,
        address: HkAddress,
    ) -> HkVote {
        HkVote::new_precommit(height, round, value_id, address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // HK-R6: per-height validator-set lookup
    // -----------------------------------------------------------------------

    fn set_with_power(power: u64) -> HkValidatorSet {
        HkValidatorSet::new(vec![HkValidator::new(
            vec![power as u8; 48],
            HkPub(vec![power as u8; 64]),
            power,
        )])
    }

    #[test]
    fn validator_set_at_answers_from_history() {
        let history: SetHistory = Default::default();
        {
            let mut h = history.lock().unwrap();
            h.push((1, set_with_power(1))); // genesis set, heights 1..=99
            h.push((100, set_with_power(2))); // rotation committed at 99 → effective 100+
            h.push((250, set_with_power(3))); // rotation committed at 249 → effective 250+
        }
        let ctx = HkContext::with_history(history);

        let at = |h: u64| {
            ctx.validator_set_at(HkHeight::new(h))
                .expect("set expected")
                .total_voting_power()
        };
        assert_eq!(at(1), 1);
        assert_eq!(at(99), 1);
        assert_eq!(at(100), 2);
        assert_eq!(at(249), 2);
        assert_eq!(at(250), 3);
        assert_eq!(at(1_000_000), 3);
    }

    #[test]
    fn validator_set_at_none_cases() {
        // No history attached (plain new): always None — engine falls back to
        // the current set, i.e. exactly the pre-R6 behavior.
        assert!(HkContext::new().validator_set_at(HkHeight::new(42)).is_none());

        // History attached but the height predates the first entry (a restored
        // node is never asked about heights below its own snapshot).
        let history: SetHistory = Default::default();
        history.lock().unwrap().push((100, set_with_power(2)));
        let ctx = HkContext::with_history(history);
        assert!(ctx.validator_set_at(HkHeight::new(50)).is_none());
        assert!(ctx.validator_set_at(HkHeight::new(100)).is_some());
    }

    #[test]
    fn value_id_is_digest_of_txs() {
        let a = HkValue::new(Bytes::from_static(b"batch-a"));
        let b = HkValue::new(Bytes::from_static(b"batch-b"));
        assert_ne!(a.id(), b.id());
        assert_eq!(a.id(), HkValue::new(Bytes::from_static(b"batch-a")).id());
    }

    #[test]
    fn vote_sign_bytes_bind_all_fields() {
        let addr = HkAddress::new([7; 20]);
        let id = HkValueId::new([1; 32]);
        let v1 = HkVote::new_prevote(HkHeight::new(5), Round::new(0), NilOrVal::Val(id), addr);
        let v2 = HkVote::new_precommit(HkHeight::new(5), Round::new(0), NilOrVal::Val(id), addr);
        let v3 = HkVote::new_prevote(HkHeight::new(6), Round::new(0), NilOrVal::Val(id), addr);
        let v4 = HkVote::new_prevote(HkHeight::new(5), Round::new(0), NilOrVal::Nil, addr);
        assert_ne!(v1.to_sign_bytes(), v2.to_sign_bytes());
        assert_ne!(v1.to_sign_bytes(), v3.to_sign_bytes());
        assert_ne!(v1.to_sign_bytes(), v4.to_sign_bytes());
    }

    #[test]
    fn validator_set_orders_by_power_then_address() {
        // Distinct pubkey bytes suffice for ordering — no (slow) LMS keygen needed.
        let v1 = HkValidator::new(vec![10u8; 48], HkPub(vec![1u8; 60]), 1);
        let v2 = HkValidator::new(vec![20u8; 48], HkPub(vec![2u8; 60]), 9);
        let set = HkValidatorSet::new(vec![v1, v2.clone()]);
        assert_eq!(set.get_by_index(0), Some(&v2)); // highest power first
        assert_eq!(set.total_voting_power(), 10);
    }

    #[test]
    fn rotate_swaps_operational_key_and_keeps_address() {
        let v1 = HkValidator::new(vec![10u8; 48], HkPub(vec![1u8; 60]), 1);
        let v2 = HkValidator::new(vec![20u8; 48], HkPub(vec![2u8; 60]), 1);
        let addr1 = v1.address;
        let set = HkValidatorSet::new(vec![v1, v2.clone()]);

        let new_op = HkPub(vec![9u8; 60]);
        let rotated = set.rotate_operational_key(&addr1, new_op.clone());

        // v1's operational key is swapped; its address (identity) is unchanged.
        let got = rotated.get_by_address(&addr1).unwrap();
        assert_eq!(got.public_key, new_op);
        assert_eq!(got.address, addr1);
        // v2 is untouched, and total power / membership are preserved.
        assert_eq!(rotated.get_by_address(&v2.address).unwrap().public_key, v2.public_key);
        assert_eq!(rotated.total_voting_power(), 2);
    }
}
