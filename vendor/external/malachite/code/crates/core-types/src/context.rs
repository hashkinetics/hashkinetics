use crate::{
    Address, Extension, Height, NilOrVal, Proposal, ProposalPart, Round, Signature, SigningScheme,
    Validator, ValidatorSet, Value, ValueId, Vote,
};

/// This trait allows to abstract over the various datatypes
/// that are used in the consensus engine.
pub trait Context
where
    Self: Sized + Clone + Send + Sync + 'static,
{
    /// The type of address of a validator.
    type Address: Address;

    /// The type of the height of a block.
    type Height: Height;

    /// The type of proposal part
    type ProposalPart: ProposalPart<Self>;

    /// The interface provided by the proposal type.
    type Proposal: Proposal<Self>;

    /// The interface provided by the validator type.
    type Validator: Validator<Self>;

    /// The interface provided by the validator set type.
    type ValidatorSet: ValidatorSet<Self>;

    /// The `Value` type denotes the value `v` carried by the `Proposal`
    /// consensus message that is gossiped to other nodes by the proposer.
    type Value: Value;

    /// The type of votes that can be cast.
    type Vote: Vote<Self>;

    /// The type of vote extensions.
    type Extension: Extension;

    /// The signing scheme used to sign consensus messages.
    type SigningScheme: SigningScheme;

    /// Select a proposer in the validator set for the given height and round.
    fn select_proposer<'a>(
        &self,
        validator_set: &'a Self::ValidatorSet,
        height: Self::Height,
        round: Round,
    ) -> &'a Self::Validator;

    /// HK-R6: the validator set AS OF the given height, if the integration tracks
    /// set history (validator-key rotations change the set over a chain's life).
    /// A commit certificate for height H must be verified against the set that
    /// actually signed it — not the current set — or a node syncing/replaying
    /// across a rotation boundary rejects perfectly valid history.
    ///
    /// The default returns `None`, which means "use the caller's current set"
    /// (the pre-R6 behavior) — contexts without rotation need not implement this.
    fn validator_set_at(&self, _height: Self::Height) -> Option<Self::ValidatorSet> {
        None
    }

    /// HK-R5.4: a placeholder signature for INTERNAL proposals that are never
    /// verified by anyone. Synced values (and parts-only mode) fabricate a local
    /// `SignedProposal` purely to satisfy the driver's types — upstream signs it
    /// with this node's real key ("keep all happy", see the TODO in
    /// `on_proposed_value`), which for a STATEFUL hash-based scheme burns one
    /// irreplaceable one-time leaf per synced block: a syncing non-validator
    /// eventually exhausts its tree and wedges (observed in production).
    ///
    /// Returning `Some(sig)` short-circuits that signing; the signature is a
    /// dummy carried only inside this node. The default `None` keeps the
    /// upstream behavior for contexts whose signatures are cheap.
    fn placeholder_signature(&self) -> Option<Signature<Self>> {
        None
    }

    /// HK-R8: abstain-while-behind. When `Some(gap)`, an active validator STOPS
    /// signing votes and proposals while corroborated peer evidence shows the
    /// network at least `gap` heights ahead of it — votes at a height the
    /// network has already passed are worthless by construction, yet for a
    /// STATEFUL hash-based scheme each one burns an irreplaceable one-time
    /// leaf (observed in production: a freshly-rotated 32,768-leaf tree burned
    /// to ZERO in ~20 h of futile nil-votes below tip). Abstaining is
    /// protocol-safe: it is indistinguishable from the node being offline,
    /// which BFT already tolerates.
    ///
    /// "Corroborated" = the SECOND-highest height claimed by DISTINCT members
    /// of the current validator set (via buffered future-height votes and
    /// proposals) — one faulty or malicious validator cannot fabricate the
    /// signal alone, and a lone ahead-of-quorum node cannot stall the others.
    ///
    /// The default `None` disables the feature (upstream behavior unchanged).
    fn abstain_threshold(&self) -> Option<u64> {
        None
    }

    /// Build a new proposal for the given value at the given height, round and POL round.
    fn new_proposal(
        &self,
        height: Self::Height,
        round: Round,
        value: Self::Value,
        pol_round: Round,
        address: Self::Address,
    ) -> Self::Proposal;

    /// Build a new prevote vote by the validator with the given address,
    /// for the value identified by the given value id, at the given round.
    fn new_prevote(
        &self,
        height: Self::Height,
        round: Round,
        value_id: NilOrVal<ValueId<Self>>,
        address: Self::Address,
    ) -> Self::Vote;

    /// Build a new precommit vote by the validator with the given address,
    /// for the value identified by the given value id, at the given round.
    fn new_precommit(
        &self,
        height: Self::Height,
        round: Round,
        value_id: NilOrVal<ValueId<Self>>,
        address: Self::Address,
    ) -> Self::Vote;
}
