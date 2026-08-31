#![no_std]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

extern crate alloc;

use alloc::boxed::Box;

use async_trait::async_trait;
use malachitebft_core_types::{Context, PublicKey, Signature, SignedMessage};

mod error;
pub use error::Error;

mod ext;
pub use ext::SigningProviderExt;

/// The result of a signature verification operation.
pub enum VerificationResult {
    /// The signature is valid.
    Valid,

    /// The signature is invalid.
    Invalid,
}

impl VerificationResult {
    /// Create a new `VerificationResult` from a boolean indicating validity.
    pub fn from_bool(valid: bool) -> Self {
        if valid {
            VerificationResult::Valid
        } else {
            VerificationResult::Invalid
        }
    }

    /// Convert the result to a boolean indicating validity.
    pub fn is_valid(&self) -> bool {
        matches!(self, VerificationResult::Valid)
    }

    /// Convert the result to a boolean indicating invalidity.
    pub fn is_invalid(&self) -> bool {
        matches!(self, VerificationResult::Invalid)
    }
}

/// A provider of signing functionality for the consensus engine.
///
/// This trait defines the core signing operations needed by the engine,
/// including signing and verifying votes, proposals, proposal parts, and commit signatures.
/// It is parameterized by a context type `Ctx` that defines the specific types used
/// for votes, proposals, and other consensus-related data structures.
///
/// Implementers of this trait are responsible for managing the private keys used for signing
/// and providing verification logic using the corresponding public keys.
#[async_trait]
pub trait SigningProvider<Ctx>
where
    Ctx: Context,
    Self: Send + Sync + 'static,
{
    /// Sign the given vote with our private key.
    async fn sign_vote(&self, vote: Ctx::Vote) -> Result<SignedMessage<Ctx, Ctx::Vote>, Error>;

    /// Verify the given vote's signature using the given public key.
    async fn verify_signed_vote(
        &self,
        vote: &Ctx::Vote,
        signature: &Signature<Ctx>,
        public_key: &PublicKey<Ctx>,
    ) -> Result<VerificationResult, Error>;

    /// Sign the given proposal with our private key.
    async fn sign_proposal(
        &self,
        proposal: Ctx::Proposal,
    ) -> Result<SignedMessage<Ctx, Ctx::Proposal>, Error>;

    /// Verify the given proposal's signature using the given public key.
    async fn verify_signed_proposal(
        &self,
        proposal: &Ctx::Proposal,
        signature: &Signature<Ctx>,
        public_key: &PublicKey<Ctx>,
    ) -> Result<VerificationResult, Error>;

    /// Sign the proposal part with our private key.
    async fn sign_proposal_part(
        &self,
        proposal_part: Ctx::ProposalPart,
    ) -> Result<SignedMessage<Ctx, Ctx::ProposalPart>, Error>;

    /// Verify the given proposal part signature using the given public key.
    async fn verify_signed_proposal_part(
        &self,
        proposal_part: &Ctx::ProposalPart,
        signature: &Signature<Ctx>,
        public_key: &PublicKey<Ctx>,
    ) -> Result<VerificationResult, Error>;

    /// Sign the given vote extension with our private key.
    async fn sign_vote_extension(
        &self,
        extension: Ctx::Extension,
    ) -> Result<SignedMessage<Ctx, Ctx::Extension>, Error>;

    /// Verify the given vote extension's signature using the given public key.
    async fn verify_signed_vote_extension(
        &self,
        extension: &Ctx::Extension,
        signature: &Signature<Ctx>,
        public_key: &PublicKey<Ctx>,
    ) -> Result<VerificationResult, Error>;

    /// HK-R5.2: batch-verify many (vote, signature, public key) triples at once — e.g.
    /// every commit signature in a certificate — so a provider can parallelize the
    /// CPU-bound work (hash-based signature verification is pure and order-free).
    /// Returning `None` (the default) means "no fast path": callers fall back to the
    /// historical per-signature calls. A `Some(results)` MUST be the same length and
    /// order as `votes`, `true` = valid.
    async fn verify_signed_votes_batch(
        &self,
        votes: &[(Ctx::Vote, Signature<Ctx>, PublicKey<Ctx>)],
    ) -> Option<alloc::vec::Vec<bool>> {
        let _ = votes;
        None
    }
}

#[async_trait]
impl<Ctx> SigningProvider<Ctx> for Box<dyn SigningProvider<Ctx> + '_>
where
    Ctx: Context,
{
    async fn sign_vote(&self, vote: Ctx::Vote) -> Result<SignedMessage<Ctx, Ctx::Vote>, Error> {
        (**self).sign_vote(vote).await
    }

    async fn verify_signed_vote(
        &self,
        vote: &Ctx::Vote,
        signature: &Signature<Ctx>,
        public_key: &PublicKey<Ctx>,
    ) -> Result<VerificationResult, Error> {
        self.as_ref()
            .verify_signed_vote(vote, signature, public_key)
            .await
    }

    async fn sign_proposal(
        &self,
        proposal: Ctx::Proposal,
    ) -> Result<SignedMessage<Ctx, Ctx::Proposal>, Error> {
        self.as_ref().sign_proposal(proposal).await
    }

    async fn verify_signed_proposal(
        &self,
        proposal: &Ctx::Proposal,
        signature: &Signature<Ctx>,
        public_key: &PublicKey<Ctx>,
    ) -> Result<VerificationResult, Error> {
        self.as_ref()
            .verify_signed_proposal(proposal, signature, public_key)
            .await
    }

    async fn sign_proposal_part(
        &self,
        proposal_part: Ctx::ProposalPart,
    ) -> Result<SignedMessage<Ctx, Ctx::ProposalPart>, Error> {
        self.as_ref().sign_proposal_part(proposal_part).await
    }

    async fn verify_signed_proposal_part(
        &self,
        proposal_part: &Ctx::ProposalPart,
        signature: &Signature<Ctx>,
        public_key: &PublicKey<Ctx>,
    ) -> Result<VerificationResult, Error> {
        self.as_ref()
            .verify_signed_proposal_part(proposal_part, signature, public_key)
            .await
    }

    async fn sign_vote_extension(
        &self,
        extension: Ctx::Extension,
    ) -> Result<SignedMessage<Ctx, Ctx::Extension>, Error> {
        self.as_ref().sign_vote_extension(extension).await
    }

    async fn verify_signed_vote_extension(
        &self,
        extension: &Ctx::Extension,
        signature: &Signature<Ctx>,
        public_key: &PublicKey<Ctx>,
    ) -> Result<VerificationResult, Error> {
        self.as_ref()
            .verify_signed_vote_extension(extension, signature, public_key)
            .await
    }

    /// HK-R5.2: delegate the batch fast path through the Box, otherwise a boxed
    /// provider silently loses its override and every certificate goes serial again.
    async fn verify_signed_votes_batch(
        &self,
        votes: &[(Ctx::Vote, Signature<Ctx>, PublicKey<Ctx>)],
    ) -> Option<alloc::vec::Vec<bool>> {
        (**self).verify_signed_votes_batch(votes).await
    }
}
