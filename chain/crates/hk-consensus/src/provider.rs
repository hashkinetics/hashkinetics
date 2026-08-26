//! HkSigningProvider — HASH-BASED consensus signing (P1 gate 1, Stage 2).
//! Signs votes/proposals with LMS/HSS over SHAKE-256 (`hk-crypto::hashsig` via
//! `HkPriv`). This is the scheme the honesty-ledger promised: consensus votes are now
//! quantum-secure, not stock Ed25519. Network/transport identity stays Ed25519 in
//! libp2p (derived from the same seed) — that is peer auth, not ledger security.

use async_trait::async_trait;
use bytes::Bytes;

use malachitebft_core_types::{
    SignedExtension, SignedMessage, SignedProposal, SignedProposalPart, SignedVote,
};
use malachitebft_signing::{Error, SigningProvider, VerificationResult};

use crate::context::{HkContext, HkProposal, HkProposalPart, HkVote};
use crate::hashsig_scheme::{self, HkPriv, HkPub, HkSig};

#[derive(Debug)]
pub struct HkSigningProvider {
    private_key: HkPriv,
}

impl HkSigningProvider {
    pub fn new(private_key: HkPriv) -> Self {
        Self { private_key }
    }

    pub fn private_key(&self) -> &HkPriv {
        &self.private_key
    }

    /// Sign, advancing the stateful key. State is persisted before release
    /// (reserve-then-sign) when this provider was built via `get_signing_provider`. A
    /// validator that exhausts its ~32K-signature (2^15) tree rotates to a fresh tree
    /// certified by its stateless SLH-DSA root — see docs/MAINNET-KEY-MANAGEMENT.md.
    pub fn sign(&self, data: &[u8]) -> HkSig {
        self.private_key
            .sign(data)
            .expect("consensus signing key exhausted — rotate the tree via the SLH-DSA root")
    }
}

#[async_trait]
impl SigningProvider<HkContext> for HkSigningProvider {
    async fn sign_vote(&self, vote: HkVote) -> Result<SignedVote<HkContext>, Error> {
        let signature = self.sign(&vote.to_sign_bytes());
        Ok(SignedVote::new(vote, signature))
    }

    async fn verify_signed_vote(
        &self,
        vote: &HkVote,
        signature: &HkSig,
        public_key: &HkPub,
    ) -> Result<VerificationResult, Error> {
        Ok(VerificationResult::from_bool(hashsig_scheme::verify(
            &vote.to_sign_bytes(),
            signature,
            public_key,
        )))
    }

    async fn sign_proposal(&self, proposal: HkProposal) -> Result<SignedProposal<HkContext>, Error> {
        let signature = self.sign(&proposal.to_sign_bytes());
        Ok(SignedProposal::new(proposal, signature))
    }

    async fn verify_signed_proposal(
        &self,
        proposal: &HkProposal,
        signature: &HkSig,
        public_key: &HkPub,
    ) -> Result<VerificationResult, Error> {
        Ok(VerificationResult::from_bool(hashsig_scheme::verify(
            &proposal.to_sign_bytes(),
            signature,
            public_key,
        )))
    }

    async fn sign_proposal_part(
        &self,
        proposal_part: HkProposalPart,
    ) -> Result<SignedProposalPart<HkContext>, Error> {
        let signature = self.sign(&proposal_part.to_sign_bytes());
        Ok(SignedProposalPart::new(proposal_part, signature))
    }

    async fn verify_signed_proposal_part(
        &self,
        proposal_part: &HkProposalPart,
        signature: &HkSig,
        public_key: &HkPub,
    ) -> Result<VerificationResult, Error> {
        Ok(VerificationResult::from_bool(hashsig_scheme::verify(
            &proposal_part.to_sign_bytes(),
            signature,
            public_key,
        )))
    }

    async fn sign_vote_extension(&self, extension: Bytes) -> Result<SignedExtension<HkContext>, Error> {
        let signature = self.sign(extension.as_ref());
        Ok(SignedMessage::new(extension, signature))
    }

    async fn verify_signed_vote_extension(
        &self,
        extension: &Bytes,
        signature: &HkSig,
        public_key: &HkPub,
    ) -> Result<VerificationResult, Error> {
        Ok(VerificationResult::from_bool(hashsig_scheme::verify(
            extension.as_ref(),
            signature,
            public_key,
        )))
    }
}
