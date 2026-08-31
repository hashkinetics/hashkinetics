//! HkSigningProvider — HASH-BASED consensus signing (P1 gate 1, Stage 2).
//! Signs votes/proposals with LMS/HSS over SHAKE-256 (`hk-crypto::hashsig` via
//! `HkPriv`). This is the scheme the honesty-ledger promised: consensus votes are now
//! quantum-secure, not stock Ed25519. Network/transport identity stays Ed25519 in
//! libp2p (derived from the same seed) — that is peer auth, not ledger security.

use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;

use malachitebft_core_types::{
    SignedExtension, SignedMessage, SignedProposal, SignedProposalPart, SignedVote,
};
use malachitebft_signing::{Error, SigningProvider, VerificationResult};

use crate::context::{HkContext, HkProposal, HkProposalPart, HkVote};
use crate::hashsig_scheme::{self, HkPriv, HkPub, HkSig};

/// Rate limiter for the exhaustion error log (a stuck round retries signing forever;
/// one screaming line per attempt would drown the journal).
static EXHAUSTED_ATTEMPTS: AtomicU64 = AtomicU64::new(0);

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
    /// (reserve-then-sign) when this provider was built via `get_signing_provider`.
    ///
    /// R2 (staging incident #1): exhaustion is NOT fatal. A validator that spends its
    /// full tree (CONSENSUS_CAPACITY one-time leaves) returns `Err` here; the engine
    /// logs and drops that one signature, and the node stays ALIVE — RPC serving,
    /// value-sync running — as a mute observer. Recovery is a root-signed RotationCert
    /// (issued offline via `hk-node issue-rotation`, carried by any peer via
    /// `hk_submitRotation`); when it commits, `rotate_to` swaps this shared handle to
    /// the fresh tree and signing resumes in place. See docs/MAINNET-KEY-MANAGEMENT.md.
    pub fn sign(&self, data: &[u8]) -> Result<HkSig, Error> {
        match self.private_key.sign(data) {
            Some(sig) => Ok(sig),
            None => {
                let n = EXHAUSTED_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
                if n == 0 || n % 100 == 0 {
                    tracing::error!(
                        attempts = n + 1,
                        "consensus signing key EXHAUSTED — node stays alive as observer; \
                         revive: `hk-node issue-rotation <HOME>` offline, submit the cert \
                         to any peer via hk_submitRotation, then this node rotates live"
                    );
                }
                Err(Error::new())
            }
        }
    }
}

#[async_trait]
impl SigningProvider<HkContext> for HkSigningProvider {
    async fn sign_vote(&self, vote: HkVote) -> Result<SignedVote<HkContext>, Error> {
        let signature = self.sign(&vote.to_sign_bytes())?;
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
        let signature = self.sign(&proposal.to_sign_bytes())?;
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
        let signature = self.sign(&proposal_part.to_sign_bytes())?;
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
        let signature = self.sign(extension.as_ref())?;
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

    /// HK-R5.2: the batch fast path — every commit signature in a certificate is a
    /// pure, order-free LMS/HSS verify, so run them all in parallel on the dedicated
    /// 32 MiB-stack pool. This is what turns catch-up's per-block certificate cost
    /// from N sequential verifies into max(one verify).
    async fn verify_signed_votes_batch(
        &self,
        votes: &[(HkVote, HkSig, HkPub)],
    ) -> Option<Vec<bool>> {
        if votes.len() < 2 {
            return None; // pool handoff costs more than one verify — go serial
        }
        Some(crate::par::par_bools(votes, |(vote, sig, pk)| {
            hashsig_scheme::verify(&vote.to_sign_bytes(), sig, pk)
        }))
    }
}
