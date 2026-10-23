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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::HkHeight;
    use crate::hashsig_scheme::address_of;
    use hk_crypto::hashsig::CONSENSUS_SIG_LEN;
    use malachitebft_core_types::{NilOrVal, Round};

    /// hbs-lms works on large stack arrays: the node runs verification on 32 MiB stacks
    /// (tokio workers, the rayon pool), and so do these tests.
    fn on_big_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new().stack_size(32 * 1024 * 1024).spawn(f).unwrap().join().unwrap();
    }

    fn malformed(good: &HkSig) -> Vec<HkSig> {
        let mut bogus_level = good.clone();
        bogus_level.0[..4].copy_from_slice(&8u32.to_be_bytes());
        let mut bogus_type = good.clone();
        bogus_type.0[8..12].copy_from_slice(&99u32.to_be_bytes());
        vec![
            HkSig(vec![]),
            HkSig(vec![0xAB; 10]),
            HkSig(good.0[..good.0.len() - 1].to_vec()),
            HkSig(vec![0u8; CONSENSUS_SIG_LEN]),
            bogus_level,
            bogus_type,
        ]
    }

    /// RZ-1 (external report 2026-10-14): the exact entry point the engine calls for a vote off
    /// the wire — `SigningProvider::verify_signed_vote` — answers `Invalid` for a malformed
    /// signature (empty, truncated, one byte short, a zero blob, a bogus level, a bogus type
    /// code) and never panics; the batch path (the rayon verification pool, which the commit
    /// certificates of catch-up go through) reports `false` for the malformed entries and `true`
    /// for the good ones, in order, and nothing panics on a pool thread either.
    #[test]
    fn rz1_malformed_vote_is_invalid_not_a_panic_through_the_provider() {
        on_big_stack(|| {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async {
                let sk = HkPriv::from_seed([23u8; 32]);
                let pk = sk.public();
                let addr = address_of(&pk);
                let provider = HkSigningProvider::new(sk);
                let vote = HkVote::new_prevote(HkHeight::new(7), Round::new(0), NilOrVal::Nil, addr);
                let signed = provider.sign_vote(vote.clone()).await.expect("sign");
                assert_eq!(signed.signature.0.len(), CONSENSUS_SIG_LEN);
                let good = provider
                    .verify_signed_vote(&vote, &signed.signature, &pk)
                    .await
                    .expect("verify");
                assert!(good.is_valid());

                for bad in malformed(&signed.signature) {
                    let r = provider.verify_signed_vote(&vote, &bad, &pk).await.expect("verify");
                    assert!(!r.is_valid(), "a {}-byte malformed signature must be Invalid", bad.0.len());
                }

                // The batch path: good, malformed ×6, good — order preserved, no panic.
                let mut votes = vec![(vote.clone(), signed.signature.clone(), pk.clone())];
                for bad in malformed(&signed.signature) {
                    votes.push((vote.clone(), bad, pk.clone()));
                }
                votes.push((vote.clone(), signed.signature.clone(), pk.clone()));
                let verdicts = provider.verify_signed_votes_batch(&votes).await.expect("batch");
                assert_eq!(verdicts, vec![true, false, false, false, false, false, false, true]);

                // Proposal, part and extension verification share the same verifier: each
                // verifies its own real signature and refuses every malformed one.
                let proposal = HkProposal::new(
                    HkHeight::new(7),
                    Round::new(0),
                    crate::HkValue::new(Bytes::from_static(b"txs")),
                    Round::Nil,
                    addr,
                );
                let signed_proposal = provider.sign_proposal(proposal.clone()).await.expect("sign proposal");
                assert!(provider
                    .verify_signed_proposal(&proposal, &signed_proposal.signature, &pk)
                    .await
                    .unwrap()
                    .is_valid());
                for bad in malformed(&signed_proposal.signature) {
                    assert!(!provider.verify_signed_proposal(&proposal, &bad, &pk).await.unwrap().is_valid());
                }
                let part = HkProposalPart::TxBatch(Bytes::from_static(b"a chunk"));
                let signed_part = provider.sign_proposal_part(part.clone()).await.expect("sign part");
                assert!(provider
                    .verify_signed_proposal_part(&part, &signed_part.signature, &pk)
                    .await
                    .unwrap()
                    .is_valid());
                for bad in malformed(&signed_part.signature) {
                    assert!(!provider.verify_signed_proposal_part(&part, &bad, &pk).await.unwrap().is_valid());
                }
                let ext = Bytes::from_static(b"ext");
                let signed_ext = provider.sign_vote_extension(ext.clone()).await.expect("sign ext");
                assert!(provider
                    .verify_signed_vote_extension(&ext, &signed_ext.signature, &pk)
                    .await
                    .unwrap()
                    .is_valid());
                for bad in malformed(&signed_ext.signature) {
                    assert!(!provider.verify_signed_vote_extension(&ext, &bad, &pk).await.unwrap().is_valid());
                }
            });
        });
    }

    /// RZ-1, the reporter's "actor crash test" inverted: a task that verifies votes off a
    /// channel through the real provider used to die on the first malformed vote (the panic
    /// unwound out of `verify`); now it stays alive, answers `Invalid`, and still verifies the
    /// next good vote. (The Malachite consensus actor is not spawned here; what killed it was
    /// the unwinding panic, which the tests above pin as gone at every layer.)
    #[test]
    fn rz1_a_verifying_task_survives_a_malformed_vote() {
        // Keygen and signing need the big stack too (the test thread's default is small).
        on_big_stack(|| {
            let (tx, rx) = std::sync::mpsc::channel::<Option<(HkVote, HkSig, HkPub)>>();
            let (out_tx, out_rx) = std::sync::mpsc::channel::<bool>();
            let worker = std::thread::Builder::new()
                .stack_size(32 * 1024 * 1024)
                .spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
                    let provider = HkSigningProvider::new(HkPriv::from_seed([24u8; 32]));
                    while let Ok(Some((vote, sig, pk))) = rx.recv() {
                        let verdict = rt
                            .block_on(provider.verify_signed_vote(&vote, &sig, &pk))
                            .expect("verify");
                        out_tx.send(verdict.is_valid()).unwrap();
                    }
                })
                .unwrap();

            let (vote, good, pk) = {
                let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
                let sk = HkPriv::from_seed([24u8; 32]);
                let pk = sk.public();
                let addr = address_of(&pk);
                let provider = HkSigningProvider::new(sk);
                let vote = HkVote::new_precommit(HkHeight::new(9), Round::new(1), NilOrVal::Nil, addr);
                let signed = rt.block_on(provider.sign_vote(vote.clone())).expect("sign");
                (vote, signed.signature, pk)
            };
            tx.send(Some((vote.clone(), good.clone(), pk.clone()))).unwrap();
            assert!(out_rx.recv().unwrap(), "the good vote verifies");
            for bad in malformed(&good) {
                tx.send(Some((vote.clone(), bad, pk.clone()))).unwrap();
                assert!(!out_rx.recv().unwrap(), "the malformed vote is Invalid, and the task answered");
            }
            tx.send(Some((vote.clone(), good.clone(), pk.clone()))).unwrap();
            assert!(out_rx.recv().unwrap(), "the task is alive and verifies the next good vote");
            tx.send(None).unwrap();
            worker.join().expect("the verifying task ended without a panic");
        });
    }
}
