//! HkSigningProvider — HASH-BASED consensus signing (P1 gate 1, Stage 2).
//! Signs votes/proposals with LMS/HSS over SHAKE-256 (`hk-crypto::hashsig` via
//! `HkPriv`). This is the scheme the honesty-ledger promised: consensus votes are now
//! quantum-secure, not stock Ed25519. Network/transport identity stays Ed25519 in
//! libp2p (derived from the same seed) — that is peer auth, not ledger security.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;

use malachitebft_core_types::{
    SignedExtension, SignedMessage, SignedProposal, SignedProposalPart, SignedVote,
};
use malachitebft_signing::{Error, SigningProvider, VerificationResult};

use crate::context::{HkAddress, HkContext, HkProposal, HkProposalPart, HkValueId, HkVote};
use crate::hashsig_scheme::{self, HkPriv, HkPub, HkSig};

/// Rate limiter for the exhaustion error log (a stuck round retries signing forever;
/// one screaming line per attempt would drown the journal).
static EXHAUSTED_ATTEMPTS: AtomicU64 = AtomicU64::new(0);

/// v0.19.13: how many signatures of one height the provider keeps for reuse. A round takes
/// at most three (a proposal, a prevote, a precommit), so this covers the newest eighty-odd
/// rounds of a height; past the bound the oldest entry makes room.
const SIGNED_AT_HEIGHT_MAX: usize = 256;

/// v0.19.13: what a kept signature was made over.
#[derive(Clone, PartialEq, Eq, Hash)]
enum SignedItem {
    /// A vote, by its exact sign-bytes.
    Vote(Vec<u8>),
    /// A proposal, by every field its sign-bytes are built from, with the value's bytes named
    /// by their id and length. `sign_proposal` checks that the id is the hash of the bytes
    /// before it looks an item up, so two proposals that agree on these fields have the same
    /// sign-bytes. (The sign-bytes themselves carry the whole value and are not kept.)
    Proposal { round: i64, pol_round: i64, value_id: HkValueId, value_len: u64, proposer: HkAddress },
}

/// v0.19.13: the signatures this provider made at the newest height it has signed for, by what
/// they were made over. A request to sign the same item at that height again is answered with
/// the kept signature, so no further one-time leaf is spent on it. A request for a later height
/// empties the store; a request for an earlier one is signed without it. At most
/// `SIGNED_AT_HEIGHT_MAX` entries.
///
/// The store belongs to the operational key that made its signatures. What this provider can
/// read of the live key is its position (`HkPriv::used`: the signatures the live tree has
/// made). The provider notes that position after every signature it makes, and a live tree
/// that stands anywhere else when the next request comes (a rotation put another tree in the
/// handle, or something else signed with this one) empties the store before anything is
/// answered from it (`follow_key`).
struct SignedAtHeight {
    height: u64,
    /// The live key's position right after the last signature this provider made, or as it was
    /// found when the store last started to follow it; `None` before the first request.
    key_position: Option<u64>,
    sigs: HashMap<SignedItem, HkSig>,
    /// The kept items, oldest first.
    order: VecDeque<SignedItem>,
}

impl SignedAtHeight {
    fn new() -> Self {
        Self { height: 0, key_position: None, sigs: HashMap::new(), order: VecDeque::new() }
    }

    /// The live key stands at `live_position`. When that is not where this provider left it,
    /// the kept signatures may be another key's: the store is emptied and follows the live key
    /// from this position.
    fn follow_key(&mut self, live_position: u64) {
        if self.key_position != Some(live_position) {
            self.sigs.clear();
            self.order.clear();
            self.key_position = Some(live_position);
        }
    }

    /// The signature kept for `item` at `height`. A later height than the store's empties the
    /// store and becomes its height; an earlier one is answered `None`.
    fn kept(&mut self, height: u64, item: &SignedItem) -> Option<HkSig> {
        if height > self.height {
            self.height = height;
            self.sigs.clear();
            self.order.clear();
        }
        if height < self.height {
            return None;
        }
        self.sigs.get(item).cloned()
    }

    /// Keep `sig` as the signature made over `item` at `height`, when that is the store's
    /// height and the item is not kept yet. At the bound the oldest entry is dropped first.
    fn keep(&mut self, height: u64, item: SignedItem, sig: HkSig) {
        if height != self.height || self.sigs.contains_key(&item) {
            return;
        }
        if self.order.len() >= SIGNED_AT_HEIGHT_MAX {
            if let Some(oldest) = self.order.pop_front() {
                self.sigs.remove(&oldest);
            }
        }
        self.order.push_back(item.clone());
        self.sigs.insert(item, sig);
    }
}

impl std::fmt::Debug for SignedAtHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedAtHeight")
            .field("height", &self.height)
            .field("kept", &self.sigs.len())
            .finish()
    }
}

#[derive(Debug)]
pub struct HkSigningProvider {
    private_key: HkPriv,
    /// v0.19.13: the signatures of the newest height signed for, kept for reuse
    /// (`SignedAtHeight`). Behind a lock: the provider is shared.
    signed: Mutex<SignedAtHeight>,
}

impl HkSigningProvider {
    pub fn new(private_key: HkPriv) -> Self {
        Self { private_key, signed: Mutex::new(SignedAtHeight::new()) }
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
        // v0.19.13: every signature is made under the lock of the store of kept signatures
        // (`sign_with_live_key`), so the store knows where this provider left the live key.
        let mut signed = self.signed.lock().unwrap_or_else(|e| e.into_inner());
        self.sign_with_live_key(&mut signed, data)
    }

    /// v0.19.13: the one place this provider signs, with the store's lock held by the caller.
    /// The store follows the live key first (`SignedAtHeight::follow_key`) and notes the key's
    /// position after the signature. The outcome is `sign`'s (above): a signature, or `Err`
    /// for a tree that is used up.
    fn sign_with_live_key(&self, signed: &mut SignedAtHeight, data: &[u8]) -> Result<HkSig, Error> {
        signed.follow_key(self.private_key.used());
        match self.private_key.sign(data) {
            Some(sig) => {
                signed.key_position = Some(self.private_key.used());
                Ok(sig)
            }
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

    /// v0.19.13: sign `item` for `height` once. When this provider has already signed the same
    /// item at this height with the key it holds now, the signature it made then is returned
    /// and no one-time leaf is spent; otherwise the sign-bytes are built and signed
    /// (`sign_with_live_key`) and the signature is kept (`SignedAtHeight`). The store follows
    /// the live key before it answers: a live key that does not stand where this provider left
    /// it empties the store first, so what is answered was made by the tree the handle holds.
    /// The store's lock is held across the signing, so two identical requests give one
    /// signature. A request that cannot be signed keeps nothing.
    fn sign_once(
        &self,
        height: u64,
        item: SignedItem,
        sign_bytes: impl FnOnce() -> Bytes,
    ) -> Result<HkSig, Error> {
        let mut signed = self.signed.lock().unwrap_or_else(|e| e.into_inner());
        signed.follow_key(self.private_key.used());
        if let Some(sig) = signed.kept(height, &item) {
            return Ok(sig);
        }
        let sig = self.sign_with_live_key(&mut signed, &sign_bytes())?;
        signed.keep(height, item, sig.clone());
        Ok(sig)
    }
}

/// v0.19.12: is the id a proposal carries the hash of the bytes it carries?
fn value_id_is_hash_of_bytes(proposal: &HkProposal) -> bool {
    crate::context::HkValue::new(proposal.value.txs.clone()).id() == proposal.value.id()
}

#[async_trait]
impl SigningProvider<HkContext> for HkSigningProvider {
    async fn sign_vote(&self, vote: HkVote) -> Result<SignedVote<HkContext>, Error> {
        // v0.19.13: a vote already signed at this height is answered with the signature made
        // then (`sign_once`): the same sign-bytes, the same signature, one leaf.
        let bytes = vote.to_sign_bytes();
        let item = SignedItem::Vote(bytes.to_vec());
        let signature = self.sign_once(vote.height.as_u64(), item, move || bytes)?;
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
        // v0.19.12: never sign a proposal whose value id is not the hash of the bytes
        // it carries (see `verify_signed_proposal`). No path of this node builds one; if one
        // ever reached here, not proposing is the safe outcome and no leaf is spent on it.
        if !value_id_is_hash_of_bytes(&proposal) {
            tracing::error!(
                height = %proposal.height,
                round = %proposal.round,
                "refusing to sign a proposal whose value id is not the hash of its bytes"
            );
            return Err(Error::new());
        }
        // v0.19.13: a proposal already signed at this height is answered with the signature
        // made then (`sign_once`). The id was checked against the bytes just above, so the
        // fields of the item name these exact sign-bytes, which are built only when they are
        // signed.
        let item = SignedItem::Proposal {
            round: proposal.round.as_i64(),
            pol_round: proposal.pol_round.as_i64(),
            value_id: proposal.value.id(),
            value_len: proposal.value.txs.len() as u64,
            proposer: proposal.validator_address,
        };
        let signature = self.sign_once(proposal.height.as_u64(), item, || proposal.to_sign_bytes())?;
        Ok(SignedProposal::new(proposal, signature))
    }

    async fn verify_signed_proposal(
        &self,
        proposal: &HkProposal,
        signature: &HkSig,
        public_key: &HkPub,
    ) -> Result<VerificationResult, Error> {
        // v0.19.12: a proposal whose value id is not the hash of the bytes it carries is not a
        // valid proposal. The bytes inside the proposal ARE the value, so the binding is checked
        // here, where every proposal is verified (from the network, from the future-height
        // buffer, from the WAL). A proposal is answered as valid only when both hold: the id
        // is the hash of the bytes, and the signature over the sign-bytes verifies under
        // `public_key`. `sign_proposal` above refuses to sign a proposal whose id fails the
        // same check. An honest proposer builds its value with `HkValue::new`, which makes
        // the id that hash.
        if !value_id_is_hash_of_bytes(proposal) {
            tracing::warn!(
                height = %proposal.height,
                round = %proposal.round,
                proposer = %proposal.validator_address,
                "proposal refused: its value id is not the hash of its bytes"
            );
            return Ok(VerificationResult::from_bool(false));
        }
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

    /// v0.19.12: a proposal whose value id is not the hash of the bytes it carries is refused
    /// at verification even when the proposer's own key signed exactly those sign-bytes, and
    /// this node refuses to sign one. The honest proposal over the same id verifies.
    /// Kill: remove the id check from `verify_signed_proposal` and the mismatched proposal
    /// verifies.
    #[test]
    fn a_proposal_whose_id_is_not_the_hash_of_its_bytes_is_invalid_and_is_not_signed() {
        on_big_stack(|| {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async {
                let sk = HkPriv::from_seed([25u8; 32]);
                let pk = sk.public();
                let addr = address_of(&pk);
                let provider = HkSigningProvider::new(sk);

                let honest = HkProposal::new(
                    HkHeight::new(7),
                    Round::new(0),
                    crate::HkValue::new(Bytes::from_static(b"the bytes")),
                    Round::Nil,
                    addr,
                );
                let mut mismatched_value = crate::HkValue::new(Bytes::from_static(b"other bytes"));
                mismatched_value.id = honest.value.id();
                let mismatched =
                    HkProposal::new(HkHeight::new(7), Round::new(0), mismatched_value, Round::Nil, addr);

                // Signed with the proposer's own key over these sign-bytes.
                let sig = provider.sign(&mismatched.to_sign_bytes()).expect("sign");
                assert!(
                    hashsig_scheme::verify(&mismatched.to_sign_bytes(), &sig, &pk),
                    "the raw signature verifies"
                );
                assert!(
                    !provider.verify_signed_proposal(&mismatched, &sig, &pk).await.unwrap().is_valid(),
                    "the proposal does not"
                );
                assert!(
                    provider.sign_proposal(mismatched.clone()).await.is_err(),
                    "and this node does not sign one"
                );

                let signed = provider.sign_proposal(honest.clone()).await.expect("sign the honest one");
                assert!(provider
                    .verify_signed_proposal(&honest, &signed.signature, &pk)
                    .await
                    .unwrap()
                    .is_valid());
            });
        });
    }

    /// v0.19.13: a vote or a proposal this provider has signed at a height is signed once. The
    /// same request again is answered with the same signature, which verifies, and no further
    /// one-time leaf is spent; a different vote, and the same value proposed in another round,
    /// are signed on a leaf of their own. Caught mutant: sign every request anew and the second request
    /// spends a second leaf.
    #[test]
    fn a_request_signed_before_at_this_height_gets_the_same_signature_and_spends_no_leaf() {
        on_big_stack(|| {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async {
                let sk = HkPriv::from_seed([26u8; 32]);
                let pk = sk.public();
                let addr = address_of(&pk);
                let provider = HkSigningProvider::new(sk);
                let start = provider.private_key().remaining();

                let prevote = HkVote::new_prevote(HkHeight::new(7), Round::new(0), NilOrVal::Nil, addr);
                let first = provider.sign_vote(prevote.clone()).await.expect("sign");
                assert_eq!(provider.private_key().remaining(), start - 1);
                let again = provider.sign_vote(prevote.clone()).await.expect("sign again");
                assert_eq!(again.signature, first.signature, "the same signature");
                assert_eq!(provider.private_key().remaining(), start - 1, "and no further leaf");
                assert!(provider
                    .verify_signed_vote(&prevote, &again.signature, &pk)
                    .await
                    .unwrap()
                    .is_valid());

                // Another vote of the same height and round has a leaf of its own.
                let precommit = HkVote::new_precommit(HkHeight::new(7), Round::new(0), NilOrVal::Nil, addr);
                let other = provider.sign_vote(precommit.clone()).await.expect("sign");
                assert_ne!(other.signature, first.signature);
                assert_eq!(provider.private_key().remaining(), start - 2);
                assert!(provider
                    .verify_signed_vote(&precommit, &other.signature, &pk)
                    .await
                    .unwrap()
                    .is_valid());

                // A proposal is signed once too, and the kept signature verifies.
                let value = crate::HkValue::new(Bytes::from_static(b"txs"));
                let proposal =
                    HkProposal::new(HkHeight::new(7), Round::new(0), value.clone(), Round::Nil, addr);
                let p1 = provider.sign_proposal(proposal.clone()).await.expect("sign proposal");
                let p2 = provider.sign_proposal(proposal.clone()).await.expect("sign proposal again");
                assert_eq!(p2.signature, p1.signature);
                assert_eq!(provider.private_key().remaining(), start - 3);
                assert!(provider
                    .verify_signed_proposal(&proposal, &p2.signature, &pk)
                    .await
                    .unwrap()
                    .is_valid());

                // The same value proposed in a later round is another proposal.
                let later = HkProposal::new(HkHeight::new(7), Round::new(1), value, Round::new(0), addr);
                let p3 = provider.sign_proposal(later.clone()).await.expect("sign the later round's");
                assert_ne!(p3.signature, p1.signature);
                assert_eq!(provider.private_key().remaining(), start - 4);
                assert!(provider
                    .verify_signed_proposal(&later, &p3.signature, &pk)
                    .await
                    .unwrap()
                    .is_valid());
            });
        });
    }

    /// v0.19.13: the signatures kept for reuse are those of the newest height signed for. A
    /// request for a later height empties the store, so a request of the earlier height is then
    /// signed anew, and the newer height's signatures stay kept through it.
    #[test]
    fn signatures_are_kept_for_the_newest_height_signed_for() {
        on_big_stack(|| {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async {
                let sk = HkPriv::from_seed([27u8; 32]);
                let pk = sk.public();
                let addr = address_of(&pk);
                let provider = HkSigningProvider::new(sk);
                let start = provider.private_key().remaining();

                let at_seven = HkVote::new_prevote(HkHeight::new(7), Round::new(0), NilOrVal::Nil, addr);
                let at_eight = HkVote::new_prevote(HkHeight::new(8), Round::new(0), NilOrVal::Nil, addr);
                let seven = provider.sign_vote(at_seven.clone()).await.expect("sign");
                let eight = provider.sign_vote(at_eight.clone()).await.expect("sign");
                assert_eq!(provider.private_key().remaining(), start - 2);

                // The newer height's vote is kept.
                let eight_again = provider.sign_vote(at_eight.clone()).await.expect("sign");
                assert_eq!(eight_again.signature, eight.signature);
                assert_eq!(provider.private_key().remaining(), start - 2);

                // The earlier height's is not: it is signed anew, and that signature verifies.
                let seven_again = provider.sign_vote(at_seven.clone()).await.expect("sign");
                assert_ne!(seven_again.signature, seven.signature);
                assert_eq!(provider.private_key().remaining(), start - 3);
                assert!(provider
                    .verify_signed_vote(&at_seven, &seven_again.signature, &pk)
                    .await
                    .unwrap()
                    .is_valid());

                // And the newer height's signatures are kept as they were.
                let eight_once_more = provider.sign_vote(at_eight.clone()).await.expect("sign");
                assert_eq!(eight_once_more.signature, eight.signature);
                assert_eq!(provider.private_key().remaining(), start - 3);
            });
        });
    }

    /// v0.19.13: the store of kept signatures is bounded. Past the bound the oldest entry makes
    /// room and the newer ones are still answered; an earlier height is neither answered nor
    /// kept; a later height empties the store.
    #[test]
    fn signatures_kept_for_one_height_are_bounded() {
        let item = |i: usize| SignedItem::Vote(i.to_le_bytes().to_vec());
        let sig = |i: usize| HkSig(i.to_le_bytes().to_vec());
        let mut store = SignedAtHeight::new();
        for i in 0..SIGNED_AT_HEIGHT_MAX + 10 {
            assert!(store.kept(5, &item(i)).is_none());
            store.keep(5, item(i), sig(i));
            assert!(store.sigs.len() <= SIGNED_AT_HEIGHT_MAX);
            assert_eq!(store.sigs.len(), store.order.len());
        }
        assert_eq!(store.sigs.len(), SIGNED_AT_HEIGHT_MAX);
        for i in 0..10 {
            assert!(store.kept(5, &item(i)).is_none(), "the oldest entries made room");
        }
        let newest = SIGNED_AT_HEIGHT_MAX + 9;
        assert_eq!(store.kept(5, &item(newest)), Some(sig(newest)));
        assert_eq!(store.kept(5, &item(10)), Some(sig(10)), "the oldest entry still kept");

        // A kept item is not replaced.
        store.keep(5, item(newest), sig(0));
        assert_eq!(store.kept(5, &item(newest)), Some(sig(newest)));
        assert_eq!(store.sigs.len(), SIGNED_AT_HEIGHT_MAX);

        // An earlier height is neither answered nor kept.
        assert!(store.kept(4, &item(newest)).is_none());
        store.keep(4, item(0), sig(0));
        assert_eq!(store.sigs.len(), SIGNED_AT_HEIGHT_MAX);
        assert!(store.kept(5, &item(0)).is_none());

        // A later height empties the store and becomes its height.
        assert!(store.kept(6, &item(newest)).is_none());
        assert!(store.sigs.is_empty() && store.order.is_empty());
        store.keep(6, item(1), sig(1));
        assert_eq!(store.kept(6, &item(1)), Some(sig(1)));
        assert!(store.kept(5, &item(1)).is_none(), "an earlier height than the store's");
    }

    /// A directory of its own for signer state files, removed with everything in it when the
    /// test ends.
    struct TempHome(std::path::PathBuf);

    impl TempHome {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!("hk-provider-test-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("a directory for the test's signer state");
            Self(dir)
        }

        fn file(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// v0.19.13: the kept signatures belong to the operational key that made them. When a
    /// rotation puts another key in the provider's handle, a request already signed at this
    /// height is signed anew under the new key, and that signature is the one kept from then
    /// on. Caught mutant: answer from the store without following the live key and the second request
    /// gets the first key's signature back.
    #[test]
    fn signatures_kept_for_reuse_are_dropped_when_the_operational_key_changes() {
        on_big_stack(|| {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async {
                let home = TempHome::new("rotation");
                let sk = HkPriv::from_seed([28u8; 32]);
                let old_pk = sk.public();
                let addr = address_of(&old_pk);
                let provider = HkSigningProvider::new(sk);
                let vote = HkVote::new_prevote(HkHeight::new(7), Round::new(0), NilOrVal::Nil, addr);
                let before = provider.sign_vote(vote.clone()).await.expect("sign");
                assert!(provider
                    .verify_signed_vote(&vote, &before.signature, &old_pk)
                    .await
                    .unwrap()
                    .is_valid());

                // The rotation: the same handle signs with another tree from here.
                let new_pk = provider.private_key().rotate_to([29u8; 32], home.file("epoch-1.bin"));
                assert_ne!(new_pk, old_pk);
                let fresh = provider.private_key().remaining();

                let after = provider.sign_vote(vote.clone()).await.expect("sign under the new key");
                assert_ne!(after.signature, before.signature, "a signature of the new key");
                assert!(provider
                    .verify_signed_vote(&vote, &after.signature, &new_pk)
                    .await
                    .unwrap()
                    .is_valid());
                assert!(!provider
                    .verify_signed_vote(&vote, &after.signature, &old_pk)
                    .await
                    .unwrap()
                    .is_valid());
                assert_eq!(provider.private_key().remaining(), fresh - 1, "one leaf of the new key");

                // And that signature is the one kept now.
                let again = provider.sign_vote(vote.clone()).await.expect("sign");
                assert_eq!(again.signature, after.signature);
                assert_eq!(provider.private_key().remaining(), fresh - 1);
            });
        });
    }

    /// v0.19.13: a request that cannot be signed keeps nothing. A signer that is used up
    /// answers every request with an error and the store stays empty; once a rotation has put
    /// a fresh key in the handle, a later height is signed, and kept.
    #[test]
    fn a_request_that_cannot_be_signed_keeps_nothing_and_a_later_height_signs() {
        on_big_stack(|| {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async {
                let home = TempHome::new("used-up");
                // A state file that is not this key's record: the attach holds the tree used up.
                let state = home.file("consensus_state.bin");
                std::fs::write(&state, b"not a signer state").unwrap();
                let sk = HkPriv::from_seed([30u8; 32]).into_persistent(state);
                assert_eq!(sk.remaining(), 0, "the signer is used up");
                let addr = address_of(&sk.public());
                let provider = HkSigningProvider::new(sk);

                let at_seven = HkVote::new_prevote(HkHeight::new(7), Round::new(0), NilOrVal::Nil, addr);
                assert!(provider.sign_vote(at_seven.clone()).await.is_err());
                assert!(provider.sign_vote(at_seven.clone()).await.is_err(), "and the same request again");
                let proposal = HkProposal::new(
                    HkHeight::new(7),
                    Round::new(0),
                    crate::HkValue::new(Bytes::from_static(b"txs")),
                    Round::Nil,
                    addr,
                );
                assert!(provider.sign_proposal(proposal).await.is_err());
                {
                    let store = provider.signed.lock().unwrap();
                    assert!(store.sigs.is_empty() && store.order.is_empty(), "nothing is kept");
                }

                // A rotation puts a fresh key in the handle: a later height is signed, and kept.
                let new_pk = provider.private_key().rotate_to([31u8; 32], home.file("epoch-1.bin"));
                let fresh = provider.private_key().remaining();
                assert!(fresh > 0);
                let at_eight = HkVote::new_prevote(HkHeight::new(8), Round::new(0), NilOrVal::Nil, addr);
                let signed = provider.sign_vote(at_eight.clone()).await.expect("a later height signs");
                assert!(provider
                    .verify_signed_vote(&at_eight, &signed.signature, &new_pk)
                    .await
                    .unwrap()
                    .is_valid());
                let again = provider.sign_vote(at_eight.clone()).await.expect("sign");
                assert_eq!(again.signature, signed.signature);
                assert_eq!(provider.private_key().remaining(), fresh - 1);
            });
        });
    }

    /// v0.19.13: proposals that differ in one field are different proposals. Through the
    /// provider, another round, another proof-of-lock round, another value of the same length
    /// and another proposer each get a signature and a leaf of their own, and each is kept
    /// beside the others. A value of another length has another id, so the length alone is told
    /// apart at the store's item, where each of the five fields alone makes another item.
    #[test]
    fn proposals_that_differ_in_one_field_are_signed_each_on_a_leaf_of_its_own() {
        on_big_stack(|| {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async {
                let sk = HkPriv::from_seed([32u8; 32]);
                let pk = sk.public();
                let addr = address_of(&pk);
                let other_addr = HkAddress::new([9u8; 20]);
                assert!(other_addr != addr);
                let provider = HkSigningProvider::new(sk);
                let start = provider.private_key().remaining();

                let height = HkHeight::new(7);
                let value = crate::HkValue::new(Bytes::from_static(b"txs"));
                let same_len = crate::HkValue::new(Bytes::from_static(b"TXS"));
                let base = HkProposal::new(height, Round::new(1), value.clone(), Round::new(0), addr);
                let variants = [
                    HkProposal::new(height, Round::new(2), value.clone(), Round::new(0), addr),
                    HkProposal::new(height, Round::new(1), value.clone(), Round::Nil, addr),
                    HkProposal::new(height, Round::new(1), same_len, Round::new(0), addr),
                    HkProposal::new(height, Round::new(1), value.clone(), Round::new(0), other_addr),
                ];

                let first = provider.sign_proposal(base.clone()).await.expect("sign");
                let mut made = vec![first.signature];
                for (i, proposal) in variants.iter().enumerate() {
                    let signed = provider.sign_proposal(proposal.clone()).await.expect("sign");
                    assert!(!made.contains(&signed.signature), "variant {i}: a signature of its own");
                    assert!(provider
                        .verify_signed_proposal(proposal, &signed.signature, &pk)
                        .await
                        .unwrap()
                        .is_valid());
                    made.push(signed.signature);
                    assert_eq!(
                        provider.private_key().remaining(),
                        start - 2 - i as u64,
                        "variant {i}: a leaf of its own"
                    );
                }

                // Each is kept beside the others: asked again, each gets its signature back.
                let spent = provider.private_key().remaining();
                let again = provider.sign_proposal(base.clone()).await.expect("sign");
                assert_eq!(again.signature, made[0]);
                for (i, proposal) in variants.iter().enumerate() {
                    let again = provider.sign_proposal(proposal.clone()).await.expect("sign");
                    assert_eq!(again.signature, made[i + 1]);
                }
                assert_eq!(provider.private_key().remaining(), spent);
            });
        });

        // The store's item: each field alone makes another item.
        let item = |round: i64, pol_round: i64, id: u8, value_len: u64, proposer: u8| SignedItem::Proposal {
            round,
            pol_round,
            value_id: HkValueId::new([id; 32]),
            value_len,
            proposer: HkAddress::new([proposer; 20]),
        };
        let base = item(1, 0, 5, 3, 7);
        let others = [
            item(2, 0, 5, 3, 7),
            item(1, -1, 5, 3, 7),
            item(1, 0, 6, 3, 7),
            item(1, 0, 5, 4, 7),
            item(1, 0, 5, 3, 8),
        ];
        let mut store = SignedAtHeight::new();
        store.keep(0, base.clone(), HkSig(vec![1]));
        assert_eq!(store.kept(0, &base), Some(HkSig(vec![1])));
        for (i, other) in others.iter().enumerate() {
            assert!(store.kept(0, other).is_none(), "item {i} differs in one field");
        }
    }
}
