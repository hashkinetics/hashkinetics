pub mod aux;
pub mod definitions;
pub mod parameter;
pub mod reference_impl_private_key;
mod seed_derive;
pub mod signing;
pub mod verify;

use core::{convert::TryFrom, marker::PhantomData};
use tinyvec::ArrayVec;

use crate::{
    constants::{MAX_HSS_PUBLIC_KEY_LENGTH, REF_IMPL_MAX_PRIVATE_KEY_SIZE},
    hss::{aux::hss_is_aux_data_used, reference_impl_private_key::Seed},
    signature::{Error, SignerMut, Verifier},
    HashChain, Signature, VerifierSignature,
};

use self::{
    aux::MutableExpandedAuxData,
    definitions::{HssPrivateKey, HssPublicKey, InMemoryHssPublicKey},
    parameter::HssParameter,
    reference_impl_private_key::ReferenceImplPrivateKey,
    signing::{HssSignature, InMemoryHssSignature},
};

/**
 * Implementation of [`SignerMut`] using [`Signature`].
 */
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningKey<H: HashChain> {
    pub bytes: ArrayVec<[u8; REF_IMPL_MAX_PRIVATE_KEY_SIZE]>,
    phantom_data: PhantomData<H>,
}

impl<H: HashChain> SigningKey<H> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes = ArrayVec::try_from(bytes).map_err(|_| Error::new())?;

        Ok(Self {
            bytes,
            phantom_data: PhantomData,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.bytes.as_mut_slice()
    }

    pub fn get_lifetime(&self) -> Result<u64, Error> {
        let rfc_sk = ReferenceImplPrivateKey::from_binary_representation(self.bytes.as_slice())
            .map_err(|_| Error::new())?;

        let parsed_sk = HssPrivateKey::<H>::from(&rfc_sk, &mut None).map_err(|_| Error::new())?;

        Ok(parsed_sk.get_lifetime())
    }

    pub fn try_sign_with_aux(
        &mut self,
        msg: &[u8],
        aux_data: Option<&mut &mut [u8]>,
    ) -> Result<Signature, Error> {
        let private_key = self.bytes;
        let mut private_key_update_function = |new_key: &[u8]| {
            self.bytes.as_mut_slice().copy_from_slice(new_key);
            Ok(())
        };

        hss_sign::<H>(
            msg,
            private_key.as_slice(),
            &mut private_key_update_function,
            aux_data,
        )
    }
}

impl<H: HashChain> SignerMut<Signature> for SigningKey<H> {
    fn try_sign(&mut self, msg: &[u8]) -> Result<Signature, Error> {
        self.try_sign_with_aux(msg, None)
    }
}

/**
 * Implementation of [`Verifier`] using [`Signature`] or [`VerifierSignature`].
 */
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey<H: HashChain> {
    pub bytes: ArrayVec<[u8; MAX_HSS_PUBLIC_KEY_LENGTH]>,
    phantom_data: PhantomData<H>,
}

impl<H: HashChain> VerifyingKey<H> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes = ArrayVec::try_from(bytes).map_err(|_| Error::new())?;

        Ok(Self {
            bytes,
            phantom_data: PhantomData,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl<H: HashChain> Verifier<Signature> for VerifyingKey<H> {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        hss_verify::<H>(msg, signature.as_ref(), &self.bytes)
    }
}

impl<'a, H: HashChain> Verifier<VerifierSignature<'a>> for VerifyingKey<H> {
    fn verify(&self, msg: &[u8], signature: &VerifierSignature) -> Result<(), Error> {
        hss_verify::<H>(msg, signature.as_ref(), &self.bytes)
    }
}

/**
 * Verify a signature ([`Signature`] or [`VerifierSignature`]).
 *
 * # Arguments
 * * `HashChain` - The hasher implementation that should be used. ```Sha256``` is a standard software implementation.
 * * `message` - The message that should be verified.
 * * `signature` - The signature that should be used for verification.
 * * `public_key` - The public key that should be used for verification.
 */
pub fn hss_verify<H: HashChain>(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), Error> {
    let signature = InMemoryHssSignature::<H>::new(signature).ok_or_else(Error::new)?;
    let public_key = InMemoryHssPublicKey::<H>::new(public_key).ok_or_else(Error::new)?;

    crate::hss::verify::verify(&signature, &public_key, message).map_err(|_| Error::new())
}

/**
 * Generate a [`Signature`].
 *
 * # Arguments
 * * `HashChain` - The hasher implementation that should be used. ```Sha256``` is a standard software implementation.
 * * `message` - The message that should be signed.
 * * `private_key` - The private key that should be used.
 * * `private_key_update_function` - The update function that is called with the new private key. This function should save the new private key.
 * * `aux_data` - Auxiliary data to speedup signature generation if available
 */
pub fn hss_sign<H: HashChain>(
    message: &[u8],
    private_key: &[u8],
    private_key_update_function: &mut dyn FnMut(&[u8]) -> Result<(), ()>,
    aux_data: Option<&mut &mut [u8]>,
) -> Result<Signature, Error> {
    hss_sign_core::<H>(
        Some(message),
        None,
        private_key,
        private_key_update_function,
        aux_data,
    )
}

#[cfg(feature = "fast_verify")]
pub fn hss_sign_mut<H: HashChain>(
    message_mut: &mut [u8],
    private_key: &[u8],
    private_key_update_function: &mut dyn FnMut(&[u8]) -> Result<(), ()>,
    aux_data: Option<&mut &mut [u8]>,
) -> Result<Signature, Error> {
    if message_mut.len() <= H::OUTPUT_SIZE.into() {
        return Err(Error::new());
    }

    let (_, message_randomizer) = message_mut.split_at(message_mut.len() - H::OUTPUT_SIZE as usize);
    if !message_randomizer.iter().all(|&byte| byte == 0u8) {
        return Err(Error::new());
    }

    hss_sign_core::<H>(
        None,
        Some(message_mut),
        private_key,
        private_key_update_function,
        aux_data,
    )
}

fn hss_sign_core<H: HashChain>(
    message: Option<&[u8]>,
    message_mut: Option<&mut [u8]>,
    private_key: &[u8],
    private_key_update_function: &mut dyn FnMut(&[u8]) -> Result<(), ()>,
    aux_data: Option<&mut &mut [u8]>,
) -> Result<Signature, Error> {
    let mut rfc_private_key = ReferenceImplPrivateKey::from_binary_representation(private_key)
        .map_err(|_| Error::new())?;

    let is_aux_data_used = if let Some(ref aux_data) = aux_data {
        hss_is_aux_data_used(aux_data)
    } else {
        false
    };

    let parameters = rfc_private_key
        .compressed_parameter
        .to::<H>()
        .map_err(|_| Error::new())?;
    let mut expanded_aux_data = HssPrivateKey::get_expanded_aux_data(
        aux_data,
        &rfc_private_key,
        parameters[0].get_lms_parameter(),
        is_aux_data_used,
    );

    let mut private_key = HssPrivateKey::<H>::from(&rfc_private_key, &mut expanded_aux_data)
        .map_err(|_| Error::new())?;

    let hss_signature = HssSignature::sign(
        &mut private_key,
        message,
        message_mut,
        &mut expanded_aux_data,
    )
    .map_err(|_| Error::new())?;

    // Advance private key
    rfc_private_key.increment(&private_key);
    private_key_update_function(&rfc_private_key.to_binary_representation())
        .map_err(|_| Error::new())?;

    signature_from_hss::<H>(&hss_signature)
}

fn signature_from_hss<H: HashChain>(hss_signature: &HssSignature<H>) -> Result<Signature, Error> {
    let hash_iterations = {
        let mut hash_iterations: u32 = 0;
        for signed_public_key in hss_signature.signed_public_keys.iter() {
            hash_iterations += signed_public_key.sig.lmots_signature.hash_iterations as u32;
        }
        hash_iterations + hss_signature.signature.lmots_signature.hash_iterations as u32
    };

    Signature::from_bytes_verbose(&hss_signature.to_binary_representation(), hash_iterations)
}

/**
 * A long-lived signing session (HashKinetics R15, 2026-09-08 — found by testnet-1 seat #1).
 *
 * `hss_sign` re-parses the compressed private key on every call and rebuilds the expanded
 * hierarchy through `HssPrivateKey::from`: for a two-level key that regenerates the whole
 * bottom tree and re-signs its public key with the top tree on **every** signature,
 * although that work only changes when the bottom tree rolls over. This session keeps the
 * expanded key in memory between signatures, so a signature costs one LM-OTS signature plus
 * the bottom tree's authentication path; the expanded key is rebuilt only when the bottom
 * tree is exhausted or after a `rollback`.
 *
 * The compressed private key stays the ONLY durable state. The protocol for the caller is
 * reserve-then-sign: call [`sign`](Self::sign), persist [`pending_private_key`](Self::pending_private_key)
 * durably, and only then [`commit`](Self::commit) and release the signature. If persistence
 * fails, [`rollback`](Self::rollback) and drop the signature: the next `sign` rebuilds the
 * expanded key from the last committed compressed key and uses the same leaf again — never
 * skipped, never reused, because the dropped signature never left the process.
 *
 * Signatures are byte-identical to `hss_sign` for the same compressed key: LM-OTS signing is
 * deterministic (seed-derived keys and randomizer), and the top-level signature over the
 * bottom public key is the same value `HssPrivateKey::from` recomputes every time.
 */
pub struct HssSigningSession<H: HashChain> {
    rfc: ReferenceImplPrivateKey<H>,
    expanded: Option<HssPrivateKey<H>>,
    pending: Option<ReferenceImplPrivateKey<H>>,
    /// Node cache for the CURRENT bottom tree (every level, zero = not yet computed). The
    /// crate's own `get_tree_element` fills it as authentication paths are built, so after
    /// the first signature of a bottom tree every path is a lookup. Cleared on rebuild.
    bottom_aux: alloc::vec::Vec<u8>,
}

/// Build the crate's aux view over a flat buffer holding every level of a tree of `height`:
/// level L occupies `H::OUTPUT_SIZE << L` bytes, in level order, root first.
fn full_tree_aux_view<'a, H: HashChain>(
    buf: &'a mut [u8],
    height: usize,
) -> MutableExpandedAuxData<'a> {
    let mut view: MutableExpandedAuxData<'a> = Default::default();
    let hash_size = H::OUTPUT_SIZE as usize;
    let mut rest = buf;
    for level in 0..=height {
        let (data, r) = rest.split_at_mut(hash_size << level);
        view.data[level] = Some(data);
        rest = r;
    }
    view.level = 0;
    view.hmac = rest;
    view
}

fn full_tree_aux_len<H: HashChain>(height: usize) -> usize {
    let hash_size = H::OUTPUT_SIZE as usize;
    (0..=height).map(|level| hash_size << level).sum()
}

impl<H: HashChain> HssSigningSession<H> {
    /// Open a session on a compressed private key (the bytes `hss_sign` takes). Nothing is
    /// expanded until the first `sign`.
    pub fn open(private_key: &[u8]) -> Result<Self, Error> {
        let rfc = ReferenceImplPrivateKey::from_binary_representation(private_key)
            .map_err(|_| Error::new())?;
        Ok(Self {
            rfc,
            expanded: None,
            pending: None,
            bottom_aux: alloc::vec::Vec::new(),
        })
    }

    /// The compressed private key the session stands on (the last committed state).
    pub fn private_key(&self) -> ArrayVec<[u8; REF_IMPL_MAX_PRIVATE_KEY_SIZE]> {
        self.rfc.to_binary_representation()
    }

    /// The compressed private key AFTER the pending signature — persist this, then `commit`.
    pub fn pending_private_key(&self) -> Option<ArrayVec<[u8; REF_IMPL_MAX_PRIVATE_KEY_SIZE]>> {
        self.pending.as_ref().map(|p| p.to_binary_representation())
    }

    fn bottom_exhausted(expanded: &HssPrivateKey<H>) -> bool {
        match expanded.private_key.last() {
            Some(bottom) => {
                bottom.used_leafs_index as usize >= bottom.lms_parameter.number_of_lm_ots_keys()
            }
            None => true,
        }
    }

    /// Sign `message`. `aux_data` is the top tree's cache (as for `hss_sign`); it is only
    /// read when the expanded key has to be (re)built. Errors if a previous signature is
    /// still pending (`commit` or `rollback` it first) or the key is exhausted.
    pub fn sign(
        &mut self,
        message: &[u8],
        aux_data: Option<&mut &mut [u8]>,
    ) -> Result<Signature, Error> {
        if self.pending.is_some() {
            return Err(Error::new());
        }

        let rebuild = match &self.expanded {
            None => true,
            Some(expanded) => Self::bottom_exhausted(expanded),
        };
        if rebuild {
            let is_aux_data_used = if let Some(ref aux_data) = aux_data {
                hss_is_aux_data_used(aux_data)
            } else {
                false
            };
            let parameters = self
                .rfc
                .compressed_parameter
                .to::<H>()
                .map_err(|_| Error::new())?;
            let mut expanded_aux_data = HssPrivateKey::get_expanded_aux_data(
                aux_data,
                &self.rfc,
                parameters[0].get_lms_parameter(),
                is_aux_data_used,
            );
            let expanded = HssPrivateKey::<H>::from(&self.rfc, &mut expanded_aux_data)
                .map_err(|_| Error::new())?;
            // A fresh bottom tree: start its node cache from zero.
            let height = expanded
                .private_key
                .last()
                .map(|k| k.lms_parameter.get_tree_height() as usize)
                .unwrap_or(0);
            self.bottom_aux = alloc::vec![0u8; full_tree_aux_len::<H>(height)];
            self.expanded = Some(expanded);
        }

        let expanded = match self.expanded.as_mut() {
            Some(expanded) => expanded,
            None => return Err(Error::new()),
        };
        if Self::bottom_exhausted(expanded) {
            // A fresh expansion with no leaf left means the whole key is exhausted.
            self.expanded = None;
            return Err(Error::new());
        }

        // The top tree's cache does not describe the bottom tree; the session keeps its own
        // full node cache for the current bottom tree instead (filled by the crate as paths
        // are built), so the authentication path is a lookup after the first signature.
        let height = expanded
            .private_key
            .last()
            .map(|k| k.lms_parameter.get_tree_height() as usize)
            .unwrap_or(0);
        if self.bottom_aux.len() != full_tree_aux_len::<H>(height) {
            self.bottom_aux = alloc::vec![0u8; full_tree_aux_len::<H>(height)];
        }
        let mut bottom_aux: Option<MutableExpandedAuxData> =
            Some(full_tree_aux_view::<H>(&mut self.bottom_aux, height));
        let hss_signature = HssSignature::sign(expanded, Some(message), None, &mut bottom_aux)
            .map_err(|_| Error::new())?;

        // `HssSignature::sign` appends the bottom-tree signature to the expanded key; only the
        // L-1 signatures over child public keys belong there. Drop it so the next call signs.
        if expanded.signatures.len() == expanded.private_key.len() {
            expanded.signatures.pop();
        }

        let mut next = self.rfc.clone();
        next.increment(expanded);
        self.pending = Some(next);

        signature_from_hss::<H>(&hss_signature)
    }

    /// Adopt the pending compressed key: the caller has persisted it durably.
    pub fn commit(&mut self) {
        if let Some(next) = self.pending.take() {
            self.rfc = next;
        }
    }

    /// Forget the pending signature (the caller must not release it). The expanded key is
    /// dropped, so the next `sign` rebuilds it from the last committed compressed key and
    /// signs with the same leaf again.
    pub fn rollback(&mut self) {
        self.pending = None;
        self.expanded = None;
        self.bottom_aux.clear();
    }
}

/**
 * Generate [`SigningKey`] and [`VerifyingKey`].
 * # Arguments
 *
 * * `HashChain` - The hasher implementation that should be used. ```Sha256``` is a standard software implementation.
 * * `parameters` - An array which specifies the Winternitz parameter and tree height of each individual HSS level. The first element describes Level 1, the second element Level 2 and so on.
 * * `seed` - An optional seed which will be used to generate the private key. It must be only used for testing purposes and not for production used key pairs.
 * * `aux_data` - The reference to a slice to auxiliary data. This can be used to speedup signature generation.
 *
 * # Example
 * ```
 * use rand::{rngs::OsRng, RngCore};
 * use tinyvec::ArrayVec;
 * use hbs_lms::{keygen, HssParameter, LmotsAlgorithm, LmsAlgorithm, Sha256_256, HashChain, Seed};
 *
 * let parameters = [
 *      HssParameter::new(LmotsAlgorithm::LmotsW4, LmsAlgorithm::LmsH5),
 *      HssParameter::new(LmotsAlgorithm::LmotsW1, LmsAlgorithm::LmsH5),
 * ];
 * let mut aux_data = vec![0u8; 10_000];
 * let aux_slice: &mut &mut [u8] = &mut &mut aux_data[..];
 * let mut seed = Seed::default();
 * OsRng.fill_bytes(seed.as_mut_slice());
 *
 * let (signing_key, verifying_key) =
 *      keygen::<Sha256_256>(&parameters, &seed, Some(aux_slice)).unwrap();
 * ```
 */
pub fn hss_keygen<H: HashChain>(
    parameters: &[HssParameter<H>],
    seed: &Seed<H>,
    aux_data: Option<&mut &mut [u8]>,
) -> Result<(SigningKey<H>, VerifyingKey<H>), Error> {
    let private_key =
        ReferenceImplPrivateKey::generate(parameters, seed).map_err(|_| Error::new())?;

    let hss_public_key = HssPublicKey::from(&private_key, aux_data).map_err(|_| Error::new())?;

    let signing_key = SigningKey::from_bytes(&private_key.to_binary_representation())?;
    let verifying_key = VerifyingKey::from_bytes(&hss_public_key.to_binary_representation())?;
    Ok((signing_key, verifying_key))
}

#[cfg(test)]
mod tests {
    use crate::util::helper::test_helper::gen_random_seed;
    use crate::{
        constants::{HSS_COMPRESSED_USED_LEAFS_SIZE, MAX_HASH_SIZE},
        hasher::{
            sha256::{Sha256_128, Sha256_192, Sha256_256},
            shake256::{Shake256_128, Shake256_192, Shake256_256},
            HashChain,
        },
        LmotsAlgorithm, LmsAlgorithm,
    };

    use super::*;
    // R15 tests: the crate is `no_std` unless the `std` feature is on, so heap types come
    // from `alloc` explicitly (lib.rs declares `extern crate alloc`).
    use alloc::vec::Vec;

    /// R15: the session must produce byte-identical signatures to `hss_sign` for the same
    /// compressed key, across bottom-tree rollovers, and advance the compressed key identically.
    #[test]
    fn signing_session_matches_hss_sign_across_rollover() {
        type H = Shake256_256;
        let seed = gen_random_seed::<H>();
        let parameters = [
            HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
            HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
        ];
        // Reference path: fresh expansion every call (aux-less), state advanced by the callback.
        let (signing_key, verifying_key) =
            hss_keygen::<H>(&parameters, &seed, None).expect("keygen");
        let mut reference_state = signing_key.as_slice().to_vec();
        // Session path on the same starting key.
        let mut session = HssSigningSession::<H>::open(signing_key.as_slice()).expect("open");

        // 70 signatures crosses two H5 rollovers (at 32 and 64).
        for i in 0u32..70 {
            let message = [i as u8, 7, 42, 0xAB, (i * 3) as u8];
            let mut next_reference: Vec<u8> = Vec::new();
            let mut update = |new_key: &[u8]| {
                next_reference = new_key.to_vec();
                Ok(())
            };
            let reference_sig =
                hss_sign::<H>(&message, &reference_state, &mut update, None).expect("hss_sign");
            reference_state = next_reference;

            let session_sig = session.sign(&message, None).expect("session sign");
            let pending = session.pending_private_key().expect("pending state");
            session.commit();

            assert_eq!(
                session_sig.as_ref(),
                reference_sig.as_ref(),
                "signature {} differs between the session and hss_sign",
                i
            );
            assert_eq!(pending.as_slice(), reference_state.as_slice(), "state {} differs", i);
            assert!(
                hss_verify::<H>(&message, session_sig.as_ref(), verifying_key.as_slice()).is_ok(),
                "signature {} does not verify",
                i
            );
        }
    }

    /// R15: `rollback` must make the next signature use the same leaf again (never skipped).
    #[test]
    fn signing_session_rollback_reuses_the_unreleased_leaf() {
        type H = Shake256_256;
        let seed = gen_random_seed::<H>();
        let parameters = [
            HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
            HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
        ];
        let (signing_key, _) = hss_keygen::<H>(&parameters, &seed, None).expect("keygen");
        let mut session = HssSigningSession::<H>::open(signing_key.as_slice()).expect("open");
        let message = b"the same leaf, twice";

        let first = session.sign(message, None).expect("sign");
        let before = session.private_key();
        session.rollback();
        assert_eq!(session.private_key().as_slice(), before.as_slice(), "rollback must not advance");
        let again = session.sign(message, None).expect("sign again");
        assert_eq!(first.as_ref(), again.as_ref(), "after rollback the same leaf signs again");
        session.commit();
        let third = session.sign(message, None).expect("sign after commit");
        assert_ne!(first.as_ref(), third.as_ref(), "after commit the leaf has moved on");
    }

    /// R15: an aux buffer larger than the finalized cache must still validate — the MAC is one
    /// hash wide, not "everything after the layers".
    #[test]
    fn aux_cache_validates_from_an_oversized_buffer() {
        type H = Shake256_256;
        let seed = gen_random_seed::<H>();
        let parameters = [
            HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
            HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
        ];
        let mut aux = alloc::vec![0u8; 64 * 1024]; // far more than an H5 top tree needs
        let (signing_key, _) = {
            let mut a: &mut [u8] = &mut aux;
            hss_keygen::<H>(&parameters, &seed, Some(&mut a)).expect("keygen with aux")
        };
        assert!(hss_is_aux_data_used(&aux), "keygen must mark the cache used");
        let rfc = ReferenceImplPrivateKey::<H>::from_binary_representation(signing_key.as_slice())
            .expect("parse");
        // The full, oversized buffer — what a caller that keeps its Vec around passes at sign time.
        let expanded = aux::hss_expand_aux_data::<H>(Some(&mut aux[..]), Some(rfc.seed.as_slice()));
        assert!(expanded.is_some(), "the cache must validate from the oversized buffer");
    }

    #[test]
    fn update_keypair() {
        let message = [
            32u8, 48, 2, 1, 48, 58, 20, 57, 9, 83, 99, 255, 0, 34, 2, 1, 0,
        ];
        type H = Sha256_256;
        let seed = gen_random_seed::<H>();

        let lmots = LmotsAlgorithm::LmotsW4;
        let lms = LmsAlgorithm::LmsH5;
        let parameters = [HssParameter::new(lmots, lms)];

        let (mut signing_key, verifying_key) =
            hss_keygen::<H>(&parameters, &seed, None).expect("Should generate HSS keys");

        let signing_key_const = signing_key.clone();

        let mut update_private_key = |new_key: &[u8]| {
            signing_key.as_mut_slice().copy_from_slice(new_key);
            Ok(())
        };

        let signature = hss_sign::<H>(
            &message,
            signing_key_const.as_slice(),
            &mut update_private_key,
            None,
        )
        .expect("Signing should complete without error.");

        assert!(hss_verify::<H>(&message, signature.as_ref(), verifying_key.as_slice()).is_ok());

        assert_ne!(signing_key.as_slice(), signing_key_const.as_slice());
        assert_eq!(
            signing_key.as_slice()[HSS_COMPRESSED_USED_LEAFS_SIZE..],
            signing_key_const.as_slice()[HSS_COMPRESSED_USED_LEAFS_SIZE..]
        );
    }

    #[test]
    fn exhaust_keypair() {
        let message = [
            32u8, 48, 2, 1, 48, 58, 20, 57, 9, 83, 99, 255, 0, 34, 2, 1, 0,
        ];
        type H = Sha256_256;
        let seed = gen_random_seed::<H>();

        let lmots = LmotsAlgorithm::LmotsW2;
        let lms = LmsAlgorithm::LmsH2;
        let parameters = [HssParameter::new(lmots, lms), HssParameter::new(lmots, lms)];

        let (mut signing_key, verifying_key) =
            hss_keygen::<H>(&parameters, &seed, None).expect("Should generate HSS keys");
        let keypair_lifetime = signing_key.get_lifetime().unwrap();

        assert_ne!(
            signing_key.as_slice()[(REF_IMPL_MAX_PRIVATE_KEY_SIZE - H::OUTPUT_SIZE as usize)..],
            [0u8; H::OUTPUT_SIZE as usize],
        );

        for index in 0..keypair_lifetime {
            assert_eq!(
                signing_key.as_slice()[..HSS_COMPRESSED_USED_LEAFS_SIZE],
                index.to_be_bytes(),
            );
            assert_eq!(
                keypair_lifetime - signing_key.get_lifetime().unwrap(),
                index
            );

            let signing_key_const = signing_key.clone();

            let mut update_private_key = |new_key: &[u8]| {
                signing_key.as_mut_slice().copy_from_slice(new_key);
                Ok(())
            };

            let signature = hss_sign::<H>(
                &message,
                signing_key_const.as_slice(),
                &mut update_private_key,
                None,
            )
            .expect("Signing should complete without error.");

            assert!(
                hss_verify::<H>(&message, signature.as_ref(), verifying_key.as_slice()).is_ok()
            );
        }
        assert_eq!(
            signing_key.as_slice()[(REF_IMPL_MAX_PRIVATE_KEY_SIZE - H::OUTPUT_SIZE as usize)..],
            [0u8; H::OUTPUT_SIZE as usize],
        );
    }

    #[test]
    #[should_panic(expected = "Signing should panic!")]
    fn use_exhausted_keypair() {
        let message = [
            32u8, 48, 2, 1, 48, 58, 20, 57, 9, 83, 99, 255, 0, 34, 2, 1, 0,
        ];
        type H = Sha256_256;
        let seed = gen_random_seed::<H>();

        let lmots = LmotsAlgorithm::LmotsW2;
        let lms = LmsAlgorithm::LmsH2;
        let parameters = [HssParameter::new(lmots, lms), HssParameter::new(lmots, lms)];

        let (mut signing_key, verifying_key) =
            hss_keygen::<H>(&parameters, &seed, None).expect("Should generate HSS keys");
        let keypair_lifetime = signing_key.get_lifetime().unwrap();

        for index in 0..(1u64 + keypair_lifetime) {
            let signing_key_const = signing_key.clone();

            let mut update_private_key = |new_key: &[u8]| {
                signing_key.as_mut_slice().copy_from_slice(new_key);
                Ok(())
            };

            let signature = hss_sign::<H>(
                &message,
                signing_key_const.as_slice(),
                &mut update_private_key,
                None,
            )
            .unwrap_or_else(|_| {
                if index < keypair_lifetime {
                    panic!("Signing should complete without error.");
                } else {
                    assert!(signing_key.get_lifetime().is_err());
                    panic!("Signing should panic!");
                }
            });

            assert!(
                hss_verify::<H>(&message, signature.as_ref(), verifying_key.as_slice()).is_ok()
            );
        }
    }

    #[test]
    fn keygen_with_forged_aux_data() {
        type H = Sha256_256;
        let seed = gen_random_seed::<H>();

        let lmots = LmotsAlgorithm::LmotsW2;
        let lms = LmsAlgorithm::LmsH5;
        let parameters = [HssParameter::new(lmots, lms), HssParameter::new(lmots, lms)];

        let mut aux_data = [0u8; 1_000];
        let aux_slice: &mut &mut [u8] = &mut &mut aux_data[..];

        let (sk1, vk1) =
            hss_keygen::<H>(&parameters, &seed, Some(aux_slice)).expect("Should generate HSS keys");

        aux_slice[2 * MAX_HASH_SIZE - 1] ^= 0x1;

        let (sk2, vk2) =
            hss_keygen::<H>(&parameters, &seed, Some(aux_slice)).expect("Should generate HSS keys");

        assert_eq!(sk1, sk2);
        assert_eq!(vk1, vk2);
    }

    #[test]
    fn test_signing_sha256_128() {
        test_signing_core_sha_x::<Sha256_128>();
    }

    #[test]
    fn test_signing_sha256_192() {
        test_signing_core_sha_x::<Sha256_192>();
    }

    #[test]
    fn test_signing_sha256_256() {
        test_signing_core_sha_x::<Sha256_256>();
    }

    #[test]
    fn test_signing_shake256_128() {
        test_signing_core_sha_x::<Shake256_128>();
    }

    #[test]
    fn test_signing_shake256_192() {
        test_signing_core_sha_x::<Shake256_192>();
    }

    #[test]
    fn test_signing_shake256_256() {
        test_signing_core_sha_x::<Shake256_256>();
    }

    fn test_signing_core_sha_x<H: HashChain>() {
        test_signing_core::<H>(&mut None);
        let mut aux_data = [0u8; 1_000];
        test_signing_core::<H>(&mut Some(&mut aux_data));
    }

    fn test_signing_core<H: HashChain>(aux_data: &mut Option<&mut [u8]>) {
        let seed = gen_random_seed::<H>();
        let (mut signing_key, verifying_key) = hss_keygen::<H>(
            &[
                HssParameter::construct_default_parameters(),
                HssParameter::construct_default_parameters(),
                HssParameter::construct_default_parameters(),
            ],
            &seed,
            aux_data.as_mut(),
        )
        .expect("Should generate HSS keys");

        let message_values = [
            32u8, 48, 2, 1, 48, 58, 20, 57, 9, 83, 99, 255, 0, 34, 2, 1, 0,
        ];
        let mut message = [0u8; 64];
        message[..message_values.len()].copy_from_slice(&message_values);

        let signing_key_const = signing_key.clone();

        let mut update_private_key = |new_key: &[u8]| {
            signing_key.as_mut_slice().copy_from_slice(new_key);
            Ok(())
        };

        let signature = hss_sign::<H>(
            &message,
            signing_key_const.as_slice(),
            &mut update_private_key,
            aux_data.as_mut(),
        )
        .expect("Signing should complete without error.");

        assert!(hss_verify::<H>(&message, signature.as_ref(), verifying_key.as_slice(),).is_ok());

        message[0] = 33;

        assert!(hss_verify::<H>(&message, signature.as_ref(), verifying_key.as_slice(),).is_err());
    }

    #[cfg(feature = "fast_verify")]
    #[test]
    fn test_signing_fast_verify() {
        type H = Sha256_256;
        let seed = gen_random_seed::<H>();

        let (mut signing_key, verifying_key) = hss_keygen::<H>(
            &[
                HssParameter::construct_default_parameters(),
                HssParameter::construct_default_parameters(),
                HssParameter::construct_default_parameters(),
            ],
            &seed,
            None,
        )
        .expect("Should generate HSS keys");

        let message_values = [
            32u8, 48, 2, 1, 48, 58, 20, 57, 9, 83, 99, 255, 0, 34, 2, 1, 0,
        ];
        let mut message = [0u8; 64];
        message[..message_values.len()].copy_from_slice(&message_values);

        let signing_key_const = signing_key.clone();

        let mut update_private_key = |new_key: &[u8]| {
            signing_key.as_mut_slice().copy_from_slice(new_key);
            Ok(())
        };

        let signature = hss_sign_mut::<H>(
            &mut message,
            signing_key_const.as_slice(),
            &mut update_private_key,
            None,
        )
        .expect("Signing should complete without error.");

        assert!(H::OUTPUT_SIZE == MAX_HASH_SIZE as u16);
        assert_ne!(
            message[(message.len() - MAX_HASH_SIZE)..],
            [0u8; MAX_HASH_SIZE]
        );

        assert!(hss_verify::<H>(&message, signature.as_ref(), verifying_key.as_slice()).is_ok());
    }
}
