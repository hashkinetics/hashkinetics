//! SLH-DSA-SHAKE-192s ROOT signer (FIPS 205) over the `fips205` crate.
//!
//! This is the STATELESS validator identity — the permanent root that certifies (rotates)
//! the stateful LMS/HSS operational trees and, being stateless, never exhausts (~2^64
//! signatures). It is the answer to "what happens after root exhaustion": nothing, the
//! root is the anchor; operational keys rotate under it. See docs/MAINNET-KEY-MANAGEMENT.md.
//!
//! Keygen is deterministic from a 32-byte master seed (SHAKE-256 expands to the three
//! FIPS-205 seeds); signatures are deterministic (non-hedged) so a rotation certificate is
//! reproducible. SLH-DSA-SHAKE-192s: 48-byte public key, 16,224-byte signature, cat-3.

use fips205::slh_dsa_shake_192s::{self as slh, PublicKey, KG};
use fips205::traits::{KeyGen, SerDes, Signer, Verifier};

use crate::hash::shake256_n;

/// SLH-DSA-SHAKE-192s public-key length (bytes).
pub const ROOT_PK_LEN: usize = slh::PK_LEN; // 48
/// SLH-DSA-SHAKE-192s signature length (bytes).
pub const ROOT_SIG_LEN: usize = slh::SIG_LEN; // 16224

const DOM_ROOT_SEED: &str = "hk/v1/slhdsa-root-seed";

/// A validator's stateless SLH-DSA root secret (its permanent identity). Holds the
/// private key plus the cached 48-byte public key.
pub struct RootSecret {
    sk: slh::PrivateKey,
    pk: [u8; ROOT_PK_LEN],
}

impl RootSecret {
    /// Deterministically derive the root keypair from a 32-byte master seed.
    /// SHAKE-256 expands the seed into the three FIPS-205 seeds (SK.seed, SK.prf, PK.seed).
    pub fn from_seed(seed32: &[u8; 32]) -> Self {
        let m = shake256_n(DOM_ROOT_SEED, &[seed32], 3 * slh::N);
        let mut sk_seed = [0u8; slh::N];
        let mut sk_prf = [0u8; slh::N];
        let mut pk_seed = [0u8; slh::N];
        sk_seed.copy_from_slice(&m[..slh::N]);
        sk_prf.copy_from_slice(&m[slh::N..2 * slh::N]);
        pk_seed.copy_from_slice(&m[2 * slh::N..]);
        let (pk, sk) = KG::keygen_with_seeds(&sk_seed, &sk_prf, &pk_seed);
        Self { sk, pk: pk.into_bytes() }
    }

    /// The 48-byte root public key — the validator's permanent on-chain identity.
    pub fn public_bytes(&self) -> [u8; ROOT_PK_LEN] {
        self.pk
    }

    /// Deterministically sign `msg` (empty FIPS-205 context, non-hedged). The root signs
    /// rotation certificates; it never advances state, so this is safe to repeat.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.sk.try_sign(msg, &[], false).expect("slh-dsa-192s sign").to_vec()
    }
}

/// Verify an SLH-DSA-SHAKE-192s signature (stateless, order-free). Rejects malformed
/// public-key or signature lengths.
pub fn root_verify(pk_bytes: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if pk_bytes.len() != ROOT_PK_LEN || sig.len() != ROOT_SIG_LEN {
        return false;
    }
    let mut pk_arr = [0u8; ROOT_PK_LEN];
    pk_arr.copy_from_slice(pk_bytes);
    let pk = match PublicKey::try_from_bytes(&pk_arr) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let mut sig_arr = [0u8; ROOT_SIG_LEN];
    sig_arr.copy_from_slice(sig);
    pk.verify(msg, &sig_arr, &[])
}

// SLH-DSA keygen/sign allocate large fixed arrays — run on a generous stack (like LMS).
#[cfg(test)]
fn on_big_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new().stack_size(32 * 1024 * 1024).spawn(f).unwrap().join().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_sign_verify_and_deterministic_keygen() {
        on_big_stack(|| {
            let root = RootSecret::from_seed(&[7u8; 32]);
            let pk = root.public_bytes();
            assert_eq!(pk.len(), ROOT_PK_LEN);

            let msg = b"hk/v1/rotation-cert epoch=1";
            let sig = root.sign(msg);
            assert_eq!(sig.len(), ROOT_SIG_LEN);
            assert!(root_verify(&pk, msg, &sig));
            assert!(!root_verify(&pk, b"other message", &sig));

            // Same seed → same public key (deterministic); different seed → different key.
            assert_eq!(pk, RootSecret::from_seed(&[7u8; 32]).public_bytes());
            assert_ne!(pk, RootSecret::from_seed(&[8u8; 32]).public_bytes());
        });
    }

    #[test]
    fn tampered_sig_and_wrong_root_rejected() {
        on_big_stack(|| {
            let root = RootSecret::from_seed(&[1u8; 32]);
            let pk = root.public_bytes();
            let msg = b"authorize operational key";
            let mut sig = root.sign(msg);
            assert!(root_verify(&pk, msg, &sig));

            let mid = sig.len() / 2;
            sig[mid] ^= 1;
            assert!(!root_verify(&pk, msg, &sig));

            // A different root's key must not verify a good signature.
            let other = RootSecret::from_seed(&[2u8; 32]);
            let good = root.sign(msg);
            assert!(!root_verify(&other.public_bytes(), msg, &good));
        });
    }
}
