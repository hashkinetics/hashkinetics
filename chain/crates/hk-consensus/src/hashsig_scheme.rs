//! HkHashScheme — the hash-based consensus signing scheme (P1 gate 1, Stage 1).
//!
//! Implements Malachite's `SigningScheme` over `hk-crypto::hashsig` (stateful LMS/HSS
//! signatures on SHAKE-256). This is the scheme that replaces stock Ed25519 for
//! consensus votes; Stage 1 builds and unit-tests it standalone (the node is untouched
//! and stays green). Stage 2 sets `HkContext::SigningScheme = HkHashScheme` and rewires
//! the provider/codec/genesis/keyfile (see docs/HASHSIG-CONSENSUS-SWAP.md).
//!
//! Trait-bound notes:
//! - `Signature` wraps LMS sig bytes in a newtype so it gets Clone/Eq/Ord (hbs-lms's
//!   own Signature type has none of these).
//! - `PrivateKey` is a **non-cloning handle**: `Arc<Mutex<HashSigner>>` + the 32-byte
//!   seed. Cloning shares the signer (never forks leaf state); the mutex serializes a
//!   validator's own signing — which is exactly what one-time-leaf safety requires.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use malachitebft_core_types::SigningScheme;

use hk_crypto::hash::shake256_32;
use hk_crypto::hashsig::{self, HashSigPublic, HashSigner};

use crate::context::DOM_VALIDATOR_ADDR;
use crate::HkAddress;

/// LMS/HSS signature bytes (~1–2.5 KB). Newtype for the Clone/Eq/Ord bounds.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HkSig(pub Vec<u8>);

impl From<Vec<u8>> for HkSig {
    fn from(v: Vec<u8>) -> Self {
        HkSig(v)
    }
}

/// LMS/HSS public key bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HkPub(pub Vec<u8>);

/// Consensus private key: the seed (for deterministic public/network derivation), the
/// cached public key (keygen is expensive — do it once), and a shared, state-advancing
/// signer. `Clone` shares the signer handle — it never forks leaf state.
#[derive(Clone)]
pub struct HkPriv {
    pub seed: [u8; 32],
    pubkey: HkPub,
    signer: Arc<Mutex<HashSigner>>,
}

impl HkPriv {
    /// Build a consensus key from a 32-byte seed (HSS 2×H10 ≈ 1M signatures).
    /// One keygen; the public key is cached (all later `public()` calls are free).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let (signer, pk) = hashsig::generate_consensus(&seed);
        Self { seed, pubkey: HkPub(pk.0), signer: Arc::new(Mutex::new(signer)) }
    }

    /// Attach a durable state file to this key's signer and adopt any state already on
    /// disk (reserve-then-sign; survives restarts without leaf reuse). Call once, on the
    /// single signer that advances this tree — the consensus engine's provider.
    pub fn into_persistent(self, path: std::path::PathBuf) -> Self {
        if let Err(e) = self.signer.lock().unwrap().attach_persistence(path) {
            panic!("consensus key persistence attach failed: {e}");
        }
        self
    }

    /// The public key (cached; deterministic from the seed).
    pub fn public(&self) -> HkPub {
        self.pubkey.clone()
    }

    /// Signatures remaining before this tree is exhausted (rotate via the root then).
    pub fn remaining(&self) -> u64 {
        self.signer.lock().unwrap().remaining()
    }

    /// Sign, advancing state. Persist-before-release lives inside `HashSigner::sign`.
    pub fn sign(&self, msg: &[u8]) -> Option<HkSig> {
        self.signer.lock().unwrap().sign(msg).map(HkSig)
    }

    /// SCMS rotation: replace this handle's inner operational signer with a FRESH tree
    /// derived from `new_seed`, persisting to `persist_path`. Because `Clone` shares the
    /// `Arc<Mutex<HashSigner>>`, every holder of this handle — including the consensus
    /// engine's signing provider — immediately signs with the new tree. Returns the new
    /// operational public key (which must equal the one in the applied `RotationCert`).
    /// Call exactly at the height the validator set swaps this validator's key, so votes
    /// verify against the matching key. (The cached `pubkey` field is intentionally left
    /// as the genesis key; it is not used for signing after startup.)
    pub fn rotate_to(&self, new_seed: [u8; 32], persist_path: std::path::PathBuf) -> HkPub {
        let (mut signer, pk) = hashsig::generate_consensus(&new_seed);
        if let Err(e) = signer.attach_persistence(persist_path) {
            panic!("rotation persistence attach failed: {e}");
        }
        *self.signer.lock().unwrap() = signer;
        HkPub(pk.0)
    }
}

/// Deterministic per-epoch operational-key seed. Epoch 0 is the master seed itself (the
/// genesis operational key); epoch ≥ 1 is SHAKE-256(master ‖ epoch). Any node can derive
/// the same seed, but only the key's owner (with the master seed) can build the tree.
pub fn op_seed(master: &[u8; 32], epoch: u64) -> [u8; 32] {
    if epoch == 0 {
        *master
    } else {
        let ep = epoch.to_le_bytes();
        shake256_32("hk/v1/op-rotation-seed", &[&master[..], &ep[..]])
    }
}

impl std::fmt::Debug for HkPriv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HkPriv(seed=0x{}…)", hex::encode(&self.seed[..4]))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HkHashScheme;

impl SigningScheme for HkHashScheme {
    type DecodingError = std::io::Error;
    type Signature = HkSig;
    type PublicKey = HkPub;
    type PrivateKey = HkPriv;

    fn decode_signature(bytes: &[u8]) -> Result<HkSig, Self::DecodingError> {
        Ok(HkSig(bytes.to_vec()))
    }

    fn encode_signature(signature: &HkSig) -> Vec<u8> {
        signature.0.clone()
    }
}

/// Verify a vote/proposal signature. Stateless, order-free.
pub fn verify(msg: &[u8], sig: &HkSig, pk: &HkPub) -> bool {
    hashsig::verify(msg, &sig.0, &HashSigPublic(pk.0.clone()))
}

/// Validator address from a hash-based public key — same 20-byte SHAKE-256 rule as the
/// Ed25519 path, so addressing is scheme-agnostic.
pub fn address_of(pk: &HkPub) -> HkAddress {
    let h = shake256_32(DOM_VALIDATOR_ADDR, &[&pk.0]);
    let mut a = [0u8; HkAddress::LENGTH];
    a.copy_from_slice(&h[..HkAddress::LENGTH]);
    HkAddress::new(a)
}

#[cfg(test)]
fn on_big_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new().stack_size(32 * 1024 * 1024).spawn(f).unwrap().join().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_sign_verify_encode_decode() {
        on_big_stack(|| {
            let sk = HkPriv::from_seed([5u8; 32]);
            let pk = sk.public();
            assert!(sk.remaining() > 32_000); // HSS H10/H5 ≈ 32,768 capacity

            let m1 = b"hk/v1/consensus-vote prevote h=1 r=0";
            let s1 = sk.sign(m1).expect("sign 1");
            assert!(verify(m1, &s1, &pk));

            // Encode/decode round-trip through the SigningScheme methods.
            let enc = HkHashScheme::encode_signature(&s1);
            let dec = HkHashScheme::decode_signature(&enc).unwrap();
            assert_eq!(dec, s1);

            // State advanced: a second signature uses a different leaf, still verifies.
            let m2 = b"hk/v1/consensus-vote precommit h=1 r=0";
            let s2 = sk.sign(m2).expect("sign 2");
            assert!(verify(m2, &s2, &pk));
            assert_ne!(s1, s2);

            // Tamper + wrong message rejected.
            let mut bad = s1.clone();
            let mid = bad.0.len() / 2;
            bad.0[mid] ^= 1;
            assert!(!verify(m1, &bad, &pk));
            assert!(!verify(b"other", &s1, &pk));
        });
    }

    #[test]
    fn public_and_address_are_deterministic() {
        on_big_stack(|| {
            let a = HkPriv::from_seed([9u8; 32]);
            let b = HkPriv::from_seed([9u8; 32]);
            assert_eq!(a.public(), b.public());
            assert_eq!(address_of(&a.public()), address_of(&b.public()));
            let c = HkPriv::from_seed([10u8; 32]);
            assert_ne!(a.public(), c.public());
        });
    }
}
