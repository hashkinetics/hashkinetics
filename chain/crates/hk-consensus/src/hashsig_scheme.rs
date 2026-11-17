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

/// LMS/HSS signature bytes — a consensus signature is exactly
/// `hk_crypto::hashsig::CONSENSUS_SIG_LEN` = 9,140 bytes (RZ-1: `verify` refuses any other
/// length before parsing). Newtype for the Clone/Eq/Ord bounds.
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
    /// Build a consensus key from a 32-byte seed (HSS tree of
    /// `hk_crypto::hashsig::CONSENSUS_CAPACITY` = 2^15 = 32,768 one-time signatures —
    /// ~10.9K heights at ~3 sigs/height; staging incident #1 burned one to exactly zero).
    /// One keygen; the public key is cached (all later `public()` calls are free).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let (signer, pk) = hashsig::generate_consensus(&seed);
        Self { seed, pubkey: HkPub(pk.0), signer: Arc::new(Mutex::new(signer)) }
    }

    /// Attach a durable state file to this key's signer and adopt any state already on
    /// disk (reserve-then-sign; survives restarts without leaf reuse). Call once, on the
    /// single signer that advances this tree — the consensus engine's provider. A damaged or
    /// foreign file retires the tree as used up with one `error!` line while the node keeps
    /// running (HR-7, v0.19.12; `attach_state_file`).
    pub fn into_persistent(self, path: std::path::PathBuf) -> Self {
        attach_state_file(&mut self.signer.lock().unwrap(), path);
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

    /// Signatures this tree has already produced — the leaf position it resumed at plus
    /// everything signed since, or the capacity for a tree attached used up (HR-7, v0.19.12:
    /// the node logs it right after the attach).
    pub fn used(&self) -> u64 {
        self.signer.lock().unwrap().used()
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
    /// as the genesis key; it is not used for signing after startup.) The new epoch's state
    /// file is attached like any other (`attach_state_file`): a damaged or foreign one retires
    /// the new tree as used up with one `error!` line instead of a panic inside commit (HR-7,
    /// v0.19.12), and the leaf-budget trigger then moves on to the next epoch.
    pub fn rotate_to(&self, new_seed: [u8; 32], persist_path: std::path::PathBuf) -> HkPub {
        let (mut signer, pk) = hashsig::generate_consensus(&new_seed);
        attach_state_file(&mut signer, persist_path);
        *self.signer.lock().unwrap() = signer;
        HkPub(pk.0)
    }
}

/// Attach `path` to a consensus signer and log what the attach retired (HR-7, v0.19.12).
/// The attach answers every state-file condition itself (a damaged or foreign file is
/// retired as used up, its bytes kept beside it when they can be read; a good one resumes)
/// and returns `Ok` for all of them, so no state file can panic the start
/// (`into_persistent`) or a live rotation (`rotate_to`, inside commit, where a panic would
/// recur at every restart). No `Err` can occur; the `expect` only fails closed should the
/// attach ever grow one. A retired file's account is the one `error!` line logged here.
fn attach_state_file(signer: &mut HashSigner, path: std::path::PathBuf) {
    signer
        .attach_persistence(path)
        .expect("HashSigner::attach_persistence answers Ok for every state file");
    if let Some(report) = signer.take_damage_report() {
        tracing::error!("{}", report);
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

    /// RZ-1: a consensus signature has exactly `CONSENSUS_SIG_LEN` bytes (every consensus key is
    /// a `generate_consensus` tree); any other length is a decoding error here and `false` in
    /// `verify`. (The wire path builds `HkSig` through `From<Vec<u8>>`, not this method; the
    /// length is enforced again in `verify`, which every path reaches.)
    fn decode_signature(bytes: &[u8]) -> Result<HkSig, Self::DecodingError> {
        if bytes.len() != hashsig::CONSENSUS_SIG_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "consensus signature must be {} bytes, got {}",
                    hashsig::CONSENSUS_SIG_LEN,
                    bytes.len()
                ),
            ));
        }
        Ok(HkSig(bytes.to_vec()))
    }

    fn encode_signature(signature: &HkSig) -> Vec<u8> {
        signature.0.clone()
    }
}

/// Verify a vote/proposal signature. Stateless, order-free, and total: a malformed signature
/// is `false`, never a panic (RZ-1, external report 2026-10-14 — before v0.19.9 an empty or
/// truncated signature on a vote carrying a real validator's address panicked the vendored
/// parser inside the consensus actor, which then stopped for good while the process stayed up).
/// Every consensus key is a `generate_consensus` tree, so an honest signature has exactly
/// `CONSENSUS_SIG_LEN` bytes: any other length is refused here, before a byte is parsed — the
/// cheapest refusal of a crafted vote. Below that, `hashsig::verify` carries its own window,
/// the total parser and the panic boundary.
pub fn verify(msg: &[u8], sig: &HkSig, pk: &HkPub) -> bool {
    if sig.0.len() != hashsig::CONSENSUS_SIG_LEN {
        return false;
    }
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

    /// RZ-1: the consensus verifier refuses a malformed signature — empty, short, one byte
    /// short, one byte long, a bogus level or type code at full length, a zero blob — as
    /// `false`, never a panic; the real signature's length is the pinned constant.
    #[test]
    fn rz1_malformed_consensus_signatures_are_invalid_not_panics() {
        on_big_stack(|| {
            let sk = HkPriv::from_seed([21u8; 32]);
            let pk = sk.public();
            let m = b"hk/v1/consensus-vote prevote h=7 r=0";
            let s = sk.sign(m).expect("sign");
            assert_eq!(s.0.len(), hashsig::CONSENSUS_SIG_LEN);
            assert!(verify(m, &s, &pk));

            assert!(!verify(m, &HkSig(vec![]), &pk));
            assert!(!verify(m, &HkSig(vec![0xAB; 10]), &pk));
            assert!(!verify(m, &HkSig(s.0[..s.0.len() - 1].to_vec()), &pk));
            let mut longer = s.0.clone();
            longer.push(0);
            assert!(!verify(m, &HkSig(longer), &pk));
            assert!(!verify(m, &HkSig(vec![0u8; hashsig::CONSENSUS_SIG_LEN]), &pk));
            for level in [0u32, 7, 8, u32::MAX] {
                let mut bad = s.clone();
                bad.0[..4].copy_from_slice(&level.to_be_bytes());
                assert!(!verify(m, &bad, &pk), "level {level}");
            }
            for at in [8usize, 4 + 4 + (4 + 32 + 32 * 133)] {
                let mut bad = s.clone();
                bad.0[at..at + 4].copy_from_slice(&99u32.to_be_bytes());
                assert!(!verify(m, &bad, &pk), "type code at {at}");
            }
            // The SigningScheme decoder enforces the same length.
            assert!(HkHashScheme::decode_signature(&[]).is_err());
            assert!(HkHashScheme::decode_signature(&s.0[..10]).is_err());
            assert_eq!(HkHashScheme::decode_signature(&s.0).unwrap(), s);
            assert!(verify(m, &s, &pk), "the real signature still verifies");
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

    /// HR-7 (v0.19.12): a damaged state file panics neither the start (`into_persistent`) nor
    /// the live rotation path (`rotate_to`, which runs inside commit): the tree attaches used
    /// up and signs nothing, and a rotation onto the next epoch's (missing) file signs
    /// normally — the way out of a retired tree.
    /// KILL: restore the refusing attach with the panicking callers and `into_persistent`
    /// panics on the 3-byte file (and `rotate_to` on the 7-byte one).
    #[test]
    fn hr7_a_damaged_state_file_retires_the_tree_and_rotation_moves_on() {
        on_big_stack(|| {
            let dir = std::env::temp_dir().join(format!("hk_hr7_scheme_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let master = [31u8; 32];
            let e0 = dir.join("consensus_state.bin");
            std::fs::write(&e0, [1u8, 2, 3]).unwrap();
            let sk = HkPriv::from_seed(master).into_persistent(e0.clone());
            assert_eq!(sk.remaining(), 0, "attached used up");
            assert_eq!(sk.used(), hashsig::CONSENSUS_CAPACITY);
            assert!(sk.sign(b"h=1 vote").is_none(), "a retired tree signs nothing");
            // The live rotation path onto a damaged file: used up again, no panic.
            let e1 = dir.join("consensus_state_e1.bin");
            std::fs::write(&e1, [0u8; 7]).unwrap();
            sk.rotate_to(op_seed(&master, 1), e1.clone());
            assert_eq!(sk.remaining(), 0);
            assert!(sk.sign(b"h=2 vote").is_none());
            // The next epoch's file is missing: a fresh tree, and it signs.
            let e2 = dir.join("consensus_state_e2.bin");
            let pk2 = sk.rotate_to(op_seed(&master, 2), e2.clone());
            assert_eq!(sk.remaining(), hashsig::CONSENSUS_CAPACITY);
            let sig = sk.sign(b"h=3 vote").expect("the rotated tree signs");
            assert!(verify(b"h=3 vote", &sig, &pk2));
            let record = std::fs::read(&e2).unwrap();
            assert_eq!(u64::from_le_bytes(record[..8].try_into().unwrap()), 1, "the first record of the new tree");
            let _ = std::fs::remove_dir_all(&dir);
        });
    }
}
