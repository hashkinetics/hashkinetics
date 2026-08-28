//! Lamport one-time signatures over SHAKE-256 — the v0 account-authentication scheme.
//!
//! WHY THIS EXISTS (honesty note): the LMS/SLH-DSA adapters are KAT-gated and not yet
//! wired. Rather than run the devnet with fake/no signatures, accounts use a REAL
//! hash-based OTS in a self-ratcheting chain ("L-ratchet"):
//!   - account state stores `auth_commit` = commitment to the CURRENT Lamport pubkey;
//!   - every tx carries: the full pubkey (opens the commitment), a signature over the
//!     tx (which includes `next_auth`, the commitment to the NEXT pubkey);
//!   - on success the account ratchets: auth_commit ← next_auth, nonce += 1.
//! Each key signs exactly once (nonce = chain position = the leaf-index=nonce rule of
//! plan §3.3 in miniature). Security = second-preimage resistance of SHAKE-256 only.
//! Cost: pk 16 KiB + sig 8 KiB per tx — fine for devnet (hash-based mainnets live at ~50 KB).
//! Production path: same ratchet discipline, XMSS/LMS keys (constant-size, multi-use).
//!
//! Bit convention: message bit i (0-based) = bit (7 - i%8) of msg32[i/8] — big-endian
//! within bytes. Frozen; do not change without a domain-tag bump.

use crate::hash::{shake256_32, DOM_LAMPORT_LEAF, DOM_LAMPORT_PK, DOM_LAMPORT_SK};
use crate::CryptoError;

pub const CHUNK: usize = 32;
pub const N_CHUNKS_SK: usize = 512; // 256 message bits × 2
pub const SK_LEN: usize = N_CHUNKS_SK * CHUNK; // 16384
pub const PK_LEN: usize = N_CHUNKS_SK * CHUNK; // 16384
pub const SIG_LEN: usize = 256 * CHUNK; // 8192

/// Secret key: 512 secret chunks (flat).
pub struct LamportSk {
    bytes: Vec<u8>,
}

/// Deterministic keygen from (seed, index). Index = the account nonce this key will
/// authorize — deriving the whole ratchet chain from one seed.
pub fn keygen(seed: &[u8], index: u64) -> (LamportSk, Vec<u8>) {
    let mut sk = Vec::with_capacity(SK_LEN);
    let mut pk = Vec::with_capacity(PK_LEN);
    for j in 0..N_CHUNKS_SK as u32 {
        let s = shake256_32(DOM_LAMPORT_SK, &[seed, &index.to_le_bytes(), &j.to_le_bytes()]);
        pk.extend_from_slice(&shake256_32(DOM_LAMPORT_LEAF, &[&s]));
        sk.extend_from_slice(&s);
    }
    (LamportSk { bytes: sk }, pk)
}

/// 32-byte commitment to a public key — what lives in account state.
pub fn pk_commit(pk: &[u8]) -> [u8; 32] {
    shake256_32(DOM_LAMPORT_PK, &[pk])
}

/// Sign a 32-byte message digest. Reveals one secret chunk per message bit.
pub fn sign(sk: &LamportSk, msg32: &[u8; 32]) -> Vec<u8> {
    debug_assert_eq!(sk.bytes.len(), SK_LEN);
    let mut sig = Vec::with_capacity(SIG_LEN);
    for i in 0..256usize {
        let bit = (msg32[i / 8] >> (7 - (i % 8))) & 1;
        let j = 2 * i + bit as usize;
        sig.extend_from_slice(&sk.bytes[j * CHUNK..(j + 1) * CHUNK]);
    }
    sig
}

/// Verify: each revealed chunk must hash to the pubkey chunk selected by the bit.
pub fn verify(pk: &[u8], msg32: &[u8; 32], sig: &[u8]) -> Result<(), CryptoError> {
    if pk.len() != PK_LEN || sig.len() != SIG_LEN {
        return Err(CryptoError::VerifyFailed);
    }
    for i in 0..256usize {
        let bit = (msg32[i / 8] >> (7 - (i % 8))) & 1;
        let j = 2 * i + bit as usize;
        let h = shake256_32(DOM_LAMPORT_LEAF, &[&sig[i * CHUNK..(i + 1) * CHUNK]]);
        if h[..] != pk[j * CHUNK..(j + 1) * CHUNK] {
            return Err(CryptoError::VerifyFailed);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn roundtrip() {
        let (sk, pk) = keygen(b"seed", 0);
        let sig = sign(&sk, &msg(0x5a));
        assert!(verify(&pk, &msg(0x5a), &sig).is_ok());
    }

    #[test]
    fn wrong_message_rejected() {
        let (sk, pk) = keygen(b"seed", 0);
        let sig = sign(&sk, &msg(0x5a));
        assert!(verify(&pk, &msg(0x5b), &sig).is_err());
    }

    #[test]
    fn tampered_sig_rejected() {
        let (sk, pk) = keygen(b"seed", 0);
        let mut sig = sign(&sk, &msg(1));
        sig[100] ^= 1;
        assert!(verify(&pk, &msg(1), &sig).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let (sk, _) = keygen(b"seed", 0);
        let (_, pk2) = keygen(b"seed", 1); // different index = different key
        let sig = sign(&sk, &msg(1));
        assert!(verify(&pk2, &msg(1), &sig).is_err());
    }

    #[test]
    fn commitment_binds_key() {
        let (_, pk_a) = keygen(b"a", 0);
        let (_, pk_b) = keygen(b"b", 0);
        assert_ne!(pk_commit(&pk_a), pk_commit(&pk_b));
        assert_eq!(pk_commit(&pk_a), pk_commit(&pk_a));
    }

    #[test]
    fn keygen_is_deterministic() {
        let (_, pk1) = keygen(b"seed", 7);
        let (_, pk2) = keygen(b"seed", 7);
        assert_eq!(pk1, pk2);
    }
}
