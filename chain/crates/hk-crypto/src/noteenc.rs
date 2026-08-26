//! noteenc — SHAKE-256 authenticated encryption for shielded-note ciphertexts (P2.1/WS4).
//!
//! Encrypt-then-MAC, both primitives domain-separated SHAKE-256 (pure hash — the doctrine
//! holds even here; no AES/ChaCha dependency):
//!   keystream = SHAKE-256(DOM_NOTE_ENC ‖ key ‖ nonce)   (XOF, XORed over the plaintext)
//!   tag       = SHAKE-256₃₂(DOM_NOTE_MAC ‖ key ‖ nonce ‖ ciphertext)
//!
//! `key` is derived from the ML-KEM shared secret (see `mlkem::note_key`); `nonce` must be
//! unique per (key, message) — the wallet uses the note COMMITMENT, unique by construction.
//! One-time keys + unique nonces ⇒ the XOF stream is never reused.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::hash::{shake256_32, DOM_NOTE_ENC, DOM_NOTE_MAC};

pub const TAG_LEN: usize = 32;

/// Encrypt + authenticate. Output = ciphertext ‖ 32-byte tag.
pub fn seal(key: &[u8; 32], nonce: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let mut out = xor_stream(key, nonce, plaintext);
    let tag = shake256_32(DOM_NOTE_MAC, &[key, nonce, &out]);
    out.extend_from_slice(&tag);
    out
}

/// Verify + decrypt. `None` on any tampering or a wrong key (constant-time tag check) —
/// this is exactly the trial-decapsulation "not mine" signal the scanner relies on.
pub fn open(key: &[u8; 32], nonce: &[u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < TAG_LEN {
        return None;
    }
    let (ct, tag) = sealed.split_at(sealed.len() - TAG_LEN);
    let expect = shake256_32(DOM_NOTE_MAC, &[key, nonce, ct]);
    let mut diff = 0u8;
    for (a, b) in expect.iter().zip(tag) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return None;
    }
    Some(xor_stream(key, nonce, ct))
}

fn xor_stream(key: &[u8; 32], nonce: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(DOM_NOTE_ENC.as_bytes());
    h.update(&[0u8]); // domain terminator, mirrors hash.rs framing
    h.update(key);
    h.update(nonce);
    let mut reader = h.finalize_xof();
    let mut ks = vec![0u8; data.len()];
    reader.read(&mut ks);
    let mut out = data.to_vec();
    for (o, k) in out.iter_mut().zip(ks) {
        *o ^= k;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [7u8; 32];
        let nonce = [9u8; 32];
        let pt = b"value=5000000 rho=... rcm=... memo=coffee";
        let sealed = seal(&key, &nonce, pt);
        assert_eq!(open(&key, &nonce, &sealed).as_deref(), Some(pt.as_slice()));
    }

    #[test]
    fn tamper_and_wrong_key_fail() {
        let key = [7u8; 32];
        let nonce = [9u8; 32];
        let mut sealed = seal(&key, &nonce, b"secret note");
        // flipped ciphertext byte
        sealed[0] ^= 1;
        assert!(open(&key, &nonce, &sealed).is_none());
        sealed[0] ^= 1;
        // flipped tag byte
        let n = sealed.len() - 1;
        sealed[n] ^= 1;
        assert!(open(&key, &nonce, &sealed).is_none());
        sealed[n] ^= 1;
        // wrong key — the scanner's "not mine"
        assert!(open(&[8u8; 32], &nonce, &sealed).is_none());
        // right key still works
        assert!(open(&key, &nonce, &sealed).is_some());
    }

    #[test]
    fn distinct_nonces_distinct_streams() {
        let key = [1u8; 32];
        let a = seal(&key, &[2u8; 32], b"same plaintext");
        let b = seal(&key, &[3u8; 32], b"same plaintext");
        assert_ne!(a, b);
    }
}
