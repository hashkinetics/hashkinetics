//! Domain-separated SHAKE-256 (plan §3.1: SHAKE outside circuits, Poseidon2/RPO inside).
//! Every hash in the protocol carries an explicit domain tag — frozen strings below.
//! Convention: versioned, rename-proof domain tags ("hk/v1/...").

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

// Frozen v1 domain tags. NEVER reuse a tag for a second meaning; add new tags instead.
pub const DOM_PAYWORD_SEED: &str = "hk/v1/payword-seed";
pub const DOM_PAYWORD_LINK: &str = "hk/v1/payword-link";
pub const DOM_ACCOUNT_ID: &str = "hk/v1/account-id";
pub const DOM_MANDATE_ID: &str = "hk/v1/mandate-id";
pub const DOM_CHANNEL_ID: &str = "hk/v1/channel-id";
pub const DOM_CERT_MSG: &str = "hk/v1/delegation-cert";
pub const DOM_TX_MSG: &str = "hk/v1/tx";
pub const DOM_LAMPORT_SK: &str = "hk/v1/lamport-sk";
pub const DOM_LAMPORT_LEAF: &str = "hk/v1/lamport-leaf";
pub const DOM_LAMPORT_PK: &str = "hk/v1/lamport-pk-commit";
pub const DOM_STATE_COMMIT: &str = "hk/v1/state-commit";
// P2.1 (WS4) — note confidentiality:
pub const DOM_MLKEM_SEED: &str = "hk/v1/mlkem-note-seed";
pub const DOM_NOTE_KEY: &str = "hk/v1/note-key";
pub const DOM_NOTE_ENC: &str = "hk/v1/note-enc";
pub const DOM_NOTE_MAC: &str = "hk/v1/note-mac";
// P2.3 (WS3) — aggregation coverage keys:
pub const DOM_AGG_COVER: &str = "hk/v1/agg-cover";
// P2.5 (WS8) — genesis-pinned verifying keys:
pub const DOM_VK_PIN: &str = "hk/v1/vk-pin";

/// SHAKE-256 with domain separation → 32 bytes.
pub fn shake256_32(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Shake256::default();
    h.update(domain.as_bytes());
    h.update(&[0x00]); // tag/data separator
    for p in parts {
        // length-prefix each part (u64 LE) — no ambiguity between ["ab","c"] and ["a","bc"]
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

/// Arbitrary-length XOF output (seed derivation).
pub fn shake256_n(domain: &str, parts: &[&[u8]], n: usize) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(domain.as_bytes());
    h.update(&[0x00]);
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    let mut out = vec![0u8; n];
    h.finalize_xof().read(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separation_matters() {
        let a = shake256_32(DOM_PAYWORD_SEED, &[b"x"]);
        let b = shake256_32(DOM_PAYWORD_LINK, &[b"x"]);
        assert_ne!(a, b);
    }

    #[test]
    fn length_prefixing_prevents_concat_ambiguity() {
        let a = shake256_32(DOM_TX_MSG, &[b"ab", b"c"]);
        let b = shake256_32(DOM_TX_MSG, &[b"a", b"bc"]);
        assert_ne!(a, b);
    }

    #[test]
    fn deterministic() {
        assert_eq!(shake256_32(DOM_TX_MSG, &[b"hello"]), shake256_32(DOM_TX_MSG, &[b"hello"]));
    }
}
