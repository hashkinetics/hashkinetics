//! agg — the aggregation tier's shared digest (P2.3/WS3).
//!
//! ONE STARK per block: the aggregator guest verifies N compressed spend/mint proofs
//! in-zkVM (`verify_sp1_proof`) and commits a single digest binding, for each proof,
//! (statement KIND, verifying key, exact public bytes). The node re-derives the same
//! digest from the CHAIN-DERIVED expected publics of the block's proof-less pool txs and
//! verifies the aggregate once. This module is that digest's single source of truth —
//! guest, prover service, and node all compile it, so they can never disagree.
//!
//! Doctrine: the aggregate itself stays a RAW COMPRESSED STARK (finding F1 — the
//! pairing-based plonk/groth16 wraps in upstream examples are banned here).

use alloc::vec::Vec;

use crate::{sha, Hash};

/// Statement-kind tags bound into every leaf (a spend proof can never stand in for a
/// mint proof or vice versa).
pub const KIND_SPEND: u8 = 1;
pub const KIND_MINT: u8 = 2;

/// SP1 vkey words → bytes (LE), matching the upstream aggregation convention.
pub fn vkey_bytes(words: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// One aggregated item: H(kind ‖ vkey_le ‖ len_be(publics) ‖ publics).
/// `publics` = the proof's committed public bytes (bincode of SpendPublic/MintPublic).
pub fn agg_leaf(kind: u8, vkey: &[u32; 8], publics: &[u8]) -> Hash {
    sha(&[
        &[kind],
        &vkey_bytes(vkey),
        &(publics.len() as u32).to_be_bytes(),
        publics,
    ])
}

/// The aggregate's committed public output: H(count_be ‖ leaf_0 ‖ … ‖ leaf_{n-1}).
/// ORDER-SENSITIVE — the node builds its expected list in transaction order.
pub fn agg_digest(leaves: &[Hash]) -> Hash {
    let count = (leaves.len() as u32).to_be_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(leaves.len() + 1);
    parts.push(&count);
    for l in leaves {
        parts.push(l);
    }
    sha(&parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_order_and_kind_sensitive() {
        let vk = [7u32; 8];
        let a = agg_leaf(KIND_SPEND, &vk, b"publics-a");
        let b = agg_leaf(KIND_MINT, &vk, b"publics-a");
        assert_ne!(a, b, "kind is bound");
        let c = agg_leaf(KIND_SPEND, &[8u32; 8], b"publics-a");
        assert_ne!(a, c, "vkey is bound");
        assert_ne!(agg_digest(&[a, b]), agg_digest(&[b, a]), "order is bound");
        assert_ne!(agg_digest(&[a]), agg_digest(&[a, a]), "count is bound");
    }
}
