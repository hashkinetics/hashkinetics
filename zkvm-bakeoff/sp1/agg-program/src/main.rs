//! SP1 guest: the AGGREGATOR (P2.3). Verifies N compressed spend/mint proofs inside the
//! zkVM (recursive verification — the proofs are witnessed by the prover, not read here)
//! and commits ONE digest binding every (kind, vkey, public bytes) triple in order.
//! A block then carries this single aggregate; validators verify once.
#![no_main]
sp1_zkvm::entrypoint!(main);

use hk_spend_circuit::agg::{agg_digest, agg_leaf};
use sha2::{Digest, Sha256};

pub fn main() {
    let kinds = sp1_zkvm::io::read::<Vec<u8>>();
    let vkeys = sp1_zkvm::io::read::<Vec<[u32; 8]>>();
    let publics = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    assert_eq!(kinds.len(), vkeys.len());
    assert_eq!(kinds.len(), publics.len());
    assert!(!kinds.is_empty());

    let mut leaves = Vec::with_capacity(kinds.len());
    for i in 0..kinds.len() {
        // SP1's committed-values digest convention: sha256 of the public bytes.
        let pv_digest = Sha256::digest(&publics[i]);
        sp1_zkvm::lib::verify::verify_sp1_proof(&vkeys[i], &pv_digest.into());
        leaves.push(agg_leaf(kinds[i], &vkeys[i], &publics[i]));
    }
    sp1_zkvm::io::commit_slice(&agg_digest(&leaves));
}
