//! SP1 guest: the MINT statement (shield, t→z). Reads the note being shielded, commits
//! (commitment, value). The chain matches both against the transaction's public fields —
//! the proof guarantees the commitment opens to exactly that value (the inflation guard)
//! while owner/rho/rcm never leave the wallet.
#![no_main]
sp1_zkvm::entrypoint!(main);

use hk_spend_circuit::{run_mint, MintWitness};

pub fn main() {
    let w = sp1_zkvm::io::read::<MintWitness>();
    let public = run_mint(&w);
    sp1_zkvm::io::commit(&public);
}
