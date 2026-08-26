//! SP1 guest: read the spend witness, run the shared circuit, commit the public outputs.
//! The proof attests that a valid shielded spend exists for these public outputs.
#![no_main]
sp1_zkvm::entrypoint!(main);

use hk_spend_circuit::{run, SpendWitness};

pub fn main() {
    let w = sp1_zkvm::io::read::<SpendWitness>();
    // A proof only exists when every check passes; an invalid witness panics (no proof).
    let public = run(&w).expect("invalid spend witness");
    sp1_zkvm::io::commit(&public);
}
