//! RISC Zero guest: read the spend witness, run the shared circuit, commit the public outputs.
//! Identical statement to the SP1 guest — same `hk_spend_circuit::run`, same witness.
#![no_main]

use hk_spend_circuit::{run, SpendWitness};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let w: SpendWitness = env::read();
    // A proof only exists when every check passes; an invalid witness panics (no receipt).
    let public = run(&w).expect("invalid spend witness");
    env::commit(&public);
}
