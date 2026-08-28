//! OpenVM guest: the same spend statement, proven under OpenVM's modular VM with its
//! SHA-256 extension (`openvm.toml` enables it; the circuit's `openvm-accel` feature routes
//! hashing through openvm-sha2).
//!
//! ⚠ Benchmark note: this variant EMBEDS the witness (`build_valid_spend(7)`) instead of
//! reading it from the host, so the cycle count includes witness construction (~512 extra
//! hashes for the Lamport keypair). That overstates OpenVM's workload relative to SP1/RISC0;
//! it is the zero-input-plumbing way to validate the pipeline first. A `--input`-fed variant
//! is the follow-up for exact apples-to-apples.

#![cfg_attr(all(target_os = "zkvm", not(feature = "std")), no_main)]
#![cfg_attr(all(target_os = "zkvm", not(feature = "std")), no_std)]

extern crate alloc;

use hk_spend_circuit::{build_valid_spend, run};

openvm::entry!(main);

pub fn main() {
    let w = build_valid_spend(7);
    // A proof only exists when every check passes; an invalid witness panics (no proof).
    let public = run(&w).expect("invalid spend witness");
    // Commit the nullifier (32 bytes) as the public value — it binds the whole statement
    // (computed from the spend key + note under a valid Merkle root and signature).
    openvm::io::reveal_bytes32(public.nullifier);
}
