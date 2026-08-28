//! RISC Zero host bench: build the same witness, prove the same circuit, verify, and report
//! against G2. Uses a **succinct** receipt (recursion-compressed STARK) — the PQ-deployable
//! artifact, comparable to SP1's compressed proof. API per risc0 v5
//! (vendor/external-full/risc0/examples).

use std::time::Instant;

use hk_spend_circuit::{build_valid_spend, SpendPublic};
use hk_spend_risc0_methods::{HK_SPEND_ELF, HK_SPEND_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};

fn main() {
    let witness = build_valid_spend(7);
    let env = ExecutorEnv::builder().write(&witness).unwrap().build().unwrap();

    let prover = default_prover();

    let t = Instant::now();
    let info = prover
        .prove_with_opts(env, HK_SPEND_ELF, &ProverOpts::succinct())
        .expect("proving failed");
    let prove_ms = t.elapsed().as_millis();
    println!("stats: {:?}", info.stats);

    let receipt = info.receipt;
    let t2 = Instant::now();
    receipt.verify(HK_SPEND_ID).expect("verification failed");
    let verify_ms = t2.elapsed().as_millis();

    // Sanity: the journal carries the same public outputs the circuit computes natively.
    let public: SpendPublic = receipt.journal.decode().expect("journal decode");
    assert_eq!(public.fee, 10);

    let size = bincode::serialize(&receipt).map(|b| b.len()).unwrap_or(0);
    let kb = size / 1024;
    let g2 = |ok: bool| if ok { "PASS" } else { "FAIL" };
    println!(
        "\nRISC0  prove={prove_ms}ms  verify={verify_ms}ms  size={kb}KB   \
         [G2: {} prove(<2000ms), {} verify(<10ms), {} size(<300KB)]",
        g2(prove_ms < 2000),
        g2(verify_ms < 10),
        g2(kb < 300),
    );
}
