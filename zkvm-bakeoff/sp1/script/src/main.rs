//! SP1 host bench: build a witness, prove the spend circuit, verify, and report against G2.
//! Uses a **compressed** proof (recursive STARK, ~hundreds of KB) — the deployable size, not
//! the multi-MB core proof. API per SP1 v6 (matches vendor/external/sp1/examples).

use std::time::Instant;

use hk_spend_circuit::build_valid_spend;
use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

/// ELF of the guest, produced by `build.rs`. Name = the guest crate's package name.
const ELF: Elf = include_elf!("hk-spend-program");

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let witness = build_valid_spend(7);
    let mut stdin = SP1Stdin::new();
    stdin.write(&witness);

    let client = ProverClient::from_env().await;

    // First: execute without proving — reports the cycle count (the workload's true size).
    let (_, report) = client.execute(ELF, stdin.clone()).await.expect("execution failed");
    println!("cycles: {}", report.total_instruction_count());

    let pk = client.setup(ELF).await.expect("setup failed");

    let t = Instant::now();
    let proof = client.prove(&pk, stdin).compressed().await.expect("proving failed");
    let prove_ms = t.elapsed().as_millis();

    let t2 = Instant::now();
    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    let verify_ms = t2.elapsed().as_millis();

    let size = bincode::serialize(&proof).map(|b| b.len()).unwrap_or(0);
    report_g2("SP1", prove_ms, verify_ms, size);
}

fn report_g2(name: &str, prove_ms: u128, verify_ms: u128, size_bytes: usize) {
    let kb = size_bytes / 1024;
    let g2 = |ok: bool| if ok { "PASS" } else { "FAIL" };
    println!(
        "\n{name:<6} prove={prove_ms}ms  verify={verify_ms}ms  size={kb}KB   \
         [G2: {} prove(<2000ms), {} verify(<10ms), {} size(<300KB)]",
        g2(prove_ms < 2000),
        g2(verify_ms < 10),
        g2(kb < 300),
    );
}
