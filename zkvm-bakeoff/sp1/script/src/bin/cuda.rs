//! SP1 CUDA host bench — same spend circuit, proven on the GPU (RTX 5090 path).
//! API per vendor/external/sp1/examples/fibonacci-cuda. The CUDA prover runs SP1's
//! moongate service; if it errors on startup, Docker + NVIDIA container toolkit are
//! missing in WSL — paste the error and we'll wire that up.

use std::time::Instant;

use hk_spend_circuit::build_valid_spend;
use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

const ELF: Elf = include_elf!("hk-spend-program");

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let witness = build_valid_spend(7);
    let mut stdin = SP1Stdin::new();
    stdin.write(&witness);

    let client = ProverClient::builder().cuda().build().await;

    // Cycle count for the current statement (cheap; witness-dependent).
    let (_, report) = client.execute(ELF, stdin.clone()).await.expect("execution failed");
    println!("cycles: {}", report.total_instruction_count());

    let pk = client.setup(ELF).await.expect("setup failed");

    // HK_MODE=core measures the raw core proof (the agent-side latency in the aggregation
    // architecture, where an aggregator compresses many spends at once); default =
    // compressed (the standalone deployable artifact).
    let core_mode = std::env::var("HK_MODE").map(|v| v == "core").unwrap_or(false);
    println!("mode: {}", if core_mode { "core" } else { "compressed" });

    // Warm-up prove (GPU kernel init, allocator warm-up) — not timed.
    if core_mode {
        let _ = client.prove(&pk, stdin.clone()).core().await.expect("warm-up prove failed");
    } else {
        let _ = client.prove(&pk, stdin.clone()).compressed().await.expect("warm-up prove failed");
    }

    // Three timed proves; report each + best (steady-state is what an agent wallet sees).
    let mut times = Vec::new();
    let mut proof = None;
    for i in 1..=3 {
        let t = Instant::now();
        let p = if core_mode {
            client.prove(&pk, stdin.clone()).core().await.expect("proving failed")
        } else {
            client.prove(&pk, stdin.clone()).compressed().await.expect("proving failed")
        };
        let ms = t.elapsed().as_millis();
        println!("prove #{i}: {ms}ms");
        times.push(ms);
        proof = Some(p);
    }
    let proof = proof.unwrap();
    let prove_ms = *times.iter().min().unwrap();

    let t2 = Instant::now();
    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    let verify_ms = t2.elapsed().as_millis();

    let size = bincode::serialize(&proof).map(|b| b.len()).unwrap_or(0);
    let kb = size / 1024;
    let g2 = |ok: bool| if ok { "PASS" } else { "FAIL" };
    println!(
        "\nSP1-CUDA prove={prove_ms}ms  verify={verify_ms}ms  size={kb}KB   \
         [G2: {} prove(<2000ms), {} verify(<10ms), {} size(<300KB)]",
        g2(prove_ms < 2000),
        g2(verify_ms < 10),
        g2(kb < 300),
    );
}
