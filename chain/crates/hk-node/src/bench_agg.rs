//! C1p2.a — the aggregation scaling curve: measure T_agg(N) = a + b·N.
//!
//! THE unknown of the throughput program (C-PROGRAM-PLAN.md): `a` (fixed fold
//! overhead) is known from N=3 ≈ 2.6 s; `b` (marginal cost per folded proof) sizes
//! the proving farm and prices the aggregator market — farm GPUs ≈ b × proofs/s.
//!
//! Design:
//!   - NO devnet needed. Notes are minted LOCALLY (commitments from `build_mint`),
//!     the commitment tree is assembled in-process, and `build_spend` produces real
//!     witnesses against it. Only the PROVER is contacted.
//!   - Compressed spend proofs are generated ONCE for max(N) and reused for every
//!     aggregation point — the expensive phase runs a single time.
//!   - Each aggregation point folds the first N proofs and records the guest's
//!     reported prove_ms + aggregate size (expected: constant ~1.24 MB at every N).
//!
//! Run (prover must be up; GPU-hours for N=256):
//!   hk-node agg-bench http://127.0.0.1:9911 --n 4,10,50,100,256
//!
//! Output ends with a paste-ready block for docs/CAPACITY-SHEET.md §d.

use serde_json::json;
use std::time::Instant;

use hk_wallet::{build_mint, build_spend, WalletKeys};

use crate::demo::rpc;
use crate::demo_shielded::{r32, take_proof};

pub fn run(prover: &str, ns: Vec<usize>) -> eyre::Result<()> {
    let mut ns = ns;
    ns.sort_unstable();
    ns.dedup();
    let maxn = *ns.last().ok_or_else(|| eyre::eyre!("no N values"))?;
    if maxn > 1000 {
        eyre::bail!("N > 1000 exceeds the bench wallet's one-time-key tree (depth 10)");
    }

    println!("\n=== C1p2.a — AGGREGATION SCALING CURVE ===");
    println!("    prover: {prover}   points: {ns:?}   (proof set generated once at N={maxn})\n");

    if rpc(prover, "health", json!({})).get("result").is_none() {
        eyre::bail!("hk-prove not reachable at {prover}");
    }
    // Fresh proof store on the server — this bench aggregates BY ID (no re-upload).
    if rpc(prover, "store_clear", json!({})).get("result").is_none() {
        eyre::bail!("prover lacks the proof store (rebuild `serve` — C1p2.a version required)");
    }

    // ---- local pool: maxn notes, no chain --------------------------------------------
    // Capacity 2^10 = 1024 one-time spend keys (the default h=6 caps at 64 — the bench
    // signs one witness per note, so it needs an index per N).
    let alice = WalletKeys::with_capacity(b"agg-bench-master", 10);
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(maxn);
    let mut notes = Vec::with_capacity(maxn);
    for i in 0..maxn {
        let note = alice.self_note(1_000_000, i as u64);
        let (_mw, mp) = build_mint(&note);
        leaves.push(mp.commitment);
        notes.push(note);
    }
    println!("[1] local pool built: {maxn} commitments (no devnet involved).\n");

    // ---- the expensive phase: maxn compressed spend proofs ---------------------------
    println!("[2] proving {maxn} shielded spends in COMPRESSED mode (the GPU phase)...");
    let mut items = Vec::with_capacity(maxn);
    let mut prove_ms_total: u64 = 0;
    let t0 = Instant::now();
    for (i, note) in notes.into_iter().enumerate() {
        let out = alice.self_note(note.value, 100_000 + i as u64);
        let dummy = hk_spend_circuit::Note {
            value: 0,
            owner: [0; 32],
            rho: r32(7, i as u8),
            rcm: r32(9, i as u8),
        };
        let plan = build_spend(&leaves, i as u64, note, &alice, i as u32, out, dummy, 0, [0; 32])
            .map_err(|e| eyre::eyre!(e))?;
        let pr = rpc(
            prover,
            "prove_spend",
            json!({"witness": serde_json::to_value(&plan.witness)?, "mode": "compressed"}),
        );
        let (_proof, ms) = take_proof(&pr)?;
        let id = pr
            .get("result")
            .and_then(|r| r.get("id"))
            .and_then(|v| v.as_i64())
            .filter(|v| *v >= 0)
            .ok_or_else(|| eyre::eyre!("prover returned no store id (rebuild serve)"))?;
        prove_ms_total += ms;
        items.push(id);
        if (i + 1) % 10 == 0 || i + 1 == maxn || i == 0 {
            let done = (i + 1) as f64;
            let avg = t0.elapsed().as_secs_f64() / done;
            let eta = avg * (maxn as f64 - done);
            println!(
                "    proof {}/{maxn} — {ms} ms (avg {:.1}s/proof, ETA {:.0} min)",
                i + 1,
                avg,
                eta / 60.0
            );
        }
    }
    println!(
        "    ✓ {maxn} compressed proofs in {:.1} min (prover-reported total {:.1} min).\n",
        t0.elapsed().as_secs_f64() / 60.0,
        prove_ms_total as f64 / 60_000.0
    );

    // ---- the curve: fold first N for each point --------------------------------------
    println!("[3] folding — one aggregate per point:");
    let mut points: Vec<(usize, u64, usize)> = Vec::new(); // (N, prove_ms, agg_bytes)
    for &n in &ns {
        let ar = rpc(prover, "aggregate", json!({"ids": items[..n].to_vec()}));
        if let Some(e) = ar.get("error") {
            eyre::bail!("aggregate(N={n}) failed: {e}");
        }
        let r = ar.get("result").unwrap();
        let ms = r.get("prove_ms").and_then(|m| m.as_u64()).unwrap_or(0);
        let bytes = r.get("agg_proof").and_then(|p| p.as_str()).map(|s| s.len() / 2).unwrap_or(0);
        println!("    N={n:>4}  T_agg = {:>8.2} s   size = {} KB", ms as f64 / 1000.0, bytes / 1024);
        points.push((n, ms, bytes));
    }

    // ---- least-squares fit T = a + b·N -----------------------------------------------
    let m = points.len() as f64;
    let sx: f64 = points.iter().map(|p| p.0 as f64).sum();
    let sy: f64 = points.iter().map(|p| p.1 as f64 / 1000.0).sum();
    let sxx: f64 = points.iter().map(|p| (p.0 as f64).powi(2)).sum();
    let sxy: f64 = points.iter().map(|p| p.0 as f64 * (p.1 as f64 / 1000.0)).sum();
    let b = (m * sxy - sx * sy) / (m * sxx - sx * sx);
    let a = (sy - b * sx) / m;

    println!("\n=== THE CURVE ===");
    println!("  T_agg(N) ≈ {a:.2} s + {b:.4} s/proof · N");
    for (n, ms, _) in &points {
        let fit = a + b * *n as f64;
        println!(
            "    N={n:>4}  measured {:>8.2} s   fit {:>8.2} s   residual {:>+6.2} s",
            *ms as f64 / 1000.0,
            fit,
            *ms as f64 / 1000.0 - fit
        );
    }
    println!("\n  Farm sizing (GPUs ≈ b × R for R shielded proofs/s, this GPU class):");
    for r in [64u32, 256, 1024] {
        println!("    R = {r:>4}/s  →  ~{:.0} GPUs", (b * r as f64).ceil());
    }
    println!("\n=== PASTE INTO docs/CAPACITY-SHEET.md §d ===");
    for (n, ms, bytes) in &points {
        println!("| {n} | {ms} | {} KB | <DATE> · <GPU> |", bytes / 1024);
    }
    println!("| fit | T_agg(N) ≈ {a:.2} s + {b:.4} s·N | — | least-squares over {} points |", points.len());
    println!("\n(quote rule: this is a single-GPU measured curve — label it with the GPU model.)");
    Ok(())
}
