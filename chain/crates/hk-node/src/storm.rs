//! storm — C1 load harness (P3.1 / WS-G; docs/CAPACITY-SHEET.md is the output form).
//!
//! Floods the chain with transparent transfers from the five genesis accounts (one
//! thread per sender — per-sender nonce ordering is preserved by construction) while
//! sampling real wall-clock height progression, then reads the block log back through
//! the explorer RPC and prints the capacity numbers that matter:
//! sustained included-tx/s · block fill · real block interval · admission behavior.
//!
//! Run:  hk-node storm <RPC> [RATE_TX_S] [DURATION_S]
//!       RATE_TX_S 0 (default) = flood as fast as signing+submission allows.
//!
//! Scope v1 (honest): transparent txs only — this measures the STATE-APPLY and
//! consensus/gossip path (C1 items a/b/e). The shielded/aggregation scaling curve
//! (C1 item d) needs the GPU prover in the loop and lands as phase 2.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;

use hk_primitives::Amount;
use hk_state::tx::Tx;

use crate::demo::{account_nonce, balance, chain_height, rpc, usd, wait, Wallet};

const SENDERS: [&str; 5] = ["org", "agent-a", "agent-b", "agent-c", "merchant"];
const M: Amount = 1_000_000;

fn submit_quiet(base: &str, tx: &hk_state::tx::SignedTx) -> bool {
    rpc(base, "hk_submitTx", json!({ "tx": serde_json::to_value(tx).unwrap() }))
        .get("result")
        .and_then(|r| r.get("accepted"))
        .and_then(|a| a.as_bool())
        .unwrap_or(false)
}

fn mempool_count(base: &str) -> u64 {
    rpc(base, "hk_getMempool", json!({}))
        .get("result")
        .and_then(|r| r.get("count"))
        .and_then(|c| c.as_u64())
        .unwrap_or(0)
}

/// Sum included txs + per-block fill over (from_h, to_h] via the explorer RPC.
fn window_stats(base: &str, from_h: u64, to_h: u64) -> (u64, u64, u64) {
    let (mut txs, mut blocks, mut max_fill) = (0u64, 0u64, 0u64);
    let mut before = to_h + 1;
    while before > from_h + 1 {
        let v = rpc(base, "hk_getBlocks", json!({"before": before, "limit": 50}));
        let Some(arr) = v.get("result").and_then(|r| r.get("blocks")).and_then(|b| b.as_array())
        else { break };
        if arr.is_empty() { break }
        let mut lowest = before;
        for b in arr {
            let h = b.get("height").and_then(|x| x.as_u64()).unwrap_or(0);
            lowest = lowest.min(h);
            if h <= from_h { continue }
            let n = b.get("tx_count").and_then(|x| x.as_u64()).unwrap_or(0);
            txs += n;
            blocks += 1;
            max_fill = max_fill.max(n);
        }
        if lowest >= before { break }
        before = lowest;
    }
    (txs, blocks, max_fill)
}

/// Swap the port at the end of an http base URL ("http://host:26000" → ":26001").
fn with_port(base: &str, port: u64) -> String {
    match base.rsplit_once(':') {
        Some((head, tail)) if tail.chars().all(|c| c.is_ascii_digit()) => format!("{head}:{port}"),
        _ => base.to_string(),
    }
}

fn base_port(base: &str) -> u64 {
    base.rsplit_once(':')
        .and_then(|(_, t)| t.parse().ok())
        .unwrap_or(26000)
}

pub fn run(base: &str, rate: u64, duration_s: u64, nodes: u64) -> eyre::Result<()> {
    println!("\n=== HashKinetics C1 STORM — transparent load harness ===");
    println!("    target: {base} (+{} sibling RPCs) · rate: {} · duration: {duration_s}s",
        nodes.saturating_sub(1),
        if rate == 0 { "MAX".into() } else { format!("{rate} tx/s") });
    if nodes <= 1 {
        println!("    SINGLE-NODE MODE — every sender submits to {base} only. Pre-C2.3 this");
        println!("    measured 27 tx/s (C1 finding #1: no tx gossip; only node0's proposals had");
        println!("    work). With gossip live, this run should match the home-node baseline.\n");
    } else {
        println!("    Home-node-per-sender across {nodes} RPCs; C2.3 gossip additionally pushes");
        println!("    every admission to all peers, so every proposer sees every tx.\n");
    }

    if !wait("node RPC reachable", || chain_height(base) >= 1) {
        eyre::bail!("node not reachable at {base}");
    }

    // ---- senders: sync nonces; fund the non-org accounts if they're dry ----
    let mut senders: Vec<Wallet> = SENDERS.iter().map(|n| Wallet::new(n)).collect();
    for w in senders.iter_mut() {
        match account_nonce(base, &w.id) {
            Some(n) => w.next_nonce = n,
            None => eyre::bail!("genesis account missing on this chain — use a devnet/testnet genesis"),
        }
    }
    let org_bal = balance(base, &senders[0].id);
    if org_bal < 5 * M {
        eyre::bail!("org has {} micro — storm wants a reasonably funded devnet (fresh, or post-demo)", org_bal);
    }
    let targets: Vec<_> = senders.iter().map(|w| w.id).collect();
    let mut funded = 0;
    for i in 1..senders.len() {
        if balance(base, &targets[i]) < M / 2 {
            let t = targets[i];
            let tx = senders[0].sign(Tx::Transfer { to: t, asset: usd(), amount: M });
            submit_quiet(base, &tx);
            funded += 1;
        }
    }
    if funded > 0 {
        println!("[setup] funding {funded} sender(s) with $1 each…");
        let need: Vec<_> = targets[1..].to_vec();
        wait("senders funded", || need.iter().all(|t| balance(base, t) >= M / 2));
    }
    // Re-sync org's nonce after funding txs committed.
    if let Some(n) = account_nonce(base, &senders[0].id) {
        senders[0].next_nonce = n;
    }

    // ---- the storm: one thread per sender (nonce order preserved per sender) ----
    let submitted = Arc::new(AtomicU64::new(0));
    let rejected = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let start_h = chain_height(base);
    let t0 = Instant::now();
    let per_thread_gap = if rate == 0 { None } else {
        Some(Duration::from_secs_f64(SENDERS.len() as f64 / rate as f64))
    };

    let port0 = base_port(base);
    println!("[storm] flooding from {} senders for {duration_s}s (start height {start_h})…", SENDERS.len());
    std::thread::scope(|s| {
        for (idx, mut w) in senders.drain(..).enumerate() {
            // Home node per sender: nonce ordering is preserved inside one mempool,
            // and every proposer in the rotation has transactions to include.
            let home = with_port(base, port0 + (idx as u64 % nodes.max(1)));
            let (base, submitted, rejected, stop) =
                (home, submitted.clone(), rejected.clone(), stop.clone());
            let to = targets[(idx + 1) % targets.len()]; // ring: everyone pays the next account
            s.spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let t_iter = Instant::now();
                    let tx = w.sign(Tx::Transfer { to, asset: usd(), amount: 1 });
                    if submit_quiet(&base, &tx) {
                        submitted.fetch_add(1, Ordering::Relaxed);
                    } else {
                        rejected.fetch_add(1, Ordering::Relaxed);
                        w.rollback(); // never leave a local nonce gap on failed admission
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    if let Some(gap) = per_thread_gap {
                        if let Some(rem) = gap.checked_sub(t_iter.elapsed()) {
                            std::thread::sleep(rem);
                        }
                    }
                }
            });
        }
        // Sampler thread: real wall-clock height + mempool depth once a second.
        {
            let (base, stop) = (base.to_string(), stop.clone());
            let submitted = submitted.clone();
            s.spawn(move || {
                let mut last_h = start_h;
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_secs(5));
                    let h = chain_height(&base);
                    let mp = mempool_count(&base);
                    println!(
                        "  t={:>4}s  height {h} (+{})  submitted {}  mempool {}",
                        t0.elapsed().as_secs(), h - last_h,
                        submitted.load(Ordering::Relaxed), mp
                    );
                    last_h = h;
                }
            });
        }
        std::thread::sleep(Duration::from_secs(duration_s));
        stop.store(true, Ordering::Relaxed);
    });
    let flood_wall = t0.elapsed().as_secs_f64();

    // ---- drain: let the mempool clear (bounded) ----
    println!("[drain] letting the mempool clear…");
    let drain0 = Instant::now();
    while mempool_count(base) > 0 && drain0.elapsed() < Duration::from_secs(60) {
        std::thread::sleep(Duration::from_millis(500));
    }
    let end_h = chain_height(base);
    let total_wall = t0.elapsed().as_secs_f64();

    // ---- read the window back through the block log ----
    let (inc_txs, blocks, max_fill) = window_stats(base, start_h, end_h);
    let sub = submitted.load(Ordering::Relaxed);
    let rej = rejected.load(Ordering::Relaxed);
    let sustained = inc_txs as f64 / total_wall;
    let interval = if blocks > 0 { total_wall / blocks as f64 } else { 0.0 };

    println!("\n=== C1 CAPACITY REPORT (paste into docs/CAPACITY-SHEET.md) ===");
    println!("  window                : heights {}..{} · {:.1}s flood + {:.1}s drain",
        start_h + 1, end_h, flood_wall, total_wall - flood_wall);
    println!("  submitted / admitted  : {sub} ok · {rej} rpc-rejected");
    println!("  included on-chain     : {inc_txs} txs in {blocks} blocks");
    println!("  SUSTAINED THROUGHPUT  : {sustained:.1} tx/s (included / total wall)");
    println!("  block fill            : avg {:.1} · max {max_fill} (cap {})",
        if blocks > 0 { inc_txs as f64 / blocks as f64 } else { 0.0 },
        crate::batch::MAX_TXS_PER_BLOCK);
    println!("  real block interval   : {interval:.2}s");
    println!("  mempool residual      : {}", mempool_count(base));
    println!("\n  M1 bar: 183 tx/s sustained for 30 min on the PUBLIC testnet.");
    println!("  (This run is a devnet point-measurement — label it as such in the sheet.)\n");
    Ok(())
}
