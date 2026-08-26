//! The P2.3 aggregation storyline — ONE STARK per block, live.
//!
//!   Three notes are minted, then three shielded spends are proven COMPRESSED, folded by
//!   the aggregator guest into ONE aggregate STARK, and submitted as a PROOF-LESS bundle.
//!   One block commits all three; every validator verifies exactly ONE proof for them
//!   (watch the node log line "Aggregate STARK verified — ONE verify covers…"). Then a
//!   fourth spend goes through the classic per-proof path — the legal fallback, alive.
//!
//! The wire win: three individual spends ≈ 3 × 2.7 MB of proof; the bundle carries ONE
//! ~1.3 MB aggregate and three ~2 KB proof-less txs.
//!
//! Run:  hk-node demo-agg http://127.0.0.1:26000 http://127.0.0.1:9911

use serde_json::json;

use hk_primitives::{Amount, H256};
use hk_state::tx::Tx;
use hk_wallet::{build_mint, build_spend, seal_note, WalletKeys};

use crate::demo::{
    account_nonce, balance, chain_height, dollars, rpc, submit, usd, wait, wait_tx, Wallet,
};
use crate::demo_shielded::{pool_notes, r32, take_proof};

const M: Amount = 1_000_000;

pub fn run(base: &str, prover: &str) -> eyre::Result<()> {
    println!("\n=== HashKinetics P2.3 demo — AGGREGATION: one STARK per block ===");
    println!("    chain: {base}   prover: {prover}\n");

    if !wait("node RPC reachable", || chain_height(base) >= 1) {
        eyre::bail!("node not reachable at {base}");
    }
    if rpc(prover, "health", json!({})).get("result").is_none() {
        eyre::bail!("hk-prove not reachable at {prover}");
    }

    let mut org = Wallet::new("org");
    if let Some(n) = account_nonce(base, &org.id) {
        org.next_nonce = n;
    }
    let usd = usd();
    let org0 = balance(base, &org.id);
    if org0 < 6 * M {
        eyre::bail!("org has {} — needs ≥ $6 (fresh devnet)", dollars(org0));
    }
    let tag = chain_height(base);
    // Per-demo seed: a shared seed would make [5]'s scan sweep notes from OTHER demos.
    let alice = WalletKeys::new(b"agg-alice-master");

    // ---- [1] three notes to spend ---------------------------------------------------
    // SEQUENTIAL + COMPRESSED: compressed is what the aggregator recursion consumes,
    // and sequencing keeps the storyline legible. (The old JSON-codec gossip-cap reason
    // is retired — P2.5's binary codec carries proofs at ~1×.)
    println!("[1] minting 3 notes ($1, $2, $3) — sequential, compressed proofs...");
    let mut notes = Vec::new();
    let mut spent_total: Amount = 0;
    for (i, v) in [1u64, 2, 3].iter().enumerate() {
        let note = alice.self_note(*v * M as u64, tag + i as u64);
        let (mw, mp) = build_mint(&note);
        let (ct, _) = seal_note(&note, &alice.address(), &r32(tag, 10 + i as u8), b"agg-demo")
            .ok_or_else(|| eyre::eyre!("seal"))?;
        let pr = rpc(prover, "prove_mint",
            json!({"witness": serde_json::to_value(&mw)?, "mode": "compressed"}));
        let (proof, ms) = take_proof(&pr)?;
        submit(base, &org.sign(Tx::MintToPool {
            asset: usd,
            value: *v as Amount * M,
            commitment: H256(mp.commitment),
            proof,
            stealth_ct: ct,
        }));
        spent_total += *v as Amount * M;
        let want = org0 - spent_total;
        if !wait(&format!("mint {} committed", i + 1), || balance(base, &org.id) == want) {
            eyre::bail!("mint {} not applied", i + 1);
        }
        println!("    ✓ mint {} (${v}) committed — proof {ms} ms compressed.", i + 1);
        notes.push((note, mp.commitment));
    }
    println!("    ✓ 3 commitments in the pool.\n");

    // ---- [2] three COMPRESSED spend proofs ------------------------------------------
    println!("[2] proving 3 shielded spends in COMPRESSED mode (recursion-ready)...");
    let (leaves, _) = pool_notes(base)?;
    let mut items = Vec::new();
    let mut spend_txs = Vec::new();
    for (i, (note, cm)) in notes.into_iter().enumerate() {
        let idx = leaves.iter().rposition(|l| *l == cm).unwrap() as u64;
        let out = alice.self_note(note.value, tag + 20 + i as u64); // full value forward
        let (out_ct, _) = seal_note(&out, &alice.address(), &r32(tag, 30 + i as u8), b"agg-out")
            .ok_or_else(|| eyre::eyre!("seal"))?;
        let dummy = hk_spend_circuit::Note {
            value: 0,
            owner: [0; 32],
            rho: r32(tag, 40 + i as u8),
            rcm: r32(tag, 50 + i as u8),
        };
        let plan = build_spend(&leaves, idx, note, &alice, i as u32, out, dummy, 0, [0; 32])
            .map_err(|e| eyre::eyre!(e))?;
        let pr = rpc(prover, "prove_spend",
            json!({"witness": serde_json::to_value(&plan.witness)?, "mode": "compressed"}));
        let (proof, ms) = take_proof(&pr)?;
        println!("    ✓ spend {} compressed-proved in {ms} ms ({} KB)", i + 1, proof.len() / 1024);
        items.push(json!({"kind": "spend", "proof": hex::encode(&proof)}));
        spend_txs.push(Tx::ShieldedSpend {
            anchor: H256(plan.public.merkle_root),
            nullifier: H256(plan.public.nullifier),
            out_commitment: H256(plan.public.out_commitment),
            out2_commitment: H256(plan.public.out2_commitment),
            fee: 0,
            credit: None,
            mandate: None,
            proof: Vec::new(), // PROOF-LESS — the aggregate carries the truth
            stealth_ct: out_ct,
            stealth_ct2: Vec::new(),
        });
    }

    // ---- [3] fold them into ONE aggregate -------------------------------------------
    println!("\n[3] aggregating: the guest VERIFIES all 3 proofs inside the zkVM...");
    let ar = rpc(prover, "aggregate", json!({"items": items}));
    if let Some(e) = ar.get("error") {
        eyre::bail!("aggregate failed: {e}");
    }
    let r = ar.get("result").unwrap();
    let agg_hex = r.get("agg_proof").and_then(|p| p.as_str()).unwrap_or("").to_string();
    let agg_ms = r.get("prove_ms").and_then(|m| m.as_u64()).unwrap_or(0);
    println!("    ✓ ONE aggregate STARK: {} KB, proved in {agg_ms} ms — replaces 3 × ~2.7 MB.\n",
        agg_hex.len() / 2048);

    // ---- [4] the proof-less bundle --------------------------------------------------
    println!("[4] submitting the bundle (3 proof-less txs + 1 aggregate)...");
    let nf0 = pool_nullifiers(base);
    let signed: Vec<_> = spend_txs.into_iter().map(|t| org.sign(t)).collect();
    let v = rpc(base, "hk_submitBundle", json!({
        "txs": serde_json::to_value(&signed)?,
        "agg_proof": agg_hex,
    }));
    if v.get("result").is_none() {
        eyre::bail!("hk_submitBundle failed: {v}");
    }
    if !wait("bundle committed (3 nullifiers burned)", || pool_nullifiers(base) == nf0 + 3) {
        eyre::bail!("bundle not applied (is node0 the proposer soon? it holds the bundle)");
    }
    println!("    ✓ ALL THREE spends committed. Check the node logs for:");
    println!("      'Aggregate STARK verified — ONE verify covers this block's shielded txs'\n");

    // ---- [5] fallback stays legal ---------------------------------------------------
    println!("[5] a 4th spend via the CLASSIC per-proof path (fallback alive)...");
    let (leaves2, entries2) = pool_notes(base)?;
    let mine = hk_wallet::scan(&alice, &entries2);
    let pick = mine.iter().max_by_key(|d| d.note.value).ok_or_else(|| eyre::eyre!("no note"))?;
    let out = alice.self_note(pick.note.value, tag + 60);
    let (out_ct, _) = seal_note(&out, &alice.address(), &r32(tag, 61), b"solo")
        .ok_or_else(|| eyre::eyre!("seal"))?;
    let dummy = hk_spend_circuit::Note { value: 0, owner: [0; 32], rho: r32(tag, 62), rcm: r32(tag, 63) };
    let plan = build_spend(&leaves2, pick.leaf_index, pick.note.clone(), &alice, 10, out, dummy, 0, [0; 32])
        .map_err(|e| eyre::eyre!(e))?;
    println!("    spending alice's own note: ${} at leaf {}", pick.note.value / M as u64, pick.leaf_index);
    let pr = rpc(prover, "prove_spend", json!({"witness": serde_json::to_value(&plan.witness)?}));
    let (proof, ms) = take_proof(&pr)?;
    println!("    ✓ solo proof in {ms} ms ({} KB core).", proof.len() / 1024);
    let solo = submit(base, &org.sign(Tx::ShieldedSpend {
        anchor: H256(plan.public.merkle_root),
        nullifier: H256(plan.public.nullifier),
        out_commitment: H256(plan.public.out_commitment),
        out2_commitment: H256(plan.public.out2_commitment),
        fee: 0,
        credit: None,
        mandate: None,
        proof,
        stealth_ct: out_ct,
        stealth_ct2: Vec::new(),
    }));
    if !wait_tx(base, "solo spend committed", &solo, || pool_nullifiers(base) == nf0 + 4) {
        eyre::bail!("solo spend not applied");
    }
    println!("    ✓ per-proof path verified as always.\n");

    println!("=== P2.3 ===");
    println!("A block carried THREE shielded spends and validators verified ONE proof.");
    println!("Wire cost: one ~{} KB aggregate vs 3 × ~2.7 MB individuals. Fallback legal.\n",
        agg_hex.len() / 2048);
    Ok(())
}

fn pool_nullifiers(base: &str) -> u64 {
    rpc(base, "hk_getPoolInfo", json!({}))
        .get("result")
        .and_then(|r| r.get("nullifiers"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}
