//! The P2.1 stealth-payment storyline, live on the devnet with REAL STARK proofs.
//!
//!   org shields $5 → org pays BOB $2 FULLY SHIELDED (fee 0, no transparent trace; the
//!   change returns to org) → Bob's wallet DISCOVERS the note by trial-decapsulation
//!   scanning (nobody else can) → Bob SPENDS the discovered note, unshielding $1 to the
//!   merchant — ownership proven, not asserted → a double-spend replay and a forged
//!   proof are both refused by consensus.
//!
//! Topology: driver + devnet in WSL; `hk-prove` next to the GPU. Nodes must have fetched
//! the (v3) verifying keys at startup (devnet.sh --prover-url ...).
//!
//! Run:  hk-node demo-shielded http://127.0.0.1:26000 http://127.0.0.1:9911

use serde_json::{json, Value};

use hk_primitives::{Amount, H256};
use hk_spend_circuit::Hash;
use hk_state::tx::Tx;
use hk_wallet::{build_mint, build_output, build_spend, scan, seal_note, WalletKeys};

use crate::demo::{
    account_nonce, balance, chain_height, dollars, receipt, rpc, submit, usd, wait, Wallet,
};

const M: Amount = 1_000_000; // $1 in micro-units

/// Deterministic per-run randomness for the demo (real wallets: CSPRNG).
pub(crate) fn r32(a: u64, b: u8) -> [u8; 32] {
    let mut x = [b; 32];
    x[..8].copy_from_slice(&a.to_le_bytes());
    x
}

pub fn run(base: &str, prover: &str) -> eyre::Result<()> {
    println!("\n=== HashKinetics P2.1 demo — STEALTH PAYMENTS (ML-KEM + spend-tree v3) ===");
    println!("    chain: {base}   prover: {prover}\n");

    if !wait("node RPC reachable", || chain_height(base) >= 1) {
        eyre::bail!("node not reachable / not producing blocks at {base}");
    }
    let health = rpc(prover, "health", json!({}));
    let Some(mode) = health
        .get("result")
        .and_then(|r| r.get("mode"))
        .and_then(|m| m.as_str())
        .map(str::to_string)
    else {
        eyre::bail!(
            "hk-prove not reachable at {prover} — start it in WSL:\n  cd zkvm-bakeoff/sp1/script && cargo run --release --bin serve\n(response: {health})"
        );
    };
    println!("Chain live at height {}; hk-prove up (mode: {mode}).\n", chain_height(base));

    // Transparent envelopes (relayers) + shielded wallets.
    let mut org = Wallet::new("org");
    let mut merchant = Wallet::new("merchant");
    if let Some(n) = account_nonce(base, &org.id) {
        org.next_nonce = n;
    }
    if let Some(n) = account_nonce(base, &merchant.id) {
        merchant.next_nonce = n;
    }
    let usd = usd();
    let org0 = balance(base, &org.id);
    let mer0 = balance(base, &merchant.id);
    if org0 < 5 * M {
        eyre::bail!("org has {} transparent — needs at least $5 (use a fresh devnet)", dollars(org0));
    }
    let tag = chain_height(base); // fresh rho/randomness per run

    let alice = WalletKeys::new(b"org-shield-master");
    let bob = WalletKeys::new(b"bob-shield-master");
    let eve = WalletKeys::new(b"eve-shield-master");
    println!(
        "Stealth addresses derived (spend-tree + nk + ML-KEM-768):\n  alice(org) tag {}…\n  bob        tag {}…\n",
        hex::encode(&alice.address().tag[..6]),
        hex::encode(&bob.address().tag[..6]),
    );

    // ---- [1] SHIELD $5 --------------------------------------------------------------
    println!("[1] org SHIELDS $5 to alice's stealth address...");
    let a_note = alice.self_note((5 * M) as u64, tag);
    let (mint_witness, mint_public) = build_mint(&a_note);
    let (mint_stealth, _) = seal_note(&a_note, &alice.address(), &r32(tag, 1), b"self-mint")
        .ok_or_else(|| eyre::eyre!("seal mint note"))?;
    println!("    requesting MINT proof (GPU)...");
    let pr = rpc(prover, "prove_mint", json!({"witness": serde_json::to_value(&mint_witness)?}));
    let (mint_proof, mint_ms) = take_proof(&pr)?;
    println!("    ✓ mint proof in {mint_ms} ms.");
    let mint_txid = submit(base, &org.sign(Tx::MintToPool {
        asset: usd,
        value: 5 * M,
        commitment: H256(mint_public.commitment),
        proof: mint_proof,
        stealth_ct: mint_stealth,
    }));
    if !wait("mint committed (org −$5)", || balance(base, &org.id) == org0 - 5 * M) {
        if let Some(r) = receipt(base, &mint_txid) {
            eyre::bail!("mint not applied; receipt: {r}");
        }
        eyre::bail!("mint not applied (no receipt yet)");
    }
    println!("    ✓ $5 shielded. Pool: {}\n", pool_line(base));

    // ---- [2] PAY BOB, FULLY SHIELDED ------------------------------------------------
    println!("[2] org pays BOB $2 — FULLY SHIELDED (fee 0: no transparent trace at all)...");
    let (leaves, entries) = pool_notes(base)?;
    let a_idx = leaves
        .iter()
        .rposition(|l| *l == mint_public.commitment)
        .ok_or_else(|| eyre::eyre!("alice's commitment not in pool"))? as u64;
    let to_bob = build_output(&bob.address(), (2 * M) as u64, &r32(tag, 2), &r32(tag, 3), b"first stealth payment <3")
        .ok_or_else(|| eyre::eyre!("build bob output"))?;
    let change = alice.self_note((3 * M) as u64, tag + 1);
    let (change_ct, _) = seal_note(&change, &alice.address(), &r32(tag, 4), b"change")
        .ok_or_else(|| eyre::eyre!("seal change"))?;
    let plan = build_spend(&leaves, a_idx, a_note, &alice, 0, to_bob.note.clone(), change, 0, [0; 32])
        .map_err(|e| eyre::eyre!("build_spend: {e}"))?;
    println!("    requesting SPEND proof (GPU)...");
    let pr = rpc(prover, "prove_spend", json!({"witness": serde_json::to_value(&plan.witness)?}));
    let (spend_proof, pay_ms) = take_proof(&pr)?;
    println!("    ✓ spend proof in {pay_ms} ms.");
    let _ = submit(base, &org.sign(Tx::ShieldedSpend {
        anchor: H256(plan.public.merkle_root),
        nullifier: H256(plan.public.nullifier),
        out_commitment: H256(plan.public.out_commitment),
        out2_commitment: H256(plan.public.out2_commitment),
        fee: 0,
        credit: None,
        mandate: None,
        proof: spend_proof,
        stealth_ct: to_bob.stealth_ct.clone(),
        stealth_ct2: change_ct,
    }));
    if !wait("shielded payment committed (nullifier burned)", || {
        pool_info(base).get("nullifiers").and_then(|v| v.as_u64()) == Some(1)
    }) {
        eyre::bail!("shielded payment not applied");
    }
    println!("    ✓ committed. The chain saw: one nullifier, two commitments, fee 0. WHO PAID WHOM: invisible.\n");

    // ---- [3] BOB'S WALLET DISCOVERS THE NOTE ----------------------------------------
    println!("[3] Bob's wallet SCANS the pool (trial-decapsulation over every stealth ct)...");
    let (_, entries2) = pool_notes(base)?;
    let _ = entries; // pre-payment view, superseded
    let found = scan(&bob, &entries2);
    if found.len() != 1 {
        eyre::bail!("bob expected exactly 1 discovered note, got {}", found.len());
    }
    println!(
        "    ✓ BOB DISCOVERED: ${} at tree index {}, memo: {:?}",
        found[0].note.value / M as u64,
        found[0].leaf_index,
        String::from_utf8_lossy(&found[0].memo),
    );
    let alice_view = scan(&alice, &entries2);
    println!("    ✓ alice's scanner sees her own {} note(s) (mint + change).", alice_view.len());
    let eve_view = scan(&eve, &entries2);
    println!("    ✓ eve's scanner sees {} — nobody else can.\n", eve_view.len());
    if !eve_view.is_empty() {
        eyre::bail!("eve should discover nothing");
    }

    // ---- [4] BOB SPENDS WHAT HE DISCOVERED ------------------------------------------
    println!("[4] Bob SPENDS the discovered note: $1 unshields to the merchant, $1 change stays his...");
    let (leaves3, _) = pool_notes(base)?;
    let bob_change = bob.self_note(M as u64, 1);
    let (bob_change_ct, _) = seal_note(&bob_change, &bob.address(), &r32(tag, 5), b"bob change")
        .ok_or_else(|| eyre::eyre!("seal bob change"))?;
    let plan2 = build_spend(
        &leaves3,
        found[0].leaf_index,
        found[0].note.clone(),
        &bob,
        0,
        bob_change,
        hk_spend_circuit::Note { value: 0, owner: [0; 32], rho: r32(tag, 6), rcm: r32(tag, 7) },
        M as u64,
        merchant.id.0,
    )
    .map_err(|e| eyre::eyre!("bob build_spend: {e}"))?;
    println!("    requesting Bob's SPEND proof (GPU)...");
    let pr = rpc(prover, "prove_spend", json!({"witness": serde_json::to_value(&plan2.witness)?}));
    let (bob_proof, bob_ms) = take_proof(&pr)?;
    println!("    ✓ proof in {bob_ms} ms.");
    let bob_payload = Tx::ShieldedSpend {
        anchor: H256(plan2.public.merkle_root),
        nullifier: H256(plan2.public.nullifier),
        out_commitment: H256(plan2.public.out_commitment),
        out2_commitment: H256(plan2.public.out2_commitment),
        fee: M,
        credit: Some(merchant.id),
        mandate: None,
        proof: bob_proof.clone(),
        stealth_ct: bob_change_ct,
        stealth_ct2: Vec::new(),
    };
    let _ = submit(base, &merchant.sign(bob_payload.clone()));
    if !wait("bob's spend committed (merchant +$1)", || balance(base, &merchant.id) == mer0 + M) {
        eyre::bail!("bob's spend not applied");
    }
    println!("    ✓ Bob OWNS what he discovered — the stealth pipeline is spend-complete.\n");

    // ---- [5] double spend + [6] forgery ---------------------------------------------
    println!("[5] replaying Bob's nullifier — consensus must refuse...");
    let ds_txid = submit(base, &merchant.sign(bob_payload));
    wait("double-spend receipt", || {
        receipt(base, &ds_txid).map(|r| println!("    ⛔ {r}")).is_some()
    });
    merchant.rollback();

    println!("[6] submitting a FORGED proof (one byte flipped)...");
    let mut forged = bob_proof;
    if let Some(b) = forged.get_mut(2000) {
        *b ^= 1;
    }
    let fg_txid = submit(base, &org.sign(Tx::ShieldedSpend {
        anchor: H256(plan2.public.merkle_root),
        nullifier: H256(r32(tag, 8)),
        out_commitment: H256(r32(tag, 9)),
        out2_commitment: H256(r32(tag, 10)),
        fee: 0,
        credit: None,
        mandate: None,
        proof: forged,
        stealth_ct: Vec::new(),
        stealth_ct2: Vec::new(),
    }));
    wait("forged-proof receipt", || {
        receipt(base, &fg_txid).map(|r| println!("    ⛔ {r}")).is_some()
    });
    org.rollback();

    // ---- final ----------------------------------------------------------------------
    println!("\n=== final ===");
    println!("  org transparent      : {}", dollars(balance(base, &org.id)));
    println!("  merchant transparent : {}", dollars(balance(base, &merchant.id)));
    println!("  pool                 : {}", pool_line(base));
    println!("  proof latencies      : mint {mint_ms} ms · pay-bob {pay_ms} ms · bob-spend {bob_ms} ms");
    println!("\nThat's P2.1: a payment where the chain never learns who paid whom, the");
    println!("recipient FOUND it by scanning, and only the recipient could spend it.\n");
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn pool_info(base: &str) -> Value {
    rpc(base, "hk_getPoolInfo", json!({})).get("result").cloned().unwrap_or(Value::Null)
}

fn pool_line(base: &str) -> String {
    let i = pool_info(base);
    format!(
        "{} shielded · {} commitments · {} nullifier(s)",
        i.get("total_shielded").and_then(|v| v.as_str()).map(|s| {
            let a: Amount = s.parse().unwrap_or(0);
            dollars(a)
        }).unwrap_or_default(),
        i.get("next_index").and_then(|v| v.as_u64()).unwrap_or(0),
        i.get("nullifiers").and_then(|v| v.as_u64()).unwrap_or(0),
    )
}

/// Fetch the scanner feed: (leaves in order, (index, commitment, stealth_ct) entries).
/// H3 (v0.16.1): the feed is paged (`from`/`limit`, `next` = the following page); this
/// CLI reads it whole, page by page — the GUI wallet keeps a cursor instead.
#[allow(clippy::type_complexity)]
pub(crate) fn pool_notes(base: &str) -> eyre::Result<(Vec<Hash>, Vec<(u64, Hash, Vec<u8>)>)> {
    let mut leaves = Vec::new();
    let mut entries: Vec<(u64, Hash, Vec<u8>)> = Vec::new();
    let mut from = 0u64;
    loop {
        let v = rpc(base, "hk_getPoolNotes", json!({ "from": from, "limit": 5_000 }));
        let r = v.get("result").ok_or_else(|| eyre::eyre!("hk_getPoolNotes failed: {v}"))?;
        let arr = r.get("notes").and_then(|n| n.as_array()).ok_or_else(|| eyre::eyre!("hk_getPoolNotes failed: {v}"))?;
        for e in arr {
            let idx = e.get("index").and_then(|i| i.as_u64()).ok_or_else(|| eyre::eyre!("bad index"))?;
            if idx < entries.len() as u64 {
                continue; // a pre-H3 node answers everything regardless of `from`
            }
            let cm_hex = e.get("commitment").and_then(|c| c.as_str()).ok_or_else(|| eyre::eyre!("bad cm"))?;
            let ct_hex = e.get("stealth_ct").and_then(|c| c.as_str()).unwrap_or("");
            let cm_b = hex::decode(cm_hex)?;
            let cm: Hash = cm_b.as_slice().try_into().map_err(|_| eyre::eyre!("cm not 32B"))?;
            leaves.push(cm);
            entries.push((idx, cm, hex::decode(ct_hex)?));
        }
        match r.get("next").and_then(|n| n.as_u64()) {
            Some(n) if n > from => from = n,
            _ => return Ok((leaves, entries)),
        }
    }
}

/// Pull (proof bytes, prove_ms) out of an hk-prove response, or surface its error.
pub(crate) fn take_proof(v: &Value) -> eyre::Result<(Vec<u8>, u64)> {
    if let Some(e) = v.get("error") {
        eyre::bail!("hk-prove error: {e}");
    }
    let r = v.get("result").ok_or_else(|| eyre::eyre!("hk-prove: no result: {v}"))?;
    let proof_hex =
        r.get("proof").and_then(|p| p.as_str()).ok_or_else(|| eyre::eyre!("hk-prove: no proof"))?;
    Ok((hex::decode(proof_hex)?, r.get("prove_ms").and_then(|m| m.as_u64()).unwrap_or(0)))
}
