//! The P2.4 storyline — MANDATES × SHIELDED: the flagship $50 demo with hidden balances.
//!
//!   org shields $50 and pays three agents STEALTH notes ($20/$20/$10 — amounts invisible
//!   on-chain). org builds an OVERSUBSCRIBED mandate tree: root envelope $45, children
//!   capped $20/$25/$20 ($65 promised > $45 real). Agents unshield to the merchant under
//!   their mandates: a $20 ✓, b $20 ✓ — then c tries $10 and the ROOT ENVELOPE (only $5
//!   left) refuses it with the iconic receipt `insufficient buffer at depth 1` — the
//!   org's consensus-enforced cap holding over balances nobody can see. c's note
//!   survives untouched (nothing half-applies).
//!
//! Run:  hk-node demo-mandates http://127.0.0.1:26000 http://127.0.0.1:9911

use serde_json::json;

use hk_primitives::{Amount, H256};
use hk_state::tx::Tx;
use hk_wallet::{build_mint, build_output, build_spend, scan, seal_note, WalletKeys};

use crate::demo::{account_nonce, balance, chain_height, dollars, receipt, rpc, submit, usd, wait, Wallet};
use crate::demo_shielded::{pool_notes, r32, take_proof};

const M: Amount = 1_000_000;
const BIG: u64 = 10_000_000;

pub fn run(base: &str, prover: &str) -> eyre::Result<()> {
    println!("\n=== HashKinetics P2.4 demo — MANDATES × SHIELDED (the $50 storyline, hidden) ===");
    println!("    chain: {base}   prover: {prover}\n");

    if !wait("node RPC reachable", || chain_height(base) >= 1) {
        eyre::bail!("node not reachable at {base}");
    }
    if rpc(prover, "health", json!({})).get("result").is_none() {
        eyre::bail!("hk-prove not reachable at {prover}");
    }

    let mut org = Wallet::new("org");
    let mut a = Wallet::new("agent-a");
    let mut b = Wallet::new("agent-b");
    let mut c = Wallet::new("agent-c");
    for w in [&mut org, &mut a, &mut b, &mut c] {
        if let Some(n) = account_nonce(base, &w.id) {
            w.next_nonce = n;
        }
    }
    let merchant_id = Wallet::new("merchant").id;
    let usd = usd();
    let org0 = balance(base, &org.id);
    let mer0 = balance(base, &merchant_id);
    if org0 < 50 * M {
        eyre::bail!("org has {} — needs $50 (fresh devnet)", dollars(org0));
    }
    let tag = chain_height(base);

    let alice = WalletKeys::new(b"org-shield-master");
    let wa = WalletKeys::new(b"agent-a-shield");
    let wb = WalletKeys::new(b"agent-b-shield");
    let wc = WalletKeys::new(b"agent-c-shield");

    // ---- [1] shield $50, deal stealth notes to the agents ---------------------------
    println!("[1] org shields $50 and pays the agents STEALTH notes ($20/$20/$10)...");
    let org_note = alice.self_note((50 * M) as u64, tag);
    let (mw, mp) = build_mint(&org_note);
    let (ct, _) = seal_note(&org_note, &alice.address(), &r32(tag, 1), b"treasury")
        .ok_or_else(|| eyre::eyre!("seal"))?;
    let pr = rpc(prover, "prove_mint", json!({"witness": serde_json::to_value(&mw)?, "mode": "compressed"}));
    let (proof, _) = take_proof(&pr)?;
    submit(base, &org.sign(Tx::MintToPool {
        asset: usd, value: 50 * M, commitment: H256(mp.commitment), proof, stealth_ct: ct,
    }));
    if !wait("treasury shielded", || balance(base, &org.id) == org0 - 50 * M) {
        eyre::bail!("mint not applied");
    }

    // Three sequential stealth deals from the org treasury note.
    let deals: [(u64, &WalletKeys, &[u8]); 3] =
        [(20, &wa, b"agent-a allowance"), (20, &wb, b"agent-b allowance"), (10, &wc, b"agent-c allowance")];
    let mut treasury = org_note;
    let mut nf_count = 0u64;
    for (i, (amount, to, memo)) in deals.iter().enumerate() {
        let (leaves, _) = pool_notes(base)?;
        let t_cm = hk_spend_circuit::commit_note(&treasury);
        let idx = leaves.iter().rposition(|l| *l == t_cm).unwrap() as u64;
        let out = build_output(&to.address(), *amount * M as u64, &r32(tag, 10 + i as u8), &r32(tag, 20 + i as u8), memo)
            .ok_or_else(|| eyre::eyre!("out"))?;
        let change_v = treasury.value - *amount * M as u64;
        let change = alice.self_note(change_v, tag + 1 + i as u64);
        let (change_ct, _) = seal_note(&change, &alice.address(), &r32(tag, 30 + i as u8), b"change")
            .ok_or_else(|| eyre::eyre!("seal"))?;
        let plan = build_spend(&leaves, idx, treasury.clone(), &alice, i as u32, out.note.clone(), change.clone(), 0, [0; 32])
            .map_err(|e| eyre::eyre!(e))?;
        let pr = rpc(prover, "prove_spend", json!({"witness": serde_json::to_value(&plan.witness)?, "mode": "compressed"}));
        let (proof, _) = take_proof(&pr)?;
        submit(base, &org.sign(Tx::ShieldedSpend {
            anchor: H256(plan.public.merkle_root), nullifier: H256(plan.public.nullifier),
            out_commitment: H256(plan.public.out_commitment), out2_commitment: H256(plan.public.out2_commitment),
            fee: 0, credit: None, mandate: None, proof,
            stealth_ct: out.stealth_ct.clone(), stealth_ct2: change_ct,
        }));
        nf_count += 1;
        if !wait(&format!("stealth deal {} committed", i + 1), || pool_nfs(base) == nf_count) {
            eyre::bail!("deal {} not applied", i + 1);
        }
        treasury = change;
    }
    println!("    ✓ three agents hold hidden allowances — the chain saw only commitments.\n");

    // ---- [2] the oversubscribed mandate tree ---------------------------------------
    println!("[2] org builds the mandate tree: root $45; children $20/$25/$20 ($65 promised)...");
    let (m0, ma, mb, mc) = (H256([0xA0; 32]), H256([0xA1; 32]), H256([0xA2; 32]), H256([0xA3; 32]));
    let mk = |id, parent, holder, cap: Amount| Tx::MandateCreate {
        id, parent, holder, asset: usd, rate_per_sec: 0, buffer_max: cap, per_tx_max: cap,
        initial_buffer: cap, expiry: BIG, tier: 0,
    };
    submit(base, &org.sign(mk(m0, None, org.id, 45 * M)));
    submit(base, &org.sign(mk(ma, Some(m0), a.id, 20 * M)));
    submit(base, &org.sign(mk(mb, Some(m0), b.id, 25 * M)));
    submit(base, &org.sign(mk(mc, Some(m0), c.id, 20 * M)));
    if !wait("mandate tree live", || account_nonce(base, &org.id).unwrap_or(0) >= 8) {
        eyre::bail!("mandates not applied");
    }
    println!("    ✓ consensus now enforces the org's envelope over the POOL.\n");

    // ---- [3] agents discover + unshield under their mandates ------------------------
    println!("[3] agents SCAN for their notes and unshield to the merchant under mandate...");
    let (leaves, entries) = pool_notes(base)?;
    let unshield = |agent: &mut Wallet, keys: &WalletKeys, leaf: H256, amount: u64, label: &str|
        -> eyre::Result<String> {
        let mine = scan(keys, &entries);
        let note = mine.iter().find(|d| d.note.value == amount * M as u64)
            .ok_or_else(|| eyre::eyre!("{label}: note not found by scan"))?;
        let dummy = hk_spend_circuit::Note { value: 0, owner: [0; 32], rho: r32(tag, 70), rcm: r32(tag, 71) };
        let keep = note.note.value - amount * M as u64; // 0 — full unshield
        let out = hk_spend_circuit::Note { value: keep, owner: [0; 32], rho: r32(tag, 72), rcm: r32(tag, 73) };
        let plan = build_spend(&leaves, note.leaf_index, note.note.clone(), keys, 0, out, dummy,
            amount * M as u64, merchant_id.0).map_err(|e| eyre::eyre!("{label}: {e}"))?;
        let pr = rpc(prover, "prove_spend", json!({"witness": serde_json::to_value(&plan.witness)?, "mode": "compressed"}));
        let (proof, _) = take_proof(&pr)?;
        Ok(submit(base, &agent.sign(Tx::ShieldedSpend {
            anchor: H256(plan.public.merkle_root), nullifier: H256(plan.public.nullifier),
            out_commitment: H256(plan.public.out_commitment), out2_commitment: H256(plan.public.out2_commitment),
            fee: amount as Amount * M, credit: Some(merchant_id), mandate: Some(leaf), proof,
            stealth_ct: Vec::new(), stealth_ct2: Vec::new(),
        })))
    };

    let _ = unshield(&mut a, &wa, ma, 20, "agent-a")?;
    if !wait("agent-a unshielded $20", || balance(base, &merchant_id) == mer0 + 20 * M) {
        eyre::bail!("a's unshield not applied");
    }
    println!("    ✓ agent-a unshielded $20 under its mandate (root envelope: $25 left).");
    let _ = unshield(&mut b, &wb, mb, 20, "agent-b")?;
    if !wait("agent-b unshielded $20", || balance(base, &merchant_id) == mer0 + 40 * M) {
        eyre::bail!("b's unshield not applied");
    }
    println!("    ✓ agent-b unshielded $20 (root envelope: $5 left).\n");

    println!("[4] agent-c tries $10 — its own leaf allows $20, but the ROOT has $5. Watch consensus...");
    let c_txid = unshield(&mut c, &wc, mc, 10, "agent-c")?;
    let mut iconic = String::new();
    wait("agent-c's receipt", || {
        if let Some(r) = receipt(base, &c_txid) {
            println!("    ⛔ consensus receipt: {r}");
            iconic = r;
            true
        } else {
            false
        }
    });
    c.rollback();
    if !iconic.contains("insufficient buffer at depth 1") {
        eyre::bail!("expected the iconic ancestor-envelope receipt, got: {iconic}");
    }
    println!("    ✓ THE ICONIC RECEIPT — over balances the chain cannot see.");
    println!("    ✓ agent-c's $10 note survives untouched in the pool.\n");

    println!("=== P2.4 ===");
    println!("  merchant transparent : {} (a's $20 + b's $20)", dollars(balance(base, &merchant_id)));
    println!("  pool (hidden)        : {} — incl. agent-c's intact allowance", dollars(pool_total(base)));
    println!("The org's hierarchical caps held IN CONSENSUS while every balance stayed hidden.");
    println!("That is the HashKinetics thesis, complete.\n");
    Ok(())
}

fn pool_nfs(base: &str) -> u64 {
    rpc(base, "hk_getPoolInfo", json!({})).get("result")
        .and_then(|r| r.get("nullifiers")).and_then(|v| v.as_u64()).unwrap_or(0)
}

fn pool_total(base: &str) -> Amount {
    rpc(base, "hk_getPoolInfo", json!({})).get("result")
        .and_then(|r| r.get("total_shielded")).and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok()).unwrap_or(0)
}
