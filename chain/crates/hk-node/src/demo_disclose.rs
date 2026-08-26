//! The P2.2 disclosure storyline — the CVA differentiator, live.
//!
//!   Two shielded payments happen (Alice→Bob, Alice→Carol). Bob produces a ONE-TIME
//!   DISCLOSURE PACKAGE for his payment — a JSON file an auditor verifies on a machine
//!   with NO chain access (value, memo, commitment, inclusion path, all bound). The
//!   package's key opens NOTHING else: Carol's payment stays invisible to it. Then
//!   Alice hands the auditor an epoch-0 INCOMING VIEWING KEY — the auditor sees her
//!   epoch-0 notes, and a fresh epoch-1 payment stays outside the key's scope.
//!   Confidential with lawful disclosure — never a master key, never a forever-key.
//!
//! Run:  hk-node demo-disclose http://127.0.0.1:26000 http://127.0.0.1:9911
//! Then: hk-node verify-disclosure <package.json>        (works fully offline)

use serde_json::json;

use hk_primitives::{Amount, H256};
use hk_state::tx::Tx;
use hk_wallet::{
    build_disclosure, build_mint, build_output, build_spend, note_key_as_recipient, scan,
    scan_with_ivk, seal_note, verify_disclosure, WalletKeys,
};

use crate::demo::{
    account_nonce, balance, chain_height, dollars, rpc, submit, usd, wait, wait_tx, Wallet,
};
use crate::demo_shielded::{pool_notes, r32, take_proof};

const M: Amount = 1_000_000;

pub fn run(base: &str, prover: &str) -> eyre::Result<()> {
    println!("\n=== HashKinetics P2.2 demo — ONE-TIME DISCLOSURE + EPOCH VIEWING KEYS ===");
    println!("    chain: {base}   prover: {prover}\n");

    if !wait("node RPC reachable", || chain_height(base) >= 1) {
        eyre::bail!("node not reachable at {base}");
    }
    let health = rpc(prover, "health", json!({}));
    if health.get("result").is_none() {
        eyre::bail!("hk-prove not reachable at {prover} ({health})");
    }
    let chain_id = rpc(base, "hk_chainInfo", json!({}))
        .get("result")
        .and_then(|r| r.get("chain_id"))
        .and_then(|c| c.as_str())
        .unwrap_or("hashkinetics-devnet-1")
        .to_string();

    let mut org = Wallet::new("org");
    if let Some(n) = account_nonce(base, &org.id) {
        org.next_nonce = n;
    }
    let usd = usd();
    let org0 = balance(base, &org.id);
    if org0 < 5 * M {
        eyre::bail!("org has {} — needs ≥ $5 (fresh devnet)", dollars(org0));
    }
    let tag = chain_height(base);
    // Pool history is SHARED across demos on one devnet: count nullifiers RELATIVELY.
    let nf0 = pool_info_nullifiers(base);

    // Per-demo wallet seeds — a shared seed would make scans sweep notes from OTHER
    // demo runs on the same devnet (same nk, same address tags).
    let alice = WalletKeys::new(b"disclose-alice-master");
    let bob = WalletKeys::new(b"disclose-bob-master");
    let carol = WalletKeys::new(b"disclose-carol-master");

    // ---- [1] two shielded payments --------------------------------------------------
    println!("[1] setting the scene: shield $5, pay Bob $2, pay Carol $1 (three proofs)...");
    let a_note = alice.self_note((5 * M) as u64, tag);
    let (mw, mp) = build_mint(&a_note);
    let (mint_ct, _) = seal_note(&a_note, &alice.address(), &r32(tag, 1), b"mint")
        .ok_or_else(|| eyre::eyre!("seal"))?;
    let pr = rpc(prover, "prove_mint", json!({"witness": serde_json::to_value(&mw)?}));
    let (mint_proof, _) = take_proof(&pr)?;
    submit(base, &org.sign(Tx::MintToPool {
        asset: usd, value: 5 * M, commitment: H256(mp.commitment),
        proof: mint_proof, stealth_ct: mint_ct,
    }));
    if !wait("mint committed", || balance(base, &org.id) == org0 - 5 * M) {
        eyre::bail!("mint not applied");
    }

    // Alice → Bob $2 (THE PAYMENT TO BE DISCLOSED).
    let (leaves, _) = pool_notes(base)?;
    let a_idx = leaves.iter().rposition(|l| *l == mp.commitment).unwrap() as u64;
    let to_bob = build_output(&bob.address(), (2 * M) as u64, &r32(tag, 2), &r32(tag, 3),
        b"invoice #42 - API usage, August").ok_or_else(|| eyre::eyre!("out"))?;
    let change1 = alice.self_note((3 * M) as u64, tag + 1);
    let (change1_ct, _) = seal_note(&change1, &alice.address(), &r32(tag, 4), b"change")
        .ok_or_else(|| eyre::eyre!("seal"))?;
    let plan1 = build_spend(&leaves, a_idx, a_note, &alice, 0, to_bob.note.clone(),
        change1.clone(), 0, [0; 32]).map_err(|e| eyre::eyre!(e))?;
    let pr = rpc(prover, "prove_spend", json!({"witness": serde_json::to_value(&plan1.witness)?}));
    let (proof1, _) = take_proof(&pr)?;
    let pay1 = submit(base, &org.sign(Tx::ShieldedSpend {
        anchor: H256(plan1.public.merkle_root), nullifier: H256(plan1.public.nullifier),
        out_commitment: H256(plan1.public.out_commitment),
        out2_commitment: H256(plan1.public.out2_commitment),
        fee: 0, credit: None, mandate: None, proof: proof1,
        stealth_ct: to_bob.stealth_ct.clone(), stealth_ct2: change1_ct,
    }));
    if !wait_tx(base, "payment to Bob committed", &pay1, || {
        pool_info_nullifiers(base) == nf0 + 1
    }) {
        eyre::bail!("payment 1 not applied");
    }

    // Alice → Carol $1 (THE PAYMENT THAT MUST STAY INVISIBLE).
    let (leaves2, _) = pool_notes(base)?;
    let c1_idx = leaves2.iter().rposition(|l| *l == plan1.public.out2_commitment).unwrap() as u64;
    let to_carol = build_output(&carol.address(), M as u64, &r32(tag, 5), &r32(tag, 6),
        b"rent share").ok_or_else(|| eyre::eyre!("out"))?;
    let change2 = alice.self_note((2 * M) as u64, tag + 2);
    let (change2_ct, _) = seal_note(&change2, &alice.address(), &r32(tag, 7), b"change")
        .ok_or_else(|| eyre::eyre!("seal"))?;
    let plan2 = build_spend(&leaves2, c1_idx, change1, &alice, 1, to_carol.note.clone(),
        change2, 0, [0; 32]).map_err(|e| eyre::eyre!(e))?;
    let pr = rpc(prover, "prove_spend", json!({"witness": serde_json::to_value(&plan2.witness)?}));
    let (proof2, _) = take_proof(&pr)?;
    let pay2 = submit(base, &org.sign(Tx::ShieldedSpend {
        anchor: H256(plan2.public.merkle_root), nullifier: H256(plan2.public.nullifier),
        out_commitment: H256(plan2.public.out_commitment),
        out2_commitment: H256(plan2.public.out2_commitment),
        fee: 0, credit: None, mandate: None, proof: proof2,
        stealth_ct: to_carol.stealth_ct.clone(), stealth_ct2: change2_ct,
    }));
    if !wait_tx(base, "payment to Carol committed", &pay2, || {
        pool_info_nullifiers(base) == nf0 + 2
    }) {
        eyre::bail!("payment 2 not applied");
    }
    println!("    ✓ pool now holds two hidden payments (Bob's and Carol's).\n");

    // ---- [2] Bob builds his ONE-TIME disclosure package -----------------------------
    println!("[2] a court/exchange asks Bob to prove HIS payment. Bob builds a package...");
    let (leaves3, entries3) = pool_notes(base)?;
    let found = scan(&bob, &entries3);
    // Pick THE payment (by its commitment) — robust even if this demo ran before on
    // the same devnet and bob's scan sees notes from an earlier run.
    let b = found
        .iter()
        .find(|d| d.commitment == to_bob.commitment)
        .ok_or_else(|| eyre::eyre!("bob's scanner did not find the payment"))?;
    let entry = entries3.iter().find(|(i, _, _)| *i == b.leaf_index).unwrap();
    let key = note_key_as_recipient(&bob, 0, &b.commitment, &entry.2)
        .ok_or_else(|| eyre::eyre!("key recovery"))?;
    let pkg = build_disclosure(&chain_id, &leaves3, b.leaf_index, bob.owner_tag(),
        entry.2.clone(), key).ok_or_else(|| eyre::eyre!("build package"))?;
    let fname = format!("disclosure-{}.json", hex::encode(&b.commitment[..4]));
    std::fs::write(&fname, serde_json::to_string_pretty(&pkg)?)?;
    println!("    ✓ wrote {fname} — hand THIS FILE to the auditor. It contains the key");
    println!("      for exactly one ciphertext, an inclusion path, and nothing else.\n");

    // ---- [3] OFFLINE verification ---------------------------------------------------
    println!("[3] the auditor verifies — OFFLINE (also try: hk-node verify-disclosure {fname})...");
    let d = verify_disclosure(&pkg).map_err(|e| eyre::eyre!("verify failed: {e}"))?;
    println!("    ✓ VERIFIED with no chain access:");
    println!("        amount     : {}", dollars(d.value as Amount));
    println!("        memo       : {:?}", String::from_utf8_lossy(&d.memo));
    println!("        commitment : {}… (tree index {})", hex::encode(&d.commitment[..8]), d.leaf_index);
    println!("        anchor     : {}… (cross-check against the chain)", hex::encode(&d.anchor[..8]));

    // ---- [4] selectivity: the package opens NOTHING else ----------------------------
    let others = entries3.iter().filter(|(i, _, _)| *i != b.leaf_index);
    let mut opened = 0;
    for (_, cm, ct) in others {
        if ct.len() > hk_crypto::mlkem::CT_LEN
            && hk_crypto::noteenc::open(&pkg.note_key, cm, &ct[hk_crypto::mlkem::CT_LEN..]).is_some()
        {
            opened += 1;
        }
    }
    println!("    ✓ the package key opened {opened} of the {} OTHER ciphertexts in the pool", entries3.len() - 1);
    println!("      — Carol's payment (and everything else) stays invisible.\n");
    if opened != 0 {
        eyre::bail!("selectivity violated");
    }

    // ---- [5] epoch viewing keys -----------------------------------------------------
    println!("[5] Alice grants the auditor an EPOCH-0 incoming viewing key (IVK)...");
    let ivk0 = alice.ivk(0);
    let seen0 = scan_with_ivk(&ivk0, &entries3).len();
    println!("    ✓ auditor sees {seen0} epoch-0 note(s) paid to Alice — discovery+decryption only:");
    println!("      no spend authority, no nullifier key, no other epochs.");

    println!("    ...a NEW payment arrives at Alice's EPOCH-1 address...");
    let a1_note = build_output(&alice.address_at(1), M as u64, &r32(tag, 8), &r32(tag, 9), b"epoch-1")
        .ok_or_else(|| eyre::eyre!("out"))?;
    let (mw1, mp1) = build_mint(&a1_note.note);
    let pr = rpc(prover, "prove_mint", json!({"witness": serde_json::to_value(&mw1)?}));
    let (mint1_proof, _) = take_proof(&pr)?;
    submit(base, &org.sign(Tx::MintToPool {
        asset: usd, value: M, commitment: H256(mp1.commitment),
        proof: mint1_proof, stealth_ct: a1_note.stealth_ct.clone(),
    }));
    if !wait("epoch-1 note committed", || balance(base, &org.id) == org0 - 6 * M) {
        eyre::bail!("epoch-1 mint not applied");
    }
    let (_, entries4) = pool_notes(base)?;
    let ivk0_after = scan_with_ivk(&ivk0, &entries4).len();
    let wallet_e1 = hk_wallet::scan_at(&alice, 1, &entries4).len();
    println!("    ✓ IVK(0) still sees {ivk0_after} note(s) — the epoch-1 payment is OUTSIDE its scope.");
    println!("    ✓ Alice's own wallet sees the epoch-1 note ({wallet_e1} found with the epoch-1 key).");
    if ivk0_after != seen0 || wallet_e1 != 1 {
        eyre::bail!("epoch scoping violated");
    }

    println!("\n=== that's CVA ===");
    println!("Confidential by default; disclosure is one payment or one epoch at a time,");
    println!("initiated by the holder, verifiable offline — and NO master key exists.\n");
    Ok(())
}

fn pool_info_nullifiers(base: &str) -> u64 {
    rpc(base, "hk_getPoolInfo", json!({}))
        .get("result")
        .and_then(|r| r.get("nullifiers"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}
