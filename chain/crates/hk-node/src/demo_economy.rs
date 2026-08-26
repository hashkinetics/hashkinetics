//! THE CLIENT DEMO — the whole machine economy in one command (~5 minutes).
//!
//!   One principal funds a fleet. Agents BUY (mandate spends), meter SERVICES at
//!   machine speed (a PayWord channel settled by one 32-byte word), get PAID privately
//!   (stealth payroll + a broker COMMISSION nobody can see), CONVERT private funds to
//!   public money (an unshield), get REFUSED by consensus when the family budget runs
//!   dry (the receipt), and DISCLOSE exactly one payment to an auditor — offline.
//!   Ends with the full ledger: who earned what, what stayed hidden, what settled.
//!
//! Run:  hk-node demo-economy http://127.0.0.1:26000 http://127.0.0.1:9911
//! Needs: fresh devnet (org must hold its full $50) + hk-prove up.

use serde_json::json;

use hk_crypto::payword::PaywordChain;
use hk_primitives::{Amount, H256};
use hk_state::tx::Tx;
use hk_state::State;
use hk_wallet::{
    build_disclosure, build_mint, build_output, build_spend, note_key_as_recipient, scan,
    seal_note, verify_disclosure, WalletKeys,
};

use crate::demo::{
    account_nonce, balance, chain_height, dollars, receipt, rpc, submit, usd, wait, wait_tx,
    Wallet,
};
use crate::demo_shielded::{pool_notes, r32, take_proof};

const M: Amount = 1_000_000;
const BIG_EXPIRY: u64 = 10_000_000;

fn pool_nfs(base: &str) -> u64 {
    rpc(base, "hk_getPoolInfo", json!({}))
        .get("result")
        .and_then(|r| r.get("nullifiers"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

pub fn run(base: &str, prover: &str) -> eyre::Result<()> {
    println!("\n=== HASHKINETICS — THE MACHINE ECONOMY, LIVE ===");
    println!("    one principal · three agents · one merchant · money you can and cannot see");
    println!("    chain: {base}   prover: {prover}\n");

    if !wait("node RPC reachable", || chain_height(base) >= 1) {
        eyre::bail!("node not reachable at {base}");
    }
    if rpc(prover, "health", json!({})).get("result").is_none() {
        eyre::bail!("hk-prove not reachable at {prover}");
    }
    let chain_id = rpc(base, "hk_chainInfo", json!({}))
        .get("result")
        .and_then(|r| r.get("chain_id"))
        .and_then(|c| c.as_str())
        .unwrap_or("hashkinetics-devnet-1")
        .to_string();

    // Cast: the five genesis accounts, in story roles.
    let mut org = Wallet::new("org"); // ACME — the principal
    let mut a = Wallet::new("agent-a"); // BUYER agent
    let mut b = Wallet::new("agent-b"); // BROKER agent
    let mut c = Wallet::new("agent-c"); // ROGUE agent
    let mut merchant = Wallet::new("merchant"); // DataVendor
    for w in [&mut org, &mut a, &mut b, &mut c, &mut merchant] {
        if let Some(n) = account_nonce(base, &w.id) {
            w.next_nonce = n;
        }
    }
    let usd = usd();
    let org0 = balance(base, &org.id);
    let mer0 = balance(base, &merchant.id);
    if org0 < 50 * M {
        eyre::bail!("org has {} — needs $50 (run on a FRESH devnet)", dollars(org0));
    }
    let tag = chain_height(base);
    let nf0 = pool_nfs(base);

    // Per-demo shielded wallets (unique seeds — never shared across demos).
    let treasury = WalletKeys::new(b"econ-treasury-master"); // ACME's private treasury
    let w_buyer = WalletKeys::new(b"econ-buyer-master");
    let w_broker = WalletKeys::new(b"econ-broker-master");

    // ---- ACT 1 · THE LAW: a $20 family envelope, deliberately oversubscribed --------
    println!("ACT 1 · ACME writes the family budget INTO CONSENSUS");
    println!("        root envelope $20 — children promised $15 + $10 + $10 = $35 (oversubscribed on purpose)");
    let (m0, ma, mb, mc) = (H256([0xE0; 32]), H256([0xE1; 32]), H256([0xE2; 32]), H256([0xE3; 32]));
    let mk = |id, parent, holder: H256, buffer_max: Amount, per_tx: Amount, initial: Amount| Tx::MandateCreate {
        id, parent, holder, asset: usd, rate_per_sec: 0,
        buffer_max, per_tx_max: per_tx, initial_buffer: initial, expiry: BIG_EXPIRY, tier: 0,
    };
    submit(base, &org.sign(mk(m0, None, org.id, 20 * M, 20 * M, 20 * M)));
    submit(base, &org.sign(mk(ma, Some(m0), a.id, 15 * M, 15 * M, 15 * M)));
    submit(base, &org.sign(mk(mb, Some(m0), b.id, 10 * M, 10 * M, 10 * M)));
    submit(base, &org.sign(mk(mc, Some(m0), c.id, 10 * M, 10 * M, 10 * M)));
    let org_n0 = org.next_nonce;
    if !wait("mandate tree on-chain", || account_nonce(base, &org.id) == Some(org_n0)) {
        eyre::bail!("mandate tree not applied");
    }
    println!("        ✓ delegation is a promise; the envelope is the law.\n");

    // ---- ACT 2 · THE MARKET: an agent BUYS, an agent METERS, a merchant SELLS -------
    println!("ACT 2 · The market opens");
    println!("        BUYER agent purchases a dataset — $8, authorized by its leaf, paid by ACME's root:");
    let buy = submit(base, &a.sign(Tx::MandateSpend { leaf: ma, to: merchant.id, amount: 8 * M }));
    if !wait_tx(base, "dataset purchased", &buy, || balance(base, &merchant.id) == mer0 + 8 * M) {
        eyre::bail!("purchase not applied");
    }
    println!("        ✓ DataVendor +$8.00 (org pays, agent authorizes — the allowance model).\n");

    println!("        BROKER agent opens a metered API channel: 500 calls × $0.01 = $5 escrow, drawn ONCE:");
    let chain = PaywordChain::mint(b"econ-payword", b"econ-session", 500);
    let tip = H256(chain.tip());
    let b_nonce = account_nonce(base, &b.id).unwrap_or(1);
    let ch_id = State::derive_channel_id(&b.id, &merchant.id, &tip, b_nonce);
    submit(base, &b.sign(Tx::ChannelOpen {
        id: ch_id, mandate: mb, payee: merchant.id, asset: usd,
        tip, unit_price: 10_000, max_steps: 500, expiry: BIG_EXPIRY,
    }));
    if !wait("channel escrowed", || balance(base, &org.id) == org0 - 13 * M) {
        eyre::bail!("channel open not applied");
    }
    println!("        ... 320 calls happen OFF-CHAIN at machine speed (one hash each, no signatures) ...");
    let word = H256(chain.pay(320).expect("word 320"));
    let settle = submit(base, &merchant.sign(Tx::ChannelSettle { id: ch_id, word, step: 320 }));
    if !wait_tx(base, "session settled", &settle, || {
        balance(base, &merchant.id) == mer0 + 8 * M + 3_200_000
    }) {
        eyre::bail!("settle not applied");
    }
    println!("        ✓ ONE 32-byte word settled 320 payments in ONE tx — DataVendor +$3.20.\n");

    // ---- ACT 3 · THE PRIVATE SIDE: payroll + a commission nobody can see ------------
    println!("ACT 3 · The private side — ACME shields a $10 treasury");
    let t_note = treasury.self_note((10 * M) as u64, tag);
    let (mw, mp) = build_mint(&t_note);
    let (t_ct, _) = seal_note(&t_note, &treasury.address(), &r32(tag, 1), b"treasury")
        .ok_or_else(|| eyre::eyre!("seal"))?;
    let pr = rpc(prover, "prove_mint", json!({"witness": serde_json::to_value(&mw)?, "mode": "compressed"}));
    let (proof, ms) = take_proof(&pr)?;
    submit(base, &org.sign(Tx::MintToPool {
        asset: usd, value: 10 * M, commitment: H256(mp.commitment), proof, stealth_ct: t_ct,
    }));
    if !wait("treasury shielded", || balance(base, &org.id) == org0 - 23 * M) {
        eyre::bail!("mint not applied");
    }
    println!("        ✓ $10 entered the pool (proof {ms} ms). From here, amounts and recipients VANISH.\n");

    // Two stealth payments off the treasury note: a $3 bonus and a $1 broker commission.
    struct Pay<'x> { amount: u64, to: &'x WalletKeys, memo: &'x [u8], label: &'x str }
    let pays = [
        Pay { amount: 3, to: &w_buyer, memo: b"Q3 bonus - good buying", label: "$3 BONUS to the buyer agent" },
        Pay { amount: 1, to: &w_broker, memo: b"2% commission - dataset deal", label: "$1 COMMISSION to the broker (its cut of the deal)" },
    ];
    let mut t_cur = t_note;
    for (i, p) in pays.iter().enumerate() {
        println!("        stealth payment {}: {} — fee 0, ZERO transparent trace:", i + 1, p.label);
        let (leaves, _) = pool_notes(base)?;
        let cm = hk_spend_circuit::commit_note(&t_cur);
        let idx = leaves.iter().rposition(|l| *l == cm).unwrap() as u64;
        let out = build_output(&p.to.address(), p.amount * M as u64, &r32(tag, 10 + i as u8), &r32(tag, 20 + i as u8), p.memo)
            .ok_or_else(|| eyre::eyre!("out"))?;
        let change = treasury.self_note(t_cur.value - p.amount * M as u64, tag + 1 + i as u64);
        let (change_ct, _) = seal_note(&change, &treasury.address(), &r32(tag, 30 + i as u8), b"change")
            .ok_or_else(|| eyre::eyre!("seal"))?;
        let plan = build_spend(&leaves, idx, t_cur.clone(), &treasury, i as u32, out.note.clone(), change.clone(), 0, [0; 32])
            .map_err(|e| eyre::eyre!(e))?;
        let pr = rpc(prover, "prove_spend", json!({"witness": serde_json::to_value(&plan.witness)?, "mode": "compressed"}));
        let (proof, _) = take_proof(&pr)?;
        let id = submit(base, &org.sign(Tx::ShieldedSpend {
            anchor: H256(plan.public.merkle_root), nullifier: H256(plan.public.nullifier),
            out_commitment: H256(plan.public.out_commitment), out2_commitment: H256(plan.public.out2_commitment),
            fee: 0, credit: None, mandate: None, proof,
            stealth_ct: out.stealth_ct.clone(), stealth_ct2: change_ct,
        }));
        let want = nf0 + 1 + i as u64;
        if !wait_tx(base, "stealth payment committed", &id, || pool_nfs(base) == want) {
            eyre::bail!("stealth payment {} not applied", i + 1);
        }
        t_cur = change;
    }
    println!("        ✓ the chain recorded two nullifiers and four commitments. WHO got WHAT: invisible.\n");

    // Discovery: each wallet finds its own money by scanning; nobody else can.
    println!("        The agents' wallets SCAN the pool (trial decapsulation):");
    let (_, entries) = pool_notes(base)?;
    let found_buyer = scan(&w_buyer, &entries);
    let found_broker = scan(&w_broker, &entries);
    let spy = WalletKeys::new(b"econ-competitor-master");
    let found_spy = scan(&spy, &entries);
    let show = |name: &str, f: &[hk_wallet::Discovered]| {
        for d in f {
            println!("        ✓ {name} DISCOVERED ${} — memo: {:?}", d.note.value / M as u64,
                String::from_utf8_lossy(&d.memo));
        }
    };
    show("BUYER ", &found_buyer);
    show("BROKER", &found_broker);
    println!("        ✓ a competitor scanning the same pool sees: {} notes.\n", found_spy.len());
    let buyer_note = found_buyer
        .iter()
        .find(|d| d.note.value == (3 * M) as u64)
        .ok_or_else(|| eyre::eyre!("buyer bonus not discovered"))?;
    let broker_disc = found_broker
        .iter()
        .find(|d| d.note.value == (1 * M) as u64)
        .ok_or_else(|| eyre::eyre!("broker commission not discovered"))?;

    // ---- ACT 4 · PRIVATE → PUBLIC: the buyer pays a public invoice ------------------
    println!("ACT 4 · The buyer agent converts private money into a public payment");
    println!("        it spends the DISCOVERED $3 note: $2 unshields to DataVendor, $1 stays hidden change:");
    let (leaves2, _) = pool_notes(base)?;
    let out_self = w_buyer.self_note((1 * M) as u64, tag + 40);
    let (self_ct, _) = seal_note(&out_self, &w_buyer.address(), &r32(tag, 41), b"change")
        .ok_or_else(|| eyre::eyre!("seal"))?;
    let dummy = hk_spend_circuit::Note { value: 0, owner: [0; 32], rho: r32(tag, 42), rcm: r32(tag, 43) };
    let plan = build_spend(
        &leaves2, buyer_note.leaf_index, buyer_note.note.clone(), &w_buyer, 0,
        out_self, dummy, (2 * M) as u64, merchant.id.0,
    ).map_err(|e| eyre::eyre!(e))?;
    let pr = rpc(prover, "prove_spend", json!({"witness": serde_json::to_value(&plan.witness)?, "mode": "compressed"}));
    let (proof, _) = take_proof(&pr)?;
    let id = submit(base, &a.sign(Tx::ShieldedSpend {
        anchor: H256(plan.public.merkle_root), nullifier: H256(plan.public.nullifier),
        out_commitment: H256(plan.public.out_commitment), out2_commitment: H256(plan.public.out2_commitment),
        fee: 2 * M, credit: Some(merchant.id), mandate: None, proof,
        stealth_ct: self_ct, stealth_ct2: Vec::new(),
    }));
    if !wait_tx(base, "unshield committed", &id, || {
        balance(base, &merchant.id) == mer0 + 8 * M + 3_200_000 + 2 * M
    }) {
        eyre::bail!("unshield not applied");
    }
    println!("        ✓ DataVendor +$2.00 public — the agent OWNS what it discovered.\n");

    // ---- ACT 5 · THE ROGUE: consensus refuses what it cannot even see ---------------
    println!("ACT 5 · The rogue agent tries to overspend the FAMILY budget");
    println!("        its own leaf allows $10 — but the $20 family envelope has $7 left ($8 + $5 spent):");
    let rogue = submit(base, &c.sign(Tx::MandateSpend { leaf: mc, to: merchant.id, amount: 10 * M }));
    let mut iconic = String::new();
    wait("consensus verdict", || {
        if let Some(r) = receipt(base, &rogue) {
            println!("        ⛔ {r}");
            iconic = r;
            true
        } else { false }
    });
    c.rollback();
    if !iconic.contains("insufficient buffer") {
        eyre::bail!("expected the envelope refusal, got: {iconic}");
    }
    println!("        ✓ funds did not move. The org's law held — enforced BY THE CHAIN.\n");

    // ---- ACT 6 · THE AUDITOR: disclose exactly one payment, offline -----------------
    println!("ACT 6 · A regulator asks about the broker's commission. The broker discloses THAT payment only:");
    let (leaves3, entries3) = pool_notes(base)?;
    let entry = entries3.iter().find(|(i, _, _)| *i == broker_disc.leaf_index)
        .ok_or_else(|| eyre::eyre!("entry"))?;
    let key = note_key_as_recipient(&w_broker, 0, &broker_disc.commitment, &entry.2)
        .ok_or_else(|| eyre::eyre!("key recovery"))?;
    let pkg = build_disclosure(&chain_id, &leaves3, broker_disc.leaf_index, w_broker.owner_tag(), entry.2.clone(), key)
        .ok_or_else(|| eyre::eyre!("package"))?;
    let d = verify_disclosure(&pkg).map_err(|e| eyre::eyre!("offline verify failed: {e}"))?;
    println!("        ✓ VERIFIED OFFLINE (no chain access): ${} — memo {:?}",
        d.value / M as u64, String::from_utf8_lossy(&d.memo));
    let mut opened = 0;
    for (i, cm, ct) in entries3.iter().filter(|(i, _, _)| *i != broker_disc.leaf_index) {
        let _ = i;
        if ct.len() > hk_crypto::mlkem::CT_LEN
            && hk_crypto::noteenc::open(&pkg.note_key, cm, &ct[hk_crypto::mlkem::CT_LEN..]).is_some()
        { opened += 1; }
    }
    println!("        ✓ the same key opened {opened} of the {} OTHER payments — scoped, one-time, no master key.\n",
        entries3.len() - 1);
    if opened != 0 { eyre::bail!("selectivity violated"); }

    // ---- THE LEDGER -----------------------------------------------------------------
    let pool = rpc(base, "hk_getPoolInfo", json!({}));
    let hidden = pool.get("result").and_then(|r| r.get("total_shielded")).and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Amount>().ok()).unwrap_or(0);
    println!("=== THE LEDGER — what the economy did in ~5 minutes ===");
    println!("  ACME (principal)      : {} transparent  (funded everything, kept control)", dollars(balance(base, &org.id)));
    println!("  DataVendor (merchant) : {} earned — $8 sale + $3.20 metered session + $2 unshielded invoice", dollars(balance(base, &merchant.id) - mer0));
    println!("  Channel               : 320 machine-speed payments settled by ONE 32-byte word");
    println!("  Hidden economy        : {} still shielded — bonuses, commission cut, change: all invisible", dollars(hidden));
    println!("  The refusal           : \"{}\"", iconic);
    println!("  The disclosure        : one payment, verified offline, opened nothing else");
    println!();
    println!("Agents bought, sold, metered, earned commissions, moved money publicly and privately —");
    println!("and the one time an agent broke the rules, THE CHAIN said no. That is HashKinetics.");
    Ok(())
}
