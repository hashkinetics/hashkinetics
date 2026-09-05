//! wallet_cli — HashKinetics wallet v1 (P3.0b / WS-A public surface).
//!
//! A real user wallet over the node RPC + hk-prove, built on the SAME lib code every
//! demo proved (`hk-wallet` for the shielded side, the L-ratchet signer for the
//! transparent side). Commands:
//!
//!   hk-node wallet init     <DIR> <ACCOUNT> [RPC]
//!   hk-node wallet status   <DIR> [RPC]
//!   hk-node wallet address  <DIR> [RPC]
//!   hk-node wallet scan     <DIR> [RPC]
//!   hk-node wallet transfer <DIR> <TO(name|hex64)> <USD> [RPC]
//!   hk-node wallet shield   <DIR> <USD> [RPC] [PROVER]
//!   hk-node wallet unshield <DIR> <USD> [RPC] [PROVER]
//!   hk-node wallet pay      <DIR> <HKADDR> <USD> [MEMO] [RPC] [PROVER]
//!   hk-node wallet disclose <DIR> <COMMITMENT-hex64> <OUT.json> [RPC]
//!
//! Devnet-grade truths (stated, not hidden):
//! - **Accounts are genesis-only until WS-F's account-creation tx** — `init` binds to a
//!   genesis account name (org / agent-a / agent-b / agent-c / merchant).
//! - **One input note per spend (circuit v3)**: a payment must fit in a single note;
//!   consolidate by paying yourself.
//! - The OTS spend-tree index and note tags are persisted **reserve-then-advance**
//!   (written BEFORE use — a crash can waste an index, never reuse one). Capacity 64
//!   spends per address at the default h=6; rotate the shield master after that.
//! - Randomness for coins/entropy is OS-CSPRNG (`rand`), unlike the deterministic demos.

use std::path::{Path, PathBuf};

use eyre::{eyre, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

use hk_primitives::{Amount, H256};
use hk_spend_circuit::{nullifier, Hash, Note};
use hk_state::tx::Tx;
use hk_wallet::{
    build_disclosure, build_mint, build_output, build_spend, epoch_of, note_key_as_recipient,
    scan_at, seal_note, Address, Discovered, WalletKeys,
};

use crate::demo::{account_id, account_nonce, balance, chain_height, dollars, rpc, submit, usd, Wallet};
use crate::demo_shielded::{pool_notes, take_proof};

const M: Amount = 1_000_000;
const DEFAULT_RPC: &str = "http://127.0.0.1:26000";
const DEFAULT_PROVER: &str = "http://127.0.0.1:9911";

// ---------------------------------------------------------------------------
// The wallet file (reserve-then-advance for every one-time value)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct WalletFile {
    version: u8,
    /// Genesis account this wallet signs transparent envelopes as (WS-F lifts this).
    account: String,
    /// Shielded master seed, hex (distinct namespace from the demo wallets).
    shield_master_hex: String,
    /// Next NEVER-REUSED spend-tree leaf. Persisted before use.
    next_ots_index: u32,
    /// Next self-note tag (rho/rcm derivation — reuse would link notes). Persisted before use.
    next_note_tag: u64,
}

fn wpath(dir: &Path) -> PathBuf {
    dir.join("wallet.json")
}

/// K1 (v0.16.0): `wallet.json` may be sealed — same passphrase source as `account.json`
/// (`HK_WALLET_PASSPHRASE` …); `hk-node account-seal DIR` seals both in one go.
fn load(dir: &Path) -> Result<WalletFile> {
    let p = wpath(dir);
    if !p.exists() {
        return Err(eyre!("no wallet at {} — run `wallet init` first", dir.display()));
    }
    let raw = crate::keys::read_secret(&p, crate::keys::Secret::Wallet)?;
    Ok(serde_json::from_str(&raw)?)
}

fn save(dir: &Path, w: &WalletFile) -> Result<()> {
    crate::keys::write_secret(&wpath(dir), &serde_json::to_string_pretty(w)?, crate::keys::Secret::Wallet)
}

fn keys(w: &WalletFile) -> Result<WalletKeys> {
    Ok(WalletKeys::new(&hex::decode(&w.shield_master_hex)?))
}

/// Reserve the next OTS leaf: advance + persist BEFORE the caller uses it.
fn reserve_ots(dir: &Path, w: &mut WalletFile) -> Result<u32> {
    let i = w.next_ots_index;
    if i >= 64 {
        return Err(eyre!(
            "spend-tree exhausted ({i}/64 one-time leaves used) — rotate the shield master (new wallet dir), sweep funds over"
        ));
    }
    w.next_ots_index += 1;
    save(dir, w)?;
    Ok(i)
}

/// Reserve a fresh note tag the same way.
fn reserve_tag(dir: &Path, w: &mut WalletFile) -> Result<u64> {
    let t = w.next_note_tag;
    w.next_note_tag += 1;
    save(dir, w)?;
    Ok(t)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn parse_usd(s: &str) -> Result<Amount> {
    let mut it = s.trim().trim_start_matches('$').split('.');
    let whole: Amount = it.next().unwrap_or("").parse().map_err(|_| eyre!("bad amount '{s}'"))?;
    let frac = it.next().unwrap_or("");
    if it.next().is_some() || frac.len() > 6 {
        return Err(eyre!("bad amount '{s}' (max 6 decimal places)"));
    }
    let frac_n: Amount =
        if frac.is_empty() { 0 } else { frac.parse().map_err(|_| eyre!("bad amount '{s}'"))? };
    Ok(whole * M + frac_n * 10u128.pow(6 - frac.len() as u32))
}

fn fresh32() -> [u8; 32] {
    rand::random()
}

/// The transparent signer, nonce synced from the chain (the account must EXIST).
fn signer(w: &WalletFile, base: &str) -> Result<Wallet> {
    let mut s = Wallet::new(&w.account);
    match account_nonce(base, &s.id) {
        Some(n) => {
            s.next_nonce = n;
            Ok(s)
        }
        None => Err(eyre!(
            "account '{}' does not exist on this chain — devnet accounts are genesis-only \
             until the account-creation tx lands (WS-F). Known: org, agent-a, agent-b, agent-c, merchant",
            w.account
        )),
    }
}

fn addr_encode(a: &Address) -> String {
    format!("hkaddr:{}{}", hex::encode(a.tag), hex::encode(&a.kem_pk))
}

fn addr_decode(s: &str) -> Result<Address> {
    let h = s.strip_prefix("hkaddr:").ok_or_else(|| eyre!("address must start with 'hkaddr:'"))?;
    let b = hex::decode(h.trim())?;
    if b.len() <= 32 {
        return Err(eyre!("address too short"));
    }
    Ok(Address { tag: b[..32].try_into().unwrap(), kem_pk: b[32..].to_vec() })
}

fn nullifier_spent(base: &str, nf: &Hash) -> bool {
    rpc(base, "hk_nullifierSpent", json!({"nullifier": hex::encode(nf)}))
        .get("result")
        .and_then(|r| r.get("spent"))
        .and_then(|s| s.as_bool())
        .unwrap_or(false)
}

fn require_prover(prover: &str) -> Result<()> {
    let h = rpc(prover, "health", json!({}));
    if h.get("result").is_none() {
        return Err(eyre!(
            "hk-prove not reachable at {prover} — start it: cd zkvm-bakeoff/sp1/script && cargo run --release --bin serve"
        ));
    }
    Ok(())
}

/// All notes this wallet ever received (epochs 0..=current), with spent status.
fn my_notes(base: &str, k: &WalletKeys) -> Result<(Vec<Hash>, Vec<(Discovered, bool)>)> {
    let (leaves, entries) = pool_notes(base)?;
    let cur = epoch_of(chain_height(base));
    let nk = k.nk();
    let mut out: Vec<(Discovered, bool)> = Vec::new();
    for e in 0..=cur {
        for d in scan_at(k, e, &entries) {
            if !out.iter().any(|(x, _)| x.commitment == d.commitment) {
                let spent = nullifier_spent(base, &nullifier(&nk, &d.note.rho));
                out.push((d, spent));
            }
        }
    }
    Ok((leaves, out))
}

/// Pick the SMALLEST single unspent note covering `amt` (circuit v3: one input/spend).
fn pick_note(notes: &[(Discovered, bool)], amt: Amount) -> Result<Discovered> {
    let mut c: Vec<&Discovered> = notes
        .iter()
        .filter(|(d, spent)| !spent && (d.note.value as Amount) >= amt)
        .map(|(d, _)| d)
        .collect();
    if c.is_empty() {
        let have: Vec<String> = notes
            .iter()
            .filter(|(_, s)| !s)
            .map(|(d, _)| dollars(d.note.value as Amount))
            .collect();
        return Err(eyre!(
            "no single note covers {} — unspent notes: [{}]. Circuit v3 spends ONE note per tx; consolidate by paying yourself first",
            dollars(amt),
            have.join(", ")
        ));
    }
    c.sort_by_key(|d| d.note.value);
    Ok(c[0].clone())
}

fn dummy_note() -> Note {
    Note { value: 0, owner: [0; 32], rho: fresh32(), rcm: fresh32() }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

pub fn run(args: &[String]) -> Result<()> {
    let usage = "usage: hk-node wallet <init DIR ACCOUNT [RPC] | status DIR [RPC] | address DIR [RPC] | scan DIR [RPC] | transfer DIR TO USD [RPC] | shield DIR USD [RPC] [PROVER] | unshield DIR USD [RPC] [PROVER] | pay DIR HKADDR USD [MEMO] [RPC] [PROVER] | disclose DIR COMMITMENT OUT.json [RPC]>";
    let cmd = args.first().map(String::as_str).ok_or_else(|| eyre!(usage))?;
    let dir = PathBuf::from(args.get(1).ok_or_else(|| eyre!(usage))?);
    match cmd {
        "init" => {
            let account = args.get(2).ok_or_else(|| eyre!(usage))?.clone();
            let base = args.get(3).cloned().unwrap_or_else(|| DEFAULT_RPC.into());
            if wpath(&dir).exists() {
                return Err(eyre!("{} already exists — refusing to overwrite key material", wpath(&dir).display()));
            }
            std::fs::create_dir_all(&dir)?;
            let w = WalletFile {
                version: 1,
                account: account.clone(),
                shield_master_hex: hex::encode(fresh32()),
                next_ots_index: 0,
                next_note_tag: 1,
            };
            save(&dir, &w)?;
            let k = keys(&w)?;
            println!("✓ wallet created at {}", wpath(&dir).display());
            println!("  transparent account : {} ({})", account, hex::encode(account_id(&account).0));
            println!("  stealth address     : {}", addr_encode(&k.address_at(0)));
            match account_nonce(&base, &account_id(&account)) {
                Some(n) => println!("  on-chain            : ✓ exists (nonce {n}, balance {})", dollars(balance(&base, &account_id(&account)))),
                None => println!("  on-chain            : ⚠ NOT FOUND on {base} — devnet accounts are genesis-only until WS-F"),
            }
            println!("  ⚠ back up wallet.json — it contains the shield master seed.");
            Ok(())
        }
        "status" => {
            let base = args.get(2).cloned().unwrap_or_else(|| DEFAULT_RPC.into());
            let w = load(&dir)?;
            let k = keys(&w)?;
            let id = account_id(&w.account);
            println!("=== wallet status — {} ===", w.account);
            println!("  chain height        : {}", chain_height(&base));
            match account_nonce(&base, &id) {
                Some(n) => println!("  transparent         : {} (nonce {n})", dollars(balance(&base, &id))),
                None => println!("  transparent         : account not on this chain"),
            }
            let (_, notes) = my_notes(&base, &k)?;
            let unspent: Vec<&Discovered> = notes.iter().filter(|(_, s)| !s).map(|(d, _)| d).collect();
            let total: Amount = unspent.iter().map(|d| d.note.value as Amount).sum();
            println!("  shielded (mine)     : {} across {} unspent note(s) ({} total discovered)", dollars(total), unspent.len(), notes.len());
            for d in &unspent {
                println!("    · {} @ tree index {}  memo {:?}", dollars(d.note.value as Amount), d.leaf_index, String::from_utf8_lossy(&d.memo));
            }
            println!("  spend-tree leaves   : {}/64 used", w.next_ots_index);
            println!("  receiving address   : {}", addr_encode(&k.address_at(epoch_of(chain_height(&base)))));
            Ok(())
        }
        "address" => {
            let base = args.get(2).cloned().unwrap_or_else(|| DEFAULT_RPC.into());
            let k = keys(&load(&dir)?)?;
            let epoch = epoch_of(chain_height(&base));
            println!("{}", addr_encode(&k.address_at(epoch)));
            eprintln!("(epoch {epoch} — hand this to senders; scanning covers all epochs)");
            Ok(())
        }
        "scan" => {
            let base = args.get(2).cloned().unwrap_or_else(|| DEFAULT_RPC.into());
            let k = keys(&load(&dir)?)?;
            let (_, notes) = my_notes(&base, &k)?;
            if notes.is_empty() {
                println!("no notes addressed to this wallet (scanned every pool ciphertext by trial decapsulation).");
                return Ok(());
            }
            for (d, spent) in &notes {
                println!(
                    "{} {} @ index {}  memo {:?}\n       commitment {}",
                    if *spent { "SPENT " } else { "LIVE  " },
                    dollars(d.note.value as Amount),
                    d.leaf_index,
                    String::from_utf8_lossy(&d.memo),
                    hex::encode(d.commitment)
                );
            }
            Ok(())
        }
        "transfer" => {
            let to_s = args.get(2).ok_or_else(|| eyre!(usage))?;
            let amt = parse_usd(args.get(3).ok_or_else(|| eyre!(usage))?)?;
            let base = args.get(4).cloned().unwrap_or_else(|| DEFAULT_RPC.into());
            let w = load(&dir)?;
            let mut s = signer(&w, &base)?;
            let to = if to_s.len() == 64 {
                H256(hex::decode(to_s)?.as_slice().try_into().map_err(|_| eyre!("bad id"))?)
            } else {
                account_id(to_s)
            };
            let before = balance(&base, &to);
            let txid = submit(&base, &s.sign(Tx::Transfer { to, asset: usd(), amount: amt }));
            let ok = crate::demo::wait_tx(&base, "transfer committed", &txid, || balance(&base, &to) == before + amt);
            if ok {
                println!("✓ sent {} → {} (their balance: {})", dollars(amt), to_s, dollars(balance(&base, &to)));
            }
            Ok(())
        }
        "shield" => {
            let amt = parse_usd(args.get(2).ok_or_else(|| eyre!(usage))?)?;
            let base = args.get(3).cloned().unwrap_or_else(|| DEFAULT_RPC.into());
            let prover = args.get(4).cloned().unwrap_or_else(|| DEFAULT_PROVER.into());
            require_prover(&prover)?;
            let mut w = load(&dir)?;
            let k = keys(&w)?;
            let mut s = signer(&w, &base)?;
            let my0 = balance(&base, &s.id);
            if my0 < amt {
                return Err(eyre!("transparent balance {} < {}", dollars(my0), dollars(amt)));
            }
            let tag = reserve_tag(&dir, &mut w)?;
            let note = k.self_note(amt as u64, tag);
            let (witness, public) = build_mint(&note);
            let epoch = epoch_of(chain_height(&base));
            let (ct, _) = seal_note(&note, &k.address_at(epoch), &fresh32(), b"shield")
                .ok_or_else(|| eyre!("seal failed"))?;
            println!("proving MINT (GPU)…");
            let pr = rpc(&prover, "prove_mint", json!({"witness": serde_json::to_value(&witness)?}));
            let (proof, ms) = take_proof(&pr)?;
            println!("✓ proof in {ms} ms — submitting");
            let txid = submit(&base, &s.sign(Tx::MintToPool {
                asset: usd(),
                value: amt,
                commitment: H256(public.commitment),
                proof,
                stealth_ct: ct,
            }));
            if crate::demo::wait_tx(&base, "shield committed", &txid, || balance(&base, &s.id) == my0 - amt) {
                println!("✓ {} shielded. It is now invisible — run `wallet scan` to see it as yours.", dollars(amt));
            }
            Ok(())
        }
        "unshield" => {
            let amt = parse_usd(args.get(2).ok_or_else(|| eyre!(usage))?)?;
            let base = args.get(3).cloned().unwrap_or_else(|| DEFAULT_RPC.into());
            let prover = args.get(4).cloned().unwrap_or_else(|| DEFAULT_PROVER.into());
            require_prover(&prover)?;
            let mut w = load(&dir)?;
            let k = keys(&w)?;
            let mut s = signer(&w, &base)?;
            let (leaves, notes) = my_notes(&base, &k)?;
            let input = pick_note(&notes, amt)?;
            let change_v = input.note.value as Amount - amt;
            let tag = reserve_tag(&dir, &mut w)?;
            let ots = reserve_ots(&dir, &mut w)?;
            let change = k.self_note(change_v as u64, tag);
            let epoch = epoch_of(chain_height(&base));
            let (change_ct, _) = seal_note(&change, &k.address_at(epoch), &fresh32(), b"change")
                .ok_or_else(|| eyre!("seal failed"))?;
            let plan = build_spend(&leaves, input.leaf_index, input.note.clone(), &k, ots, change, dummy_note(), amt as u64, s.id.0)
                .map_err(|e| eyre!("build_spend: {e}"))?;
            println!("proving SPEND (GPU)…");
            let pr = rpc(&prover, "prove_spend", json!({"witness": serde_json::to_value(&plan.witness)?}));
            let (proof, ms) = take_proof(&pr)?;
            println!("✓ proof in {ms} ms — submitting");
            let my0 = balance(&base, &s.id);
            let txid = submit(&base, &s.sign(Tx::ShieldedSpend {
                anchor: H256(plan.public.merkle_root),
                nullifier: H256(plan.public.nullifier),
                out_commitment: H256(plan.public.out_commitment),
                out2_commitment: H256(plan.public.out2_commitment),
                fee: amt,
                credit: Some(s.id),
                mandate: None,
                proof,
                stealth_ct: change_ct,
                stealth_ct2: Vec::new(),
            }));
            if crate::demo::wait_tx(&base, "unshield committed", &txid, || balance(&base, &s.id) == my0 + amt) {
                println!("✓ {} unshielded to your transparent account ({} change went back into hiding).", dollars(amt), dollars(change_v));
            }
            Ok(())
        }
        "pay" => {
            let to = addr_decode(args.get(2).ok_or_else(|| eyre!(usage))?)?;
            let amt = parse_usd(args.get(3).ok_or_else(|| eyre!(usage))?)?;
            // MEMO is optional; RPC/PROVER follow it positionally when present.
            let (memo, base, prover) = match (args.get(4), args.get(5), args.get(6)) {
                (Some(m), b, p) if !m.starts_with("http") => (
                    m.clone(),
                    b.cloned().unwrap_or_else(|| DEFAULT_RPC.into()),
                    p.cloned().unwrap_or_else(|| DEFAULT_PROVER.into()),
                ),
                (b, p, _) => (
                    String::new(),
                    b.cloned().unwrap_or_else(|| DEFAULT_RPC.into()),
                    p.cloned().unwrap_or_else(|| DEFAULT_PROVER.into()),
                ),
            };
            require_prover(&prover)?;
            let mut w = load(&dir)?;
            let k = keys(&w)?;
            let mut s = signer(&w, &base)?;
            let (leaves, notes) = my_notes(&base, &k)?;
            let input = pick_note(&notes, amt)?;
            let change_v = input.note.value as Amount - amt;
            let out = build_output(&to, amt as u64, &fresh32(), &fresh32(), memo.as_bytes())
                .ok_or_else(|| eyre!("build output (bad recipient address?)"))?;
            let tag = reserve_tag(&dir, &mut w)?;
            let ots = reserve_ots(&dir, &mut w)?;
            let change = k.self_note(change_v as u64, tag);
            let epoch = epoch_of(chain_height(&base));
            let (change_ct, _) = seal_note(&change, &k.address_at(epoch), &fresh32(), b"change")
                .ok_or_else(|| eyre!("seal failed"))?;
            let plan = build_spend(&leaves, input.leaf_index, input.note.clone(), &k, ots, out.note.clone(), change, 0, [0; 32])
                .map_err(|e| eyre!("build_spend: {e}"))?;
            println!("proving SPEND (GPU)…");
            let pr = rpc(&prover, "prove_spend", json!({"witness": serde_json::to_value(&plan.witness)?}));
            let (proof, ms) = take_proof(&pr)?;
            println!("✓ proof in {ms} ms — submitting (fee 0: zero transparent trace)");
            let nf = plan.public.nullifier;
            let txid = submit(&base, &s.sign(Tx::ShieldedSpend {
                anchor: H256(plan.public.merkle_root),
                nullifier: H256(nf),
                out_commitment: H256(plan.public.out_commitment),
                out2_commitment: H256(plan.public.out2_commitment),
                fee: 0,
                credit: None,
                mandate: None,
                proof,
                stealth_ct: out.stealth_ct.clone(),
                stealth_ct2: change_ct,
            }));
            if crate::demo::wait_tx(&base, "stealth payment committed", &txid, || nullifier_spent(&base, &nf)) {
                println!("✓ {} sent, fully shielded. The chain saw one nullifier and two commitments —", dollars(amt));
                println!("  who paid whom: invisible. The recipient discovers it by scanning.");
                println!("  ({} change returned to you; keep wallet.json — it holds your disclosure capability.)", dollars(change_v));
            }
            Ok(())
        }
        "disclose" => {
            let cm_hex = args.get(2).ok_or_else(|| eyre!(usage))?;
            let out_path = args.get(3).ok_or_else(|| eyre!(usage))?;
            let base = args.get(4).cloned().unwrap_or_else(|| DEFAULT_RPC.into());
            let w = load(&dir)?;
            let k = keys(&w)?;
            let cm_b = hex::decode(cm_hex)?;
            let cm: Hash = cm_b.as_slice().try_into().map_err(|_| eyre!("commitment must be 32 bytes hex"))?;
            let (leaves, entries) = pool_notes(&base)?;
            let (idx, _, ct) = entries
                .iter()
                .find(|(_, c, _)| *c == cm)
                .cloned()
                .ok_or_else(|| eyre!("commitment not found in the pool"))?;
            // Recover the one-time note key as the RECIPIENT. ML-KEM decapsulation
            // NEVER fails — a wrong epoch's key yields pseudorandom garbage (implicit
            // rejection), so Some() proves nothing: VALIDATE each candidate by opening
            // the AEAD before packaging anything.
            let cur = epoch_of(chain_height(&base));
            let key = (0..=cur)
                .filter_map(|e| note_key_as_recipient(&k, e, &cm, &ct))
                .find(|key| {
                    ct.len() > hk_crypto::mlkem::CT_LEN
                        && hk_crypto::noteenc::open(key, &cm, &ct[hk_crypto::mlkem::CT_LEN..])
                            .is_some()
                })
                .ok_or_else(|| eyre!("this wallet cannot open that ciphertext (not the recipient)"))?;
            let chain_id = rpc(&base, "hk_chainInfo", json!({}))
                .get("result")
                .and_then(|r| r.get("chain_id"))
                .and_then(|c| c.as_str())
                .unwrap_or("hashkinetics-devnet-1")
                .to_string();
            let pkg = build_disclosure(&chain_id, &leaves, idx, k.owner_tag(), ct, key)
                .ok_or_else(|| eyre!("package build failed"))?;
            std::fs::write(out_path, serde_json::to_string_pretty(&pkg)?)?;
            println!("✓ one-time disclosure package written to {out_path}");
            println!("  It opens EXACTLY this payment and nothing else — no spend authority,");
            println!("  no other notes, no future visibility. Verify offline:");
            println!("    hk-node verify-disclosure {out_path}");
            Ok(())
        }
        other => Err(eyre!("unknown wallet command '{other}'\n{usage}")),
    }
}
