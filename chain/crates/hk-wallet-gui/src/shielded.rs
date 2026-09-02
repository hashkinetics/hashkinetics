//! U3v2 — the shielded side of the desktop wallet, over the public prover.
//!
//! Exactly the flow the CLI wallet (`hk-node wallet shield|unshield|pay|scan|disclose`)
//! and the P2 demos proved, carried onto the L-ratchet account the GUI already owns:
//!
//! - **Shield**: transparent → pool. A self-note is minted (STARK via `prove_mint`) and
//!   sealed to our own current-epoch stealth address, then `Tx::MintToPool` moves the
//!   value out of the transparent balance. The envelope pays the U4 fee on top.
//! - **Unshield**: pool → transparent. One input note (circuit v3: one note per spend),
//!   change sealed back to us, the public `fee` field credits our account.
//! - **Pay**: a fully shielded payment to an `hkaddr:` — the chain sees one nullifier and
//!   two commitments. (The envelope signer is still visible, exactly as before; the U4
//!   fee comes from our transparent balance, so keep a few micro there.)
//! - **Scan**: trial-decapsulation over every pool ciphertext, all epochs, spent status
//!   from `hk_nullifierSpent`.
//! - **Disclose**: a one-time package that opens ONE received payment for an auditor —
//!   no spend authority, no other notes, no future visibility.
//!
//! Key material: `shield.json` next to `account.json` holds its own random master seed
//! plus the two RESERVE-THEN-ADVANCE counters (WOTS spend-tree leaf, note tag). The
//! counters are why it is a separate file that MUST be backed up: a one-time-signature
//! leaf reused after a lossy restore would leak spend authority, so restoring the
//! shielded side from the account seed alone is deliberately not offered.

use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::Duration;

use hk_primitives::{Amount, H256};
use hk_spend_circuit::{nullifier, Hash, Note};
use hk_state::tx::Tx;
use hk_wallet::{
    build_disclosure, build_mint, build_output, build_spend, epoch_of, note_key_as_recipient,
    scan_at, seal_note, Address, Discovered, WalletKeys,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    chain_balance, chain_info, fmt_amount, log, log_err, rpc_call, send_payload, wallet_dir, Evt, USD,
};

pub const PROVER_DEFAULT: &str = "https://prover.hashkinetics.org";
/// Address capacity: 2^6 = 64 one-time spends per shield master (the CLI's default).
const OTS_CAPACITY: u32 = 64;

// ---------------------------------------------------------------------------
// shield.json — reserve-then-advance for every one-time value
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct ShieldFile {
    pub version: u8,
    /// 32 bytes, hex. All shielded keys derive from it.
    pub master_hex: String,
    /// Next NEVER-REUSED spend-tree leaf. Persisted BEFORE use.
    pub next_ots_index: u32,
    /// Next self-note tag (rho/rcm derivation — reuse would link notes). Persisted BEFORE use.
    pub next_note_tag: u64,
}

pub fn shield_path() -> PathBuf {
    wallet_dir().join("shield.json")
}

pub fn load_shield() -> Option<ShieldFile> {
    let s = std::fs::read_to_string(shield_path()).ok()?;
    serde_json::from_str(&s).ok()
}

fn save_shield(f: &ShieldFile) -> Result<(), String> {
    std::fs::create_dir_all(wallet_dir()).map_err(|e| e.to_string())?;
    let tmp = wallet_dir().join("shield.json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(f).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, shield_path()).map_err(|e| e.to_string())
}

/// First shielded use creates the master; later uses load it. Never overwrites.
pub fn load_or_create_shield() -> Result<ShieldFile, String> {
    if let Some(f) = load_shield() {
        return Ok(f);
    }
    let mut m = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut m);
    let f = ShieldFile { version: 1, master_hex: hex::encode(m), next_ots_index: 0, next_note_tag: 1 };
    save_shield(&f)?;
    Ok(f)
}

fn keys(f: &ShieldFile) -> Result<WalletKeys, String> {
    Ok(WalletKeys::new(&hex::decode(&f.master_hex).map_err(|e| e.to_string())?))
}

/// Reserve the next WOTS leaf: advance + persist BEFORE the caller uses it.
fn reserve_ots(f: &mut ShieldFile) -> Result<u32, String> {
    let i = f.next_ots_index;
    if i >= OTS_CAPACITY {
        return Err(format!(
            "spend-tree exhausted ({i}/{OTS_CAPACITY} one-time leaves used) — unshield everything, \
             then move shield.json aside to start a fresh shield master"
        ));
    }
    f.next_ots_index += 1;
    save_shield(f)?;
    Ok(i)
}

fn reserve_tag(f: &mut ShieldFile) -> Result<u64, String> {
    let t = f.next_note_tag;
    f.next_note_tag += 1;
    save_shield(f)?;
    Ok(t)
}

fn fresh32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

fn dummy_note() -> Note {
    Note { value: 0, owner: [0; 32], rho: fresh32(), rcm: fresh32() }
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

pub fn addr_encode(a: &Address) -> String {
    format!("hkaddr:{}{}", hex::encode(a.tag), hex::encode(&a.kem_pk))
}

pub fn addr_decode(s: &str) -> Result<Address, String> {
    let h = s.trim().strip_prefix("hkaddr:").ok_or("address must start with 'hkaddr:'")?;
    let b = hex::decode(h.trim()).map_err(|e| format!("bad address hex: {e}"))?;
    if b.len() <= 32 {
        return Err("address too short".into());
    }
    Ok(Address { tag: b[..32].try_into().unwrap(), kem_pk: b[32..].to_vec() })
}

fn chain_height() -> u64 {
    chain_info().map(|(_, f)| f.map(|f| f.chain_height).unwrap_or(0)).unwrap_or(0)
}

/// Our receiving address for the chain's CURRENT epoch (scanning covers every epoch).
pub fn my_address(f: &ShieldFile) -> Result<String, String> {
    let k = keys(f)?;
    Ok(addr_encode(&k.address_at(epoch_of(chain_height()))))
}

// ---------------------------------------------------------------------------
// Pool feed + scanning
// ---------------------------------------------------------------------------

/// (leaves in insertion order, (index, commitment, stealth_ct) entries) — `hk_getPoolNotes`.
#[allow(clippy::type_complexity)]
fn pool_notes() -> Result<(Vec<Hash>, Vec<(u64, Hash, Vec<u8>)>), String> {
    let v = rpc_call("hk_getPoolNotes", json!({}))?;
    let arr = v
        .get("result")
        .and_then(|r| r.get("notes"))
        .and_then(|n| n.as_array())
        .ok_or_else(|| format!("hk_getPoolNotes: {v}"))?;
    let mut leaves = Vec::with_capacity(arr.len());
    let mut entries = Vec::with_capacity(arr.len());
    for e in arr {
        let idx = e.get("index").and_then(|i| i.as_u64()).ok_or("bad note index")?;
        let cm_hex = e.get("commitment").and_then(|c| c.as_str()).ok_or("bad commitment")?;
        let ct_hex = e.get("stealth_ct").and_then(|c| c.as_str()).unwrap_or("");
        let cm_b = hex::decode(cm_hex).map_err(|e| e.to_string())?;
        let cm: Hash = cm_b.as_slice().try_into().map_err(|_| "commitment not 32 bytes")?;
        leaves.push(cm);
        entries.push((idx, cm, hex::decode(ct_hex).map_err(|e| e.to_string())?));
    }
    Ok((leaves, entries))
}

fn nullifier_spent(nf: &Hash) -> bool {
    rpc_call("hk_nullifierSpent", json!({ "nullifier": hex::encode(nf) }))
        .ok()
        .and_then(|v| v.get("result")?.get("spent")?.as_bool())
        .unwrap_or(false)
}

/// What the UI shows per discovered note.
#[derive(Clone, Debug)]
pub struct NoteView {
    pub value: Amount,
    pub leaf_index: u64,
    pub memo: String,
    pub commitment: String,
    pub spent: bool,
}

/// Every note ever paid to this wallet (all epochs), with spent status.
fn my_notes(k: &WalletKeys) -> Result<(Vec<Hash>, Vec<(Discovered, bool)>), String> {
    let (leaves, entries) = pool_notes()?;
    let cur = epoch_of(chain_height());
    let nk = k.nk();
    let mut out: Vec<(Discovered, bool)> = Vec::new();
    for e in 0..=cur {
        for d in scan_at(k, e, &entries) {
            if !out.iter().any(|(x, _)| x.commitment == d.commitment) {
                let spent = nullifier_spent(&nullifier(&nk, &d.note.rho));
                out.push((d, spent));
            }
        }
    }
    Ok((leaves, out))
}

fn views(notes: &[(Discovered, bool)]) -> Vec<NoteView> {
    notes
        .iter()
        .map(|(d, spent)| NoteView {
            value: d.note.value as Amount,
            leaf_index: d.leaf_index,
            memo: String::from_utf8_lossy(&d.memo).to_string(),
            commitment: hex::encode(d.commitment),
            spent: *spent,
        })
        .collect()
}

/// The SMALLEST single unspent note covering `amt` (circuit v3: one input per spend).
fn pick_note(notes: &[(Discovered, bool)], amt: Amount) -> Result<Discovered, String> {
    let mut c: Vec<&Discovered> = notes
        .iter()
        .filter(|(d, spent)| !spent && (d.note.value as Amount) >= amt)
        .map(|(d, _)| d)
        .collect();
    if c.is_empty() {
        let have: Vec<String> =
            notes.iter().filter(|(_, s)| !s).map(|(d, _)| fmt_amount(d.note.value as Amount)).collect();
        return Err(format!(
            "no single shielded note covers {} — unspent notes: [{}]. One note per spend; consolidate by paying yourself first",
            fmt_amount(amt),
            have.join(", ")
        ));
    }
    c.sort_by_key(|d| d.note.value);
    Ok(c[0].clone())
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

/// `prove_mint` / `prove_spend` on the public prover. Core-mode STARKs on CPU can take
/// a while — long timeout, and the caller runs on a worker thread with a spinner.
fn prove(prover: &str, method: &str, witness: Value) -> Result<(Vec<u8>, u64), String> {
    let health = ureq::post(prover)
        .timeout(Duration::from_secs(10))
        .send_json(json!({ "method": "health", "params": {} }))
        .map_err(|e| format!("prover unreachable at {prover}: {e}"))?
        .into_json::<Value>()
        .map_err(|e| format!("prover health parse: {e}"))?;
    if health.get("result").is_none() {
        return Err(format!("prover at {prover} is not healthy: {health}"));
    }
    let v = ureq::post(prover)
        .timeout(Duration::from_secs(900))
        .send_json(json!({ "method": method, "params": { "witness": witness } }))
        .map_err(|e| format!("prover {method}: {e}"))?
        .into_json::<Value>()
        .map_err(|e| format!("prover {method} parse: {e}"))?;
    if let Some(e) = v.get("error") {
        return Err(format!("prover error: {e}"));
    }
    let r = v.get("result").ok_or_else(|| format!("prover: no result: {v}"))?;
    let proof_hex = r.get("proof").and_then(|p| p.as_str()).ok_or("prover: no proof in result")?;
    Ok((
        hex::decode(proof_hex).map_err(|e| e.to_string())?,
        r.get("prove_ms").and_then(|m| m.as_u64()).unwrap_or(0),
    ))
}

fn fee_now() -> Amount {
    chain_info().ok().and_then(|(_, f)| f).map(|f| f.current()).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Worker flows (each ends with Busy(false); each refreshes the note list on success)
// ---------------------------------------------------------------------------

fn finish(tx: &Sender<Evt>, id: &H256, sf: Option<&ShieldFile>) {
    if let Ok(b) = chain_balance(id) {
        let _ = tx.send(Evt::Balance(b));
    }
    if let Some(f) = sf {
        if let Ok(k) = keys(f) {
            if let Ok((_, notes)) = my_notes(&k) {
                let _ = tx.send(Evt::Notes(views(&notes)));
            }
        }
    }
    let _ = tx.send(Evt::Busy(false));
}

pub fn spawn_scan(tx: Sender<Evt>, id: H256) {
    std::thread::spawn(move || {
        let _ = tx.send(Evt::Busy(true));
        match load_or_create_shield() {
            Ok(f) => {
                match my_address(&f) {
                    Ok(a) => {
                        let _ = tx.send(Evt::StealthAddr(a));
                    }
                    Err(e) => log_err(&tx, e),
                }
                match keys(&f).and_then(|k| my_notes(&k)) {
                    Ok((_, notes)) => {
                        let unspent = notes.iter().filter(|(_, s)| !s).count();
                        log(&tx, format!("Scanned the pool: {} note(s) are yours, {unspent} unspent.", notes.len()));
                        let _ = tx.send(Evt::Notes(views(&notes)));
                    }
                    Err(e) => log_err(&tx, e),
                }
            }
            Err(e) => log_err(&tx, e),
        }
        finish(&tx, &id, None);
    });
}

/// Transparent → pool.
pub fn spawn_shield(tx: Sender<Evt>, seed: Vec<u8>, id: H256, amount: Amount, prover: String) {
    std::thread::spawn(move || {
        let _ = tx.send(Evt::Busy(true));
        let mut f = match load_or_create_shield() {
            Ok(f) => f,
            Err(e) => {
                log_err(&tx, e);
                let _ = tx.send(Evt::Busy(false));
                return;
            }
        };
        let res: Result<(), String> = (|| {
            let k = keys(&f)?;
            let bal = chain_balance(&id)?;
            let fee = fee_now();
            if amount.saturating_add(fee) > bal {
                return Err(format!(
                    "Not enough transparent balance for {} + network fee {} (have {}).",
                    fmt_amount(amount),
                    fmt_amount(fee),
                    fmt_amount(bal)
                ));
            }
            if amount > u64::MAX as Amount {
                return Err("amount too large for a single note".into());
            }
            let tag = reserve_tag(&mut f)?;
            let note = k.self_note(amount as u64, tag);
            let (witness, public) = build_mint(&note);
            let epoch = epoch_of(chain_height());
            let (ct, _) = seal_note(&note, &k.address_at(epoch), &fresh32(), b"shield").ok_or("seal failed")?;
            log(&tx, format!("Proving the mint of {} on the prover… (a STARK; this can take a while)", fmt_amount(amount)));
            let (proof, ms) = prove(&prover, "prove_mint", serde_json::to_value(&witness).map_err(|e| e.to_string())?)?;
            log(&tx, format!("Proof ready in {ms} ms — submitting."));
            send_payload(
                &tx,
                &seed,
                id,
                Tx::MintToPool { asset: USD, value: amount, commitment: H256(public.commitment), proof, stealth_ct: ct },
                &format!("Shielded {} ✓", fmt_amount(amount)),
            )
            .map_err(|_| "shield not committed".to_string())?;
            Ok(())
        })();
        if let Err(e) = res {
            log_err(&tx, e);
        }
        finish(&tx, &id, Some(&f));
    });
}

/// Pool → transparent (our own account).
pub fn spawn_unshield(tx: Sender<Evt>, seed: Vec<u8>, id: H256, amount: Amount, prover: String) {
    std::thread::spawn(move || {
        let _ = tx.send(Evt::Busy(true));
        let mut f = match load_or_create_shield() {
            Ok(f) => f,
            Err(e) => {
                log_err(&tx, e);
                let _ = tx.send(Evt::Busy(false));
                return;
            }
        };
        let res: Result<(), String> = (|| {
            let k = keys(&f)?;
            let fee = fee_now();
            if chain_balance(&id)? < fee {
                return Err(format!(
                    "The network fee ({}) is paid from your TRANSPARENT balance — top it up first (faucet).",
                    fmt_amount(fee)
                ));
            }
            let (leaves, notes) = my_notes(&k)?;
            let input = pick_note(&notes, amount)?;
            let change_v = input.note.value as Amount - amount;
            let tag = reserve_tag(&mut f)?;
            let ots = reserve_ots(&mut f)?;
            let change = k.self_note(change_v as u64, tag);
            let epoch = epoch_of(chain_height());
            let (change_ct, _) = seal_note(&change, &k.address_at(epoch), &fresh32(), b"change").ok_or("seal failed")?;
            let plan = build_spend(&leaves, input.leaf_index, input.note.clone(), &k, ots, change, dummy_note(), amount as u64, id.0)
                .map_err(|e| format!("build_spend: {e}"))?;
            log(&tx, format!("Proving the spend of {} on the prover… (a STARK; this can take a while)", fmt_amount(amount)));
            let (proof, ms) = prove(&prover, "prove_spend", serde_json::to_value(&plan.witness).map_err(|e| e.to_string())?)?;
            log(&tx, format!("Proof ready in {ms} ms — submitting."));
            send_payload(
                &tx,
                &seed,
                id,
                Tx::ShieldedSpend {
                    anchor: H256(plan.public.merkle_root),
                    nullifier: H256(plan.public.nullifier),
                    out_commitment: H256(plan.public.out_commitment),
                    out2_commitment: H256(plan.public.out2_commitment),
                    fee: amount,
                    credit: Some(id),
                    mandate: None,
                    proof,
                    stealth_ct: change_ct,
                    stealth_ct2: Vec::new(),
                },
                &format!("Unshielded {} ✓ ({} change went back into hiding)", fmt_amount(amount), fmt_amount(change_v)),
            )
            .map_err(|_| "unshield not committed".to_string())?;
            Ok(())
        })();
        if let Err(e) = res {
            log_err(&tx, e);
        }
        finish(&tx, &id, Some(&f));
    });
}

/// Fully shielded payment to a stealth address.
pub fn spawn_pay(tx: Sender<Evt>, seed: Vec<u8>, id: H256, to: String, amount: Amount, memo: String, prover: String) {
    std::thread::spawn(move || {
        let _ = tx.send(Evt::Busy(true));
        let mut f = match load_or_create_shield() {
            Ok(f) => f,
            Err(e) => {
                log_err(&tx, e);
                let _ = tx.send(Evt::Busy(false));
                return;
            }
        };
        let res: Result<(), String> = (|| {
            let to = addr_decode(&to)?;
            let k = keys(&f)?;
            let fee = fee_now();
            if chain_balance(&id)? < fee {
                return Err(format!(
                    "The network fee ({}) is paid from your TRANSPARENT balance — top it up first (faucet).",
                    fmt_amount(fee)
                ));
            }
            let (leaves, notes) = my_notes(&k)?;
            let input = pick_note(&notes, amount)?;
            let change_v = input.note.value as Amount - amount;
            let out = build_output(&to, amount as u64, &fresh32(), &fresh32(), memo.as_bytes())
                .ok_or("could not build the output (bad recipient address?)")?;
            let tag = reserve_tag(&mut f)?;
            let ots = reserve_ots(&mut f)?;
            let change = k.self_note(change_v as u64, tag);
            let epoch = epoch_of(chain_height());
            let (change_ct, _) = seal_note(&change, &k.address_at(epoch), &fresh32(), b"change").ok_or("seal failed")?;
            let plan = build_spend(&leaves, input.leaf_index, input.note.clone(), &k, ots, out.note.clone(), change, 0, [0; 32])
                .map_err(|e| format!("build_spend: {e}"))?;
            log(&tx, format!("Proving a shielded payment of {} on the prover… (a STARK; this can take a while)", fmt_amount(amount)));
            let (proof, ms) = prove(&prover, "prove_spend", serde_json::to_value(&plan.witness).map_err(|e| e.to_string())?)?;
            log(&tx, format!("Proof ready in {ms} ms — submitting."));
            send_payload(
                &tx,
                &seed,
                id,
                Tx::ShieldedSpend {
                    anchor: H256(plan.public.merkle_root),
                    nullifier: H256(plan.public.nullifier),
                    out_commitment: H256(plan.public.out_commitment),
                    out2_commitment: H256(plan.public.out2_commitment),
                    fee: 0,
                    credit: None,
                    mandate: None,
                    proof,
                    stealth_ct: out.stealth_ct.clone(),
                    stealth_ct2: change_ct,
                },
                &format!("Paid {} shielded ✓ — the chain saw one nullifier and two commitments; who paid whom is invisible", fmt_amount(amount)),
            )
            .map_err(|_| "shielded payment not committed".to_string())?;
            Ok(())
        })();
        if let Err(e) = res {
            log_err(&tx, e);
        }
        finish(&tx, &id, Some(&f));
    });
}

/// One-time disclosure package for a note WE received, written next to the wallet.
pub fn spawn_disclose(tx: Sender<Evt>, id: H256, commitment_hex: String) {
    std::thread::spawn(move || {
        let _ = tx.send(Evt::Busy(true));
        let res: Result<(), String> = (|| {
            let f = load_shield().ok_or("no shield.json — nothing shielded yet")?;
            let k = keys(&f)?;
            let cm_b = hex::decode(&commitment_hex).map_err(|e| e.to_string())?;
            let cm: Hash = cm_b.as_slice().try_into().map_err(|_| "commitment must be 32 bytes")?;
            let (leaves, entries) = pool_notes()?;
            let (idx, _, ct) = entries.iter().find(|(_, c, _)| *c == cm).cloned().ok_or("commitment not found in the pool")?;
            // ML-KEM decapsulation never fails (implicit rejection) — VALIDATE each epoch's
            // candidate key by opening the AEAD before packaging anything.
            let cur = epoch_of(chain_height());
            let key = (0..=cur)
                .filter_map(|e| note_key_as_recipient(&k, e, &cm, &ct))
                .find(|key| {
                    ct.len() > hk_crypto::mlkem::CT_LEN
                        && hk_crypto::noteenc::open(key, &cm, &ct[hk_crypto::mlkem::CT_LEN..]).is_some()
                })
                .ok_or("this wallet cannot open that ciphertext (not the recipient)")?;
            let chain_id = chain_info().map(|(c, _)| c).unwrap_or_else(|_| "hashkinetics".into());
            let pkg = build_disclosure(&chain_id, &leaves, idx, k.owner_tag(), ct, key).ok_or("package build failed")?;
            let out = wallet_dir().join(format!("disclosure-{}.json", &commitment_hex[..12]));
            std::fs::write(&out, serde_json::to_string_pretty(&pkg).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            log(&tx, format!("Disclosure package written: {} — it opens exactly this payment and nothing else. Verify offline: hk-node verify-disclosure <file>", out.display()));
            Ok(())
        })();
        if let Err(e) = res {
            log_err(&tx, e);
        }
        finish(&tx, &id, None);
    });
}
