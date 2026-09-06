//! The shielded side — a straight port of the desktop wallet's `shielded.rs` onto the
//! library `Wallet` (no UI thread, no egui events; progress goes to the app's listener):
//!
//! - **Shield**: transparent → pool (`prove_mint` + `Tx::MintToPool`, self-note sealed to
//!   our current-epoch stealth address; the envelope pays the fee).
//! - **Unshield**: pool → transparent (one input note, change sealed back to us, the public
//!   `fee` field credits our account).
//! - **Pay**: fully shielded payment to an `hkaddr:` — one nullifier, two commitments.
//! - **Scan**: incremental and paged (H3): cursor + found notes live in `shield.json`.
//! - **Disclose**: a one-time package opening ONE received payment for an auditor.
//!
//! `shield.json` holds its own random master seed plus the two RESERVE-THEN-ADVANCE counters
//! (WOTS spend-tree leaf, note tag): it MUST be backed up — restoring the shielded side from
//! the account seed alone is deliberately impossible (a reused one-time leaf leaks authority).

use std::path::PathBuf;

use hk_primitives::{Amount, H256};
use hk_spend_circuit::{nullifier, Hash, Note};
use hk_state::tx::Tx;
use hk_wallet::{
    build_disclosure_with_path, build_mint, build_output, build_spend_with_path, epoch_of, note_key_as_recipient,
    scan_at, seal_note, Address, Discovered, WalletKeys,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::account::fmt_amount;
use crate::client::{Http, USD};
use crate::{NoteView, ScanResult, TxResult, Wallet, WalletError};

/// Address capacity: 2^6 = 64 one-time spends per shield master (the CLI's default).
pub const OTS_CAPACITY: u32 = 64;
/// H3: a page of the pool feed (~5 MB of hex at most) and its call budget.
const POOL_PAGE: u64 = 2_000;
const POOL_CALL_SECS: u64 = 90;

#[derive(Serialize, Deserialize, Clone)]
pub struct ShieldFile {
    pub version: u8,
    /// 32 bytes, hex. All shielded keys derive from it.
    pub master_hex: String,
    /// Next NEVER-REUSED spend-tree leaf. Persisted BEFORE use.
    pub next_ots_index: u32,
    /// Next self-note tag (rho/rcm derivation — reuse would link notes). Persisted BEFORE use.
    pub next_note_tag: u64,
    /// H3: scan cursor + found notes (serde default = scan everything once, then remember).
    #[serde(default)]
    pub scan: ScanCache,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ScanCache {
    pub chain_id: String,
    pub scanned_through: u64,
    pub notes: Vec<StoredNote>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StoredNote {
    pub leaf_index: u64,
    pub commitment: String,
    pub value: u64,
    pub rho: String,
    pub rcm: String,
    /// hex
    pub memo: String,
    pub spent: bool,
}

impl StoredNote {
    fn from_discovered(d: &Discovered) -> Self {
        Self {
            leaf_index: d.leaf_index,
            commitment: hex::encode(d.commitment),
            value: d.note.value,
            rho: hex::encode(d.note.rho),
            rcm: hex::encode(d.note.rcm),
            memo: hex::encode(&d.memo),
            spent: false,
        }
    }

    fn to_discovered(&self, owner: Hash) -> Result<Discovered, WalletError> {
        let h32 = |s: &str, what: &str| -> Result<Hash, WalletError> {
            hex::decode(s)
                .map_err(|e| WalletError::msg(format!("shield.json {what}: {e}")))?
                .as_slice()
                .try_into()
                .map_err(|_| WalletError::msg(format!("shield.json {what}: not 32 bytes")))
        };
        Ok(Discovered {
            note: Note { value: self.value, owner, rho: h32(&self.rho, "rho")?, rcm: h32(&self.rcm, "rcm")? },
            commitment: h32(&self.commitment, "commitment")?,
            leaf_index: self.leaf_index,
            memo: hex::decode(&self.memo).unwrap_or_default(),
        })
    }
}

fn keys(f: &ShieldFile) -> Result<WalletKeys, WalletError> {
    Ok(WalletKeys::new(&hex::decode(&f.master_hex).map_err(|e| WalletError::msg(e.to_string()))?))
}

fn fresh32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

fn dummy_note() -> Note {
    Note { value: 0, owner: [0; 32], rho: fresh32(), rcm: fresh32() }
}

pub fn addr_encode(a: &Address) -> String {
    format!("hkaddr:{}{}", hex::encode(a.tag), hex::encode(&a.kem_pk))
}

pub fn addr_decode(s: &str) -> Result<Address, WalletError> {
    let h = s.trim().strip_prefix("hkaddr:").ok_or_else(|| WalletError::msg("address must start with 'hkaddr:'"))?;
    let b = hex::decode(h.trim()).map_err(|e| WalletError::msg(format!("bad address hex: {e}")))?;
    if b.len() <= 32 {
        return Err(WalletError::msg("address too short"));
    }
    Ok(Address { tag: b[..32].try_into().unwrap(), kem_pk: b[32..].to_vec() })
}

type Entry = (u64, Hash, Vec<u8>);

fn parse_hash(hex_str: &str, what: &str) -> Result<Hash, WalletError> {
    let b = hex::decode(hex_str).map_err(|e| WalletError::msg(format!("{what}: {e}")))?;
    b.as_slice().try_into().map_err(|_| WalletError::msg(format!("{what}: not 32 bytes")))
}

// ---------------------------------------------------------------------------
// Pool feed (paged) — pure functions over the HTTP client
// ---------------------------------------------------------------------------

fn pool_page(http: &Http, from: u64) -> Result<(Vec<Entry>, Option<u64>, Option<u64>), WalletError> {
    let v = http.rpc_within("hk_getPoolNotes", json!({ "from": from, "limit": POOL_PAGE }), POOL_CALL_SECS)?;
    let r = v.get("result").ok_or_else(|| WalletError::msg(format!("hk_getPoolNotes: {v}")))?;
    let arr = r.get("notes").and_then(|n| n.as_array()).ok_or_else(|| WalletError::msg(format!("hk_getPoolNotes: {v}")))?;
    let mut entries = Vec::with_capacity(arr.len());
    for e in arr {
        let idx = e.get("index").and_then(|i| i.as_u64()).ok_or_else(|| WalletError::msg("bad note index"))?;
        let cm = parse_hash(e.get("commitment").and_then(|c| c.as_str()).ok_or_else(|| WalletError::msg("bad commitment"))?, "commitment")?;
        let ct_hex = e.get("stealth_ct").and_then(|c| c.as_str()).unwrap_or("");
        entries.push((idx, cm, hex::decode(ct_hex).map_err(|e| WalletError::msg(e.to_string()))?));
    }
    Ok((entries, r.get("next").and_then(|n| n.as_u64()), r.get("total").and_then(|t| t.as_u64())))
}

/// Every pool entry with index ≥ `from`, plus the pool's size. Pages until `next` is null.
fn pool_notes_from(http: &Http, from: u64) -> Result<(Vec<Entry>, u64), WalletError> {
    let mut all: Vec<Entry> = Vec::new();
    let mut cursor = from;
    loop {
        let (page, next, total) = pool_page(http, cursor)?;
        all.extend(page.into_iter().filter(|(i, _, _)| *i >= from));
        match next {
            Some(n) if n > cursor => cursor = n,
            _ => {
                let total = total.unwrap_or_else(|| all.iter().map(|(i, _, _)| i + 1).max().unwrap_or(from).max(from));
                return Ok((all, total));
            }
        }
    }
}

fn pool_entry(http: &Http, index: u64) -> Result<Entry, WalletError> {
    let (page, _, _) = pool_page(http, index)?;
    page.into_iter().find(|(i, _, _)| *i == index).ok_or_else(|| WalletError::msg(format!("leaf {index} is not in the pool")))
}

fn pool_leaves_all(http: &Http) -> Result<Vec<Hash>, WalletError> {
    let mut leaves: Vec<Hash> = Vec::new();
    let mut cursor = 0u64;
    loop {
        let v = http.rpc_within("hk_getPoolLeaves", json!({ "from": cursor, "limit": POOL_PAGE }), POOL_CALL_SECS)?;
        let r = v.get("result").ok_or_else(|| WalletError::msg(format!("hk_getPoolLeaves: {v}")))?;
        let arr = r.get("leaves").and_then(|l| l.as_array()).ok_or_else(|| WalletError::msg(format!("hk_getPoolLeaves: {v}")))?;
        let from = r.get("from").and_then(|f| f.as_u64()).unwrap_or(0);
        for (i, l) in arr.iter().enumerate() {
            if from + i as u64 >= leaves.len() as u64 {
                leaves.push(parse_hash(l.as_str().ok_or_else(|| WalletError::msg("bad leaf"))?, "leaf")?);
            }
        }
        match r.get("next").and_then(|n| n.as_u64()) {
            Some(n) if n > cursor => cursor = n,
            _ => return Ok(leaves),
        }
    }
}

/// H3: the authentication path for one leaf — `hk_getPoolPath` on a v0.16.1+ node, the full
/// leaf list on an older one. `(siblings, root)`; the caller's builder re-folds before use.
fn pool_path(http: &Http, index: u64) -> Result<(Vec<Hash>, Hash), WalletError> {
    if let Ok(v) = http.rpc("hk_getPoolPath", json!({ "index": index })) {
        if let Some(r) = v.get("result") {
            let sib = r.get("siblings").and_then(|s| s.as_array()).ok_or_else(|| WalletError::msg("hk_getPoolPath: no siblings"))?;
            let siblings = sib.iter().map(|s| parse_hash(s.as_str().unwrap_or(""), "sibling")).collect::<Result<Vec<_>, _>>()?;
            let root = parse_hash(r.get("root").and_then(|s| s.as_str()).ok_or_else(|| WalletError::msg("hk_getPoolPath: no root"))?, "root")?;
            return Ok((siblings, root));
        }
        if let Some(e) = v.get("error").and_then(|e| e.as_str()) {
            if e.contains("out of range") {
                return Err(WalletError::msg(format!("hk_getPoolPath: {e}")));
            }
        }
    }
    let leaves = pool_leaves_all(http)?;
    if index as usize >= leaves.len() {
        return Err(WalletError::msg(format!("leaf {index} is not in the pool ({} commitments)", leaves.len())));
    }
    Ok(hk_state::pool::full_tree_path(&leaves, index))
}

fn nullifier_spent(http: &Http, nf: &Hash) -> bool {
    http.rpc("hk_nullifierSpent", json!({ "nullifier": hex::encode(nf) }))
        .ok()
        .and_then(|v| v.get("result")?.get("spent")?.as_bool())
        .unwrap_or(false)
}

fn views(notes: &[(Discovered, bool)]) -> Vec<NoteView> {
    notes
        .iter()
        .map(|(d, spent)| NoteView {
            value_micro: d.note.value,
            leaf_index: d.leaf_index,
            memo: String::from_utf8_lossy(&d.memo).to_string(),
            commitment: hex::encode(d.commitment),
            spent: *spent,
        })
        .collect()
}

/// The SMALLEST single unspent note covering `amt` (circuit v3: one input per spend).
fn pick_note(notes: &[(Discovered, bool)], amt: Amount) -> Result<Discovered, WalletError> {
    let mut c: Vec<&Discovered> =
        notes.iter().filter(|(d, spent)| !spent && (d.note.value as Amount) >= amt).map(|(d, _)| d).collect();
    if c.is_empty() {
        let have: Vec<String> = notes.iter().filter(|(_, s)| !s).map(|(d, _)| fmt_amount(d.note.value as Amount)).collect();
        return Err(WalletError::msg(format!(
            "no single shielded note covers {} — unspent notes: [{}]. One note per spend; consolidate by paying yourself first",
            fmt_amount(amt),
            have.join(", ")
        )));
    }
    c.sort_by_key(|d| d.note.value);
    Ok(c[0].clone())
}

// ---------------------------------------------------------------------------
// Wallet methods (file access through the vault; network through Http)
// ---------------------------------------------------------------------------

impl Wallet {
    pub(crate) fn shield_path(&self) -> PathBuf {
        self.dir.join("shield.json")
    }

    pub(crate) fn load_shield(&self) -> Result<Option<ShieldFile>, WalletError> {
        let path = self.shield_path();
        if !path.exists() {
            return Ok(None);
        }
        match self.read_secret(&path)? {
            Some(s) => serde_json::from_str(&s).map(Some).map_err(|e| WalletError::msg(format!("shield.json: {e}"))),
            None => Err(WalletError::msg("shield.json is sealed — unlock the wallet first")),
        }
    }

    pub(crate) fn save_shield(&self, f: &ShieldFile) -> Result<(), WalletError> {
        let text = serde_json::to_string_pretty(f).map_err(|e| WalletError::msg(e.to_string()))?;
        self.write_secret(&self.shield_path(), "shield.json.tmp", &text)
    }

    /// First shielded use creates the master; later uses load it. Never overwrites.
    fn load_or_create_shield(&self) -> Result<ShieldFile, WalletError> {
        if let Some(f) = self.load_shield()? {
            return Ok(f);
        }
        let f = ShieldFile {
            version: 1,
            master_hex: hex::encode(fresh32()),
            next_ots_index: 0,
            next_note_tag: 1,
            scan: ScanCache::default(),
        };
        self.save_shield(&f)?;
        Ok(f)
    }

    /// Reserve the next WOTS leaf: advance + persist BEFORE the caller uses it.
    fn reserve_ots(&self, f: &mut ShieldFile) -> Result<u32, WalletError> {
        let i = f.next_ots_index;
        if i >= OTS_CAPACITY {
            return Err(WalletError::msg(format!(
                "spend-tree exhausted ({i}/{OTS_CAPACITY} one-time leaves used) — unshield everything, then move shield.json aside to start a fresh shield master"
            )));
        }
        f.next_ots_index += 1;
        self.save_shield(f)?;
        Ok(i)
    }

    fn reserve_tag(&self, f: &mut ShieldFile) -> Result<u64, WalletError> {
        let t = f.next_note_tag;
        f.next_note_tag += 1;
        self.save_shield(f)?;
        Ok(t)
    }

    /// Our receiving address for the chain's CURRENT epoch (scanning covers every epoch).
    pub(crate) fn stealth_address_of(&self, http: &Http, f: &ShieldFile) -> Result<String, WalletError> {
        let k = keys(f)?;
        Ok(addr_encode(&k.address_at(epoch_of(http.height()?))))
    }

    /// Every note ever paid to this wallet (all epochs), with spent status — incremental.
    fn my_notes(&self, http: &Http, k: &WalletKeys, f: &mut ShieldFile) -> Result<Vec<(Discovered, bool)>, WalletError> {
        let chain_id = http.chain_info().map(|c| c.chain_id).unwrap_or_default();
        let mut changed = false;
        if f.scan.chain_id != chain_id {
            f.scan = ScanCache { chain_id, ..Default::default() };
            changed = true;
        }
        let (mut entries, mut total) = pool_notes_from(http, f.scan.scanned_through)?;
        if total < f.scan.scanned_through {
            f.scan = ScanCache { chain_id: f.scan.chain_id.clone(), ..Default::default() };
            changed = true;
            let again = pool_notes_from(http, 0)?;
            entries = again.0;
            total = again.1;
        }
        if !entries.is_empty() {
            let cur = epoch_of(http.height()?);
            for e in 0..=cur {
                for d in scan_at(k, e, &entries) {
                    if !f.scan.notes.iter().any(|n| n.leaf_index == d.leaf_index) {
                        f.scan.notes.push(StoredNote::from_discovered(&d));
                        changed = true;
                    }
                }
            }
        }
        if total > f.scan.scanned_through {
            f.scan.scanned_through = total;
            changed = true;
        }
        let nk = k.nk();
        let owner = k.owner_tag();
        let mut out: Vec<(Discovered, bool)> = Vec::with_capacity(f.scan.notes.len());
        for n in f.scan.notes.iter_mut() {
            let d = n.to_discovered(owner)?;
            if !n.spent && nullifier_spent(http, &nullifier(&nk, &d.note.rho)) {
                n.spent = true;
                changed = true;
            }
            out.push((d, n.spent));
        }
        if changed {
            self.save_shield(f)?;
        }
        Ok(out)
    }

    // ---- the flows the app calls (each returns what the screen needs) ----

    pub(crate) fn do_scan(&self) -> Result<ScanResult, WalletError> {
        let http = self.http();
        let mut f = self.load_or_create_shield()?;
        let stealth_address = self.stealth_address_of(&http, &f)?;
        let before = f.scan.scanned_through;
        let k = keys(&f)?;
        let notes = self.my_notes(&http, &k, &mut f)?;
        let unspent = notes.iter().filter(|(_, s)| !s).count() as u32;
        let fresh = f.scan.scanned_through.saturating_sub(before);
        self.log_info(format!(
            "Scanned {fresh} new pool entr{} (pool size {}): {} note(s) are yours, {unspent} unspent.",
            if fresh == 1 { "y" } else { "ies" },
            f.scan.scanned_through,
            notes.len()
        ));
        Ok(ScanResult {
            notes: views(&notes),
            fresh_entries: fresh,
            pool_size: f.scan.scanned_through,
            unspent,
            stealth_address,
            ots_used: f.next_ots_index,
            ots_capacity: OTS_CAPACITY,
        })
    }

    /// Transparent → pool.
    pub(crate) fn do_shield(&self, amount: Amount) -> Result<TxResult, WalletError> {
        let http = self.http();
        let (seed, id) = self.signer()?;
        let mut f = self.load_or_create_shield()?;
        let k = keys(&f)?;
        let bal = http.balance(&id)?;
        let fee = http.chain_info()?.fee_now();
        if amount.saturating_add(fee) > bal {
            return Err(WalletError::msg(format!(
                "Not enough transparent balance for {} + network fee {} (have {}).",
                fmt_amount(amount),
                fmt_amount(fee),
                fmt_amount(bal)
            )));
        }
        if amount > u64::MAX as Amount {
            return Err(WalletError::msg("amount too large for a single note"));
        }
        let tag = self.reserve_tag(&mut f)?;
        let note = k.self_note(amount as u64, tag);
        let (witness, public) = build_mint(&note);
        let epoch = epoch_of(http.height()?);
        let (ct, _) = seal_note(&note, &k.address_at(epoch), &fresh32(), b"shield").ok_or_else(|| WalletError::msg("seal failed"))?;
        self.log_info(format!("Proving the mint of {} on the prover… (a STARK; this can take a while)", fmt_amount(amount)));
        let (proof, ms) = http.prove("prove_mint", serde_json::to_value(&witness).map_err(|e| WalletError::msg(e.to_string()))?)?;
        self.log_info(format!("Proof ready in {ms} ms — submitting."));
        self.send_payload(
            &http,
            &seed,
            id,
            Tx::MintToPool { asset: USD, value: amount, commitment: H256(public.commitment), proof, stealth_ct: ct },
            &format!("Shielded {} ✓", fmt_amount(amount)),
        )
    }

    /// Pool → transparent (our own account).
    pub(crate) fn do_unshield(&self, amount: Amount) -> Result<TxResult, WalletError> {
        let http = self.http();
        let (seed, id) = self.signer()?;
        let mut f = self.load_or_create_shield()?;
        let k = keys(&f)?;
        let fee = http.chain_info()?.fee_now();
        if http.balance(&id)? < fee {
            return Err(WalletError::msg(format!(
                "The network fee ({}) is paid from your TRANSPARENT balance — top it up first (faucet).",
                fmt_amount(fee)
            )));
        }
        let notes = self.my_notes(&http, &k, &mut f)?;
        let input = pick_note(&notes, amount)?;
        let change_v = input.note.value as Amount - amount;
        let (siblings, root) = pool_path(&http, input.leaf_index)?;
        let tag = self.reserve_tag(&mut f)?;
        let ots = self.reserve_ots(&mut f)?;
        let change = k.self_note(change_v as u64, tag);
        let epoch = epoch_of(http.height()?);
        let (change_ct, _) = seal_note(&change, &k.address_at(epoch), &fresh32(), b"change").ok_or_else(|| WalletError::msg("seal failed"))?;
        let plan = build_spend_with_path(siblings, root, input.leaf_index, input.note.clone(), &k, ots, change, dummy_note(), amount as u64, id.0)
            .map_err(|e| WalletError::msg(format!("build_spend: {e}")))?;
        self.log_info(format!("Proving the spend of {} on the prover… (a STARK; this can take a while)", fmt_amount(amount)));
        let (proof, ms) = http.prove("prove_spend", serde_json::to_value(&plan.witness).map_err(|e| WalletError::msg(e.to_string()))?)?;
        self.log_info(format!("Proof ready in {ms} ms — submitting."));
        self.send_payload(
            &http,
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
    }

    /// Fully shielded payment to a stealth address.
    pub(crate) fn do_pay(&self, to: &str, amount: Amount, memo: &str) -> Result<TxResult, WalletError> {
        let http = self.http();
        let (seed, id) = self.signer()?;
        let to = addr_decode(to)?;
        let mut f = self.load_or_create_shield()?;
        let k = keys(&f)?;
        let fee = http.chain_info()?.fee_now();
        if http.balance(&id)? < fee {
            return Err(WalletError::msg(format!(
                "The network fee ({}) is paid from your TRANSPARENT balance — top it up first (faucet).",
                fmt_amount(fee)
            )));
        }
        let notes = self.my_notes(&http, &k, &mut f)?;
        let input = pick_note(&notes, amount)?;
        let change_v = input.note.value as Amount - amount;
        let out = build_output(&to, amount as u64, &fresh32(), &fresh32(), memo.as_bytes())
            .ok_or_else(|| WalletError::msg("could not build the output (bad recipient address?)"))?;
        let (siblings, root) = pool_path(&http, input.leaf_index)?;
        let tag = self.reserve_tag(&mut f)?;
        let ots = self.reserve_ots(&mut f)?;
        let change = k.self_note(change_v as u64, tag);
        let epoch = epoch_of(http.height()?);
        let (change_ct, _) = seal_note(&change, &k.address_at(epoch), &fresh32(), b"change").ok_or_else(|| WalletError::msg("seal failed"))?;
        let plan = build_spend_with_path(siblings, root, input.leaf_index, input.note.clone(), &k, ots, out.note.clone(), change, 0, [0; 32])
            .map_err(|e| WalletError::msg(format!("build_spend: {e}")))?;
        self.log_info(format!("Proving a shielded payment of {} on the prover… (a STARK; this can take a while)", fmt_amount(amount)));
        let (proof, ms) = http.prove("prove_spend", serde_json::to_value(&plan.witness).map_err(|e| WalletError::msg(e.to_string()))?)?;
        self.log_info(format!("Proof ready in {ms} ms — submitting."));
        self.send_payload(
            &http,
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
    }

    /// One-time disclosure package (JSON) for a note WE received.
    pub(crate) fn do_disclose(&self, commitment_hex: &str) -> Result<String, WalletError> {
        let http = self.http();
        let mut f = self.load_shield()?.ok_or_else(|| WalletError::msg("no shield.json — nothing shielded yet"))?;
        let k = keys(&f)?;
        let commitment_hex = commitment_hex.trim().to_lowercase();
        let cm: Hash = parse_hash(&commitment_hex, "commitment")?;
        let idx = match f.scan.notes.iter().find(|n| n.commitment == commitment_hex) {
            Some(n) => n.leaf_index,
            None => {
                let _ = self.my_notes(&http, &k, &mut f);
                f.scan
                    .notes
                    .iter()
                    .find(|n| n.commitment == commitment_hex)
                    .map(|n| n.leaf_index)
                    .or_else(|| pool_notes_from(&http, 0).ok()?.0.into_iter().find(|(_, c, _)| *c == cm).map(|(i, _, _)| i))
                    .ok_or_else(|| WalletError::msg("commitment not found in the pool"))?
            }
        };
        let (_, _, ct) = pool_entry(&http, idx)?;
        let cur = epoch_of(http.height()?);
        let key = (0..=cur)
            .filter_map(|e| note_key_as_recipient(&k, e, &cm, &ct))
            .find(|key| ct.len() > hk_crypto::mlkem::CT_LEN && hk_crypto::noteenc::open(key, &cm, &ct[hk_crypto::mlkem::CT_LEN..]).is_some())
            .ok_or_else(|| WalletError::msg("this wallet cannot open that ciphertext (not the recipient)"))?;
        let chain_id = http.chain_info().map(|c| c.chain_id).unwrap_or_else(|_| "hashkinetics".into());
        let (siblings, anchor) = pool_path(&http, idx)?;
        let pkg = build_disclosure_with_path(&chain_id, cm, siblings, anchor, idx, k.owner_tag(), ct, key)
            .ok_or_else(|| WalletError::msg("package build failed (the node's path does not fold to its root)"))?;
        let text = serde_json::to_string_pretty(&pkg).map_err(|e| WalletError::msg(e.to_string()))?;
        let out = self.dir.join(format!("disclosure-{}.json", &commitment_hex[..12.min(commitment_hex.len())]));
        std::fs::write(&out, &text).map_err(|e| WalletError::msg(e.to_string()))?;
        self.log_info(format!("Disclosure package written: {} — it opens exactly this payment and nothing else.", out.display()));
        Ok(text)
    }

    /// The value the app shows next to "Shielded" without a scan: cached notes only.
    pub(crate) fn cached_notes(&self) -> Result<Vec<NoteView>, WalletError> {
        let f = match self.load_shield()? {
            Some(f) => f,
            None => return Ok(Vec::new()),
        };
        Ok(f.scan
            .notes
            .iter()
            .map(|n| NoteView {
                value_micro: n.value,
                leaf_index: n.leaf_index,
                memo: String::from_utf8_lossy(&hex::decode(&n.memo).unwrap_or_default()).to_string(),
                commitment: n.commitment.clone(),
                spent: n.spent,
            })
            .collect())
    }
}
