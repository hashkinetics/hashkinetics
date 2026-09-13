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
//!
//! P6.2 (2026-09-13): ONE POOL PER ASSET. Every operation names the asset it acts in; the
//! native unit lives in the chain's legacy pool (addressed by OMITTING `asset` on the RPC —
//! on a devnet the legacy pool may be unpinned, and naming the native id there would address
//! a pool that does not exist), every other asset in its own pool (`asset` = its id). The
//! scan cache is per pool: `scan` stays the legacy pool's (byte-compatible with every
//! shield.json ever written), `pools[<asset hex>]` holds the others. The stealth address,
//! the spend-tree leaves and the note tags are shared across pools — they are properties of
//! the shield master, not of a pool.

use std::collections::BTreeMap;
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
use serde_json::{json, Value};

use crate::account::fmt_amount;
use crate::client::{Http, USD};
use crate::{AssetCtx, NoteView, ScanResult, TxResult, Wallet, WalletError};

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
    /// H3: scan cursor + found notes of the LEGACY pool (the native unit).
    #[serde(default)]
    pub scan: ScanCache,
    /// P6.2: scan cursor + found notes of every per-asset pool, by asset id (lowercase hex).
    /// Absent in files written before P6.2 — serde fills an empty map; older readers ignore it.
    #[serde(default)]
    pub pools: BTreeMap<String, ScanCache>,
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

impl ShieldFile {
    /// The scan cache of `asset`'s pool (created empty on first use for a new asset).
    pub fn cache_mut(&mut self, asset: &H256) -> &mut ScanCache {
        if *asset == USD {
            &mut self.scan
        } else {
            self.pools.entry(hex::encode(asset.0)).or_default()
        }
    }

    pub fn cache(&self, asset: &H256) -> Option<&ScanCache> {
        if *asset == USD {
            Some(&self.scan)
        } else {
            self.pools.get(&hex::encode(asset.0))
        }
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

/// P6: the pool an RPC call addresses. The native unit = the legacy pool = NO `asset`
/// parameter (see the module docs); anything else names its own pool.
fn with_asset(mut params: Value, asset: &H256) -> Value {
    if *asset != USD {
        if let Some(o) = params.as_object_mut() {
            o.insert("asset".into(), json!(hex::encode(asset.0)));
        }
    }
    params
}

// ---------------------------------------------------------------------------
// Pool feed (paged) — pure functions over the HTTP client
// ---------------------------------------------------------------------------

fn pool_page(http: &Http, from: u64, asset: &H256) -> Result<(Vec<Entry>, Option<u64>, Option<u64>), WalletError> {
    let v = http.rpc_within("hk_getPoolNotes", with_asset(json!({ "from": from, "limit": POOL_PAGE }), asset), POOL_CALL_SECS)?;
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
fn pool_notes_from(http: &Http, from: u64, asset: &H256) -> Result<(Vec<Entry>, u64), WalletError> {
    let mut all: Vec<Entry> = Vec::new();
    let mut cursor = from;
    loop {
        let (page, next, total) = pool_page(http, cursor, asset)?;
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

fn pool_entry(http: &Http, index: u64, asset: &H256) -> Result<Entry, WalletError> {
    let (page, _, _) = pool_page(http, index, asset)?;
    page.into_iter().find(|(i, _, _)| *i == index).ok_or_else(|| WalletError::msg(format!("leaf {index} is not in the pool")))
}

fn pool_leaves_all(http: &Http, asset: &H256) -> Result<Vec<Hash>, WalletError> {
    let mut leaves: Vec<Hash> = Vec::new();
    let mut cursor = 0u64;
    loop {
        let v = http.rpc_within("hk_getPoolLeaves", with_asset(json!({ "from": cursor, "limit": POOL_PAGE }), asset), POOL_CALL_SECS)?;
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
fn pool_path(http: &Http, index: u64, asset: &H256) -> Result<(Vec<Hash>, Hash), WalletError> {
    if let Ok(v) = http.rpc("hk_getPoolPath", with_asset(json!({ "index": index }), asset)) {
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
    let leaves = pool_leaves_all(http, asset)?;
    if index as usize >= leaves.len() {
        return Err(WalletError::msg(format!("leaf {index} is not in the pool ({} commitments)", leaves.len())));
    }
    Ok(hk_state::pool::full_tree_path(&leaves, index))
}

fn nullifier_spent(http: &Http, nf: &Hash, asset: &H256) -> bool {
    http.rpc("hk_nullifierSpent", with_asset(json!({ "nullifier": hex::encode(nf) }), asset))
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
fn pick_note(notes: &[(Discovered, bool)], amt: Amount, a: &AssetCtx) -> Result<Discovered, WalletError> {
    let mut c: Vec<&Discovered> =
        notes.iter().filter(|(d, spent)| !spent && (d.note.value as Amount) >= amt).map(|(d, _)| d).collect();
    if c.is_empty() {
        let have: Vec<String> = notes.iter().filter(|(_, s)| !s).map(|(d, _)| a.fmt(d.note.value as Amount)).collect();
        return Err(WalletError::msg(format!(
            "no single shielded {} note covers {} — unspent notes: [{}]. One note per spend; consolidate by paying yourself first",
            a.symbol,
            a.fmt(amt),
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
            pools: BTreeMap::new(),
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
    /// One address for every pool — it is a property of the shield master.
    pub(crate) fn stealth_address_of(&self, http: &Http, f: &ShieldFile) -> Result<String, WalletError> {
        let k = keys(f)?;
        Ok(addr_encode(&k.address_at(epoch_of(http.height()?))))
    }

    /// The fee is always paid from the NATIVE transparent balance — refuse locally before a
    /// proof is made for a spend the chain would refuse.
    fn require_fee(&self, http: &Http, id: &H256) -> Result<Amount, WalletError> {
        let fee = http.chain_info()?.fee_now();
        if http.balance(id)? < fee {
            return Err(WalletError::msg(format!(
                "The network fee ({} test units) is paid from your TRANSPARENT native balance — top it up first (Get test funds).",
                fmt_amount(fee)
            )));
        }
        Ok(fee)
    }

    /// Every note ever paid to this wallet (all epochs) in `asset`'s pool, with spent status —
    /// incremental against that pool's own cursor.
    fn my_notes(&self, http: &Http, k: &WalletKeys, f: &mut ShieldFile, asset: &H256) -> Result<Vec<(Discovered, bool)>, WalletError> {
        let chain_id = http.chain_info().map(|c| c.chain_id).unwrap_or_default();
        let mut changed = false;
        let cache = f.cache_mut(asset);
        if cache.chain_id != chain_id {
            *cache = ScanCache { chain_id, ..Default::default() };
            changed = true;
        }
        let (mut entries, mut total) = pool_notes_from(http, cache.scanned_through, asset)?;
        if total < cache.scanned_through {
            *cache = ScanCache { chain_id: cache.chain_id.clone(), ..Default::default() };
            changed = true;
            let again = pool_notes_from(http, 0, asset)?;
            entries = again.0;
            total = again.1;
        }
        if !entries.is_empty() {
            let cur = epoch_of(http.height()?);
            for e in 0..=cur {
                for d in scan_at(k, e, &entries) {
                    if !cache.notes.iter().any(|n| n.leaf_index == d.leaf_index) {
                        cache.notes.push(StoredNote::from_discovered(&d));
                        changed = true;
                    }
                }
            }
        }
        if total > cache.scanned_through {
            cache.scanned_through = total;
            changed = true;
        }
        let nk = k.nk();
        let owner = k.owner_tag();
        let mut out: Vec<(Discovered, bool)> = Vec::with_capacity(cache.notes.len());
        for n in cache.notes.iter_mut() {
            let d = n.to_discovered(owner)?;
            if !n.spent && nullifier_spent(http, &nullifier(&nk, &d.note.rho), asset) {
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

    pub(crate) fn do_scan(&self, a: &AssetCtx) -> Result<ScanResult, WalletError> {
        let http = self.http();
        let mut f = self.load_or_create_shield()?;
        let stealth_address = self.stealth_address_of(&http, &f)?;
        let before = f.cache(&a.id).map(|c| c.scanned_through).unwrap_or(0);
        let k = keys(&f)?;
        let notes = self.my_notes(&http, &k, &mut f, &a.id)?;
        let pool_size = f.cache(&a.id).map(|c| c.scanned_through).unwrap_or(0);
        let unspent = notes.iter().filter(|(_, s)| !s).count() as u32;
        let fresh = pool_size.saturating_sub(before);
        self.log_info(format!(
            "Scanned {fresh} new {} pool entr{} (pool size {pool_size}): {} note(s) are yours, {unspent} unspent.",
            a.symbol,
            if fresh == 1 { "y" } else { "ies" },
            notes.len()
        ));
        Ok(ScanResult {
            notes: views(&notes),
            fresh_entries: fresh,
            pool_size,
            unspent,
            stealth_address,
            ots_used: f.next_ots_index,
            ots_capacity: OTS_CAPACITY,
            asset: hex::encode(a.id.0),
        })
    }

    /// Transparent → pool (of `asset`).
    pub(crate) fn do_shield(&self, amount: Amount, a: &AssetCtx) -> Result<TxResult, WalletError> {
        let http = self.http();
        let (seed, id) = self.signer()?;
        let mut f = self.load_or_create_shield()?;
        let k = keys(&f)?;
        let fee = http.chain_info()?.fee_now();
        if a.id == USD {
            let bal = http.balance(&id)?;
            if amount.saturating_add(fee) > bal {
                return Err(WalletError::msg(format!(
                    "Not enough transparent balance for {} + network fee {} (have {}).",
                    a.fmt(amount),
                    fmt_amount(fee),
                    a.fmt(bal)
                )));
            }
        } else {
            self.require_fee(&http, &id)?;
            let bal = http.balance_of(&id, &a.id)?;
            if amount > bal {
                return Err(WalletError::msg(format!("Not enough {}: shielding {} but the transparent balance is {}.", a.symbol, a.fmt(amount), a.fmt(bal))));
            }
        }
        if amount > u64::MAX as Amount {
            return Err(WalletError::msg("amount too large for a single note"));
        }
        let tag = self.reserve_tag(&mut f)?;
        let note = k.self_note(amount as u64, tag);
        let (witness, public) = build_mint(&note);
        let epoch = epoch_of(http.height()?);
        let (ct, _) = seal_note(&note, &k.address_at(epoch), &fresh32(), b"shield").ok_or_else(|| WalletError::msg("seal failed"))?;
        self.log_info(format!("Proving the mint of {} {} on the prover… (a STARK; this can take a while)", a.fmt(amount), a.symbol));
        let (proof, ms) = http.prove("prove_mint", serde_json::to_value(&witness).map_err(|e| WalletError::msg(e.to_string()))?)?;
        self.log_info(format!("Proof ready in {ms} ms — submitting."));
        self.send_payload(
            &http,
            &seed,
            id,
            Tx::MintToPool { asset: a.id, value: amount, commitment: H256(public.commitment), proof, stealth_ct: ct },
            &format!("Shielded {} {} ✓", a.fmt(amount), a.symbol),
        )
    }

    /// Pool (of `asset`) → transparent (our own account, credited in that asset).
    pub(crate) fn do_unshield(&self, amount: Amount, a: &AssetCtx) -> Result<TxResult, WalletError> {
        let http = self.http();
        let (seed, id) = self.signer()?;
        let mut f = self.load_or_create_shield()?;
        let k = keys(&f)?;
        self.require_fee(&http, &id)?;
        let notes = self.my_notes(&http, &k, &mut f, &a.id)?;
        let input = pick_note(&notes, amount, a)?;
        let change_v = input.note.value as Amount - amount;
        let (siblings, root) = pool_path(&http, input.leaf_index, &a.id)?;
        let tag = self.reserve_tag(&mut f)?;
        let ots = self.reserve_ots(&mut f)?;
        let change = k.self_note(change_v as u64, tag);
        let epoch = epoch_of(http.height()?);
        let (change_ct, _) = seal_note(&change, &k.address_at(epoch), &fresh32(), b"change").ok_or_else(|| WalletError::msg("seal failed"))?;
        let plan = build_spend_with_path(siblings, root, input.leaf_index, input.note.clone(), &k, ots, change, dummy_note(), amount as u64, id.0)
            .map_err(|e| WalletError::msg(format!("build_spend: {e}")))?;
        self.log_info(format!("Proving the spend of {} {} on the prover… (a STARK; this can take a while)", a.fmt(amount), a.symbol));
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
            &format!("Unshielded {} {} ✓ ({} change went back into hiding)", a.fmt(amount), a.symbol, a.fmt(change_v)),
        )
    }

    /// Fully shielded payment to a stealth address, in `asset`'s pool.
    pub(crate) fn do_pay(&self, to: &str, amount: Amount, memo: &str, a: &AssetCtx) -> Result<TxResult, WalletError> {
        let http = self.http();
        let (seed, id) = self.signer()?;
        let to = addr_decode(to)?;
        let mut f = self.load_or_create_shield()?;
        let k = keys(&f)?;
        self.require_fee(&http, &id)?;
        let notes = self.my_notes(&http, &k, &mut f, &a.id)?;
        let input = pick_note(&notes, amount, a)?;
        let change_v = input.note.value as Amount - amount;
        let out = build_output(&to, amount as u64, &fresh32(), &fresh32(), memo.as_bytes())
            .ok_or_else(|| WalletError::msg("could not build the output (bad recipient address?)"))?;
        let (siblings, root) = pool_path(&http, input.leaf_index, &a.id)?;
        let tag = self.reserve_tag(&mut f)?;
        let ots = self.reserve_ots(&mut f)?;
        let change = k.self_note(change_v as u64, tag);
        let epoch = epoch_of(http.height()?);
        let (change_ct, _) = seal_note(&change, &k.address_at(epoch), &fresh32(), b"change").ok_or_else(|| WalletError::msg("seal failed"))?;
        let plan = build_spend_with_path(siblings, root, input.leaf_index, input.note.clone(), &k, ots, out.note.clone(), change, 0, [0; 32])
            .map_err(|e| WalletError::msg(format!("build_spend: {e}")))?;
        self.log_info(format!("Proving a shielded payment of {} {} on the prover… (a STARK; this can take a while)", a.fmt(amount), a.symbol));
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
            &format!("Paid {} {} shielded ✓ — the chain saw one nullifier and two commitments; who paid whom is invisible", a.fmt(amount), a.symbol),
        )
    }

    /// One-time disclosure package (JSON) for a note WE received in `asset`'s pool.
    pub(crate) fn do_disclose(&self, commitment_hex: &str, a: &AssetCtx) -> Result<String, WalletError> {
        let http = self.http();
        let mut f = self.load_shield()?.ok_or_else(|| WalletError::msg("no shield.json — nothing shielded yet"))?;
        let k = keys(&f)?;
        let commitment_hex = commitment_hex.trim().to_lowercase();
        let cm: Hash = parse_hash(&commitment_hex, "commitment")?;
        let asset = a.id;
        let cached = f.cache(&asset).and_then(|c| c.notes.iter().find(|n| n.commitment == commitment_hex).map(|n| n.leaf_index));
        let idx = match cached {
            Some(i) => i,
            None => {
                let _ = self.my_notes(&http, &k, &mut f, &asset);
                f.cache(&asset)
                    .and_then(|c| c.notes.iter().find(|n| n.commitment == commitment_hex).map(|n| n.leaf_index))
                    .or_else(|| pool_notes_from(&http, 0, &asset).ok()?.0.into_iter().find(|(_, c, _)| *c == cm).map(|(i, _, _)| i))
                    .ok_or_else(|| WalletError::msg(format!("commitment not found in the {} pool", a.symbol)))?
            }
        };
        let (_, _, ct) = pool_entry(&http, idx, &asset)?;
        let cur = epoch_of(http.height()?);
        let key = (0..=cur)
            .filter_map(|e| note_key_as_recipient(&k, e, &cm, &ct))
            .find(|key| ct.len() > hk_crypto::mlkem::CT_LEN && hk_crypto::noteenc::open(key, &cm, &ct[hk_crypto::mlkem::CT_LEN..]).is_some())
            .ok_or_else(|| WalletError::msg("this wallet cannot open that ciphertext (not the recipient)"))?;
        let chain_id = http.chain_info().map(|c| c.chain_id).unwrap_or_else(|_| "hashkinetics".into());
        let (siblings, anchor) = pool_path(&http, idx, &asset)?;
        let pkg = build_disclosure_with_path(&chain_id, cm, siblings, anchor, idx, k.owner_tag(), ct, key)
            .ok_or_else(|| WalletError::msg("package build failed (the node's path does not fold to its root)"))?;
        let mut text = serde_json::to_string_pretty(&pkg).map_err(|e| WalletError::msg(e.to_string()))?;
        // P6.2: the package names the pool it was opened against, so an auditor verifying it
        // knows which pool's anchor to check (a verifier that predates P6.2 ignores the field).
        if asset != USD {
            if let Ok(mut v) = serde_json::from_str::<Value>(&text) {
                if let Some(o) = v.as_object_mut() {
                    o.insert("asset".into(), json!(hex::encode(asset.0)));
                    text = serde_json::to_string_pretty(&v).map_err(|e| WalletError::msg(e.to_string()))?;
                }
            }
        }
        let out = self.dir.join(format!("disclosure-{}.json", &commitment_hex[..12.min(commitment_hex.len())]));
        std::fs::write(&out, &text).map_err(|e| WalletError::msg(e.to_string()))?;
        self.log_info(format!("Disclosure package written: {} — it opens exactly this payment and nothing else.", out.display()));
        Ok(text)
    }

    /// The value the app shows next to "Shielded" without a scan: cached notes of one pool.
    pub(crate) fn cached_notes(&self, asset: &H256) -> Result<Vec<NoteView>, WalletError> {
        let f = match self.load_shield()? {
            Some(f) => f,
            None => return Ok(Vec::new()),
        };
        Ok(f.cache(asset)
            .map(|c| {
                c.notes
                    .iter()
                    .map(|n| NoteView {
                        value_micro: n.value,
                        leaf_index: n.leaf_index,
                        memo: String::from_utf8_lossy(&hex::decode(&n.memo).unwrap_or_default()).to_string(),
                        commitment: n.commitment.clone(),
                        spent: n.spent,
                    })
                    .collect()
            })
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p62_shield_file_keeps_the_legacy_shape_and_adds_pools() {
        // A file written before P6.2 (no `pools`) loads, and its legacy cache is the native pool's.
        let old = r#"{"version":1,"master_hex":"00","next_ots_index":3,"next_note_tag":9,
            "scan":{"chain_id":"c","scanned_through":42,"notes":[]}}"#;
        let mut f: ShieldFile = serde_json::from_str(old).unwrap();
        assert!(f.pools.is_empty());
        assert_eq!(f.cache(&USD).unwrap().scanned_through, 42);
        let usdc = H256([0x0cu8; 32]);
        assert!(f.cache(&usdc).is_none(), "an asset never scanned has no cache");
        // First use creates the per-asset cache; the legacy one is untouched.
        f.cache_mut(&usdc).scanned_through = 7;
        assert_eq!(f.cache(&usdc).unwrap().scanned_through, 7);
        assert_eq!(f.cache(&USD).unwrap().scanned_through, 42);
        // Round trip keeps both, and the legacy fields stay where every older reader expects them.
        let text = serde_json::to_string(&f).unwrap();
        let back: ShieldFile = serde_json::from_str(&text).unwrap();
        assert_eq!(back.cache(&usdc).unwrap().scanned_through, 7);
        assert_eq!(back.next_ots_index, 3);
        assert!(text.contains("\"scan\"") && text.contains("\"pools\""));
    }

    #[test]
    fn p62_native_pool_is_addressed_without_an_asset_parameter() {
        let p = with_asset(json!({ "from": 0 }), &USD);
        assert!(p.get("asset").is_none(), "the legacy pool must be addressed by omission: {p}");
        let a = H256([1u8; 32]);
        let p = with_asset(json!({ "from": 0 }), &a);
        assert_eq!(p.get("asset").and_then(|x| x.as_str()), Some(hex::encode(a.0).as_str()));
    }
}
