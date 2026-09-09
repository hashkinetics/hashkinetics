//! attest.rs — `hk-attest`, the bridge attestation service (B1, docs/BRIDGE-SEPOLIA-USDC-PLAN.md),
//! shipped as `hk-node attest-serve <CONFIG.toml>` so it reuses the node's account files, sealed-key
//! handling, RPC client and receipts exactly as the CLI does.
//!
//! Four flows, one loop, one ledger:
//!   deposit  Sepolia `Locked` on HKVault      → after finality → AssetMint USDC.sep on HashKinetics
//!   burn     HashKinetics `asset_burn` USDC.sep → EIP-712 attestation(s) → HKVault.unlock on Sepolia
//!   wlock    HashKinetics `asset_burn` HKT     → attestation(s) → HKWrapped.mint (wHKT.sep) on Sepolia
//!   wburn    Sepolia `Burned` on HKWrapped     → after finality → AssetMint HKT on HashKinetics
//!
//! The ledger is an append-only JSONL file with a WRITE-AHEAD rule: a record goes to `submitting`
//! (fsynced) BEFORE any transaction leaves this process, to `submitted` with the id the moment the
//! network has it, and to `confirmed` on a receipt. A crash between `submitting` and `submitted`
//! leaves a record the service will NOT retry by itself — it is listed under `needs_review` on
//! /health and resolved by an operator with `hk-node attest-ledger … resolve` after checking the
//! chain. That is what makes `kill -9` at any instant unable to double-mint or double-unlock; on
//! the Ethereum side the vault's `processed[id]` is checked before every send as a second guard.
//!
//! Trust label: the attestor key is ECDSA because Ethereum verifies nothing else. It never moves a
//! HashKinetics balance — the mint is signed by the bridge issuer's hash-based account key.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hk_primitives::{Amount, H256};
use hk_state::tx::Tx;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::account::{parse_h256, AccountFile};
use crate::demo::{self, Wallet};
use crate::eth::{self, Address, BridgeEvent, EthClient, Signer};

// ---------------------------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize, Clone)]
pub(crate) struct Cfg {
    pub hk: HkCfg,
    pub eth: EthCfg,
    #[serde(default)]
    pub service: ServiceCfg,
}

#[derive(Deserialize, Clone)]
pub(crate) struct HkCfg {
    /// The HashKinetics RPC this service reads and submits to (a node we run; the public edge works too).
    pub rpc: String,
    /// The bridge issuer's account directory (`hk-node account-new`; sealed → HK_WALLET_PASSPHRASE_FILE).
    pub issuer_dir: String,
    /// Asset id of USDC.sep (64 hex).
    pub usdc_asset: String,
    /// Asset id of the HK-issued asset wrapped on Sepolia (HKT), optional (reverse leg).
    #[serde(default)]
    pub hkt_asset: Option<String>,
    /// First HashKinetics height to scan (the asset's registration height is a fine choice).
    #[serde(default)]
    pub from_height: u64,
}

#[derive(Deserialize, Clone)]
pub(crate) struct EthCfg {
    /// Provider URL (a credential: prefer `ETH_RPC_URL` in the environment / a systemd credential over the file).
    #[serde(default)]
    pub rpc: String,
    pub chain_id: u64,
    pub vault: String,
    #[serde(default)]
    pub wrapped: Option<String>,
    /// First Ethereum block to scan (the vault's deploy block).
    pub from_block: u64,
    /// `finalized` (default) · `safe` · `latest` · a number of confirmations (demo/anvil).
    #[serde(default = "default_confirm")]
    pub confirm: String,
    /// Path to the attestor key (32 bytes hex); overridden by `ETH_ATTESTOR_KEY_FILE` / `ETH_ATTESTOR_KEY`.
    #[serde(default)]
    pub attestor_key_file: Option<String>,
    /// Co-signer endpoints (`hk-node attest-cosign`) queried for extra attestations; t-of-n on the contract.
    #[serde(default)]
    pub cosigners: Vec<String>,
    /// Blocks per eth_getLogs page.
    #[serde(default = "default_page")]
    pub log_page: u64,
}

fn default_confirm() -> String {
    "finalized".into()
}
fn default_page() -> u64 {
    2000
}

#[derive(Deserialize, Clone)]
pub(crate) struct ServiceCfg {
    #[serde(default = "default_ledger")]
    pub ledger: String,
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_poll")]
    pub poll_secs: u64,
    /// Maximum HashKinetics heights scanned per loop (keeps /health responsive while catching up).
    #[serde(default = "default_hk_batch")]
    pub hk_batch: u64,
    /// Reconciliation interval (vault reserves vs supply − burned).
    #[serde(default = "default_reconcile")]
    pub reconcile_secs: u64,
}

impl Default for ServiceCfg {
    fn default() -> Self {
        Self {
            ledger: default_ledger(),
            listen: default_listen(),
            poll_secs: default_poll(),
            hk_batch: default_hk_batch(),
            reconcile_secs: default_reconcile(),
        }
    }
}
fn default_ledger() -> String {
    "attest-ledger.jsonl".into()
}
fn default_listen() -> String {
    "127.0.0.1:9933".into()
}
fn default_poll() -> u64 {
    5
}
fn default_hk_batch() -> u64 {
    300
}
fn default_reconcile() -> u64 {
    600
}

// ---------------------------------------------------------------------------------------------
// the ledger
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct Event {
    pub t: u64,
    pub kind: String,
    pub id: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub fields: serde_json::Map<String, Value>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub(crate) struct Record {
    pub kind: String,
    pub id: String,
    pub state: String,
    pub amount: u128,
    /// deposit/wburn: the HashKinetics account credited · burn/wlock: the Sepolia address paid
    pub to: String,
    /// where it was seen: the Ethereum block or the HashKinetics height
    pub at: u64,
    pub source_tx: String,
    pub hk_txid: Option<String>,
    pub eth_tx: Option<String>,
    pub note: Option<String>,
    pub updated: u64,
    pub attempts: u32,
}

pub(crate) struct Ledger {
    file: File,
    pub records: BTreeMap<String, Record>,
    pub eth_cursor: u64,
    pub hk_cursor: u64,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn key(kind: &str, id: &str) -> String {
    format!("{kind}:{id}")
}

impl Ledger {
    pub(crate) fn open(path: &Path, eth_from: u64, hk_from: u64) -> eyre::Result<Self> {
        let mut records = BTreeMap::new();
        let mut eth_cursor = eth_from.saturating_sub(1);
        let mut hk_cursor = hk_from.saturating_sub(1);
        if path.exists() {
            let f = File::open(path)?;
            for (n, line) in BufReader::new(f).lines().enumerate() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let ev: Event = serde_json::from_str(&line).map_err(|e| eyre::eyre!("ledger line {}: {e}", n + 1))?;
                Self::fold(&mut records, &mut eth_cursor, &mut hk_cursor, &ev);
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file, records, eth_cursor, hk_cursor })
    }

    fn fold(records: &mut BTreeMap<String, Record>, eth_cursor: &mut u64, hk_cursor: &mut u64, ev: &Event) {
        if ev.kind == "cursor" {
            let n = ev.fields.get("n").and_then(|v| v.as_u64()).unwrap_or(0);
            match ev.id.as_str() {
                "eth" => *eth_cursor = n,
                "hk" => *hk_cursor = n,
                _ => {}
            }
            return;
        }
        let r = records.entry(key(&ev.kind, &ev.id)).or_insert_with(|| Record {
            kind: ev.kind.clone(),
            id: ev.id.clone(),
            ..Default::default()
        });
        r.state = ev.state.clone();
        r.updated = ev.t;
        let f = &ev.fields;
        if let Some(a) = f.get("amount").and_then(|v| v.as_str()).and_then(|s| s.parse::<u128>().ok()) {
            r.amount = a;
        }
        if let Some(s) = f.get("to").and_then(|v| v.as_str()) {
            r.to = s.to_string();
        }
        if let Some(n) = f.get("at").and_then(|v| v.as_u64()) {
            r.at = n;
        }
        if let Some(s) = f.get("source_tx").and_then(|v| v.as_str()) {
            r.source_tx = s.to_string();
        }
        if let Some(s) = f.get("hk_txid").and_then(|v| v.as_str()) {
            r.hk_txid = Some(s.to_string());
        }
        if let Some(s) = f.get("eth_tx").and_then(|v| v.as_str()) {
            r.eth_tx = Some(s.to_string());
        }
        if let Some(s) = f.get("note").and_then(|v| v.as_str()) {
            r.note = Some(s.to_string());
        }
        if f.get("attempt").is_some() {
            r.attempts += 1;
        }
    }

    /// Append + flush + fsync, then fold — the line is on disk before the state is in memory.
    pub(crate) fn write(&mut self, kind: &str, id: &str, state: &str, fields: Value) -> eyre::Result<()> {
        let fields = match fields {
            Value::Object(m) => m,
            _ => serde_json::Map::new(),
        };
        let ev = Event { t: now(), kind: kind.into(), id: id.into(), state: state.into(), fields };
        let mut line = serde_json::to_string(&ev)?;
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.flush()?;
        self.file.sync_data()?;
        let (mut e, mut h) = (self.eth_cursor, self.hk_cursor);
        Self::fold(&mut self.records, &mut e, &mut h, &ev);
        self.eth_cursor = e;
        self.hk_cursor = h;
        Ok(())
    }

    pub(crate) fn cursor(&mut self, chain: &str, n: u64) -> eyre::Result<()> {
        self.write("cursor", chain, "", json!({"n": n}))
    }

    pub(crate) fn has(&self, kind: &str, id: &str) -> bool {
        self.records.contains_key(&key(kind, id))
    }

    pub(crate) fn get(&self, kind: &str, id: &str) -> Option<&Record> {
        self.records.get(&key(kind, id))
    }

    pub(crate) fn in_states(&self, kind: &str, states: &[&str]) -> Vec<Record> {
        self.records
            .values()
            .filter(|r| r.kind == kind && states.contains(&r.state.as_str()))
            .cloned()
            .collect()
    }

    pub(crate) fn counts(&self) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for r in self.records.values() {
            *m.entry(format!("{}:{}", r.kind, r.state)).or_insert(0) += 1;
        }
        m
    }
}

// ---------------------------------------------------------------------------------------------
// health
// ---------------------------------------------------------------------------------------------

#[derive(Default, Clone)]
struct Health {
    started: u64,
    eth_head: u64,
    eth_safe: u64,
    eth_cursor: u64,
    hk_height: u64,
    hk_cursor: u64,
    attestor: String,
    attestor_wei: u128,
    issuer: String,
    issuer_fee_micro: u128,
    vault_paused: bool,
    vault_remaining_today: u128,
    reserves: u128,
    supply_minus_burned: u128,
    reconciled_at: u64,
    reconciled_ok: bool,
    counts: BTreeMap<String, usize>,
    needs_review: Vec<Value>,
    held: Vec<Value>,
    last_error: Option<String>,
    loops: u64,
}

fn health_json(h: &Health) -> Value {
    json!({
        "ok": h.last_error.is_none() && h.reconciled_ok && h.needs_review.is_empty(),
        "uptime_secs": now().saturating_sub(h.started),
        "loops": h.loops,
        "eth": {"head": h.eth_head, "safe": h.eth_safe, "cursor": h.eth_cursor, "lag_blocks": h.eth_head.saturating_sub(h.eth_cursor),
                "attestor": h.attestor, "attestor_wei": h.attestor_wei.to_string(),
                "vault_paused": h.vault_paused, "vault_remaining_today": h.vault_remaining_today.to_string()},
        "hk": {"height": h.hk_height, "cursor": h.hk_cursor, "lag_heights": h.hk_height.saturating_sub(h.hk_cursor),
               "issuer": h.issuer, "issuer_fee_micro": h.issuer_fee_micro.to_string()},
        "reconciliation": {"vault_reserves": h.reserves.to_string(), "supply_minus_burned": h.supply_minus_burned.to_string(),
                           "ok": h.reconciled_ok, "at": h.reconciled_at},
        "counts": h.counts,
        "needs_review": h.needs_review,
        "held": h.held,
        "last_error": h.last_error,
    })
}

fn respond(stream: &mut TcpStream, status: &str, body: &Value) {
    let body = body.to_string();
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
}

fn serve_health(listen: &str, health: Arc<Mutex<Health>>) -> eyre::Result<()> {
    let listener = TcpListener::bind(listen)?;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let health = health.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let h = health.lock().unwrap_or_else(|e| e.into_inner()).clone();
                respond(&mut stream, "200 OK", &health_json(&h));
            });
        }
    });
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// HashKinetics side helpers
// ---------------------------------------------------------------------------------------------

/// Sign + submit one envelope from the issuer directory with the CLI's reserve-then-sign discipline;
/// returns the txid. `HK_ATTEST_CRASH=after-submit` is the gate's crash hook (exit right after the submit).
fn hk_submit(dir: &Path, rpc: &str, payload: Tx) -> Result<String, String> {
    let mut f = AccountFile::load(dir).map_err(|e| e.to_string())?;
    let seed = f.seed_bytes().map_err(|e| e.to_string())?;
    let id = f.id_h256().map_err(|e| e.to_string())?;
    match demo::account_nonce(rpc, &id) {
        Some(n) => {
            if n != f.next_nonce {
                f.next_nonce = n;
            }
        }
        None => return Err("issuer account does not exist on-chain".into()),
    }
    let mut w = Wallet::from_seed(seed, id, f.next_nonce);
    let tx = w.sign(payload);
    f.next_nonce = w.next_nonce;
    f.save(dir).map_err(|e| e.to_string())?;
    let txid = demo::submit(rpc, &tx);
    if txid.starts_with("submit-failed") {
        f.next_nonce -= 1;
        let _ = f.save(dir);
        return Err(txid);
    }
    if std::env::var("HK_ATTEST_CRASH").map(|v| v == "after-submit").unwrap_or(false) {
        eprintln!("HK_ATTEST_CRASH=after-submit: exiting after submit, before the txid is recorded");
        std::process::exit(9);
    }
    Ok(txid)
}

/// Wait up to ~20 s for a receipt; `Some("ok…")` / `Some("rejected…")` / `None` (still pending).
fn hk_wait_receipt(rpc: &str, txid: &str) -> Option<String> {
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(700));
        if let Some(r) = demo::receipt(rpc, txid) {
            return Some(r);
        }
    }
    None
}

fn hk_account_exists(rpc: &str, id: &H256) -> bool {
    demo::account_nonce(rpc, id).is_some()
}

fn hk_asset_supply_minus_burned(rpc: &str, asset: &H256) -> Option<u128> {
    let v = demo::rpc(rpc, "hk_getAsset", json!({"asset": hex::encode(asset.0)}));
    let a = v.get("result")?.get("asset")?;
    let supply: u128 = a.get("supply")?.as_str()?.parse().ok()?;
    let burned: u128 = a.get("burned")?.as_str()?.parse().ok()?;
    Some(supply.saturating_sub(burned))
}

/// Every committed `asset_burn` of `asset` at `height`: (txid, amount, destination hex, receipt class) where the
/// class is `ok` (accepted), `rejected` (moved nothing) or `unknown` (the node has no receipt for it — a restart
/// since that block; such a burn is held for review, never silently skipped and never bridged unverified).
fn hk_burns_at(rpc: &str, height: u64, asset_hex: &str) -> Result<Vec<(String, u128, String, &'static str)>, String> {
    let v = demo::rpc(rpc, "hk_getBlock", json!({"height": height}));
    if let Some(e) = v.get("error") {
        return Err(format!("hk_getBlock {height}: {e}"));
    }
    let r = v.get("result").ok_or_else(|| format!("hk_getBlock {height}: no result"))?;
    if r.get("found").and_then(|f| f.as_bool()) == Some(false) {
        return Err(format!("hk_getBlock {height}: not found"));
    }
    let mut out = Vec::new();
    for tx in r.get("txs").and_then(|t| t.as_array()).cloned().unwrap_or_default() {
        if tx.get("kind").and_then(|k| k.as_str()) != Some("asset_burn") {
            continue;
        }
        let f = tx.get("fields").cloned().unwrap_or(Value::Null);
        if f.get("asset").and_then(|a| a.as_str()) != Some(asset_hex) {
            continue;
        }
        // a refused burn carries a `rejected: …` receipt and moved nothing — never bridge it.
        // hk_getBlock reports the receipt as {found, ok, detail}; hk_getTx as a bare string — accept both.
        let class = match tx.get("receipt") {
            Some(Value::String(r)) if r.starts_with("ok") => "ok",
            Some(Value::String(_)) => "rejected",
            Some(Value::Object(o)) => match (o.get("found").and_then(|f| f.as_bool()), o.get("ok").and_then(|k| k.as_bool())) {
                (Some(true), Some(true)) => "ok",
                (Some(true), _) => "rejected",
                _ => "unknown",
            },
            _ => "unknown",
        };
        if class == "rejected" {
            continue;
        }
        let txid = tx.get("txid").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let amount: u128 = f.get("amount").and_then(|a| a.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
        let dest = f.get("destination").and_then(|d| d.as_str()).unwrap_or("").to_string();
        out.push((txid, amount, dest, class));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// the service
// ---------------------------------------------------------------------------------------------

struct Svc {
    cfg: Cfg,
    eth: EthClient,
    signer: Signer,
    vault: Address,
    wrapped: Option<Address>,
    vault_domain: [u8; 32],
    wrapped_domain: Option<[u8; 32]>,
    usdc: H256,
    hkt: Option<H256>,
    issuer_dir: PathBuf,
    issuer_id: H256,
    fee_asset: H256,
    ledger: Ledger,
    health: Arc<Mutex<Health>>,
}

fn env_or(cfg: &str, var: &str) -> String {
    std::env::var(var).ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| cfg.to_string())
}

fn load_attestor_key(cfg: &EthCfg) -> Result<Signer, String> {
    if let Ok(k) = std::env::var("ETH_ATTESTOR_KEY") {
        return Signer::from_hex(&k);
    }
    let path = std::env::var("ETH_ATTESTOR_KEY_FILE")
        .ok()
        .or_else(|| cfg.attestor_key_file.clone())
        .or_else(|| std::env::var("CREDENTIALS_DIRECTORY").ok().map(|d| format!("{d}/attestor.key")))
        .ok_or("no attestor key: set ETH_ATTESTOR_KEY_FILE (or eth.attestor_key_file) — a file with 32 bytes of hex")?;
    let s = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    Signer::from_hex(&s)
}

pub(crate) fn cmd_serve(cfg_path: &Path) -> eyre::Result<()> {
    let text = std::fs::read_to_string(cfg_path)?;
    let cfg: Cfg = toml::from_str(&text).map_err(|e| eyre::eyre!("{}: {e}", cfg_path.display()))?;
    let eth_url = env_or(&cfg.eth.rpc, "ETH_RPC_URL");
    if eth_url.is_empty() {
        return Err(eyre::eyre!("no Ethereum RPC: set ETH_RPC_URL or eth.rpc"));
    }
    let eth = EthClient::new(&eth_url, cfg.eth.chain_id);
    let got = eth.chain_id().map_err(|e| eyre::eyre!("eth: {e}"))?;
    if got != cfg.eth.chain_id {
        return Err(eyre::eyre!("eth chain id mismatch: provider says {got}, config says {}", cfg.eth.chain_id));
    }
    let signer = load_attestor_key(&cfg.eth).map_err(|e| eyre::eyre!(e))?;
    let vault = Address::parse(&cfg.eth.vault).map_err(|e| eyre::eyre!(e))?;
    let wrapped = match &cfg.eth.wrapped {
        Some(w) if !w.trim().is_empty() => Some(Address::parse(w).map_err(|e| eyre::eyre!(e))?),
        _ => None,
    };
    // the check that matters: our EIP-712 domain == the contract's
    let vault_domain = eth::domain_separator("HKVault", cfg.eth.chain_id, &vault);
    let on_chain = eth::decode_word_b32(&eth.eth_call(&vault, &eth::encode_view("domainSeparator()")).map_err(|e| eyre::eyre!("vault: {e}"))?)
        .map_err(|e| eyre::eyre!(e))?;
    if on_chain != vault_domain {
        return Err(eyre::eyre!("EIP-712 domain mismatch with the vault (name/version/chain/contract) — refusing to start"));
    }
    let is_att = eth
        .eth_call(&vault, &eth::encode_attestor_query(&signer.address))
        .ok()
        .and_then(|b| eth::decode_word_u(&b).ok())
        .unwrap_or(0);
    if is_att != 1 {
        eprintln!("WARNING: {} is not in the vault's attestor set — unlocks will be refused until it is", signer.address.hex());
    }
    let wrapped_domain = match (&wrapped, &cfg.eth.wrapped) {
        (Some(w), _) => {
            let name_bytes = eth.eth_call(w, &eth::encode_view("name()")).map_err(|e| eyre::eyre!("wrapped: {e}"))?;
            let name = eth::decode_string(&name_bytes).map_err(|e| eyre::eyre!(e))?;
            let d = eth::domain_separator(&name, cfg.eth.chain_id, w);
            let on = eth::decode_word_b32(&eth.eth_call(w, &eth::encode_view("domainSeparator()")).map_err(|e| eyre::eyre!("wrapped: {e}"))?)
                .map_err(|e| eyre::eyre!(e))?;
            if on != d {
                return Err(eyre::eyre!("EIP-712 domain mismatch with HKWrapped — refusing to start"));
            }
            Some(d)
        }
        _ => None,
    };
    let usdc = parse_h256(&cfg.hk.usdc_asset)?;
    let hkt = match &cfg.hk.hkt_asset {
        Some(h) if !h.trim().is_empty() => Some(parse_h256(h)?),
        _ => None,
    };
    if hkt.is_some() != wrapped.is_some() {
        return Err(eyre::eyre!("hk.hkt_asset and eth.wrapped must be set together (the reverse leg)"));
    }
    let issuer_dir = PathBuf::from(&cfg.hk.issuer_dir);
    let issuer_id = AccountFile::load(&issuer_dir)?.id_h256()?;
    let info = demo::rpc(&cfg.hk.rpc, "hk_chainInfo", json!({}));
    let fee_asset = info
        .get("result")
        .and_then(|r| r.get("fee"))
        .and_then(|f| f.get("asset"))
        .and_then(|a| a.as_str())
        .and_then(|s| parse_h256(s).ok())
        .unwrap_or(H256([9u8; 32]));
    // the issuer must be the asset's issuer, or every mint is refused
    let a = demo::rpc(&cfg.hk.rpc, "hk_getAsset", json!({"asset": hex::encode(usdc.0)}));
    let issuer_on_chain = a.get("result").and_then(|r| r.get("asset")).and_then(|x| x.get("issuer")).and_then(|s| s.as_str()).unwrap_or("");
    if issuer_on_chain != hex::encode(issuer_id.0) {
        return Err(eyre::eyre!("hk: {} is not the issuer of usdc_asset (issuer on chain: {issuer_on_chain}) — refusing to start", hex::encode(issuer_id.0)));
    }
    let ledger = Ledger::open(Path::new(&cfg.service.ledger), cfg.eth.from_block, cfg.hk.from_height)?;
    let health = Arc::new(Mutex::new(Health { started: now(), attestor: signer.address.hex(), issuer: hex::encode(issuer_id.0), ..Default::default() }));
    serve_health(&cfg.service.listen, health.clone())?;
    eprintln!(
        "hk-attest: vault {} · chain {} · confirm {} · attestor {} · issuer {} · USDC.sep {} · ledger {} ({} records; eth cursor {}, hk cursor {}) · health http://{}/health",
        vault.hex(), cfg.eth.chain_id, cfg.eth.confirm, signer.address.hex(), hex::encode(issuer_id.0), hex::encode(usdc.0),
        cfg.service.ledger, ledger.records.len(), ledger.eth_cursor, ledger.hk_cursor, cfg.service.listen
    );
    let mut svc = Svc { cfg, eth, signer, vault, wrapped, vault_domain, wrapped_domain, usdc, hkt, issuer_dir, issuer_id, fee_asset, ledger, health };
    let mut last_reconcile = 0u64;
    loop {
        let t0 = now();
        let r = svc.tick();
        if let Err(e) = &r {
            eprintln!("hk-attest: {e}");
        }
        {
            let mut h = svc.health.lock().unwrap_or_else(|e| e.into_inner());
            h.last_error = r.err();
            h.loops += 1;
            h.eth_cursor = svc.ledger.eth_cursor;
            h.hk_cursor = svc.ledger.hk_cursor;
            h.counts = svc.ledger.counts();
            // `submitting` = a send may or may not have left before a crash — an operator's call, never a retry
            h.needs_review = svc.ledger.in_states("deposit", &["needs_review", "rejected", "submitting"]).iter()
                .chain(svc.ledger.in_states("wburn", &["needs_review", "rejected", "submitting"]).iter())
                .chain(svc.ledger.in_states("burn", &["needs_review", "reverted", "submitting"]).iter())
                .chain(svc.ledger.in_states("wlock", &["needs_review", "reverted", "submitting"]).iter())
                .map(|r| serde_json::to_value(r).unwrap_or(Value::Null)).collect();
            h.held = svc.ledger.in_states("deposit", &["held_recipient"]).iter()
                .chain(svc.ledger.in_states("wburn", &["held_recipient"]).iter())
                .chain(svc.ledger.in_states("burn", &["queued_cap", "queued_paused", "unbridgeable", "submitted"]).iter())
                .chain(svc.ledger.in_states("wlock", &["queued_cap", "queued_paused", "unbridgeable", "submitted"]).iter())
                .map(|r| serde_json::to_value(r).unwrap_or(Value::Null)).collect();
        }
        if now().saturating_sub(last_reconcile) >= svc.cfg.service.reconcile_secs {
            svc.reconcile();
            last_reconcile = now();
        }
        let spent = now().saturating_sub(t0);
        std::thread::sleep(Duration::from_secs(svc.cfg.service.poll_secs.saturating_sub(spent).max(1)));
    }
}

impl Svc {
    fn tick(&mut self) -> Result<(), String> {
        self.scan_eth()?;
        self.process_eth_events()?;
        self.scan_hk()?;
        self.process_hk_burns()?;
        Ok(())
    }

    /// The Ethereum block up to which events are final enough to act on.
    fn eth_safe_head(&self, head: u64) -> Result<u64, String> {
        let c = self.cfg.eth.confirm.trim();
        match c {
            "finalized" | "safe" | "latest" => self.eth.tagged_block(c),
            n => {
                let n: u64 = n.parse().map_err(|_| format!("eth.confirm must be finalized|safe|latest|<blocks>, got '{c}'"))?;
                Ok(head.saturating_sub(n))
            }
        }
    }

    fn scan_eth(&mut self) -> Result<(), String> {
        let head = self.eth.block_number()?;
        let safe = self.eth_safe_head(head)?;
        {
            let mut h = self.health.lock().unwrap_or_else(|e| e.into_inner());
            h.eth_head = head;
            h.eth_safe = safe;
        }
        // scan up to the head (events are recorded as seen; acted on only once safe)
        while self.ledger.eth_cursor < head {
            let from = self.ledger.eth_cursor + 1;
            let to = (from + self.cfg.eth.log_page - 1).min(head);
            let locked = self.eth.logs(&self.vault, &eth::event_topic(eth::LOCKED_SIG), from, to)?;
            for log in &locked {
                let ev = eth::decode_bridge_event(log)?;
                self.record_eth_event("deposit", &ev)?;
            }
            if let Some(w) = self.wrapped {
                let burned = self.eth.logs(&w, &eth::event_topic(eth::BURNED_SIG), from, to)?;
                for log in &burned {
                    let ev = eth::decode_bridge_event(log)?;
                    self.record_eth_event("wburn", &ev)?;
                }
            }
            self.ledger.cursor("eth", to).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn record_eth_event(&mut self, kind: &str, ev: &BridgeEvent) -> Result<(), String> {
        let id = hex::encode(ev.id);
        if self.ledger.has(kind, &id) {
            return Ok(());
        }
        // a reorg past our cursor cannot re-emit a different event under the same id: ids are
        // keccak(chainid, contract, nonce) and we only act once the block is behind the safe head
        self.ledger
            .write(kind, &id, "seen", json!({"amount": ev.amount.to_string(), "to": hex::encode(ev.hk_account), "at": ev.block, "source_tx": ev.tx_hash}))
            .map_err(|e| e.to_string())?;
        eprintln!("hk-attest: {kind} {id} seen at eth block {} — {} units → hk {}", ev.block, ev.amount, hex::encode(ev.hk_account));
        Ok(())
    }

    /// deposit / wburn → AssetMint on HashKinetics once the event's block is behind the safe head.
    fn process_eth_events(&mut self) -> Result<(), String> {
        let safe = self.health.lock().unwrap_or_else(|e| e.into_inner()).eth_safe;
        for kind in ["deposit", "wburn"] {
            let asset = match kind {
                "deposit" => self.usdc,
                _ => match self.hkt {
                    Some(a) => a,
                    None => continue,
                },
            };
            for r in self.ledger.in_states(kind, &["seen", "held_recipient", "submitted"]) {
                if r.state == "submitted" {
                    // a receipt we did not see before a restart / timeout
                    if let Some(txid) = &r.hk_txid {
                        match demo::receipt(&self.cfg.hk.rpc, txid) {
                            Some(rc) if rc.starts_with("ok") => self.ledger.write(kind, &r.id, "confirmed", json!({"note": rc})).map_err(|e| e.to_string())?,
                            Some(rc) => self.ledger.write(kind, &r.id, "rejected", json!({"note": rc})).map_err(|e| e.to_string())?,
                            None => {}
                        }
                    }
                    continue;
                }
                if r.at > safe {
                    continue; // not final yet
                }
                let to = match parse_h256(&r.to) {
                    Ok(h) => h,
                    Err(_) => {
                        self.ledger.write(kind, &r.id, "needs_review", json!({"note": "bad hk account id"})).map_err(|e| e.to_string())?;
                        continue;
                    }
                };
                if !hk_account_exists(&self.cfg.hk.rpc, &to) {
                    if r.state != "held_recipient" {
                        self.ledger.write(kind, &r.id, "held_recipient", json!({"note": "hk account does not exist yet — retrying"})).map_err(|e| e.to_string())?;
                    }
                    continue;
                }
                let amount: Amount = r.amount;
                if amount == 0 {
                    self.ledger.write(kind, &r.id, "needs_review", json!({"note": "zero amount"})).map_err(|e| e.to_string())?;
                    continue;
                }
                // WRITE-AHEAD: nothing leaves this process before this line is on disk
                self.ledger.write(kind, &r.id, "submitting", json!({"attempt": 1})).map_err(|e| e.to_string())?;
                match hk_submit(&self.issuer_dir, &self.cfg.hk.rpc, Tx::AssetMint { asset, to, amount }) {
                    Ok(txid) => {
                        self.ledger.write(kind, &r.id, "submitted", json!({"hk_txid": txid})).map_err(|e| e.to_string())?;
                        eprintln!("hk-attest: {kind} {} → AssetMint {amount} to {} · txid {txid}", r.id, r.to);
                        match hk_wait_receipt(&self.cfg.hk.rpc, &txid) {
                            Some(rc) if rc.starts_with("ok") => self.ledger.write(kind, &r.id, "confirmed", json!({"note": rc})).map_err(|e| e.to_string())?,
                            Some(rc) => self.ledger.write(kind, &r.id, "rejected", json!({"note": rc})).map_err(|e| e.to_string())?,
                            None => {} // stays submitted; re-checked next loop
                        }
                    }
                    Err(e) => {
                        // never entered the mempool (the nonce was rolled back) — safe to retry later
                        self.ledger.write(kind, &r.id, "seen", json!({"note": format!("submit failed: {e}")})).map_err(|e| e.to_string())?;
                        return Err(format!("{kind} {}: {e}", r.id));
                    }
                }
            }
        }
        Ok(())
    }

    fn scan_hk(&mut self) -> Result<(), String> {
        let height = demo::chain_height(&self.cfg.hk.rpc);
        if height == 0 {
            return Err("hk: chain height 0 / RPC unreachable".into());
        }
        self.health.lock().unwrap_or_else(|e| e.into_inner()).hk_height = height;
        let usdc_hex = hex::encode(self.usdc.0);
        let hkt_hex = self.hkt.map(|h| hex::encode(h.0));
        let stop = (self.ledger.hk_cursor + self.cfg.service.hk_batch).min(height);
        while self.ledger.hk_cursor < stop {
            let h = self.ledger.hk_cursor + 1;
            for (txid, amount, dest, class) in hk_burns_at(&self.cfg.hk.rpc, h, &usdc_hex)? {
                self.record_hk_burn("burn", &txid, amount, &dest, h, class)?;
            }
            if let Some(hh) = &hkt_hex {
                for (txid, amount, dest, class) in hk_burns_at(&self.cfg.hk.rpc, h, hh)? {
                    self.record_hk_burn("wlock", &txid, amount, &dest, h, class)?;
                }
            }
            self.ledger.cursor("hk", h).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn record_hk_burn(&mut self, kind: &str, txid: &str, amount: u128, dest_hex: &str, height: u64, class: &str) -> Result<(), String> {
        if self.ledger.has(kind, txid) {
            return Ok(());
        }
        let (state, note) = if class == "unknown" {
            ("needs_review", "the node has no receipt for this burn (restarted since?) — verify it was accepted, then resolve to seen")
        } else if dest_hex.len() == 40 {
            ("seen", "")
        } else {
            ("unbridgeable", "destination is not a 20-byte address — an issuer decision, never automatic")
        };
        self.ledger
            .write(kind, txid, state, json!({"amount": amount.to_string(), "to": format!("0x{dest_hex}"), "at": height, "source_tx": txid, "note": note}))
            .map_err(|e| e.to_string())?;
        eprintln!("hk-attest: {kind} {txid} {state} at hk height {height} — {amount} → 0x{dest_hex}");
        Ok(())
    }

    /// burn / wlock → attested unlock / mint on Sepolia.
    fn process_hk_burns(&mut self) -> Result<(), String> {
        let paused = self.vault_paused()?;
        let remaining = self.vault_remaining()?;
        {
            let mut h = self.health.lock().unwrap_or_else(|e| e.into_inner());
            h.vault_paused = paused;
            h.vault_remaining_today = remaining;
            h.attestor_wei = self.eth.balance_wei(&self.signer.address).unwrap_or(0);
        }
        for kind in ["burn", "wlock"] {
            let (contract, domain, fn_sig, type_sig) = match kind {
                "burn" => (self.vault, self.vault_domain, "unlock(address,uint256,bytes32,bytes[])", eth::UNLOCK_TYPE),
                _ => match (self.wrapped, self.wrapped_domain) {
                    (Some(w), Some(d)) => (w, d, "mint(address,uint256,bytes32,bytes[])", eth::MINT_TYPE),
                    _ => continue,
                },
            };
            for r in self.ledger.in_states(kind, &["seen", "queued_cap", "queued_paused", "submitted"]) {
                let mut id = [0u8; 32];
                match hex::decode(&r.id) {
                    Ok(b) if b.len() == 32 => id.copy_from_slice(&b),
                    _ => continue,
                }
                // already released? (a submit whose receipt we missed, or a co-operator's) → confirmed
                let processed = eth::decode_word_u(&self.eth.eth_call(&contract, &eth::encode_view_b32("processed(bytes32)", &id))?)? == 1;
                if processed {
                    if r.state != "confirmed" {
                        self.ledger.write(kind, &r.id, "confirmed", json!({"note": "processed on chain"})).map_err(|e| e.to_string())?;
                    }
                    continue;
                }
                if r.state == "submitted" {
                    if let Some(tx) = &r.eth_tx {
                        match self.eth.receipt_status(tx)? {
                            Some((true, _)) => {} // processed() will flip on the next loop
                            Some((false, b)) => self.ledger.write(kind, &r.id, "reverted", json!({"note": format!("eth tx reverted in block {b}")})).map_err(|e| e.to_string())?,
                            None => {}
                        }
                    }
                    continue;
                }
                if paused {
                    if r.state != "queued_paused" {
                        self.ledger.write(kind, &r.id, "queued_paused", json!({"note": "contract paused"})).map_err(|e| e.to_string())?;
                    }
                    continue;
                }
                if r.amount > remaining {
                    if r.state != "queued_cap" {
                        self.ledger.write(kind, &r.id, "queued_cap", json!({"note": format!("daily cap: {} remaining today", remaining)})).map_err(|e| e.to_string())?;
                    }
                    continue;
                }
                let to = Address::parse(&r.to)?;
                let sigs = self.attest(kind, &domain, type_sig, &to, r.amount, &id)?;
                let data = eth::encode_attested_call(fn_sig, &to, r.amount, &id, &sigs);
                // WRITE-AHEAD
                self.ledger.write(kind, &r.id, "submitting", json!({"attempt": 1})).map_err(|e| e.to_string())?;
                match self.eth.send_call(&self.signer, &contract, data) {
                    Ok(tx) => {
                        self.ledger.write(kind, &r.id, "submitted", json!({"eth_tx": tx})).map_err(|e| e.to_string())?;
                        eprintln!("hk-attest: {kind} {} → {} {} to {} · eth tx {tx}", r.id, fn_sig.split('(').next().unwrap_or(""), r.amount, r.to);
                        // wait a little for the receipt; otherwise the next loop re-checks processed()
                        for _ in 0..20 {
                            std::thread::sleep(Duration::from_secs(3));
                            match self.eth.receipt_status(&tx)? {
                                Some((true, b)) => {
                                    self.ledger.write(kind, &r.id, "confirmed", json!({"note": format!("eth block {b}")})).map_err(|e| e.to_string())?;
                                    break;
                                }
                                Some((false, b)) => {
                                    self.ledger.write(kind, &r.id, "reverted", json!({"note": format!("eth tx reverted in block {b}")})).map_err(|e| e.to_string())?;
                                    break;
                                }
                                None => {}
                            }
                        }
                    }
                    Err(e) => {
                        // the provider refused the send — nothing is on chain; safe to retry
                        self.ledger.write(kind, &r.id, "seen", json!({"note": format!("send failed: {e}")})).map_err(|e| e.to_string())?;
                        return Err(format!("{kind} {}: {e}", r.id));
                    }
                }
            }
        }
        Ok(())
    }

    /// Collect `threshold` signatures: ours plus every configured co-signer that answers; sorted by
    /// signer address (the contract's rule). A co-signer that refuses is skipped — the contract
    /// counts, we do not decide.
    fn attest(&self, kind: &str, domain: &[u8; 32], type_sig: &str, to: &Address, amount: u128, id: &[u8; 32]) -> Result<Vec<[u8; 65]>, String> {
        let sh = eth::attest_struct_hash(type_sig, to, amount, id);
        let digest = eth::typed_digest(domain, &sh);
        let mut sigs: Vec<(Address, [u8; 65])> = vec![(self.signer.address, self.signer.sign_digest(&digest)?)];
        for url in &self.cfg.eth.cosigners {
            let body = json!({"kind": kind, "to": to.hex(), "amount": amount.to_string(), "id": hex::encode(id), "digest": eth::hex0x(&digest)});
            match demo::post_json(&format!("{}/sign", url.trim_end_matches('/')), &body, 20) {
                Ok(v) => {
                    let sig = v.get("sig").and_then(|s| s.as_str()).and_then(|s| eth::unhex(s).ok());
                    let addr = v.get("address").and_then(|s| s.as_str()).and_then(|s| Address::parse(s).ok());
                    match (sig, addr) {
                        (Some(s), Some(a)) if s.len() == 65 => {
                            let mut b = [0u8; 65];
                            b.copy_from_slice(&s);
                            sigs.push((a, b));
                        }
                        _ => eprintln!("hk-attest: cosigner {url} refused {kind} {}: {v}", hex::encode(id)),
                    }
                }
                Err(e) => eprintln!("hk-attest: cosigner {url} unreachable: {e}"),
            }
        }
        sigs.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
        sigs.dedup_by(|a, b| a.0 == b.0);
        Ok(sigs.into_iter().map(|(_, s)| s).collect())
    }

    fn vault_paused(&self) -> Result<bool, String> {
        Ok(eth::decode_word_u(&self.eth.eth_call(&self.vault, &eth::encode_view("paused()"))?)? == 1)
    }

    fn vault_remaining(&self) -> Result<u128, String> {
        eth::decode_word_u(&self.eth.eth_call(&self.vault, &eth::encode_view("remainingToday()"))?)
    }

    /// vault.reserves() must equal supply − burned of USDC.sep. Drift means a mint or an unlock the
    /// other side does not know about — alert, never "fix".
    fn reconcile(&mut self) {
        let reserves = self.eth.eth_call(&self.vault, &eth::encode_view("reserves()")).ok().and_then(|b| eth::decode_word_u(&b).ok());
        let smb = hk_asset_supply_minus_burned(&self.cfg.hk.rpc, &self.usdc);
        let fee = demo::balance_of(&self.cfg.hk.rpc, &self.issuer_id, &self.fee_asset);
        let mut h = self.health.lock().unwrap_or_else(|e| e.into_inner());
        h.issuer_fee_micro = fee;
        h.reconciled_at = now();
        match (reserves, smb) {
            (Some(r), Some(s)) => {
                h.reserves = r;
                h.supply_minus_burned = s;
                // The invariant, exactly: reserves == (supply − burned) + burns not yet released (queued, in flight,
                // unbridgeable — still backed in the vault) + deposits locked but not yet minted. Anything else is
                // drift: a mint or an unlock one side does not know about. Alert, never "fix".
                let pending_burns: u128 = self
                    .ledger
                    .in_states("burn", &["seen", "queued_cap", "queued_paused", "submitting", "submitted", "unbridgeable", "reverted", "needs_review"])
                    .iter()
                    .map(|x| x.amount)
                    .sum();
                let pending_deposits: u128 = self
                    .ledger
                    .in_states("deposit", &["seen", "held_recipient", "submitting", "submitted", "rejected", "needs_review"])
                    .iter()
                    .map(|x| x.amount)
                    .sum();
                let expected = s + pending_burns + pending_deposits;
                h.reconciled_ok = r == expected;
                if r != expected {
                    eprintln!("hk-attest: reconciliation DRIFT: vault reserves {r} vs supply−burned {s} + pending burns {pending_burns} + pending deposits {pending_deposits} = {expected}");
                }
            }
            _ => h.reconciled_ok = false,
        }
        if fee < 10_000 {
            eprintln!("hk-attest: WARNING issuer fee balance {fee} micro — every mint pays the protocol fee; refill the issuer account");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// co-signer: `hk-node attest-cosign <CONFIG.toml>` — a second attestor on its own machine with its
// own key. It signs only a digest it can RECOMPUTE from the fields, after checking the HashKinetics
// burn itself (kind, asset, amount, destination, receipt ok) on its own RPC. Never trusts the digest
// it is sent; never sees the primary's key.
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize, Clone)]
pub(crate) struct CosignCfg {
    pub hk: CosignHk,
    pub eth: CosignEth,
    #[serde(default = "default_cosign_listen")]
    pub listen: String,
}
#[derive(Deserialize, Clone)]
pub(crate) struct CosignHk {
    pub rpc: String,
    pub usdc_asset: String,
    #[serde(default)]
    pub hkt_asset: Option<String>,
}
#[derive(Deserialize, Clone)]
pub(crate) struct CosignEth {
    pub chain_id: u64,
    pub vault: String,
    #[serde(default)]
    pub wrapped: Option<String>,
    #[serde(default)]
    pub wrapped_name: Option<String>,
    #[serde(default)]
    pub attestor_key_file: Option<String>,
}
fn default_cosign_listen() -> String {
    "127.0.0.1:9934".into()
}

pub(crate) fn cmd_cosign(cfg_path: &Path) -> eyre::Result<()> {
    let text = std::fs::read_to_string(cfg_path)?;
    let cfg: CosignCfg = toml::from_str(&text).map_err(|e| eyre::eyre!("{}: {e}", cfg_path.display()))?;
    let signer = load_attestor_key(&EthCfg {
        rpc: String::new(),
        chain_id: cfg.eth.chain_id,
        vault: cfg.eth.vault.clone(),
        wrapped: None,
        from_block: 0,
        confirm: String::new(),
        attestor_key_file: cfg.eth.attestor_key_file.clone(),
        cosigners: vec![],
        log_page: 0,
    })
    .map_err(|e| eyre::eyre!(e))?;
    let vault = Address::parse(&cfg.eth.vault).map_err(|e| eyre::eyre!(e))?;
    let vault_domain = eth::domain_separator("HKVault", cfg.eth.chain_id, &vault);
    let wrapped_domain = match (&cfg.eth.wrapped, &cfg.eth.wrapped_name) {
        (Some(w), Some(n)) => Some(eth::domain_separator(n, cfg.eth.chain_id, &Address::parse(w).map_err(|e| eyre::eyre!(e))?)),
        _ => None,
    };
    let listener = TcpListener::bind(&cfg.listen)?;
    eprintln!("hk-attest cosigner: {} · listening on {} · vault {}", signer.address.hex(), cfg.listen, vault.hex());
    let cfg = Arc::new(cfg);
    let signer = Arc::new(signer);
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let cfg = cfg.clone();
        let signer = signer.clone();
        std::thread::spawn(move || {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut buf = vec![0u8; 8192];
            let mut read = 0usize;
            loop {
                let Ok(n) = stream.read(&mut buf[read..]) else { break };
                if n == 0 {
                    break;
                }
                read += n;
                let text = String::from_utf8_lossy(&buf[..read]);
                if let Some(end) = text.find("\r\n\r\n") {
                    let cl = text.lines().find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                        .and_then(|l| l.split(':').nth(1)).and_then(|v| v.trim().parse::<usize>().ok()).unwrap_or(0);
                    if read >= end + 4 + cl {
                        break;
                    }
                }
                if read >= buf.len() {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&buf[..read]).to_string();
            let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
            let req: Value = serde_json::from_str(body).unwrap_or(Value::Null);
            let out = cosign_one(&cfg, &signer, &vault_domain, wrapped_domain.as_ref(), &req);
            match out {
                Ok(v) => respond(&mut stream, "200 OK", &v),
                Err(e) => respond(&mut stream, "403 Forbidden", &json!({"error": e})),
            }
        });
    }
    Ok(())
}

fn cosign_one(cfg: &CosignCfg, signer: &Signer, vault_domain: &[u8; 32], wrapped_domain: Option<&[u8; 32]>, req: &Value) -> Result<Value, String> {
    let kind = req.get("kind").and_then(|k| k.as_str()).unwrap_or("");
    let to = Address::parse(req.get("to").and_then(|t| t.as_str()).unwrap_or(""))?;
    let amount: u128 = req.get("amount").and_then(|a| a.as_str()).and_then(|s| s.parse().ok()).ok_or("amount")?;
    let id_hex = req.get("id").and_then(|i| i.as_str()).unwrap_or("");
    let id_b = hex::decode(id_hex).map_err(|e| e.to_string())?;
    if id_b.len() != 32 {
        return Err("id must be 32 bytes".into());
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&id_b);
    let (domain, type_sig, asset) = match kind {
        "burn" => (*vault_domain, eth::UNLOCK_TYPE, cfg.hk.usdc_asset.clone()),
        "wlock" => (*wrapped_domain.ok_or("no wrapped contract configured")?, eth::MINT_TYPE, cfg.hk.hkt_asset.clone().ok_or("no hkt asset configured")?),
        _ => return Err("kind must be burn|wlock".into()),
    };
    // independent check: the HashKinetics burn exists, was accepted, and says exactly this
    let v = demo::rpc(&cfg.hk.rpc, "hk_getTx", json!({"txid": id_hex}));
    let r = v.get("result").ok_or("hk_getTx: no result")?;
    if r.get("found").and_then(|f| f.as_bool()) != Some(true) {
        return Err("burn not found on my HashKinetics node".into());
    }
    let s = r.get("summary").ok_or("no summary")?;
    if s.get("kind").and_then(|k| k.as_str()) != Some("asset_burn") {
        return Err("not an asset_burn".into());
    }
    let f = s.get("fields").ok_or("no fields")?;
    if f.get("asset").and_then(|a| a.as_str()) != Some(asset.as_str()) {
        return Err("asset mismatch".into());
    }
    let amt: u128 = f.get("amount").and_then(|a| a.as_str()).and_then(|x| x.parse().ok()).ok_or("amount field")?;
    if amt != amount {
        return Err(format!("amount mismatch: chain says {amt}"));
    }
    let dest = f.get("destination").and_then(|d| d.as_str()).unwrap_or("");
    if dest.to_ascii_lowercase() != hex::encode(to.0) {
        return Err("destination mismatch".into());
    }
    if !r.get("receipt").and_then(|x| x.as_str()).unwrap_or("").starts_with("ok") {
        return Err("burn was not accepted by the chain".into());
    }
    let sh = eth::attest_struct_hash(type_sig, &to, amount, &id);
    let digest = eth::typed_digest(&domain, &sh);
    // the primary's digest must match ours — otherwise it is asking us to sign something else
    if let Some(d) = req.get("digest").and_then(|d| d.as_str()) {
        if eth::unhex(d)? != digest {
            return Err("digest mismatch — refusing".into());
        }
    }
    let sig = signer.sign_digest(&digest)?;
    Ok(json!({"sig": eth::hex0x(&sig), "address": signer.address.hex()}))
}

// ---------------------------------------------------------------------------------------------
// operator tools
// ---------------------------------------------------------------------------------------------

/// `attest-ledger <LEDGER> list [STATE]` · `attest-ledger <LEDGER> resolve <KIND> <ID> <STATE> [--hk-txid X] [--eth-tx X] [--note …]`
pub(crate) fn cmd_ledger(args: &[String]) -> eyre::Result<()> {
    let usage = "usage: hk-node attest-ledger <LEDGER.jsonl> list [STATE] | resolve <KIND> <ID> <confirmed|seen|needs_review> [--hk-txid X] [--eth-tx X] [--note TEXT]";
    let path = PathBuf::from(args.first().ok_or_else(|| eyre::eyre!(usage))?);
    let mut l = Ledger::open(&path, 0, 0)?;
    match args.get(1).map(String::as_str) {
        Some("list") => {
            let filter = args.get(2).cloned();
            println!("eth cursor {} · hk cursor {} · {} records", l.eth_cursor, l.hk_cursor, l.records.len());
            for r in l.records.values() {
                if filter.as_deref().map(|f| f == r.state).unwrap_or(true) {
                    println!("{}", serde_json::to_string(r)?);
                }
            }
            Ok(())
        }
        Some("resolve") => {
            let kind = args.get(2).ok_or_else(|| eyre::eyre!(usage))?;
            let id = args.get(3).ok_or_else(|| eyre::eyre!(usage))?;
            let state = args.get(4).ok_or_else(|| eyre::eyre!(usage))?;
            if !["confirmed", "seen", "needs_review"].contains(&state.as_str()) {
                return Err(eyre::eyre!(usage));
            }
            l.get(kind, id).ok_or_else(|| eyre::eyre!("no record {kind}:{id}"))?;
            let mut fields = serde_json::Map::new();
            fields.insert("note".into(), json!("resolved by operator"));
            let mut i = 5;
            while i < args.len() {
                match args[i].as_str() {
                    "--hk-txid" => { fields.insert("hk_txid".into(), json!(args.get(i + 1).cloned().unwrap_or_default())); i += 2 }
                    "--eth-tx" => { fields.insert("eth_tx".into(), json!(args.get(i + 1).cloned().unwrap_or_default())); i += 2 }
                    "--note" => { fields.insert("note".into(), json!(args.get(i + 1).cloned().unwrap_or_default())); i += 2 }
                    other => return Err(eyre::eyre!("unknown flag {other}\n{usage}")),
                }
            }
            l.write(kind, id, state, Value::Object(fields))?;
            println!("{kind}:{id} → {state}");
            Ok(())
        }
        _ => Err(eyre::eyre!(usage)),
    }
}

/// `attest-key-new <OUT-FILE>` — a fresh secp256k1 attestor key written 0600; prints ONLY the address.
pub(crate) fn cmd_key_new(out: &Path) -> eyre::Result<()> {
    if out.exists() {
        return Err(eyre::eyre!("{} exists — refusing to overwrite", out.display()));
    }
    let key = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let hex_key = hex::encode(key.to_bytes());
    let signer = Signer::from_hex(&hex_key).map_err(|e| eyre::eyre!(e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(out)?;
        f.write_all(hex_key.as_bytes())?;
        f.write_all(b"\n")?;
    }
    #[cfg(not(unix))]
    std::fs::write(out, format!("{hex_key}\n"))?;
    println!("attestor address {}  (key in {}, 0600 — fund it with Sepolia ETH; pass it to the vault's ATTESTORS)", signer.address.hex(), out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_is_write_ahead_and_replays() {
        let dir = std::env::temp_dir().join(format!("hk-attest-test-{}", now()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("ledger.jsonl");
        {
            let mut l = Ledger::open(&p, 100, 5).unwrap();
            assert_eq!(l.eth_cursor, 99);
            assert_eq!(l.hk_cursor, 4);
            l.write("deposit", "abc", "seen", json!({"amount": "20000000", "to": "11", "at": 120, "source_tx": "0xdead"})).unwrap();
            l.write("deposit", "abc", "submitting", json!({"attempt": 1})).unwrap();
            l.cursor("eth", 130).unwrap();
            l.cursor("hk", 9).unwrap();
            assert_eq!(l.get("deposit", "abc").unwrap().state, "submitting");
            assert_eq!(l.get("deposit", "abc").unwrap().amount, 20_000_000);
        }
        // a crash here leaves `submitting` without a txid — replay must keep it that way (never retried by itself)
        let l = Ledger::open(&p, 100, 5).unwrap();
        assert_eq!(l.eth_cursor, 130);
        assert_eq!(l.hk_cursor, 9);
        let r = l.get("deposit", "abc").unwrap();
        assert_eq!(r.state, "submitting");
        assert_eq!(r.attempts, 1);
        assert!(r.hk_txid.is_none());
        assert_eq!(l.in_states("deposit", &["seen", "held_recipient", "submitted"]).len(), 0);
        assert_eq!(l.counts().get("deposit:submitting"), Some(&1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_parses_with_defaults() {
        let t = r#"
[hk]
rpc = "http://127.0.0.1:26000"
issuer_dir = "/tmp/issuer"
usdc_asset = "00"
[eth]
chain_id = 11155111
vault = "0x00000000000000000000000000000000000000cc"
from_block = 10
"#;
        let c: Cfg = toml::from_str(t).unwrap();
        assert_eq!(c.eth.confirm, "finalized");
        assert_eq!(c.eth.log_page, 2000);
        assert_eq!(c.service.poll_secs, 5);
        assert_eq!(c.service.listen, "127.0.0.1:9933");
        assert!(c.eth.cosigners.is_empty());
    }
}
