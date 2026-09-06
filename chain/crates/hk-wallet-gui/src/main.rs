//! U3 — HashKinetics Wallet: the front door as a desktop app.
//!
//! Create a keychain, tap the faucet, hold a balance, pay anyone — the same
//! journey as `hk-node account-*`, behind a double-click. Design rules carried
//! over from the rest of the repo, each one bought with an incident:
//!
//! - Keys are born locally and never leave this machine; the faucet only ever
//!   sees an auth commitment. The account file is byte-compatible with the CLI's
//!   (`account.json`: seed / id / next_nonce), so CLI and GUI can share a wallet.
//! - RESERVE-THEN-SIGN: the L-ratchet nonce is persisted BEFORE a transaction is
//!   submitted and rolled back (and persisted) only on a definitive on-chain
//!   refusal — a crash can never re-sign a spent one-time index. Before every
//!   send the chain's nonce is adopted if the local file drifted (restored
//!   backups follow the chain, never the other way).
//! - All network work runs on worker threads; the UI thread never blocks.
//! - U4: the wallet reads the chain's fee policy and refuses locally what the chain
//!   would refuse (amount + fee > balance), so a ratchet index is never burned on a
//!   doomed envelope. "max" = balance − fee.
//! - U3v2 (`shielded.rs`): shield / unshield / stealth pay / scan / disclose over the
//!   public prover — the same lib code the CLI wallet and the P2 demos proved.
//! - K1 (v0.14.0, node v0.16.0): "Protect with a passphrase" seals account.json and
//!   shield.json on disk (`HKE1`: Argon2id → XChaCha20-Poly1305, the same envelope the
//!   CLI's `account-seal` writes, so CLI and GUI still share a wallet). A sealed wallet
//!   opens to an Unlock screen; the passphrase lives in memory for the session only.
//! - H3 (v0.14.1, node v0.16.1): the pool scan is incremental and paged, and spends fetch
//!   one Merkle path from the node — the wallet stays fast however large the pool grows.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod shielded;

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;

use eframe::egui;
use hk_crypto::hash::{shake256_32, DOM_ACCOUNT_ID};
use hk_crypto::lamport;
use hk_primitives::{Amount, H256};
use hk_state::tx::{signing_digest, SignedTx, Tx};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Shown in the footer; bump with every release (the crate version is workspace-wide).
pub const WALLET_VERSION: &str = "v0.14.1";
const RPC_DEFAULT: &str = "https://rpc.hashkinetics.org";
const FAUCET_DEFAULT: &str = "https://faucet.hashkinetics.org";
const EXPLORER: &str = "https://www.hashkinetics.org/explorer/";

/// v0.13.1: the endpoints can be pointed at a devnet without a rebuild —
/// `HK_WALLET_RPC` / `HK_WALLET_FAUCET` (read once, on first use).
fn rpc_url() -> &'static str {
    static URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    URL.get_or_init(|| std::env::var("HK_WALLET_RPC").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| RPC_DEFAULT.to_string())).as_str()
}
fn faucet_url() -> &'static str {
    static URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    URL.get_or_init(|| std::env::var("HK_WALLET_FAUCET").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| FAUCET_DEFAULT.to_string())).as_str()
}
const USD: H256 = H256([9u8; 32]);
const CYAN: egui::Color32 = egui::Color32::from_rgb(0x4e, 0xf0, 0xd0);
const GOLD: egui::Color32 = egui::Color32::from_rgb(0xf5, 0xc5, 0x18);
const RED: egui::Color32 = egui::Color32::from_rgb(0xff, 0x6b, 0x6b);
const DIM: egui::Color32 = egui::Color32::from_rgb(0x93, 0xa0, 0xc6);

// ---------------------------------------------------------------------------
// Account file — identical shape to the CLI's account.json.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
struct AccountFile {
    seed: String,
    id: String,
    next_nonce: u64,
}

fn wallet_dir() -> PathBuf {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".hashkinetics")
}

fn account_path() -> PathBuf {
    wallet_dir().join("account.json")
}

// ---------------------------------------------------------------------------
// K1 — keys at rest (v0.14.0). One in-memory passphrase for both secret files.
// ---------------------------------------------------------------------------

pub mod vault {
    //! The GUI's view of `hk_wallet::sealed`: while a passphrase is set, every secret file
    //! is written sealed; while it is unset, files are written plain. A sealed file with no
    //! passphrase in memory is "locked" — the loaders return `None` and the UI shows the
    //! Unlock screen instead of offering to create a wallet over it.
    //!
    //! Brute-force posture (see the module docs in `hk_wallet::sealed`): the Argon2id work
    //! (512 MiB, ≈1 s) runs ONCE at unlock/protect and the derived key is cached per salt;
    //! every save afterwards is an AEAD call, so a heavy KDF costs the user nothing per send.
    //! `HK_WALLET_KEYFILE=<path>` adds a key-file second factor (a file the backup does not
    //! carry) to any wallet protected while it is set.
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::Mutex;

    use hk_wallet::sealed::{self, Kdf, SealKey, Sealed};

    #[derive(Default)]
    struct State {
        passphrase: Option<String>,
        /// Derived keys by salt; `primary` is the salt new files are sealed under.
        keys: HashMap<String, SealKey>,
        primary: Option<String>,
    }

    static STATE: Mutex<Option<State>> = Mutex::new(None);

    fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
        let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
        f(g.get_or_insert_with(State::default))
    }

    pub fn passphrase() -> Option<String> {
        with(|s| s.passphrase.clone())
    }

    pub fn is_protected() -> bool {
        passphrase().is_some()
    }

    fn keyfile() -> Result<Option<Vec<u8>>, String> {
        sealed::keyfile_from_env("HK_WALLET").map_err(|e| e.to_string())
    }

    /// Forget everything (lock / remove passphrase).
    pub fn clear() {
        with(|s| *s = State::default());
    }

    /// Put a passphrase back without deriving anything yet (rollback path); keys are
    /// derived per envelope as files are touched.
    pub fn restore_passphrase(p: &str) {
        with(|s| {
            *s = State::default();
            s.passphrase = Some(p.to_string());
        });
    }

    /// Set a NEW passphrase: derives a fresh key (fresh salt) that becomes the primary.
    pub fn set_new_passphrase(p: &str) -> Result<(), String> {
        sealed::check_strength(p)?;
        let key = SealKey::new(p, keyfile()?.as_deref(), Kdf::default_profile()).map_err(|e| e.to_string())?;
        with(|s| {
            *s = State::default();
            s.passphrase = Some(p.to_string());
            s.primary = Some(key.salt_hex());
            s.keys.insert(key.salt_hex(), key);
        });
        Ok(())
    }

    /// Does this file exist as an `HKE1` envelope?
    pub fn is_sealed_file(path: &Path) -> bool {
        std::fs::read_to_string(path).map(|s| sealed::is_sealed(&s)).unwrap_or(false)
    }

    /// A sealed file we cannot open right now (no passphrase in memory).
    pub fn is_locked(path: &Path) -> bool {
        is_sealed_file(path) && passphrase().is_none()
    }

    fn key_for(env: &Sealed) -> Result<(), String> {
        // Ensure a cached key exists for this envelope's salt (derive if needed).
        let have = with(|s| s.keys.get(&env.salt).map(|k| k.fits(env)).unwrap_or(false));
        if have {
            return Ok(());
        }
        let p = passphrase().ok_or("locked")?;
        let key = SealKey::for_envelope(env, &p, keyfile()?.as_deref()).map_err(|e| e.to_string())?;
        with(|s| {
            if s.primary.is_none() {
                s.primary = Some(key.salt_hex());
            }
            s.keys.insert(key.salt_hex(), key);
        });
        Ok(())
    }

    /// Read a secret file: `Ok(Some)` plain or opened; `Ok(None)` = sealed and locked;
    /// `Err` = wrong passphrase / missing key file / malformed / I/O.
    pub fn read(path: &Path) -> Result<Option<String>, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        if !sealed::is_sealed(&raw) {
            return Ok(Some(raw));
        }
        if passphrase().is_none() {
            return Ok(None);
        }
        let env = sealed::parse(&raw).map_err(|e| e.to_string())?;
        key_for(&env)?;
        let bytes = with(|s| s.keys[&env.salt].open(&env)).map_err(|e| e.to_string())?;
        String::from_utf8(bytes).map(Some).map_err(|e| e.to_string())
    }

    /// Try a passphrase against `path`; on success it becomes the session passphrase and
    /// the derived key is cached (the one expensive step of the session).
    pub fn unlock(path: &Path, candidate: &str) -> Result<(), String> {
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        if !sealed::is_sealed(&raw) {
            clear();
            return Ok(());
        }
        let env = sealed::parse(&raw).map_err(|e| e.to_string())?;
        let key = SealKey::for_envelope(&env, candidate, keyfile()?.as_deref()).map_err(|e| e.to_string())?;
        key.open(&env).map_err(|e| e.to_string())?;
        with(|s| {
            *s = State::default();
            s.passphrase = Some(candidate.to_string());
            s.primary = Some(key.salt_hex());
            s.keys.insert(key.salt_hex(), key);
        });
        Ok(())
    }

    /// The bytes to put on disk for `plaintext` at `path`: sealed while a passphrase is
    /// set (under the key of the envelope being replaced, else the primary key); plain otherwise.
    pub fn encode(path: &Path, plaintext: &str) -> Result<String, String> {
        if passphrase().is_none() {
            return Ok(plaintext.to_string());
        }
        let existing = std::fs::read_to_string(path).ok().filter(|s| sealed::is_sealed(s));
        let salt = match existing {
            Some(raw) => {
                let env = sealed::parse(&raw).map_err(|e| e.to_string())?;
                key_for(&env)?;
                env.salt
            }
            None => match with(|s| s.primary.clone()) {
                Some(salt) => salt,
                None => {
                    // A new file with no primary key yet (e.g. right after a rollback): one derivation.
                    let p = passphrase().ok_or("locked")?;
                    let key = SealKey::new(&p, keyfile()?.as_deref(), Kdf::default_profile()).map_err(|e| e.to_string())?;
                    let salt = key.salt_hex();
                    with(|s| {
                        s.primary = Some(salt.clone());
                        s.keys.insert(salt.clone(), key);
                    });
                    salt
                }
            },
        };
        with(|s| s.keys[&salt].seal_to_json(plaintext)).map_err(|e| e.to_string())
    }
}

fn load_account() -> Option<AccountFile> {
    let s = vault::read(&account_path()).ok()??;
    serde_json::from_str(&s).ok()
}

/// v0.13.1: write → fsync → rename. Both key files are reserve-then-advance
/// counters; a crash right after a reservation must never roll a counter back
/// (a reused one-time key leaks spend authority), so the bytes have to be on
/// disk before the rename makes them the live file.
pub fn write_atomic(path: &std::path::Path, tmp: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut f = std::fs::File::create(tmp).map_err(|e| e.to_string())?;
    f.write_all(bytes).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);
    std::fs::rename(tmp, path).map_err(|e| e.to_string())
}

fn save_account(f: &AccountFile) -> Result<(), String> {
    std::fs::create_dir_all(wallet_dir()).map_err(|e| e.to_string())?;
    let tmp = wallet_dir().join("account.json.tmp");
    let bytes = vault::encode(&account_path(), &serde_json::to_string_pretty(f).map_err(|e| e.to_string())?)?;
    write_atomic(&account_path(), &tmp, bytes.as_bytes())
}

/// K1: the two secret files as currently readable (under the CURRENT vault passphrase).
/// Read BEFORE switching the passphrase, written AFTER — that is what makes a change of
/// passphrase (or removing it) safe: nothing is written that was not first read back.
type SecretFiles = (Option<AccountFile>, Option<shielded::ShieldFile>);

fn read_secret_files() -> Result<SecretFiles, String> {
    let a = if account_path().exists() { Some(load_account().ok_or("could not read account.json")?) } else { None };
    let s = if shielded::shield_path().exists() { Some(shielded::load_shield().ok_or("could not read shield.json")?) } else { None };
    Ok((a, s))
}

fn write_secret_files(files: &SecretFiles) -> Result<usize, String> {
    let mut n = 0;
    if let Some(a) = &files.0 {
        save_account(a)?;
        n += 1;
    }
    if let Some(s) = &files.1 {
        shielded::save_shield(s)?;
        n += 1;
    }
    Ok(n)
}

fn commit_at(seed: &[u8], nonce: u64) -> H256 {
    let (_, pk) = lamport::keygen(seed, nonce);
    H256(lamport::pk_commit(&pk))
}

fn derived_id(auth_commit: &H256) -> H256 {
    H256(shake256_32(DOM_ACCOUNT_ID, &[&auth_commit.0]))
}

fn parse_h256(s: &str) -> Result<H256, String> {
    let raw = hex::decode(s.trim().trim_start_matches("0x")).map_err(|e| format!("bad hex: {e}"))?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| "expected 64 hex characters".to_string())?;
    Ok(H256(arr))
}

fn sign_tx(seed: &[u8], id: H256, nonce: u64, payload: Tx) -> SignedTx {
    let (sk, pk) = lamport::keygen(seed, nonce);
    let next_auth = commit_at(seed, nonce + 1);
    let digest = signing_digest(&payload, &id, nonce, &next_auth).expect("digest");
    let sig = lamport::sign(&sk, &digest);
    SignedTx { sender: id, nonce, payload, next_auth, lamport_pk: pk, sig }
}

/// "0.25" / "1" / ".5" → micro-units (u128), max 6 decimals, integer math only.
fn parse_amount(s: &str) -> Option<Amount> {
    let s = s.trim().trim_start_matches('$');
    let (int, frac) = match s.split_once('.') {
        Some((a, b)) => (a, b),
        None => (s, ""),
    };
    if int.is_empty() && frac.is_empty() {
        return None;
    }
    if !int.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) || frac.len() > 6 {
        return None;
    }
    let int: Amount = if int.is_empty() { 0 } else { int.parse().ok()? };
    let mut f = frac.to_string();
    while f.len() < 6 {
        f.push('0');
    }
    let frac: Amount = if f.is_empty() { 0 } else { f.parse().ok()? };
    int.checked_mul(1_000_000)?.checked_add(frac)
}

fn fmt_amount(micro: Amount) -> String {
    format!("{}.{:06}", micro / 1_000_000, micro % 1_000_000)
}

// ---------------------------------------------------------------------------
// Network (worker threads only — ureq is blocking).
// ---------------------------------------------------------------------------

fn rpc_call(method: &str, params: Value) -> Result<Value, String> {
    rpc_call_within(method, params, 8)
}

/// H3 (v0.14.1): a page of the pool feed can be megabytes — the scanner's calls get a
/// longer budget than the balance/nonce reads.
fn rpc_call_within(method: &str, params: Value, secs: u64) -> Result<Value, String> {
    ureq::post(rpc_url())
        .timeout(Duration::from_secs(secs))
        .send_json(json!({ "method": method, "params": params }))
        .map_err(|e| format!("rpc: {e}"))?
        .into_json::<Value>()
        .map_err(|e| format!("rpc parse: {e}"))
}

fn chain_balance(id: &H256) -> Result<Amount, String> {
    let v = rpc_call("hk_balance", json!({ "id": hex::encode(id.0), "asset": hex::encode(USD.0) }))?;
    Ok(v.get("result")
        .and_then(|r| r.get("amount"))
        .and_then(|a| a.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0))
}

fn chain_nonce(id: &H256) -> Result<Option<u64>, String> {
    let v = rpc_call("hk_getAccount", json!({ "id": hex::encode(id.0) }))?;
    let r = v.get("result").ok_or("rpc: no result")?;
    if r.get("found").and_then(|f| f.as_bool()).unwrap_or(false) {
        Ok(r.get("nonce").and_then(|n| n.as_u64()))
    } else {
        Ok(None)
    }
}

fn chain_receipt(txid: &str) -> Option<String> {
    let v = rpc_call("hk_getReceipt", json!({ "txid": txid })).ok()?;
    let r = v.get("result")?;
    if r.get("found")?.as_bool()? {
        r.get("detail")?.as_str().map(str::to_string)
    } else {
        None
    }
}

/// POST to the faucet. Success and refusal both come back as JSON; non-2xx
/// statuses (cooldown, bad input) carry their explanation in the body.
fn faucet_post(body: Value) -> Result<Value, String> {
    let req = ureq::post(&format!("{}/drip", faucet_url())).timeout(Duration::from_secs(30));
    match req.send_json(body) {
        Ok(resp) => resp.into_json().map_err(|e| format!("faucet parse: {e}")),
        Err(ureq::Error::Status(_, resp)) => {
            resp.into_json().map_err(|e| format!("faucet parse: {e}"))
        }
        Err(e) => Err(format!("faucet unreachable: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Worker → UI events
// ---------------------------------------------------------------------------

/// U4: the chain's fee policy as the wallet sees it (from `hk_chainInfo`).
#[derive(Clone, Copy, Debug)]
struct FeeInfo {
    micro: Amount,
    from_height: u64,
    chain_height: u64,
}

impl FeeInfo {
    /// The fee charged on a transaction sent NOW (0 before activation).
    fn current(&self) -> Amount {
        if self.micro > 0 && self.chain_height + 1 >= self.from_height { self.micro } else { 0 }
    }
}

enum Evt {
    /// (line, color, optional explorer link rendered as "view ↗")
    Log(String, egui::Color32, Option<String>),
    Balance(Amount),
    OnChain(bool),
    Busy(bool),
    /// (chain id, fee policy) — refreshed with the balance.
    Chain(String, Option<FeeInfo>),
    /// U3v2: every note the scanner found for this wallet (all epochs), spent status included.
    Notes(Vec<shielded::NoteView>),
    /// U3v2: our current-epoch stealth address.
    StealthAddr(String),
}

/// `hk_chainInfo` → (chain id, fee policy). Fee fields are strings on the wire (u128).
fn chain_info() -> Result<(String, Option<FeeInfo>), String> {
    let v = rpc_call("hk_chainInfo", json!({}))?;
    let r = v.get("result").ok_or("rpc: no result")?;
    let chain_id = r.get("chain_id").and_then(|c| c.as_str()).unwrap_or("?").to_string();
    let height = r.get("height").and_then(|h| h.as_u64()).unwrap_or(0);
    let fee = r.get("fee").map(|f| FeeInfo {
        micro: f.get("micro").and_then(|m| m.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0),
        from_height: f.get("from_height").and_then(|h| h.as_u64()).unwrap_or(u64::MAX),
        chain_height: height,
    });
    Ok((chain_id, fee))
}

fn log(tx: &Sender<Evt>, msg: impl Into<String>) {
    let _ = tx.send(Evt::Log(msg.into(), DIM, None));
}
#[allow(dead_code)] // success lines currently all carry tx links (log_tx); kept for linkless successes
fn log_ok(tx: &Sender<Evt>, msg: impl Into<String>) {
    let _ = tx.send(Evt::Log(msg.into(), CYAN, None));
}
fn log_err(tx: &Sender<Evt>, msg: impl Into<String>) {
    let _ = tx.send(Evt::Log(msg.into(), RED, None));
}
/// A success line that carries a clickable explorer deep-link to its transaction.
fn log_tx(tx: &Sender<Evt>, msg: impl Into<String>, txid: &str) {
    let _ = tx.send(Evt::Log(msg.into(), CYAN, Some(format!("{EXPLORER}#tx={txid}"))));
}

/// Refresh balance + on-chain status.
fn spawn_refresh(tx: Sender<Evt>, id: H256) {
    std::thread::spawn(move || {
        let _ = tx.send(Evt::Busy(true));
        match chain_info() {
            Ok((cid, fee)) => {
                let _ = tx.send(Evt::Chain(cid, fee));
            }
            Err(e) => log_err(&tx, e),
        }
        match chain_nonce(&id) {
            Ok(Some(_)) => {
                let _ = tx.send(Evt::OnChain(true));
                match chain_balance(&id) {
                    Ok(b) => {
                        let _ = tx.send(Evt::Balance(b));
                    }
                    Err(e) => log_err(&tx, e),
                }
            }
            Ok(None) => {
                let _ = tx.send(Evt::OnChain(false));
                log(&tx, "Not on-chain yet — tap “Get test funds” to be created + funded.");
            }
            Err(e) => log_err(&tx, e),
        }
        let _ = tx.send(Evt::Busy(false));
    });
}

/// Faucet: create+fund if new (auth commit at ratchet 0), top-up if existing.
fn spawn_faucet(tx: Sender<Evt>, seed: Vec<u8>, id: H256) {
    std::thread::spawn(move || {
        let _ = tx.send(Evt::Busy(true));
        log(&tx, "Requesting test funds…");
        let body = match chain_nonce(&id) {
            Ok(Some(_)) => json!({ "account": hex::encode(id.0) }),
            Ok(None) => json!({ "auth_commit": hex::encode(commit_at(&seed, 0).0) }),
            Err(e) => {
                log_err(&tx, e);
                let _ = tx.send(Evt::Busy(false));
                return;
            }
        };
        match faucet_post(body) {
            Ok(v) if v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false) => {
                let amt = v.get("amount_micro").map(|a| a.to_string()).unwrap_or_default();
                let txid = v.get("txid").and_then(|t| t.as_str()).unwrap_or("?").to_string();
                log_tx(&tx, format!("Faucet dripped {} micro — tx {}…", amt, &txid[..16.min(txid.len())]), &txid);
                // Give the chain a couple of blocks, then refresh.
                std::thread::sleep(Duration::from_secs(3));
                let _ = tx.send(Evt::OnChain(true));
                if let Ok(b) = chain_balance(&id) {
                    let _ = tx.send(Evt::Balance(b));
                }
            }
            Ok(v) => {
                let err = v.get("error").and_then(|e| e.as_str()).unwrap_or("faucet refused");
                let retry = v
                    .get("retry_after_secs")
                    .and_then(|r| r.as_u64())
                    .map(|s| format!(" (retry in ~{}h{:02}m)", s / 3600, (s % 3600) / 60))
                    .unwrap_or_default();
                log_err(&tx, format!("{err}{retry}"));
            }
            Err(e) => log_err(&tx, e),
        }
        let _ = tx.send(Evt::Busy(false));
    });
}

/// Send a payment: chain-nonce sync → reserve-then-sign → submit → receipt.
fn spawn_send(tx: Sender<Evt>, seed: Vec<u8>, id: H256, to: H256, amount: Amount) {
    std::thread::spawn(move || {
        let _ = tx.send(Evt::Busy(true));
        // 0) U4: the fee is charged on top of the amount, from the same balance. Refuse
        //    locally with the exact number instead of burning a ratchet index on a tx
        //    the chain will refuse ("a refusal never moves money", but it costs a leaf).
        if let (Ok((_, Some(fee))), Ok(bal)) = (chain_info(), chain_balance(&id)) {
            let f = fee.current();
            if f > 0 && amount.saturating_add(f) > bal {
                log_err(
                    &tx,
                    format!(
                        "Not enough for amount + network fee ({}). Balance {} → max sendable {}.",
                        fmt_amount(f),
                        fmt_amount(bal),
                        fmt_amount(bal.saturating_sub(f))
                    ),
                );
                let _ = tx.send(Evt::Busy(false));
                return;
            }
        }
        log(&tx, format!("Sending {} to {}…", fmt_amount(amount), &hex::encode(to.0)[..12]));
        let _ = send_payload(&tx, &seed, id, Tx::Transfer { to, asset: USD, amount }, "Paid ✓");
        if let Ok(b) = chain_balance(&id) {
            let _ = tx.send(Evt::Balance(b));
        }
        let _ = tx.send(Evt::Busy(false));
    });
}

/// The one way this wallet puts a transaction on the chain — shared by the transparent
/// send and every shielded operation (U3v2): chain-nonce sync → RESERVE-THEN-SIGN →
/// submit → receipt, with the nonce rolled back (and persisted) only on a definitive
/// refusal. Returns the txid of a committed-ok transaction; every failure is logged.
pub(crate) fn send_payload(
    tx: &Sender<Evt>,
    seed: &[u8],
    id: H256,
    payload: Tx,
    ok_label: &str,
) -> Result<String, ()> {
    // 1) The chain's nonce is the truth (restored backups follow the chain).
    let nonce = match chain_nonce(&id) {
        Ok(Some(n)) => n,
        Ok(None) => {
            log_err(tx, "This wallet isn't on-chain yet — get test funds first.");
            return Err(());
        }
        Err(e) => {
            log_err(tx, e);
            return Err(());
        }
    };
    // 2) RESERVE-THEN-SIGN: persist nonce+1 before the network sees the tx.
    let mut file = match load_account() {
        Some(f) => f,
        None => {
            log_err(tx, "account file vanished — restart the wallet");
            return Err(());
        }
    };
    file.next_nonce = nonce + 1;
    if let Err(e) = save_account(&file) {
        log_err(tx, format!("could not persist nonce (refusing to sign): {e}"));
        return Err(());
    }
    let signed = sign_tx(seed, id, nonce, payload);
    // 3) Submit.
    let rollback = |file: &mut AccountFile, tx: &Sender<Evt>| {
        file.next_nonce = nonce;
        if let Err(e) = save_account(file) {
            log_err(tx, format!("rollback persist failed: {e}"));
        }
    };
    let txid = match rpc_call("hk_submitTx", json!({ "tx": serde_json::to_value(&signed).unwrap() })) {
        Ok(v) => match v.get("result").and_then(|r| r.get("txid")).and_then(|t| t.as_str()) {
            Some(t) => t.to_string(),
            None => {
                rollback(&mut file, tx);
                log_err(tx, format!("submit refused (nonce rolled back): {v}"));
                return Err(());
            }
        },
        Err(e) => {
            rollback(&mut file, tx);
            log_err(tx, format!("submit failed (nonce rolled back): {e}"));
            return Err(());
        }
    };
    // 4) Receipt. v0.13.1: wait up to ~60 s — a slow block must not strand a ratchet index
    //    (the nonce stays advanced either way; the wallet just kept giving up too early).
    for _ in 0..75 {
        std::thread::sleep(Duration::from_millis(800));
        if let Some(r) = chain_receipt(&txid) {
            if r.starts_with("rejected") {
                rollback(&mut file, tx);
                let why = if r.contains("protocol fee") {
                    "the network fee could not be paid — keep a little transparent balance back for it".to_string()
                } else {
                    r.clone()
                };
                log_err(tx, format!("Chain refused: {why} (nonce rolled back)"));
                return Err(());
            }
            log_tx(tx, format!("{ok_label}  tx {}…  ({r})", &txid[..16.min(txid.len())]), &txid);
            return Ok(txid);
        }
    }
    let _ = tx.send(Evt::Log(
        format!("No receipt after 60 s for {}… — it is probably still pending; ↻ Refresh in a minute (the nonce stays advanced; nothing to redo).", &txid[..16.min(txid.len())]),
        DIM,
        Some(format!("{EXPLORER}#tx={txid}")),
    ));
    Err(())
}

// ---------------------------------------------------------------------------
// The app
// ---------------------------------------------------------------------------

struct App {
    account: Option<AccountFile>,
    balance: Option<Amount>,
    on_chain: Option<bool>,
    /// U4: the chain id + fee policy the wallet is talking to (None until first refresh).
    chain_id: Option<String>,
    fee: Option<FeeInfo>,
    busy: bool,
    to_input: String,
    amount_input: String,
    restore_input: String,
    // U3v2 — shielded
    notes: Vec<shielded::NoteView>,
    stealth_addr: Option<String>,
    shield_amount: String,
    unshield_amount: String,
    pay_to: String,
    pay_amount: String,
    pay_memo: String,
    prover_input: String,
    log_lines: Vec<(String, egui::Color32, Option<String>)>,
    evt_rx: Receiver<Evt>,
    evt_tx: Sender<Evt>,
    booted: bool,
    // K1 — keys at rest
    locked: bool,
    unlock_input: String,
    pass_new: String,
    pass_repeat: String,
    /// A generated passphrase shown in clear until the user protects or clears it.
    generated: Option<String>,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = egui::Color32::from_rgb(0x06, 0x08, 0x0f);
        visuals.extreme_bg_color = egui::Color32::from_rgb(0x0f, 0x17, 0x30);
        visuals.widgets.noninteractive.fg_stroke.color = egui::Color32::from_rgb(0xdd, 0xe4, 0xf6);
        visuals.hyperlink_color = CYAN;
        visuals.selection.bg_fill = CYAN.gamma_multiply(0.35);
        cc.egui_ctx.set_visuals(visuals);
        let (evt_tx, evt_rx) = channel();
        install_panic_hook(evt_tx.clone(), cc.egui_ctx.clone());
        let locked = vault::is_locked(&account_path());
        Self {
            account: if locked { None } else { load_account() },
            balance: None,
            on_chain: None,
            chain_id: None,
            fee: None,
            busy: false,
            to_input: String::new(),
            amount_input: String::new(),
            restore_input: String::new(),
            notes: Vec::new(),
            stealth_addr: None,
            shield_amount: String::new(),
            unshield_amount: String::new(),
            pay_to: String::new(),
            pay_amount: String::new(),
            pay_memo: String::new(),
            prover_input: shielded::PROVER_DEFAULT.to_string(),
            log_lines: Vec::new(),
            evt_rx,
            evt_tx,
            booted: false,
            locked,
            unlock_input: String::new(),
            pass_new: String::new(),
            pass_repeat: String::new(),
            generated: None,
        }
    }

    // ---- K1: unlock / protect / unprotect --------------------------------------------

    fn unlock(&mut self) {
        let candidate = std::mem::take(&mut self.unlock_input);
        match vault::unlock(&account_path(), candidate.trim()) {
            Ok(()) => {
                self.locked = false;
                self.account = load_account();
                self.push_log("Wallet unlocked — the passphrase stays in memory for this session only.".into(), CYAN);
                if let Some(id) = self.id_h256() {
                    spawn_refresh(self.evt_tx.clone(), id);
                }
            }
            Err(e) => self.push_log(format!("Could not unlock: {e}"), RED),
        }
    }

    fn protect(&mut self) {
        let a = self.pass_new.trim().to_string();
        let b = self.pass_repeat.trim().to_string();
        if a != b {
            self.push_log("The two passphrases differ.".into(), RED);
            return;
        }
        if let Err(why) = hk_wallet::sealed::check_strength(&a) {
            self.push_log(format!("Passphrase refused: {why}. Try Generate — 7 random words are easy to type and beyond any offline attack."), RED);
            return;
        }
        let files = match read_secret_files() {
            Ok(f) => f,
            Err(e) => {
                self.push_log(format!("Could not read the wallet files — nothing changed: {e}"), RED);
                return;
            }
        };
        let previous = vault::passphrase();
        // Argon2id 512 MiB × 4 passes: about a second, once. Every save afterwards is instant.
        if let Err(e) = vault::set_new_passphrase(&a) {
            self.push_log(format!("Could not derive the sealing key — nothing changed: {e}"), RED);
            return;
        }
        match write_secret_files(&files) {
            Ok(n) => {
                self.pass_new.clear();
                self.pass_repeat.clear();
                self.generated = None;
                let kf = if std::env::var("HK_WALLET_KEYFILE").map(|v| !v.trim().is_empty()).unwrap_or(false) { " + your key file" } else { "" };
                self.push_log(format!("Protected: {n} file(s) sealed on disk (Argon2id 512 MiB → XChaCha20-Poly1305{kf}). Back up the passphrase — it cannot be recovered."), CYAN);
            }
            Err(e) => {
                match &previous {
                    Some(p) => vault::restore_passphrase(p),
                    None => vault::clear(),
                }
                let _ = write_secret_files(&files);
                self.push_log(format!("Could not seal the wallet files — restored the previous state: {e}"), RED);
            }
        }
    }

    fn generate_passphrase(&mut self) {
        let p = hk_wallet::sealed::generate_passphrase(7);
        self.pass_new = p.clone();
        self.pass_repeat = p.clone();
        self.generated = Some(p);
    }

    fn unprotect(&mut self) {
        let files = match read_secret_files() {
            Ok(f) => f,
            Err(e) => {
                self.push_log(format!("Could not read the wallet files — still protected: {e}"), RED);
                return;
            }
        };
        let previous = vault::passphrase();
        vault::clear();
        match write_secret_files(&files) {
            Ok(n) => self.push_log(format!("Passphrase removed: {n} file(s) are plain JSON on disk again."), GOLD),
            Err(e) => {
                if let Some(p) = &previous {
                    vault::restore_passphrase(p);
                }
                let _ = write_secret_files(&files);
                self.push_log(format!("Could not rewrite the wallet files — still protected: {e}"), RED);
            }
        }
    }

    fn seed_bytes(&self) -> Option<Vec<u8>> {
        hex::decode(&self.account.as_ref()?.seed).ok()
    }

    fn id_h256(&self) -> Option<H256> {
        parse_h256(&self.account.as_ref()?.id).ok()
    }

    fn push_log(&mut self, line: String, color: egui::Color32) {
        self.log_lines.insert(0, (line, color, None));
        self.log_lines.truncate(80);
    }

    fn push_log_link(&mut self, line: String, color: egui::Color32, link: Option<String>) {
        self.log_lines.insert(0, (line, color, link));
        self.log_lines.truncate(80);
    }

    fn create_account(&mut self) {
        if account_path().exists() {
            self.push_log("A wallet already exists on this machine — refusing to overwrite.".into(), RED);
            self.account = load_account();
            return;
        }
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let auth0 = commit_at(&seed, 0);
        let id = derived_id(&auth0);
        let file = AccountFile { seed: hex::encode(seed), id: hex::encode(id.0), next_nonce: 0 };
        match save_account(&file) {
            Ok(()) => {
                self.push_log("Wallet created. Your keys never leave this machine.".into(), CYAN);
                self.push_log(format!("Account id: {}", file.id), DIM);
                self.account = Some(file);
                self.on_chain = Some(false);
            }
            Err(e) => self.push_log(format!("could not save wallet: {e}"), RED),
        }
    }

    fn restore_account(&mut self) {
        if account_path().exists() {
            self.push_log("A wallet already exists — delete ~/.hashkinetics first to restore over it.".into(), RED);
            return;
        }
        let raw = match hex::decode(self.restore_input.trim()) {
            Ok(r) if r.len() == 32 => r,
            _ => {
                self.push_log("Restore needs the 64-hex seed from account.json.".into(), RED);
                return;
            }
        };
        let auth0 = commit_at(&raw, 0);
        let id = derived_id(&auth0);
        let file = AccountFile { seed: hex::encode(&raw), id: hex::encode(id.0), next_nonce: 0 };
        match save_account(&file) {
            Ok(()) => {
                self.push_log("Wallet restored — the chain's nonce is adopted automatically.".into(), CYAN);
                self.account = Some(file);
                self.restore_input.clear();
                if let (Some(id),) = (self.id_h256(),) {
                    spawn_refresh(self.evt_tx.clone(), id);
                }
            }
            Err(e) => self.push_log(format!("could not save wallet: {e}"), RED),
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drain worker events.
        while let Ok(evt) = self.evt_rx.try_recv() {
            match evt {
                Evt::Log(s, c, link) => self.push_log_link(s, c, link),
                Evt::Balance(b) => self.balance = Some(b),
                Evt::OnChain(b) => self.on_chain = Some(b),
                Evt::Busy(b) => self.busy = b,
                Evt::Chain(cid, fee) => {
                    self.chain_id = Some(cid);
                    self.fee = fee;
                }
                Evt::Notes(n) => self.notes = n,
                Evt::StealthAddr(a) => self.stealth_addr = Some(a),
            }
        }
        // First frame: kick a refresh if a wallet exists.
        if !self.booted {
            self.booted = true;
            if let Some(id) = self.id_h256() {
                spawn_refresh(self.evt_tx.clone(), id);
            }
        }
        ctx.request_repaint_after(Duration::from_millis(400));

        egui::CentralPanel::default().show(ctx, |ui| {
          // v0.13.1: the whole page scrolls, so the activity log stays reachable when the
          // SHIELDED section is open in the default 660-px window.
          egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("HASH").strong().size(20.0));
                ui.label(egui::RichText::new("KINETICS").strong().size(20.0).color(CYAN));
                let net = self.chain_id.clone().unwrap_or_else(|| "connecting…".into());
                ui.label(egui::RichText::new(format!("  wallet · {net}")).size(12.0).color(DIM));
            });
            ui.add_space(4.0);
            ui.separator();
            ui.add_space(8.0);

            if self.locked {
                // K1: a sealed wallet lives here — never offer to create one over it.
                ui.label(egui::RichText::new("This wallet is protected.").size(16.0));
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Enter the passphrase to unlock account.json / shield.json for this session.").color(DIM));
                ui.add_space(8.0);
                let r = ui.add(egui::TextEdit::singleline(&mut self.unlock_input).password(true).desired_width(300.0).hint_text("passphrase"));
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                ui.add_space(6.0);
                if ui.add(egui::Button::new(egui::RichText::new("  Unlock  ").size(15.0).color(egui::Color32::BLACK)).fill(CYAN)).clicked() || enter {
                    self.unlock();
                }
                ui.add_space(8.0);
                ui.label(egui::RichText::new(format!("Files: {}", wallet_dir().display())).size(10.0).color(DIM));
                ui.add_space(8.0);
                ui.separator();
                ui.label(egui::RichText::new("ACTIVITY").size(10.0).color(DIM));
                for (line, color, _) in &self.log_lines {
                    ui.label(egui::RichText::new(line).size(11.0).color(*color));
                }
            } else {
            match self.account.clone() {
                None => {
                    ui.label(egui::RichText::new("Get on the chain in one click.").size(16.0));
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(
                            "This creates a post-quantum keychain on YOUR machine. \
                             Nothing is sent anywhere until you ask for funds.",
                        )
                        .color(DIM),
                    );
                    ui.add_space(10.0);
                    if ui.add(egui::Button::new(egui::RichText::new("  Create my wallet  ").size(16.0).color(egui::Color32::BLACK)).fill(CYAN)).clicked() {
                        self.create_account();
                    }
                    ui.add_space(10.0);
                    egui::CollapsingHeader::new("Restore from a seed").show(ui, |ui| {
                        ui.label(egui::RichText::new("Paste the 64-hex seed from a backed-up account.json:").color(DIM));
                        ui.text_edit_singleline(&mut self.restore_input);
                        if ui.button("Restore").clicked() {
                            self.restore_account();
                        }
                    });
                }
                Some(acct) => {
                    // Identity
                    ui.label(egui::RichText::new("ACCOUNT").size(10.0).color(DIM));
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&acct.id).monospace().size(11.0).color(CYAN));
                    });
                    ui.horizontal(|ui| {
                        if ui.small_button("copy id").clicked() {
                            ui.output_mut(|o| o.copied_text = acct.id.clone());
                            self.push_log("Account id copied.".into(), DIM);
                        }
                        ui.hyperlink_to(
                            egui::RichText::new("view on explorer ↗").size(11.0),
                            format!("{EXPLORER}#account={}", acct.id),
                        );
                    });
                    ui.add_space(10.0);

                    // Balance
                    ui.label(egui::RichText::new("BALANCE (test units — no monetary value)").size(10.0).color(DIM));
                    let bal_txt = match (self.balance, self.on_chain) {
                        (Some(b), _) => fmt_amount(b),
                        (None, Some(false)) => "not on-chain yet".into(),
                        _ => "…".into(),
                    };
                    ui.label(egui::RichText::new(bal_txt).size(30.0).strong());
                    // U4: say what a transaction costs BEFORE the user finds out.
                    if let Some(fee) = self.fee {
                        let line = if fee.current() > 0 {
                            format!("network fee {} per transaction (burned)", fmt_amount(fee.micro))
                        } else if fee.micro > 0 && fee.from_height != u64::MAX {
                            format!("network fee {} per transaction from height {}", fmt_amount(fee.micro), fee.from_height)
                        } else {
                            "no network fee on this chain".to_string()
                        };
                        ui.label(egui::RichText::new(line).size(10.0).color(DIM));
                    }
                    ui.add_space(8.0);

                    // Actions
                    ui.horizontal(|ui| {
                        let enabled = !self.busy;
                        if ui.add_enabled(enabled, egui::Button::new("↻ Refresh")).clicked() {
                            if let Some(id) = self.id_h256() {
                                spawn_refresh(self.evt_tx.clone(), id);
                            }
                        }
                        if ui
                            .add_enabled(
                                enabled,
                                egui::Button::new(egui::RichText::new(" Get test funds ").color(egui::Color32::BLACK)).fill(CYAN),
                            )
                            .clicked()
                        {
                            if let (Some(seed), Some(id)) = (self.seed_bytes(), self.id_h256()) {
                                spawn_faucet(self.evt_tx.clone(), seed, id);
                            }
                        }
                        if self.busy {
                            ui.spinner();
                        }
                    });

                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(6.0);

                    // Send
                    ui.label(egui::RichText::new("SEND A PAYMENT").size(10.0).color(DIM));
                    ui.label(egui::RichText::new("To (account id, 64 hex):").color(DIM).size(11.0));
                    ui.add(egui::TextEdit::singleline(&mut self.to_input).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY));
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Amount:").color(DIM).size(11.0));
                        ui.add(egui::TextEdit::singleline(&mut self.amount_input).desired_width(90.0));
                        // U4: "Max" = balance minus the fee the chain will charge now.
                        let fee_now = self.fee.map(|f| f.current()).unwrap_or(0);
                        if let Some(b) = self.balance {
                            if ui.small_button("max").on_hover_text("balance minus the network fee").clicked() {
                                self.amount_input = fmt_amount(b.saturating_sub(fee_now));
                            }
                        }
                        let preview = parse_amount(&self.amount_input).map(|m| {
                            if fee_now > 0 { format!("= {m} micro + {fee_now} fee") } else { format!("= {m} micro") }
                        });
                        if let Some(p) = preview.clone() {
                            ui.label(egui::RichText::new(p).color(DIM).size(10.0));
                        }
                        let over = match (parse_amount(&self.amount_input), self.balance) {
                            (Some(a), Some(b)) => a.saturating_add(fee_now) > b,
                            _ => false,
                        };
                        if over {
                            ui.label(egui::RichText::new("exceeds balance + fee").color(RED).size(10.0));
                        }
                        let can_send = !self.busy
                            && !over
                            && parse_amount(&self.amount_input).map(|a| a > 0).unwrap_or(false)
                            && parse_h256(&self.to_input).is_ok();
                        if ui.add_enabled(can_send, egui::Button::new(" Send ")).clicked() {
                            if let (Some(seed), Some(id), Ok(to), Some(amount)) = (
                                self.seed_bytes(),
                                self.id_h256(),
                                parse_h256(&self.to_input),
                                parse_amount(&self.amount_input),
                            ) {
                                spawn_send(self.evt_tx.clone(), seed, id, to, amount);
                            }
                        }
                    });

                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(6.0);

                    // ---- U3v2: SHIELDED ----------------------------------------------
                    let shielded_total: Amount = self.notes.iter().filter(|n| !n.spent).map(|n| n.value).sum();
                    let unspent_n = self.notes.iter().filter(|n| !n.spent).count();
                    // The title carries the live total, so the header needs a STABLE id —
                    // egui derives it from the title by default, and a changed title reads
                    // as a brand-new (collapsed) header after every operation (v0.13.0 bug).
                    egui::CollapsingHeader::new(
                        egui::RichText::new(format!("SHIELDED  ·  {} in {unspent_n} note(s)", fmt_amount(shielded_total))).size(11.0),
                    )
                    .id_source("shielded-section")
                    .default_open(false)
                    .show(ui, |ui| {
                        let busy = self.busy;
                        let ready = self.on_chain == Some(true) && !busy;
                        ui.label(
                            egui::RichText::new(
                                "Post-quantum shielded pool: amounts and parties are hidden; proofs are made on the public prover \
                                 (each one takes a while). The network fee is paid from your transparent balance.",
                            )
                            .color(DIM)
                            .size(10.0),
                        );
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            if ui.add_enabled(ready, egui::Button::new("↻ Scan pool")).clicked() {
                                if let Some(id) = self.id_h256() {
                                    shielded::spawn_scan(self.evt_tx.clone(), id);
                                }
                            }
                            if let Some(a) = self.stealth_addr.clone() {
                                if ui.small_button("copy my stealth address").clicked() {
                                    ui.output_mut(|o| o.copied_text = a.clone());
                                    self.push_log("Stealth address copied — hand it to whoever pays you.".into(), DIM);
                                }
                            }
                        });
                        if let Some(a) = &self.stealth_addr {
                            ui.label(egui::RichText::new(format!("{}…{}", &a[..22.min(a.len())], &a[a.len().saturating_sub(10)..])).monospace().size(10.0).color(CYAN));
                        }
                        // v0.13.1: the one-time spend-key budget is visible before it runs out.
                        if let Some((used, cap)) = shielded::ots_budget() {
                            let warn = used.saturating_mul(4) >= cap.saturating_mul(3);
                            ui.label(
                                egui::RichText::new(format!("one-time spend keys used: {used} / {cap}{}", if warn { " — move shield.json aside and shield again soon (old notes stay spendable from the old file)" } else { "" }))
                                    .size(10.0)
                                    .color(if warn { GOLD } else { DIM }),
                            );
                        }

                        // Notes
                        if !self.notes.is_empty() {
                            ui.add_space(4.0);
                            egui::ScrollArea::vertical().max_height(90.0).auto_shrink([false, true]).show(ui, |ui| {
                                let mut disclose: Option<String> = None;
                                for n in &self.notes {
                                    ui.horizontal(|ui| {
                                        let tag = if n.spent { "SPENT" } else { "LIVE " };
                                        let col = if n.spent { DIM } else { CYAN };
                                        ui.label(egui::RichText::new(format!("{tag} {}", fmt_amount(n.value))).monospace().size(10.0).color(col));
                                        if !n.memo.is_empty() {
                                            ui.label(egui::RichText::new(format!("“{}”", n.memo)).size(10.0).color(DIM));
                                        }
                                        ui.label(egui::RichText::new(format!("#{} {}…", n.leaf_index, &n.commitment[..8])).size(10.0).color(DIM));
                                        if ui.add_enabled(!busy, egui::Button::new(egui::RichText::new("disclose").size(10.0))).on_hover_text("write a one-time disclosure package for this payment").clicked() {
                                            disclose = Some(n.commitment.clone());
                                        }
                                    });
                                }
                                if let (Some(cm), Some(id)) = (disclose, self.id_h256()) {
                                    shielded::spawn_disclose(self.evt_tx.clone(), id, cm);
                                }
                            });
                        }

                        ui.add_space(6.0);
                        // Shield
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Shield").color(DIM).size(11.0));
                            ui.add(egui::TextEdit::singleline(&mut self.shield_amount).desired_width(80.0).hint_text("amount"));
                            let ok = ready && parse_amount(&self.shield_amount).map(|a| a > 0).unwrap_or(false);
                            if ui.add_enabled(ok, egui::Button::new(" Shield → pool ")).clicked() {
                                if let (Some(seed), Some(id), Some(a)) = (self.seed_bytes(), self.id_h256(), parse_amount(&self.shield_amount)) {
                                    shielded::spawn_shield(self.evt_tx.clone(), seed, id, a, self.prover_input.trim().to_string());
                                }
                            }
                        });
                        // Unshield
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Unshield").color(DIM).size(11.0));
                            ui.add(egui::TextEdit::singleline(&mut self.unshield_amount).desired_width(80.0).hint_text("amount"));
                            let ok = ready && unspent_n > 0 && parse_amount(&self.unshield_amount).map(|a| a > 0).unwrap_or(false);
                            if ui.add_enabled(ok, egui::Button::new(" Pool → me ")).clicked() {
                                if let (Some(seed), Some(id), Some(a)) = (self.seed_bytes(), self.id_h256(), parse_amount(&self.unshield_amount)) {
                                    shielded::spawn_unshield(self.evt_tx.clone(), seed, id, a, self.prover_input.trim().to_string());
                                }
                            }
                        });
                        // Pay
                        ui.label(egui::RichText::new("Pay shielded to (hkaddr:…):").color(DIM).size(11.0));
                        ui.add(egui::TextEdit::singleline(&mut self.pay_to).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY));
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut self.pay_amount).desired_width(80.0).hint_text("amount"));
                            ui.add(egui::TextEdit::singleline(&mut self.pay_memo).desired_width(140.0).hint_text("memo (optional)"));
                            let ok = ready
                                && unspent_n > 0
                                && parse_amount(&self.pay_amount).map(|a| a > 0).unwrap_or(false)
                                && shielded::addr_decode(&self.pay_to).is_ok();
                            if ui.add_enabled(ok, egui::Button::new(" Pay shielded ")).clicked() {
                                if let (Some(seed), Some(id), Some(a)) = (self.seed_bytes(), self.id_h256(), parse_amount(&self.pay_amount)) {
                                    shielded::spawn_pay(self.evt_tx.clone(), seed, id, self.pay_to.trim().to_string(), a, self.pay_memo.clone(), self.prover_input.trim().to_string());
                                }
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Prover:").color(DIM).size(10.0));
                            ui.add(egui::TextEdit::singleline(&mut self.prover_input).desired_width(220.0).font(egui::TextStyle::Monospace));
                        });
                        ui.label(
                            egui::RichText::new(format!(
                                "⚠ shield.json (next to account.json) holds the shielded keys + one-time counters — back it up too. {}",
                                shielded::shield_path().display()
                            ))
                            .color(GOLD)
                            .size(10.0),
                        );
                    });

                    ui.add_space(10.0);
                    egui::CollapsingHeader::new("Backup & advanced").show(ui, |ui| {
                        ui.label(egui::RichText::new("⚠ The seed IS the account. Back it up; never share it.").color(GOLD).size(11.0));
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Seed:").color(DIM).size(11.0));
                            if ui.small_button("copy seed").clicked() {
                                ui.output_mut(|o| o.copied_text = acct.seed.clone());
                                self.push_log("Seed copied — treat it like the money it is.".into(), GOLD);
                            }
                        });
                        if let Some(seed) = self.seed_bytes() {
                            let auth0 = commit_at(&seed, 0);
                            ui.label(egui::RichText::new(format!("Auth commit (for the web faucet): {}", hex::encode(auth0.0))).monospace().size(10.0).color(DIM));
                        }
                        ui.label(egui::RichText::new(format!("Wallet file: {}", account_path().display())).size(10.0).color(DIM));
                    });

                    // K1 (v0.14.0): keys at rest.
                    ui.add_space(6.0);
                    let protected = vault::is_protected();
                    let title = if protected { "Passphrase: ON (files sealed on disk)" } else { "Protect with a passphrase" };
                    egui::CollapsingHeader::new(title).show(ui, |ui| {
                        if protected {
                            ui.label(egui::RichText::new("account.json and shield.json are encrypted on disk (Argon2id 512 MiB → XChaCha20-Poly1305). A copied file is useless without the passphrase; a running, unlocked wallet still holds the keys in memory.").color(DIM).size(11.0));
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("Change:").color(DIM).size(11.0));
                                ui.add(egui::TextEdit::singleline(&mut self.pass_new).password(true).desired_width(130.0).hint_text("new passphrase"));
                                ui.add(egui::TextEdit::singleline(&mut self.pass_repeat).password(true).desired_width(130.0).hint_text("repeat"));
                                if ui.small_button("generate").clicked() {
                                    self.generate_passphrase();
                                }
                                if ui.small_button("apply").clicked() {
                                    self.protect();
                                }
                            });
                            if let Some(g) = self.generated.clone() {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(egui::RichText::new(&g).monospace().size(12.0).color(GOLD));
                                    if ui.small_button("copy").clicked() {
                                        ui.output_mut(|o| o.copied_text = g.clone());
                                    }
                                });
                            }
                            if ui.small_button("remove passphrase (write plain files)").clicked() {
                                self.unprotect();
                            }
                        } else {
                            ui.label(egui::RichText::new("Seal account.json and shield.json so a stolen backup or disk image is useless without the passphrase (Argon2id 512 MiB — about a second to unlock, then instant; a copied file allows only tens of guesses per second even on a GPU). The CLI reads the same format (hk-node account-seal). There is NO recovery if you forget it — keep the seed backup too.").color(DIM).size(11.0));
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.add(egui::TextEdit::singleline(&mut self.pass_new).password(true).desired_width(140.0).hint_text("12+ chars or 4+ words"));
                                ui.add(egui::TextEdit::singleline(&mut self.pass_repeat).password(true).desired_width(140.0).hint_text("repeat"));
                                if ui.small_button("generate").on_hover_text("7 random words from a 512-word list = 63 bits").clicked() {
                                    self.generate_passphrase();
                                }
                            });
                            if let Some(g) = self.generated.clone() {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(egui::RichText::new(&g).monospace().size(12.0).color(GOLD));
                                    if ui.small_button("copy").clicked() {
                                        ui.output_mut(|o| o.copied_text = g.clone());
                                    }
                                });
                                ui.label(egui::RichText::new("Write it down before you click Protect. It is shown once.").color(DIM).size(10.0));
                            }
                            if ui.button(" Protect this wallet ").clicked() {
                                self.protect();
                            }
                        }
                    });

                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);

                    // Activity log
                    ui.label(egui::RichText::new("ACTIVITY").size(10.0).color(DIM));
                    egui::ScrollArea::vertical().max_height(150.0).auto_shrink([false, true]).show(ui, |ui| {
                        for (line, color, link) in &self.log_lines {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(egui::RichText::new(line).size(11.0).color(*color));
                                if let Some(url) = link {
                                    ui.hyperlink_to(egui::RichText::new("view ↗").size(11.0), url);
                                }
                            });
                        }
                    });
                }
            }
            } // !locked

            // Footer (flows after the content now that the page scrolls)
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                ui.hyperlink_to("explorer", "https://www.hashkinetics.org/explorer/");
                ui.label(egui::RichText::new("·").color(DIM));
                ui.hyperlink_to("hashkinetics.org", "https://www.hashkinetics.org");
                ui.label(egui::RichText::new("·").color(DIM));
                ui.label(egui::RichText::new(format!("{WALLET_VERSION} · hash-based keys · your first spend signs at ratchet index 0")).size(10.0).color(DIM));
            });
            ui.add_space(8.0);
          });
        });
    }
}

/// v0.13.1: a panic on a worker thread used to kill that job silently — the
/// spinner stayed on and every button stayed disabled until a restart. The hook
/// reports it in ACTIVITY and clears the busy flag; the default hook still prints.
static PANIC_TX: std::sync::Mutex<Option<Sender<Evt>>> = std::sync::Mutex::new(None);

fn install_panic_hook(tx: Sender<Evt>, ctx: egui::Context) {
    if let Ok(mut g) = PANIC_TX.lock() {
        *g = Some(tx);
    }
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Ok(g) = PANIC_TX.lock() {
            if let Some(tx) = g.as_ref() {
                let _ = tx.send(Evt::Log(
                    format!("Internal error in a background job — nothing was sent, you can retry: {info}"),
                    RED,
                    None,
                ));
                let _ = tx.send(Evt::Busy(false));
                ctx.request_repaint();
            }
        }
        prev(info);
    }));
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([460.0, 660.0])
            .with_min_inner_size([420.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native(
        "HashKinetics Wallet",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
