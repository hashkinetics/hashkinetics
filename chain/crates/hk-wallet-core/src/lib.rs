//! hk-wallet-core — the HashKinetics wallet as a library with a UniFFI surface (WA1).
//!
//! Everything the desktop wallet does, minus the window: one [`Wallet`] object per wallet
//! directory, every method blocking (the app calls them off its main thread), progress lines
//! delivered to an optional [`Progress`] listener. Files are byte-compatible with the desktop
//! wallet and the CLI (`account.json`, `shield.json`, `disclosure-*.json`), sealed at rest with
//! the same `HKE1` envelope when a passphrase is set — a phone backup restores on a PC and
//! vice-versa.
//!
//! Rules carried over from the desktop wallet, each bought with an incident:
//! - keys are born locally and never leave the device; the faucet only sees an auth commit;
//! - RESERVE-THEN-SIGN: the ratchet nonce is persisted before a transaction is submitted and
//!   rolled back only on a definitive on-chain refusal; the chain's nonce is adopted before
//!   every send (restored backups follow the chain);
//! - the wallet reads the fee policy and refuses locally what the chain would refuse;
//! - the shielded counters (`shield.json`) are never re-used: advance + fsync before use.
//!
//! Mobile specifics: a caller-chosen KDF profile (`set_mobile_kdf`), an app-supplied key-file
//! second factor (`set_keyfile` — Android Keystore bytes), amounts as `u64` micro-units on the
//! FFI (UniFFI has no u128; 2^64 micro is 18 trillion units — enough).
//!
//! P6.2 (2026-09-13, core v0.2.0): ISSUED ASSETS. The wallet lists the chain's assets
//! (`assets()`), shows every balance the account holds (`Status.balances`), and every money
//! operation exists in an `_asset` form that names the asset by id: transparent send, faucet
//! drip, shield / unshield / shielded pay / scan / notes / disclose — each shielded operation
//! acting in that asset's own pool (P6). The un-suffixed methods keep doing exactly what they
//! did: the native test unit. The network fee is always paid in the native unit.

#![allow(clippy::new_without_default)]

pub mod account;
pub mod client;
pub mod shield;
pub mod vault;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hk_primitives::{Amount, H256};
use hk_state::tx::Tx;
use serde_json::json;

use crate::account::{commit_at, fmt_amount, fmt_amount_dec, parse_amount, parse_amount_dec, parse_h256, sign_tx, AccountFile};
use crate::client::{AssetMeta, Http, USD};
use crate::vault::{mobile_profile, write_atomic, Vault};

uniffi::setup_scaffolding!();

/// Bumped with every core release; the app shows it next to its own version.
pub const CORE_VERSION: &str = "v0.2.0";

pub const RPC_DEFAULT: &str = "https://rpc.hashkinetics.org";
pub const FAUCET_DEFAULT: &str = "https://faucet.hashkinetics.org";
pub const PROVER_DEFAULT: &str = "https://prover.hashkinetics.org";
pub const EXPLORER_DEFAULT: &str = "https://www.hashkinetics.org/explorer/";

/// What the native unit is called on screens (the chain's unit; on testnet-1 it is a test unit
/// with no monetary value). It has no registry entry (it is the fee asset, 32 × 0x09) and six
/// decimals like everything else on testnet-1.
pub const NATIVE_SYMBOL: &str = "HKN";
pub const NATIVE_DECIMALS: u8 = 6;

// ---------------------------------------------------------------------------
// FFI types
// ---------------------------------------------------------------------------

/// Every failure crosses the FFI as one message the screen can show verbatim.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum WalletError {
    #[error("{msg}")]
    Message { msg: String },
}

impl WalletError {
    pub fn msg(m: impl Into<String>) -> Self {
        WalletError::Message { msg: m.into() }
    }
}

/// The four services a wallet talks to. Defaults = the public testnet-1 endpoints; a devnet
/// or a self-hosted prover just points elsewhere.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Endpoints {
    pub rpc: String,
    pub faucet: String,
    pub prover: String,
    pub explorer: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            rpc: RPC_DEFAULT.into(),
            faucet: FAUCET_DEFAULT.into(),
            prover: PROVER_DEFAULT.into(),
            explorer: EXPLORER_DEFAULT.into(),
        }
    }
}

/// What exists on disk and whether it can be read right now.
#[derive(Clone, Debug, uniffi::Record)]
pub struct WalletState {
    /// `account.json` exists.
    pub exists: bool,
    /// The account file is an `HKE1` envelope.
    pub sealed: bool,
    /// Sealed and no passphrase in memory — show the Unlock screen.
    pub locked: bool,
    /// The envelope needs the key-file second factor (Android Keystore) as well.
    pub needs_keyfile: bool,
    /// A passphrase is set for this session (new files are written sealed).
    pub protected: bool,
    /// Readable now (plain, or sealed and unlocked).
    pub account_id: Option<String>,
    /// `shield.json` exists (the shielded side has been used).
    pub shielded_side: bool,
    pub core_version: String,
}

/// P6.2: one asset as the screens need it. `id` is the 64-hex asset id the chain uses;
/// the native unit's id is the fee asset and `is_native` is true for it alone.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AssetInfo {
    pub id: String,
    pub symbol: String,
    pub decimals: u8,
    /// May be shielded into its own pool (P6).
    pub pool_eligible: bool,
    pub is_native: bool,
    /// The issuer has paused every move of this asset.
    pub paused: bool,
}

/// P6.2: one transparent balance, in the asset's base units.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AssetBalance {
    pub asset: AssetInfo,
    pub balance_micro: u64,
}

/// One refresh: chain + this account.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Status {
    pub chain_id: String,
    pub height: u64,
    pub node_version: String,
    /// The fee charged on a transaction sent now (micro, native unit).
    pub fee_micro: u64,
    pub on_chain: bool,
    /// The NATIVE balance (micro) — what the fee is paid from.
    pub balance_micro: u64,
    pub account_id: String,
    /// "max sendable" = native balance − fee (0 when nothing is sendable).
    pub max_sendable_micro: u64,
    /// P6.2: every balance this account holds, the native unit first (present even at 0).
    pub balances: Vec<AssetBalance>,
}

/// A committed transaction.
#[derive(Clone, Debug, uniffi::Record)]
pub struct TxResult {
    pub txid: String,
    /// The consensus receipt text ("ok" / detail).
    pub receipt: String,
    pub explorer_url: String,
    /// The wallet's own one-line summary ("Paid ✓ …").
    pub summary: String,
}

/// One shielded note this wallet owns.
#[derive(Clone, Debug, uniffi::Record)]
pub struct NoteView {
    pub value_micro: u64,
    pub leaf_index: u64,
    pub memo: String,
    pub commitment: String,
    pub spent: bool,
}

/// The outcome of a scan.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ScanResult {
    pub notes: Vec<NoteView>,
    pub fresh_entries: u64,
    pub pool_size: u64,
    pub unspent: u32,
    /// Our receiving address for the chain's current epoch (`hkaddr:…`) — one for every pool.
    pub stealth_address: String,
    /// One-time spend leaves used / capacity (64 per shield master) — shared by every pool.
    pub ots_used: u32,
    pub ots_capacity: u32,
    /// P6.2: the asset whose pool was scanned (64-hex).
    pub asset: String,
}

/// Progress lines for the ACTIVITY panel. `level`: "info" | "ok" | "error".
#[uniffi::export(callback_interface)]
pub trait Progress: Send + Sync {
    fn on_log(&self, level: String, line: String, link: Option<String>);
}

/// The asset an operation acts in — id plus what the messages need. Built once per call from
/// the registry (native: synthesised, no network).
#[derive(Clone, Debug)]
pub(crate) struct AssetCtx {
    pub id: H256,
    pub symbol: String,
    pub decimals: u8,
}

impl AssetCtx {
    pub fn fmt(&self, base: Amount) -> String {
        fmt_amount_dec(base, self.decimals)
    }
}

fn native_info() -> AssetInfo {
    AssetInfo { id: hex::encode(USD.0), symbol: NATIVE_SYMBOL.into(), decimals: NATIVE_DECIMALS, pool_eligible: true, is_native: true, paused: false }
}

fn meta_info(m: &AssetMeta) -> AssetInfo {
    AssetInfo { id: hex::encode(m.id.0), symbol: m.symbol.clone(), decimals: m.decimals, pool_eligible: m.pool_eligible, is_native: false, paused: m.paused }
}

// ---------------------------------------------------------------------------
// The wallet object
// ---------------------------------------------------------------------------

#[derive(uniffi::Object)]
pub struct Wallet {
    dir: PathBuf,
    endpoints: Mutex<Endpoints>,
    vault: Mutex<Vault>,
    listener: Mutex<Option<Box<dyn Progress>>>,
    /// P6.2: the registry as last read (symbols/decimals for messages without a round trip).
    assets: Mutex<Vec<AssetMeta>>,
}

#[uniffi::export]
impl Wallet {
    /// Open (or prepare) the wallet directory. Nothing is read or created until asked.
    #[uniffi::constructor]
    pub fn new(dir: String, endpoints: Option<Endpoints>) -> Arc<Self> {
        Arc::new(Self {
            dir: PathBuf::from(dir),
            endpoints: Mutex::new(endpoints.unwrap_or_default()),
            vault: Mutex::new(Vault::default()),
            listener: Mutex::new(None),
            assets: Mutex::new(Vec::new()),
        })
    }

    pub fn set_listener(&self, listener: Box<dyn Progress>) {
        *self.listener.lock().unwrap_or_else(|e| e.into_inner()) = Some(listener);
    }

    pub fn set_endpoints(&self, endpoints: Endpoints) {
        *self.endpoints.lock().unwrap_or_else(|e| e.into_inner()) = endpoints;
    }

    pub fn endpoints(&self) -> Endpoints {
        self.endpoints.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn core_version(&self) -> String {
        CORE_VERSION.to_string()
    }

    // ---- keys at rest ----

    /// Use the phone-sized Argon2id profile (256 MiB / t3) for NEW envelopes. Files sealed
    /// under it still open on a PC (the parameters ride in the envelope).
    pub fn set_mobile_kdf(&self, mobile: bool) {
        self.vault.lock().unwrap_or_else(|e| e.into_inner()).set_profile(if mobile { Some(mobile_profile()) } else { None });
    }

    /// The key-file second factor: 32 bytes the app keeps in the Android Keystore (released
    /// after biometrics / device credential). `None` clears it. Applies to every seal/open.
    pub fn set_keyfile(&self, bytes: Option<Vec<u8>>) -> Result<(), WalletError> {
        if let Some(b) = &bytes {
            if b.len() != 32 {
                return Err(WalletError::msg("key file must be exactly 32 bytes"));
            }
        }
        self.vault.lock().unwrap_or_else(|e| e.into_inner()).set_keyfile(bytes);
        Ok(())
    }

    /// 32 fresh random bytes for a new key file (the app stores them in the Keystore).
    pub fn new_keyfile(&self) -> Vec<u8> {
        hk_wallet::sealed::new_keyfile()
    }

    pub fn state(&self) -> WalletState {
        let account = self.account_path();
        let exists = account.exists();
        let sealed = exists && Vault::is_sealed_file(&account);
        let needs_keyfile = sealed && Vault::needs_keyfile(&account);
        let (locked, protected) = {
            let v = self.vault.lock().unwrap_or_else(|e| e.into_inner());
            (sealed && v.passphrase().is_none(), v.is_protected())
        };
        let account_id = if exists && !locked { self.load_account().ok().flatten().map(|a| a.id) } else { None };
        WalletState {
            exists,
            sealed,
            locked,
            needs_keyfile,
            protected,
            account_id,
            shielded_side: self.shield_path().exists(),
            core_version: CORE_VERSION.into(),
        }
    }

    /// Try a passphrase against the sealed files; on success it stays for the session.
    pub fn unlock(&self, passphrase: String) -> Result<(), WalletError> {
        let path = if self.account_path().exists() { self.account_path() } else { self.shield_path() };
        if !path.exists() {
            return Err(WalletError::msg("nothing to unlock — no wallet files yet"));
        }
        let mut v = self.vault.lock().unwrap_or_else(|e| e.into_inner());
        v.unlock(&path, &passphrase).map_err(|e| {
            let m = e.to_string();
            if m.contains("key file") {
                WalletError::msg(format!("{m} — this wallet needs its key file (biometric unlock) as well"))
            } else if m.contains("wrong") || m.contains("aead") || m.contains("decrypt") {
                WalletError::msg("wrong passphrase")
            } else {
                e
            }
        })
    }

    /// Forget the passphrase (the files stay sealed on disk).
    pub fn lock(&self) {
        self.vault.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// Set (or change) the passphrase: every secret file is read back under the OLD state
    /// first and re-written sealed under the new one — nothing is written that was not read.
    pub fn protect(&self, passphrase: String) -> Result<u32, WalletError> {
        let files = self.read_secret_files()?;
        let old = self.vault.lock().unwrap_or_else(|e| e.into_inner()).passphrase().map(str::to_string);
        self.vault.lock().unwrap_or_else(|e| e.into_inner()).set_new_passphrase(&passphrase)?;
        match self.write_secret_files(&files) {
            Ok(n) => {
                self.log("ok", format!("Protected: {n} file(s) sealed on disk."), None);
                Ok(n)
            }
            Err(e) => {
                let mut v = self.vault.lock().unwrap_or_else(|e| e.into_inner());
                match old {
                    Some(p) => v.restore_passphrase(&p),
                    None => v.clear(),
                }
                Err(e)
            }
        }
    }

    /// Remove the passphrase: files are re-written PLAIN (read back sealed first).
    pub fn unprotect(&self) -> Result<u32, WalletError> {
        let files = self.read_secret_files()?;
        let old = self.vault.lock().unwrap_or_else(|e| e.into_inner()).passphrase().map(str::to_string);
        self.vault.lock().unwrap_or_else(|e| e.into_inner()).clear();
        match self.write_secret_files(&files) {
            Ok(n) => {
                self.log("info", format!("Passphrase removed: {n} file(s) now plain on disk."), None);
                Ok(n)
            }
            Err(e) => {
                if let Some(p) = old {
                    self.vault.lock().unwrap_or_else(|e| e.into_inner()).restore_passphrase(&p);
                }
                Err(e)
            }
        }
    }

    /// The strength rule the seal enforces (≥ 12 chars or 4+ words, nothing obvious).
    pub fn passphrase_strength(&self, passphrase: String) -> Result<(), WalletError> {
        hk_wallet::sealed::check_strength(&passphrase).map_err(WalletError::msg)
    }

    /// Seven words from the built-in list (63 bits).
    pub fn generate_passphrase(&self) -> String {
        hk_wallet::sealed::generate_passphrase(7)
    }

    // ---- keychain ----

    /// Create a fresh keychain. Refuses to overwrite an existing (or locked) one.
    pub fn create(&self) -> Result<String, WalletError> {
        if self.account_path().exists() {
            return Err(WalletError::msg("a wallet already exists in this directory"));
        }
        let a = AccountFile::generate();
        self.save_account(&a)?;
        self.log("ok", format!("Keychain created — account {}…", &a.id[..12]), None);
        Ok(a.id)
    }

    /// Restore a keychain from its 32-byte seed (hex). The nonce is adopted from the chain
    /// on the first send, so a stale backup follows the chain.
    pub fn restore(&self, seed_hex: String) -> Result<String, WalletError> {
        if self.account_path().exists() {
            return Err(WalletError::msg("a wallet already exists in this directory"));
        }
        let seed = hex::decode(seed_hex.trim()).map_err(|e| WalletError::msg(format!("seed: {e}")))?;
        if seed.len() != 32 {
            return Err(WalletError::msg("seed must be 32 bytes (64 hex characters)"));
        }
        let a = AccountFile::from_seed(&seed);
        self.save_account(&a)?;
        self.log("ok", format!("Keychain restored — account {}…", &a.id[..12]), None);
        Ok(a.id)
    }

    /// The seed, hex — for the app's backup screen only. Never logged.
    pub fn export_seed(&self) -> Result<String, WalletError> {
        Ok(self.require_account()?.seed)
    }

    pub fn account_id(&self) -> Result<String, WalletError> {
        Ok(self.require_account()?.id)
    }

    /// The auth commitment at ratchet 0 — what the web faucet asks a new account for.
    pub fn auth_commit(&self) -> Result<String, WalletError> {
        let a = self.require_account()?;
        Ok(hex::encode(commit_at(&a.seed_bytes()?, 0).0))
    }

    // ---- assets (P6.2) ----

    /// The native unit — always first in every list, never in the chain's registry.
    pub fn native_asset(&self) -> AssetInfo {
        native_info()
    }

    /// Every asset the wallet can act in: the native unit, then the chain's registry
    /// (`hk_getAssets`), sorted by symbol. One RPC; the result is cached for messages.
    pub fn assets(&self) -> Result<Vec<AssetInfo>, WalletError> {
        let metas = self.http().assets()?;
        let mut out = vec![native_info()];
        out.extend(metas.iter().map(meta_info));
        *self.assets.lock().unwrap_or_else(|e| e.into_inner()) = metas;
        Ok(out)
    }

    /// Look one asset up by id (64-hex) — from the cache, then the chain.
    pub fn asset_info(&self, asset_hex: String) -> Result<AssetInfo, WalletError> {
        let id = parse_h256(&asset_hex)?;
        let c = self.asset_ctx(&id)?;
        Ok(self.ctx_info(&c))
    }

    /// "0.25" → base units for an asset with `decimals` decimals.
    pub fn parse_amount_dec(&self, text: String, decimals: u8) -> Option<u64> {
        parse_amount_dec(&text, decimals).map(clamp_u64)
    }

    pub fn format_amount_dec(&self, base: u64, decimals: u8) -> String {
        fmt_amount_dec(base as Amount, decimals)
    }

    // ---- transparent journey ----

    /// Chain + account snapshot (fee policy, on-chain status, every balance).
    pub fn refresh(&self) -> Result<Status, WalletError> {
        let http = self.http();
        let a = self.require_account()?;
        let id = a.id_h256()?;
        let ci = http.chain_info()?;
        let fee = ci.fee_now();
        let (on_chain, balance, held) = match http.nonce(&id)? {
            Some(_) => (true, http.balance(&id)?, http.account_balances(&id)?),
            None => (false, 0, Vec::new()),
        };
        if !on_chain {
            self.log("info", "Not on-chain yet — tap “Get test funds” to be created + funded.", None);
        }
        // P6.2: the native balance first (even at 0), then every issued asset held, with the
        // registry's symbol/decimals (one RPC, cached) — unknown ids still show, by id.
        let mut balances = vec![AssetBalance { asset: native_info(), balance_micro: clamp_u64(balance) }];
        if held.iter().any(|(asset, _, _)| *asset != USD) {
            let metas = self.registry(&http);
            for (asset, symbol, amount) in held {
                if asset == USD {
                    continue;
                }
                let info = metas.iter().find(|m| m.id == asset).map(meta_info).unwrap_or_else(|| AssetInfo {
                    id: hex::encode(asset.0),
                    symbol: symbol.unwrap_or_else(|| format!("{}…", &hex::encode(asset.0)[..8])),
                    decimals: 6,
                    pool_eligible: false,
                    is_native: false,
                    paused: false,
                });
                balances.push(AssetBalance { asset: info, balance_micro: clamp_u64(amount) });
            }
        }
        Ok(Status {
            chain_id: ci.chain_id,
            height: ci.height,
            node_version: ci.node_version,
            fee_micro: clamp_u64(fee),
            on_chain,
            balance_micro: clamp_u64(balance),
            account_id: a.id,
            max_sendable_micro: clamp_u64(balance.saturating_sub(fee)),
            balances,
        })
    }

    /// Faucet: create+fund if new (auth commit at ratchet 0), top-up if existing.
    pub fn faucet(&self) -> Result<TxResult, WalletError> {
        self.do_faucet(None)
    }

    /// P6.2: a drip of an issued asset (e.g. USDC.sep) from the same faucet. An account that
    /// is not on-chain yet is created + funded with the native drip first — the asset drip is
    /// an ordinary transfer and needs an existing account to land in.
    pub fn faucet_asset(&self, asset_hex: String) -> Result<TxResult, WalletError> {
        let id = parse_h256(&asset_hex)?;
        if id == USD {
            return self.do_faucet(None);
        }
        let a = self.require_account()?;
        if self.http().nonce(&a.id_h256()?)?.is_none() {
            self.log("info", "Not on-chain yet — taking the native drip first so the account exists.", None);
            self.do_faucet(None)?;
        }
        self.do_faucet(Some(id))
    }

    /// Transparent payment in the native unit: fee check → chain-nonce sync → reserve-then-sign → submit → receipt.
    pub fn send(&self, to_hex: String, amount_micro: u64) -> Result<TxResult, WalletError> {
        self.do_send(to_hex, amount_micro, &self.native_ctx())
    }

    /// P6.2: the same payment in any asset; the fee is still paid in the native unit.
    pub fn send_asset(&self, to_hex: String, amount_micro: u64, asset_hex: String) -> Result<TxResult, WalletError> {
        let ctx = self.asset_ctx(&parse_h256(&asset_hex)?)?;
        self.do_send(to_hex, amount_micro, &ctx)
    }

    /// "0.25" → micro-units (the app validates input with this).
    pub fn parse_amount(&self, text: String) -> Option<u64> {
        parse_amount(&text).map(clamp_u64)
    }

    pub fn format_amount(&self, micro: u64) -> String {
        fmt_amount(micro as Amount)
    }

    pub fn explorer_tx_url(&self, txid: String) -> String {
        self.explorer_tx(&txid)
    }

    // ---- shielded journey (see shield.rs) ----

    pub fn stealth_address(&self) -> Result<String, WalletError> {
        let http = self.http();
        let f = self.load_shield()?.ok_or_else(|| WalletError::msg("no shielded side yet — scan once to create it"))?;
        self.stealth_address_of(&http, &f)
    }

    pub fn scan(&self) -> Result<ScanResult, WalletError> {
        self.do_scan(&self.native_ctx())
    }

    pub fn scan_asset(&self, asset_hex: String) -> Result<ScanResult, WalletError> {
        let ctx = self.asset_ctx(&parse_h256(&asset_hex)?)?;
        self.do_scan(&ctx)
    }

    /// The notes from the last scan, without touching the network.
    pub fn notes(&self) -> Result<Vec<NoteView>, WalletError> {
        self.cached_notes(&USD)
    }

    pub fn notes_asset(&self, asset_hex: String) -> Result<Vec<NoteView>, WalletError> {
        self.cached_notes(&parse_h256(&asset_hex)?)
    }

    pub fn shield(&self, amount_micro: u64) -> Result<TxResult, WalletError> {
        self.do_shield(amount_micro as Amount, &self.native_ctx())
    }

    pub fn shield_asset(&self, amount_micro: u64, asset_hex: String) -> Result<TxResult, WalletError> {
        let ctx = self.asset_ctx(&parse_h256(&asset_hex)?)?;
        self.do_shield(amount_micro as Amount, &ctx)
    }

    pub fn unshield(&self, amount_micro: u64) -> Result<TxResult, WalletError> {
        self.do_unshield(amount_micro as Amount, &self.native_ctx())
    }

    pub fn unshield_asset(&self, amount_micro: u64, asset_hex: String) -> Result<TxResult, WalletError> {
        let ctx = self.asset_ctx(&parse_h256(&asset_hex)?)?;
        self.do_unshield(amount_micro as Amount, &ctx)
    }

    pub fn pay_shielded(&self, to_address: String, amount_micro: u64, memo: String) -> Result<TxResult, WalletError> {
        self.do_pay(&to_address, amount_micro as Amount, &memo, &self.native_ctx())
    }

    pub fn pay_shielded_asset(&self, to_address: String, amount_micro: u64, memo: String, asset_hex: String) -> Result<TxResult, WalletError> {
        let ctx = self.asset_ctx(&parse_h256(&asset_hex)?)?;
        self.do_pay(&to_address, amount_micro as Amount, &memo, &ctx)
    }

    /// Returns the disclosure package JSON (also written next to the wallet files).
    pub fn disclose(&self, commitment_hex: String) -> Result<String, WalletError> {
        self.do_disclose(&commitment_hex, &self.native_ctx())
    }

    pub fn disclose_asset(&self, commitment_hex: String, asset_hex: String) -> Result<String, WalletError> {
        let ctx = self.asset_ctx(&parse_h256(&asset_hex)?)?;
        self.do_disclose(&commitment_hex, &ctx)
    }
}

// ---------------------------------------------------------------------------
// Internals shared by the modules
// ---------------------------------------------------------------------------

fn clamp_u64(a: Amount) -> u64 {
    a.min(u64::MAX as Amount) as u64
}

fn short(txid: &str) -> &str {
    &txid[..16.min(txid.len())]
}

impl Wallet {
    pub(crate) fn http(&self) -> Http {
        Http::new(self.endpoints())
    }

    pub(crate) fn account_path(&self) -> PathBuf {
        self.dir.join("account.json")
    }

    fn explorer_tx(&self, txid: &str) -> String {
        format!("{}#tx={txid}", self.endpoints().explorer)
    }

    pub(crate) fn log(&self, level: &str, line: impl Into<String>, link: Option<String>) {
        if let Some(l) = self.listener.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            l.on_log(level.to_string(), line.into(), link);
        }
    }

    pub(crate) fn log_info(&self, line: impl Into<String>) {
        self.log("info", line, None);
    }

    fn native_ctx(&self) -> AssetCtx {
        AssetCtx { id: USD, symbol: NATIVE_SYMBOL.into(), decimals: NATIVE_DECIMALS }
    }

    fn ctx_info(&self, c: &AssetCtx) -> AssetInfo {
        if c.id == USD {
            return native_info();
        }
        let cache = self.assets.lock().unwrap_or_else(|e| e.into_inner());
        cache.iter().find(|m| m.id == c.id).map(meta_info).unwrap_or(AssetInfo {
            id: hex::encode(c.id.0),
            symbol: c.symbol.clone(),
            decimals: c.decimals,
            pool_eligible: false,
            is_native: false,
            paused: false,
        })
    }

    /// The registry, from the cache when it has the asset, else re-read from the chain.
    fn registry(&self, http: &Http) -> Vec<AssetMeta> {
        let cached = self.assets.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if !cached.is_empty() {
            return cached;
        }
        match http.assets() {
            Ok(m) => {
                *self.assets.lock().unwrap_or_else(|e| e.into_inner()) = m.clone();
                m
            }
            Err(_) => Vec::new(),
        }
    }

    /// The context for an asset id: native without a round trip; issued assets from the
    /// registry (cached, re-read once on a miss). An id the chain does not know is refused —
    /// sending to a made-up asset would be refused by the chain, at the cost of a ratchet index.
    pub(crate) fn asset_ctx(&self, id: &H256) -> Result<AssetCtx, WalletError> {
        if *id == USD {
            return Ok(self.native_ctx());
        }
        let http = self.http();
        let find = |metas: &[AssetMeta]| metas.iter().find(|m| m.id == *id).cloned();
        let hit = find(&self.assets.lock().unwrap_or_else(|e| e.into_inner()));
        let meta = match hit {
            Some(m) => m,
            None => {
                let fresh = http.assets()?;
                *self.assets.lock().unwrap_or_else(|e| e.into_inner()) = fresh.clone();
                find(&fresh).ok_or_else(|| WalletError::msg(format!("asset {}… is not registered on this chain", &hex::encode(id.0)[..8])))?
            }
        };
        Ok(AssetCtx { id: meta.id, symbol: meta.symbol, decimals: meta.decimals })
    }

    /// `Ok(Some)` plain or opened; `Ok(None)` sealed and locked.
    pub(crate) fn read_secret(&self, path: &Path) -> Result<Option<String>, WalletError> {
        self.vault.lock().unwrap_or_else(|e| e.into_inner()).read(path)
    }

    /// Sealed while a passphrase is set, plain otherwise; fsync + rename.
    pub(crate) fn write_secret(&self, path: &Path, tmp_name: &str, plaintext: &str) -> Result<(), WalletError> {
        std::fs::create_dir_all(&self.dir).map_err(|e| WalletError::msg(e.to_string()))?;
        let bytes = self.vault.lock().unwrap_or_else(|e| e.into_inner()).encode(path, plaintext)?;
        write_atomic(path, &self.dir.join(tmp_name), bytes.as_bytes())
    }

    pub(crate) fn load_account(&self) -> Result<Option<AccountFile>, WalletError> {
        let path = self.account_path();
        if !path.exists() {
            return Ok(None);
        }
        match self.read_secret(&path)? {
            Some(s) => serde_json::from_str(&s).map(Some).map_err(|e| WalletError::msg(format!("account.json: {e}"))),
            None => Ok(None),
        }
    }

    pub(crate) fn save_account(&self, a: &AccountFile) -> Result<(), WalletError> {
        let text = serde_json::to_string_pretty(a).map_err(|e| WalletError::msg(e.to_string()))?;
        self.write_secret(&self.account_path(), "account.json.tmp", &text)
    }

    fn require_account(&self) -> Result<AccountFile, WalletError> {
        match self.load_account()? {
            Some(a) => Ok(a),
            None if self.account_path().exists() => Err(WalletError::msg("wallet is locked — unlock it first")),
            None => Err(WalletError::msg("no wallet yet — create or restore one")),
        }
    }

    /// (seed bytes, account id) for signing.
    pub(crate) fn signer(&self) -> Result<(Vec<u8>, H256), WalletError> {
        let a = self.require_account()?;
        Ok((a.seed_bytes()?, a.id_h256()?))
    }

    /// K1: both secret files as currently readable — read BEFORE a passphrase change,
    /// written AFTER.
    fn read_secret_files(&self) -> Result<(Option<AccountFile>, Option<shield::ShieldFile>), WalletError> {
        let a = if self.account_path().exists() {
            Some(self.load_account()?.ok_or_else(|| WalletError::msg("could not read account.json (locked?)"))?)
        } else {
            None
        };
        let s = if self.shield_path().exists() { Some(self.load_shield()?.ok_or_else(|| WalletError::msg("could not read shield.json (locked?)"))?) } else { None };
        Ok((a, s))
    }

    fn write_secret_files(&self, files: &(Option<AccountFile>, Option<shield::ShieldFile>)) -> Result<u32, WalletError> {
        let mut n = 0;
        if let Some(a) = &files.0 {
            self.save_account(a)?;
            n += 1;
        }
        if let Some(s) = &files.1 {
            self.save_shield(s)?;
            n += 1;
        }
        Ok(n)
    }

    /// The faucet call: native (`asset = None`) or an issued asset. The server answers the
    /// same shape for both; the asset drip is refused for an account that does not exist.
    fn do_faucet(&self, asset: Option<H256>) -> Result<TxResult, WalletError> {
        let http = self.http();
        let a = self.require_account()?;
        let id = a.id_h256()?;
        let seed = a.seed_bytes()?;
        let what = match asset {
            Some(x) => self.asset_ctx(&x).map(|c| c.symbol).unwrap_or_else(|_| "asset".into()),
            None => "test funds".into(),
        };
        self.log("info", format!("Requesting {what}…"), None);
        let mut body = match http.nonce(&id)? {
            Some(_) => json!({ "account": hex::encode(id.0) }),
            None => json!({ "auth_commit": hex::encode(commit_at(&seed, 0).0) }),
        };
        if let Some(x) = asset {
            body["asset"] = json!(hex::encode(x.0));
        }
        let v = http.faucet_post(body)?;
        if v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false) {
            let amt = v.get("amount_micro").map(|a| a.to_string()).unwrap_or_default();
            let txid = v.get("txid").and_then(|t| t.as_str()).unwrap_or("?").to_string();
            // Name what actually landed: a P6.2 faucet echoes the asset it dripped; an older
            // faucet ignores the `asset` field and drips the native unit — say so, do not
            // label a native drip with the asset the user asked for (seen 2026-09-13).
            let got = v.get("asset").and_then(|a| a.as_str()).map(|s| s.to_ascii_lowercase());
            let label = match (asset, got) {
                (Some(x), Some(g)) if g == hex::encode(x.0) => what.clone(),
                (Some(_), _) => format!("test funds — this faucet does not serve {what} yet (it dripped the native unit)"),
                (None, _) => what.clone(),
            };
            let summary = format!("Faucet dripped {amt} base units of {label}");
            self.log("ok", format!("{summary} — tx {}…", short(&txid)), Some(self.explorer_tx(&txid)));
            // Give the chain a couple of blocks before the app refreshes.
            std::thread::sleep(Duration::from_secs(3));
            Ok(TxResult { explorer_url: self.explorer_tx(&txid), txid, receipt: "ok".into(), summary })
        } else {
            let err = v.get("error").and_then(|e| e.as_str()).unwrap_or("faucet refused").to_string();
            let retry = v
                .get("retry_after_secs")
                .and_then(|r| r.as_u64())
                .map(|s| format!(" (retry in ~{}h{:02}m)", s / 3600, (s % 3600) / 60))
                .unwrap_or_default();
            Err(WalletError::msg(format!("{err}{retry}")))
        }
    }

    /// Transparent payment in `asset`: fee check (native) + balance check (asset) →
    /// chain-nonce sync → reserve-then-sign → submit → receipt.
    fn do_send(&self, to_hex: String, amount_micro: u64, a: &AssetCtx) -> Result<TxResult, WalletError> {
        let http = self.http();
        let (seed, id) = self.signer()?;
        let to = parse_h256(&to_hex)?;
        let amount = amount_micro as Amount;
        if amount == 0 {
            return Err(WalletError::msg("amount must be above zero"));
        }
        let fee = http.chain_info()?.fee_now();
        let native = http.balance(&id)?;
        if a.id == USD {
            if fee > 0 && amount.saturating_add(fee) > native {
                return Err(WalletError::msg(format!(
                    "Not enough for amount + network fee ({}). Balance {} → max sendable {}.",
                    fmt_amount(fee),
                    fmt_amount(native),
                    fmt_amount(native.saturating_sub(fee))
                )));
            }
        } else {
            if native < fee {
                return Err(WalletError::msg(format!(
                    "The network fee ({} {NATIVE_SYMBOL}) is paid from your native balance, which is {} — get test funds first.",
                    fmt_amount(fee),
                    fmt_amount(native)
                )));
            }
            let bal = http.balance_of(&id, &a.id)?;
            if amount > bal {
                return Err(WalletError::msg(format!("Not enough {}: sending {} but the balance is {}.", a.symbol, a.fmt(amount), a.fmt(bal))));
            }
        }
        self.log("info", format!("Sending {} {} to {}…", a.fmt(amount), a.symbol, &to_hex.trim()[..12.min(to_hex.trim().len())]), None);
        self.send_payload(&http, &seed, id, Tx::Transfer { to, asset: a.id, amount }, &format!("Paid {} {} ✓", a.fmt(amount), a.symbol))
    }

    /// The one way this wallet puts a transaction on the chain — shared by the transparent
    /// send and every shielded operation: chain-nonce sync → RESERVE-THEN-SIGN → submit →
    /// receipt, with the nonce rolled back (and persisted) only on a definitive refusal.
    pub(crate) fn send_payload(&self, http: &Http, seed: &[u8], id: H256, payload: Tx, ok_label: &str) -> Result<TxResult, WalletError> {
        // 1) The chain's nonce is the truth (restored backups follow the chain).
        let nonce = match http.nonce(&id)? {
            Some(n) => n,
            None => return Err(WalletError::msg("This wallet isn't on-chain yet — get test funds first.")),
        };
        // 2) RESERVE-THEN-SIGN: persist nonce+1 before the network sees the tx.
        let mut file = self.require_account()?;
        file.next_nonce = nonce + 1;
        self.save_account(&file).map_err(|e| WalletError::msg(format!("could not persist nonce (refusing to sign): {e}")))?;
        let signed = sign_tx(seed, id, nonce, payload);
        let rollback = |file: &mut AccountFile| {
            file.next_nonce = nonce;
            if let Err(e) = self.save_account(file) {
                self.log("error", format!("rollback persist failed: {e}"), None);
            }
        };
        // 3) Submit.
        let txid = match http.rpc("hk_submitTx", json!({ "tx": serde_json::to_value(&signed).unwrap() })) {
            Ok(v) => match v.get("result").and_then(|r| r.get("txid")).and_then(|t| t.as_str()) {
                Some(t) => t.to_string(),
                None => {
                    rollback(&mut file);
                    let why = v
                        .get("result")
                        .and_then(|r| r.get("reason"))
                        .and_then(|r| r.as_str())
                        .map(str::to_string)
                        .unwrap_or_else(|| v.to_string());
                    return Err(WalletError::msg(format!("submit refused (nonce rolled back): {why}")));
                }
            },
            Err(e) => {
                rollback(&mut file);
                return Err(WalletError::msg(format!("submit failed (nonce rolled back): {e}")));
            }
        };
        // 4) Receipt: wait up to ~60 s — a slow block must not strand a ratchet index.
        for _ in 0..75 {
            std::thread::sleep(Duration::from_millis(800));
            if let Some(r) = http.receipt(&txid) {
                if r.starts_with("rejected") {
                    rollback(&mut file);
                    let why = if r.contains("protocol fee") {
                        "the network fee could not be paid — keep a little native balance back for it".to_string()
                    } else {
                        r.clone()
                    };
                    return Err(WalletError::msg(format!("Chain refused: {why} (nonce rolled back)")));
                }
                let summary = format!("{ok_label}  tx {}…  ({r})", short(&txid));
                self.log("ok", summary.clone(), Some(self.explorer_tx(&txid)));
                return Ok(TxResult { explorer_url: self.explorer_tx(&txid), txid, receipt: r, summary });
            }
        }
        self.log(
            "info",
            format!("No receipt after 60 s for {}… — probably still pending; refresh in a minute (the nonce stays advanced; nothing to redo).", short(&txid)),
            Some(self.explorer_tx(&txid)),
        );
        Err(WalletError::msg(format!("no receipt after 60 s for {} — check the explorer", short(&txid))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hk-wallet-core-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    struct Collect(Mutex<Vec<String>>);
    impl Progress for Collect {
        fn on_log(&self, level: String, line: String, _link: Option<String>) {
            self.0.lock().unwrap().push(format!("{level}: {line}"));
        }
    }

    #[test]
    fn wa1_create_state_seed_roundtrip() {
        let dir = tmp_dir("create");
        let w = Wallet::new(dir.to_string_lossy().to_string(), None);
        let st = w.state();
        assert!(!st.exists && !st.sealed && !st.locked && st.account_id.is_none());
        let id = w.create().unwrap();
        assert_eq!(id.len(), 64);
        assert!(w.create().is_err(), "must not overwrite");
        let st = w.state();
        assert!(st.exists && !st.sealed && !st.locked && st.account_id.as_deref() == Some(id.as_str()));
        let seed = w.export_seed().unwrap();
        // The same seed restores the same id in another directory.
        let dir2 = tmp_dir("restore");
        let w2 = Wallet::new(dir2.to_string_lossy().to_string(), None);
        assert_eq!(w2.restore(seed).unwrap(), id);
        assert!(w2.restore("00".repeat(32)).is_err());
        assert_eq!(w.auth_commit().unwrap().len(), 64);
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(dir2);
    }

    #[test]
    fn wa1_protect_unlock_unprotect_with_mobile_profile_and_keyfile() {
        // Small profile via env so the test stays fast: the vault reads Kdf::default_profile
        // only when no explicit profile is set — set the mobile one explicitly, then shrink it
        // through the env floors for the test run (64 MiB, t3 — the module minimum).
        std::env::set_var("HK_SEAL_M_KIB", "65536");
        std::env::set_var("HK_SEAL_T", "3");
        let dir = tmp_dir("protect");
        let w = Wallet::new(dir.to_string_lossy().to_string(), None);
        let logs = Arc::new(Collect(Mutex::new(Vec::new())));
        struct Fwd(Arc<Collect>);
        impl Progress for Fwd {
            fn on_log(&self, level: String, line: String, link: Option<String>) {
                self.0.on_log(level, line, link)
            }
        }
        w.set_listener(Box::new(Fwd(logs.clone())));
        let id = w.create().unwrap();
        let kf = w.new_keyfile();
        assert_eq!(kf.len(), 32);
        w.set_keyfile(Some(kf.clone())).unwrap();
        // Default profile here is the env-shrunk one (fast); protect seals account.json.
        assert!(w.passphrase_strength("short".into()).is_err());
        let pass = w.generate_passphrase();
        assert_eq!(w.protect(pass.clone()).unwrap(), 1);
        let st = w.state();
        assert!(st.sealed && st.needs_keyfile && st.protected && !st.locked);
        assert_eq!(st.account_id.as_deref(), Some(id.as_str()));
        // Lock → locked; unlock with the wrong passphrase refused, right one opens.
        w.lock();
        assert!(w.state().locked);
        assert!(w.export_seed().is_err());
        assert!(w.unlock("not the passphrase at all".into()).is_err());
        w.unlock(pass.clone()).unwrap();
        assert_eq!(w.account_id().unwrap(), id);
        // Without the key file bytes the envelope is refused by name.
        w.lock();
        w.set_keyfile(None).unwrap();
        let e = w.unlock(pass.clone()).unwrap_err().to_string();
        assert!(e.contains("key file"), "{e}");
        w.set_keyfile(Some(kf)).unwrap();
        w.unlock(pass).unwrap();
        // Unprotect → plain again, same id.
        assert_eq!(w.unprotect().unwrap(), 1);
        let st = w.state();
        assert!(!st.sealed && !st.locked && st.account_id.as_deref() == Some(id.as_str()));
        assert!(logs.0.lock().unwrap().iter().any(|l| l.starts_with("ok: Protected")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn wa1_endpoints_default_to_the_public_testnet() {
        let w = Wallet::new(tmp_dir("ep").to_string_lossy().to_string(), None);
        let e = w.endpoints();
        assert_eq!(e.rpc, RPC_DEFAULT);
        assert_eq!(e.prover, PROVER_DEFAULT);
        assert_eq!(w.explorer_tx_url("abc".into()), format!("{EXPLORER_DEFAULT}#tx=abc"));
        assert_eq!(w.parse_amount("0.25".into()), Some(250_000));
        assert_eq!(w.format_amount(250_000), "0.250000");
        w.set_endpoints(Endpoints { rpc: "http://127.0.0.1:26000".into(), ..Endpoints::default() });
        assert_eq!(w.endpoints().rpc, "http://127.0.0.1:26000");
    }

    #[test]
    fn p62_native_asset_needs_no_network_and_is_first() {
        let w = Wallet::new(tmp_dir("native").to_string_lossy().to_string(), None);
        let n = w.native_asset();
        assert!(n.is_native && n.pool_eligible && n.decimals == 6 && n.symbol == NATIVE_SYMBOL);
        assert_eq!(n.id, hex::encode(USD.0));
        // The native id resolves without a round trip (no endpoints reachable in a unit test).
        w.set_endpoints(Endpoints { rpc: "http://127.0.0.1:1".into(), ..Endpoints::default() });
        assert_eq!(w.asset_info(n.id.clone()).unwrap(), n);
        // An issued asset the chain cannot be asked about is refused, not guessed.
        assert!(w.asset_info("11".repeat(32)).is_err());
        assert!(w.asset_info("zz".into()).is_err());
        assert_eq!(w.parse_amount_dec("1.5".into(), 2), Some(150));
        assert_eq!(w.format_amount_dec(150, 2), "1.50");
    }

    /// The whole journey against a devnet + faucet + prover (gate-wa1.sh sets the env):
    /// HK_CORE_RPC, HK_CORE_FAUCET, HK_CORE_PROVER; HK_CORE_DIR keeps the wallet directory
    /// (and leaves the passphrase in `.gate-passphrase`) so the gate can open the files the
    /// core wrote with the CLI — the byte-compatibility receipt. Ignored otherwise.
    #[test]
    #[ignore]
    fn wa1_devnet_journey() {
        let rpc = std::env::var("HK_CORE_RPC").expect("HK_CORE_RPC");
        let faucet = std::env::var("HK_CORE_FAUCET").expect("HK_CORE_FAUCET");
        let prover = std::env::var("HK_CORE_PROVER").expect("HK_CORE_PROVER");
        let keep = std::env::var("HK_CORE_DIR").ok().map(PathBuf::from);
        let dir = match &keep {
            Some(d) => {
                let _ = std::fs::remove_dir_all(d);
                d.clone()
            }
            None => tmp_dir("journey"),
        };
        let w = Wallet::new(dir.to_string_lossy().to_string(), Some(Endpoints { rpc, faucet, prover, explorer: EXPLORER_DEFAULT.into() }));
        let logs = Arc::new(Collect(Mutex::new(Vec::new())));
        struct Fwd(Arc<Collect>);
        impl Progress for Fwd {
            fn on_log(&self, level: String, line: String, link: Option<String>) {
                eprintln!("  [{level}] {line}");
                self.0.on_log(level, line, link)
            }
        }
        w.set_listener(Box::new(Fwd(logs)));
        let id = w.create().unwrap();
        let st = w.refresh().unwrap();
        assert!(!st.on_chain, "fresh wallet must not be on-chain");
        // 1) faucet creates + funds
        let drip = w.faucet().unwrap();
        assert_eq!(drip.txid.len(), 64);
        let st = w.refresh().unwrap();
        assert!(st.on_chain && st.balance_micro > 0, "after the drip: {st:?}");
        assert!(st.balances[0].asset.is_native && st.balances[0].balance_micro == st.balance_micro);
        let bal0 = st.balance_micro;
        // 2) transparent send to a fresh account of ours (created by the transfer? no — to a
        //    known id: pay ourselves is refused? send to a second wallet's id (not on-chain)
        //    would create-or-fail; use the same id — a self-transfer is a valid transfer).
        let r = w.send(id.clone(), 1_000).unwrap();
        assert_eq!(r.txid.len(), 64);
        let st = w.refresh().unwrap();
        assert!(st.balance_micro <= bal0, "self-send pays the fee: {} vs {bal0}", st.balance_micro);
        // 3) shield 0.05, scan finds it, unshield 0.02 (change goes back into hiding)
        let s = w.shield(50_000).unwrap();
        assert_eq!(s.txid.len(), 64);
        let sc = w.scan().unwrap();
        assert!(sc.notes.iter().any(|n| n.value_micro == 50_000 && !n.spent), "scan: {sc:?}");
        assert!(sc.stealth_address.starts_with("hkaddr:"));
        let u = w.unshield(20_000).unwrap();
        assert_eq!(u.txid.len(), 64);
        let sc = w.scan().unwrap();
        assert!(sc.notes.iter().any(|n| n.value_micro == 30_000 && !n.spent), "change note: {sc:?}");
        assert!(sc.notes.iter().any(|n| n.value_micro == 50_000 && n.spent), "input spent: {sc:?}");
        assert_eq!(sc.ots_used, 1);
        // 4) shielded pay to our own stealth address with a memo, then disclose it
        let p = w.pay_shielded(sc.stealth_address.clone(), 10_000, "hello from the core".into()).unwrap();
        assert_eq!(p.txid.len(), 64);
        let sc = w.scan().unwrap();
        let paid = sc.notes.iter().find(|n| n.value_micro == 10_000 && n.memo == "hello from the core").expect("paid note found");
        let pkg = w.disclose(paid.commitment.clone()).unwrap();
        assert!(pkg.contains("\"chain_id\""));
        assert_eq!(sc.ots_used, 2);
        // 5) protect (fast env profile) + lock + unlock + a send from the sealed files
        std::env::set_var("HK_SEAL_M_KIB", "65536");
        std::env::set_var("HK_SEAL_T", "3");
        let pass = w.generate_passphrase();
        assert_eq!(w.protect(pass.clone()).unwrap(), 2);
        w.lock();
        assert!(w.refresh().is_err());
        w.unlock(pass.clone()).unwrap();
        let r = w.send(id, 1_000).unwrap();
        assert_eq!(r.txid.len(), 64);
        assert!(w.state().sealed);
        match keep {
            Some(d) => std::fs::write(d.join(".gate-passphrase"), format!("{pass}\n")).unwrap(),
            None => {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }

    /// P6.2: the same journey in an ISSUED asset (gate-p6-2.sh sets HK_CORE_ASSET to an asset
    /// the faucet drips — a devnet `USDC.t`). Ignored without the env.
    #[test]
    #[ignore]
    fn p62_devnet_asset_journey() {
        let rpc = std::env::var("HK_CORE_RPC").expect("HK_CORE_RPC");
        let faucet = std::env::var("HK_CORE_FAUCET").expect("HK_CORE_FAUCET");
        let prover = std::env::var("HK_CORE_PROVER").expect("HK_CORE_PROVER");
        let asset = std::env::var("HK_CORE_ASSET").expect("HK_CORE_ASSET (64-hex)");
        let dir = tmp_dir("asset-journey");
        let w = Wallet::new(dir.to_string_lossy().to_string(), Some(Endpoints { rpc, faucet, prover, explorer: EXPLORER_DEFAULT.into() }));
        struct Print;
        impl Progress for Print {
            fn on_log(&self, level: String, line: String, _link: Option<String>) {
                eprintln!("  [{level}] {line}");
            }
        }
        w.set_listener(Box::new(Print));
        let id = w.create().unwrap();
        // The registry knows the asset; the native unit is listed first.
        let list = w.assets().unwrap();
        assert!(list[0].is_native);
        let info = list.iter().find(|a| a.id == asset).expect("asset registered").clone();
        assert!(info.pool_eligible, "the gate's asset must be pool-eligible: {info:?}");
        // 1) the asset drip on a NOT-YET-ON-CHAIN wallet: native drip first, then the asset.
        let d = w.faucet_asset(asset.clone()).unwrap();
        assert_eq!(d.txid.len(), 64);
        let st = w.refresh().unwrap();
        assert!(st.on_chain && st.balance_micro > 0, "native drip landed: {st:?}");
        let held = st.balances.iter().find(|b| b.asset.id == asset).expect("asset balance shown");
        assert!(held.balance_micro > 0, "asset drip landed: {st:?}");
        let a0 = held.balance_micro;
        // 2) transparent send of the asset (self-transfer), fee in the native unit.
        let r = w.send_asset(id.clone(), 1_000, asset.clone()).unwrap();
        assert_eq!(r.txid.len(), 64);
        let st = w.refresh().unwrap();
        let held = st.balances.iter().find(|b| b.asset.id == asset).unwrap();
        assert_eq!(held.balance_micro, a0, "a self-transfer moves nothing in the asset: {st:?}");
        // 3) shield into the asset's own pool; the NATIVE pool stays empty.
        let s = w.shield_asset(50_000, asset.clone()).unwrap();
        assert_eq!(s.txid.len(), 64);
        let sc = w.scan_asset(asset.clone()).unwrap();
        assert_eq!(sc.asset, asset);
        assert!(sc.notes.iter().any(|n| n.value_micro == 50_000 && !n.spent), "asset scan: {sc:?}");
        let native = w.scan().unwrap();
        assert!(native.notes.is_empty(), "notes must not leak across pools: {native:?}");
        // 4) unshield part, pay the rest to ourselves in the same pool, disclose it.
        let u = w.unshield_asset(20_000, asset.clone()).unwrap();
        assert_eq!(u.txid.len(), 64);
        let sc = w.scan_asset(asset.clone()).unwrap();
        assert!(sc.notes.iter().any(|n| n.value_micro == 30_000 && !n.spent), "change: {sc:?}");
        let p = w.pay_shielded_asset(sc.stealth_address.clone(), 10_000, "asset memo".into(), asset.clone()).unwrap();
        assert_eq!(p.txid.len(), 64);
        let sc = w.scan_asset(asset.clone()).unwrap();
        let paid = sc.notes.iter().find(|n| n.value_micro == 10_000 && n.memo == "asset memo").expect("paid note");
        let pkg = w.disclose_asset(paid.commitment.clone(), asset.clone()).unwrap();
        assert!(pkg.contains("\"asset\""), "the package names its pool: {pkg}");
        assert_eq!(sc.ots_used, 2, "leaves are shared across pools");
        // 5) cached notes per pool, and the file still opens.
        assert!(!w.notes_asset(asset).unwrap().is_empty());
        assert!(w.notes().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
