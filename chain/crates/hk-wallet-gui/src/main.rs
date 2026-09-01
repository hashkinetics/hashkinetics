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
//! - Transparent path only in v1 — shielded ops ride the public prover in a
//!   later release; this version is the "join, get funded, pay" story.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

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

const RPC: &str = "https://rpc.hashkinetics.org";
const FAUCET: &str = "https://faucet.hashkinetics.org";
const EXPLORER: &str = "https://www.hashkinetics.org/explorer/";
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

fn load_account() -> Option<AccountFile> {
    let s = std::fs::read_to_string(account_path()).ok()?;
    serde_json::from_str(&s).ok()
}

fn save_account(f: &AccountFile) -> Result<(), String> {
    std::fs::create_dir_all(wallet_dir()).map_err(|e| e.to_string())?;
    let tmp = wallet_dir().join("account.json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(f).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, account_path()).map_err(|e| e.to_string())
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
    ureq::post(RPC)
        .timeout(Duration::from_secs(8))
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
    let req = ureq::post(&format!("{FAUCET}/drip")).timeout(Duration::from_secs(30));
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

enum Evt {
    /// (line, color, optional explorer link rendered as "view ↗")
    Log(String, egui::Color32, Option<String>),
    Balance(Amount),
    OnChain(bool),
    Busy(bool),
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
        // 1) The chain's nonce is the truth (restored backups follow the chain).
        let nonce = match chain_nonce(&id) {
            Ok(Some(n)) => n,
            Ok(None) => {
                log_err(&tx, "This wallet isn't on-chain yet — get test funds first.");
                let _ = tx.send(Evt::Busy(false));
                return;
            }
            Err(e) => {
                log_err(&tx, e);
                let _ = tx.send(Evt::Busy(false));
                return;
            }
        };
        // 2) RESERVE-THEN-SIGN: persist nonce+1 before the network sees the tx.
        let mut file = match load_account() {
            Some(f) => f,
            None => {
                log_err(&tx, "account file vanished — restart the wallet");
                let _ = tx.send(Evt::Busy(false));
                return;
            }
        };
        file.next_nonce = nonce + 1;
        if let Err(e) = save_account(&file) {
            log_err(&tx, format!("could not persist nonce (refusing to sign): {e}"));
            let _ = tx.send(Evt::Busy(false));
            return;
        }
        let signed = sign_tx(&seed, id, nonce, Tx::Transfer { to, asset: USD, amount });
        log(&tx, format!("Sending {} to {}…", fmt_amount(amount), &hex::encode(to.0)[..12]));
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
                    rollback(&mut file, &tx);
                    log_err(&tx, format!("submit refused (nonce rolled back): {v}"));
                    let _ = tx.send(Evt::Busy(false));
                    return;
                }
            },
            Err(e) => {
                rollback(&mut file, &tx);
                log_err(&tx, format!("submit failed (nonce rolled back): {e}"));
                let _ = tx.send(Evt::Busy(false));
                return;
            }
        };
        // 4) Receipt.
        for _ in 0..24 {
            std::thread::sleep(Duration::from_millis(800));
            if let Some(r) = chain_receipt(&txid) {
                if r.starts_with("rejected") {
                    rollback(&mut file, &tx);
                    log_err(&tx, format!("Chain refused: {r} (nonce rolled back)"));
                } else {
                    log_tx(&tx, format!("Paid ✓  tx {}…  ({r})", &txid[..16.min(txid.len())]), &txid);
                }
                if let Ok(b) = chain_balance(&id) {
                    let _ = tx.send(Evt::Balance(b));
                }
                let _ = tx.send(Evt::Busy(false));
                return;
            }
        }
        let _ = tx.send(Evt::Log(
            format!("No receipt yet for {}… — nonce stays advanced.", &txid[..16.min(txid.len())]),
            DIM,
            Some(format!("{EXPLORER}#tx={txid}")),
        ));
        let _ = tx.send(Evt::Busy(false));
    });
}

// ---------------------------------------------------------------------------
// The app
// ---------------------------------------------------------------------------

struct App {
    account: Option<AccountFile>,
    balance: Option<Amount>,
    on_chain: Option<bool>,
    busy: bool,
    to_input: String,
    amount_input: String,
    restore_input: String,
    log_lines: Vec<(String, egui::Color32, Option<String>)>,
    evt_rx: Receiver<Evt>,
    evt_tx: Sender<Evt>,
    booted: bool,
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
        Self {
            account: load_account(),
            balance: None,
            on_chain: None,
            busy: false,
            to_input: String::new(),
            amount_input: String::new(),
            restore_input: String::new(),
            log_lines: Vec::new(),
            evt_rx,
            evt_tx,
            booted: false,
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
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("HASH").strong().size(20.0));
                ui.label(egui::RichText::new("KINETICS").strong().size(20.0).color(CYAN));
                ui.label(egui::RichText::new("  wallet · staging-1").size(12.0).color(DIM));
            });
            ui.add_space(4.0);
            ui.separator();
            ui.add_space(8.0);

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
                        let preview = parse_amount(&self.amount_input).map(|m| format!("= {} micro", m));
                        if let Some(p) = preview.clone() {
                            ui.label(egui::RichText::new(p).color(DIM).size(10.0));
                        }
                        let can_send = !self.busy
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

            // Footer
            ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.hyperlink_to("explorer", "https://www.hashkinetics.org/explorer/");
                    ui.label(egui::RichText::new("·").color(DIM));
                    ui.hyperlink_to("hashkinetics.org", "https://www.hashkinetics.org");
                    ui.label(egui::RichText::new("·").color(DIM));
                    ui.label(egui::RichText::new("hash-based keys · your first spend signs at ratchet index 0").size(10.0).color(DIM));
                });
            });
        });
    }
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
