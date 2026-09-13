//! U3 — HashKinetics Wallet: the front door as a desktop app.
//!
//! Create a keychain, tap the faucet, hold a balance, pay anyone — the same journey as
//! `hk-node account-*`, behind a double-click.
//!
//! P6.2 (v0.15.0, 2026-09-13): this window is a THIN SHELL over `hk-wallet-core` — the same
//! library the Android app runs. Every rule the desktop wallet used to carry in its own code
//! now lives in the core (keys born locally; RESERVE-THEN-SIGN with the chain's nonce as the
//! truth; the fee policy read and refused locally; the shielded counters advanced + fsynced
//! before use; HKE1-sealed files shared byte-for-byte with the CLI and the phone). What this
//! file does: threads, widgets, and the asset dropdown — the native test unit, `USDC.sep` and
//! every registered asset, with balance / send / shield / unshield / pay / scan acting in the
//! selected asset and a "Get test USDC" button next to "Get test funds". All network work
//! runs on worker threads; the UI thread never blocks.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

use eframe::egui;
use hk_wallet_core::{AssetInfo, Endpoints, NoteView, Progress, ScanResult, Status, Wallet, WalletState};

/// Shown in the footer; bump with every release (the crate version is workspace-wide).
pub const WALLET_VERSION: &str = "v0.15.0";
const EXPLORER: &str = "https://www.hashkinetics.org/explorer/";
const BRIDGE_URL: &str = "https://www.hashkinetics.org/bridge";

const CYAN: egui::Color32 = egui::Color32::from_rgb(0x4e, 0xf0, 0xd0);
const GOLD: egui::Color32 = egui::Color32::from_rgb(0xf5, 0xc5, 0x18);
const RED: egui::Color32 = egui::Color32::from_rgb(0xff, 0x6b, 0x6b);
const DIM: egui::Color32 = egui::Color32::from_rgb(0x93, 0xa0, 0xc6);

fn wallet_dir() -> PathBuf {
    let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".hashkinetics")
}

/// v0.13.1: the endpoints can be pointed at a devnet without a rebuild —
/// `HK_WALLET_RPC` / `HK_WALLET_FAUCET` / `HK_WALLET_PROVER` (read once, at start).
fn endpoints_from_env() -> Endpoints {
    let env = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());
    let d = Endpoints::default();
    Endpoints {
        rpc: env("HK_WALLET_RPC").unwrap_or(d.rpc),
        faucet: env("HK_WALLET_FAUCET").unwrap_or(d.faucet),
        prover: env("HK_WALLET_PROVER").unwrap_or(d.prover),
        explorer: EXPLORER.into(),
    }
}

// ---------------------------------------------------------------------------
// Worker → UI events
// ---------------------------------------------------------------------------

enum Evt {
    /// (line, color, optional explorer link rendered as "view ↗")
    Log(String, egui::Color32, Option<String>),
    Busy(bool),
    /// One refresh: chain, fee policy, every balance.
    Status(Status),
    /// The asset list (native first) — read once per refresh.
    Assets(Vec<AssetInfo>),
    /// A scan of ONE asset's pool.
    Scan(ScanResult),
}

/// The core's progress lines land in ACTIVITY with the same colours as before.
struct Fwd(std::sync::Mutex<Sender<Evt>>);
impl Progress for Fwd {
    fn on_log(&self, level: String, line: String, link: Option<String>) {
        let color = match level.as_str() {
            "ok" => CYAN,
            "error" => RED,
            _ => DIM,
        };
        if let Ok(tx) = self.0.lock() {
            let _ = tx.send(Evt::Log(line, color, link));
        }
    }
}

fn log(tx: &Sender<Evt>, msg: impl Into<String>) {
    let _ = tx.send(Evt::Log(msg.into(), DIM, None));
}
fn log_err(tx: &Sender<Evt>, msg: impl Into<String>) {
    let _ = tx.send(Evt::Log(msg.into(), RED, None));
}

/// Every network job: busy on, the work, busy off. The core logs its own progress lines.
fn spawn<F: FnOnce() + Send + 'static>(tx: Sender<Evt>, job: F) {
    std::thread::spawn(move || {
        let _ = tx.send(Evt::Busy(true));
        job();
        let _ = tx.send(Evt::Busy(false));
    });
}

/// Refresh: balances in every asset + the asset list.
fn spawn_refresh(tx: Sender<Evt>, w: Arc<Wallet>) {
    spawn(tx.clone(), move || {
        match w.refresh() {
            Ok(s) => {
                let _ = tx.send(Evt::Status(s));
            }
            Err(e) => log_err(&tx, e.to_string()),
        }
        match w.assets() {
            Ok(a) => {
                let _ = tx.send(Evt::Assets(a));
            }
            Err(e) => log(&tx, format!("asset registry unavailable ({e}) — showing the native unit only")),
        }
    });
}

// ---------------------------------------------------------------------------
// The app
// ---------------------------------------------------------------------------

struct App {
    wallet: Arc<Wallet>,
    state: WalletState,
    status: Option<Status>,
    assets: Vec<AssetInfo>,
    /// Index into `assets` — what every balance/send/shield widget acts in.
    selected: usize,
    busy: bool,
    to_input: String,
    amount_input: String,
    restore_input: String,
    // shielded (of the selected asset)
    notes: Vec<NoteView>,
    notes_asset: String,
    stealth_addr: Option<String>,
    ots: Option<(u32, u32)>,
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
        let ep = endpoints_from_env();
        let prover_input = ep.prover.clone();
        let wallet = Wallet::new(wallet_dir().to_string_lossy().to_string(), Some(ep));
        wallet.set_listener(Box::new(Fwd(std::sync::Mutex::new(evt_tx.clone()))));
        // The optional key-file second factor (a file the backup does not carry).
        match hk_wallet::sealed::keyfile_from_env("HK_WALLET") {
            Ok(Some(bytes)) => {
                if let Err(e) = wallet.set_keyfile(Some(bytes)) {
                    let _ = evt_tx.send(Evt::Log(format!("HK_WALLET_KEYFILE ignored: {e}"), RED, None));
                }
            }
            Ok(None) => {}
            Err(e) => {
                let _ = evt_tx.send(Evt::Log(format!("HK_WALLET_KEYFILE: {e}"), RED, None));
            }
        }
        let state = wallet.state();
        let assets = vec![wallet.native_asset()];
        Self {
            wallet,
            state,
            status: None,
            assets,
            selected: 0,
            busy: false,
            to_input: String::new(),
            amount_input: String::new(),
            restore_input: String::new(),
            notes: Vec::new(),
            notes_asset: String::new(),
            stealth_addr: None,
            ots: None,
            shield_amount: String::new(),
            unshield_amount: String::new(),
            pay_to: String::new(),
            pay_amount: String::new(),
            pay_memo: String::new(),
            prover_input,
            log_lines: Vec::new(),
            evt_rx,
            evt_tx,
            booted: false,
            unlock_input: String::new(),
            pass_new: String::new(),
            pass_repeat: String::new(),
            generated: None,
        }
    }

    // ---- helpers ----------------------------------------------------------------------

    fn cur(&self) -> &AssetInfo {
        &self.assets[self.selected.min(self.assets.len().saturating_sub(1))]
    }

    fn cur_id(&self) -> String {
        self.cur().id.clone()
    }

    fn fmt(&self, base: u64) -> String {
        self.wallet.format_amount_dec(base, self.cur().decimals)
    }

    fn parse(&self, text: &str) -> Option<u64> {
        self.wallet.parse_amount_dec(text.to_string(), self.cur().decimals)
    }

    /// The transparent balance in the selected asset (None until the first refresh).
    fn balance(&self) -> Option<u64> {
        let s = self.status.as_ref()?;
        let id = self.cur_id();
        Some(s.balances.iter().find(|b| b.asset.id == id).map(|b| b.balance_micro).unwrap_or(0))
    }

    fn fee_now(&self) -> u64 {
        self.status.as_ref().map(|s| s.fee_micro).unwrap_or(0)
    }

    fn on_chain(&self) -> bool {
        self.status.as_ref().map(|s| s.on_chain).unwrap_or(false)
    }

    fn push_log(&mut self, line: String, color: egui::Color32) {
        self.log_lines.insert(0, (line, color, None));
        self.log_lines.truncate(80);
    }

    fn push_log_link(&mut self, line: String, color: egui::Color32, link: Option<String>) {
        self.log_lines.insert(0, (line, color, link));
        self.log_lines.truncate(80);
    }

    /// The prover field is live: the next shielded job uses whatever is in it.
    fn sync_prover(&self) {
        let mut ep = self.wallet.endpoints();
        let p = self.prover_input.trim().to_string();
        if !p.is_empty() && ep.prover != p {
            ep.prover = p;
            self.wallet.set_endpoints(ep);
        }
    }

    fn refresh(&self) {
        spawn_refresh(self.evt_tx.clone(), self.wallet.clone());
    }

    /// Cached notes of the selected asset — no network; called when the selection changes.
    fn load_cached_notes(&mut self) {
        let id = self.cur_id();
        match self.wallet.notes_asset(id.clone()) {
            Ok(n) => {
                self.notes = n;
                self.notes_asset = id;
            }
            Err(e) => self.push_log(format!("notes: {e}"), RED),
        }
    }

    // ---- K1: unlock / protect / unprotect --------------------------------------------

    fn unlock(&mut self) {
        let candidate = std::mem::take(&mut self.unlock_input);
        match self.wallet.unlock(candidate.trim().to_string()) {
            Ok(()) => {
                self.state = self.wallet.state();
                self.push_log("Wallet unlocked — the passphrase stays in memory for this session only.".into(), CYAN);
                self.load_cached_notes();
                self.refresh();
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
        if let Err(why) = self.wallet.passphrase_strength(a.clone()) {
            self.push_log(format!("Passphrase refused: {why}. Try Generate — 7 random words are easy to type and beyond any offline attack."), RED);
            return;
        }
        // Argon2id 512 MiB × 4 passes: about a second, once. Every save afterwards is instant.
        match self.wallet.protect(a) {
            Ok(n) => {
                self.pass_new.clear();
                self.pass_repeat.clear();
                self.generated = None;
                let kf = if std::env::var("HK_WALLET_KEYFILE").map(|v| !v.trim().is_empty()).unwrap_or(false) { " + your key file" } else { "" };
                self.push_log(format!("Protected: {n} file(s) sealed on disk (Argon2id 512 MiB → XChaCha20-Poly1305{kf}). Back up the passphrase — it cannot be recovered."), CYAN);
                self.state = self.wallet.state();
            }
            Err(e) => self.push_log(format!("Could not seal the wallet files — nothing changed: {e}"), RED),
        }
    }

    fn generate_passphrase(&mut self) {
        let p = self.wallet.generate_passphrase();
        self.pass_new = p.clone();
        self.pass_repeat = p.clone();
        self.generated = Some(p);
    }

    fn unprotect(&mut self) {
        match self.wallet.unprotect() {
            Ok(n) => {
                self.push_log(format!("Passphrase removed: {n} file(s) are plain JSON on disk again."), GOLD);
                self.state = self.wallet.state();
            }
            Err(e) => self.push_log(format!("Could not rewrite the wallet files — still protected: {e}"), RED),
        }
    }

    fn create_account(&mut self) {
        match self.wallet.create() {
            Ok(id) => {
                self.push_log("Wallet created. Your keys never leave this machine.".into(), CYAN);
                self.push_log(format!("Account id: {id}"), DIM);
                self.state = self.wallet.state();
                self.refresh();
            }
            Err(e) => self.push_log(format!("could not create the wallet: {e}"), RED),
        }
    }

    fn restore_account(&mut self) {
        match self.wallet.restore(self.restore_input.trim().to_string()) {
            Ok(_) => {
                self.push_log("Wallet restored — the chain's nonce is adopted automatically.".into(), CYAN);
                self.restore_input.clear();
                self.state = self.wallet.state();
                self.refresh();
            }
            Err(e) => self.push_log(format!("Restore refused: {e}"), RED),
        }
    }

    // ---- money (each on a worker; the core logs the outcome) ---------------------------

    fn faucet(&self, asset: Option<String>) {
        let w = self.wallet.clone();
        let tx = self.evt_tx.clone();
        spawn(tx.clone(), move || {
            let r = match asset {
                Some(a) => w.faucet_asset(a),
                None => w.faucet(),
            };
            match r {
                Ok(_) => spawn_refresh_inline(&tx, &w),
                Err(e) => log_err(&tx, e.to_string()),
            }
        });
    }

    fn send(&self, to: String, amount: u64) {
        let w = self.wallet.clone();
        let tx = self.evt_tx.clone();
        let a = self.cur().clone();
        spawn(tx.clone(), move || {
            let r = if a.is_native { w.send(to, amount) } else { w.send_asset(to, amount, a.id.clone()) };
            match r {
                Ok(_) => spawn_refresh_inline(&tx, &w),
                Err(e) => log_err(&tx, e.to_string()),
            }
        });
    }

    fn scan(&self) {
        self.sync_prover();
        let w = self.wallet.clone();
        let tx = self.evt_tx.clone();
        let a = self.cur().clone();
        spawn(tx.clone(), move || match w.scan_asset(a.id.clone()) {
            Ok(s) => {
                let _ = tx.send(Evt::Scan(s));
            }
            Err(e) => log_err(&tx, e.to_string()),
        });
    }

    fn shield(&self, amount: u64) {
        self.sync_prover();
        let w = self.wallet.clone();
        let tx = self.evt_tx.clone();
        let a = self.cur().clone();
        spawn(tx.clone(), move || {
            match w.shield_asset(amount, a.id.clone()) {
                Ok(_) => {}
                Err(e) => log_err(&tx, e.to_string()),
            }
            after_shielded(&tx, &w, &a.id);
        });
    }

    fn unshield(&self, amount: u64) {
        self.sync_prover();
        let w = self.wallet.clone();
        let tx = self.evt_tx.clone();
        let a = self.cur().clone();
        spawn(tx.clone(), move || {
            match w.unshield_asset(amount, a.id.clone()) {
                Ok(_) => {}
                Err(e) => log_err(&tx, e.to_string()),
            }
            after_shielded(&tx, &w, &a.id);
        });
    }

    fn pay(&self, to: String, amount: u64, memo: String) {
        self.sync_prover();
        let w = self.wallet.clone();
        let tx = self.evt_tx.clone();
        let a = self.cur().clone();
        spawn(tx.clone(), move || {
            match w.pay_shielded_asset(to, amount, memo, a.id.clone()) {
                Ok(_) => {}
                Err(e) => log_err(&tx, e.to_string()),
            }
            after_shielded(&tx, &w, &a.id);
        });
    }

    fn disclose(&self, commitment: String) {
        self.sync_prover();
        let w = self.wallet.clone();
        let tx = self.evt_tx.clone();
        let a = self.cur().clone();
        spawn(tx.clone(), move || {
            if let Err(e) = w.disclose_asset(commitment, a.id.clone()) {
                log_err(&tx, e.to_string());
            }
        });
    }
}

/// After a shielded operation: rescan that pool (spent flags, change note) and refresh balances.
fn after_shielded(tx: &Sender<Evt>, w: &Arc<Wallet>, asset: &str) {
    match w.scan_asset(asset.to_string()) {
        Ok(s) => {
            let _ = tx.send(Evt::Scan(s));
        }
        Err(e) => log_err(tx, format!("rescan: {e}")),
    }
    spawn_refresh_inline(tx, w);
}

/// A refresh on the CURRENT worker thread (after a drip / send), not a new one.
fn spawn_refresh_inline(tx: &Sender<Evt>, w: &Arc<Wallet>) {
    match w.refresh() {
        Ok(s) => {
            let _ = tx.send(Evt::Status(s));
        }
        Err(e) => log_err(tx, e.to_string()),
    }
    if let Ok(a) = w.assets() {
        let _ = tx.send(Evt::Assets(a));
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drain worker events.
        let mut reload_notes = false;
        while let Ok(evt) = self.evt_rx.try_recv() {
            match evt {
                Evt::Log(s, c, link) => self.push_log_link(s, c, link),
                Evt::Busy(b) => self.busy = b,
                Evt::Status(s) => self.status = Some(s),
                Evt::Assets(list) => {
                    // Keep the selection on the same asset id across registry reloads.
                    let keep = self.cur_id();
                    self.assets = if list.is_empty() { vec![self.wallet.native_asset()] } else { list };
                    self.selected = self.assets.iter().position(|a| a.id == keep).unwrap_or(0);
                }
                Evt::Scan(s) => {
                    if s.asset == self.cur_id() {
                        self.notes = s.notes;
                        self.notes_asset = s.asset;
                    }
                    self.stealth_addr = Some(s.stealth_address);
                    self.ots = Some((s.ots_used, s.ots_capacity));
                }
            }
        }
        // First frame: kick a refresh if a wallet exists and is readable.
        if !self.booted {
            self.booted = true;
            if self.state.account_id.is_some() {
                self.load_cached_notes();
                self.refresh();
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
                let net = self.status.as_ref().map(|s| s.chain_id.clone()).unwrap_or_else(|| "connecting…".into());
                ui.label(egui::RichText::new(format!("  wallet · {net}")).size(12.0).color(DIM));
            });
            ui.add_space(4.0);
            ui.separator();
            ui.add_space(8.0);

            if self.state.locked {
                // K1: a sealed wallet lives here — never offer to create one over it.
                ui.label(egui::RichText::new("This wallet is protected.").size(16.0));
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Enter the passphrase to unlock account.json / shield.json for this session.").color(DIM));
                if self.state.needs_keyfile {
                    ui.label(egui::RichText::new("This wallet also needs its key file: set HK_WALLET_KEYFILE to its path before starting the wallet.").color(GOLD).size(11.0));
                }
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
            match self.state.account_id.clone() {
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
                Some(acct_id) => {
                    // Identity
                    ui.label(egui::RichText::new("ACCOUNT").size(10.0).color(DIM));
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&acct_id).monospace().size(11.0).color(CYAN));
                    });
                    ui.horizontal(|ui| {
                        if ui.small_button("copy id").clicked() {
                            ui.output_mut(|o| o.copied_text = acct_id.clone());
                            self.push_log("Account id copied.".into(), DIM);
                        }
                        ui.hyperlink_to(egui::RichText::new("view on explorer ↗").size(11.0), format!("{EXPLORER}#account={acct_id}"));
                    });
                    ui.add_space(10.0);

                    // ---- P6.2: the asset dropdown ---------------------------------------
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("ASSET").size(10.0).color(DIM));
                        let before = self.selected;
                        let cur_label = {
                            let a = self.cur();
                            if a.is_native { format!("{} (test units)", a.symbol) } else { a.symbol.clone() }
                        };
                        egui::ComboBox::from_id_source("asset-picker").selected_text(cur_label).show_ui(ui, |ui| {
                            for (i, a) in self.assets.iter().enumerate() {
                                let label = if a.is_native {
                                    format!("{} — test units, pays the fee", a.symbol)
                                } else if a.pool_eligible {
                                    format!("{} — shieldable", a.symbol)
                                } else {
                                    a.symbol.clone()
                                };
                                ui.selectable_value(&mut self.selected, i, label);
                            }
                        });
                        if self.assets.len() == 1 {
                            ui.label(egui::RichText::new("(registry not read yet — ↻ Refresh)").size(10.0).color(DIM));
                        }
                        if self.selected != before {
                            reload_notes = true;
                            self.shield_amount.clear();
                            self.unshield_amount.clear();
                            self.pay_amount.clear();
                            self.amount_input.clear();
                        }
                    });
                    ui.add_space(6.0);

                    // Balance (of the selected asset)
                    let cur = self.cur().clone();
                    let bal_label = if cur.is_native { "BALANCE (test units — no monetary value)".to_string() } else { format!("BALANCE · {} (test asset — no monetary value)", cur.symbol) };
                    ui.label(egui::RichText::new(bal_label).size(10.0).color(DIM));
                    let bal_txt = match (self.balance(), self.status.as_ref().map(|s| s.on_chain)) {
                        (Some(b), Some(true)) => self.fmt(b),
                        (_, Some(false)) => "not on-chain yet".into(),
                        _ => "…".into(),
                    };
                    ui.label(egui::RichText::new(bal_txt).size(30.0).strong());
                    // U4: say what a transaction costs BEFORE the user finds out.
                    if let Some(s) = &self.status {
                        let native = self.wallet.native_asset();
                        let fee = self.wallet.format_amount(s.fee_micro);
                        let line = if s.fee_micro > 0 && cur.is_native {
                            format!("network fee {fee} per transaction (burned)")
                        } else if s.fee_micro > 0 {
                            format!("network fee {fee} {} per transaction — paid from your {} balance ({})", native.symbol, native.symbol, self.wallet.format_amount(s.balance_micro))
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
                            self.refresh();
                        }
                        if ui.add_enabled(enabled, egui::Button::new(egui::RichText::new(" Get test funds ").color(egui::Color32::BLACK)).fill(CYAN)).clicked() {
                            self.faucet(None);
                        }
                        if !cur.is_native {
                            let label = format!(" Get test {} ", cur.symbol);
                            if ui
                                .add_enabled(enabled, egui::Button::new(egui::RichText::new(label).color(egui::Color32::BLACK)).fill(GOLD))
                                .on_hover_text("a small drip of the test asset from the faucet — bridged in, never minted from nothing")
                                .clicked()
                            {
                                self.faucet(Some(cur.id.clone()));
                            }
                        }
                        if self.busy {
                            ui.spinner();
                        }
                    });
                    if !cur.is_native {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("or bring real Sepolia USDC across yourself:").size(10.0).color(DIM));
                            ui.hyperlink_to(egui::RichText::new("bridge ↗").size(10.0), BRIDGE_URL);
                        });
                    }

                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(6.0);

                    // Send
                    ui.label(egui::RichText::new(format!("SEND {}", cur.symbol)).size(10.0).color(DIM));
                    ui.label(egui::RichText::new("To (account id, 64 hex):").color(DIM).size(11.0));
                    ui.add(egui::TextEdit::singleline(&mut self.to_input).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY));
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Amount:").color(DIM).size(11.0));
                        ui.add(egui::TextEdit::singleline(&mut self.amount_input).desired_width(90.0));
                        // U4: "Max" = balance minus the fee the chain will charge now (native only —
                        // an issued asset's fee comes out of the native balance).
                        let fee_now = self.fee_now();
                        if let Some(b) = self.balance() {
                            if ui.small_button("max").on_hover_text(if cur.is_native { "balance minus the network fee" } else { "the whole balance (the fee is paid in test units)" }).clicked() {
                                self.amount_input = if cur.is_native { self.fmt(b.saturating_sub(fee_now)) } else { self.fmt(b) };
                            }
                        }
                        let parsed = self.parse(&self.amount_input);
                        if let Some(m) = parsed {
                            let p = if fee_now > 0 && cur.is_native { format!("= {m} base units + {fee_now} fee") } else { format!("= {m} base units") };
                            ui.label(egui::RichText::new(p).color(DIM).size(10.0));
                        }
                        let over = match (parsed, self.balance()) {
                            (Some(a), Some(b)) => if cur.is_native { a.saturating_add(fee_now) > b } else { a > b },
                            _ => false,
                        };
                        if over {
                            ui.label(egui::RichText::new(if cur.is_native { "exceeds balance + fee" } else { "exceeds balance" }).color(RED).size(10.0));
                        }
                        let to_ok = {
                            let t = self.to_input.trim().trim_start_matches("0x");
                            t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit())
                        };
                        let can_send = !self.busy && !over && parsed.map(|a| a > 0).unwrap_or(false) && to_ok;
                        if ui.add_enabled(can_send, egui::Button::new(" Send ")).clicked() {
                            if let Some(amount) = parsed {
                                self.send(self.to_input.trim().to_string(), amount);
                            }
                        }
                    });

                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(6.0);

                    // ---- SHIELDED (of the selected asset) --------------------------------
                    let shielded_total: u64 = self.notes.iter().filter(|n| !n.spent).map(|n| n.value_micro).sum();
                    let unspent_n = self.notes.iter().filter(|n| !n.spent).count();
                    // The title carries the live total, so the header needs a STABLE id —
                    // egui derives it from the title by default, and a changed title reads
                    // as a brand-new (collapsed) header after every operation (v0.13.0 bug).
                    egui::CollapsingHeader::new(
                        egui::RichText::new(format!("SHIELDED · {}  ·  {} in {unspent_n} note(s)", cur.symbol, self.fmt(shielded_total))).size(11.0),
                    )
                    .id_source("shielded-section")
                    .default_open(false)
                    .show(ui, |ui| {
                        let busy = self.busy;
                        let ready = self.on_chain() && !busy;
                        if cur.pool_eligible {
                            ui.label(
                                egui::RichText::new(format!(
                                    "Post-quantum shielded pool of {}: amounts and parties are hidden; proofs are made on the public prover \
                                     (each one takes a while). The network fee is paid from your test-unit balance.",
                                    cur.symbol
                                ))
                                .color(DIM)
                                .size(10.0),
                            );
                        } else {
                            ui.label(egui::RichText::new(format!("{} is not pool-eligible on this chain — it cannot be shielded.", cur.symbol)).color(GOLD).size(10.0));
                        }
                        let ready = ready && cur.pool_eligible;
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            if ui.add_enabled(ready, egui::Button::new("↻ Scan pool")).clicked() {
                                self.scan();
                            }
                            if let Some(a) = self.stealth_addr.clone() {
                                if ui.small_button("copy my stealth address").clicked() {
                                    ui.output_mut(|o| o.copied_text = a.clone());
                                    self.push_log("Stealth address copied — hand it to whoever pays you (it works for every asset).".into(), DIM);
                                }
                            }
                        });
                        if let Some(a) = &self.stealth_addr {
                            ui.label(egui::RichText::new(format!("{}…{}", &a[..22.min(a.len())], &a[a.len().saturating_sub(10)..])).monospace().size(10.0).color(CYAN));
                        }
                        // v0.13.1: the one-time spend-key budget is visible before it runs out.
                        if let Some((used, cap)) = self.ots {
                            let warn = used.saturating_mul(4) >= cap.saturating_mul(3);
                            ui.label(
                                egui::RichText::new(format!("one-time spend keys used: {used} / {cap} (shared by every asset){}", if warn { " — move shield.json aside and shield again soon (old notes stay spendable from the old file)" } else { "" }))
                                    .size(10.0)
                                    .color(if warn { GOLD } else { DIM }),
                            );
                        }

                        // Notes
                        if !self.notes.is_empty() {
                            ui.add_space(4.0);
                            let mut disclose: Option<String> = None;
                            egui::ScrollArea::vertical().max_height(90.0).auto_shrink([false, true]).show(ui, |ui| {
                                for n in &self.notes {
                                    ui.horizontal(|ui| {
                                        let tag = if n.spent { "SPENT" } else { "LIVE " };
                                        let col = if n.spent { DIM } else { CYAN };
                                        ui.label(egui::RichText::new(format!("{tag} {} {}", self.wallet.format_amount_dec(n.value_micro, cur.decimals), cur.symbol)).monospace().size(10.0).color(col));
                                        if !n.memo.is_empty() {
                                            ui.label(egui::RichText::new(format!("“{}”", n.memo)).size(10.0).color(DIM));
                                        }
                                        ui.label(egui::RichText::new(format!("#{} {}…", n.leaf_index, &n.commitment[..8.min(n.commitment.len())])).size(10.0).color(DIM));
                                        if ui.add_enabled(!busy, egui::Button::new(egui::RichText::new("disclose").size(10.0))).on_hover_text("write a one-time disclosure package for this payment").clicked() {
                                            disclose = Some(n.commitment.clone());
                                        }
                                    });
                                }
                            });
                            if let Some(cm) = disclose {
                                self.disclose(cm);
                            }
                        }

                        ui.add_space(6.0);
                        // Shield
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Shield").color(DIM).size(11.0));
                            ui.add(egui::TextEdit::singleline(&mut self.shield_amount).desired_width(80.0).hint_text("amount"));
                            let parsed = self.parse(&self.shield_amount);
                            let ok = ready && parsed.map(|a| a > 0).unwrap_or(false);
                            if ui.add_enabled(ok, egui::Button::new(" Shield → pool ")).clicked() {
                                if let Some(a) = parsed {
                                    self.shield(a);
                                }
                            }
                        });
                        // Unshield
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Unshield").color(DIM).size(11.0));
                            ui.add(egui::TextEdit::singleline(&mut self.unshield_amount).desired_width(80.0).hint_text("amount"));
                            let parsed = self.parse(&self.unshield_amount);
                            let ok = ready && unspent_n > 0 && parsed.map(|a| a > 0).unwrap_or(false);
                            if ui.add_enabled(ok, egui::Button::new(" Pool → me ")).clicked() {
                                if let Some(a) = parsed {
                                    self.unshield(a);
                                }
                            }
                        });
                        // Pay
                        ui.label(egui::RichText::new("Pay shielded to (hkaddr:…):").color(DIM).size(11.0));
                        ui.add(egui::TextEdit::singleline(&mut self.pay_to).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY));
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut self.pay_amount).desired_width(80.0).hint_text("amount"));
                            ui.add(egui::TextEdit::singleline(&mut self.pay_memo).desired_width(140.0).hint_text("memo (optional)"));
                            let parsed = self.parse(&self.pay_amount);
                            let addr_ok = {
                                let t = self.pay_to.trim();
                                t.starts_with("hkaddr:") && t.len() > 7 + 64 && t[7..].chars().all(|c| c.is_ascii_hexdigit())
                            };
                            let ok = ready && unspent_n > 0 && parsed.map(|a| a > 0).unwrap_or(false) && addr_ok;
                            if ui.add_enabled(ok, egui::Button::new(" Pay shielded ")).clicked() {
                                if let Some(a) = parsed {
                                    self.pay(self.pay_to.trim().to_string(), a, self.pay_memo.clone());
                                }
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Prover:").color(DIM).size(10.0));
                            ui.add(egui::TextEdit::singleline(&mut self.prover_input).desired_width(220.0).font(egui::TextStyle::Monospace));
                        });
                        ui.label(
                            egui::RichText::new(format!(
                                "⚠ shield.json (next to account.json) holds the shielded keys + one-time counters for EVERY asset — back it up too. {}",
                                wallet_dir().join("shield.json").display()
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
                                match self.wallet.export_seed() {
                                    Ok(seed) => {
                                        ui.output_mut(|o| o.copied_text = seed);
                                        self.push_log("Seed copied — treat it like the money it is.".into(), GOLD);
                                    }
                                    Err(e) => self.push_log(format!("seed: {e}"), RED),
                                }
                            }
                        });
                        if let Ok(auth0) = self.wallet.auth_commit() {
                            ui.label(egui::RichText::new(format!("Auth commit (for the web faucet): {auth0}")).monospace().size(10.0).color(DIM));
                        }
                        ui.label(egui::RichText::new(format!("Wallet file: {}", wallet_dir().join("account.json").display())).size(10.0).color(DIM));
                        ui.label(egui::RichText::new(format!("core {}", self.state.core_version)).size(10.0).color(DIM));
                    });

                    // K1 (v0.14.0): keys at rest.
                    ui.add_space(6.0);
                    let protected = self.state.protected;
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
                            ui.label(egui::RichText::new("Seal account.json and shield.json so a stolen backup or disk image is useless without the passphrase (Argon2id 512 MiB — about a second to unlock, then instant; a copied file allows only tens of guesses per second even on a GPU). The CLI and the Android app read the same format. There is NO recovery if you forget it — keep the seed backup too.").color(DIM).size(11.0));
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

        if reload_notes {
            self.load_cached_notes();
        }
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
            .with_inner_size([460.0, 700.0])
            .with_min_inner_size([420.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native("HashKinetics Wallet", options, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}
