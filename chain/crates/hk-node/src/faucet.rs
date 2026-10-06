//! U2 — the public faucet: the front door of the chain.
//!
//! A deliberately boring HTTP service (std-net, thread-per-connection — the same
//! hand-rolled minimalism as rpc.rs) that turns an auth commitment into a funded,
//! spendable on-chain account:
//!
//!   POST /drip  {"auth_commit":"<64 hex>"}   → AccountCreate (create + fund)
//!   POST /drip  {"account":"<64 hex>"}       → Transfer (top-up an existing id)
//!   GET  /health                              → faucet id + balance + drip size
//!
//! Design rules, each bought with an incident elsewhere in this repo:
//! - CORS by construction: every response carries `Access-Control-Allow-Origin: *`,
//!   and the site calls us with NO custom headers (a "simple request") — no
//!   preflight, because our RPC edge taught us OPTIONS goes unanswered at the worst
//!   moment. We still answer OPTIONS 204 defensively.
//! - Reserve-then-sign: the faucet wallet's nonce persists BEFORE submit; rollback
//!   (persisted) only on refusal — a crash can never re-sign a spent L-ratchet index.
//! - Rate limiting is the anti-spam floor alongside the U4 fee: per-IP cooldown +
//!   a global daily cap. X-Real-IP / X-Forwarded-For are honored ONLY from a loopback/private
//!   peer (the nginx in front of us) — a direct caller cannot forge its own address (H9).
//! - R17 L-4 (reported 2026-10-06, fixed the same day; precedence corrected by the review
//!   the same day): of a forwarded chain we key on the entry OUR proxy wrote — the
//!   RIGHTMOST `X-Forwarded-For` entry, else `X-Real-IP` — never
//!   the leftmost, which is whatever the client typed. Values are parsed as `IpAddr` (the old
//!   `split(':')` cut `2001:db8::1` down to `2001`), IPv6 is keyed on its /64, and an absent
//!   or unparseable header falls back to the peer address, never to a client string. The
//!   rule only holds if nginx OVERWRITES both headers (`proxy_set_header X-Real-IP
//!   $remote_addr; proxy_set_header X-Forwarded-For $remote_addr;`) — see `client_ip`.
//! - Cooldowns persist (`faucet-cooldowns.json` next to the wallet) and the map is
//!   bounded: a restart no longer hands everyone a fresh drip, and a scan of a
//!   million addresses no longer grows memory without limit (H9, v0.13.2).
//! - K3 (v0.16.0) hot/cold: the faucet account is a HOT wallet holding a small float;
//!   the treasury stays in a COLD account that tops it up by hand (docs/FAUCET-RUNBOOK.md).
//!   `/health` reports `low` (balance under `HK_FAUCET_LOW_MICRO`, default 50 drips) and
//!   `drips_left`; below `HK_FAUCET_RESERVE_MICRO` (default 2 drips) it refuses with 503
//!   instead of burning a ratchet index on a doomed transfer. Its `account.json` can be
//!   sealed (`hk-node account-seal DIR`; passphrase via `LoadCredential=hk-wallet-passphrase`).
//! - P6.2 (2026-09-13) ISSUED-ASSET DRIPS: `--drip-asset <64-hex>:<MICRO>` (repeatable) lets the
//!   same hot account drip an issued asset — `POST /drip {"account": …, "asset": "<hex>"}` is an
//!   ordinary `Transfer` of that asset (the account must already exist: the native drip creates
//!   it). The float is never minted here: for `USDC.sep` it is bridged in from Sepolia by a
//!   founder lock naming the faucet account, so `supply − burned == vault` stays true
//!   (docs/P6.2-WALLET-ASSETS.md §2). Cooldowns are per (address, asset) so a newcomer can take
//!   the native drip and the USDC drip back to back; `/health.assets[]` reports each float.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use hk_primitives::{Amount, H256};
use hk_state::tx::Tx;
use serde_json::{json, Value};

use crate::account::{derived_id, health_json, parse_h256, AccountFile};
use crate::demo::{self, Wallet};

pub(crate) struct FaucetCfg {
    pub wallet_dir: PathBuf,
    pub node_rpc: String,
    pub listen: String,
    pub drip: Amount,
    pub asset: H256,
    pub cooldown: Duration,
    pub daily_cap: u32,
    /// K3: `/health.low = balance < low_micro` — the refill signal for the cold wallet.
    pub low_micro: Amount,
    /// K3: below this the faucet answers 503 rather than sign a transfer that will fail.
    pub reserve_micro: Amount,
    /// P6.2: issued assets this faucet drips, `(asset id, drip in the asset's base units)`.
    pub drip_assets: Vec<(H256, Amount)>,
}

impl FaucetCfg {
    fn drip_of(&self, asset: &H256) -> Option<Amount> {
        if *asset == self.asset {
            return Some(self.drip);
        }
        self.drip_assets.iter().find(|(a, _)| a == asset).map(|(_, d)| *d)
    }
}

struct FaucetState {
    cfg: FaucetCfg,
    faucet_id: H256,
    /// (wallet, dir) under one lock: sign + persist are atomic w.r.t. other drips.
    signer: Mutex<(Wallet, AccountFile)>,
    /// ip → last successful drip (unix seconds; persisted, bounded).
    last_drip: Mutex<HashMap<String, u64>>,
    cooldown_path: PathBuf,
    /// (day-stamp, count) global cap.
    daily: Mutex<(u64, u32)>,
}

pub(crate) fn serve(cfg: FaucetCfg) -> eyre::Result<()> {
    let file = AccountFile::load(&cfg.wallet_dir)?;
    let id = file.id_h256()?;
    // Trust the chain's nonce at boot (same rule as account-send).
    let chain_nonce = demo::account_nonce(&cfg.node_rpc, &id).ok_or_else(|| {
        eyre::eyre!("faucet account {} not on-chain — create/fund it first", file.id)
    })?;
    let wallet = Wallet::from_seed(file.seed_bytes()?, id, chain_nonce);
    let bal = demo::balance(&cfg.node_rpc, &id);
    println!("🚰 faucet up: account {} · balance {bal} micro · drip {} micro", file.id, cfg.drip);
    println!(
        "   listening on {} (put nginx in front; rightmost X-Forwarded-For, else X-Real-IP, honored from a local peer — R17 L-4)",
        cfg.listen
    );
    println!(
        "   K3 hot/cold: low watermark {} micro ({} drips) · reserve floor {} micro — top up from the cold account",
        cfg.low_micro,
        cfg.low_micro / cfg.drip.max(1),
        cfg.reserve_micro
    );
    if bal < cfg.low_micro {
        println!("   ⚠ LOW: balance {bal} micro is under the watermark — refill from the cold wallet");
    }
    for (asset, drip) in &cfg.drip_assets {
        let b = demo::balance_of(&cfg.node_rpc, &id, asset);
        println!("   P6.2 asset drip: {}… · float {b} · drip {drip} · {} drips left", &hex::encode(asset.0)[..8], b / drip.max(&1));
        if b < *drip {
            println!("   ⚠ asset {}… float is EMPTY — bridge a float to the faucet account (P6.2 §2)", &hex::encode(asset.0)[..8]);
        }
    }

    let listener = TcpListener::bind(&cfg.listen)?;
    let cooldown_path = cfg.wallet_dir.join("faucet-cooldowns.json");
    let restored = load_cooldowns(&cooldown_path, cfg.cooldown);
    println!("   cooldowns restored: {} address(es) still inside the window", restored.len());
    let state = std::sync::Arc::new(FaucetState {
        faucet_id: id,
        signer: Mutex::new((wallet, file)),
        last_drip: Mutex::new(restored),
        cooldown_path,
        daily: Mutex::new((0, 0)),
        cfg,
    });
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let st = state.clone();
        std::thread::spawn(move || {
            let _ = handle(st, stream);
        });
    }
    Ok(())
}

fn respond(stream: &mut TcpStream, status: &str, body: &Value) {
    let body = body.to_string();
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: content-type\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
}

fn handle(st: std::sync::Arc<FaucetState>, mut stream: TcpStream) -> eyre::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = vec![0u8; 8192];
    let mut read = 0usize;
    // Read until we have headers + declared body (bounded).
    loop {
        let n = stream.read(&mut buf[read..])?;
        if n == 0 {
            break;
        }
        read += n;
        if read >= buf.len() {
            break;
        }
        let text = String::from_utf8_lossy(&buf[..read]);
        if let Some(hdr_end) = text.find("\r\n\r\n") {
            let cl = text
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if read >= hdr_end + 4 + cl {
                break;
            }
        }
    }
    let text = String::from_utf8_lossy(&buf[..read]).to_string();
    let first = text.lines().next().unwrap_or("");
    let (method, path) = {
        let mut it = first.split_whitespace();
        (it.next().unwrap_or(""), it.next().unwrap_or("/"))
    };

    if method == "OPTIONS" {
        respond(&mut stream, "204 No Content", &json!({}));
        return Ok(());
    }
    if method == "GET" && path.starts_with("/health") {
        let mut h = health_json(&st.cfg.node_rpc, &st.faucet_id, st.cfg.drip);
        // K3: the refill signal. `low` is what the site/alerts watch; `drips_left` is the
        // human number; `reserve_micro` is where drips stop.
        let bal: Amount = h
            .get("faucet_balance_micro")
            .and_then(|b| b.as_u64().map(|x| x as Amount).or_else(|| b.as_f64().map(|f| f as Amount)))
            .unwrap_or(0);
        if let Some(o) = h.as_object_mut() {
            o.insert("low".into(), json!(bal < st.cfg.low_micro));
            o.insert("low_watermark_micro".into(), json!(st.cfg.low_micro));
            o.insert("reserve_micro".into(), json!(st.cfg.reserve_micro));
            o.insert("drips_left".into(), json!(bal.saturating_sub(st.cfg.reserve_micro) / st.cfg.drip.max(1)));
            // P6.2: every issued-asset float this faucet serves.
            let assets: Vec<Value> = st
                .cfg
                .drip_assets
                .iter()
                .map(|(asset, drip)| {
                    let b = demo::balance_of(&st.cfg.node_rpc, &st.faucet_id, asset);
                    json!({
                        "asset": hex::encode(asset.0),
                        "balance_micro": b,
                        "drip_micro": drip,
                        "drips_left": b / drip.max(&1),
                        "low": b < drip.saturating_mul(10),
                    })
                })
                .collect();
            o.insert("assets".into(), json!(assets));
        }
        respond(&mut stream, "200 OK", &h);
        return Ok(());
    }
    if !(method == "POST" && path.starts_with("/drip")) {
        respond(&mut stream, "404 Not Found", &json!({"error":"POST /drip or GET /health"}));
        return Ok(());
    }

    // ---- rate limits ------------------------------------------------------
    // H9: forwarding headers are trusted only when the TCP peer is the local reverse
    // proxy; anyone reaching us directly is rated by the address they came from.
    // R17 L-4: WHICH forwarded entry, and how it is parsed, lives in `client_ip`; the
    // map key is the canonical form from `cooldown_key`. Only the header block is
    // searched — a JSON body cannot smuggle a header line in.
    let peer_ip = stream.peer_addr().ok().map(|a| a.ip());
    let head = text.split("\r\n\r\n").next().unwrap_or("");
    let ip = match client_ip(peer_ip, head) {
        Some(ip) => cooldown_key(ip),
        // peer_addr() failed on an accepted socket: nothing to key on, and nothing a
        // client can choose either. Pre-R17 behaviour, kept.
        None => "?".into(),
    };
    // ---- P6.2: which asset? ----------------------------------------------------------
    // Absent = the native drip (the only one that can CREATE an account). An issued asset must
    // be one this faucet serves. The cooldown is keyed per (address, asset) so the native drip
    // and the USDC drip of a newcomer do not block each other; the daily cap counts both.
    let body = text.splitn(2, "\r\n\r\n").nth(1).unwrap_or("");
    let v: Value = serde_json::from_str(body).unwrap_or(json!({}));
    let asset_req: Option<H256> = match v.get("asset").and_then(|a| a.as_str()) {
        Some(s) => match parse_h256(s) {
            Ok(a) => Some(a),
            Err(e) => {
                respond(&mut stream, "400 Bad Request", &json!({"error": format!("asset: {e}")}));
                return Ok(());
            }
        },
        None => None,
    };
    let (drip_asset, drip_amt) = match asset_req {
        Some(a) if a != st.cfg.asset => match st.cfg.drip_of(&a) {
            Some(d) => (a, d),
            None => {
                respond(&mut stream, "400 Bad Request", &json!({"error": "this faucet does not drip that asset", "asset": hex::encode(a.0)}));
                return Ok(());
            }
        },
        _ => (st.cfg.asset, st.cfg.drip),
    };
    let native_drip = drip_asset == st.cfg.asset;
    let ip = if native_drip { ip } else { format!("{ip}|{}", &hex::encode(drip_asset.0)[..8]) };
    {
        let now_secs = unix_now();
        let now_day = now_secs / 86_400;
        let mut daily = st.daily.lock().unwrap_or_else(|e| e.into_inner());
        if daily.0 != now_day {
            *daily = (now_day, 0);
        }
        if daily.1 >= st.cfg.daily_cap {
            respond(&mut stream, "429 Too Many Requests", &json!({"error":"faucet daily cap reached — try tomorrow"}));
            return Ok(());
        }
        let mut last = st.last_drip.lock().unwrap_or_else(|e| e.into_inner());
        let cooldown_secs = st.cfg.cooldown.as_secs();
        if let Some(t) = last.get(&ip) {
            let since = now_secs.saturating_sub(*t);
            if since < cooldown_secs {
                let wait = cooldown_secs - since;
                respond(&mut stream, "429 Too Many Requests", &json!({"error":"cooldown", "retry_after_secs": wait}));
                return Ok(());
            }
        }
        // H9: bounded map — drop expired entries whenever it gets large.
        if last.len() >= COOLDOWN_MAP_MAX {
            last.retain(|_, t| now_secs.saturating_sub(*t) < cooldown_secs);
        }
        // Optimistically stamp both (rolled back on failure below via re-lock).
        last.insert(ip.clone(), now_secs);
        daily.1 += 1;
        save_cooldowns(&st.cooldown_path, &last);
    }

    // ---- parse target -----------------------------------------------------
    let (payload, target_id) = if let Some(a) = v.get("auth_commit").and_then(|x| x.as_str()) {
        match parse_h256(a) {
            Ok(auth) => {
                let id = derived_id(&auth);
                if demo::account_nonce(&st.cfg.node_rpc, &id).is_some() {
                    // Already created — treat as a top-up (in whichever asset was asked for).
                    (Tx::Transfer { to: id, asset: drip_asset, amount: drip_amt }, id)
                } else if native_drip {
                    (
                        Tx::AccountCreate {
                            id,
                            auth_commit: auth,
                            asset: st.cfg.asset,
                            amount: st.cfg.drip,
                        },
                        id,
                    )
                } else {
                    // P6.2: an asset transfer cannot create an account.
                    undo_stamp(&st, &ip);
                    respond(&mut stream, "400 Bad Request", &json!({"error":"account does not exist yet — take the native drip first (it creates the account), then ask for the asset"}));
                    return Ok(());
                }
            }
            Err(e) => {
                undo_stamp(&st, &ip);
                respond(&mut stream, "400 Bad Request", &json!({"error": format!("auth_commit: {e}")}));
                return Ok(());
            }
        }
    } else if let Some(a) = v.get("account").and_then(|x| x.as_str()) {
        match parse_h256(a) {
            Ok(id) if demo::account_nonce(&st.cfg.node_rpc, &id).is_some() => {
                (Tx::Transfer { to: id, asset: drip_asset, amount: drip_amt }, id)
            }
            Ok(_) => {
                undo_stamp(&st, &ip);
                respond(&mut stream, "400 Bad Request", &json!({"error":"account does not exist — send your auth_commit instead so the faucet can create it"}));
                return Ok(());
            }
            Err(e) => {
                undo_stamp(&st, &ip);
                respond(&mut stream, "400 Bad Request", &json!({"error": format!("account: {e}")}));
                return Ok(());
            }
        }
    } else {
        undo_stamp(&st, &ip);
        respond(&mut stream, "400 Bad Request", &json!({"error":"body must be {\"auth_commit\":\"<64 hex>\"} or {\"account\":\"<64 hex>\"}"}));
        return Ok(());
    };

    // ---- K3: reserve floor — refuse instead of burning a ratchet index --------------
    {
        let bal = demo::balance(&st.cfg.node_rpc, &st.faucet_id);
        // The native balance pays every drip's fee; a native drip also spends the drip itself.
        let need = if native_drip { st.cfg.reserve_micro.saturating_add(st.cfg.drip) } else { st.cfg.reserve_micro };
        if bal < need {
            undo_stamp(&st, &ip);
            eprintln!("⚠ faucet dry: balance {bal} micro < reserve {} (+ drip {}) — refill from the cold wallet", st.cfg.reserve_micro, if native_drip { st.cfg.drip } else { 0 });
            respond(&mut stream, "503 Service Unavailable", &json!({"error":"faucet is being refilled — try again later", "faucet_balance_micro": bal}));
            return Ok(());
        }
        if bal < st.cfg.low_micro {
            eprintln!("⚠ faucet low: balance {bal} micro < watermark {} — refill from the cold wallet", st.cfg.low_micro);
        }
        if !native_drip {
            let float = demo::balance_of(&st.cfg.node_rpc, &st.faucet_id, &drip_asset);
            if float < drip_amt {
                undo_stamp(&st, &ip);
                eprintln!("⚠ asset {}… float {float} < drip {drip_amt} — bridge a float to the faucet account", &hex::encode(drip_asset.0)[..8]);
                respond(&mut stream, "503 Service Unavailable", &json!({"error":"the test-asset float is empty — try again later", "asset": hex::encode(drip_asset.0), "float_micro": float}));
                return Ok(());
            }
        }
    }

    // ---- sign (reserve-then-sign) + submit + receipt ----------------------
    let txid = {
        let mut g = st.signer.lock().unwrap_or_else(|e| e.into_inner());
        let (wallet, file) = &mut *g;
        let tx = wallet.sign(payload);
        file.next_nonce = wallet.next_nonce;
        if let Err(e) = file.save(&st.cfg.wallet_dir) {
            wallet.rollback();
            undo_stamp(&st, &ip);
            respond(&mut stream, "500 Internal Server Error", &json!({"error": format!("nonce persist failed: {e}")}));
            return Ok(());
        }
        let txid = demo::submit(&st.cfg.node_rpc, &tx);
        if txid.starts_with("submit-failed") {
            wallet.rollback();
            file.next_nonce = wallet.next_nonce;
            let _ = file.save(&st.cfg.wallet_dir);
            undo_stamp(&st, &ip);
            respond(&mut stream, "500 Internal Server Error", &json!({"error": txid}));
            return Ok(());
        }
        txid
    };
    for _ in 0..24 {
        std::thread::sleep(Duration::from_millis(700));
        if let Some(r) = demo::receipt(&st.cfg.node_rpc, &txid) {
            if r.starts_with("rejected") {
                let mut g = st.signer.lock().unwrap_or_else(|e| e.into_inner());
                let (wallet, file) = &mut *g;
                wallet.rollback();
                file.next_nonce = wallet.next_nonce;
                let _ = file.save(&st.cfg.wallet_dir);
                undo_stamp(&st, &ip);
                respond(&mut stream, "500 Internal Server Error", &json!({"error": r}));
                return Ok(());
            }
            respond(
                &mut stream,
                "200 OK",
                &json!({
                    "ok": true,
                    "account": hex::encode(target_id.0),
                    "amount_micro": drip_amt,
                    "asset": hex::encode(drip_asset.0),
                    "txid": txid,
                    "note": if native_drip { "spendable now — your ratchet starts at nonce 0" } else { "test asset landed — shield it from the wallet" },
                }),
            );
            return Ok(());
        }
    }
    respond(&mut stream, "202 Accepted", &json!({
        "ok": true, "account": hex::encode(target_id.0), "txid": txid, "asset": hex::encode(drip_asset.0),
        "note": "submitted; receipt pending — check the explorer",
    }));
    Ok(())
}

/// A refused/failed drip should not burn the caller's cooldown or the daily budget.
fn undo_stamp(st: &FaucetState, ip: &str) {
    {
        let mut last = st.last_drip.lock().unwrap_or_else(|e| e.into_inner());
        last.remove(ip);
        save_cooldowns(&st.cooldown_path, &last);
    }
    let mut daily = st.daily.lock().unwrap_or_else(|e| e.into_inner());
    daily.1 = daily.1.saturating_sub(1);
}

/// H9: never more than this many addresses in the cooldown map (expired ones are
/// pruned first; the window is 24 h, so this is far above any honest load).
const COOLDOWN_MAP_MAX: usize = 100_000;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// RFC 1918 / link-local / unique-local — "the proxy is on this box or this LAN".
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// R17 L-4 (reported 2026-10-06): the address a drip is rate-limited by.
///
/// Before R17 the key was the LEFTMOST `X-Forwarded-For` entry, cut at the first ':' of
/// the header LINE. Two defects: (1) nginx's `$proxy_add_x_forwarded_for` APPENDS the real
/// peer to whatever the client sent, so the leftmost entry is the client's own string — a
/// caller sending a fresh `X-Forwarded-For` per request never met the cooldown and only
/// the global daily cap (`--daily-cap`, default 200) stood between it and the float;
/// (2) `split(':').nth(1)` on the line turned `X-Forwarded-For: 2001:db8::1` into the key
/// "2001", folding every v6 caller with that first hextet into one bucket — one honest
/// drip locked out an entire provider's v6 range for the window.
///
/// Now, and only when the peer is the loopback/private proxy (the H9 gate, unchanged):
///   1. the RIGHTMOST entry of the LAST `X-Forwarded-For` line — the entry the trusted
///      proxy wrote, the only one a client cannot choose under EITHER standard nginx form
///      (`$proxy_add_x_forwarded_for` appends `$remote_addr`; `$remote_addr` leaves exactly
///      one);
///   2. else `X-Real-IP` — single-valued, written by nginx only where the vhost carries
///      `proxy_set_header X-Real-IP $remote_addr;`;
///   3. else the peer address itself.
/// Why XFF before X-Real-IP (R17 review, 2026-10-06 — the first cut of this fix read
/// X-Real-IP first): nginx forwards a client-supplied `X-Real-IP` UNTOUCHED unless the
/// vhost overrides it, and the gateway's faucet vhost is not in this repo. Its
/// X-Forwarded-For line is the one the faucet has relied on since H9 (v0.13.2); the
/// X-Real-IP line is the one still owed (`ops/ROLL-v0.19.6-R17-2026-10-06.md` §5). On a
/// vhost that sets only X-Forwarded-For, X-Real-IP-first handed the cooldown key back to
/// the client — through a header the pre-R17 code never read, i.e. a regression under the
/// one config the tree cannot rule out — while XFF-rightmost-first is never worse than
/// pre-R17 under either form. The reverse mistake (an X-Real-IP line but XFF passed
/// through) is what the runbook's `grep proxy_set_header` check exists to catch before
/// L-4 is called closed.
/// A header is used only if `IpAddr::from_str` accepts it: an absent, empty or garbage
/// value lands on the PROXY's own address, which collapses every proxied caller into one
/// cooldown. That is the strict failure (the faucet gets stingy, not open) and
/// `warn_proxy_header_once` names the nginx lines that fix it. A direct peer (public
/// address) is always keyed on itself; its headers are ignored.
///
/// The one thing this cannot defend: an nginx that passes the client's headers through
/// UNTOUCHED (no `proxy_set_header` for either name). Then the rightmost entry and
/// X-Real-IP are both the client's again — no worse than pre-R17, but the fix is only real
/// once the gateway's nginx site config (not in this repo) overwrites both headers.
fn client_ip(peer: Option<IpAddr>, head: &str) -> Option<IpAddr> {
    let peer_is_proxy = peer.map(|ip| ip.is_loopback() || is_private(ip)).unwrap_or(false);
    if !peer_is_proxy {
        return peer;
    }
    if let Some(ip) = header_value(head, "x-forwarded-for")
        .and_then(|v| v.rsplit(',').next())
        .and_then(parse_ip)
    {
        return Some(ip);
    }
    if let Some(ip) = header_value(head, "x-real-ip").and_then(parse_ip) {
        return Some(ip);
    }
    if let Some(p) = peer {
        warn_proxy_header_once(p);
    }
    peer
}

/// The LAST `name:` header line in `head` (name compared case-insensitively), split at
/// the FIRST ':' only and trimmed. HTTP treats repeated same-name lines as one
/// comma-joined value in order, so "last line" keeps the proxy-appended entry rightmost.
/// The pre-R17 `split(':').nth(1)` cut IPv6 values at their own first colon.
fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
        })
        .last()
}

/// `IpAddr::from_str` with the one tolerance a forwarded value needs: an IPv6 literal
/// written `[2001:db8::1]` (RFC 7239 style) is accepted. Anything else that fails to parse
/// — a port suffix, a hostname, a shell payload — is `None`, and the caller keys on the peer.
fn parse_ip(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    let s = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')).unwrap_or(s);
    IpAddr::from_str(s).ok()
}

/// Canonical cooldown-map key for an address. The map persists (`faucet-cooldowns.json`),
/// so the spelling matters across restarts and upgrades:
/// - IPv4: the dotted quad — byte-identical to the pre-R17 keys, so v4 cooldowns written
///   by v0.19.x survive the roll; an IPv4-mapped v6 (`::ffff:a.b.c.d`, what a dual-stack
///   listener reports for a v4 client) keys as that v4, one client = one key either way.
/// - IPv6: the /64 the address sits in, written `2001:db8:1:2::/64`. DECISION (R17): key on
///   the /64, not the address. A residential allocation is at least a /64 and SLAAC privacy
///   extensions rotate the low 64 bits at will, so a per-address key would hand a v6 caller
///   2^64 fresh identities per window; the /64 is the smallest unit a subscriber cannot
///   cheaply escape. Pre-R17 v6 keys ("2001"-style truncations) simply age out of the map.
fn cooldown_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let prefix = Ipv6Addr::from(u128::from(v6) & !((1u128 << 64) - 1));
                format!("{prefix}/64")
            }
        },
    }
}

static PROXY_HEADER_WARNED: AtomicBool = AtomicBool::new(false);

/// Once per process: a loopback/private peer POSTed /drip without a usable forwarding
/// header. If that peer is nginx, every proxied caller now shares ONE cooldown and the
/// site config is missing its `proxy_set_header` lines — say so, once, not per request.
fn warn_proxy_header_once(peer: IpAddr) {
    if !PROXY_HEADER_WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "⚠ faucet: local peer {peer} sent no parseable X-Real-IP / X-Forwarded-For — if that is nginx, every proxied caller shares one cooldown; add `proxy_set_header X-Real-IP $remote_addr;` and `proxy_set_header X-Forwarded-For $remote_addr;` to the site config (R17 L-4)"
        );
    }
}

/// Cooldowns on disk: `{ "<ip>": <unix secs>, ... }`. Entries outside the window are
/// dropped on load; a missing or corrupt file is an empty map (never fatal).
fn load_cooldowns(path: &std::path::Path, cooldown: Duration) -> HashMap<String, u64> {
    let Ok(bytes) = std::fs::read(path) else { return HashMap::new() };
    let Ok(map) = serde_json::from_slice::<HashMap<String, u64>>(&bytes) else { return HashMap::new() };
    let now = unix_now();
    map.into_iter().filter(|(_, t)| now.saturating_sub(*t) < cooldown.as_secs()).collect()
}

/// Best-effort atomic write (tmp + rename); a failure is logged, never fatal — the
/// in-memory map still protects the running process.
fn save_cooldowns(path: &std::path::Path, map: &HashMap<String, u64>) {
    let tmp = path.with_extension("json.tmp");
    let res = serde_json::to_vec(map)
        .map_err(|e| e.to_string())
        .and_then(|b| std::fs::write(&tmp, b).map_err(|e| e.to_string()))
        .and_then(|_| std::fs::rename(&tmp, path).map_err(|e| e.to_string()));
    if let Err(e) = res {
        eprintln!("faucet: could not persist cooldowns: {e}");
    }
}

#[cfg(test)]
mod r17_tests {
    //! R17 L-4 (reported 2026-10-06): the rate-limit key must be the address OUR proxy
    //! wrote, parsed as an address, and never a string the client chose.
    use super::{client_ip, cooldown_key, header_value};
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    /// The TCP peer as nginx on the same box presents it (the H9 gate opens).
    fn proxy() -> Option<IpAddr> {
        Some(ip("127.0.0.1"))
    }
    /// A request head as `handle` sees it: request line + header lines, CRLF, no body.
    fn head(lines: &[&str]) -> String {
        format!("POST /drip HTTP/1.1\r\nHost: faucet.hashkinetics.org\r\n{}\r\n", lines.join("\r\n"))
    }

    #[test]
    fn ipv4_xff_chain_keys_on_rightmost_entry() {
        // Client typed 203.0.113.9; nginx ($proxy_add_x_forwarded_for) appended the real peer.
        let h = head(&["X-Forwarded-For: 203.0.113.9, 198.51.100.7"]);
        assert_eq!(client_ip(proxy(), &h), Some(ip("198.51.100.7")));
        // Three hops, odd spacing: still the rightmost.
        let h = head(&["X-Forwarded-For:  203.0.113.9 ,10.0.0.1,   198.51.100.7  "]);
        assert_eq!(client_ip(proxy(), &h), Some(ip("198.51.100.7")));
        // Repeated header lines are one comma-joined value in order: the LAST line's
        // rightmost entry is the proxy's.
        let h = head(&["X-Forwarded-For: 203.0.113.9", "X-Forwarded-For: 203.0.113.10, 198.51.100.7"]);
        assert_eq!(client_ip(proxy(), &h), Some(ip("198.51.100.7")));
        // `proxy_set_header X-Forwarded-For $remote_addr` leaves exactly one entry.
        let h = head(&["x-forwarded-for:198.51.100.7"]);
        assert_eq!(client_ip(proxy(), &h), Some(ip("198.51.100.7")));
        assert_eq!(cooldown_key(ip("198.51.100.7")), "198.51.100.7");
    }

    #[test]
    fn xff_rightmost_wins_over_x_real_ip() {
        // The review case (2026-10-06): a vhost that sets only X-Forwarded-For passes a
        // client-typed X-Real-IP through untouched — it must never be the key.
        let h = head(&["X-Forwarded-For: 203.0.113.9, 198.51.100.7", "X-Real-IP: 192.0.2.44"]);
        assert_eq!(client_ip(proxy(), &h), Some(ip("198.51.100.7")));
        // Order of the two headers is irrelevant; the name match is case-insensitive.
        let h = head(&["x-real-ip: 192.0.2.44", "X-FORWARDED-FOR: 198.51.100.7"]);
        assert_eq!(client_ip(proxy(), &h), Some(ip("198.51.100.7")));
        // No XFF at all (a vhost that sets only X-Real-IP): X-Real-IP is the key.
        let h = head(&["X-Real-IP: 192.0.2.44"]);
        assert_eq!(client_ip(proxy(), &h), Some(ip("192.0.2.44")));
        // A garbage XFF rightmost does not poison the key: fall through to X-Real-IP.
        let h = head(&["X-Forwarded-For: 203.0.113.9, garbage", "X-Real-IP: 192.0.2.44"]);
        assert_eq!(client_ip(proxy(), &h), Some(ip("192.0.2.44")));
        // A garbage X-Real-IP beside a good XFF never matters.
        let h = head(&["X-Real-IP: not-an-ip", "X-Forwarded-For: 203.0.113.9, 198.51.100.7"]);
        assert_eq!(client_ip(proxy(), &h), Some(ip("198.51.100.7")));
    }

    #[test]
    fn ipv6_literal_round_trips() {
        // Pre-R17 this became the key "2001" (split on the line's first ':').
        let h = head(&["X-Forwarded-For: 2001:db8::1"]);
        assert_eq!(client_ip(proxy(), &h), Some(ip("2001:db8::1")));
        assert_eq!(header_value(&h, "x-forwarded-for"), Some("2001:db8::1"));
        // No space after the colon, mixed case, a v6 chain: the whole literal survives.
        let h = head(&["x-forwarded-for:2001:DB8::1, 2001:db8:1:2:3:4:5:6"]);
        assert_eq!(client_ip(proxy(), &h), Some(ip("2001:db8:1:2:3:4:5:6")));
        // X-Real-IP in RFC 7239 bracket style.
        let h = head(&["X-Real-IP: [2001:db8::1]"]);
        assert_eq!(client_ip(proxy(), &h), Some(ip("2001:db8::1")));
        // The key is the /64 (see `cooldown_key`): one subscriber, one bucket.
        assert_eq!(cooldown_key(ip("2001:db8::1")), "2001:db8::/64");
        assert_eq!(cooldown_key(ip("2001:db8:1:2:3:4:5:6")), "2001:db8:1:2::/64");
        assert_eq!(cooldown_key(ip("2001:db8::1")), cooldown_key(ip("2001:db8::ffff:ffff:ffff:ffff")));
        assert_ne!(cooldown_key(ip("2001:db8::1")), cooldown_key(ip("2001:db8:0:1::1")));
        // IPv4-mapped v6 (dual-stack listener) keys as the v4 — same client, same key.
        assert_eq!(cooldown_key(ip("::ffff:198.51.100.7")), "198.51.100.7");
    }

    #[test]
    fn garbage_header_falls_back_to_peer() {
        for h in [
            head(&["X-Forwarded-For: not-an-ip"]),
            head(&["X-Forwarded-For:"]),
            head(&["X-Forwarded-For: 203.0.113.9, garbage"]), // rightmost is junk: NOT the leftmost
            head(&["X-Forwarded-For: 198.51.100.7:4321"]),    // a port is not an address
            head(&["X-Forwarded-For: 2001"]),                 // the pre-R17 truncation, verbatim
            head(&["X-Real-IP: faucet.hashkinetics.org"]),
            head(&["X-Real-IP: $remote_addr"]), // an un-expanded nginx variable
            head(&["X-Real-IP:", "X-Forwarded-For: ,"]),
        ] {
            assert_eq!(client_ip(proxy(), &h), proxy(), "head: {h:?}");
        }
    }

    #[test]
    fn header_absent_keys_on_peer() {
        let h = head(&["Content-Type: application/json"]);
        assert_eq!(client_ip(proxy(), &h), proxy());
        assert_eq!(client_ip(Some(ip("10.0.0.5")), &h), Some(ip("10.0.0.5")));
        assert_eq!(client_ip(Some(ip("203.0.113.9")), &h), Some(ip("203.0.113.9")));
        // No peer address at all: nothing to key on, and no header can supply one.
        assert_eq!(client_ip(None, &head(&["X-Real-IP: 192.0.2.44"])), None);
        assert_eq!(client_ip(None, &h), None);
    }

    #[test]
    fn direct_public_peer_ignores_forwarding_headers() {
        // H9: a caller that reaches the socket directly is rated by its own address,
        // whatever it claims.
        let h = head(&["X-Real-IP: 192.0.2.44", "X-Forwarded-For: 203.0.113.9, 198.51.100.7"]);
        assert_eq!(client_ip(Some(ip("203.0.113.77")), &h), Some(ip("203.0.113.77")));
        assert_eq!(client_ip(Some(ip("2a02:c207:2355:1558::1")), &h), Some(ip("2a02:c207:2355:1558::1")));
        // Loopback, RFC 1918, ULA and link-local peers are "the proxy" and open the gate
        // (to the proxy-written XFF entry first).
        for p in ["::1", "10.42.7.9", "192.168.1.2", "172.16.0.3", "fd00:1::5", "fe80::1"] {
            assert_eq!(client_ip(Some(ip(p)), &h), Some(ip("198.51.100.7")), "peer {p}");
        }
    }

    #[test]
    fn header_value_splits_on_first_colon_only_and_ignores_the_body() {
        let h = head(&["Content-Length: 12"]) + "\r\n" + "x-real-ip: 192.0.2.44";
        // `handle` passes only the head; a header-shaped line in the body is never seen.
        let only_head = h.split("\r\n\r\n").next().unwrap();
        assert_eq!(header_value(only_head, "x-real-ip"), None);
        assert_eq!(header_value(only_head, "content-length"), Some("12"));
        assert_eq!(header_value("X-Real-IP: a:b:c", "x-real-ip"), Some("a:b:c"));
        assert_eq!(header_value("X-Real-IP-Extra: 1.2.3.4", "x-real-ip"), None);
        assert_eq!(header_value("no colon here", "x-real-ip"), None);
    }
}
