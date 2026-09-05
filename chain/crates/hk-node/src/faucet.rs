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
//!   a global daily cap. X-Forwarded-For is honored ONLY from a loopback/private peer
//!   (the nginx in front of us) — a direct caller cannot forge its own address (H9).
//! - Cooldowns persist (`faucet-cooldowns.json` next to the wallet) and the map is
//!   bounded: a restart no longer hands everyone a fresh drip, and a scan of a
//!   million addresses no longer grows memory without limit (H9, v0.13.2).
//! - K3 (v0.16.0) hot/cold: the faucet account is a HOT wallet holding a small float;
//!   the treasury stays in a COLD account that tops it up by hand (docs/FAUCET-RUNBOOK.md).
//!   `/health` reports `low` (balance under `HK_FAUCET_LOW_MICRO`, default 50 drips) and
//!   `drips_left`; below `HK_FAUCET_RESERVE_MICRO` (default 2 drips) it refuses with 503
//!   instead of burning a ratchet index on a doomed transfer. Its `account.json` can be
//!   sealed (`hk-node account-seal DIR`; passphrase via `LoadCredential=hk-wallet-passphrase`).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
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
    println!("   listening on {} (put nginx in front; X-Forwarded-For honored)", cfg.listen);
    println!(
        "   K3 hot/cold: low watermark {} micro ({} drips) · reserve floor {} micro — top up from the cold account",
        cfg.low_micro,
        cfg.low_micro / cfg.drip.max(1),
        cfg.reserve_micro
    );
    if bal < cfg.low_micro {
        println!("   ⚠ LOW: balance {bal} micro is under the watermark — refill from the cold wallet");
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
        }
        respond(&mut stream, "200 OK", &h);
        return Ok(());
    }
    if !(method == "POST" && path.starts_with("/drip")) {
        respond(&mut stream, "404 Not Found", &json!({"error":"POST /drip or GET /health"}));
        return Ok(());
    }

    // ---- rate limits ------------------------------------------------------
    // H9: X-Forwarded-For is trusted only when the TCP peer is the local reverse
    // proxy; anyone reaching us directly is rated by the address they came from.
    let peer_ip = stream.peer_addr().ok().map(|a| a.ip());
    let peer_is_proxy = peer_ip.map(|ip| ip.is_loopback() || is_private(ip)).unwrap_or(false);
    let forwarded = text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("x-forwarded-for:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|v| v.split(',').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty());
    let ip = match (peer_is_proxy, forwarded) {
        (true, Some(f)) => f,
        _ => peer_ip.map(|a| a.to_string()).unwrap_or_else(|| "?".into()),
    };
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
    let body = text.splitn(2, "\r\n\r\n").nth(1).unwrap_or("");
    let v: Value = serde_json::from_str(body).unwrap_or(json!({}));
    let (payload, target_id) = if let Some(a) = v.get("auth_commit").and_then(|x| x.as_str()) {
        match parse_h256(a) {
            Ok(auth) => {
                let id = derived_id(&auth);
                if demo::account_nonce(&st.cfg.node_rpc, &id).is_some() {
                    // Already created — treat as a top-up.
                    (Tx::Transfer { to: id, asset: st.cfg.asset, amount: st.cfg.drip }, id)
                } else {
                    (
                        Tx::AccountCreate {
                            id,
                            auth_commit: auth,
                            asset: st.cfg.asset,
                            amount: st.cfg.drip,
                        },
                        id,
                    )
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
                (Tx::Transfer { to: id, asset: st.cfg.asset, amount: st.cfg.drip }, id)
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
        if bal < st.cfg.reserve_micro.saturating_add(st.cfg.drip) {
            undo_stamp(&st, &ip);
            eprintln!("⚠ faucet dry: balance {bal} micro < reserve {} + drip {} — refill from the cold wallet", st.cfg.reserve_micro, st.cfg.drip);
            respond(&mut stream, "503 Service Unavailable", &json!({"error":"faucet is being refilled — try again later", "faucet_balance_micro": bal}));
            return Ok(());
        }
        if bal < st.cfg.low_micro {
            eprintln!("⚠ faucet low: balance {bal} micro < watermark {} — refill from the cold wallet", st.cfg.low_micro);
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
                    "amount_micro": st.cfg.drip,
                    "txid": txid,
                    "note": "spendable now — your ratchet starts at nonce 0",
                }),
            );
            return Ok(());
        }
    }
    respond(&mut stream, "202 Accepted", &json!({
        "ok": true, "account": hex::encode(target_id.0), "txid": txid,
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
fn is_private(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
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
