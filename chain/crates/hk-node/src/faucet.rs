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
//! - Rate limiting is the anti-spam floor until U4 fees land: per-IP cooldown +
//!   a global daily cap, honoring X-Forwarded-For (we sit behind nginx).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
}

struct FaucetState {
    cfg: FaucetCfg,
    faucet_id: H256,
    /// (wallet, dir) under one lock: sign + persist are atomic w.r.t. other drips.
    signer: Mutex<(Wallet, AccountFile)>,
    /// ip → last successful drip.
    last_drip: Mutex<HashMap<String, Instant>>,
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
    if bal < cfg.drip * 10 {
        println!("   ⚠ balance covers <10 drips — refill soon");
    }

    let listener = TcpListener::bind(&cfg.listen)?;
    let state = std::sync::Arc::new(FaucetState {
        faucet_id: id,
        signer: Mutex::new((wallet, file)),
        last_drip: Mutex::new(HashMap::new()),
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
        let h = health_json(&st.cfg.node_rpc, &st.faucet_id, st.cfg.drip);
        respond(&mut stream, "200 OK", &h);
        return Ok(());
    }
    if !(method == "POST" && path.starts_with("/drip")) {
        respond(&mut stream, "404 Not Found", &json!({"error":"POST /drip or GET /health"}));
        return Ok(());
    }

    // ---- rate limits ------------------------------------------------------
    let ip = text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("x-forwarded-for:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|v| v.split(',').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            stream.peer_addr().map(|a| a.ip().to_string()).unwrap_or_else(|_| "?".into())
        });
    {
        let day = Instant::now(); // day bucketing via elapsed on a fixed epoch below
        let _ = day;
        let now_day = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / 86_400;
        let mut daily = st.daily.lock().unwrap_or_else(|e| e.into_inner());
        if daily.0 != now_day {
            *daily = (now_day, 0);
        }
        if daily.1 >= st.cfg.daily_cap {
            respond(&mut stream, "429 Too Many Requests", &json!({"error":"faucet daily cap reached — try tomorrow"}));
            return Ok(());
        }
        let mut last = st.last_drip.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = last.get(&ip) {
            let since = t.elapsed();
            if since < st.cfg.cooldown {
                let wait = (st.cfg.cooldown - since).as_secs();
                respond(&mut stream, "429 Too Many Requests", &json!({"error":"cooldown", "retry_after_secs": wait}));
                return Ok(());
            }
        }
        // Optimistically stamp both (rolled back on failure below via re-lock).
        last.insert(ip.clone(), Instant::now());
        daily.1 += 1;
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
    st.last_drip.lock().unwrap_or_else(|e| e.into_inner()).remove(ip);
    let mut daily = st.daily.lock().unwrap_or_else(|e| e.into_inner());
    daily.1 = daily.1.saturating_sub(1);
}
