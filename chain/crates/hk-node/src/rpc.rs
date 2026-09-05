//! Minimal JSON-RPC-ish HTTP server (0.7) — zero extra deps, tokio only.
//!
//! POST any path with body `{"method":"...","params":{...}}` → `{"result":...}`
//! or `{"error":"..."}`. Agent-first surface; nothing EVM-shaped.
//!
//! Methods:
//!   hk_chainInfo                              -> {chain_id, height, app_hash,
//!                                                 signer: {epoch, remaining, capacity}}  (R4)
//!   hk_submitRotation {cert}                   -> {accepted, epoch, queued}  (R2: peer-carried
//!                                                 revival — cert from `hk-node issue-rotation`)
//!   hk_getAccount   {id}                      -> {found, nonce, auth_commit, balances[]}
//!   hk_getAsset     {asset | issuer+symbol}   -> {found, asset: {symbol, issuer, policy,
//!                                                 supply, burned, circulating, held, conserved,
//!                                                 paused, frozen_count}}            (X1)
//!   hk_getAssets                              -> {count, fee_asset, assets[]}      (X1)
//!   hk_balance      {id, asset}               -> {amount}            (u128 as string)
//!   hk_mandateAvailable {leaf, at?}           -> {available}         (string | null)
//!   hk_submitTx     {tx}                       -> {accepted, txid}
//!   hk_getReceipt   {txid}                     -> {found, detail}
//!   hk_getPoolInfo                             -> {version, asset?, root, latest_anchor,
//!                                                  next_index, nullifiers, total_shielded}
//!   hk_getPoolLeaves                           -> {leaves: [hex; ...]}  (wallet path rebuilds)
//!
//! P3.0b explorer surface (store-backed — reads the durable block log, no app locks):
//!   hk_getBlock     {height}                   -> full block: txs (public summaries) +
//!                                                 per-tx receipts + aggregate verdict + cert
//!   hk_getBlocks    {before?, limit?<=50}      -> newest-first block list
//!   hk_getValidators                           -> the live validator set + power (+ queued set changes)
//!   hk_getPeers                                -> this node's live p2p peer table (N1, v0.15.2):
//!                                                 {self, count, inbound, outbound, public_addr,
//!                                                  identified, islands_refused, peers[{peer_id,
//!                                                  direction, addr (masked /24 · /48), private_addr,
//!                                                  version, genesis, connected_secs}]}
//!   hk_submitSetChange {cert}                  -> {accepted, queued}  (V1: a seat admitted/removed
//!                                                 by a supermajority of the current seats' roots;
//!                                                 rides this node's next proposal)
//!   hk_getMempool                              -> {count, txids[<=100]}
//!
//! PRIVACY NOTE: these endpoints expose only what consensus already made public —
//! the transparent skeleton. Shielded txs show commitments/nullifiers/fee, NEVER
//! amounts or parties. The explorer built on this is itself a privacy demo.
//!
//! All 32-byte ids are lowercase hex (64 chars).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

use hk_primitives::H256;
use hk_state::tx::SignedTx;

use crate::batch::{txid, Batch};
use crate::state::SharedHandles;

/// H1 (v0.13.2): a request must arrive within this window, headers and body — a
/// half-open connection used to pin a task and up to 1 MiB of buffer forever.
const RPC_CONN_TIMEOUT: Duration = Duration::from_secs(10);
/// H1: at most this many connections are served concurrently; the rest get a fast
/// 503 instead of queueing behind a slowloris.
const RPC_MAX_CONNS: usize = 256;

pub async fn serve(addr: SocketAddr, h: SharedHandles) -> eyre::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, timeout_s = RPC_CONN_TIMEOUT.as_secs(), max_conns = RPC_MAX_CONNS, "RPC listening");
    let slots = Arc::new(tokio::sync::Semaphore::new(RPC_MAX_CONNS));
    loop {
        let (mut sock, _peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(%e, "accept failed");
                continue;
            }
        };
        let h = h.clone();
        let slots = slots.clone();
        tokio::spawn(async move {
            let Ok(_permit) = slots.try_acquire() else {
                let _ = respond(&mut sock, 503, &json!({"error":"rpc busy — try again"})).await;
                return;
            };
            match tokio::time::timeout(RPC_CONN_TIMEOUT, handle_conn(&mut sock, &h)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(%e, "rpc conn error"),
                Err(_) => {
                    let _ = respond(&mut sock, 408, &json!({"error":"request timed out"})).await;
                }
            }
        });
    }
}

/// H2 (v0.13.2): operator methods a web page must never be able to drive. A browser
/// always sends `Origin` on a cross-site POST; CORS only hides the RESPONSE, the
/// request still runs — so these are refused outright when an Origin is present.
/// Read methods and `hk_submitTx` stay browser-callable (the explorer, the site,
/// the wallet). Override for a deliberately browser-driven devnet: HK_RPC_ALLOW_BROWSER_OPS=1.
const OPERATOR_METHODS: &[&str] = &["hk_submitRotation", "hk_submitSetChange", "hk_gossipTxs", "hk_submitBundle"];

fn browser_ops_allowed() -> bool {
    std::env::var("HK_RPC_ALLOW_BROWSER_OPS").map(|v| v == "1").unwrap_or(false)
}

/// C2.1: the shared admission gate for `hk_submitTx` AND `hk_gossipTxs`.
/// Lock order: chain BEFORE mempool (the commit path's order — no deadlocks).
/// WAL on success only: the WAL replays through this same gate at restart, so
/// what was never admissible is never persisted.
fn admit_one(h: &SharedHandles, tx: &SignedTx) -> Result<[u8; 32], String> {
    let admitted = {
        let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut mp = h.mempool.lock().unwrap_or_else(|e| e.into_inner());
        mp.try_admit(tx.clone(), &chain)
    };
    match admitted {
        Ok(id) => {
            if let Some(store) = &h.store {
                if let Err(e) = store.wal_append(tx) {
                    warn!(%e, "mempool WAL append failed");
                }
            }
            Ok(id)
        }
        Err(e) => Err(e.as_str()),
    }
}

async fn handle_conn(sock: &mut tokio::net::TcpStream, h: &SharedHandles) -> eyre::Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];

    // Read until headers complete.
    let header_end = loop {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 1_048_576 {
            return respond(sock, 413, &json!({"error":"headers too large"})).await;
        }
    };

    let headers = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
    let content_len: usize = headers
        .split("\r\n")
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    // H1: the body cap is enforced before reading it, not after.
    if content_len > 8_388_608 {
        return respond(sock, 413, &json!({"error":"body too large"})).await;
    }
    // H2: a browser page is calling (cross-site POSTs always carry Origin).
    let from_browser = headers.split("\r\n").any(|l| l.starts_with("origin:"));

    while buf.len() < header_end + content_len {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 8_388_608 {
            return respond(sock, 413, &json!({"error":"body too large"})).await;
        }
    }

    let body = &buf[header_end..(header_end + content_len).min(buf.len())];
    let req: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return respond(sock, 400, &json!({"error": format!("bad json: {e}")})).await,
    };

    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    if from_browser && OPERATOR_METHODS.contains(&method) && !browser_ops_allowed() {
        warn!(method, "operator RPC method refused: called from a browser origin");
        return respond(sock, 403, &json!({"error": format!("{method} is an operator method and cannot be called from a browser page")})).await;
    }
    let result = dispatch(method, &params, h);
    let status = if result.get("error").is_some() { 400 } else { 200 };
    respond(sock, status, &result).await
}

/// H4/H5 (v0.13.2) bounds on unauthenticated ingress.
const BUNDLE_QUEUE_MAX: usize = 64;
const GOSSIP_MAX_TXS: usize = 1_024;

fn dispatch(method: &str, params: &Value, h: &SharedHandles) -> Value {
    match method {
        "hk_chainInfo" => {
            let (epoch, remaining) = *h.signer_gauge.lock().unwrap_or_else(|e| e.into_inner());
            let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
            json!({"result": {
                "chain_id": h.chain_id,
                // Genesis-gate: the network's identity fingerprint (== `sha256sum
                // genesis.json`). A joiner confirms this matches before trusting a node.
                "genesis_digest": hex::encode(h.genesis_digest),
                // N1 (v0.15.2): an operator can prove which binary answers, and how many
                // peers it holds (the full table is `hk_getPeers`).
                "node_version": crate::NODE_VERSION,
                "peers": malachitebft_network::hk_peers().len(),
                "height": chain.height,
                "app_hash": hex::encode(chain.state_commitment().0),
                // R4: THIS node's consensus-signer leaf budget (the fuse, visible).
                "signer": {
                    "epoch": epoch,
                    "remaining": remaining,
                    "capacity": hk_crypto::hashsig::CONSENSUS_CAPACITY,
                },
                // U4: the flat envelope fee — policy this node enforces + total burned.
                "fee": {
                    "micro": chain.fee_micro.to_string(),
                    "from_height": chain.fee_from,
                    "burned_micro": chain.fees_burned.to_string(),
                },
                // R10 v2: what this node serves to syncing peers from disk (gap-free
                // suffix floor; null until the first block lands) + its RAM window.
                "history": {
                    "disk_from": h.store.as_ref().map(|s| s.disk_min()).filter(|m| *m > 0),
                    "ram_window": crate::state::decided_window(),
                    "indexed_txs": h.tx_index.lock().unwrap_or_else(|e| e.into_inner()).len(),
                },
            }})
        }
        // R2: accept a root-signed RotationCert on behalf of ANOTHER validator (an
        // exhausted signer can't propose its own revival — peers carry it). Validated
        // against the live set here AND re-validated at propose + commit; the root
        // signature makes this trustless (nothing to spoof, replay is epoch-monotone).
        "hk_submitRotation" => match params.get("cert") {
            Some(c) => match serde_json::from_value::<hk_consensus::RotationCert>(c.clone()) {
                Ok(cert) => {
                    let check = { h.validators.lock().unwrap_or_else(|e| e.into_inner()).apply_rotation(&cert) };
                    match check {
                        Ok(_) => {
                            let mut q = h.foreign_rotations.lock().unwrap_or_else(|e| e.into_inner());
                            let dup = q
                                .iter()
                                .any(|x| x.root_pk == cert.root_pk && x.epoch >= cert.epoch);
                            if !dup {
                                q.retain(|x| {
                                    !(x.root_pk == cert.root_pk && x.epoch < cert.epoch)
                                });
                                q.push(cert.clone());
                            }
                            json!({"result": {"accepted": true, "epoch": cert.epoch,
                                "queued": !dup,
                                "note": "cert rides this node's next proposal"}})
                        }
                        Err(e) => json!({"result": {"accepted": false, "reason": e}}),
                    }
                }
                Err(e) => json!({"error": format!("bad cert: {e}")}),
            },
            None => json!({"error": "params.cert required (output of `hk-node issue-rotation`)"}),
        },
        "hk_getAccount" => match param_h256(params, "id") {
            Some(id) => {
                let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
                match chain.accounts.get(&id) {
                    Some(acc) => {
                        // X1: every transparent balance this account holds, by asset
                        // (a wallet must show two balances once issued assets exist).
                        let balances: Vec<Value> = chain
                            .balances
                            .range((id, H256([0u8; 32]))..=(id, H256([0xffu8; 32])))
                            .filter(|(_, amt)| **amt > 0)
                            .map(|((_, asset), amt)| json!({
                                "asset": hex::encode(asset.0),
                                "symbol": chain.assets.get(asset).map(|i| i.symbol.clone()),
                                "amount": amt.to_string(),
                                "frozen": chain.assets.get(asset).map(|i| i.frozen.contains(&id)).unwrap_or(false),
                            }))
                            .collect();
                        json!({"result": {
                            "found": true,
                            "nonce": acc.nonce,
                            "auth_commit": hex::encode(acc.auth_commit.0),
                            "balances": balances,
                        }})
                    }
                    None => json!({"result": {"found": false}}),
                }
            }
            None => json!({"error": "id must be 64-char hex"}),
        },
        // X1: the issued-asset registry. `asset` (hex) OR `issuer` + `symbol` (the id rule).
        "hk_getAsset" => {
            let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
            let id = match param_h256(params, "asset") {
                Some(a) => Some(a),
                None => match (param_h256(params, "issuer"), params.get("symbol").and_then(|v| v.as_str())) {
                    (Some(issuer), Some(sym)) => Some(hk_state::assets::derive_asset_id(&issuer, sym)),
                    _ => None,
                },
            };
            match id {
                Some(id) => match chain.assets.get(&id) {
                    Some(info) => json!({"result": {"found": true, "asset": asset_json(&id, info, &chain)}}),
                    None => json!({"result": {"found": false, "asset_id": hex::encode(id.0)}}),
                },
                None => json!({"error": "asset (64-char hex) or issuer (64-char hex) + symbol required"}),
            }
        }
        "hk_getAssets" => {
            let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
            let list: Vec<Value> = chain.assets.iter().map(|(id, info)| asset_json(id, info, &chain)).collect();
            json!({"result": {"count": list.len(), "fee_asset": hex::encode(chain.fee_asset.0), "assets": list}})
        }
        "hk_balance" => match (param_h256(params, "id"), param_h256(params, "asset")) {
            (Some(id), Some(asset)) => {
                let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
                // AccountId/AssetId are aliases of H256 — pass the H256 values directly.
                json!({"result": {"amount": chain.balance(&id, &asset).to_string()}})
            }
            _ => json!({"error": "id and asset must be 64-char hex"}),
        },
        "hk_mandateAvailable" => match param_h256(params, "leaf") {
            Some(leaf) => {
                let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
                let at = params.get("at").and_then(|v| v.as_u64()).unwrap_or(chain.time);
                match chain.mandates.available(&leaf, at) {
                    Ok(a) => json!({"result": {"available": a.to_string()}}),
                    Err(e) => json!({"result": {"available": null, "reason": e.to_string()}}),
                }
            }
            None => json!({"error": "leaf must be 64-char hex"}),
        },
        "hk_submitTx" => {
            let tx_val = params.get("tx").cloned().unwrap_or(Value::Null);
            match serde_json::from_value::<SignedTx>(tx_val) {
                Ok(tx) => match admit_one(h, &tx) {
                    Ok(id) => {
                        // C2.3: single-hop push to peers (local admissions only —
                        // gossip-received txs never re-forward, so no loops).
                        if let Some(g) = &h.gossip {
                            g.enqueue(tx);
                        }
                        json!({"result": {"accepted": true, "txid": hex::encode(id)}})
                    }
                    Err(reason) => {
                        json!({"result": {"accepted": false, "reason": reason}})
                    }
                },
                Err(e) => json!({"error": format!("bad tx: {e}")}),
            }
        }
        // C2.3: peer ingress. Same admission gate as hk_submitTx, but NEVER
        // re-forwarded (single-hop by construction). Duplicate/stale refusals here
        // are business as usual — most gossiped txs race their own origin copies.
        "hk_gossipTxs" => {
            let txs: Vec<SignedTx> = params
                .get("txs")
                .cloned()
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default();
            // H5 (v0.13.2): one gossip call carries at most a block's worth; a peer
            // that floods gets refused, not served. Duplicates are already refused by
            // the mempool's admission gate (the seen-set is the mempool itself).
            if txs.len() > GOSSIP_MAX_TXS {
                return json!({"error": format!("too many txs in one gossip call (max {GOSSIP_MAX_TXS})")});
            }
            let (mut admitted, mut dropped) = (0usize, 0usize);
            for tx in txs {
                match admit_one(h, &tx) {
                    Ok(_) => admitted += 1,
                    Err(_) => dropped += 1,
                }
            }
            json!({"result": {"admitted": admitted, "dropped": dropped}})
        }
        "hk_getChannel" => match param_h256(params, "id") {
            Some(id) => {
                let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
                match chain.channels.get(&id) {
                    Some(ch) => json!({"result": {
                        "found": true,
                        "payer": hex::encode(ch.state.payer.0),
                        "payee": hex::encode(ch.state.payee.0),
                        "asset": hex::encode(ch.state.asset.0),
                        "mandate": hex::encode(ch.state.mandate.0),
                        "tip": hex::encode(ch.state.tip.0),
                        "unit_price": ch.state.unit_price.to_string(),
                        "max_steps": ch.state.max_steps,
                        "highest_step_settled": ch.state.highest_step_settled,
                        "escrow_remaining": ch.escrow_remaining.to_string(),
                        "expiry": ch.state.expiry,
                        "refunded": ch.refunded,
                    }}),
                    None => json!({"result": {"found": false}}),
                }
            }
            None => json!({"error": "id must be 64-char hex"}),
        },
        "hk_submitBundle" => {
            // P2.3: proof-less pool txs + ONE aggregate STARK. The proposer includes the
            // bundle whole; every validator verifies the aggregate once at commit.
            let txs_val = params.get("txs").cloned().unwrap_or(Value::Null);
            let agg_hex = params.get("agg_proof").and_then(|p| p.as_str()).unwrap_or("");
            match (serde_json::from_value::<Vec<SignedTx>>(txs_val), hex::decode(agg_hex)) {
                (Ok(txs), Ok(agg)) if !txs.is_empty() && !agg.is_empty() => {
                    // H4 (v0.13.2): the queue is bounded and de-duplicated by the
                    // aggregate bytes — an unauthenticated push can no longer grow
                    // memory or block the proposer's head-of-line behind copies.
                    let mut q = h.bundles.lock().unwrap_or_else(|e| e.into_inner());
                    if q.len() >= BUNDLE_QUEUE_MAX {
                        return json!({"error": format!("bundle queue full (max {BUNDLE_QUEUE_MAX}) — retry after the next block")});
                    }
                    if q.iter().any(|(_, a)| *a == agg) {
                        return json!({"error": "duplicate bundle (same aggregate proof already queued)"});
                    }
                    let ids: Vec<String> = txs.iter().map(|t| hex::encode(txid(t))).collect();
                    q.push((txs, agg));
                    json!({"result": {"accepted": true, "txids": ids}})
                }
                (Err(e), _) => json!({"error": format!("bad txs: {e}")}),
                (_, Err(e)) => json!({"error": format!("bad agg_proof hex: {e}")}),
                _ => json!({"error": "txs (non-empty) and agg_proof required"}),
            }
        }
        "hk_getPoolInfo" => {
            let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
            let p = &chain.pool;
            json!({"result": {
                "version": p.version,
                "asset": p.asset.map(|a| hex::encode(a.0)),
                "root": hex::encode(p.tree.root()),
                "latest_anchor": p.latest_anchor().map(hex::encode),
                "next_index": p.tree.next_index(),
                "nullifiers": p.nullifiers.len(),
                "total_shielded": p.total_shielded.to_string(),
            }})
        }
        "hk_getPoolLeaves" => {
            let notes = h.pool_notes.lock().unwrap_or_else(|e| e.into_inner());
            json!({"result": {
                "leaves": notes.iter().map(|(l, _)| hex::encode(l.0)).collect::<Vec<_>>(),
            }})
        }
        "hk_getPoolNotes" => {
            // For scanners: (leaf index, commitment, stealth payload).
            let notes = h.pool_notes.lock().unwrap_or_else(|e| e.into_inner());
            json!({"result": {
                "notes": notes.iter().enumerate().map(|(i, (l, ct))| json!({
                    "index": i,
                    "commitment": hex::encode(l.0),
                    "stealth_ct": hex::encode(ct),
                })).collect::<Vec<_>>(),
            }})
        }
        "hk_getReceipt" => match param_h256(params, "txid") {
            Some(id) => {
                let rlog = h.receipts.lock().unwrap_or_else(|e| e.into_inner());
                match rlog.get(&id.0) {
                    Some(detail) => json!({"result": {"found": true, "detail": detail}}),
                    None => json!({"result": {"found": false}}),
                }
            }
            None => json!({"error": "txid must be 64-char hex"}),
        },

        // ---- v0.11.2 search surface (node-local indexes; see state.rs::index_txs) ----
        // A txid resolves to its block + full summary — the receipt ring may evict old
        // entries, but the index + block log answer forever.
        "hk_getTx" => match param_h256(params, "txid") {
            Some(id) => {
                let hit = h.tx_index.lock().unwrap_or_else(|e| e.into_inner()).get(&id.0).copied();
                match hit {
                    Some((height, idx)) => {
                        let summary = h
                            .store
                            .as_ref()
                            .and_then(|s| s.load_block(height).ok().flatten())
                            .and_then(|sb| crate::batch::Batch::decode(&sb.value_bytes))
                            .and_then(|b| b.txs.get(idx as usize).map(tx_summary));
                        let receipt = h
                            .receipts
                            .lock()
                            .unwrap()
                            .get(&id.0)
                            .cloned();
                        json!({"result": {
                            "found": true,
                            "txid": hex::encode(id.0),
                            "height": height,
                            "index": idx,
                            "summary": summary,
                            "receipt": receipt,
                        }})
                    }
                    None => json!({"result": {"found": false}}),
                }
            }
            None => json!({"error": "txid must be 64-char hex"}),
        },
        // An account's transaction history (sender or counterparty), newest first.
        "hk_getAccountTxs" => match param_h256(params, "id") {
            Some(id) => {
                let limit = params
                    .get("limit")
                    .and_then(|l| l.as_u64())
                    .unwrap_or(25)
                    .min(100) as usize;
                let ai = h.acct_index.lock().unwrap_or_else(|e| e.into_inner());
                let (total, txs): (usize, Vec<Value>) = match ai.get(&id) {
                    Some(v) => {
                        // R10 v2: the background history pass appends OLD heights
                        // after live commits already landed — order by height, not
                        // by insertion, so "newest first" stays true mid-pass.
                        let mut sorted: Vec<&([u8; 32], u64, &'static str)> = v.iter().collect();
                        sorted.sort_by(|a, b| b.1.cmp(&a.1));
                        (
                            v.len(),
                            sorted
                                .into_iter()
                                .take(limit)
                                .map(|(t, ht, kind)| {
                                    json!({"txid": hex::encode(t), "height": ht, "kind": kind})
                                })
                                .collect(),
                        )
                    }
                    None => (0, Vec::new()),
                };
                json!({"result": {"id": hex::encode(id.0), "total": total, "txs": txs}})
            }
            None => json!({"error": "id must be 64-char hex"}),
        },

        // ---- P3.0b explorer surface ----
        "hk_nullifierSpent" => match param_h256(params, "nullifier") {
            // Wallets use this to tell spent notes from live ones (a nullifier reveals
            // nothing by itself — it is unlinkable to any commitment without nk).
            Some(nf) => {
                let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
                json!({"result": {"spent": chain.pool.nullifiers.contains(&nf.0)}})
            }
            None => json!({"error": "nullifier must be 64-char hex"}),
        },
        "hk_getValidators" => {
            let vs = h.validators.lock().unwrap_or_else(|e| e.into_inner());
            let queued = h.pending_set_changes.lock().unwrap_or_else(|e| e.into_inner());
            json!({"result": {
                "count": vs.len(),
                "total_power": vs.total_voting_power(),
                "validators": vs.iter().map(|v| json!({
                    "address": v.address.to_string(),
                    "voting_power": v.voting_power,
                    "epoch": v.epoch,
                    "root_pk": hex::encode(&v.root_pk),
                })).collect::<Vec<_>>(),
                "pending_set_changes": queued.iter().map(|c| {
                    let change = match &c.body.change {
                        hk_consensus::SetChange::Admit { root_pk, voting_power, .. } =>
                            json!({"admit": hex::encode(root_pk), "voting_power": voting_power}),
                        hk_consensus::SetChange::Remove { root_pk } =>
                            json!({"remove": hex::encode(root_pk)}),
                    };
                    json!({
                        "change": change,
                        "not_before": c.body.not_before,
                        "not_after": c.body.not_after,
                        "approvals": c.approvals.len(),
                    })
                }).collect::<Vec<_>>(),
            }})
        }
        // N1 (v0.15.2): this node's live p2p peer table, straight from the swarm — who is
        // connected, which way, from where (masked), on which genesis and node version.
        // Measured, not configured: an entry exists only while a connection is open. The
        // gateway's table is the network's public roll call (every kit node bootstraps
        // through it); a node that peers only with other operators is not visible here.
        "hk_getPeers" => {
            let peers = malachitebft_network::hk_peers();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let (mut inbound, mut outbound, mut public_addr, mut identified) = (0usize, 0usize, 0usize, 0usize);
            let mut list = Vec::with_capacity(peers.len());
            for p in &peers {
                let (addr, private) = mask_multiaddr(&p.remote_addr);
                if p.direction == "inbound" { inbound += 1 } else { outbound += 1 }
                if !private { public_addr += 1 }
                if p.identified { identified += 1 }
                let genesis = match (p.identified, p.genesis) {
                    (false, _) => "pending",
                    (true, Some(g)) if g == h.genesis_digest => "match",
                    (true, Some(_)) => "mismatch",
                    (true, None) => "untagged",
                };
                list.push(json!({
                    "peer_id": p.peer_id,
                    "direction": p.direction,
                    "addr": addr,
                    "private_addr": private,
                    // null = a ≤ v0.15.1 node (genesis tag only) or identify not yet received
                    "version": p.node_version,
                    "genesis": genesis,
                    "identified": p.identified,
                    "connected_secs": now.saturating_sub(p.connected_at),
                    "connections": p.connections,
                }));
            }
            json!({"result": {
                "self": {
                    "peer_id": h.self_peer_id,
                    "version": crate::NODE_VERSION,
                    "genesis_digest": hex::encode(h.genesis_digest),
                },
                "count": peers.len(),
                "inbound": inbound,
                "outbound": outbound,
                "public_addr": public_addr,
                "identified": identified,
                "islands_refused": malachitebft_network::hk_islands_refused(),
                "peers": list,
                "note": "live from this node's swarm; addresses masked to /24 (v4) · /48 (v6) — a peer's real source address, not what it claims to listen on; private_addr = loopback/RFC 1918/CGNAT/ULA (the founding fleet peers over its private network)",
            }})
        }
        // V1: queue a validator-set change certificate. Checked against the live set
        // here (chain id, supermajority of CURRENT seats, window not yet closed) and
        // re-checked at propose + commit by every node; the root signatures make it
        // trustless to carry — anyone may relay a valid certificate.
        "hk_submitSetChange" => match params.get("cert") {
            Some(c) => match serde_json::from_value::<hk_consensus::SetChangeCert>(c.clone()) {
                Ok(cert) => {
                    let tip = h.chain.lock().unwrap_or_else(|e| e.into_inner()).height;
                    let check = {
                        let vs = h.validators.lock().unwrap_or_else(|e| e.into_inner());
                        cert.verify_against(&vs, &h.chain_id)
                    };
                    match check {
                        Ok(()) if cert.body.not_after < tip => json!({"result": {
                            "accepted": false,
                            "reason": format!("window closed: not_after {} < tip {tip}", cert.body.not_after)
                        }}),
                        Ok(()) => {
                            let mut q = h.pending_set_changes.lock().unwrap_or_else(|e| e.into_inner());
                            let dup = q.iter().any(|x| x.body == cert.body);
                            if !dup {
                                q.push(cert.clone());
                            }
                            json!({"result": {"accepted": true, "queued": !dup,
                                "approvals": cert.approvals.len(),
                                "window": [cert.body.not_before, cert.body.not_after],
                                "note": "cert rides this node's next proposal inside its window"}})
                        }
                        Err(e) => json!({"result": {"accepted": false, "reason": e}}),
                    }
                }
                Err(e) => json!({"error": format!("bad cert: {e}")}),
            },
            None => json!({"error": "params.cert required (output of `hk-node set-change assemble`)"}),
        },
        "hk_getMempool" => {
            let mp = h.mempool.lock().unwrap_or_else(|e| e.into_inner());
            json!({"result": {
                "count": mp.len(),
                "txids": mp.iter().take(100).map(|t| hex::encode(txid(t))).collect::<Vec<_>>(),
            }})
        }
        "hk_getBlock" => {
            let Some(store) = &h.store else {
                return json!({"error": "persistence disabled on this node (HK_NO_PERSIST)"});
            };
            match params.get("height").and_then(|v| v.as_u64()) {
                Some(height) => match store.load_block(height) {
                    Ok(Some(sb)) => {
                        let batch = Batch::decode(&sb.value_bytes);
                        let rlog = h.receipts.lock().unwrap_or_else(|e| e.into_inner());
                        let txs: Vec<Value> = batch
                            .as_ref()
                            .map(|b| {
                                b.txs
                                    .iter()
                                    .map(|stx| {
                                        let mut v = tx_summary(stx);
                                        let rec = rlog
                                            .get(&txid(stx))
                                            .map(|d| json!({
                                                "found": true,
                                                "ok": d.starts_with("ok"),
                                                "detail": d,
                                            }))
                                            .unwrap_or_else(|| json!({"found": false}));
                                        v["receipt"] = rec;
                                        v
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        json!({"result": {
                            "found": true,
                            "height": sb.height,
                            "time": h.chain_start_time + sb.height,
                            "parent_app_hash": batch.as_ref().map(|b| hex::encode(b.parent_app_hash)),
                            "tx_count": txs.len(),
                            "txs": txs,
                            "aggregate": {
                                "present": batch.as_ref().map(|b| !b.agg_proof.is_empty()).unwrap_or(false),
                                "verified": sb.agg_valid,
                            },
                            "rotations": batch.as_ref().map(|b| b.rotations.len()).unwrap_or(0),
                            // v0.15.2: validator-set change certificates carried by this block
                            // (V1) — the explorer surface could not show the block that seated
                            // testnet-1's first external validator (72219) until this existed.
                            "set_changes": batch.as_ref().map(|b| b.set_changes.iter().map(|c| {
                                let (kind, root_pk, power) = match &c.body.change {
                                    hk_consensus::SetChange::Admit { root_pk, voting_power, .. } =>
                                        ("admit", hex::encode(root_pk), Some(*voting_power)),
                                    hk_consensus::SetChange::Remove { root_pk } =>
                                        ("remove", hex::encode(root_pk), None),
                                };
                                json!({"change": kind, "root_pk": root_pk, "voting_power": power,
                                       "approvals": c.approvals.len(),
                                       "not_before": c.body.not_before, "not_after": c.body.not_after})
                            }).collect::<Vec<_>>()).unwrap_or_default(),
                            "certificate": {
                                "round": sb.certificate.round.as_i64(),
                                "value_id": hex::encode(sb.certificate.value_id.as_bytes()),
                                "signatures": sb.certificate.commit_signatures.len(),
                            },
                        }})
                    }
                    Ok(None) => json!({"result": {"found": false}}),
                    Err(e) => {
                        warn!(height, %e, "block load failed");
                        json!({"error": "block load failed (see node log)"})
                    }
                },
                None => json!({"error": "height (number) required"}),
            }
        }
        "hk_getBlocks" => {
            let Some(store) = &h.store else {
                return json!({"error": "persistence disabled on this node (HK_NO_PERSIST)"});
            };
            let before = params.get("before").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
            let limit = params
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(20)
                .min(50) as usize;
            // R10 v2: walk DOWN from the chain tip over the gap-free disk suffix —
            // no per-call directory listing (that was a 100k-entry scan on every
            // explorer poll). `earliest` is the suffix floor restore measured.
            let latest = h.chain.lock().unwrap_or_else(|e| e.into_inner()).height;
            let earliest = store.disk_min();
            let (earliest_v, latest_v) = if earliest == 0 || earliest > latest {
                (Value::Null, Value::Null)
            } else {
                (json!(earliest), json!(latest))
            };
            let mut blocks = Vec::with_capacity(limit);
            let mut hgt = before.saturating_sub(1).min(latest);
            let floor = earliest.max(1);
            while blocks.len() < limit && earliest != 0 && hgt >= floor {
                if let Ok(Some(sb)) = store.load_block(hgt) {
                    let batch = Batch::decode(&sb.value_bytes);
                    blocks.push(json!({
                        "height": sb.height,
                        "time": h.chain_start_time + sb.height,
                        "tx_count": batch.as_ref().map(|b| b.txs.len()).unwrap_or(0),
                        "aggregate": batch.as_ref().map(|b| !b.agg_proof.is_empty()).unwrap_or(false),
                        "rotations": batch.as_ref().map(|b| b.rotations.len()).unwrap_or(0),
                        "set_changes": batch.as_ref().map(|b| b.set_changes.len()).unwrap_or(0),
                        "value_id": hex::encode(&sb.certificate.value_id.as_bytes()[..8]),
                    }));
                }
                if hgt == 0 {
                    break;
                }
                hgt -= 1;
            }
            json!({"result": {"blocks": blocks, "earliest": earliest_v, "latest": latest_v}})
        }

        other => json!({"error": format!("unknown method: {other}")}),
    }
}

/// Public per-tx summary for the explorer: kind + the tx's PUBLIC fields only. What's
/// listed here is already on-chain in the clear (the transparent skeleton); shielded
/// txs surface commitments/nullifiers/fee — NEVER amounts, senders, or recipients.
fn tx_summary(stx: &SignedTx) -> Value {
    use hk_state::tx::Tx;
    let (kind, fields) = match &stx.payload {
        Tx::Transfer { to, asset, amount } => ("transfer", json!({
            "to": hex::encode(to.0), "asset": hex::encode(asset.0),
            "amount": amount.to_string(),
        })),
        Tx::MandateCreate { id, parent, holder, .. } => ("mandate_create", json!({
            "id": hex::encode(id.0),
            "parent": parent.map(|p| hex::encode(p.0)),
            "holder": hex::encode(holder.0),
        })),
        Tx::MandateSpend { leaf, to, amount } => ("mandate_spend", json!({
            "leaf": hex::encode(leaf.0), "to": hex::encode(to.0),
            "amount": amount.to_string(),
        })),
        Tx::MandateRevoke { target } => ("mandate_revoke", json!({
            "target": hex::encode(target.0),
        })),
        Tx::ChannelOpen { id, payee, unit_price, max_steps, .. } => ("channel_open", json!({
            "id": hex::encode(id.0), "payee": hex::encode(payee.0),
            "unit_price": unit_price.to_string(), "max_steps": max_steps,
        })),
        Tx::ChannelSettle { id, step, .. } => ("channel_settle", json!({
            "id": hex::encode(id.0), "step": step,
        })),
        Tx::ChannelRefund { id } => ("channel_refund", json!({
            "id": hex::encode(id.0),
        })),
        Tx::MintToPool { value, commitment, proof, .. } => ("shield", json!({
            "value": value.to_string(), "commitment": hex::encode(commitment.0),
            "via_aggregate": proof.is_empty(),
        })),
        Tx::ShieldedSpend { nullifier, fee, credit, mandate, proof, .. } => ("shielded_spend", json!({
            "nullifier": hex::encode(nullifier.0), "fee": fee.to_string(),
            "credit": credit.map(|c| hex::encode(c.0)),
            "mandate": mandate.map(|m| hex::encode(m.0)),
            "via_aggregate": proof.is_empty(),
        })),
        // U1: runtime account creation (the faucet flow) — visible in the explorer.
        Tx::AccountCreate { id, asset, amount, .. } => ("account_create", json!({
            "id": hex::encode(id.0), "asset": hex::encode(asset.0), "amount": amount.to_string(),
        })),
        // X1: issued assets — the five issuer verbs, all public by construction.
        Tx::AssetRegister { asset, symbol, decimals, policy } => ("asset_register", json!({
            "asset": hex::encode(asset.0), "symbol": symbol, "decimals": decimals,
            "policy": policy.flags(),
        })),
        Tx::AssetMint { asset, to, amount } => ("asset_mint", json!({
            "asset": hex::encode(asset.0), "to": hex::encode(to.0), "amount": amount.to_string(),
        })),
        Tx::AssetBurn { asset, amount, destination } => ("asset_burn", json!({
            "asset": hex::encode(asset.0), "amount": amount.to_string(),
            "destination": hex::encode(destination),
        })),
        Tx::AssetFreeze { asset, account, frozen } => ("asset_freeze", json!({
            "asset": hex::encode(asset.0), "account": hex::encode(account.0), "frozen": frozen,
        })),
        Tx::AssetPause { asset, paused } => ("asset_pause", json!({
            "asset": hex::encode(asset.0), "paused": paused,
        })),
    };
    json!({
        "txid": hex::encode(txid(stx)),
        "sender": hex::encode(stx.sender.0),
        "nonce": stx.nonce,
        "kind": kind,
        "fields": fields,
    })
}

/// X1: one registry entry as the explorer/wallet sees it, with the conservation
/// receipt (`held` must equal `issued` on every honest node — invariant I5').
fn asset_json(id: &H256, info: &hk_state::assets::AssetInfo, chain: &hk_state::State) -> Value {
    let (held, issued) = chain.asset_conservation(id).unwrap_or((0, 0));
    json!({
        "asset": hex::encode(id.0),
        "symbol": info.symbol,
        "decimals": info.decimals,
        "issuer": hex::encode(info.issuer.0),
        "policy": {
            "flags": info.policy.flags(),
            "mintable": info.policy.mintable,
            "freezable": info.policy.freezable,
            "pausable": info.policy.pausable,
            "pool_eligible": info.policy.pool_eligible,
        },
        "supply": info.supply.to_string(),
        "burned": info.burned.to_string(),
        "circulating": issued.to_string(),
        "held": held.to_string(),
        "conserved": held == issued,
        "paused": info.paused,
        "frozen_count": info.frozen.len(),
        "registered_at": info.registered_at,
    })
}

fn param_h256(params: &Value, key: &str) -> Option<H256> {
    let s = params.get(key)?.as_str()?;
    let bytes = hex::decode(s).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(H256(arr))
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

async fn respond(sock: &mut tokio::net::TcpStream, status: u16, body: &Value) -> eyre::Result<()> {
    let payload = serde_json::to_vec(body)?;
    let reason = if status == 200 { "OK" } else { "ERR" };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        payload.len()
    );
    sock.write_all(head.as_bytes()).await?;
    sock.write_all(&payload).await?;
    sock.flush().await?;
    Ok(())
}

/// N1 (v0.15.2): mask a multiaddr's host for public display — IPv4 to its /24, IPv6 to
/// its /48 (a v4-mapped v6 address is masked like v4), DNS names kept as they are.
/// Returns `(masked, is_private)`; private = loopback, unspecified, RFC 1918, CGNAT
/// (100.64/10), link-local, or a v6 ULA — i.e. a peer on the same private network.
pub(crate) fn mask_multiaddr(addr: &str) -> (String, bool) {
    let parts: Vec<&str> = addr.split('/').collect();
    let mut out: Vec<String> = Vec::with_capacity(parts.len());
    let mut private = false;
    let mut i = 0;
    while i < parts.len() {
        let p = parts[i];
        if (p == "ip4" || p == "ip6") && i + 1 < parts.len() {
            let (masked, prv) = mask_host(p, parts[i + 1]);
            private |= prv;
            out.push(p.to_string());
            out.push(masked);
            i += 2;
        } else {
            out.push(p.to_string());
            i += 1;
        }
    }
    (out.join("/"), private)
}

fn mask_v4(ip: std::net::Ipv4Addr) -> (String, bool) {
    let o = ip.octets();
    let private = ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_private()
        || ip.is_link_local()
        || (o[0] == 100 && (o[1] & 0xc0) == 64);
    (format!("{}.{}.{}.0", o[0], o[1], o[2]), private)
}

fn mask_host(proto: &str, host: &str) -> (String, bool) {
    if proto == "ip4" {
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            return mask_v4(ip);
        }
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        if let Some(v4) = ip.to_ipv4_mapped() {
            let (m, prv) = mask_v4(v4);
            return (format!("::ffff:{m}"), prv);
        }
        let s = ip.segments();
        let private = ip.is_loopback()
            || ip.is_unspecified()
            || (s[0] & 0xfe00) == 0xfc00
            || (s[0] & 0xffc0) == 0xfe80;
        return (format!("{:x}:{:x}:{:x}::", s[0], s[1], s[2]), private);
    }
    (host.to_string(), false)
}

#[cfg(test)]
mod n1_tests {
    use super::mask_multiaddr;

    #[test]
    fn masks_public_and_private_hosts() {
        assert_eq!(mask_multiaddr("/ip4/203.0.113.77/tcp/27000"), ("/ip4/203.0.113.0/tcp/27000".into(), false));
        assert_eq!(mask_multiaddr("/ip4/10.128.0.9/tcp/27000"), ("/ip4/10.128.0.0/tcp/27000".into(), true));
        assert_eq!(mask_multiaddr("/ip4/127.0.0.1/tcp/27001"), ("/ip4/127.0.0.0/tcp/27001".into(), true));
        assert_eq!(mask_multiaddr("/ip4/100.64.3.4/tcp/1"), ("/ip4/100.64.3.0/tcp/1".into(), true));
        assert_eq!(mask_multiaddr("/ip4/100.128.3.4/tcp/1"), ("/ip4/100.128.3.0/tcp/1".into(), false));
        assert_eq!(
            mask_multiaddr("/ip6/2a02:c207:2355:1558::1/tcp/27000"),
            ("/ip6/2a02:c207:2355::/tcp/27000".into(), false)
        );
        assert_eq!(mask_multiaddr("/ip6/fd00:1::5/tcp/27000"), ("/ip6/fd00:1:0::/tcp/27000".into(), true));
        assert_eq!(mask_multiaddr("/ip6/::1/tcp/27000"), ("/ip6/0:0:0::/tcp/27000".into(), true));
        assert_eq!(
            mask_multiaddr("/ip6/::ffff:203.0.113.9/tcp/27000"),
            ("/ip6/::ffff:203.0.113.0/tcp/27000".into(), false)
        );
        assert_eq!(
            mask_multiaddr("/dns4/seed.hashkinetics.org/tcp/27000"),
            ("/dns4/seed.hashkinetics.org/tcp/27000".into(), false)
        );
        // garbage stays garbage, never panics
        assert_eq!(mask_multiaddr("/ip4/not-an-ip/tcp/1"), ("/ip4/not-an-ip/tcp/1".into(), false));
        assert_eq!(mask_multiaddr(""), ("".into(), false));
    }

    #[test]
    fn peer_agent_tags_parse_both_generations() {
        use malachitebft_network::{hk_peer_genesis_digest, hk_peer_node_version};
        let digest = "4e4ea68d48cba1ad4cc7155c19e7768f1fa2cbc99ba0f2b47c58948ec9e971c7";
        let old = format!("hashkinetics/1/genesis/{digest}");
        let new = format!("hashkinetics/1/genesis/{digest}/hk-node/v0.15.2");
        let want = hex::decode(digest).unwrap();
        assert_eq!(hk_peer_genesis_digest(&old).unwrap().to_vec(), want);
        assert_eq!(hk_peer_genesis_digest(&new).unwrap().to_vec(), want);
        assert_eq!(hk_peer_node_version(&old), None);
        assert_eq!(hk_peer_node_version(&new).as_deref(), Some("v0.15.2"));
        // not a tag / wrong length / junk after the digest / non-ASCII boundaries: never gate, never panic
        assert_eq!(hk_peer_genesis_digest("hashkinetics/1"), None);
        assert_eq!(hk_peer_genesis_digest(&format!("hashkinetics/1/genesis/{}", &digest[..63])), None);
        assert_eq!(hk_peer_genesis_digest(&format!("hashkinetics/1/genesis/{digest}x")), None);
        assert_eq!(hk_peer_genesis_digest("hashkinetics/1/genesis/ééééééééééééééééééééééééééééééééé"), None);
        assert_eq!(hk_peer_node_version(&format!("hashkinetics/1/genesis/{digest}/hk-node/")), None);
        assert_eq!(hk_peer_node_version(&format!("hashkinetics/1/genesis/{digest}/hk-node/v0.15.2 <script>")), None);
    }
}
