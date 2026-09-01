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
//!   hk_getAccount   {id}                      -> {found, nonce, auth_commit}
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
//!   hk_getValidators                           -> the live validator set + power
//!   hk_getMempool                              -> {count, txids[<=100]}
//!
//! PRIVACY NOTE: these endpoints expose only what consensus already made public —
//! the transparent skeleton. Shielded txs show commitments/nullifiers/fee, NEVER
//! amounts or parties. The explorer built on this is itself a privacy demo.
//!
//! All 32-byte ids are lowercase hex (64 chars).

use std::net::SocketAddr;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

use hk_primitives::H256;
use hk_state::tx::SignedTx;

use crate::batch::{txid, Batch};
use crate::state::SharedHandles;

pub async fn serve(addr: SocketAddr, h: SharedHandles) -> eyre::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "RPC listening");
    loop {
        let (mut sock, _peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(%e, "accept failed");
                continue;
            }
        };
        let h = h.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(&mut sock, &h).await {
                warn!(%e, "rpc conn error");
            }
        });
    }
}

/// C2.1: the shared admission gate for `hk_submitTx` AND `hk_gossipTxs`.
/// Lock order: chain BEFORE mempool (the commit path's order — no deadlocks).
/// WAL on success only: the WAL replays through this same gate at restart, so
/// what was never admissible is never persisted.
fn admit_one(h: &SharedHandles, tx: &SignedTx) -> Result<[u8; 32], String> {
    let admitted = {
        let chain = h.chain.lock().unwrap();
        let mut mp = h.mempool.lock().unwrap();
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

    let result = dispatch(method, &params, h);
    let status = if result.get("error").is_some() { 400 } else { 200 };
    respond(sock, status, &result).await
}

fn dispatch(method: &str, params: &Value, h: &SharedHandles) -> Value {
    match method {
        "hk_chainInfo" => {
            let (epoch, remaining) = *h.signer_gauge.lock().unwrap();
            let chain = h.chain.lock().unwrap();
            json!({"result": {
                "chain_id": h.chain_id,
                // Genesis-gate: the network's identity fingerprint (== `sha256sum
                // genesis.json`). A joiner confirms this matches before trusting a node.
                "genesis_digest": hex::encode(h.genesis_digest),
                "height": chain.height,
                "app_hash": hex::encode(chain.state_commitment().0),
                // R4: THIS node's consensus-signer leaf budget (the fuse, visible).
                "signer": {
                    "epoch": epoch,
                    "remaining": remaining,
                    "capacity": hk_crypto::hashsig::CONSENSUS_CAPACITY,
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
                            let mut q = h.foreign_rotations.lock().unwrap();
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
                let chain = h.chain.lock().unwrap();
                match chain.accounts.get(&id) {
                    Some(acc) => json!({"result": {
                        "found": true,
                        "nonce": acc.nonce,
                        "auth_commit": hex::encode(acc.auth_commit.0),
                    }}),
                    None => json!({"result": {"found": false}}),
                }
            }
            None => json!({"error": "id must be 64-char hex"}),
        },
        "hk_balance" => match (param_h256(params, "id"), param_h256(params, "asset")) {
            (Some(id), Some(asset)) => {
                let chain = h.chain.lock().unwrap();
                // AccountId/AssetId are aliases of H256 — pass the H256 values directly.
                json!({"result": {"amount": chain.balance(&id, &asset).to_string()}})
            }
            _ => json!({"error": "id and asset must be 64-char hex"}),
        },
        "hk_mandateAvailable" => match param_h256(params, "leaf") {
            Some(leaf) => {
                let chain = h.chain.lock().unwrap();
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
                let chain = h.chain.lock().unwrap();
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
                    let ids: Vec<String> = txs.iter().map(|t| hex::encode(txid(t))).collect();
                    h.bundles.lock().unwrap().push((txs, agg));
                    json!({"result": {"accepted": true, "txids": ids}})
                }
                (Err(e), _) => json!({"error": format!("bad txs: {e}")}),
                (_, Err(e)) => json!({"error": format!("bad agg_proof hex: {e}")}),
                _ => json!({"error": "txs (non-empty) and agg_proof required"}),
            }
        }
        "hk_getPoolInfo" => {
            let chain = h.chain.lock().unwrap();
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
            let notes = h.pool_notes.lock().unwrap();
            json!({"result": {
                "leaves": notes.iter().map(|(l, _)| hex::encode(l.0)).collect::<Vec<_>>(),
            }})
        }
        "hk_getPoolNotes" => {
            // For scanners: (leaf index, commitment, stealth payload).
            let notes = h.pool_notes.lock().unwrap();
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
                let rlog = h.receipts.lock().unwrap();
                match rlog.get(&id.0) {
                    Some(detail) => json!({"result": {"found": true, "detail": detail}}),
                    None => json!({"result": {"found": false}}),
                }
            }
            None => json!({"error": "txid must be 64-char hex"}),
        },

        // ---- P3.0b explorer surface ----
        "hk_nullifierSpent" => match param_h256(params, "nullifier") {
            // Wallets use this to tell spent notes from live ones (a nullifier reveals
            // nothing by itself — it is unlinkable to any commitment without nk).
            Some(nf) => {
                let chain = h.chain.lock().unwrap();
                json!({"result": {"spent": chain.pool.nullifiers.contains(&nf.0)}})
            }
            None => json!({"error": "nullifier must be 64-char hex"}),
        },
        "hk_getValidators" => {
            let vs = h.validators.lock().unwrap_or_else(|e| e.into_inner());
            json!({"result": {
                "count": vs.len(),
                "total_power": vs.total_voting_power(),
                "validators": vs.iter().map(|v| json!({
                    "address": v.address.to_string(),
                    "voting_power": v.voting_power,
                    "epoch": v.epoch,
                    "root_pk": hex::encode(&v.root_pk),
                })).collect::<Vec<_>>(),
            }})
        }
        "hk_getMempool" => {
            let mp = h.mempool.lock().unwrap();
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
                        let rlog = h.receipts.lock().unwrap();
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
                            "certificate": {
                                "round": sb.certificate.round.as_i64(),
                                "value_id": hex::encode(sb.certificate.value_id.as_bytes()),
                                "signatures": sb.certificate.commit_signatures.len(),
                            },
                        }})
                    }
                    Ok(None) => json!({"result": {"found": false}}),
                    Err(e) => json!({"error": format!("block load failed: {e}")}),
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
            let heights = match store.block_heights() {
                Ok(hs) => hs,
                Err(e) => return json!({"error": format!("block list failed: {e}")}),
            };
            let mut blocks = Vec::with_capacity(limit);
            for hgt in heights.iter().rev().filter(|hh| **hh < before).take(limit) {
                if let Ok(Some(sb)) = store.load_block(*hgt) {
                    let batch = Batch::decode(&sb.value_bytes);
                    blocks.push(json!({
                        "height": sb.height,
                        "time": h.chain_start_time + sb.height,
                        "tx_count": batch.as_ref().map(|b| b.txs.len()).unwrap_or(0),
                        "aggregate": batch.as_ref().map(|b| !b.agg_proof.is_empty()).unwrap_or(false),
                        "rotations": batch.as_ref().map(|b| b.rotations.len()).unwrap_or(0),
                        "value_id": hex::encode(&sb.certificate.value_id.as_bytes()[..8]),
                    }));
                }
            }
            json!({"result": {"blocks": blocks, "earliest": heights.first(), "latest": heights.last()}})
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
    };
    json!({
        "txid": hex::encode(txid(stx)),
        "sender": hex::encode(stx.sender.0),
        "nonce": stx.nonce,
        "kind": kind,
        "fields": fields,
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
