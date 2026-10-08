//! Minimal JSON-RPC-ish HTTP server (0.7) — zero extra deps, tokio only.
//!
//! POST any path with body `{"method":"...","params":{...}}` → `{"result":...}`
//! or `{"error":"..."}`. Agent-first surface; nothing EVM-shaped.
//!
//! Methods:
//!   hk_chainInfo                              -> {chain_id, height, app_hash,
//!                                                 signer: {epoch, remaining, capacity},  (R4)
//!                                                 process: {rss_bytes, uptime_secs,
//!                                                           verifier_init_ms,   (R11, v0.17.0)
//!                                                           disk_free_bytes},   (v0.19.4: free
//!                                                 bytes on the block log's filesystem; null off-Unix)
//!                                                 activations: {mandate_asset_from,   (R17, v0.19.6:
//!                                                               rotation_v2_from,     the heights THIS
//!                                                               payword_cap_from}}    node will switch rules at — null = never; the roll
//!                                                 call reads them off every seat before a height is named;
//!                                                 payword_cap_from = R18, 2026-10-08: the PayWord caps)
//!   hk_submitRotation {cert}                   -> {accepted, epoch, queued}  (R2: peer-carried
//!                                                 revival — cert from `hk-node issue-rotation`;
//!                                                 L-2: judged by the rule at tip + 1 — domain +
//!                                                 valid_from_height window — exactly as commit will)
//!   hk_getAccount   {id}                      -> {found, nonce, auth_commit, balances[]}
//!   hk_getAsset     {asset | issuer+symbol}   -> {found, asset: {symbol, issuer, policy,
//!                                                 supply, burned, circulating, held, conserved,
//!                                                 paused, frozen_count}}            (X1)
//!   hk_getAssets                              -> {count, fee_asset, assets[]}      (X1)
//!   hk_balance      {id, asset}               -> {amount}            (u128 as string)
//!   hk_mandateAvailable {leaf, at?}           -> {available}         (string | null)
//!   hk_submitTx     {tx}                       -> {accepted, txid}
//!   hk_getReceipt   {txid}                     -> {found, detail}
//!   hk_getPoolInfo  {asset?}                   -> {legacy, version, asset?, root, latest_anchor,
//!                                                  next_index, nullifiers, total_shielded}
//!                                                 (P6: `asset` = that asset's pool; absent = legacy)
//!   hk_getPools                                -> {count, multi_pool_from, pools: [hk_getPoolInfo…]}  (P6)
//!   hk_getPoolLeaves {asset?, from?, limit?<=10000} -> {asset, leaves: [hex; ...], from, count, total, next}  (H3: paged)
//!   hk_getPoolNotes  {asset?, from?, limit?<=10000} -> {asset, notes: [{index, commitment, stealth_ct}], from,
//!                                                 count, total, next}   (H3, v0.16.1: paged — `next`
//!                                                 is the wallet's scan cursor; null = end)
//!   hk_getPoolPath   {asset?, index}           -> {asset, index, commitment, siblings[TREE_DEPTH], root, total}
//!                                                 (H3: one authentication path; spenders no longer
//!                                                 download every commitment)
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
//!                                                  version, genesis, connected_secs, last_connection_secs, reconnects}]}
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
//!
//! R17 (reported 2026-10-06; L-5 + L-6 — client-side only, no consensus impact, no gate):
//!   * L-5: the pool feed is paged UNDER its lock and only the page leaves the lock
//!     (`with_pool_feed`). v0.16.1 (H3) paged this way; the P6 refactor (v0.19.0) cloned
//!     the ENTIRE feed — stealth ciphertexts included — per call, and the commit path takes
//!     the same lock while holding the chain lock, so one scanner on a big pool stalled
//!     commit on every node it polled. `hk_getPoolPath` now copies the 32-byte leaves only,
//!     and (R17 review, 2026-10-06) at most `POOL_PATH_SLOTS` of those full-leaf copies +
//!     O(n) tree builds run at once — past that, "busy — retry", the feed lock untouched.
//!     Response shapes are unchanged byte for byte.
//!   * L-6: `hk_submitRotation` / `hk_submitSetChange` are unauthenticated (Origin check
//!     only) with no per-IP limit, and ran the ≈1.7 ms SLH-DSA-192s verify (a 16,224-byte
//!     signature) FIRST, under the validator-set mutex, for any blob a stranger posted.
//!     Now every free refusal — shape, membership, epoch / window, queue dedup — comes
//!     first (`rotation_preflight`, `set_change_preflight`), the verify runs on a snapshot
//!     with no lock held, the free checks are re-run under the lock before anything is
//!     queued, and at most `CERT_VERIFY_SLOTS` verifies run at once across both methods:
//!     callers past that get a "busy — retry" error instead of pinning every worker thread.
//!   * L-2 (consensus, gated — `genesis::rotation_v2_from_for`): a rotation certificate is
//!     judged here by `hk_consensus::rotation::RotationRules` at `tip + 1` (the earliest
//!     height it can commit at): before the chain's v2 height the v1 rule, byte for byte;
//!     from it only the chain-bound v2 domain, with `valid_from_height` enforced as a
//!     freshness window (not from the future, not more than `ROTATION_FRESHNESS_HORIZON`
//!     blocks old). The window is a free check and runs in the preflight; the domain is the
//!     signature itself. `hk_chainInfo.activations` publishes the heights.
//!
//! R18 (reported 2026-10-04, confirmed 2026-10-08; client-side here, no gate): `hk_submitTx`
//! and `hk_gossipTxs` refuse, through the mempool door (`Mempool::envelope_verdict` /
//! `try_admit_verified`), a `ChannelOpen` past `hk_state::MAX_CHANNEL_STEPS` and a
//! `ChannelSettle` more than `hk_state::MAX_SETTLE_DELTA` links past its channel's settled
//! step — the settle whose apply was ≈ 4.29e9 SHAKE-256 links under the chain mutex, free to
//! the sender and replayable every block. Reasons: `channel too long (N steps, max M)` /
//! `settle delta too large (D links past the highest settled step, max M per settlement)` —
//! hk-state's receipt wording, byte for byte (mempool.rs `AdmitError::as_str`; docs/RPC.md)
//! — and, since the same-day review, `settle too costly to propose (L links from the tip,
//! max B per block …)` for a settle no block this node builds could carry (mempool.rs).
//! The consensus rule behind them is height-gated (`hk_state::State::payword_cap_from`), and
//! `hk_chainInfo.activations.payword_cap_from` publishes that height exactly as the two R17
//! ones. R18 review (2026-10-08): `hk_submitBundle` was a sibling path into the SAME hash
//! loop that bypassed both mirrors and the proposer's budget — `build_batch` places the
//! bundle's txs ahead of the pool without costing them, and an invalid aggregate only logs
//! (the block still applies, so its `ChannelSettle`s were hashed by every validator) — so
//! an unauthenticated caller could put up to `MAX_TXS_PER_BLOCK` over-cap settles into an
//! UPGRADED proposer's next block, before or after the height. A bundle is now refused
//! unless every tx is a proof-less `MintToPool` / `ShieldedSpend` — what P2.3 defines a
//! bundle as, and exactly what `demo_agg` builds (`bundle_shape_verdict`). Nothing else on
//! this surface changes.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

use hk_consensus::rotation::RotationRules;
use hk_consensus::{HkAddress, HkValidatorSet, RotationCert, SetChange, SetChangeCert};
use hk_crypto::slhdsa_adapter::{ROOT_PK_LEN, ROOT_SIG_LEN};
use hk_primitives::{AssetId, H256};
use hk_state::tx::{SignedTx, Tx};
use hk_state::PoolKey;

use crate::batch::{txid, Batch, MAX_TXS_PER_BLOCK};
use crate::mempool::Mempool;
use crate::state::SharedHandles;

/// H1 (v0.13.2): a request must arrive within this window, headers and body — a
/// half-open connection used to pin a task and up to 1 MiB of buffer forever.
const RPC_CONN_TIMEOUT: Duration = Duration::from_secs(10);
/// H1: at most this many connections are served concurrently; the rest get a fast
/// 503 instead of queueing behind a slowloris.
const RPC_MAX_CONNS: usize = 256;

/// L-6 (R17, reported 2026-10-06): at most this many SLH-DSA-192s root-signature verifies
/// (≈1.7 ms of CPU each; one per approval for a set change) run at once across
/// `hk_submitRotation` + `hk_submitSetChange`. Both are unauthenticated with no per-IP
/// limit, so without a bound a flood of well-shaped garbage certs could occupy all
/// RPC_MAX_CONNS worker slots in verifies. Legitimate traffic is a handful of certs per
/// epoch — two slots are plenty; the rest answer "busy — retry" (`busy_error`).
const CERT_VERIFY_SLOTS: usize = 2;
static CERT_VERIFY: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(CERT_VERIFY_SLOTS);

/// L-5 residual (R17 review, 2026-10-06): `hk_getPoolPath` still copies 32 B × every leaf
/// of a pool UNDER the feed lock (32 MB at a million notes) and then hashes the whole tree
/// (`full_tree_path`, O(n) SHAKEs) per call — the page-sized copy of L-5 bounds the two
/// scanner methods, not this one, and the commit path takes the feed lock with the chain
/// lock held. Until the per-pool tree is cached (a separate item, MBP §7), at most this
/// many path builds run at once across every pool, `try_acquire` like `CERT_VERIFY`: one
/// unauthenticated scanner can no longer serialize commit behind 256 full-feed copies. A
/// wallet needs one path per spend; two slots are plenty.
const POOL_PATH_SLOTS: usize = 2;
static POOL_PATH: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(POOL_PATH_SLOTS);

/// L-6: `hk_submitSetChange` refuses, before verifying, a certificate whose window opens
/// more than this many blocks past the tip. A queued cert sits in RAM until its window
/// opens (propose keeps it while `not_before > height`), so this bounds how long an
/// accepted cert can park: ≈18 days at testnet-1's 1.6 s cadence. A certificate for a
/// later window is assembled closer to it, not parked on a node.
const SET_CHANGE_HORIZON: u64 = 1_000_000;

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
///
/// R17 review (2026-10-06): the two M-2 hashes — `pk_commit` over the 16 KiB key and the
/// 256-SHAKE Lamport verify, ≈ 0.3 ms — are state-free, so they run HERE, before either
/// lock, and only the state-dependent binding runs under the locks
/// (`Mempool::try_admit_verified`). The first cut verified inside `try_admit`, i.e. with
/// the chain lock held: a flood of right-length junk on these two unauthenticated methods
/// held the lock the commit path needs for a verify per request, 256 workers deep (the
/// L-6 shape). Verdicts and their precedence are unchanged (mempool.rs
/// `hoisted_verdict_and_try_admit_agree`).
///
/// R18 (2026-10-08): an over-cap `ChannelOpen` is refused inside `envelope_verdict`, i.e.
/// before the hashes; an over-cap `ChannelSettle` under the locks, one channel lookup,
/// before the account walk (mempool.rs `r18_caps_refuse_the_same_through_both_doors`).
fn admit_one(h: &SharedHandles, tx: &SignedTx) -> Result<[u8; 32], String> {
    let verdict = Mempool::envelope_verdict(tx);
    let admitted = {
        let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut mp = h.mempool.lock().unwrap_or_else(|e| e.into_inner());
        mp.try_admit_verified(tx.clone(), &chain, &verdict)
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

/// R18 review (2026-10-08): what `hk_submitBundle` may queue — P2.3's definition of a
/// bundle, exactly: proof-less pool txs (`MintToPool` / `ShieldedSpend` with an empty
/// `proof`) whose truth the ONE aggregate STARK carries, and no more of them than a block
/// holds (`build_batch` would never pick a longer bundle, and a queued bundle it never
/// picks sits at the head of the queue until its txs commit some other way). Anything else
/// — a `ChannelSettle` above all — has no business in a bundle: it rode ahead of the pool,
/// uncosted by the proposer's settle-link budget and unseen by the mempool's two caps, so
/// the bundle path was the one door through which an over-cap settle reached an UPGRADED
/// proposer's own block (the module doc). The verdict reads payloads only; the mempool
/// never sees bundle txs, so it is judged here, before the queue.
pub(crate) fn bundle_shape_verdict(txs: &[SignedTx]) -> Result<(), String> {
    if txs.len() > MAX_TXS_PER_BLOCK {
        return Err(format!("bad txs: a bundle may carry at most {MAX_TXS_PER_BLOCK} txs (one block)"));
    }
    for (i, t) in txs.iter().enumerate() {
        let proof_less_pool_tx = matches!(
            &t.payload,
            Tx::MintToPool { proof, .. } | Tx::ShieldedSpend { proof, .. } if proof.is_empty()
        );
        if !proof_less_pool_tx {
            return Err(format!(
                "bad txs: a bundle may carry only proof-less MintToPool / ShieldedSpend txs covered by its aggregate (tx {i} is not one — submit it through hk_submitTx)"
            ));
        }
    }
    Ok(())
}

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
                    // C2.8 (v0.16.0): null = archive node (keeps every block); N = this node
                    // prunes whole segments older than tip−N, and `disk_from` moves up.
                    "retain_blocks": Some(crate::state::retain_blocks()).filter(|r| *r > 0),
                },
                // R11 (v0.17.0): what THIS process costs — resident set (Linux + macOS
                // since v0.19.4; null elsewhere), seconds since start, and how long the
                // verify-only STARK client took to come up (null = no verifier wired). The
                // onboarding doc's RAM line is checkable on any node with one call.
                // v0.19.4: free bytes on the filesystem holding the block log (incident #13
                // was a full disk) — null without a store or off-Unix.
                "process": {
                    "rss_bytes": crate::state::rss_bytes(),
                    "uptime_secs": crate::state::uptime_secs(),
                    "verifier_init_ms": crate::state::verifier_init_ms(),
                    "disk_free_bytes": h.store.as_ref().and_then(|s| crate::state::disk_free_bytes(s.blocks_dir())),
                },
                // R17 (v0.19.6) + R18 (2026-10-08): the activation heights THIS binary holds
                // for this chain — null = never (`u64::MAX`). The roll call reads them off
                // every seat: a height is named for testnet-1 only once each seat answers the
                // same number, and a node that answers differently is the one that will island.
                "activations": {
                    "mandate_asset_from": activation_height(chain.mandate_asset_from),
                    "rotation_v2_from": activation_height(h.rotation_v2_from),
                    // R18: the PayWord caps (MAX_SETTLE_DELTA links per settle,
                    // MAX_CHANNEL_STEPS per channel) as a consensus rule; the mempool
                    // mirrors them from the moment this binary runs, gate or no gate.
                    "payword_cap_from": activation_height(chain.payword_cap_from),
                },
            }})
        }
        // R2: accept a root-signed RotationCert on behalf of ANOTHER validator (an
        // exhausted signer can't propose its own revival — peers carry it). Validated
        // against the live set here AND re-validated at propose + commit; the root
        // signature makes this trustless (nothing to spoof, replay is epoch-monotone).
        // L-6 (R17): the body lives in `submit_rotation` — free refusals first, the verify
        // on a snapshot with no lock held, bounded by CERT_VERIFY_SLOTS. L-2: judged by the
        // rule at tip + 1, the earliest height the cert can commit at (chain lock taken for
        // the tip only, released before the validator-set lock — the commit path's order).
        "hk_submitRotation" => match params.get("cert") {
            Some(c) => match serde_json::from_value::<RotationCert>(c.clone()) {
                Ok(cert) => {
                    let tip = h.chain.lock().unwrap_or_else(|e| e.into_inner()).height;
                    let rules = RotationRules::new(tip.saturating_add(1), &h.chain_id, h.rotation_v2_from);
                    submit_rotation(&h.validators, &h.foreign_rotations, &CERT_VERIFY, &rules, cert)
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
                    // R18 review (2026-10-08): only proof-less pool txs ride a bundle —
                    // judged before the queue, so a ChannelSettle can never reach
                    // `build_batch` through this door (`bundle_shape_verdict`).
                    if let Err(reason) = bundle_shape_verdict(&txs) {
                        warn!(txs = txs.len(), "hk_submitBundle refused: {reason}");
                        return json!({"error": reason});
                    }
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
            // P6: `asset` (64-hex, optional) selects a per-asset pool; absent = the legacy
            // pool — every pre-P6 wallet keeps working unchanged.
            let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
            match pool_key_param(params, &chain) {
                Err(e) => json!({"error": e}),
                Ok(key) => match chain.pool_ref(key) {
                    None => json!({"error": "no pool for that asset yet"}),
                    Some(p) => json!({"result": pool_json(key, p)}),
                },
            }
        }
        "hk_getPools" => {
            // P6: every pool, the legacy one first.
            let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
            let pools: Vec<Value> = chain.pools_iter().map(|(k, p)| pool_json(k, p)).collect();
            json!({"result": {
                "count": pools.len(),
                "multi_pool_from": if chain.multi_pool_from == u64::MAX { Value::Null } else { json!(chain.multi_pool_from) },
                "pools": pools,
            }})
        }
        // ---- H3 (v0.16.1): the pool feed is PAGED. `from` (leaf index, default 0) and
        // `limit` (default and cap POOL_PAGE_MAX) — the answer carries `total` and `next`
        // (null when the page reached the end). A wallet keeps `next` as its scan cursor and
        // asks only for what it has not seen; a spender asks `hk_getPoolPath` for one
        // authentication path instead of downloading every commitment.
        // L-5 (R17): each arm hands `with_pool_feed` a closure that copies exactly what the
        // answer needs — a page of leaves, a page of notes, or the bare 32-byte leaves — and
        // nothing else leaves the lock. The JSON shapes are the v0.19.0 ones, byte for byte.
        "hk_getPoolLeaves" => {
            // P6: `asset` (optional) selects the per-asset feed; absent = the legacy pool.
            match with_pool_feed(&h.chain, &h.pool_notes, &h.pool_notes_by_asset, params, |feed| {
                page_of(feed, params, |(l, _)| l.0)
            }) {
                Err(e) => json!({"error": e}),
                Ok((page, asset)) => json!({"result": {
                    "asset": asset,
                    "leaves": page.items.iter().map(hex::encode).collect::<Vec<_>>(),
                    "from": page.from,
                    "count": page.to - page.from,
                    "total": page.total,
                    "next": page.next,
                }}),
            }
        }
        "hk_getPoolNotes" => {
            // For scanners: (leaf index, commitment, stealth payload). P6: per pool.
            match with_pool_feed(&h.chain, &h.pool_notes, &h.pool_notes_by_asset, params, |feed| {
                page_of(feed, params, |(l, ct)| (l.0, ct.clone()))
            }) {
                Err(e) => json!({"error": e}),
                Ok((page, asset)) => json!({"result": {
                    "asset": asset,
                    "notes": page.items.iter().enumerate().map(|(i, (l, ct))| json!({
                        "index": page.from + i,
                        "commitment": hex::encode(l),
                        "stealth_ct": hex::encode(ct),
                    })).collect::<Vec<_>>(),
                    "from": page.from,
                    "count": page.to - page.from,
                    "total": page.total,
                    "next": page.next,
                }}),
            }
        }
        "hk_getPoolPath" => {
            // One leaf's authentication path (siblings bottom→top) + the root it folds to,
            // computed from the node's full leaf list. The proof binds the root; the chain
            // accepts it only while that root is a recent anchor — a wrong path can only
            // cost the spender a rejected tx, never a coin. P6: per pool (`asset`).
            // L-5: the tree is still rebuilt per call (O(n) hashing — caching it is a
            // separate item), but only the 32-byte leaves are copied out of the lock, never
            // the ≈1.2 KB stealth ciphertext beside each one; the copy + the build are
            // bounded by POOL_PATH_SLOTS (`pool_path`).
            pool_path(&h.chain, &h.pool_notes, &h.pool_notes_by_asset, &POOL_PATH, params)
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
            // P6: `asset` (optional) selects the pool; absent = the legacy pool.
            Some(nf) => {
                let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
                match pool_key_param(params, &chain) {
                    Err(e) => json!({"error": e}),
                    Ok(key) => {
                        let spent = chain.pool_ref(key).is_some_and(|p| p.nullifiers.contains(&nf.0));
                        json!({"result": {"spent": spent}})
                    }
                }
            }
            None => json!({"error": "nullifier must be 64-char hex"}),
        },
        "hk_getValidators" => {
            let vs = h.validators.lock().unwrap_or_else(|e| e.into_inner());
            let queued = h.pending_set_changes.lock().unwrap_or_else(|e| e.into_inner());
            let height = h.chain.lock().unwrap_or_else(|e| e.into_inner()).height;
            let total = vs.total_voting_power();
            // G1 (v0.18.0): the arithmetic every operator should be able to read off the
            // node — who is a genesis seat, what the founders and the externals weigh, where
            // the quorum line is, and how much power may be absent before commits stop.
            let founding: u64 = vs.iter().filter(|v| h.genesis_roots.contains(&v.root_pk)).map(|v| v.voting_power).sum();
            let quorum = hk_consensus::quorum_power(total);
            let bootstrap = crate::genesis::bootstrap_for(&h.chain_id).map(|b| json!({
                "height": b.height,
                "founding_power": b.founding_power,
                "active": height >= b.height,
            }));
            json!({"result": {
                "count": vs.len(),
                "total_power": total,
                "founding_power": founding,
                "external_power": total.saturating_sub(founding),
                "quorum_power": quorum,
                "max_absent_power": total.saturating_sub(quorum),
                "founders_alone_decide": founding >= quorum,
                "bootstrap": bootstrap,
                "validators": vs.iter().map(|v| json!({
                    "address": v.address.to_string(),
                    "voting_power": v.voting_power,
                    "epoch": v.epoch,
                    "root_pk": hex::encode(&v.root_pk),
                    "genesis": h.genesis_roots.contains(&v.root_pk),
                })).collect::<Vec<_>>(),
                "pending_set_changes": queued.iter().map(|c| {
                    let change = match &c.body.change {
                        hk_consensus::SetChange::Admit { root_pk, voting_power, .. } =>
                            json!({"admit": hex::encode(root_pk), "voting_power": voting_power}),
                        hk_consensus::SetChange::Remove { root_pk } =>
                            json!({"remove": hex::encode(root_pk)}),
                        hk_consensus::SetChange::SetPower { root_pk, voting_power } =>
                            json!({"set_power": hex::encode(root_pk), "voting_power": voting_power}),
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
                    // v0.19.3: a restart that dialed in before its old socket died keeps the entry
                    // (connected_secs runs on) — these show it: seconds since the LATEST connection
                    // and how many connections arrived beyond the first.
                    "last_connection_secs": now.saturating_sub(p.last_connection_at),
                    "reconnects": p.reconnects,
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
        // L-6 (R17): the body lives in `submit_set_change` — free refusals first (shape,
        // chain id, window, membership, power, subject, queue dedup), then the per-approval
        // verify on a snapshot with no lock held, bounded by CERT_VERIFY_SLOTS.
        "hk_submitSetChange" => match params.get("cert") {
            Some(c) => match serde_json::from_value::<SetChangeCert>(c.clone()) {
                Ok(cert) => {
                    let tip = h.chain.lock().unwrap_or_else(|e| e.into_inner()).height;
                    submit_set_change(&h.validators, &h.pending_set_changes, &CERT_VERIFY, &h.chain_id, tip, cert)
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
                                    hk_consensus::SetChange::SetPower { root_pk, voting_power } =>
                                        ("set_power", hex::encode(root_pk), Some(*voting_power)),
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
        // P6: this asset's shielded ledger across every pool that denominates it.
        "shielded": chain.shielded_of(id).to_string(),
    })
}

/// P6: the pool an RPC call addresses — `asset` (64-hex) names a per-asset pool, or the
/// legacy pool when it is that pool's pinned asset; absent = the legacy pool.
fn pool_key_param(params: &Value, chain: &hk_state::State) -> Result<hk_state::PoolKey, String> {
    match params.get("asset") {
        None | Some(Value::Null) => Ok(hk_state::PoolKey::Legacy),
        Some(_) => match param_h256(params, "asset") {
            None => Err("asset must be 64-char hex".into()),
            Some(a) => {
                if chain.pool.asset == Some(a) {
                    Ok(hk_state::PoolKey::Legacy)
                } else {
                    Ok(hk_state::PoolKey::Asset(a))
                }
            }
        },
    }
}

/// P6: one pool's public view.
fn pool_json(key: hk_state::PoolKey, p: &hk_state::pool::PoolState) -> Value {
    json!({
        "legacy": matches!(key, hk_state::PoolKey::Legacy),
        "version": p.version,
        "asset": p.asset.map(|a| hex::encode(a.0)),
        "root": hex::encode(p.tree.root()),
        "latest_anchor": p.latest_anchor().map(hex::encode),
        "next_index": p.tree.next_index(),
        "nullifiers": p.nullifiers.len(),
        "total_shielded": p.total_shielded.to_string(),
    })
}

/// One pool's note feed as the node indexes it: (commitment, stealth ciphertext) in leaf
/// order (`SharedHandles::pool_notes` / `pool_notes_by_asset`).
type PoolFeed = Vec<(H256, Vec<u8>)>;

/// L-5 (R17, reported 2026-10-06): run `f` over the leaf feed an RPC call addresses, UNDER
/// that feed's lock, and return what it produced + the asset label (`None` = the legacy
/// pool; the answer's `asset`). `f` decides what gets copied out — a page, or the bare
/// 32-byte leaves — so the lock is held for one bounded copy, never for a clone of the
/// whole feed (what v0.19.0's `pool_feed` did, ciphertexts included: ≈1.2 KB × every note,
/// per call, while the commit path waits on this lock with the chain lock held).
/// An `asset` that is the legacy pool's pinned asset reads the legacy feed; an asset
/// without a pool yet reads an empty feed (a scanner sees `total: 0`).
/// Lock order: chain (released) → the one feed lock; never both at once.
fn with_pool_feed<R>(
    chain: &Mutex<hk_state::State>,
    legacy: &Mutex<PoolFeed>,
    by_asset: &Mutex<BTreeMap<AssetId, PoolFeed>>,
    params: &Value,
    f: impl FnOnce(&[(H256, Vec<u8>)]) -> R,
) -> Result<(R, Option<String>), String> {
    let key = {
        let chain = chain.lock().unwrap_or_else(|e| e.into_inner());
        pool_key_param(params, &chain)?
    };
    match key {
        PoolKey::Legacy => {
            let notes = legacy.lock().unwrap_or_else(|e| e.into_inner());
            Ok((f(notes.as_slice()), None))
        }
        PoolKey::Asset(a) => {
            let by = by_asset.lock().unwrap_or_else(|e| e.into_inner());
            let feed = by.get(&a).map(Vec::as_slice).unwrap_or(&[]);
            Ok((f(feed), Some(hex::encode(a.0))))
        }
    }
}

/// `hk_getPoolPath` (H3 + L-5): one leaf's authentication path (siblings bottom → top) and
/// the root it folds to, from the pool's full leaf list. The 32-byte leaves are copied
/// under the feed lock, the tree is built outside it, and the whole call holds one of
/// `slots` (`POOL_PATH_SLOTS`) — `try_acquire`, so a caller past the bound gets a "busy —
/// retry" error and never queues on the lock the commit path needs. Takes the handles it
/// touches so `r17_tests` can drive it without a node; `dispatch` only routes to it.
fn pool_path(
    chain: &Mutex<hk_state::State>,
    legacy: &Mutex<PoolFeed>,
    by_asset: &Mutex<BTreeMap<AssetId, PoolFeed>>,
    slots: &tokio::sync::Semaphore,
    params: &Value,
) -> Value {
    let Some(index) = params.get("index").and_then(|v| v.as_u64()) else {
        return json!({"error": "index (leaf index, integer) required"});
    };
    let Ok(_permit) = slots.try_acquire() else {
        return json!({"error": format!(
            "busy: {POOL_PATH_SLOTS} pool-path builds already in flight — retry in a moment"
        )});
    };
    match with_pool_feed(chain, legacy, by_asset, params, |feed| feed.iter().map(|(l, _)| l.0).collect::<Vec<[u8; 32]>>()) {
        Err(e) => json!({"error": e}),
        Ok((leaves, asset)) => {
            if (index as usize) >= leaves.len() {
                json!({"error": format!("index {index} out of range (pool has {} commitments)", leaves.len())})
            } else {
                let (siblings, root) = hk_state::pool::full_tree_path(&leaves, index);
                json!({"result": {
                    "asset": asset,
                    "index": index,
                    "commitment": hex::encode(leaves[index as usize]),
                    "siblings": siblings.iter().map(hex::encode).collect::<Vec<_>>(),
                    "root": hex::encode(root),
                    "total": leaves.len(),
                }})
            }
        }
    }
}

/// One page of a pool feed, cut under the lock (L-5): `items` is `feed[from..to]` through
/// the arm's projection, `total` the feed's length, `next` the following page's `from`
/// (`None` once this page reached the end) — the H3 paging contract, unchanged.
#[derive(Debug)]
struct PoolPage<T> {
    from: usize,
    to: usize,
    total: usize,
    next: Option<usize>,
    items: Vec<T>,
}

/// `params`'s page of `feed` (`pool_page` arithmetic), each item through `project` — the
/// only copy a paged pool read makes.
fn page_of<T>(feed: &[(H256, Vec<u8>)], params: &Value, project: impl Fn(&(H256, Vec<u8>)) -> T) -> PoolPage<T> {
    let (from, to, next) = pool_page(params, feed.len());
    PoolPage { from, to, total: feed.len(), next, items: feed[from..to].iter().map(project).collect() }
}

fn param_h256(params: &Value, key: &str) -> Option<H256> {
    let s = params.get(key)?.as_str()?;
    let bytes = hex::decode(s).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(H256(arr))
}

/// H3 (v0.16.1): the largest page the pool feed answers in one call. A page of notes is
/// ~2.4 KB each (ML-KEM ciphertext + sealed note as hex), so this is ≈ 24 MB worst case —
/// bounded on the node whatever the pool grows to; wallets page with `next`.
pub(crate) const POOL_PAGE_MAX: usize = 10_000;

/// `(from, to, next)` for a paged read of `total` items: `from` clamped to `total`,
/// `limit` defaulted and capped at `POOL_PAGE_MAX`, `next` = the index after this page or
/// `None` when the page reached the end.
fn pool_page(params: &Value, total: usize) -> (usize, usize, Option<usize>) {
    let from = params.get("from").and_then(|v| v.as_u64()).unwrap_or(0).min(total as u64) as usize;
    let limit = params
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|l| (l as usize).clamp(1, POOL_PAGE_MAX))
        .unwrap_or(POOL_PAGE_MAX);
    let to = from.saturating_add(limit).min(total);
    let next = (to < total).then_some(to);
    (from, to, next)
}

// ---- L-6 (R17, reported 2026-10-06): the operator submits ------------------------------
//
// Both handlers follow one shape: (1) snapshot the validator set — an `Arc` clone — and
// DROP its lock; (2) every free refusal, under the queue's lock only, via a `*_preflight`
// that also answers "already queued"; (3) one of CERT_VERIFY_SLOTS or `busy_error`;
// (4) the SLH-DSA verify on the snapshot, no lock held; (5) re-lock, re-run the free
// checks (the set or the queue may have moved under the verify), then queue. The bodies
// take the handles they touch rather than `SharedHandles` so `r17_tests` can drive them
// without a node; `dispatch` only parses `params.cert` around them.

/// What a free pre-check says about a submitted certificate.
enum Preflight {
    /// Every free check passed — spend a verify slot on it.
    Verify,
    /// An equivalent certificate is already queued; that copy was verified when it was
    /// queued and already rides the next proposal, so the submitted bytes change nothing
    /// and are not verified (a flood of re-submits costs the node a few compares).
    AlreadyQueued,
}

fn busy_error() -> Value {
    json!({"error": format!(
        "busy: {CERT_VERIFY_SLOTS} root-signature verifications already in flight — retry in a moment"
    )})
}

fn refused(reason: String) -> Value {
    json!({"result": {"accepted": false, "reason": reason}})
}

/// R17: an activation height as `hk_chainInfo` reports it — `null` for never (`u64::MAX`).
fn activation_height(h: u64) -> Option<u64> {
    (h != u64::MAX).then_some(h)
}

/// The free checks of `hk_submitRotation`, in the order they refuse: the cert's root must
/// be a seated validator's; its epoch must be strictly newer than that seat's (epochs are
/// monotone — a replay or rollback is stale); L-2: under the v2 rule its
/// `valid_from_height` must sit inside the freshness window (`RotationCert::check_window`
/// — a u64 compare, nothing signed); the signature must be the one size SLH-DSA-192s
/// produces (anything else cannot verify, so it never reaches the verifier); and no cert
/// for that root at this epoch or newer may already be queued. Nothing here costs more than
/// a 48-byte compare per seat. `apply_rotation` repeats the first three (cheaply) in front
/// of the signature — this is the gate in front of it. The chain-id binding of L-2 is the
/// v2 signature domain itself (the cert carries no chain-id field), so it is the verify.
fn rotation_preflight(
    set: &HkValidatorSet,
    queue: &[RotationCert],
    rules: &RotationRules<'_>,
    cert: &RotationCert,
) -> Result<Preflight, String> {
    let seat = set
        .iter()
        .find(|v| v.root_pk == cert.root_pk)
        .ok_or_else(|| "rotation cert: no validator with that root identity".to_string())?;
    if cert.epoch <= seat.epoch {
        return Err(format!("rotation cert: stale (cert epoch {}, current {})", cert.epoch, seat.epoch));
    }
    cert.check_window(rules)?;
    if cert.root_sig.len() != ROOT_SIG_LEN {
        return Err(format!(
            "rotation cert: root_sig must be {ROOT_SIG_LEN} bytes (SLH-DSA-192s), got {}",
            cert.root_sig.len()
        ));
    }
    if queue.iter().any(|x| x.root_pk == cert.root_pk && x.epoch >= cert.epoch) {
        return Ok(Preflight::AlreadyQueued);
    }
    Ok(Preflight::Verify)
}

fn rotation_accepted(cert: &RotationCert, queued: bool) -> Value {
    json!({"result": {"accepted": true, "epoch": cert.epoch, "queued": queued,
        "note": if queued {
            "cert rides this node's next proposal"
        } else {
            "a cert for that root at this epoch or newer is already queued — it rides this node's next proposal"
        }}})
}

/// `hk_submitRotation` (R2 + L-6 + L-2): queue a foreign validator's root-signed rotation
/// cert for this node's next proposal, judged by `rules` (the chain's rotation rule at
/// tip + 1). Responses: `{accepted: true, epoch, queued, note}` for a verified or
/// already-queued cert (the v0.19.4 shape), `{accepted: false, reason}` for a refused one,
/// `{error}` when every verify slot is busy.
fn submit_rotation(
    validators: &Mutex<HkValidatorSet>,
    queue: &Mutex<Vec<RotationCert>>,
    slots: &tokio::sync::Semaphore,
    rules: &RotationRules<'_>,
    cert: RotationCert,
) -> Value {
    let set = validators.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let gate = {
        let q = queue.lock().unwrap_or_else(|e| e.into_inner());
        rotation_preflight(&set, &q, rules, &cert)
    };
    match gate {
        Err(reason) => return refused(reason),
        Ok(Preflight::AlreadyQueued) => return rotation_accepted(&cert, false),
        Ok(Preflight::Verify) => {}
    }
    let Ok(permit) = slots.try_acquire() else {
        return busy_error();
    };
    // The expensive part — on the snapshot, no lock held. `apply_rotation` is the exact
    // check propose and commit run; its `Err` text is what callers saw before R17.
    if let Err(reason) = set.apply_rotation(&cert, rules) {
        return refused(reason);
    }
    drop(permit);
    let set = validators.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
    match rotation_preflight(&set, &q, rules, &cert) {
        Err(reason) => refused(reason),
        Ok(Preflight::AlreadyQueued) => rotation_accepted(&cert, false),
        Ok(Preflight::Verify) => {
            // A newer cert for the same root retires any older queued copy (R9: never
            // stack beside the entry that wedged us).
            q.retain(|x| !(x.root_pk == cert.root_pk && x.epoch < cert.epoch));
            q.push(cert.clone());
            rotation_accepted(&cert, true)
        }
    }
}

/// The free checks of `hk_submitSetChange`, in the order they refuse: body shape (window
/// ordered, key sizes, power ≥ 1), chain id, window against the tip (closed, or opening
/// past SET_CHANGE_HORIZON), approvals present / well-sized / distinct / from seated roots
/// / strictly more than ⅔ of the current power (exactly as `verify_against` counts, minus
/// the signatures), the subject as commit would judge it against the set as it stands (a
/// change that is already applied would only be queued and dropped at the next propose —
/// refuse it here with the reason instead), and the pending-queue dedup. The reason texts
/// match `verify_against` / `apply_set_change` where the check is the same one.
fn set_change_preflight(
    set: &HkValidatorSet,
    queue: &[SetChangeCert],
    chain_id: &str,
    tip: u64,
    cert: &SetChangeCert,
) -> Result<Preflight, String> {
    let body = &cert.body;
    body.check_shape()?;
    if body.chain_id != chain_id {
        return Err(format!("set change: for chain {} — this is {chain_id}", body.chain_id));
    }
    if body.not_after < tip {
        return Err(format!("window closed: not_after {} < tip {tip}", body.not_after));
    }
    if body.not_before > tip.saturating_add(SET_CHANGE_HORIZON) {
        return Err(format!(
            "window too far ahead: not_before {} > tip {tip} + {SET_CHANGE_HORIZON} — assemble it closer to its window",
            body.not_before
        ));
    }
    if cert.approvals.is_empty() {
        return Err("set change: no approvals".into());
    }
    let total = set.total_voting_power();
    let mut approving: u64 = 0;
    let mut seen: Vec<&[u8]> = Vec::with_capacity(cert.approvals.len());
    for a in &cert.approvals {
        if a.root_pk.len() != ROOT_PK_LEN || a.root_sig.len() != ROOT_SIG_LEN {
            return Err(format!(
                "set change: an approval must be a {ROOT_PK_LEN}-byte root + {ROOT_SIG_LEN}-byte SLH-DSA-192s signature"
            ));
        }
        if seen.iter().any(|s| *s == a.root_pk.as_slice()) {
            return Err("set change: duplicate approval from one root".into());
        }
        let seat = set
            .iter()
            .find(|v| v.root_pk == a.root_pk)
            .ok_or_else(|| "set change: approval from a root that is not seated".to_string())?;
        seen.push(&a.root_pk);
        approving = approving.saturating_add(seat.voting_power);
    }
    if approving.saturating_mul(3) <= total.saturating_mul(2) {
        return Err(format!("set change: approving power {approving} is not > 2/3 of {total}"));
    }
    let seated = |root: &[u8]| set.iter().find(|v| v.root_pk == root);
    match &body.change {
        SetChange::Admit { root_pk, public_key, .. } => {
            if seated(root_pk).is_some() {
                return Err("set change: already applied — that root is seated".into());
            }
            let addr = HkAddress::from_public_key(public_key);
            if set.iter().any(|v| v.address == addr) {
                return Err("set change: operational key collides with a seated address".into());
            }
        }
        SetChange::Remove { root_pk } => {
            if seated(root_pk).is_none() {
                return Err("set change: already applied — that root is not seated".into());
            }
            if set.len() == 1 {
                return Err("set change: refusing to remove the last seat".into());
            }
        }
        SetChange::SetPower { root_pk, voting_power } => match seated(root_pk) {
            None => return Err("set change: set-power for a root that is not seated".into()),
            Some(v) if v.voting_power == *voting_power => {
                return Err(format!("set change: already applied — that seat already weighs {voting_power}"));
            }
            Some(_) => {}
        },
    }
    if queue.iter().any(|x| x.body == *body) {
        return Ok(Preflight::AlreadyQueued);
    }
    Ok(Preflight::Verify)
}

fn set_change_accepted(cert: &SetChangeCert, queued: bool) -> Value {
    json!({"result": {"accepted": true, "queued": queued,
        "approvals": cert.approvals.len(),
        "window": [cert.body.not_before, cert.body.not_after],
        "note": if queued {
            "cert rides this node's next proposal inside its window"
        } else {
            "an identical cert is already queued — it rides this node's next proposal inside its window"
        }}})
}

/// `hk_submitSetChange` (V1 + L-6): queue a validator-set change certificate for this
/// node's next proposal. `tip` is the chain height the window is judged against.
/// Responses: `{accepted: true, queued, approvals, window, note}` for a verified or
/// already-queued cert (the v0.19.4 shape), `{accepted: false, reason}` for a refused
/// one, `{error}` when every verify slot is busy.
fn submit_set_change(
    validators: &Mutex<HkValidatorSet>,
    queue: &Mutex<Vec<SetChangeCert>>,
    slots: &tokio::sync::Semaphore,
    chain_id: &str,
    tip: u64,
    cert: SetChangeCert,
) -> Value {
    let set = validators.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let gate = {
        let q = queue.lock().unwrap_or_else(|e| e.into_inner());
        set_change_preflight(&set, &q, chain_id, tip, &cert)
    };
    match gate {
        Err(reason) => return refused(reason),
        Ok(Preflight::AlreadyQueued) => return set_change_accepted(&cert, false),
        Ok(Preflight::Verify) => {}
    }
    let Ok(permit) = slots.try_acquire() else {
        return busy_error();
    };
    // The expensive part — every approval's root signature, on the snapshot, no lock
    // held. `verify_against` is the exact check propose and commit run.
    if let Err(reason) = cert.verify_against(&set, chain_id) {
        return refused(reason);
    }
    drop(permit);
    let set = validators.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
    match set_change_preflight(&set, &q, chain_id, tip, &cert) {
        Err(reason) => refused(reason),
        Ok(Preflight::AlreadyQueued) => set_change_accepted(&cert, false),
        Ok(Preflight::Verify) => {
            q.push(cert.clone());
            set_change_accepted(&cert, true)
        }
    }
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
        assert_eq!(mask_multiaddr("/ip4/10.42.7.9/tcp/27000"), ("/ip4/10.42.7.0/tcp/27000".into(), true));
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

/// R18 review (2026-10-08): the bundle door admits P2.3's bundle and nothing else.
#[cfg(test)]
mod r18_tests {
    use super::{bundle_shape_verdict, MAX_TXS_PER_BLOCK};
    use hk_primitives::H256;
    use hk_state::tx::{SignedTx, Tx};

    /// Unsigned frames: the verdict reads payloads only (the aggregate is the proof).
    fn frame(payload: Tx) -> SignedTx {
        SignedTx { sender: H256([1; 32]), nonce: 0, payload, next_auth: H256([0; 32]), lamport_pk: vec![], sig: vec![] }
    }
    fn spend(proof: Vec<u8>) -> SignedTx {
        frame(Tx::ShieldedSpend {
            anchor: H256([2; 32]),
            nullifier: H256([3; 32]),
            out_commitment: H256([4; 32]),
            out2_commitment: H256([5; 32]),
            fee: 0,
            credit: None,
            mandate: None,
            proof,
            stealth_ct: vec![],
            stealth_ct2: vec![],
        })
    }
    fn mint(proof: Vec<u8>) -> SignedTx {
        frame(Tx::MintToPool { asset: H256([9; 32]), value: 1, commitment: H256([6; 32]), proof, stealth_ct: vec![] })
    }

    #[test]
    fn r18_a_bundle_carries_only_proof_less_pool_txs() {
        // exactly what demo_agg builds: proof-less spends (and mints) under one aggregate
        assert_eq!(bundle_shape_verdict(&[spend(vec![]), spend(vec![]), mint(vec![])]), Ok(()));
        // the reported bypass: a ChannelSettle (over-cap or not) rode the bundle uncosted
        let settle = frame(Tx::ChannelSettle { id: H256([7; 32]), word: H256([8; 32]), step: u32::MAX });
        let err = bundle_shape_verdict(&[spend(vec![]), settle.clone()]).unwrap_err();
        assert!(err.starts_with("bad txs: a bundle may carry only proof-less MintToPool / ShieldedSpend txs"), "{err}");
        assert!(err.contains("tx 1 is not one"), "{err}");
        assert!(bundle_shape_verdict(&[settle]).is_err());
        // an over-cap ChannelOpen, a transfer: the same refusal — nothing but pool txs
        let open = frame(Tx::ChannelOpen {
            id: H256([7; 32]), mandate: H256([1; 32]), payee: H256([2; 32]), asset: H256([9; 32]),
            tip: H256([3; 32]), unit_price: 1, max_steps: u32::MAX, expiry: 1,
        });
        assert!(bundle_shape_verdict(&[open]).is_err());
        assert!(bundle_shape_verdict(&[frame(Tx::Transfer { to: H256([2; 32]), asset: H256([9; 32]), amount: 1 })]).is_err());
        // a pool tx that carries its own proof is the classic per-proof path, not a bundle
        assert!(bundle_shape_verdict(&[spend(vec![1, 2, 3])]).is_err());
        assert!(bundle_shape_verdict(&[mint(vec![1])]).is_err());
        // longer than a block: never picked by build_batch, so never queued
        let too_long: Vec<SignedTx> = (0..=MAX_TXS_PER_BLOCK).map(|_| spend(vec![])).collect();
        assert_eq!(
            bundle_shape_verdict(&too_long).unwrap_err(),
            format!("bad txs: a bundle may carry at most {MAX_TXS_PER_BLOCK} txs (one block)")
        );
        assert_eq!(bundle_shape_verdict(&too_long[..MAX_TXS_PER_BLOCK]), Ok(()));
    }
}

#[cfg(test)]
mod h3_tests {
    use super::{pool_page, POOL_PAGE_MAX};
    use serde_json::json;

    #[test]
    fn h3_pool_pages_are_bounded_and_chain_to_the_end() {
        // empty pool: nothing, no next
        assert_eq!(pool_page(&json!({}), 0), (0, 0, None));
        // default page covers a small pool in one go
        assert_eq!(pool_page(&json!({}), 7), (0, 7, None));
        // explicit pages chain: 0..3 → next 3, 3..6 → next 6, 6..7 → end
        assert_eq!(pool_page(&json!({"limit": 3}), 7), (0, 3, Some(3)));
        assert_eq!(pool_page(&json!({"from": 3, "limit": 3}), 7), (3, 6, Some(6)));
        assert_eq!(pool_page(&json!({"from": 6, "limit": 3}), 7), (6, 7, None));
        // past the end: empty page, no next (a wallet whose cursor == total asks exactly this)
        assert_eq!(pool_page(&json!({"from": 7}), 7), (7, 7, None));
        assert_eq!(pool_page(&json!({"from": 99}), 7), (7, 7, None));
        // limit is capped, never zero
        assert_eq!(pool_page(&json!({"limit": 0}), 7), (0, 1, Some(1)));
        assert_eq!(pool_page(&json!({"limit": 1_000_000}), 3 * POOL_PAGE_MAX), (0, POOL_PAGE_MAX, Some(POOL_PAGE_MAX)));
    }
}

/// R17 (reported 2026-10-06): L-5 — the pool feed is paged under its lock and a page is a
/// slice of the feed; L-6 — the operator submits refuse for free before the SLH-DSA verify,
/// verify with no lock held, and answer "busy" past the verify slots. `SharedHandles` needs
/// a genesis and a signer (`HkApp::new`), so the handler bodies are driven here over the
/// handles they take; `dispatch`'s `params.cert` plumbing around them is unchanged and is
/// exercised by gate-h3 / gate-v1 / gate-g1 against a live devnet.
#[cfg(test)]
mod r17_tests {
    use super::*;
    use hk_consensus::rotation::RotationDomain;
    use hk_consensus::{Approval, HkPub, HkValidator, RootSecret, SetChangeBody};
    use tokio::sync::Semaphore;

    const CHAIN: &str = "hashkinetics-test";

    /// SLH-DSA operations allocate large fixed arrays — anything that reaches the verifier
    /// runs on the stack the node gives its workers (main.rs: 32 MiB).
    fn on_big_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new().stack_size(32 * 1024 * 1024).spawn(f).unwrap().join().unwrap();
    }

    fn feed_of(tag: u8, n: u8) -> PoolFeed {
        (0..n).map(|i| (H256([tag ^ i; 32]), vec![tag, i, i, i, i])).collect()
    }

    fn accepted(v: &Value) -> Option<bool> {
        v.get("result")?.get("accepted")?.as_bool()
    }
    fn queued(v: &Value) -> Option<bool> {
        v.get("result")?.get("queued")?.as_bool()
    }
    fn reason(v: &Value) -> String {
        v.get("result").and_then(|r| r.get("reason")).and_then(|r| r.as_str()).unwrap_or("").to_string()
    }
    fn error(v: &Value) -> String {
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string()
    }

    #[test]
    fn l5_pool_pages_are_slices_of_the_feed_and_chain_to_the_end() {
        let chain = Mutex::new(hk_state::State::default());
        let legacy_feed = feed_of(0x10, 7);
        let asset = H256([0xaa; 32]);
        let asset_feed = feed_of(0x20, 5);
        let legacy = Mutex::new(legacy_feed.clone());
        let by_asset = Mutex::new(BTreeMap::from([(asset, asset_feed.clone())]));
        let notes = |params: &Value| {
            with_pool_feed(&chain, &legacy, &by_asset, params, |feed| page_of(feed, params, |(l, ct)| (*l, ct.clone())))
        };

        // legacy pool: a page is exactly feed[from..to], with the H3 cursor arithmetic
        let (p, asset_label) = notes(&json!({"limit": 3})).unwrap();
        assert_eq!(asset_label, None);
        assert_eq!((p.from, p.to, p.total, p.next), (0, 3, 7, Some(3)));
        assert_eq!(p.items, legacy_feed[0..3].to_vec());
        let (p, _) = notes(&json!({"from": 3, "limit": 3})).unwrap();
        assert_eq!((p.from, p.to, p.next), (3, 6, Some(6)));
        assert_eq!(p.items, legacy_feed[3..6].to_vec());
        let (p, _) = notes(&json!({"from": 6, "limit": 3})).unwrap();
        assert_eq!((p.from, p.to, p.next), (6, 7, None));
        assert_eq!(p.items, legacy_feed[6..7].to_vec());
        // past the end: an empty page, no next (a wallet whose cursor == total asks this)
        let (p, _) = notes(&json!({"from": 99})).unwrap();
        assert_eq!((p.from, p.to, p.total, p.next), (7, 7, 7, None));
        assert!(p.items.is_empty());
        // pages concatenate to the whole feed
        let (mut cursor, mut all) = (Some(0usize), Vec::new());
        while let Some(from) = cursor {
            let (p, _) = notes(&json!({"from": from, "limit": 2})).unwrap();
            all.extend(p.items);
            cursor = p.next;
        }
        assert_eq!(all, legacy_feed);

        // by-asset arm: its own feed, labelled; an asset without a pool is an empty feed
        let (p, asset_label) = notes(&json!({"asset": hex::encode(asset.0), "from": 2, "limit": 2})).unwrap();
        assert_eq!(asset_label, Some(hex::encode(asset.0)));
        assert_eq!((p.from, p.to, p.total, p.next), (2, 4, 5, Some(4)));
        assert_eq!(p.items, asset_feed[2..4].to_vec());
        let other = H256([0xbb; 32]);
        let (p, asset_label) = notes(&json!({"asset": hex::encode(other.0)})).unwrap();
        assert_eq!(asset_label, Some(hex::encode(other.0)));
        assert_eq!((p.from, p.to, p.total, p.next), (0, 0, 0, None));
        assert_eq!(notes(&json!({"asset": "zz"})).unwrap_err(), "asset must be 64-char hex");

        // the leaves-only copy hk_getPoolPath makes: every commitment, nothing else
        let (leaves, _) = with_pool_feed(&chain, &legacy, &by_asset, &json!({}), |feed| {
            feed.iter().map(|(l, _)| l.0).collect::<Vec<[u8; 32]>>()
        })
        .unwrap();
        assert_eq!(leaves, legacy_feed.iter().map(|(l, _)| l.0).collect::<Vec<_>>());
        // and the leaves page projects the same commitments
        let (p, _) = with_pool_feed(&chain, &legacy, &by_asset, &json!({"from": 1, "limit": 4}), |feed| {
            page_of(feed, &json!({"from": 1, "limit": 4}), |(l, _)| l.0)
        })
        .unwrap();
        assert_eq!(p.items, leaves[1..5].to_vec());
    }

    #[test]
    fn l5_pool_path_is_bounded_by_its_slots_and_folds_to_the_root() {
        // R17 review (2026-10-06): the full-feed leaf copy + O(n) tree build of
        // hk_getPoolPath hold one of POOL_PATH_SLOTS; past the bound the caller is told to
        // retry and the feed lock is never taken.
        let chain = Mutex::new(hk_state::State::default());
        let legacy_feed = feed_of(0x10, 5);
        let legacy = Mutex::new(legacy_feed.clone());
        let by_asset = Mutex::new(BTreeMap::new());
        let no_slots = Semaphore::new(0);
        let r = pool_path(&chain, &legacy, &by_asset, &no_slots, &json!({"index": 0}));
        assert!(error(&r).contains("busy: 2 pool-path builds"), "{r}");
        // a missing index is refused before a slot is needed
        let r = pool_path(&chain, &legacy, &by_asset, &no_slots, &json!({}));
        assert!(error(&r).contains("index (leaf index, integer) required"), "{r}");

        // with slots: the answer is `full_tree_path` over the bare leaves, shape unchanged,
        // and the slot comes back
        let slots = Semaphore::new(POOL_PATH_SLOTS);
        let leaves: Vec<[u8; 32]> = legacy_feed.iter().map(|(l, _)| l.0).collect();
        let (siblings, root) = hk_state::pool::full_tree_path(&leaves, 3);
        let r = pool_path(&chain, &legacy, &by_asset, &slots, &json!({"index": 3}));
        assert_eq!(r["result"]["index"], json!(3), "{r}");
        assert_eq!(r["result"]["commitment"], json!(hex::encode(leaves[3])));
        assert_eq!(r["result"]["root"], json!(hex::encode(root)));
        assert_eq!(r["result"]["total"], json!(5));
        assert_eq!(r["result"]["asset"], Value::Null);
        let got: Vec<String> =
            r["result"]["siblings"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();
        assert_eq!(got, siblings.iter().map(hex::encode).collect::<Vec<_>>());
        assert_eq!(slots.available_permits(), POOL_PATH_SLOTS);
        // out of range: refused, and the slot still comes back
        let r = pool_path(&chain, &legacy, &by_asset, &slots, &json!({"index": 5}));
        assert!(error(&r).contains("out of range (pool has 5 commitments)"), "{r}");
        assert_eq!(slots.available_permits(), POOL_PATH_SLOTS);
        // an asset without a pool is an empty feed: every index is out of range
        let r = pool_path(&chain, &legacy, &by_asset, &slots, &json!({"asset": hex::encode([0xbb; 32]), "index": 0}));
        assert!(error(&r).contains("pool has 0 commitments"), "{r}");
        assert_eq!(slots.available_permits(), POOL_PATH_SLOTS);
    }

    fn one_seat(seed: u8, epoch: u64) -> (RootSecret, HkValidator) {
        let root = RootSecret::from_seed(&[seed; 32]);
        let mut v = HkValidator::new(root.public_bytes().to_vec(), HkPub(vec![seed; 60]), 1);
        v.epoch = epoch;
        (root, v)
    }

    fn garbage_rotation(root_pk: Vec<u8>, epoch: u64, sig_len: usize) -> RotationCert {
        RotationCert { root_pk, new_op_pk: HkPub(vec![7u8; 60]), epoch, valid_from_height: 0, root_sig: vec![0u8; sig_len] }
    }

    /// The v0.19.4 rule: a chain that never activates v2, judged at tip + 1 = 101.
    const V1_RULES: RotationRules<'static> = RotationRules { height: 101, chain_id: CHAIN, v2_from: u64::MAX };
    /// The devnet rule: v2 from genesis, judged at tip + 1.
    fn v2_rules(tip: u64) -> RotationRules<'static> {
        RotationRules::new(tip + 1, CHAIN, 0)
    }

    #[test]
    fn l6_rotation_free_refusals_come_before_the_verify_and_the_slot() {
        let (_, seat) = one_seat(1, 3);
        let root = seat.root_pk.clone();
        let validators = Mutex::new(HkValidatorSet::new([seat]));
        let queue = Mutex::new(Vec::new());
        // zero permits: anything that reaches the verifier answers "busy" — so every
        // refusal below provably happened before the slot (and the verify) was needed
        let no_slots = Semaphore::new(0);

        let r = submit_rotation(&validators, &queue, &no_slots, &V1_RULES, garbage_rotation(vec![9u8; ROOT_PK_LEN], 4, ROOT_SIG_LEN));
        assert_eq!(accepted(&r), Some(false));
        assert!(reason(&r).contains("no validator with that root identity"), "{r}");
        for stale in [0, 2, 3] {
            let r = submit_rotation(&validators, &queue, &no_slots, &V1_RULES, garbage_rotation(root.clone(), stale, ROOT_SIG_LEN));
            assert_eq!(accepted(&r), Some(false));
            assert!(reason(&r).contains("stale (cert epoch"), "{r}");
        }
        let r = submit_rotation(&validators, &queue, &no_slots, &V1_RULES, garbage_rotation(root.clone(), 4, 10));
        assert_eq!(accepted(&r), Some(false));
        assert!(reason(&r).contains("root_sig must be"), "{r}");
        assert!(queue.lock().unwrap().is_empty());

        // a well-shaped cert that passes every free check needs a slot: none → busy, nothing queued
        let r = submit_rotation(&validators, &queue, &no_slots, &V1_RULES, garbage_rotation(root.clone(), 4, ROOT_SIG_LEN));
        assert!(error(&r).contains("busy"), "{r}");
        assert!(queue.lock().unwrap().is_empty());

        // L-2: under v2 the valid_from_height window is a free refusal too — from the
        // future, or older than the horizon, never reaches the verifier. At the RPC the
        // rule sits at tip + 1 (the earliest block the cert can commit in), so the
        // activation it is judged against is tip + 2: naming that height is fine, one
        // past it is "from the future".
        let tip = 500_000u64;
        let mut future = garbage_rotation(root.clone(), 4, ROOT_SIG_LEN);
        future.valid_from_height = tip + 3;
        let r = submit_rotation(&validators, &queue, &no_slots, &v2_rules(tip), future);
        assert_eq!(accepted(&r), Some(false));
        assert!(reason(&r).contains("valid_from_height 500003 is past its activation height 500002"), "{r}");
        let mut edge = garbage_rotation(root.clone(), 4, ROOT_SIG_LEN);
        edge.valid_from_height = tip + 2;
        let r = submit_rotation(&validators, &queue, &no_slots, &v2_rules(tip), edge);
        assert!(error(&r).contains("busy"), "{r}"); // inside the window → the verify's turn
        let mut old = garbage_rotation(root.clone(), 4, ROOT_SIG_LEN);
        old.valid_from_height = tip + 1 - hk_consensus::rotation::ROTATION_FRESHNESS_HORIZON - 1;
        let r = submit_rotation(&validators, &queue, &no_slots, &v2_rules(tip), old);
        assert_eq!(accepted(&r), Some(false));
        assert!(reason(&r).contains("stale — valid_from_height"), "{r}");
        // the same values under the v1 rule are not read at all (v0.19.4 behaviour): busy
        let mut legacy = garbage_rotation(root.clone(), 4, ROOT_SIG_LEN);
        legacy.valid_from_height = tip + 2;
        let r = submit_rotation(&validators, &queue, &no_slots, &V1_RULES, legacy);
        assert!(error(&r).contains("busy"), "{r}");
        // inside the window it is the verify's turn: busy
        let mut fresh = garbage_rotation(root.clone(), 4, ROOT_SIG_LEN);
        fresh.valid_from_height = tip + 1;
        let r = submit_rotation(&validators, &queue, &no_slots, &v2_rules(tip), fresh);
        assert!(error(&r).contains("busy"), "{r}");
        assert!(queue.lock().unwrap().is_empty());

        // dedup precedes the verify: with a cert for this root at epoch 4 already queued, a
        // garbage epoch-4 copy is "already queued" — never verified, never a slot
        queue.lock().unwrap().push(garbage_rotation(root.clone(), 4, ROOT_SIG_LEN));
        let r = submit_rotation(&validators, &queue, &no_slots, &V1_RULES, garbage_rotation(root.clone(), 4, ROOT_SIG_LEN));
        assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(false)));
        assert_eq!(queue.lock().unwrap().len(), 1);
        // but a NEWER epoch is not a duplicate — it needs the slot
        let r = submit_rotation(&validators, &queue, &no_slots, &V1_RULES, garbage_rotation(root, 5, ROOT_SIG_LEN));
        assert!(error(&r).contains("busy"), "{r}");
        assert_eq!(queue.lock().unwrap().len(), 1);
    }

    #[test]
    fn l6_rotation_verify_runs_outside_the_lock_and_returns_its_slot() {
        on_big_stack(|| {
            let (root, seat) = one_seat(1, 3);
            let root_pk = seat.root_pk.clone();
            let validators = Mutex::new(HkValidatorSet::new([seat]));
            let queue = Mutex::new(Vec::new());
            let slots = Semaphore::new(CERT_VERIFY_SLOTS);

            // garbage signature of the right size: the verify runs, fails, the slot comes back
            let r = submit_rotation(&validators, &queue, &slots, &V1_RULES, garbage_rotation(root_pk.clone(), 4, ROOT_SIG_LEN));
            assert_eq!(accepted(&r), Some(false));
            assert!(reason(&r).contains("invalid or stale"), "{r}");
            assert!(queue.lock().unwrap().is_empty());
            assert_eq!(slots.available_permits(), CERT_VERIFY_SLOTS);

            // a real cert: verified and queued once; a re-submit is "already queued"
            let c4 = RotationCert::issue(&root, RotationDomain::V1, "", HkPub(vec![4u8; 60]), 4, 0);
            let r = submit_rotation(&validators, &queue, &slots, &V1_RULES, c4.clone());
            assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(true)));
            assert_eq!(r["result"]["epoch"], json!(4));
            let r = submit_rotation(&validators, &queue, &slots, &V1_RULES, c4.clone());
            assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(false)));
            assert_eq!(queue.lock().unwrap().len(), 1);
            // a newer real cert retires the older queued copy
            let c5 = RotationCert::issue(&root, RotationDomain::V1, "", HkPub(vec![5u8; 60]), 5, 0);
            let r = submit_rotation(&validators, &queue, &slots, &V1_RULES, c5);
            assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(true)));
            {
                let q = queue.lock().unwrap();
                assert_eq!(q.len(), 1);
                assert_eq!(q[0].epoch, 5);
            }
            assert_eq!(slots.available_permits(), CERT_VERIFY_SLOTS);
        });
    }

    #[test]
    fn l2_rotation_rpc_demands_v2_from_the_height_and_names_a_v1_cert() {
        on_big_stack(|| {
            let (root, seat) = one_seat(1, 3);
            let validators = Mutex::new(HkValidatorSet::new([seat]));
            let queue = Mutex::new(Vec::new());
            let slots = Semaphore::new(CERT_VERIFY_SLOTS);
            let tip = 1_000u64;

            // a v1 cert (a ≤ v0.19.4 issuer, or `issue-rotation` without the chain id) on a
            // chain past its v2 height: the verify ran (slot taken and returned), the reason
            // says v1 so the operator re-issues instead of suspecting a forgery
            let v1 = RotationCert::issue(&root, RotationDomain::V1, "", HkPub(vec![4u8; 60]), 4, tip + 1);
            let r = submit_rotation(&validators, &queue, &slots, &v2_rules(tip), v1.clone());
            assert_eq!(accepted(&r), Some(false));
            assert!(reason(&r).contains("signed under the v1 domain"), "{r}");
            assert!(reason(&r).contains("issue-rotation <HOME> 4 <TIP+1> hashkinetics-test"), "{r}");
            assert!(queue.lock().unwrap().is_empty());
            assert_eq!(slots.available_permits(), CERT_VERIFY_SLOTS);

            // a v2 cert for ANOTHER chain: refused (the chain id is in the signed bytes)
            let elsewhere = RotationCert::issue(&root, RotationDomain::V2, "hashkinetics-1-deadbeef", HkPub(vec![4u8; 60]), 4, tip + 1);
            let r = submit_rotation(&validators, &queue, &slots, &v2_rules(tip), elsewhere);
            assert_eq!(accepted(&r), Some(false));
            assert!(reason(&r).contains("v2 domain, chain hashkinetics-test"), "{r}");
            assert!(queue.lock().unwrap().is_empty());

            // the same seat's v2 cert for this chain, issued at the tip: queued
            let v2 = RotationCert::issue_for(&root, CHAIN, 0, HkPub(vec![4u8; 60]), 4, tip + 1);
            let r = submit_rotation(&validators, &queue, &slots, &v2_rules(tip), v2.clone());
            assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(true)));
            assert_eq!(queue.lock().unwrap().len(), 1);
            // and the v1 copy is refused on a chain BEFORE its height only as "not v1" would
            // be — i.e. the v2 cert is refused there, the v1 one is what that chain takes
            let before = RotationRules::new(tip + 1, CHAIN, u64::MAX);
            let queue2 = Mutex::new(Vec::new());
            let r = submit_rotation(&validators, &queue2, &slots, &before, v2);
            assert_eq!(accepted(&r), Some(false));
            assert!(reason(&r).contains("invalid or stale (cert epoch 4, current 3)"), "{r}");
            let r = submit_rotation(&validators, &queue2, &slots, &before, v1);
            assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(true)));
            assert_eq!(slots.available_permits(), CERT_VERIFY_SLOTS);
        });
    }

    fn admit_body(root_pk: Vec<u8>, key: u8, not_before: u64, not_after: u64) -> SetChangeBody {
        SetChangeBody {
            chain_id: CHAIN.into(),
            change: SetChange::Admit { root_pk, public_key: HkPub(vec![key; 60]), voting_power: 1 },
            not_before,
            not_after,
        }
    }

    fn garbage_approvals(seats: &[&HkValidator]) -> Vec<Approval> {
        seats.iter().map(|v| Approval { root_pk: v.root_pk.clone(), root_sig: vec![0u8; ROOT_SIG_LEN] }).collect()
    }

    #[test]
    fn l6_set_change_free_refusals_come_before_the_verify_and_the_slot() {
        let tip = 100u64;
        let (_, s1) = one_seat(1, 0);
        let (_, s2) = one_seat(2, 0);
        let (_, s3) = one_seat(3, 0);
        let validators = Mutex::new(HkValidatorSet::new([s1.clone(), s2.clone(), s3.clone()]));
        let queue = Mutex::new(Vec::new());
        let no_slots = Semaphore::new(0);
        let newcomer = RootSecret::from_seed(&[9u8; 32]).public_bytes().to_vec();
        let all3 = garbage_approvals(&[&s1, &s2, &s3]);
        let submit = |body: SetChangeBody, approvals: Vec<Approval>| {
            submit_set_change(&validators, &queue, &no_slots, CHAIN, tip, SetChangeCert { body, approvals })
        };
        let refuses = |body: SetChangeBody, approvals: Vec<Approval>, needle: &str| {
            let r = submit(body, approvals);
            assert_eq!(accepted(&r), Some(false), "{r}");
            assert!(reason(&r).contains(needle), "wanted {needle:?} in {r}");
        };

        // shape, chain id, window — none of them looks at the set
        refuses(admit_body(newcomer.clone(), 9, 150, 140), all3.clone(), "not_after < not_before");
        let mut wrong = admit_body(newcomer.clone(), 9, 101, 500);
        wrong.chain_id = "hashkinetics-1-deadbeef".into();
        refuses(wrong, all3.clone(), "for chain hashkinetics-1-deadbeef — this is hashkinetics-test");
        refuses(admit_body(newcomer.clone(), 9, 1, 99), all3.clone(), "window closed: not_after 99 < tip 100");
        refuses(
            admit_body(newcomer.clone(), 9, tip + SET_CHANGE_HORIZON + 1, u64::MAX),
            all3.clone(),
            "window too far ahead",
        );
        // approvals: present, well-sized, distinct, seated, > 2/3
        refuses(admit_body(newcomer.clone(), 9, 101, 500), vec![], "no approvals");
        refuses(
            admit_body(newcomer.clone(), 9, 101, 500),
            vec![Approval { root_pk: s1.root_pk.clone(), root_sig: vec![0u8; 5] }],
            "SLH-DSA-192s signature",
        );
        refuses(admit_body(newcomer.clone(), 9, 101, 500), garbage_approvals(&[&s1, &s1, &s2]), "duplicate approval");
        let (_, stranger) = one_seat(8, 0);
        refuses(admit_body(newcomer.clone(), 9, 101, 500), garbage_approvals(&[&s1, &s2, &stranger]), "not seated");
        refuses(admit_body(newcomer.clone(), 9, 101, 500), garbage_approvals(&[&s1, &s2]), "approving power 2 is not > 2/3 of 3");
        // the subject, as commit would judge it
        refuses(admit_body(s1.root_pk.clone(), 1, 101, 500), all3.clone(), "already applied — that root is seated");
        refuses(admit_body(newcomer.clone(), 1, 101, 500), all3.clone(), "operational key collides");
        let mut rm = admit_body(newcomer.clone(), 9, 101, 500);
        rm.change = SetChange::Remove { root_pk: newcomer.clone() };
        refuses(rm, all3.clone(), "already applied — that root is not seated");
        let mut sp = admit_body(newcomer.clone(), 9, 101, 500);
        sp.change = SetChange::SetPower { root_pk: newcomer.clone(), voting_power: 2 };
        refuses(sp, all3.clone(), "set-power for a root that is not seated");
        let mut same = admit_body(newcomer.clone(), 9, 101, 500);
        same.change = SetChange::SetPower { root_pk: s1.root_pk.clone(), voting_power: 1 };
        refuses(same, all3.clone(), "already applied — that seat already weighs 1");
        assert!(queue.lock().unwrap().is_empty());

        // every free check passes → a slot is needed: none → busy, nothing queued
        let good = admit_body(newcomer.clone(), 9, 101, 500);
        let r = submit(good.clone(), all3.clone());
        assert!(error(&r).contains("busy"), "{r}");
        assert!(queue.lock().unwrap().is_empty());

        // dedup precedes the verify: an identical body already queued → "already queued",
        // the garbage approvals are never verified and no slot is taken
        queue.lock().unwrap().push(SetChangeCert { body: good.clone(), approvals: all3.clone() });
        let r = submit(good, all3);
        assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(false)));
        assert_eq!(r["result"]["approvals"], json!(3));
        assert_eq!(r["result"]["window"], json!([101, 500]));
        assert_eq!(queue.lock().unwrap().len(), 1);
    }

    #[test]
    fn l6_set_change_verify_runs_outside_the_lock_and_returns_its_slot() {
        on_big_stack(|| {
            let tip = 10u64;
            let (root1, s1) = one_seat(1, 0);
            let validators = Mutex::new(HkValidatorSet::new([s1.clone()]));
            let queue = Mutex::new(Vec::new());
            let slots = Semaphore::new(CERT_VERIFY_SLOTS);
            let newcomer = RootSecret::from_seed(&[2u8; 32]).public_bytes().to_vec();
            let body = admit_body(newcomer, 2, tip + 1, tip + 400);

            // a garbage signature of the right size: the verify runs, fails, the slot comes back
            let r = submit_set_change(&validators, &queue, &slots, CHAIN, tip, SetChangeCert {
                body: body.clone(),
                approvals: garbage_approvals(&[&s1]),
            });
            assert_eq!(accepted(&r), Some(false));
            assert!(reason(&r).contains("invalid approval signature"), "{r}");
            assert!(queue.lock().unwrap().is_empty());
            assert_eq!(slots.available_permits(), CERT_VERIFY_SLOTS);

            // a real 1-of-1 approval: verified and queued once; a re-submit is "already queued"
            let cert = SetChangeCert { body: body.clone(), approvals: vec![Approval::sign(&root1, &body)] };
            let r = submit_set_change(&validators, &queue, &slots, CHAIN, tip, cert.clone());
            assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(true)));
            assert_eq!(r["result"]["approvals"], json!(1));
            assert_eq!(r["result"]["window"], json!([11, 410]));
            let r = submit_set_change(&validators, &queue, &slots, CHAIN, tip, cert);
            assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(false)));
            assert_eq!(queue.lock().unwrap().len(), 1);
            assert_eq!(slots.available_permits(), CERT_VERIFY_SLOTS);
        });
    }
}
