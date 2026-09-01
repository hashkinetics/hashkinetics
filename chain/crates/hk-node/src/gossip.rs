//! C2.3 — tx gossip between mempools (closing C1 finding #1: "a proposer without the
//! tx never includes it").
//!
//! Design: SINGLE-HOP PUSH over the node RPC. When THIS node admits a tx via
//! `hk_submitTx`, it forwards the tx to every configured peer's RPC as
//! `hk_gossipTxs`; peers run the SAME admission gate and do NOT re-forward.
//! With the full peer list in every config (devnet and testnet-1 scale, ≤ tens of
//! nodes), one hop from the origin reaches every mempool — no flood control, no
//! seen-cache, no loops BY CONSTRUCTION. Larger topologies get a real gossip layer
//! later; this is the honest version for the network we actually run.
//!
//! Mechanics: admissions enqueue onto an unbounded channel; one worker micro-batches
//! (100 ms window, ≤512 txs) and POSTs one `hk_gossipTxs` per peer per batch —
//! amortized to ~10 connections/s/peer at any submission rate. Zero new deps: the
//! client is hand-rolled HTTP/1.1 over tokio `TcpStream`, mirroring rpc.rs's server.
//! Push failures are DEBUG-logged and dropped — gossip is best-effort; the sender's
//! own mempool still holds the tx, so at worst inclusion waits for that node's turn
//! to propose (v0 behavior). Clients needing certainty submit to their home node
//! exactly as before.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info};

use hk_state::tx::SignedTx;

/// Cheap clonable enqueue handle carried by `SharedHandles`.
#[derive(Clone)]
pub struct GossipHandle {
    tx: mpsc::UnboundedSender<SignedTx>,
}

impl GossipHandle {
    /// Fire-and-forget: called on the RPC path after a LOCAL (non-gossip) admission.
    pub fn enqueue(&self, t: SignedTx) {
        let _ = self.tx.send(t);
    }
}

/// Spawn the forwarding worker (call from the tokio runtime). `peers` are RPC base
/// addresses, e.g. `http://127.0.0.1:26001`.
pub fn spawn(peers: Vec<String>) -> GossipHandle {
    let (sender, mut rx) = mpsc::unbounded_channel::<SignedTx>();
    info!(peers = peers.len(), "tx gossip live (single-hop push, micro-batched)");
    tokio::spawn(async move {
        loop {
            // Block for the first tx, then micro-batch what arrives within 100 ms.
            let Some(first) = rx.recv().await else { return };
            let mut est = est_json_size(&first);
            let mut batch = vec![first];
            let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
            loop {
                match tokio::time::timeout_at(deadline, rx.recv()).await {
                    Ok(Some(t)) => {
                        est += est_json_size(&t);
                        batch.push(t);
                        // Stay well under rpc.rs's 8 MiB body cap: ≤64 txs (64 × ~50 KB
                        // Lamport-signed transparent ≈ 3 MB) AND ≤3.5 MB estimated —
                        // the byte bound is what matters once MB-scale proofs ride along.
                        if batch.len() >= 64 || est > 3_500_000 {
                            break;
                        }
                    }
                    Ok(None) => return,
                    Err(_) => break, // window elapsed
                }
            }
            let body = serde_json::json!({
                "method": "hk_gossipTxs",
                "params": { "txs": batch }
            })
            .to_string();
            for peer in &peers {
                if let Err(e) = post(peer, &body).await {
                    debug!(%peer, %e, "gossip push failed (peer down? best-effort, tx stays local)");
                }
            }
        }
    });
    GossipHandle { tx: sender }
}

/// Rough JSON wire size of one tx: fixed envelope (hex Lamport pk + sig ≈ 50 KB)
/// plus hex-doubled variable byte fields. Over-estimating is fine; under is not.
fn est_json_size(t: &SignedTx) -> usize {
    let var = match &t.payload {
        hk_state::tx::Tx::ShieldedSpend { proof, stealth_ct, stealth_ct2, .. } => {
            proof.len() + stealth_ct.len() + stealth_ct2.len()
        }
        hk_state::tx::Tx::MintToPool { proof, stealth_ct, .. } => {
            proof.len() + stealth_ct.len()
        }
        _ => 0,
    };
    60_000 + 2 * var
}

/// Minimal HTTP/1.1 POST — the client twin of rpc.rs's hand-rolled server.
/// `pub(crate)`: R1.b's rotation tick reuses it to push certs to peer RPCs.
pub(crate) async fn post(base: &str, body: &str) -> eyre::Result<()> {
    let hostport = base
        .trim()
        .strip_prefix("http://")
        .unwrap_or(base.trim())
        .trim_end_matches('/');
    let mut sock =
        tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(hostport)).await??;
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(req.as_bytes()).await?;
    // Drain the reply (bounded); we only care that the peer got the bytes.
    let mut resp = [0u8; 1024];
    let _ = tokio::time::timeout(Duration::from_secs(3), sock.read(&mut resp)).await;
    Ok(())
}
