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
//! Mechanics: admissions enqueue onto a channel bounded in bytes (`GOSSIP_QUEUE_MAX_BYTES`); one
//! worker micro-batches (100 ms window, ≤ `GOSSIP_BATCH_MAX_TXS` txs and ≤
//! `GOSSIP_BATCH_MAX_EST` estimated bytes, cut by `BatchCutter`) and POSTs one `hk_gossipTxs`
//! per peer per batch —
//! amortized to ~10 connections/s/peer at any submission rate. Zero new deps: the
//! client is hand-rolled HTTP/1.1 over tokio `TcpStream`, mirroring rpc.rs's server.
//! Push failures are DEBUG-logged and dropped — gossip is best-effort; the sender's
//! own mempool still holds the tx, so at worst inclusion waits for that node's turn
//! to propose (v0 behavior). Clients needing certainty submit to their home node
//! exactly as before.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use hk_state::tx::SignedTx;

/// v0.19.12: the most encoded tx bytes (`mempool::tx_encoded_len`) waiting in the gossip
/// queue. An admission past it is not gossiped (a debug line): the tx stays in this node's pool
/// and rides this node's own proposals — gossip is best-effort.
const GOSSIP_QUEUE_MAX_BYTES: usize = 64 * 1024 * 1024;

/// v0.19.12: the encoded bytes handed to the gossip worker and not yet taken by it —
/// shared by the handle (which reserves) and the worker (which releases).
#[derive(Clone, Default)]
struct QueuedBytes(Arc<AtomicUsize>);

impl QueuedBytes {
    /// Reserve `size` bytes if the total stays within `max`; `false` (nothing reserved) if not.
    fn reserve(&self, size: usize, max: usize) -> bool {
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |q| q.checked_add(size).filter(|n| *n <= max))
            .is_ok()
    }

    /// Give back `size` bytes: the worker took the tx, or the send failed.
    fn release(&self, size: usize) {
        let _ = self.0.fetch_update(Ordering::AcqRel, Ordering::Acquire, |q| Some(q.saturating_sub(size)));
    }

    #[cfg(test)]
    fn get(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }
}

/// Cheap clonable enqueue handle carried by `SharedHandles`.
#[derive(Clone)]
pub struct GossipHandle {
    tx: mpsc::UnboundedSender<(SignedTx, usize)>,
    /// The bytes waiting for the worker, against `max` (`GOSSIP_QUEUE_MAX_BYTES`).
    queued: QueuedBytes,
    max: usize,
}

impl GossipHandle {
    /// Fire-and-forget: called on the RPC path after a LOCAL (non-gossip)
    /// admission. The tx's encoded bytes are reserved against the queue's bound
    /// first; past it the tx is not queued.
    pub fn enqueue(&self, t: SignedTx) {
        let size = crate::mempool::tx_encoded_len(&t);
        if !self.queued.reserve(size, self.max) {
            debug!(size, "gossip queue full (bytes): tx not gossiped — it stays in this node's pool");
            return;
        }
        if self.tx.send((t, size)).is_err() {
            self.queued.release(size);
        }
    }
}

/// Most txs one `hk_gossipTxs` push carries (64 × ~50 KB Lamport-signed transparent
/// ≈ 3 MB as JSON).
const GOSSIP_BATCH_MAX_TXS: usize = 64;

/// The most ESTIMATED JSON bytes (`est_json_size`) one push carries — well under rpc.rs's
/// 8 MiB request cap; the byte bound is what matters once MB-scale proofs ride along.
/// v0.19.12: checked BEFORE a tx joins the batch. A tx that would take the batch past
/// it opens the next batch instead (it is carried, never dropped), so a push stays under the
/// bound unless a single tx is estimated above it on its own, and such a tx goes alone.
const GOSSIP_BATCH_MAX_EST: usize = 3_500_000;

/// Spawn the forwarding worker (call from the tokio runtime). `peers` are RPC base
/// addresses, e.g. `http://127.0.0.1:26001`.
pub fn spawn(peers: Vec<String>) -> GossipHandle {
    let (sender, mut rx) = mpsc::unbounded_channel::<(SignedTx, usize)>();
    let queued = QueuedBytes::default();
    let taken = queued.clone();
    info!(peers = peers.len(), "tx gossip live (single-hop push, micro-batched)");
    tokio::spawn(async move {
        // The batches are cut by `BatchCutter`, which keeps the tx a batch could not take.
        let mut cutter = BatchCutter::default();
        loop {
            // Open a batch — with the tx the last one could not take, or the next to arrive —
            // then micro-batch what arrives within 100 ms.
            let mut more = if cutter.is_open() {
                cutter.has_room()
            } else {
                match rx.recv().await {
                    Some((t, size)) => {
                        taken.release(size);
                        cutter.offer(t)
                    }
                    None => return,
                }
            };
            let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
            while more {
                match tokio::time::timeout_at(deadline, rx.recv()).await {
                    Ok(Some((t, size))) => {
                        taken.release(size);
                        more = cutter.offer(t);
                    }
                    Ok(None) => return,
                    Err(_) => break, // window elapsed
                }
            }
            let batch = cutter.close();
            // Typed serialization straight from the txs (`gossip_body`), never through a
            // `serde_json::Value`. A batch that does not serialize is dropped with a warning —
            // its txs stay in this node's pool — and the worker carries on.
            let body = match gossip_body(&batch) {
                Ok(body) => body,
                Err(e) => {
                    warn!(%e, txs = batch.len(), "gossip push dropped: the batch did not serialize (its txs stay in this node's pool)");
                    continue;
                }
            };
            for peer in &peers {
                if let Err(e) = post(peer, &body).await {
                    debug!(%peer, %e, "gossip push failed (peer down? best-effort, tx stays local)");
                }
            }
        }
    });
    GossipHandle { tx: sender, queued, max: GOSSIP_QUEUE_MAX_BYTES }
}

/// v0.19.12: cuts the queue's txs, in arrival order, into push batches. A batch closes at
/// `GOSSIP_BATCH_MAX_TXS` txs, or BEFORE a tx that would take its estimate past
/// `GOSSIP_BATCH_MAX_EST`: that tx is kept and opens the next batch, so nothing is dropped or
/// sent twice, and a tx estimated above the bound on its own is a batch of one. The worker
/// (`spawn`) drives it — open, offer while it takes more, close — and the tests drive it the
/// same way.
#[derive(Default)]
struct BatchCutter {
    open: Vec<SignedTx>,
    est: usize,
    carry: Option<SignedTx>,
}

impl BatchCutter {
    /// A batch is open: it holds a tx (the carried one after a `close`).
    fn is_open(&self) -> bool {
        !self.open.is_empty()
    }

    /// The open batch's count is under `GOSSIP_BATCH_MAX_TXS`.
    fn has_room(&self) -> bool {
        self.open.len() < GOSSIP_BATCH_MAX_TXS
    }

    /// The next tx in arrival order. `true` while the batch takes more (the caller keeps
    /// receiving); `false` once it must close — the count is reached, or `t` would take the
    /// estimate past the bound, and `t` is then kept to open the next batch.
    fn offer(&mut self, t: SignedTx) -> bool {
        debug_assert!(self.carry.is_none(), "a tx offered after a carry: close the batch first");
        let e = est_json_size(&t);
        if self.is_open() && self.est.saturating_add(e) > GOSSIP_BATCH_MAX_EST {
            self.carry = Some(t);
            return false;
        }
        self.est = self.est.saturating_add(e);
        self.open.push(t);
        self.has_room()
    }

    /// Hand out the open batch; the carried tx, if any, opens the next one.
    fn close(&mut self) -> Vec<SignedTx> {
        let batch = std::mem::take(&mut self.open);
        self.est = 0;
        if let Some(t) = self.carry.take() {
            self.offer(t);
        }
        batch
    }
}

/// v0.19.12: the `hk_gossipTxs` request, serialized as written — `method`, then
/// `params.txs`.
#[derive(Serialize)]
struct GossipRequest<'a> {
    method: &'static str,
    params: GossipParams<'a>,
}

#[derive(Serialize)]
struct GossipParams<'a> {
    txs: &'a [SignedTx],
}

/// v0.19.12: the push body, by typed serialization (`serde_json::to_string`) straight
/// from the txs, so every `Amount` (a u128) is written as the number it is, whatever its value;
/// a `serde_json::Value` holds integers up to u64::MAX only. The JSON is the one the `json!`
/// form wrote for every tx whose integers fit a u64, up to the order of keys inside each tx,
/// which the receiving door ignores.
fn gossip_body(txs: &[SignedTx]) -> serde_json::Result<String> {
    serde_json::to_string(&GossipRequest { method: "hk_gossipTxs", params: GossipParams { txs } })
}

/// v0.19.12: what `est_json_size` allows for everything in a tx that is not a
/// variable-length field — the field names, the variant tag, the punctuation, the 32-byte ids
/// (a JSON array of 32 numbers, at most 129 characters each) and the integers (a u128 is at
/// most 39 digits). The widest variant, `ShieldedSpend`, needs ≈ 1.3 KB of it with the
/// envelope's own fields; 4 KiB leaves room.
const EST_FIXED_JSON: usize = 4096;

/// An upper bound on one tx's JSON size in an `hk_gossipTxs` body — over-estimating is fine,
/// under-estimating is not (a body past the peer's 8 MiB request cap is refused whole).
/// v0.19.12: every variable-length field of every variant is counted at its widest JSON
/// form — the byte fields at two characters per byte (`hk_state::tx`'s format-aware fields
/// travel as hex in JSON): the Lamport key and signature, the proofs, the stealth ciphertexts,
/// the burn destination; the asset symbol, a `String`, at six characters per byte (the
/// `\u00XX` escape of a control byte) — plus [`EST_FIXED_JSON`] for the rest. The match names
/// every variant, so a new variant does not compile until it is counted here.
fn est_json_size(t: &SignedTx) -> usize {
    use hk_state::tx::Tx;
    let hex = |n: usize| n.saturating_mul(2);
    let var = match &t.payload {
        Tx::ShieldedSpend { proof, stealth_ct, stealth_ct2, .. } => {
            hex(proof.len()).saturating_add(hex(stealth_ct.len())).saturating_add(hex(stealth_ct2.len()))
        }
        Tx::MintToPool { proof, stealth_ct, .. } => hex(proof.len()).saturating_add(hex(stealth_ct.len())),
        Tx::AssetBurn { destination, .. } => hex(destination.len()),
        Tx::AssetRegister { symbol, .. } => symbol.len().saturating_mul(6),
        Tx::Transfer { .. }
        | Tx::MandateCreate { .. }
        | Tx::MandateSpend { .. }
        | Tx::MandateRevoke { .. }
        | Tx::ChannelOpen { .. }
        | Tx::ChannelSettle { .. }
        | Tx::ChannelRefund { .. }
        | Tx::AccountCreate { .. }
        | Tx::AssetMint { .. }
        | Tx::AssetFreeze { .. }
        | Tx::AssetPause { .. } => 0,
    };
    EST_FIXED_JSON
        .saturating_add(hex(t.lamport_pk.len()))
        .saturating_add(hex(t.sig.len()))
        .saturating_add(var)
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

#[cfg(test)]
mod tests {
    use super::*;
    use hk_primitives::H256;
    use hk_state::assets::AssetPolicy;
    use hk_state::tx::Tx;

    const ID: H256 = H256([0xFF; 32]);

    /// Every fixed field at its widest JSON form — 32-byte ids of 0xFF bytes (`[255,…]`, 129
    /// characters), integers at their maximum — under a full Lamport envelope.
    fn widest(payload: Tx) -> SignedTx {
        SignedTx {
            sender: ID,
            nonce: u64::MAX,
            payload,
            next_auth: ID,
            lamport_pk: vec![0xFF; hk_crypto::lamport::PK_LEN],
            sig: vec![0xFF; hk_crypto::lamport::SIG_LEN],
        }
    }

    fn json_len(t: &SignedTx) -> usize {
        serde_json::to_vec(t).unwrap().len()
    }

    /// `b` is `a` with one variable-length field longer: the estimate grows, by at least as much
    /// as the JSON does.
    fn grows(a: &SignedTx, b: &SignedTx) {
        assert!(est_json_size(b) > est_json_size(a));
        assert!(est_json_size(b) - est_json_size(a) >= json_len(b) - json_len(a));
    }

    /// v0.19.12: the estimate bounds the real JSON from above for every variant at its
    /// widest (control bytes in the symbol included), grows with every variable-length field —
    /// symbol, destination, proofs, stealth ciphertexts, key and signature — by at least the
    /// JSON's growth, and a push of estimates under the bound is a body under the estimate.
    /// KILL: drop any field from `est_json_size` (its `grows` fails), or count the symbol at
    /// one character per byte (the control-byte symbol's JSON passes the estimate).
    #[test]
    fn est_json_size_bounds_every_variant_and_grows_with_every_field() {
        let max = u128::MAX;
        let policy = AssetPolicy { mintable: false, freezable: false, pausable: false, pool_eligible: false };
        let variants = vec![
            Tx::Transfer { to: ID, asset: ID, amount: max },
            Tx::MandateCreate {
                id: ID,
                parent: Some(ID),
                holder: ID,
                asset: ID,
                rate_per_sec: max,
                buffer_max: max,
                per_tx_max: max,
                initial_buffer: max,
                expiry: u64::MAX,
                tier: u8::MAX,
            },
            Tx::MandateSpend { leaf: ID, to: ID, amount: max },
            Tx::MandateRevoke { target: ID },
            Tx::ChannelOpen {
                id: ID,
                mandate: ID,
                payee: ID,
                asset: ID,
                tip: ID,
                unit_price: max,
                max_steps: u32::MAX,
                expiry: u64::MAX,
            },
            Tx::ChannelSettle { id: ID, word: ID, step: u32::MAX },
            Tx::ChannelRefund { id: ID },
            Tx::MintToPool { asset: ID, value: max, commitment: ID, proof: vec![0xFF; 1000], stealth_ct: vec![0xFF; 300] },
            Tx::ShieldedSpend {
                anchor: ID,
                nullifier: ID,
                out_commitment: ID,
                out2_commitment: ID,
                fee: max,
                credit: Some(ID),
                mandate: Some(ID),
                proof: vec![0xFF; 1000],
                stealth_ct: vec![0xFF; 300],
                stealth_ct2: vec![0xFF; 300],
            },
            Tx::AccountCreate { id: ID, auth_commit: ID, asset: ID, amount: max },
            Tx::AssetRegister { asset: ID, symbol: "\u{1}".repeat(16), decimals: u8::MAX, policy },
            Tx::AssetMint { asset: ID, to: ID, amount: max },
            Tx::AssetBurn { asset: ID, amount: max, destination: vec![0xFF; 64] },
            Tx::AssetFreeze { asset: ID, account: ID, frozen: false },
            Tx::AssetPause { asset: ID, paused: false },
        ];
        for (i, payload) in variants.into_iter().enumerate() {
            let t = widest(payload);
            assert!(
                est_json_size(&t) >= json_len(&t),
                "variant {i}: estimate {} < JSON {}",
                est_json_size(&t),
                json_len(&t)
            );
        }
        // every variable-length field grows the estimate at least as much as the JSON
        let sym = |s: &str| widest(Tx::AssetRegister { asset: ID, symbol: s.to_string(), decimals: 0, policy });
        grows(&sym(""), &sym("\u{1}".repeat(1000).as_str()));
        grows(&sym("A"), &sym("A".repeat(1000).as_str()));
        let burn = |n: usize| widest(Tx::AssetBurn { asset: ID, amount: 1, destination: vec![0xAB; n] });
        grows(&burn(0), &burn(1000));
        let mint = |proof: usize, ct: usize| {
            widest(Tx::MintToPool { asset: ID, value: 1, commitment: ID, proof: vec![1; proof], stealth_ct: vec![2; ct] })
        };
        grows(&mint(0, 0), &mint(100_000, 0));
        grows(&mint(0, 0), &mint(0, 4096));
        let spend = |proof: usize, ct: usize, ct2: usize| {
            widest(Tx::ShieldedSpend {
                anchor: ID,
                nullifier: ID,
                out_commitment: ID,
                out2_commitment: ID,
                fee: 1,
                credit: None,
                mandate: None,
                proof: vec![1; proof],
                stealth_ct: vec![2; ct],
                stealth_ct2: vec![3; ct2],
            })
        };
        grows(&spend(0, 0, 0), &spend(100_000, 0, 0));
        grows(&spend(0, 0, 0), &spend(0, 4096, 0));
        grows(&spend(0, 0, 0), &spend(0, 0, 4096));
        let mut bare = widest(Tx::ChannelRefund { id: ID });
        bare.lamport_pk.clear();
        bare.sig.clear();
        grows(&bare, &widest(Tx::ChannelRefund { id: ID }));
        // a full push of the widest transfers (u128::MAX amounts): under the push bound, and the
        // body the worker sends — the wrapper and the commas included — under the summed
        // estimate, the amount written as the number it is
        let batch: Vec<SignedTx> =
            (0..GOSSIP_BATCH_MAX_TXS).map(|_| widest(Tx::Transfer { to: ID, asset: ID, amount: max })).collect();
        let est: usize = batch.iter().map(est_json_size).sum();
        assert!(est <= GOSSIP_BATCH_MAX_EST, "{est}");
        let body = gossip_body(&batch).expect("a batch with u128::MAX amounts serializes");
        assert!(body.len() <= est, "{} > {est}", body.len());
        assert!(body.starts_with("{\"method\":\"hk_gossipTxs\",\"params\":{\"txs\":["), "{}", &body[..64]);
        assert!(body.contains(&format!("\"amount\":{max}")));
        let back: serde_json::Value = serde_json::from_str(&body).expect("the body is JSON");
        assert_eq!(back["params"]["txs"].as_array().map(|a| a.len()), Some(GOSSIP_BATCH_MAX_TXS));
    }

    /// The worker's loop over a list instead of a channel and a clock: open a batch (the carried
    /// tx, or the next arrival), offer arrivals while the batch takes more, close it — the calls
    /// `spawn` makes, in its order. Returns the batches.
    fn cut(arrivals: Vec<SignedTx>) -> Vec<Vec<SignedTx>> {
        let mut cutter = BatchCutter::default();
        let mut arrivals = arrivals.into_iter();
        let mut out = Vec::new();
        loop {
            let mut more = if cutter.is_open() {
                cutter.has_room()
            } else {
                match arrivals.next() {
                    Some(t) => cutter.offer(t),
                    None => return out,
                }
            };
            while more {
                match arrivals.next() {
                    Some(t) => more = cutter.offer(t),
                    None => break,
                }
            }
            out.push(cutter.close());
        }
    }

    /// A transfer under a full envelope (estimate 53,248), numbered by its nonce.
    fn small(n: u64) -> SignedTx {
        let mut t = widest(Tx::Transfer { to: ID, asset: ID, amount: 1 });
        t.nonce = n;
        t
    }

    /// A shield whose proof length sets its estimate, numbered by its nonce.
    fn shield(n: u64, proof: usize) -> SignedTx {
        let mut t = widest(Tx::MintToPool { asset: ID, value: 1, commitment: ID, proof: vec![7; proof], stealth_ct: vec![] });
        t.nonce = n;
        t
    }

    fn nonces(batches: &[Vec<SignedTx>]) -> Vec<Vec<u64>> {
        batches.iter().map(|b| b.iter().map(|t| t.nonce).collect()).collect()
    }

    /// v0.19.12: a push batch closes BEFORE the tx that would take its estimate past
    /// `GOSSIP_BATCH_MAX_EST`; that tx opens the next batch; every tx is sent once, in arrival
    /// order; a batch also closes at `GOSSIP_BATCH_MAX_TXS`; a tx estimated above the bound on its
    /// own goes alone. KILL: push the tx before checking the bound (the first batch passes the
    /// bound), drop the carried tx (it is missing from every batch), or keep it in both batches
    /// (it is sent twice).
    #[test]
    fn a_push_batch_closes_before_the_tx_that_would_pass_the_bound() {
        let e_small = est_json_size(&small(0));
        assert_eq!(e_small, 53_248);
        // ten smalls, then a shield that does not fit beside them, then ten more smalls
        let big = shield(10, 1_500_000);
        let e_big = est_json_size(&big);
        assert!(10 * e_small + e_big > GOSSIP_BATCH_MAX_EST && e_big <= GOSSIP_BATCH_MAX_EST);
        let fit_after_big = (GOSSIP_BATCH_MAX_EST - e_big) / e_small;
        assert_eq!(fit_after_big, 8);
        let mut arrivals: Vec<SignedTx> = (0..10).map(small).collect();
        arrivals.push(big);
        arrivals.extend((11..21).map(small));
        let batches = cut(arrivals.clone());
        let got = nonces(&batches);
        assert_eq!(got[0], (0..10).collect::<Vec<u64>>(), "closed before the shield");
        assert_eq!(got[1], std::iter::once(10).chain(11..19).collect::<Vec<u64>>(), "the shield opens the next batch");
        assert_eq!(got[2], vec![19, 20]);
        // nothing lost, nothing sent twice, the order kept
        assert_eq!(got.concat(), arrivals.iter().map(|t| t.nonce).collect::<Vec<_>>());
        // every batch of more than one tx stays within the bound
        for b in &batches {
            let est: usize = b.iter().map(est_json_size).sum();
            assert!(b.len() == 1 || est <= GOSSIP_BATCH_MAX_EST, "{} txs, {est}", b.len());
        }
        // the count cap: 64 smalls fill a batch (within the bound), the 65th opens the next
        assert!(GOSSIP_BATCH_MAX_TXS * e_small <= GOSSIP_BATCH_MAX_EST);
        let many: Vec<SignedTx> = (0..GOSSIP_BATCH_MAX_TXS as u64 + 1).map(small).collect();
        assert_eq!(cut(many).iter().map(|b| b.len()).collect::<Vec<_>>(), vec![GOSSIP_BATCH_MAX_TXS, 1]);
        // a tx estimated above the bound on its own goes alone, between its neighbours
        let huge = shield(1, 1_800_000);
        assert!(est_json_size(&huge) > GOSSIP_BATCH_MAX_EST);
        assert_eq!(nonces(&cut(vec![small(0), huge, small(2)])), vec![vec![0], vec![1], vec![2]]);
    }

    /// v0.19.12: the gossip queue is bounded in bytes — an admission past the bound
    /// is not queued (it stays in the node's pool), the bytes come back as the worker takes txs,
    /// and a send to a stopped worker gives its reservation back. KILL: drop the reservation
    /// (the third tx queues) or a release (the queue stays full).
    #[test]
    fn the_gossip_queue_is_bounded_in_bytes() {
        let t = small(0);
        let size = crate::mempool::tx_encoded_len(&t);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let h = GossipHandle { tx, queued: QueuedBytes::default(), max: 2 * size };
        for _ in 0..3 {
            h.enqueue(t.clone());
        }
        // two fit; the third was not queued
        assert_eq!(h.queued.get(), 2 * size);
        let (_, took) = rx.try_recv().expect("the first is queued");
        assert_eq!(took, size);
        let (_, took2) = rx.try_recv().expect("the second is queued");
        assert!(rx.try_recv().is_err(), "the third is not");
        // the worker took one and gives its bytes back: room for one more
        h.queued.release(took);
        h.enqueue(t.clone());
        assert_eq!(h.queued.get(), 2 * size);
        let (_, took3) = rx.try_recv().expect("queued once there was room");
        h.queued.release(took2);
        h.queued.release(took3);
        assert_eq!(h.queued.get(), 0);
        // a stopped worker: the send fails and the reservation comes back
        drop(rx);
        h.enqueue(t);
        assert_eq!(h.queued.get(), 0);
    }
}
