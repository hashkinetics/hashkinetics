# The Capacity Sheet — C1 measurements (P3.1 / WS-G)

**The rule (from the tiers doctrine): a number is quoted publicly only from the row it lives in — measured beats configured beats target, and every row says which it is.** This sheet replaces Tier-4 arithmetic with measurement as runs land. Harness: `hk-node storm <RPC> [RATE] [DURATION_S]` (paste each report below verbatim).

## a · State-apply / end-to-end throughput (transparent)

| Date | Env | Rate req | Duration | Sustained tx/s | Avg fill /256 | Real block interval | Notes |
|---|---|---|---|---|---|---|---|
| 2026-08-26 | devnet ×4 localhost, single-RPC submission | MAX | 60s+60s drain | **27.1** | 49.7 (max 256) | 1.83 s | **C1 FINDING #1**: submission ~2,030 tx/s admitted (client not the limit); inclusion capped because **v0 has no tx gossip between mempools** — only the receiving node's proposer turns produce full blocks (256 per ~4 rounds ≈ the observed number). Fix shipped: storm v2 pins each sender to a home node; protocol-level mempool sync filed under C2. One +0 stall at t≈36s under 70k-deep mempool (prune is O(mempool×included) — also C2). |
| 2026-08-26 | devnet ×4, per-node submission (storm v2) | MAX | 60s+60s drain | **107.4** | **250.9** (max 256) | 2.34 s | Fill FIXED (4× v1). Caveats: ran atop run #1's ~108k leftover mempool → per-commit prune cost (O(mempool×included)) stretched the interval, two +0 stalls — the C2 prune/admission item measured, not just suspected. Also: 256 Lamport txs ≈ ~6 MB/block through WAL+store+gossip every ~2 s, all 4 nodes + client on one machine. |
| 2026-08-26 | devnet ×4, per-node, **fresh state (CLEAN BASELINE)** | MAX | 60s+60s drain | **123.1** | **251.8** (max 256) | 2.04 s | **The honest devnet ceiling at the 256-cap config.** Zero stalls, steady +3/5s cadence throughout, 141,814 submitted · 0 rejected. Interval 2.04 s (vs ~1.4 idle) = full ~6 MB Lamport-tx blocks through WAL+store+gossip, 4 nodes + client sharing one machine. Gap to M1 (183) = the C2 lifts, as planned. Note: this genesis is UNPINNED (prover was down at `--fresh`) — fine for transparent storms; regenerate WITH serve before any shielded work. |
| 2026-08-27 | devnet ×4, **SINGLE-RPC submission, C2.3 gossip live** | MAX | 60s+2.6s drain | **99.9** | 165.1 (max 256) | 1.65 s | **C1 FINDING #1 CLOSED.** The run that measured 27.1 pre-gossip now does 99.9 — 3.7×. Proof it's gossip: the no-gossip ceiling for single-RPC is 256/(4·1.65s) ≈ 39 tx/s; 99.9 requires nodes 1–3 proposing gossiped txs. 6,273 admitted = 6,273 included, residual 0. Mempool pinned at exactly 320 = 5 senders × NONCE_WINDOW 64 — **admission is now the throttle, by design** (5,251 refusals = FutureNonce backpressure, not junk in blocks). |
| 2026-08-27 | devnet ×4, per-node + gossip (C2.1–C2.3 in) | MAX | 60s+3.1s drain | **97.4** | 158.2 (max 256) | 1.62 s | Same as single-RPC within noise — topology no longer matters (the point of gossip). Below the 123.1 baseline BECAUSE the nonce window (64) bounds the whole pipeline at 320 pending and refusal-backoff paces senders: bounded queues traded ~20% peak. Interval improved 2.04→1.62 s (indexed prune + no junk). Lift knob: `HK_NONCE_WINDOW` (shipped with the 1024-cap). |
| 2026-08-27 | devnet ×4, **1024-cap + HK_NONCE_WINDOW=256** (C2.4) | MAX | 60s+2.1s drain | **274.1** | **636.3 (max 1024 — cap reached)** | 2.32 s | **THE M1-SHAPED CONFIG CLEARS THE M1 BAR ON DEVNET: 274 > 183, +50% headroom.** 2.2× the 123.1 baseline. Pipeline 1,280 pending (5×256 window) pinned throughout; 17,693 admitted, residual 0, 2.1 s drain. Interval 1.62→2.32 s = the next wall is BLOCK BYTES (avg ~15 MB, full blocks ~25 MB of Lamport txs through WAL+store+gossip, 4 nodes + client on ONE machine) — a transparent-tx artifact; shielded txs are ~2.7 KB + one aggregate. Remaining to quote M1 publicly: the 30-min WAN run on the public testnet, unchanged. |
| ⬜ | devnet | MAX | 30 min | ⬜ | ⬜ | ⬜ | endurance point |
| ⬜ | **public testnet (WAN)** | MAX | 30 min | ⬜ | ⬜ | ⬜ | **THE M1 ROW — 183 tx/s sustained = milestone quotable** |

## b · Gossip at MB-scale blocks

Measured implicitly when storm runs concurrently with shielded demo traffic (proof-carrying blocks). | Date ⬜ | max block bytes seen ⬜ | interval impact ⬜ |

## c · Block-time floor over WAN

Landed by the soak itself: real interval distribution from the public testnet explorer data. | Date ⬜ | p50 ⬜ | p95 ⬜ |

## d · Aggregation scaling curve — ✅ MEASURED 2026-08-28 (agg-bench, 6 points, one GPU)

**T_agg(N) ≈ 2.66 s + 0.2882 s·N** (least-squares over 6 points; residuals ≤ 2.24 s from N=4 to N=256 — linear, no wall). Aggregate size **constant 1,242 KB at every N**: 256 compressed spends (~318 MB of individual proofs) fold to ONE 1.24 MB STARK — 256× wire compression, ONE verify per block. Harness: `hk-node agg-bench` (local pool, no devnet; proofs by store-id — serve holds them, requests stay bytes-sized).

| N | T_agg (ms) | Aggregate size | Date/GPU |
|---|---|---|---|
| 3 | 2,902 (measured 0.9.9) | 1,242 KB | 2026-08-17 · RTX 5090 |
| 4 | 2,922 | 1,242 KB | 2026-08-28 · RTX 5090 |
| 10 | 4,596 | 1,242 KB | 2026-08-28 · RTX 5090 |
| 25 | 8,834 | 1,242 KB | 2026-08-28 · RTX 5090 |
| 50 | 18,762 | 1,242 KB | 2026-08-28 · RTX 5090 |
| 100 | 33,721 | 1,242 KB | 2026-08-28 · RTX 5090 |
| 256 | **75,389** | 1,242 KB | 2026-08-28 · RTX 5090 |
| fit | T_agg(N) ≈ 2.66 s + 0.2882 s·N | — | least-squares over 6 points |

**Farm sizing (GPUs ≈ b × R, this GPU class, SEQUENTIAL single-stream measurement — conservative; concurrency only improves it):** R=64/s → ~19 GPUs · R=256/s → ~74 GPUs · R=1024/s → ~296 GPUs. Per-GPU fold throughput 1/b ≈ 3.5 proofs/s; the 2.66 s fixed overhead amortizes away at scale. Same session: 256 compressed spend proofs generated at 2.3 s avg each (9.9 min total, one GPU — wallet-side proving cost).

**Quote lines this row unlocks (label "RTX 5090, measured"):** "256 shielded spends → one 1.24 MB proof in 75 s on a single gaming GPU" · "aggregate size is constant — 4 or 256 txs, same 1.24 MB." C3.A projection from b (tree-of-aggregates, 1024-tx block: 16 parallel sub-folds ≈ 21 s + root fold ≈ 7 s ≈ ~28 s wall) stays GOLD until demoed.

## e · Mempool admission under storm

**Landed 2026-08-27 (C2.1/C2.2):** indexed mempool (txid + sender-slot + pending-nullifier sets), admission mirrors apply's preconditions, O(mempool)-with-O(1)-tests prune. Storm evidence: rejected counts are pure FutureNonce backpressure (window 64), **included == admitted** (zero junk reached blocks), residual 0 after ≤3.1 s drains (was 60 s+ pre-C2 with stalls), block interval 2.04 → 1.62 s under identical load. Cap 8192 (`HK_MEMPOOL_CAP`), window 64 (`HK_NONCE_WINDOW`).

## Quote discipline

Until the M1 row is green: public materials keep saying "183 TPS at today's measured config" (Tier-1 arithmetic from the 256/1.4s measured pair) and "183,000/s effective via channels" — both already provenance-labeled. The first storm report upgrades nothing publicly by itself; **the 30-min public-testnet run is what turns M1 into a quotable fact.**
