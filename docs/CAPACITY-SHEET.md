# The Capacity Sheet — C1 measurements (P3.1 / WS-G)

**The rule (from the tiers doctrine): a number is quoted publicly only from the row it lives in — measured beats configured beats target, and every row says which it is.** This sheet replaces Tier-4 arithmetic with measurement as runs land. Harness: `hk-node storm <RPC> [RATE] [DURATION_S]` (paste each report below verbatim).

## a · State-apply / end-to-end throughput (transparent)

| Date | Env | Rate req | Duration | Sustained tx/s | Avg fill /256 | Real block interval | Notes |
|---|---|---|---|---|---|---|---|
| 2026-08-26 | devnet ×4 localhost, single-RPC submission | MAX | 60s+60s drain | **27.1** | 49.7 (max 256) | 1.83 s | **C1 FINDING #1**: submission ~2,030 tx/s admitted (client not the limit); inclusion capped because **v0 has no tx gossip between mempools** — only the receiving node's proposer turns produce full blocks (256 per ~4 rounds ≈ the observed number). Fix shipped: storm v2 pins each sender to a home node; protocol-level mempool sync filed under C2. One +0 stall at t≈36s under 70k-deep mempool (prune is O(mempool×included) — also C2). |
| 2026-08-26 | devnet ×4, per-node submission (storm v2) | MAX | 60s+60s drain | **107.4** | **250.9** (max 256) | 2.34 s | Fill FIXED (4× v1). Caveats: ran atop run #1's ~108k leftover mempool → per-commit prune cost (O(mempool×included)) stretched the interval, two +0 stalls — the C2 prune/admission item measured, not just suspected. Also: 256 Lamport txs ≈ ~6 MB/block through WAL+store+gossip every ~2 s, all 4 nodes + client on one machine. |
| 2026-08-26 | devnet ×4, per-node, **fresh state (CLEAN BASELINE)** | MAX | 60s+60s drain | **123.1** | **251.8** (max 256) | 2.04 s | **The honest devnet ceiling at the 256-cap config.** Zero stalls, steady +3/5s cadence throughout, 141,814 submitted · 0 rejected. Interval 2.04 s (vs ~1.4 idle) = full ~6 MB Lamport-tx blocks through WAL+store+gossip, 4 nodes + client sharing one machine. Gap to M1 (183) = the C2 lifts, as planned. Note: this genesis is UNPINNED (prover was down at `--fresh`) — fine for transparent storms; regenerate WITH serve before any shielded work. |
| ⬜ | devnet, after C2 lifts (1024-cap, admission pre-checks, indexed prune) | MAX | 60s | ⬜ | ⬜ | ⬜ | the M1-shaped config, pre-WAN |
| ⬜ | devnet | MAX | 30 min | ⬜ | ⬜ | ⬜ | endurance point |
| ⬜ | **public testnet (WAN)** | MAX | 30 min | ⬜ | ⬜ | ⬜ | **THE M1 ROW — 183 tx/s sustained = milestone quotable** |

## b · Gossip at MB-scale blocks

Measured implicitly when storm runs concurrently with shielded demo traffic (proof-carrying blocks). | Date ⬜ | max block bytes seen ⬜ | interval impact ⬜ |

## c · Block-time floor over WAN

Landed by the soak itself: real interval distribution from the public testnet explorer data. | Date ⬜ | p50 ⬜ | p95 ⬜ |

## d · Aggregation scaling curve (THE unknown: T_agg(N) = a + b·N)

Known point: N=3 → 2,902 ms (RTX 5090, 0.9.9). Needed: N = 10 / 50 / 100 / 256 on one GPU. Harness = phase 2 (drives prove_spend(compressed)×N → `/aggregate`, GPU-hours; runs during the soak).

| N | T_agg (ms) | Aggregate size | Date/GPU |
|---|---|---|---|
| 3 | 2,902 (measured 0.9.9) | 1,242 KB | 2026-08-17 · RTX 5090 |
| 10 | ⬜ | ⬜ | |
| 50 | ⬜ | ⬜ | |
| 100 | ⬜ | ⬜ | |
| 256 | ⬜ | ⬜ | |

## e · Mempool admission under storm

From storm reports: rpc-rejected count ⬜ · mempool residual after drain ⬜ · any stuck-tx behavior ⬜. (Admission pre-checks are a C2 item; v1 admission is deliberately permissive — rejections become receipts.)

## Quote discipline

Until the M1 row is green: public materials keep saying "183 TPS at today's measured config" (Tier-1 arithmetic from the 256/1.4s measured pair) and "183,000/s effective via channels" — both already provenance-labeled. The first storm report upgrades nothing publicly by itself; **the 30-min public-testnet run is what turns M1 into a quotable fact.**
