# P6 — the multi-asset shielded pool: one pool per asset, no circuit change

**Written 2026-09-09 (Yadu: "build multi-asset pool (P6)").** Why now: the bridge (B1, `docs/BRIDGE-SEPOLIA-USDC-PLAN.md`) brings `USDC.sep` onto testnet-1 and the demo that matters is *shielded* USDC; the v1 pool is single-asset and testnet-1's is pinned to the test asset. Every issuer conversation (`docs/STABLECOIN-RAILS-AND-ORACLE-PLAN.md` X5) also ends at "can my asset be shielded?". P6 answers it before the audit freeze, as a consensus change with an activation height, rolled like X1 and G1.

## 0 · The decision: pools per asset, not assets per note

Two ways to shield more than one asset:

| | **A — one pool per asset (chosen)** | B — asset inside the note (Zcash-ZSA style) |
|---|---|---|
| Circuit | **unchanged** — the note commitment and the spend statement stay asset-agnostic; the *pool* is the asset | new statement (per-asset balance), new keys, new vk pins, aggregator changes, wallet note format change |
| Consensus change | additive: a `pools` map that enters the state commitment only once non-empty; routing rules; an activation height | a hard fork of the pool with a migration of every existing note |
| Anonymity set | per asset (a USDC note hides among USDC notes) | shared across assets, but the asset is revealed per spend unless value commitments hide it — which is the expensive part |
| Audit surface | state machine only (~200 lines) | circuit + state + wallets |
| Time | days | weeks, and a second vk re-pin before the audit |

Per-asset pools are also what a stablecoin issuer expects: its asset in its own pool, with its own conservation ledger, its own eligibility flag, and — if it ever asks — its own value cap. The shared-anonymity-set design is a later product decision, not a prerequisite for shielding USDC.

## 1 · Rules (consensus)

- **State.** `pool: PoolState` stays exactly as it is — the *legacy pool*, pinned to the first asset ever shielded (the test asset on testnet-1). New: `pools: BTreeMap<AssetId, PoolState>` — one per additional asset, created on its first shield. `multi_pool_from: u64` is CONFIG injected by the node (like `fee_from`): the height from which additional pools exist; `u64::MAX` = never.
- **Routing — shield.** `MintToPool { asset }` (unchanged encoding): if `asset` is the legacy pool's pinned asset, or the legacy pool is unpinned, → the legacy pool (v1 behaviour, byte for byte). Otherwise, before `multi_pool_from` → `PoolAssetMismatch` (v1 behaviour); from `multi_pool_from` → the asset's own pool, created if absent, **only if the asset is registered with `pool_eligible`** (X5) and not paused, from an unfrozen sender.
- **Routing — spend.** `ShieldedSpend { anchor, … }` (unchanged encoding): the pool is **the one whose recent anchors contain `anchor`**. Roots of non-empty trees are unique across pools (every commitment carries note randomness), and an empty tree has nothing to spend, so the resolution is unambiguous; no anchor in any pool → `PoolUnknownAnchor` as before. The unshield credit pays out in the resolved pool's asset; the nullifier is checked and recorded in that pool. A note can never cross pools: membership is proven against one tree.
- **Block end.** Every pool seals its anchor (`seal_anchor` on the legacy pool and on each entry of `pools`).
- **Commitment.** Unchanged until `pools` is non-empty; then a section tagged `0xB6` — count, and per pool the asset id followed by exactly the legacy pool's encoding (version, pinned asset, next index, root, anchors, nullifiers, total_shielded). The same "enters the commitment only once non-empty" trick as `fees_burned` (U4) and the registry (X1): upgraded and pre-upgrade nodes agree on every block until the first second-asset shield commits.
- **Conservation (I5').** `Σ balances + Σ escrow + Σ shielded across every pool of the asset == supply − burned − fees` — `asset_conservation` gains the per-asset pool term; the legacy term stays.
- **Activation.** `P6_TESTNET1_HEIGHT` hard-wired by chain id in `hk-node/src/genesis.rs` next to G1; other chains via `HK_P6_HEIGHT` (unset ⇒ active from genesis on devnets, so every gate runs multi-asset from block 1). Every node must run ≥ the release before the height — the R7/X1 discipline: a node that is not upgraded rejects the first second-asset shield (`PoolAssetMismatch`) and forks.

## 2 · Node

- **Snapshots.** `StateSnapshot` gains `pools` as its LAST field (bincode is positional) → the node writes `snapshot4.bin` and keeps a read-only v3 mirror for `snapshot3.bin` (pools restore empty; if the recorded app_hash disagrees, restore refuses and the node resyncs — never a silent divergence). Highest height wins across formats, as before.
- **Pool-note index.** The node's leaf feed (`pool_notes`: leaf → commitment + stealth payload) becomes one feed per pool: the legacy `pool_notes` stays; `pool_notes_by_asset: BTreeMap<AssetId, Vec<…>>` is new (snapshotted in v4). Routing on commit: a `MintToPool` by its asset (through the state's `pool_key_of_asset`), a `ShieldedSpend` by its anchor (`pool_key_of_anchor`, resolved BEFORE apply so the anchor cannot have been evicted).
- **Mempool admission** mirrors the state: anchor and nullifier checks against the pool the anchor resolves to.
- **RPC.** `hk_getPoolInfo`, `hk_getPoolLeaves`, `hk_getPoolNotes`, `hk_getPoolPath`, `hk_nullifierSpent` take an optional `asset` (64-hex); absent ⇒ the legacy pool, so every existing wallet keeps working unchanged. New `hk_getPools` lists every pool: `asset`, `version`, `root`, `next_index`, `nullifiers`, `total_shielded`, `legacy: bool`. `hk_getAsset` gains `shielded` (the asset's pool ledger, 0 if none).
- **CLI wallet** (`hk-node wallet`): `shield / unshield / pay / scan` accept `--asset <64-hex>` (default: the test asset); notes are stored with their asset. The desktop and Android wallets stay on the test asset until P6.2 (asset picker + per-asset scan cursor in `hk-wallet-core`).
- **Explorer.** A pool row per asset on the asset page (P6.2).

## 3 · Receipts (`chain/gate-p6.sh`, devnet, prover on :9911)

1. Register `USDC.t` (`mfps`) and `EUR.t` (`mfp` — *not* pool-eligible); mint both to alice.
2. Shield 1 USDC.t → a second pool appears in `hk_getPools` (legacy = test asset, `USDC.t` = its own); `hk_getPoolInfo {asset}` shows root/size; the state commitment changed only at that block (the 0xB6 section).
3. Shield EUR.t → refused `not pool eligible`. Shield USDC.t with `HK_P6_HEIGHT=999999` on a second devnet → refused `pool asset mismatch` (pre-activation behaviour intact).
4. Pay shielded USDC.t → the spend routes by anchor into the USDC.t pool; the test-asset pool is untouched (roots, nullifier counts). Unshield 1 USDC.t → credit lands in USDC.t, `total_shielded` of that pool falls; `hk_nullifierSpent {asset}` true there, false in the legacy pool.
5. A test-asset shield + spend in the same block as a USDC.t spend → one aggregate covers both; both pools advance.
6. Kill node3, restart on its home → `snapshot4.bin` restores both pools, app_hash matches; node4 syncs from genesis and lands on the same hash. A `snapshot3.bin` from before the upgrade restores (pools empty) on a devnet without second-asset activity.
7. Conservation: `hk_getAsset {USDC.t}` `supply − burned == Σ balances + shielded`.

## 4 · Roll

Client + consensus: release `v0.19.0`, activation `P6_TESTNET1_HEIGHT` set at roll time ≈ 24 h ahead (the G1 pattern: `eta`, deadline notice in #testnet, founders roll ≥ 24 h before, externals told twice). Old binaries fork at the first second-asset shield — the announcement says so. The soak clock has not started, and the audit tag is not cut: P6 lands inside both windows, which is the whole point of doing it now.
