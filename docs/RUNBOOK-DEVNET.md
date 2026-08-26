# HashKinetics Devnet Runbook

**v0.10.0 (2026-08-26).** The operational manual for running, demoing, debugging, and
recording the devnet — every failure mode in the troubleshooting table was actually hit
and diagnosed on ASUS-SERVER. Read this before touching a terminal after time away.

**P3.0 notes:** the node is DURABLE — restart WITHOUT `--fresh` = resume (see §7 for the
restart/crash-kill procedure); the explorer lives at `../explorer/index.html` (open in
Chrome against a running devnet — green dot = connected); `demo-economy` is the client
demo (six acts, run on a FRESH devnet, best watched beside the explorer).

**C1 storm quickstart** (`hk-node storm <RPC> [RATE] [DUR] [NODES]`, gated 0.10.3): floods
from the five genesis senders, one home node each (v0 has no tx gossip between mempools —
submit to the node you want proposing your txs), prints the capacity report for
`CAPACITY-SHEET.md`. Best on a fresh devnet (leftover mempools skew the interval — the
prune cost scales with queue depth). Clean devnet baseline: **123.1 tx/s** at the 256-cap.

**Wallet v1 quickstart** (`hk-node wallet` — full loop gated 0.10.1):
```bash
HK=~/hk-target-chain/release/hk-node; W=~/my-wallet
$HK wallet init $W org                 # bind to a genesis account (WS-F lifts this)
$HK wallet shield $W 3                 # transparent → hidden (mint proof ~1.3 s)
$HK wallet scan $W                     # discover your notes (LIVE/SPENT, full commitments)
ADDR=$($HK wallet address $W 2>/dev/null)
$HK wallet pay $W "$ADDR" 1 "memo"     # fee-0 stealth payment (zero transparent trace)
$HK wallet unshield $W 1               # hidden → transparent
$HK wallet disclose $W <COMMITMENT> d.json && $HK verify-disclosure d.json
```
Truths: one input note per spend (consolidate by paying yourself) · 64 one-time spend
leaves per wallet (then rotate the master) · back up `wallet.json` (holds the shield
master + your disclosure capabilities) · faucet arrives with WS-F account-creation.

**P2.5 notes:** the consensus wire is BINCODE (proofs ride at ~1×; any codec change ⇒
`--fresh`), and genesis generated with `--prover-url` embeds **vk pins** — expect
`pinning proof-system vks into genesis` at generation and
`verifying keys MATCH the genesis pins` in every node log. A node that logs
`vk PIN MISMATCH … refusing to start` is telling you the prover's circuit changed
without a fresh genesis (see §3).

## 0 · Topology (why two worlds)

| Piece | Where | Why |
|---|---|---|
| Fast test loop (crypto/circuit/state/wallet) | **Windows** PowerShell | pure Rust, quickest iteration |
| `hk-prove` (GPU proving service) | **WSL2** | SP1 CUDA toolchain lives there (RTX 5090) |
| Shielded devnet (4 nodes, in-node STARK verify) | **WSL2** | `sp1-sdk` → `sp1-jit` is POSIX-only (shm/semaphores) — **it can never build on MSVC** |
| Transparent-only devnet (P0/rotation demos) | Windows `devnet.ps1` | builds `--no-default-features` |

Ports: consensus 27000+i · metrics 29000+i · RPC **26000+i** · hk-prove **9911**.
Windows ⇄ WSL localhost forwarding works both ways on this machine.

**Target-dir discipline (always):** WSL builds must never share `target/` with Windows.
`CARGO_TARGET_DIR=~/hk-target` for zkvm-bakeoff, `~/hk-target-chain` for the chain.

## 1 · The shielded devnet — three terminals, IN THIS ORDER

**A — hk-prove first.** Nodes fetch verifying keys at startup; if the prover is down they
silently fall back to RejectAll and every pool tx bounces.

```bash
cd "~/hashkinetics/zkvm-bakeoff/sp1/script"
CARGO_TARGET_DIR=~/hk-target cargo run --release --bin serve
# wait for: hk-prove: listening on 0.0.0.0:9911   (warm-up prove ~1.5 s happens first)
# env: HK_PROVE_MODE=core (default) | compressed · HK_PROVE_ADDR=0.0.0.0:9911
```

**B — the devnet.**

```bash
cd "~/hashkinetics/chain"
export CARGO_TARGET_DIR=~/hk-target-chain
./devnet.sh --fresh --prover-url http://127.0.0.1:9911
./devnet.sh logs      # want: 'SP1 pool verifier wired' ×4, then Committed block, matching app_hash
# other verbs: ./devnet.sh stop · -n N · --rotate-every N
# node homes + logs: ~/hk-devnet/node<i>{,.log}  (Linux fs on purpose — fast WAL)
```

Startup takes ~40 s: the SP1 CpuProver init per node is one-time.

**C — the demos.**

```bash
BIN=~/hk-target-chain/release/hk-node
# CANONICAL ORDER on one fresh devnet (mandates FIRST — it needs org's full $50):
$BIN demo-mandates http://127.0.0.1:26000 http://127.0.0.1:9911   # P2.4 thesis demo
$BIN demo-shielded http://127.0.0.1:26000 http://127.0.0.1:9911   # P2.1 stealth storyline
$BIN demo-disclose http://127.0.0.1:26000 http://127.0.0.1:9911   # P2.2 CVA (writes disclosure-*.json)
$BIN demo-agg      http://127.0.0.1:26000 http://127.0.0.1:9911   # P2.3 one STARK per block
$BIN demo          http://127.0.0.1:26000                          # P0 $50 storyline (transparent)
```

Wait for `SP1 pool verifier wired` ×4 in the logs BEFORE the first demo — startup takes
~40 s and a demo launched in the same paste will time out on "node RPC reachable".

Demos are devnet-history-tolerant (per-demo wallet seeds, relative pool counts) —
re-runnable on a lived-in pool. On any wait timeout they print the consensus receipt
(`⛔ …`) or `∅ no receipt` (never included) — the two are different bugs.

`demo-shielded` expected beats: mint proof ~1.2 s → "$5 shielded" → pay-Bob proof ~1.3 s →
"WHO PAID WHOM: invisible" → **"✓ BOB DISCOVERED: $2 … memo"** (eve sees 0) → Bob's spend
→ merchant +$1 → `⛔ nullifier already spent` → `⛔ pool proof rejected`.
`demo-mandates` money line: `⛔ rejected: mandate: insufficient buffer at depth 1 from
leaf (have 5000000, need 10000000)` — consensus enforcing caps over hidden balances.

## 2 · Fast test loop (Windows, seconds)

```powershell
cd "C:\hashkinetics\chain"
cargo test -p hk-crypto --features mlkem                   # 24
cargo test -p hk-state -p hk-wallet -p hk-node --no-default-features
#   → state 10 (keystone · storylines · agg coverage · mandated unshield)
#   → wallet 5 (stealth e2e · disclosure · IVK epochs)
#   → node 2 (bincode wire roundtrip + garbage rejection)
cd ..\zkvm-bakeoff\circuit; cargo test     # 17 (v3 + agg module)
```

## 3 · When the circuit changes (vk discipline)

Any edit to `hk-spend-circuit` that touches the statement (types, checks, constants like
SPEND_TREE_DEPTH) **changes both verifying keys**. Sequence: rebuild+restart serve
(build.rs recompiles both guests; watch the new cycle count in the warm-up) → restart the
devnet `--fresh` so nodes refetch vks → wallets/demos must use the new witness shapes.
Symptom of skipping this: every proof bounces with `pool proof rejected`.

## 4 · Troubleshooting (all previously hit)

| Symptom | Cause | Fix |
|---|---|---|
| `error[E0432] std::os::fd` / `sem_open` building hk-node on Windows | sp1-jit is POSIX-only | expected — shielded node builds in WSL; Windows uses `--no-default-features` |
| Pool txs bounce, node log: `HK_PROVER_URL not set` or `verifier init FAILED` | nodes started before serve / URL missing | start serve first, restart devnet `--fresh` |
| Every proof `pool proof rejected` though prover is up | vk mismatch (circuit changed, nodes hold old vks) | §3 sequence |
| Tx accepted but never commits; empty blocks continue; `MessageTooLarge` in logs | HISTORIC (retired at v0.9.11): the JSON codec double-hexed proofs to ~4× | the wire is bincode now (~1×; 32 MiB caps are headroom). If this EVER reappears, a block is carrying >30 MB of raw proofs — aggregate them |
| Demo times out; `⛔ consensus receipt … rejected: <reason>` printed | tx was included and REFUSED — the receipt names the rule | fix the tx (nonce/anchor/proof/mandate per the reason); state never half-mutates |
| Demo times out; `∅ no receipt — never included` printed | tx not in any block: submit failed loudly above it, or node0's proposals aren't landing | check the `✗ submit FAILED` line + node0 log |
| Node exits at startup: `vk PIN MISMATCH … refusing to start` | circuit/guests changed after genesis was pinned | §3: rebuild+restart serve, then `./devnet.sh --fresh --prover-url …` (re-pins) |
| Demo says `hk-prove not reachable` | serve died (terminal closed) | restart A, then B (`--fresh`), then C |
| Node startup "hangs" ~40 s after vk fetch | `sp1_sdk::cpu: initializing cpu prover` | normal, one-time |
| `Workspace still starting` style WSL sluggishness on /mnt/c builds | Windows-fs IO | one-time cost; targets are on ~ already |
| `error deserializing ProofRequest` (bake-off, RISC0) | r0vm version mismatch | `rzup install r0vm <exact version>` |
| `libcudart.so.12` missing (bake-off) | CUDA toolkit absent in WSL | `cuda-toolkit-12-9` via NVIDIA wsl-ubuntu repo; NEVER install a driver in WSL |
| Fresh devnet but old money/state expectations | `demo-shielded` is resume-safe (syncs nonces) but pool notes accumulate | for a clean recording always `./devnet.sh --fresh` |

## 5 · Recording a demo (GTM checklist)

1. `./devnet.sh stop` · restart serve (terminal A visible — the `proved SPEND in …ms`
   lines are part of the show) · `./devnet.sh --fresh --prover-url …`.
2. Wait for `SP1 pool verifier wired` ×4 in `./devnet.sh logs` (keep this terminal
   visible too — matching app_hash across 4 validators).
3. One take: `demo-shielded` (≈40 s wall). The money lines: "WHO PAID WHOM: invisible",
   "BOB DISCOVERED", the two ⛔ receipts, and the final pool ledger.
4. Optional second take: `demo` (P0 storyline) and `--rotate-every 30` for the live
   key-rotation log lines.

## 6 · Machine facts (ASUS-SERVER)

Threadripper PRO 7995WX (96c/192t; WSL2 sees 125 GB) · RTX 5090 32 GB (Blackwell — CUDA
≥ 12.8; 12.9 installed; sp1-gpu-server links libcudart.so.12) · Ubuntu 26.04 WSL2 ·
sp1 v6.4.0 toolchain via sp1up · `cargo test --release` for the heavy crypto suites.

## 7 · Restart & crash-kill (P3.0a / WS-B — the persistence gate)

Since 0.10.0 every node is DURABLE: block log (`node*/blocks/`), snapshots every 16
blocks (`node*/snapshot.bin`, commitment-verified on load — refuse-on-mismatch), and a
mempool WAL. **Restart = resume.** `./devnet.sh` without `--fresh` relaunches on the
existing homes and each node logs `Snapshot restored — commitment verified` and
`PERSISTENCE RESTORE COMPLETE — resuming, not resyncing`; the chain continues from its
tip, old receipts stay queryable, wallets keep their note index. `HK_NO_PERSIST=1`
restores the old in-memory behavior.

**The crash-kill demo (gate artifact):**

1. Devnet up + state rich: `./devnet.sh --fresh -n 4 --prover-url http://127.0.0.1:9911`,
   run `demo-mandates` (or any demo).
2. Note the tip: `curl -s -X POST http://127.0.0.1:26000 -d '{"method":"hk_chainInfo"}'`
   → remember `height` (call it H) and `app_hash`.
3. Murder everything mid-flight: `pkill -9 -f 'hk-node start'` (no graceful anything).
4. Relaunch WITHOUT `--fresh`: `./devnet.sh -n 4 --prover-url http://127.0.0.1:9911`.
5. `./devnet.sh logs` → all four print the restore lines; `hk_chainInfo` → height > H
   (continued, not restarted at 1); `hk_getReceipt` on a pre-kill txid → still found.
6. Run `demo-shielded` on the resumed chain — proves the pool frontier and anchors
   survived byte-exact (a wrong frontier would fail every new proof's anchor).

| New troubleshooting | Cause | Fix |
|---|---|---|
| `snapshot integrity FAILURE … refusing to run` | snapshot.bin corrupt/hand-edited | wipe that node's home (or `--fresh`); value-sync refills |
| `gap in the block log — stopping replay` | a block file failed to write pre-crash | benign: value-sync fills the gap from peers |
| `restart-after-rotation: own-signer resume is WS-F` | killed after a key rotation | known WS-F item; restart that one validator `--fresh` if it stalls |
| Old demo balances look "wrong" after restart | they SURVIVED (that's the feature) | for clean-slate recordings use `--fresh` as always |
