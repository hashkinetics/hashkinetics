# hashkinetics-chain

Rust workspace for the HashKinetics sovereign L1. **Status (2026-08-26, v0.10.3): 71 workspace tests (+17 circuit) green; P2 PHASE COMPLETE — a live 4-validator devnet with hash-based (LMS/HSS over SHAKE-256) consensus votes at ~1.4 s blocks, live SLH-DSA-root key rotation, and the full shielded suite verified in-consensus: real SP1 STARKs, stealth payments + trial-decap discovery, one-time offline disclosure, ONE constant-size aggregate STARK per block, mandates enforced over hidden balances, binary wire codec, vk-pinned genesis. P3 ACTIVE: the node is now DURABLE (P3.0a, crash-kill gated — `kill -9` all four, relaunch, byte-identical commitment, consensus continues) and the devnet has a live explorer (`../explorer/index.html`).**

**⚠ Two devnets now exist:** the **shielded** devnet runs in **WSL** (`./devnet.sh --prover-url …` — sp1's verifier is POSIX-only) with `hk-prove` on the GPU; Windows `devnet.ps1` runs the **transparent-only** chain (`--no-default-features`). Full sequences + troubleshooting: `../docs/RUNBOOK-DEVNET.md`.

## Run the devnet
```powershell
cd chain
.\devnet.ps1 -N 4 -Fresh                 # build release, generate keys/genesis/configs, launch 4 windows
.\devnet.ps1 -N 4 -Fresh -RotateEvery 30 # same, plus the SCMS demo: every validator rotates its
                                         # operational key every 30 blocks (watch for
                                         # "Rotated OUR operational signing key (live)")
```
Watch for `Committed block` lines with matching `app_hash` across windows. Consensus votes are hash-based LMS/HSS over SHAKE-256 — quantum-secure; Ed25519 exists only as libp2p transport identity. Each node persists its monotone signer state in `consensus_state.bin` (reserve-then-sign: kill a window and restart that node *without* `-Fresh` — it resumes past its last durable leaf, never reusing one).

## Test everything
```powershell
cargo build
cargo test            # `--release` recommended: the LMS/SLH-DSA suites are tree-heavy
```

## Run the G0 demo (the $50 storyline, live)
```powershell
.\devnet.ps1 -N 4 -Fresh                                   # 4 validators, RPC + P0 genesis
.\target\release\hk-node.exe demo http://127.0.0.1:26000   # drive the storyline over RPC
```
Real transactions: mandate tree → 2 payments → agent-c overspend **REJECTED by consensus** (real receipt: `insufficient buffer at depth 1 from leaf`) → revoke cascades → 1,000 PayWord calls settled in one tx → org $5 / merchant $45.

Paid search (RAG-as-a-merchant): `cargo build --release -p hk-facilitator` then `.\target\release\hk-facilitator.exe demo http://127.0.0.1:26000` — 5 real document queries at $0.05 each through a mandate-bounded PayWord channel, settled in one tx.

## Run the shielded demos (WSL — P2.0/P2.1)
```bash
# terminal A: the GPU prover        (zkvm-bakeoff/sp1/script) cargo run --release --bin serve
# terminal B: the devnet            ./devnet.sh --fresh --prover-url http://127.0.0.1:9911
# terminal C: the stealth storyline ~/hk-target-chain/release/hk-node demo-shielded \
#                                     http://127.0.0.1:26000 http://127.0.0.1:9911
```
Shield $5 (mint proof ≈1.2 s) → pay Bob $2 **fully shielded** (fee 0 — zero transparent trace) → **Bob's wallet DISCOVERS the note by trial-decap scanning** (a third wallet sees nothing) → Bob spends it, unshielding $1 → double-spend + forged proof refused with receipts. Protocol: `../docs/SHIELDED-POOL-SPEC.md` · ops detail: `../docs/RUNBOOK-DEVNET.md`.

## Crates

| Crate | State | What's real |
|---|---|---|
| `hk-primitives` | ✅ | Core protocol types (plan §7.4): amounts, ids, mandate node, delegation cert, channel, envelope. |
| `hk-crypto` | ✅ 32 tests | SHAKE-256 domain-separated hashing · PayWord chains · Lamport-OTS + L-ratchet · LeafBudget reserve-then-sign · **`hashsig`: real stateful LMS/HSS (RFC 8554), file-persisted monotone state** · **`slhdsa_adapter`: real SLH-DSA-SHAKE-192s root (FIPS 205)** · **`mlkem`: ML-KEM-768 stealth adapter (deterministic keygen/encaps, trial-decap)** · **`noteenc`: SHAKE-256 encrypt-then-MAC AEAD (doctrine-pure)**. |
| `hk-mandate` | ✅ 9 tests | MandateTree v2 accounting: drip accrual, buffer caps, per-tx caps, expiry, cascade revocation, full ancestor-chain spend check, read-only `check()` ≡ `spend()`. |
| `hk-state` | ✅ 11 tests | The deterministic state machine: accounts (L-ratchet auth, nonce=key-index), balances, mandates, channels, **the shielded pool** (frontier commitment tree, anchor window, nullifier set, conservation ledger, `MintToPool`/`ShieldedSpend` incl. mandate-bound + aggregation coverage, injected `ProofVerifier` with RejectAll default), block apply + receipts + state commitment, **`StateSnapshot` persistence image (P3.0a)**. Tests include both storylines, the tree↔circuit keystone, determinism replays, and the **snapshot-roundtrip keystone** (restore ⇒ identical C(Σ), frontier keeps appending). |
| `hk-wallet` | ✅ 5 tests | Client-side shielded wallet: stealth addresses (spend-tree + nk + KEM), per-epoch keys + **IVKs**, sealed outputs, **trial-decapsulation scanner** (lying-ciphertext defense), **one-time `DisclosurePackage` + pure-function offline `verify_disclosure`**, v3 witness building with native pre-check. |
| `hk-consensus` | ✅ 9 tests, devnet-proven | HkContext (all consensus datatypes) + **hash-based signing provider** (`HkContext::SigningScheme = HkHashScheme`). **Single consensus signer** (the proposal Fin carries a value-id echo, not a second signature — one-time-leaf safety). **`rotation::RotationCert`** — root-signed operational-key rotation with monotone-epoch verification; `HkValidatorSet::apply_rotation`. `HkValidator` = stable address + permanent `root_pk` + swappable operational key + epoch. |
| `hk-rpc` | 📝 sketch | DTOs only; the real server lives in `hk-node/src/rpc.rs`. |
| `hk-node` | ✅ 5 tests, devnet-proven | The full node: HkCodec (bincode wire/WAL), proposal-part streaming, complete AppMsg loop, Decided→`apply_block` (consensus-fatal divergence check), **the durable store (P3.0a: per-height block log + commit certs + recorded aggregate verdicts, commitment-verified snapshots every 16 blocks — refuse-on-mismatch, mempool WAL, full replay-or-resume restore)**, mempool + JSON-RPC incl. the **explorer surface** (`hk_getBlock`/`hk_getBlocks`/`hk_getValidators`/`hk_getMempool` + pool/receipt endpoints), vk-pinned genesis (refuse-to-start on mismatch), live rotation wiring, **in-node SP1 STARK verification** (per-proof + block aggregates), six demo drivers (`demo`, `demo-shielded`, `demo-disclose`, `demo-agg`, `demo-mandates`, `demo-economy` — the client demo), `verify-disclosure` offline CLI, `devnet.ps1` (Windows, transparent) + `devnet.sh` (WSL, shielded). |
| `hk-facilitator` | ✅ ran live | RAG-as-a-merchant: PayWord-metered paid document search settled on-chain. turbovec (`agentic/`) is the drop-in index upgrade. |

## Key-management model (docs/MAINNET-KEY-MANAGEMENT.md)

```
stateless SLH-DSA-192s ROOT (genesis identity, never exhausts)
        │ signs RotationCert{new_op_pk, epoch, valid_from_height}
        ▼
stateful LMS/HSS operational tree (2^15 sigs, persisted reserve-then-sign)
        │ signs
        ▼
consensus votes / proposals
```
Exhaustion and key loss are **liveness** faults (a validator stalls; the chain continues), never **safety** faults. Remaining hardening (non-blocking): persist the current epoch across restart-after-rotation, pre-generate fresh trees off the hot path, gossip certs through the mempool, trigger on the real `remaining()` threshold.

## Order of work (P3 — full plan: `../docs/P3-BUILD-PLAN.md`)
1. ✅ **P3.0 build complete (0.10.0–0.10.2):** durable node (crash-kill gated) · explorer (`../explorer/`) · wallet v1 (full loop gated) · testnet kit (keygen/genesis-build/config-gen, ceremony sim green). Faucet waits on the account-creation tx (WS-F).
2. ✅ **C1 phase 1 (0.10.3):** `storm` harness + `../docs/CAPACITY-SHEET.md` — devnet clean baseline **123.1 tx/s** at the 256-cap; findings (no tx-gossip between mempools; O(mempool×included) prune) filed under C2.
3. **NOW:** external validators (operational — `../docs/VALIDATOR-ONBOARDING.md` + `../validators/`) → the 30-day G3 soak · build lane: **C2 lifts** (1024-cap, pacing, admission pre-checks, indexed prune, mempool-sync decision) + the agg-curve GPU harness (C1 phase 2).
4. P3.2: three-track audit campaign + WS-F hardening (merkleized commitment, account-creation tx, slashing evidence, rotation-restart signer resume, block-log segmentation, WAL fsync option).
5. P3.3–P3.5: compliance rails (CASP envelopes, IVMS-101, parent-mandate views) → stablecoin path → aggregator role → **G4 → mainnet + TGE**.
6. Backlog: bake-off pass 2 (Poseidon2 tax, v3 re-bench, RISC0 sha-accel puzzle) · turbovec behind the facilitator · HTTP + MCP facilitator surfaces.
