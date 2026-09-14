# hashkinetics-chain

Rust workspace for the HashKinetics sovereign L1.

**Status (2026-09-14, hk-node v0.19.3 — consensus rules v0.19.0): TESTNET-1 IS LIVE WITH 11 SEATS.** The public chain `hashkinetics-1-4e4ea68d` has run since 2026-09-02 (≈ 462,000 blocks at ~1.3 s/block on 2026-09-14): hash-based BFT votes (LMS/HSS trees under stateless SLH-DSA-192s roots, reserve-then-sign persistence, unattended threshold rotation with per-seat jitter, 179 µs per consensus signature since R15 / v0.18.2), a pinned genesis with the protocol fee (100 micro, burned) bound in from height 1, in-node STARK verification through a verify-only client (54–59 MiB resident, restart → RPC in 6–16 s since R11 / v0.17.0), **one shielded pool per asset** (P6 — a consensus change, active since height 190,000 on 2026-09-09), **issued assets** with issuer controls (X1 / v0.15.0), **validator-set changes on the running chain** (V1 / v0.14.0 — seven external seats admitted 2026-09-05 → 09-12 by root-signed certificates, no restart, no new genesis), **bootstrap governance** (G1 / v0.18.1: the four genesis seats weigh 4 by rule from height 110,000 — 16 of 23, quorum 16 — handed back by `SetPower` certificate), sealed key files at rest (HKE1 / v0.16.0), block-log segments with retention, a live peer table (`hk_getPeers`), and the **B1 bridge** (Sepolia USDC ↔ `USDC.sep`, a 1-of-1 founder attestor labelled as such, live since 2026-09-09; `attest.rs` / `eth.rs` in hk-node). v0.19.1 → v0.19.3 are client-only: the bridge subcommands and a CLI wallet bound to a real account; faucet asset drips for the wallets' test USDC (P6.2); the N2 gossipsub subscription re-announce patch on vendored `libp2p-gossipsub` 0.49.5. Wallets: `HashKinetics-Wallet.exe` v0.15.0 (a shell over `hk-wallet-core` v0.2.0), Android v0.3.0, Linux zip v0.14.1. **The acceptance layer is the gate scripts, each GREEN on its release binary:** `rehearsal.sh` (ceremony + restore shapes) · gate-v1 25/25 · gate-x1 40/40 · gate-k6 16/16 · gate-n1 20/20 · gate-s 33/33 · gate-h3 22/22 · gate-r11 29/29 · gate-g1 40/40 · gate-wa1 19/19 · gate-p6 48/48 · gate-b1 50/50 · gate-p6-2 31/31 · gate-n2 18/18 — per-crate unit counts are no longer the headline number. Nothing is audited yet (scope prepared in `../docs/AUDIT-SCOPE.md`; CertiK engaged; the audit campaign is a gate before any mainnet) — unaudited testnet software, test units only.

**Previous status (2026-08-26, v0.10.3): 71 workspace tests (+17 circuit) green; P2 PHASE COMPLETE — a live 4-validator devnet with hash-based (LMS/HSS over SHAKE-256) consensus votes at ~1.4 s blocks, live SLH-DSA-root key rotation, and the full shielded suite verified in-consensus: real SP1 STARKs, stealth payments + trial-decap discovery, one-time offline disclosure, ONE constant-size aggregate STARK per block, mandates enforced over hidden balances, binary wire codec, vk-pinned genesis. P3 ACTIVE: the node is now DURABLE (P3.0a, crash-kill gated — `kill -9` all four, relaunch, byte-identical commitment, consensus continues) and the devnet has a live explorer (`../explorer/index.html`).**

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
| `hk-crypto` | ✅ (`hashsig` suite 10/10, v0.18.2) | SHAKE-256 domain-separated hashing · PayWord chains · Lamport-OTS + L-ratchet · LeafBudget reserve-then-sign · **`hashsig`: real stateful LMS/HSS (RFC 8554), file-persisted monotone state, R15 `HssSigningSession` (the expanded key and bottom-tree cache kept between signatures — 179 µs per consensus signature, byte-identical output, rollback on a failed write)** · **`slhdsa_adapter`: real SLH-DSA-SHAKE-192s root (FIPS 205)** · **`mlkem`: ML-KEM-768 stealth adapter (deterministic keygen/encaps, trial-decap)** · **`noteenc`: SHAKE-256 encrypt-then-MAC AEAD (doctrine-pure)**. |
| `hk-mandate` | ✅ 9 tests | MandateTree v2 accounting: drip accrual, buffer caps, per-tx caps, expiry, cascade revocation, full ancestor-chain spend check, read-only `check()` ≡ `spend()`. |
| `hk-state` | ✅ (unit suite green inside every rehearsal; testnet-proven) | The deterministic state machine: accounts (L-ratchet auth, nonce=key-index; `AccountCreate` runtime accounts with squat-proof ids since v0.11.0), balances, mandates, channels, **the protocol fee** (100 micro per envelope, burned — a genesis fact on testnet-1), **issued assets** (X1: registry with `H(issuer ‖ symbol)` ids, mint · burn · freeze · pause under a policy fixed at registration, per-asset supply in C(Σ)), **the shielded pools** (frontier commitment tree, anchor window, nullifier set, conservation ledger, `MintToPool`/`ShieldedSpend` incl. mandate-bound + aggregation coverage, injected `ProofVerifier` with RejectAll default; **P6: one pool per asset** — shields route by asset, spends by anchor, the statement unchanged), block apply + receipts + state commitment, **`StateSnapshot` persistence image (P3.0a; `snapshot4.bin` with the pools since P6)**. Tests include both storylines, the tree↔circuit keystone, determinism replays, the P6 routing/isolation cases, and the **snapshot-roundtrip keystone** (restore ⇒ identical C(Σ), frontier keeps appending). |
| `hk-wallet` | ✅ 5 tests | Client-side shielded wallet: stealth addresses (spend-tree + nk + KEM), per-epoch keys + **IVKs**, sealed outputs, **trial-decapsulation scanner** (lying-ciphertext defense), **one-time `DisclosurePackage` + pure-function offline `verify_disclosure`**, v3 witness building with native pre-check. |
| `hk-consensus` | ✅ testnet-proven | HkContext (all consensus datatypes) + **hash-based signing provider** (`HkContext::SigningScheme = HkHashScheme`). **Single consensus signer** (the proposal Fin carries a value-id echo, not a second signature — one-time-leaf safety). **`rotation::RotationCert`** — root-signed operational-key rotation with monotone-epoch verification; `HkValidatorSet::apply_rotation`. **`SetChangeCert`** (V1: `Admit` / `Remove` / `SetPower`, root approvals from > ⅔ of the current power, chain-id-bound, height-windowed) and **`reweight_roots`** (G1: the genesis seats re-weighted by rule at the activation height). Per-height set history (`validator_set_at`, R6) so certificates verify against the set as of their height. `HkValidator` = stable address + permanent `root_pk` + swappable operational key + epoch + power. |
| `hk-rpc` | 📝 sketch | DTOs only; the real server lives in `hk-node/src/rpc.rs`. |
| `hk-node` | ✅ testnet-proven (unit suite green inside every rehearsal) | The full node: HkCodec (bincode wire/WAL), proposal-part streaming, complete AppMsg loop, Decided→`apply_block` (consensus-fatal divergence check), **the durable store (per-height block log in 1,024-height segments with retention, commit certs + recorded aggregate verdicts, commitment-verified snapshots — refuse-on-mismatch, mempool WAL, replay-or-resume restore at the chain's height)**, mempool + JSON-RPC (26 methods, `../docs/RPC.md`) incl. the **explorer surface**, the paged pool feed, `hk_getValidators` with the G1 quorum view, `hk_getPeers` (the live peer table from the vendored network layer; `reconnects` / `last_connection_secs` since N2), `hk_getAssets` / `hk_getPools`, vk-pinned genesis (refuse-to-start on mismatch or without a verifier — K5; keys from the kit's `vks.json` — K6), live rotation wiring (threshold + jitter, peer-carried revival certs), **in-node SP1 STARK verification through a verify-only client** (per-proof + block aggregates), the activation table by chain id (G1 110,000 · P6 190,000 on testnet-1), the operator CLIs (`keygen` / `genesis-build` / `config-gen`, `set-change propose | approve | assemble`, `asset …`, `key-seal` / `account-seal`, `issue-rotation`), the user CLIs (`account-*`, `wallet` bound to a real account), `faucet-serve` (native + `--drip-asset` drips), **`attest.rs` / `eth.rs` — the B1 bridge service** (`attest-serve`: Sepolia watcher with a finality gate → issuer `AssetMint`; burn-with-destination → EIP-712 attestation → `unlock`; `eth.rs` is a dependency-free Ethereum client: keccak, ABI, RLP, EIP-1559 signing, EIP-712, JSON-RPC), `storm` + `agg-bench` harnesses, six demo drivers (`demo`, `demo-shielded`, `demo-disclose`, `demo-agg`, `demo-mandates`, `demo-economy` — the client demo), `verify-disclosure` offline CLI, `devnet.ps1` (Windows, transparent) + `devnet.sh` (WSL, shielded). |
| `hk-wallet-core` | ✅ gate-wa1 19/19 · gate-p6-2 31/31 | **The one wallet implementation behind both front ends** (v0.2.0): the account / vault / shielded code behind a UniFFI 0.29 surface (`Wallet` calls, `Endpoints` / `Status` / `TxResult` / `NoteView` records, a `Progress` callback), reserve-then-sign, the fee check, HKE1 sealed files with a mobile KDF profile, per-asset balances and pools (`assets()`, `Status.balances[]`, `_asset` twins of send / faucet / shield / unshield / pay / scan / notes / disclose; `shield.json` grows a `pools` map). Files byte-compatible with the CLI. |
| `hk-wallet-gui` | ✅ → `HashKinetics-Wallet.exe` v0.15.0 | Native egui + ureq/rustls (no webview, no npm), a thin shell over `hk-wallet-core` since v0.15.0: create / restore a keychain, faucet, balance, pay anyone; the shielded panel (shield → pool, pay shielded, pool → me, scan, disclose — proofs on the public prover); *Protect with a passphrase* (HKE1); the ASSET dropdown and **Get test USDC** (P6.2). Unsigned Windows testnet build; Linux zip v0.14.1 via CI. |
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
Exhaustion and key loss are **liveness** faults (a validator stalls; the chain continues), never **safety** faults. The hardening once listed here shipped as the R-series (v0.10.5 → v0.13.2, 2026-08-28 → 09-03): rotation fires itself on the real leaf-budget threshold (with per-seat jitter) and on a timer, certificates ride blocks and gossip and can be carried by a peer to revive an exhausted seat (`issue-rotation` → `hk_submitRotation`), and a restart after a rotation resumes on the rotated signer. Production-proven on the public chains (three revivals; every seat rotating unattended).

## Order of work (P3 — plan: `../docs/P3.2-IMPLEMENTATION-PLAN.md`; the ledger with every gate and roll receipt: `../CHANGELOG.md`) — 2026-09-14
1. ✅ **P3.0–P3.1 built and live (0.10.0 → 0.19.3):** durable node · explorer · wallets · testnet kit · `storm` harness (274 tx/s sustained on the lab chain, `../docs/CAPACITY-SHEET.md`) · the R-series (self-rotating keys, survivable exhaustion, per-height set verification, parallel zero-leaf sync, abstain-while-behind, fast signing) · the front door (runtime accounts, faucet, fees as a genesis fact) · **testnet-1 from a ceremony genesis (2026-09-02)** · V1 seat changes · X1 issued assets · K6/N1 join kit + peer table · S+K segments + sealed keys · H3 paged pool feed · R11 verify-only client · G1 bootstrap governance · P6 one pool per asset · B1 bridge · P6.2 test USDC in the wallets · N2 gossipsub fix. **11 seats, 7 external; every release rolled one voter at a time, the chain never paused.**
2. **NEXT — before the audit-scope freeze:** **B2** — attested mint *in consensus* (`AssetMintAttested`: deposit ids, an attestor registry, hash-based relayer signatures, a rate limit; a consensus change rolled like X1 / G1 / P6 — today's B1 attestor is a 1-of-1 off-chain service) · **C3.A** — tree-of-aggregates (recursion composed across GPUs so aggregator throughput scales with the farm, not one card).
3. **Governance → the soak:** a second external co-signer · seat #12 by external co-signature (the founders can no longer admit alone since seat #11) · **the `SetPower` handover** — the genesis seats' weight lowered by certificate so external seats hold at least ⅓ · the day that certificate commits starts the **30-day G3 soak clock**.
4. **M1** — the 30-minute testnet-1 storm run (`HK_STORM_SENDERS` over funded real accounts): the throughput label flips from "lab chain" to "measured on testnet-1".
5. **The audit campaign:** `../docs/AUDIT-SCOPE.md` refresh → scope-freeze tag → the audits → fixes → **G4 → mainnet + TGE**. Nothing is audited today.
6. Backlog: B3 light-client bridge (design + feasibility) · `hk_getRecentTxs` · Android v0.3.1 (bindings regen, the "Unaudited testnet software · test units only" footer) · the Linux wallet build past v0.14.1 · upstream the gossipsub patch · bake-off pass 2 (Poseidon2 tax, v3 re-bench, RISC0 sha-accel puzzle) · turbovec behind the facilitator · HTTP + MCP facilitator surfaces.
