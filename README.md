# HashKinetics

**The quantum-proof private settlement rail for the AI-agent economy.**

Agents get *allowances, not keys to the vault*: spending budgets enforced by consensus
itself, confidential balances with lawful one-time disclosure, and micropayments at
machine speed — standing on hash functions alone, the one cryptographic assumption a
quantum computer doesn't touch. This repository is the whole chain: node, state machine,
circuits, prover service, wallet, explorer, and the operational docs to run all of it.

**Site + papers:** [hashkinetics.org](https://hashkinetics.org) · whitepaper & yellowpaper
(md masters at repo root, PDFs in `papers/`, also on ResearchGate).

## What is real (v0.10.3 · testnet era)

Every claim below is **demo-gated**: it logged as done only after running live, and every
demo re-runs on one command.

- **Hash-based BFT, live**: a 4-validator network where every vote and proposal is signed
  with LMS/HSS over SHAKE-256 under stateless SLH-DSA-192s roots, ~1.4–2 s blocks, live
  operational-key rotation (SCMS), reserve-then-sign signer persistence (a crash can never
  reuse a one-time leaf).
- **The shielded pool, live**: hash-committed notes, real SP1 STARK spend/mint proofs
  **verified in-node**, ML-KEM-768 stealth addresses with trial-decapsulation discovery,
  fee-0 zero-trace payments, and an aggregation tier — **one 1.24 MB constant-size proof
  per block covers every shielded tx** (client proof: 1.24 s on consumer GPU).
- **Consensus-enforced budgets over hidden balances** — the thesis demo: an org's
  hierarchical mandate tree refuses a rogue agent's overspend *over balances the chain
  cannot see*, with a receipt: `insufficient buffer at depth 1 from leaf`.
- **CVA disclosure**: one-time disclosure packages verified **offline** (the key opens
  exactly one payment — measured: 0 of 21 others), epoch-scoped viewing keys.
  **No master key exists, structurally** — see `docs/LAWFUL-ACCESS.md`.
- **The durable node**: per-height block log + commitment-verified snapshots.
  `kill -9` every validator mid-flight and the network resumes to a **byte-identical
  state commitment** — restart is resume, never resync.
- **Surfaces**: a zero-build block explorer (`explorer/index.html` — no amounts, no
  parties, by construction), a full user wallet (`hk-node wallet` — shield → stealth-pay
  → unshield → disclose), a genesis-ceremony join flow for external validators, and a
  load harness (`hk-node storm` — measured devnet baseline: **274 tx/s sustained at the
  1,024-tx cap**; the capacity ledger is `docs/CAPACITY-SHEET.md`).
- **The C2 mempool (2026-08-27)**: admission pre-checks at the door (duplicates, stale
  nonces, spent/pending nullifiers, expired anchors — refused with a reason, never a
  wasted block slot), indexed O(1)-membership prune, and **single-hop tx gossip**: a tx
  submitted to any node reaches every proposer's mempool (`hk_rpc.gossip_peers`). The run
  that measured 27 tx/s pre-gossip now does 99.9 from a single RPC.

## What is NOT yet real (the honesty ledger — read this first)

**Nothing is audited.** External audits + a public audit competition precede any
value-bearing mainnet, and mainnet launches **guarded** (value caps lifted as findings
close). The public-testnet 30-day soak is in progress, not done. Numbers are single-machine
measurements unless the capacity sheet says otherwise. Known open items: rotation-restart
signer resume, block-log segmentation, in-circuit WOTS KAT campaign, account-creation tx
(accounts are genesis-only — hence no faucet yet), and the next throughput wall: block
BYTES (25 MB Lamport-tx blocks stretch intervals; shielded txs are ~20× smaller). Closed
since the release: ~~mempool sync between nodes~~ (C2 tx gossip, 2026-08-27). We keep
this list current because it is the moat.

## Quickstart

```bash
# Build (Linux/WSL2; the prover needs POSIX + a CUDA GPU, validating does not)
cd chain && cargo build --release -p hk-node && cargo test

# Prover (terminal A — GPU):   cd zkvm-bakeoff/sp1/script && cargo run --release --bin serve
# Devnet (terminal B):         ./devnet.sh --fresh -n 4 --prover-url http://127.0.0.1:9911
# The whole machine economy:   hk-node demo-economy http://127.0.0.1:26000 http://127.0.0.1:9911
# Explorer: open explorer/index.html in a browser (green dot = connected)
# Wallet:   hk-node wallet init ~/w org && hk-node wallet shield ~/w 3 && hk-node wallet scan ~/w
```

Full run sequences, demo suite, troubleshooting, crash-kill procedure: `docs/RUNBOOK-DEVNET.md`.
**Join the testnet as a validator** (no GPU, no stake, one Linux box): `docs/VALIDATOR-ONBOARDING.md`.

## Cryptographic stance

| Layer | Primitive | Assumption |
|---|---|---|
| Everything that moves money | SLH-DSA / LMS-HSS / Lamport / WOTS / PayWord — hash-based only | SHAKE-256 second-preimage resistance |
| ZK proofs | Raw STARKs (SP1), **no pairing wraps, ever** (doctrine F1) | Same hash family |
| Note confidentiality only | ML-KEM-768 + SHAKE-AEAD | A lattice break reads old metadata; it can never forge a signature or move funds |

## Repository layout

`chain/` — the Rust workspace (9 crates: primitives, crypto, mandate engine, state machine,
wallet lib, consensus context, node + RPC + durable store + demos + wallet CLI + storm) ·
`zkvm-bakeoff/circuit/` — the spend/mint circuit + aggregation digests (single source of
hashing truth, shared by chain and guests) · `zkvm-bakeoff/sp1/` — guest programs + the
GPU prover service (`serve`) · `explorer/` — the single-file block explorer ·
`vendor/external/` — pinned vendored dependencies (see `vendor/README.md`; pins in
`external/PINS.md`) · `docs/` — specs, runbook, audit scope, capacity sheet, validator
onboarding, lawful-access model · `WHITEPAPER.md` / `YELLOWPAPER.md` + `papers/`.

## Security

See `SECURITY.md` — coordinated disclosure, 90 days, security@hashkinetics.org. The
attack map an auditor should start from is `docs/AUDIT-SCOPE.md` and the yellowpaper's
ten invariants.

## Contributing & license

`CONTRIBUTING.md` for the how; the short version: small PRs, tests required, every
consensus-visible change needs a demo or a test that would have caught its absence.
Licensed under **MIT OR Apache-2.0** at your option (`LICENSE-MIT`, `LICENSE-APACHE`).
Vendored trees keep their own licenses (`vendor/README.md`).

*HashKinetics — kinetic money on hash-based trust.*
