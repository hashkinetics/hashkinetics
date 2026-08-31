# HashKinetics ($HKN)

**A post-quantum L1 that enforces AI-agent spending limits it cannot see.**

[**hashkinetics.org**](https://www.hashkinetics.org) · [**Live explorer**](https://www.hashkinetics.org/explorer) · [**Public RPC**](https://rpc.hashkinetics.org) · [**X @hashkinetics**](https://x.com/hashkinetics) · [**Discord**](https://discord.gg/RsSfb9gn3) · validators@hashkinetics.org

`staging testnet: LIVE` · `spend proof: 1.24 s (GPU)` · `274 tx/s storm-measured` · `256 proofs → ONE 1.24 MB STARK: measured` · `nothing is for sale`

---

## The idea in 90 seconds

AI agents already pay for things (x402 crossed hundreds of millions of transactions in year one) and already lose money (a third of enterprises running agents report direct financial losses). Every vendor's answer is a spending cap **in an app layer** — a promise, revocable by whoever holds the API.

HashKinetics moves the cap into consensus:

- **Allowances, not keys to the vault.** An organization funds a hierarchical **MandateTree**; agents get drip-fed, capped budget envelopes. An overspend isn't declined by a server — it's **refused by the chain**, with a signed receipt (`insufficient buffer at depth 1`). Revocation cascades through the subtree in one transaction.
- **Shielded by default.** Balances, amounts, and counterparties live in a commitment pool (STARK spend proofs verified in-consensus, ML-KEM-768 stealth addresses). The chain enforces budgets **over balances it cannot read**. There is **no master view key — structurally, not by policy**.
- **Lawful disclosure without surveillance.** One-time, offline-verifiable disclosure packages and epoch-scoped viewing keys: a court can compel exactly one payment or one epoch — measured: one key opened its payment and **0 of the other 21**.
- **Hash functions only.** Every signature that moves money or votes in consensus is hash-based (SLH-DSA roots, LMS/HSS operational trees, WOTS, PayWord). STARK proofs — no pairings, no lattice signatures in the money path. The one assumption a quantum computer doesn't touch.
- **Machine-speed micropayments.** PayWord channels: 1,000 metered API calls settle as ONE on-chain transaction; each payment costs the payer a 32-byte preimage and the verifier one hash.

## Live right now

A 4-validator **staging testnet** runs in public — real hash-signed BFT, pinned genesis, shielded pool active:

- **Explorer:** [hashkinetics.org/explorer](https://www.hashkinetics.org/explorer) — "the scanner that can't dox you": commitments, nullifiers, one running total. No amounts, no parties, by construction.
- **RPC:** `https://rpc.hashkinetics.org` (JSON-RPC over POST; try `{"method":"hk_chainInfo","params":{}}`).
- The pool shows a **$8 shielded economy** placed by the public demo suite: mandate-fed purchases, stealth bonuses wallets discovered by scanning, a rogue agent refused on-chain, and a disclosure package verified offline.
- Validator epochs are public: when a validator rotates its consensus tree under its SLH-DSA root, the explorer shows the new epoch badge. Rotations are **automatic** since v0.10.5 (leaf-budget threshold) — the fleet has rotated itself through dozens of epochs unattended, zero blocks missed.
- **The chain's identity is cryptographic:** `chain_id` is derived from the genesis digest (`hashkinetics-1-557f2ea6`), `hk_chainInfo` returns the full fingerprint, and nodes **refuse to peer across genesis** — you are either verifying this history from block 1 or you're on your own chain, by construction (v0.10.6).
- Since v0.10.7, commit certificates verify against the validator set **as of their height** — a new node syncs from genesis across every key-rotation boundary in the chain's history. That's what makes external validators possible on a chain whose keys retire themselves.

## Field report: the chain that refused to reuse a leaf

On 2026-08-28 the staging chain **halted itself at height 10,848**. A validator's LMS/HSS operational tree holds ~32,768 one-time signatures; at ~3 consensus signatures per height, that's ~10.9K blocks — and the fuse burned on schedule. Faced with signing leaf 32,769, the node **panicked rather than reuse a one-time key**. That is the designed behavior: reserve-then-sign, persisted before release, no reuse under any failure.

Recovery was the designed path too: rotation certificates signed by the stateless SLH-DSA root (which never exhausts), quorum re-formed, the rotated epoch visible on the public explorer. The outage was an ops gap, not a crypto gap — the trigger for automatic rotation wasn't armed. The fixes shipped as the R-series (v0.10.5–v0.10.8): threshold rotation that fires itself, survivable exhaustion, peer-carried revival certs (`issue-rotation` + `hk_submitRotation` — used for three real revivals since), leaf-budget gauges, continuation-driven sync, and per-height validator-set verification. Operator guidance: `docs/VALIDATOR-ONBOARDING.md` §7.

We publish incidents like this because a settlement rail's credibility is its failure behavior. **The chain chose halt over key reuse. That's the product working.**

## Measured numbers (receipts, not projections)

Everything below was measured on real hardware and is reproducible from this repo. Full provenance: `docs/CAPACITY-SHEET.md`.

| What | Number | Where |
|---|---|---|
| Shielded spend proof (full statement: commitment, 32-level Merkle, in-circuit WOTS auth) | **1.24 s** | SP1-CUDA, RTX 5090 |
| Chain throughput, storm-measured end-to-end (submit→commit, 4 validators) | **274 tx/s sustained** (1,024-cap config) · 123 tx/s (256-cap) | `hk-node storm` |
| Aggregation curve, N=4→256 (6 points, linear, no wall) | **T_agg(N) ≈ 2.66 s + 0.2882 s·N** | `hk-node agg-bench` |
| 256 shielded spends folded to ONE proof | **75.4 s, one GPU** | same run |
| Aggregate proof size at ANY N | **1,242 KB, constant** | 4 txs or 256 — same bytes |
| Validator cost per block of shielded txs | **ONE STARK verify (~100 ms), constant in N** | in-consensus |
| Crash recovery | `kill -9` all four validators → **byte-identical state commitment**, resume not resync | durable store |
| Micropayments | 1,000 metered calls settled by **one 32-byte word** | PayWord channels |
| Disclosure scope | one key opened its payment, **0 of 21 others** | CVA packages |

Numbers we do **not** claim: anything WAN-paced (the soak measures it), anything audited (nothing is audited yet), any TPS beyond the measured configs. The aggregation farm table extrapolates the measured curve and says so: ~296 GPUs of this class saturate 1,024 shielded proofs/s, measured sequentially — concurrency only improves it.

## Try it (10 minutes, one machine)

Runs in WSL2/Linux (the SP1 verifier is POSIX-only). Rust stable required; GPU only needed for *proving* (verification is CPU-cheap; a devnet without shielded proving needs no GPU).

```bash
git clone https://github.com/hashkinetics/hashkinetics
cd hashkinetics/chain && cargo build --release

# 4-validator devnet (add --prover-url http://127.0.0.1:9911 if the GPU prover is up):
./devnet.sh --fresh -n 4

# the six-act machine economy (budgets, stealth pay, a refused rogue, offline disclosure):
./target/release/hk-node demo-economy http://127.0.0.1:26000

# load harness — reproduce the 274 tx/s row yourself:
./target/release/hk-node storm http://127.0.0.1:26000

# the aggregation curve (needs the GPU prover, zkvm-bakeoff/sp1):
./target/release/hk-node agg-bench http://127.0.0.1:9911 --n 4,10,25
```

Every claim in the table above has a command that reproduces it.

## Run a full node on the staging network (now, no permission needed)

`networks/staging-1/` holds the pinned genesis and bootstrap peers — clone, build, point your node at them, and you're syncing and independently verifying the live chain, serving your own RPC and explorer. One screen of commands, no GPU, no stake: `networks/staging-1/README.md`. The genesis digest is the network's fingerprint; your node's `app_hash` at any height must equal what `rpc.hashkinetics.org` reports — same input, same hash, no trust required.

## Run a validator

The staging network recruits external validators now — one Linux box, **no GPU, no stake, no cost**. Your keys are generated on your machine and never leave it; your permanent identity is a stateless SLH-DSA root; exhaustion and downtime are liveness faults only, never fund-loss — proven the hard way: this network's val-0 ran its tree to zero, was revived by a root-signed cert carried through a peer (`issue-rotation` → `hk_submitRotation`), and rejoined with a fresh tree. The whole flow is in this repo.

Read `docs/VALIDATOR-ONBOARDING.md`, then mail **validators@hashkinetics.org** with your `validator.json`. The next genesis ceremony forms testnet-1 with external operators from day one.

## What this repo is

| Path | What |
|---|---|
| `chain/` | The Rust workspace — state machine, mandates, shielded pool, channels, consensus adapter (Malachite BFT), node, wallet, RPC |
| `chain/crates/hk-crypto` | Hash-based signatures: LMS/HSS (RFC 8554) with reserve-then-sign persistence, SLH-DSA-SHAKE-192s roots (FIPS 205), PayWord, KAT-verified |
| `zkvm-bakeoff/` | The shared spend circuit (`no_std`) + SP1/RISC0/OpenVM harnesses, the GPU prover service, and the aggregation guest |
| `docs/CAPACITY-SHEET.md` | Every measured number with date, hardware, and the command that produced it |
| `docs/VALIDATOR-ONBOARDING.md` | Join the network: keygen → ceremony → run → operating rules |
| `docs/AUDIT-SCOPE.md` | Trust boundaries, crypto inventory, consensus invariants — the audit work-packages, prepared before the auditors |

Protocol papers (whitepaper + formal yellowpaper with the state transition, proof relations, and invariants I1–I10): [hashkinetics.org](https://www.hashkinetics.org) → Papers.

## The honesty ledger (what is NOT real yet)

This section is load-bearing. If it ever disappears, assume the worst.

- **Nothing is audited.** Scope is prepared (`docs/AUDIT-SCOPE.md`); the audit campaign is a gate before any mainnet.
- **No 30-day public soak yet** — the staging net is young; the soak clock starts with external validators aboard.
- **Rotation hardening (R-series) is production-proven, not just built:** automatic threshold rotation has fired unattended across 45+ epochs; the peer-carried revival path has resurrected a fully-exhausted validator three times; certificates verify against the set as of their height, so syncing across rotation boundaries works (v0.10.7); catch-up verification is parallel (v0.10.8 — a joining machine measured 2→71 blocks/min, converging on a chain that adds ~27); and since v0.10.9 syncing spends **zero** signing leaves — proven end-to-end when an independent observer re-verified the entire chain from genesis (~76,000 blocks, every vote and STARK) and reported the byte-identical state commitment with zero leaves spent. Still open and ledgered: engine resume at store tip (deep restarts spend ~10 minutes rehydrating the decided-log before rejoining — measured and acceptable, but on the list), abstain-while-behind (a parked validator burns one-time leaves on futile rounds), and a tick-based rotation-threshold check.
- All throughput numbers are **single-machine or single-datacenter**; WAN pacing is unmeasured until the soak.
- Transparent (Lamport-signed) transactions are wire-heavy at scale — block-log segmentation and the WOTS account scheme are queued; the shielded path (2.7 KB/tx + one aggregate) is the product path.
- A faucet waits on the account-creation transaction (accounts are genesis-only today).
- Explorer and wallet are devnet-grade surfaces; in-circuit WOTS awaits its KAT campaign; agent-side proving assumes GPU-class hardware.

What "LIVE" means above: demonstrated on a running chain with a receipt you can reproduce from this repo. Nothing here is a projection wearing a demo's clothes.

## Security

Found something? **security@hashkinetics.org.** No bug bounty is funded yet (pre-audit stage); reports are credited, taken seriously, and answered by a human who reads code.

## License

MIT OR Apache-2.0, at your option. Vendored third-party trees keep their own licenses.

---

*HashKinetics — kinetic money on hash-based trust. Nothing is for sale; the chain is the pitch.*
