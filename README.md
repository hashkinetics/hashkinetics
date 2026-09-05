# HashKinetics ($HKN)

**A post-quantum L1 that enforces AI-agent spending limits it cannot see.**

[**hashkinetics.org**](https://www.hashkinetics.org) · [**Live explorer**](https://www.hashkinetics.org/explorer) · [**Public RPC**](https://rpc.hashkinetics.org) · [**X @hashkinetics**](https://x.com/hashkinetics) · [**Discord**](https://discord.gg/RsSfb9gn3) · [**Telegram**](https://t.me/+tnRXX8KOCWA3YjE1) · validators@hashkinetics.org

`testnet-1: LIVE since 2026-09-02` · `node v0.16.0 · wallet v0.14.0` · `seats change on the running chain (v0.14.0)` · `issued assets with issuer controls (v0.15.0)` · `spend proof: 1.24 s (GPU)` · `274 tx/s storm-measured` · `nothing is for sale`

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

A 4-validator public **testnet-1** runs since 2026-09-02 — real hash-signed BFT, pinned genesis, protocol fee bound into the genesis from block 1, shielded pool active, 59,000+ blocks by 2026-09-05, every seat on v0.15.0 (its predecessor staging-1 ran 107k blocks and is archived). Four releases have rolled onto it without a pause, one voter at a time: v0.13.2 (hardening), v0.14.0 (seat changes), v0.15.0 (issued assets).

- **Explorer:** [hashkinetics.org/explorer](https://www.hashkinetics.org/explorer) — "the scanner that can't dox you": commitments, nullifiers, one running total. No amounts, no parties, by construction.
- **RPC:** `https://rpc.hashkinetics.org` (JSON-RPC over POST; try `{"method":"hk_chainInfo","params":{}}`).
- The pool shows a **$8 shielded economy** placed by the public demo suite: mandate-fed purchases, stealth bonuses wallets discovered by scanning, a rogue agent refused on-chain, and a disclosure package verified offline.
- Validator epochs are public: when a validator rotates its consensus tree under its SLH-DSA root, the explorer shows the new epoch badge. Rotations are **automatic** since v0.10.5 (leaf-budget threshold) — the fleet has rotated itself through dozens of epochs unattended, zero blocks missed.
- **The chain's identity is cryptographic:** `chain_id` is derived from the genesis digest (testnet-1: `hashkinetics-1-4e4ea68d`; staging-1 was `hashkinetics-1-557f2ea6`), `hk_chainInfo` returns the full fingerprint, and nodes **refuse to peer across genesis** — you are either verifying this history from block 1 or you're on your own chain, by construction (v0.10.6).
- Since v0.10.7, commit certificates verify against the validator set **as of their height** — a new node syncs from genesis across every key-rotation boundary in the chain's history. That's what makes external validators possible on a chain whose keys retire themselves. Since v0.14.0 the **validator set itself changes on the running chain** — a seat is admitted or removed by a certificate approved by strictly more than ⅔ of the current seats' root keys, no new genesis (`docs/V1-VALIDATOR-SET-CHANGES.md`; rolled to the fleet 2026-09-04, chain never paused).
- Since v0.15.0 the chain carries **issued assets**: an issuer registers an asset under an id only it can claim (`H(issuer ‖ symbol)`), mints, burns, freezes an account and pauses the asset under a policy fixed at registration; per-asset supply lives in the state commitment and every movement of a registered asset passes one gate — the floor a stablecoin issuer needs before it deploys (`docs/X1-ISSUED-ASSETS.md`; `hk_getAssets` on the public RPC; devnet gate 40/40).

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

## Get ON the chain (since v0.11 — the front door; v0.13.0 pays shielded too)

You no longer need a genesis seat — and you no longer need a terminal. **Windows users: download `HashKinetics-Wallet.exe` from the latest release** (unsigned testnet build — SmartScreen will warn; verify the published sha256): create a wallet, tap the faucet, pay anyone. Your keys never leave your machine, and your first payment signs with your own hash-based one-time key at index 0.

Prefer the CLI? Generate a keychain locally, paste one string into the faucet, and you hold a funded, spendable account whose id nobody can squat (`id = H(auth commit)`, checked in consensus):

```bash
# 1 · keys are born on YOUR machine and never leave it
./target/release/hk-node account-new ~/my-account       # prints your account id + auth commit

# 2 · paste the AUTH COMMIT at https://www.hashkinetics.org/faucet  (or curl the faucet directly)

# 3 · you're a chain user — check, then pay anyone:
./target/release/hk-node account-balance https://rpc.hashkinetics.org ~/my-account
./target/release/hk-node account-send ~/my-account https://rpc.hashkinetics.org <TO-ID> 50000
# or sponsor a friend onto the chain from your own balance:
./target/release/hk-node account-create ~/my-account https://rpc.hashkinetics.org <THEIR-AUTH-COMMIT> 10000
```

Your first spend signs with your own hash-based ratchet at index 0 — the same one-time-signature discipline the validators live by, in your hands. ⚠ v0.11.0 is a consensus-breaking upgrade: nodes below it cannot decode blocks containing an account creation.

Then **watch it land**: the explorer at [hashkinetics.org/explorer](https://www.hashkinetics.org/explorer) now answers *anything* — paste a block height, a transaction id, an account id, or a nullifier into one search box and get the full picture, with shareable deep links (`#tx=…`, `#account=…`, `#block=…`). The wallet links every payment straight to its proof on-chain. Shielded holdings stay invisible by design — the scanner that can't dox you. (v0.11.2) **Since v0.13.0 the wallet is fee-aware and shielded:** it shows the chain's fee, refuses locally what the chain would refuse, and can shield, unshield, pay a stealth address and export a one-time disclosure — proofs made on the public prover.

## Issue an asset (since v0.15.0 — the floor a stablecoin issuer needs)

Any funded account can become an issuer. The asset id is derived from *your* account and the symbol, so nobody can squat it; the policy you register with is the policy the chain enforces forever after — mint, freeze an account, pause the asset, allow shielding — and every movement of your asset passes one consensus gate. Supply lives in the state commitment; `hk_getAsset` reports it with the node's own conservation check.

```bash
# the id your account gets for a symbol (offline)
./target/release/hk-node asset-id ~/my-account USDC.t

# register (policy flags: m=mintable f=freezable p=pausable s=shieldable, or - for none), then mint, freeze, pause, burn
./target/release/hk-node asset register ~/my-account https://rpc.hashkinetics.org USDC.t 6 mfps
./target/release/hk-node asset mint     ~/my-account https://rpc.hashkinetics.org <ASSET-ID> <TO-ID> 5000000
./target/release/hk-node asset freeze   ~/my-account https://rpc.hashkinetics.org <ASSET-ID> <ACCOUNT-ID>   # unfreeze to lift
./target/release/hk-node asset pause    ~/my-account https://rpc.hashkinetics.org <ASSET-ID>                # unpause to lift
./target/release/hk-node asset burn     <holder-dir> https://rpc.hashkinetics.org <ASSET-ID> 1000000 <DESTINATION-hex>
./target/release/hk-node asset info     https://rpc.hashkinetics.org USDC.t@<YOUR-ACCOUNT-ID>            # supply, burned, paused, frozen, conserved
```

A frozen account's transfer comes back as `rejected: frozen by issuer`; a paused asset's as `rejected: asset paused` — receipts the explorer shows. What is *not* here yet: attested (reserve-backed) minting and burn receipts for an issuer's return path — designed in `docs/STABLECOIN-RAILS-AND-ORACLE-PLAN.md`, not built; every issued asset on testnet-1 is a test asset. Rule, gates and commitment layout: `docs/X1-ISSUED-ASSETS.md`. ⚠ The first asset transaction on testnet-1 makes v0.15.0 the minimum node version from that block.

## Run a full node on testnet-1 (now, no permission needed)

`networks/testnet-1/` holds the pinned genesis, the bootstrap peers and — since v0.15.1 — the three STARK verifying keys (`vks.json`, pinned by the genesis, so your node verifies every proof locally and never depends on our prover). Clone, build, point your node at them, and you're syncing and independently verifying the live chain, serving your own RPC and explorer — and, since v0.15.2, listed on the network's live roll call ([hashkinetics.org/network#live](https://www.hashkinetics.org/network#live), read from the gateway's own peer table through `hk_getPeers`) the moment you connect. One screen of commands, no GPU, no stake: `networks/testnet-1/README.md` (run the current release, v0.15.2; v0.13.0 is the minimum to sync, and each appended transaction kind raises the minimum at the block where it first appears). The genesis digest is the network's fingerprint; your node's `app_hash` at any height must equal what `rpc.hashkinetics.org` reports — same input, same hash, no trust required.

### Keys at rest and disk (since v0.16.0)

Every secret file — the validator seed, `account.json`, `wallet.json`, the GUI's `shield.json` — can be stored **sealed**: `hk-node key-seal ~/hk-validator`, `hk-node account-seal <DIR>`, or the wallet's *Protect with a passphrase* (Argon2id 512 MiB, ≈1 s once per unlock → XChaCha20-Poly1305; the passphrase comes from `HK_KEY_PASSPHRASE` / `HK_WALLET_PASSPHRASE`, a `_FILE`, a systemd `LoadCredential=`, or a prompt; weak passphrases are refused, `hk-node passphrase-new` prints seven random words, and an optional key file — `hk-node keyfile-new`, `*_KEYFILE` — is a second factor the backup never carries). Plain files keep working; sealing is per file and reversible. On disk, committed blocks are packed into 1,024-block segments off the commit path, whole old segments can be pruned with `HK_RETAIN_BLOCKS`, and the search index survives restarts (`docs/VALIDATOR-ONBOARDING.md` §5a–5b). The faucet runs as a hot wallet with a small float refilled from a cold treasury (`docs/FAUCET-RUNBOOK.md`).

## Run a validator

The testnet recruits external validators now — one Linux box, **no GPU, no stake, no cost** — and the first one is seated: on 2026-09-05 an independent operator who had re-verified the chain from genesis on the public kit was admitted on the running chain by a certificate from 3 of the 4 founding seats' roots (block 72219, effective 72220; 5 seats since, no new genesis, chain never paused). Your keys are generated on your machine and never leave it; your permanent identity is a stateless SLH-DSA root; exhaustion and downtime are liveness faults only, never fund-loss — proven the hard way: this network's val-0 ran its tree to zero, was revived by a root-signed cert carried through a peer (`issue-rotation` → `hk_submitRotation`), and rejoined with a fresh tree. The whole flow is in this repo.

Read `docs/VALIDATOR-ONBOARDING.md`, then mail **validators@hashkinetics.org** with your `validator.json`. Honest framing: external operators start as **observers** (full verification, own RPC + explorer — same binary, minus the vote); since v0.14.0 a voting seat is **admitted on the running chain** by a certificate approved by more than ⅔ of the current seats' root keys — no new genesis (`docs/V1-VALIDATOR-SET-CHANGES.md`). An observer at the tip with our `app_hash`, running the current release, is the precondition; the first external operator is syncing toward exactly that, and his seat follows the moment he is there — no ceremony, no restart. How a genesis is run, with the record of this one: `docs/CEREMONY-TESTNET-1.md`.

## What this repo is

| Path | What |
|---|---|
| `chain/` | The Rust workspace — state machine, mandates, shielded pool, channels, consensus adapter (Malachite BFT), node, wallet, RPC |
| `chain/crates/hk-crypto` | Hash-based signatures: LMS/HSS (RFC 8554) with reserve-then-sign persistence, SLH-DSA-SHAKE-192s roots (FIPS 205), PayWord, KAT-verified |
| `zkvm-bakeoff/` | The shared spend circuit (`no_std`) + SP1/RISC0/OpenVM harnesses, the GPU prover service, and the aggregation guest |
| `docs/CAPACITY-SHEET.md` | Every measured number with date, hardware, and the command that produced it |
| `networks/testnet-1/` | The join kit: pinned genesis, bootstrap peers, `CHECKSUMS` for every release |
| `docs/VALIDATOR-ONBOARDING.md` | Join the network: keygen → observer → seat (admitted on the running chain since v0.14.0) → operating rules |
| `docs/V1-VALIDATOR-SET-CHANGES.md` · `docs/X1-ISSUED-ASSETS.md` | The v0.14 / v0.15 consensus rules: seat changes and issued assets — rule, wire, activation, runbooks |
| `docs/RPC.md` · `docs/FEES.md` · `docs/WALLET-GUIDE.md` | Every RPC method with its fields; the protocol fee as a genesis fact; the Windows wallet guide |
| `docs/AUDIT-SCOPE.md` | Trust boundaries, crypto inventory, consensus invariants (incl. V1 and X1) — the audit work-packages, prepared before the auditors |
| `explorer/` | The single-file explorer behind hashkinetics.org/explorer — runs against any node RPC |
| `chain/rehearsal.sh` · `chain/gate-v1.sh` · `chain/gate-x1.sh` | The devnet gates every release passes: ceremony + restore shapes, seat changes (25/25), issued assets (40/40) |
| `CHANGELOG.md` | Every release with its gate receipts and roll receipts — dated, with the incidents that shaped it |

Protocol papers (whitepaper + formal yellowpaper with the state transition, proof relations, and invariants I1–I10): [hashkinetics.org](https://www.hashkinetics.org) → Papers.

## The honesty ledger (what is NOT real yet)

This section is load-bearing. If it ever disappears, assume the worst.

- **Nothing is audited.** Scope is prepared (`docs/AUDIT-SCOPE.md`) and CertiK is engaged (2026-09-02); the audit campaign is a gate before any mainnet.
- **No 30-day public soak yet** — testnet-1 launched 2026-09-02 (staging-1 before it ran six days and 107k blocks); the soak clock starts with external validators aboard — the first external operator is syncing, and since v0.14.0 the seat can be admitted without a genesis.
- **Issued assets are issuer-signed, not yet attested.** The registry, mint/burn/freeze/pause and conservation are live (v0.15.0); the attested-mint path (an issuer's deposit attestation verified in consensus, paired with a bonded hash-signed relayer) and the burn-receipt return path are designed (`docs/STABLECOIN-RAILS-AND-ORACLE-PLAN.md`), not built; no stablecoin issuer has deployed — every issued asset on testnet-1 is a test asset.
- **Rotation hardening (R-series) is production-proven, not just built:** automatic threshold rotation has fired unattended across 45+ epochs; the peer-carried revival path has resurrected a fully-exhausted validator three times; certificates verify against the set as of their height, so syncing across rotation boundaries works (v0.10.7); catch-up verification is parallel (v0.10.8 — a joining machine measured 2→71 blocks/min, converging on a chain that adds ~27); since v0.10.9 syncing spends **zero** signing leaves — proven end-to-end when an independent observer re-verified the entire chain from genesis (~76,000 blocks, every vote and STARK) and reported the byte-identical state commitment with zero leaves spent; and since v0.10.10 a validator that falls behind **abstains instead of burning keys** (corroborated peer evidence gates all vote/proposal signing; gate receipt: a deliberately-wedged voter spent 2 leaves where the old behavior cost a fresh tree ~1,700, then rejoined byte-identical and voted at the first possible height) and the rotation threshold is checked on a **timer as well as on commits** — a parked node now rotates itself before exhaustion instead of after. Since v0.12.2 a rotation certificate that never landed is re-issued instead of wedging the validator (R9 — production-proven the day it shipped), and since v0.13.0 (R10 v2) a restart resumes at the chain height without rehydrating history — voting within seconds. testnet-1's own first rotation: all four seats crossed their thresholds and rotated unattended at heights 11,584–11,595 on 2026-09-03, zero blocks missed. Still open and ledgered: R11 — the node's ~6.7 GB steady RSS is the proof-system verifier client's fixed footprint, not chain history; a verify-only client trims it.
- All throughput numbers are **single-machine or single-datacenter**; WAN pacing is unmeasured until the soak.
- Transparent (Lamport-signed) transactions are wire-heavy at scale — the block log is segmented on disk since v0.16.0 (1,024-block segments, whole-segment retention), but the WOTS account scheme that shrinks them on the wire is still queued; the shielded path (2.7 KB/tx + one aggregate) is the product path.
- The faucet drips test units with no monetary value; the treasury was allocated in the testnet-1 genesis. Every transaction pays a flat 100-micro protocol fee (burned) — an anti-spam floor and a mechanism rehearsal, not a fee market.
- Explorer and wallet are public-testnet surfaces, not audited products: keys sit in JSON on your disk — plain by default, sealed with a passphrase if you choose (v0.16.0 / wallet v0.14.0: Argon2id 512 MiB → XChaCha20-Poly1305, strength-checked passphrases, optional key file; no OS-keystore or HSM path yet, and a running node or wallet still holds keys in memory), and the wallet's shielded side has a 64-spend one-time-key budget per master before you rotate it. In-circuit WOTS awaits its KAT campaign; agent-side proving on your own hardware assumes a GPU — the public prover does it for you on the testnet.

What "LIVE" means above: demonstrated on a running chain with a receipt you can reproduce from this repo. Nothing here is a projection wearing a demo's clothes.

## Security

Found something? **security@hashkinetics.org.** No bug bounty is funded yet (pre-audit stage); reports are credited, taken seriously, and answered by a human who reads code.

## License

MIT OR Apache-2.0, at your option. Vendored third-party trees keep their own licenses.

---

*HashKinetics — kinetic money on hash-based trust. Nothing is for sale; the chain is the pitch.*
