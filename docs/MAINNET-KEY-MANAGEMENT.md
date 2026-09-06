# Mainnet Validator Key Management (SCMS)

**Status:** design + first build (0.9 → 1.0 track)
**Answers:** *"What happens after root exhaustion? What is the plan for mainnet?"*
**Date:** 2026-08-16

---

## TL;DR — there is no "root exhaustion"

That is the entire reason the root is a **stateless** signature.

HashKinetics validator keys are a two-layer hierarchy:

```
   SLH-DSA-SHAKE-192s ROOT      ← stateless (FIPS 205). Never exhausts. Cold/HSM.
        │  signs a RotationCert delegating to ↓
        ▼
   HSS/LMS OPERATIONAL TREE      ← stateful (RFC 8554). Finite. Rotated under the root.
        │  signs ↓
        ▼
   consensus votes & proposals
```

- The **root never runs out.** SLH-DSA (FIPS 205) is a *stateless* hash-based
  signature. It keeps no leaf counter and is designed for ~2⁶⁴ signatures per key —
  astronomically beyond a validator's lifetime. It is the permanent on-chain
  identity, registered once when the validator stakes.
- The thing that **does** exhaust is the **operational HSS tree** (stateful,
  one-time leaves). When it nears empty the validator mints a *fresh* operational
  tree and the root signs a **rotation certificate** binding the new operational
  public key. Because the root is inexhaustible, this repeats **forever**.
- Push the thought experiment to the root's own 2⁶⁴ ceiling: at one rotation per
  hour that is ~10¹⁵ years. Not a real event. And even then the answer is a
  staking-level root re-key (a governance transaction), never a liveness fault.

So: **operational keys exhaust and rotate; the root is the anchor that refreshes
them.** The finite thing is renewed by the infinite thing.

---

## What exhausts, what doesn't

| Layer | Scheme | Stateful? | Capacity | On exhaustion |
|---|---|---|---|---|
| Root identity | SLH-DSA-SHAKE-192s | No | ~2⁶⁴ sigs | Never happens in practice; if ever, re-stake a new root (governance) |
| Operational | HSS/LMS-SHAKE-256 | **Yes** | 2¹⁵ now (tunable to 2²⁰⁺) | **Auto-rotate** to a fresh tree, root-certified |
| (optional) Epoch | XMSS^MT / large HSS | Yes | 2²⁰⁺ | Rotate under root; keeps the cold root even colder |

Only the middle row is a live concern, and it is handled by rotation + persistence
(below). The root's job is precisely to make that row renewable.

---

## The rotation certificate (SCMS primitive)

SCMS = Signed Certificate Management System: a long-term certificate (the SLH-DSA
root) issues short-term operational certificates (the HSS trees). This is the same
pattern that secures V2X fleets and, here, is the chain's consensus key-rotation
primitive.

```
RotationCert {
    root_pk:            SLH-DSA-192s public key (48 B)   // permanent validator identity
    new_op_pk:          HSS operational public key        // root of the fresh tree
    epoch:              u64                               // strictly increasing rotation counter
    valid_from_height:  u64                               // activation height
    root_sig:           SLH-DSA signature (~16 KB)        // root signs (new_op_pk ‖ epoch ‖ valid_from_height)
}
```

**Verification (every validator, stateless):**
1. `SLH-DSA.verify(root_pk, new_op_pk ‖ epoch ‖ valid_from_height, root_sig)` ✓
2. `root_pk ∈ active staking set` ✓
3. `epoch > last accepted epoch for this validator` ✓ (monotone — no rollback)

On accept, the validator-set entry's *current operational pubkey* becomes
`new_op_pk`, effective at `valid_from_height`. From that height the validator signs
votes with the new tree; peers verify against `new_op_pk`. The old tree is retired.

Cost: one ~16 KB cert per rotation. At 2¹⁵ sigs/tree and a few sigs/sec that's a
cert every several hours per validator — negligible bandwidth.

---

## Rotation flow (seamless, no missed blocks)

1. Node watches `operational.remaining()`.
2. At a threshold (e.g. 20 % left) it generates a **fresh** operational tree from a
   new random seed — off the hot path, on a big-stack worker.
3. It asks the **root** to sign the `RotationCert` for the new pubkey
   (root lives in an HSM in prod; on devnet the root seed is local).
4. The cert is published as a consensus-visible message / transaction.
5. Peers verify (3 checks above) and stage `new_op_pk` at `valid_from_height`.
6. The **old** tree keeps signing until `valid_from_height`; the **new** tree takes
   over exactly there. Overlap means zero missed blocks.
7. Old tree retired; its remaining leaves are never touched again.

---

## Mainnet safety rule #1 — monotone persisted state ("reserve-then-sign")

A stateful hash key must **never** sign twice from the same leaf. Across a crash or
restart that means the advancing private state has to be **durable before the
signature is released**:

1. hbs-lms computes the signature and the *advanced* key bytes.
2. We atomically write `used ‖ advanced_state` to disk and `fsync` — **the reserve**.
3. Only *then* do we commit the advance in memory and release the signature.

If the write fails we release nothing and don't advance — the same leaf is retried.
On restart we reload the persisted state (same seed → same tree/pubkey; the state
bytes carry the true leaf index) and continue **past** the last durably-used leaf.
The one forbidden operation is restoring an **older** snapshot — that reuses leaves.
Backups of this file are therefore poison; only forward motion is legal.

**Built in this pass:** `HashSigner` persists `used ‖ state` atomically inside
`sign()` before returning; the node's consensus signer loads it from
`<home>/consensus_state.bin` on start. A restarted validator no longer risks leaf
reuse.

---

## Mainnet safety rule #2 — one key, one signer

A stateful key must have exactly **one** advancing writer. Two independent signers
over one tree will both march from leaf 0 and collide.

**Finding (fixed in this pass):** the node built two HSS signers from the same seed —
one in `HkApp` for the proposal Fin, one in the engine for votes/proposals — so a
proposer used **leaf 0 twice** (a Fin and a Proposal) under one tree. Both verified,
but OTS reuse leaks key material. **Fix:** the proposal Fin no longer carries a
consensus-key signature. Streamed proposal parts are authenticated transitively —
the value id is a hash of the content, and the engine already verifies the
proposer's `SignedProposal` over that id. The Fin now carries the value id for a
consistency check only. Result: the **engine is the sole consensus signer**, and it
is the one whose state is persisted.

---

## Mainnet signature size — aggregate to a proof of consensus

Operational HSS signatures are a few KB each; a commit certificate over N validators
is N of them. That is fine at devnet scale and heavy at mainnet scale. The mainnet
answer is **aggregation, not a different signature**:

- A commit certificate becomes a single **STARK proof** attesting "≥⅔ of the staked
  set signed this block" — one ~200 KB proof regardless of N, verified in ms. This is
  the lean-multisig / post-quantum-SNARK direction (recursive hash-based STARKs, no
  pairing, no trusted setup — quantum-safe end to end).
- **Checkpoint proofs** compress history: a periodic STARK proves the whole chain of
  commit certs and rotation certs up to height H, so light clients and new nodes
  verify one proof instead of replaying every multi-KB signature.

Neither changes the trust model — both are hash-based and prove exactly the
signatures they replace. They are a P2/P3 item; the primitives (STARK prover on the
spend circuit) are the same ones gate 2 is already benchmarking.

---

## Custody — HSM per NIST SP 800-208

- **Root (SLH-DSA-192s):** cold. In production it lives in an HSM that implements
  the stateful-HBS guidance of SP 800-208 (Marvell LiquidSecurity, Thales, et al.
  now ship SLH-DSA/LMS/XMSS). The root signs only rotation certs — rarely — so it can
  stay offline and be brought out on a rotation cadence.
- **Operational tree:** hot, in the node, but its monotone counter is the *only*
  authority on leaf position and is the HSM/enclave-guarded artifact where available.
  The persisted-state rule above is the software-only floor when no HSM is present.
- **Optional epoch tier:** a middle XMSS^MT layer lets the cold root sign *weekly*
  (certifying epoch keys) while epoch keys certify operational keys *hourly* — the
  root then touches key material a handful of times a year.

### Where the software stands today (v0.16.0) and the seam an HSM plugs into

- **Keys at rest — shipped.** `priv_validator_key.json` (root seed), `account.json`,
  `wallet.json` and the GUI's `shield.json` can be sealed on disk: the `HKE1` envelope
  (`hk-wallet/src/sealed.rs`) — Argon2id 512 MiB/t=4/p=4 by default (parameters ride in
  the envelope; `HK_SEAL_M_KIB`/`HK_SEAL_T`, floor 64 MiB/t=3) → XChaCha20-Poly1305, AAD
  `hk/v1/sealed`, one salt per key, a fresh nonce per write; the derived key is cached so
  the KDF runs once per unlock. Passphrase strength is enforced (`check_strength`), a
  7-word generator exists (`passphrase-new`), and an optional key file (`keyfile-new`,
  `*_KEYFILE`) is a second factor the backup never carries. Passphrase sources: env, file,
  systemd `LoadCredential=`, prompt. Commands: `hk-node key-seal|key-unseal HOME`,
  `account-seal|account-unseal DIR`; the GUI has "Protect with a passphrase". A plain file
  keeps working — sealing is per file, per operator, reversible.
- **Not sealed yet:** `consensus_state.bin`, the advancing LMS/HSS private state
  (`used ‖ state`) rewritten on every signature. It is the *current operational tree*
  only — it cannot yield the root, and a root-signed rotation retires it — but a copy
  taken between two votes can sign as that operational key until rotation. Sealing it
  needs the derived key held in memory and one AEAD per write (cheap); it is scheduled
  with the signer refactor below rather than bolted on.
- **The seam.** Every signer the node uses goes through `hk_consensus::HkPriv` →
  `HashSigner::sign(&mut self, msg) -> Option<Vec<u8>>` with persistence inside the
  call (reserve-then-sign). An HSM-backed signer implements the same surface: the module
  holds the LMS private state and its monotone counter, the node passes the message
  digest and receives the signature; `remaining()` and `used()` come from the module.
  The root (`RootSecret`, SLH-DSA-192s, stateless) needs only `sign(bytes)` — the
  easiest half to move into an HSM first, since it signs a handful of certs a year.
  Nothing in consensus, the wire format or the certificates changes when the seed
  stops being a file.

---

## Validator lifecycle (staking)

- **Join:** stake + register the **SLH-DSA root public key** on-chain. That key *is*
  the validator's permanent identity and address. An initial `RotationCert` bootstraps
  the first operational tree.
- **Operate:** vote with the operational tree; auto-rotate under the root as above.
- **Exit / re-key:** unstake, or (on suspected root compromise) exit and re-stake a
  fresh root. Root change = governance-visible staking event, never a silent swap.

---

## Failure modes

| Event | Consequence | Handling |
|---|---|---|
| Operational tree nears empty | — | Proactive rotation at threshold |
| Operational tree fully exhausts before rotating | Validator can't sign → **liveness** fault (not safety); it stalls, quorum continues without it | Rotate; rejoin. Threshold + overlap prevents it |
| Node crash / restart | Risk of leaf reuse | Reload persisted `used ‖ state`; continue past last durable leaf |
| Root key lost | Validator can't rotate → eventually stalls | Exit + re-stake new root (governance) |
| Root key compromised | Attacker could certify a rogue op key | Detectable (unexpected epoch bump on-chain); slash + re-stake |
| Equivocation (two sigs, one leaf/height) | — | On-chain fraud proof → **slashable**; the stateful design makes reuse *detectable*, not just forbidden |

Note the asymmetry: exhaustion and key-loss are **liveness** faults (the validator
stops; the chain doesn't), never **safety** faults (the chain never accepts a bad
block). That is the property to preserve.

---

## Build status

**Done (0.9.1):**
- Single consensus signer (leaf-reuse bug fixed).
- Monotone persisted operational state (reserve-then-sign to
  `consensus_state.bin`, restart-safe).
- `provider`/`node` wiring so only the engine's signer advances, and it persists.

**Done (0.9.2 — rotation, increment 1):**
- Real **SLH-DSA-SHAKE-192s root** (`hk-crypto::slhdsa_adapter`, FIPS 205 via `fips205`):
  deterministic keygen from the master seed, deterministic sign, stateless verify. 48-byte
  key, 16,224-byte signature. Tested.
- **`RotationCert`** (`hk-consensus::rotation`): `{root_pk, new_op_pk, epoch,
  valid_from_height, root_sig}` with `issue()` (root signs a fresh operational pubkey),
  `verify_sig()`, and `verify_against(registered_root, last_epoch)` enforcing identity +
  monotone epoch. Tested (issue/verify chain, rollback rejected, forgery rejected, wrong
  root rejected).

**Done (0.9.3 — rotation, increment 2, live swap):**
- Genesis carries each validator's **SLH-DSA root pubkey** (derived from the same master
  seed); `HkValidator` stores `root_pk` + `epoch`; the address stays derived from the genesis
  operational key (stable across rotations).
- A `RotationCert` rides in the block (`Batch.rotations`). On commit every node runs
  `HkValidatorSet::apply_rotation` (signature + registered-root + monotone-epoch checks) and
  the engine gets the rotated set via the existing `Decided → Next::Start(height, set)` hook.
- The validator that owns the rotated root also swaps its **live operational signer** in the
  same commit: `HkPriv::rotate_to` replaces the tree inside the shared `Arc<Mutex<…>>`, so
  the engine's provider signs the next height with the new key — in lockstep with the set
  update, so votes verify.
- Per-epoch operational seeds via `op_seed(master, epoch)` (epoch 0 = genesis key).
- Demo trigger `HK_ROTATE_EVERY=N` issues a self-rotation every N heights.

**Hardening status — R-series SHIPPED AND PRODUCTION-PROVEN (v0.10.5 → v0.15.0):**
Staging incident #1 (2026-08-28) field-proved the urgency: no rotation trigger armed,
val-0's tree exhausted at height 10,848 and the chain halted 6 h rather than reuse a
leaf. The design held; the R-series closed the ops gap (C-PROGRAM-PLAN.md §R):
- **R1 ✅** — rotation fires itself at the `remaining()` <20% threshold; the fleet has
  rotated through dozens of epochs unattended, zero blocks missed.
- **R2 ✅** — exhausted-validator revival: `issue-rotation` CLI (root signs offline) +
  `hk_submitRotation` RPC (any peer carries the cert into a proposal). **Three real
  production revivals to date** (E1, E2, E3 — the third crossed live rotation
  boundaries on the way home).
- **R4 ✅** — leaf-budget gauge: `hk_chainInfo.signer {epoch, remaining, capacity}` +
  tiered budget logs + explorer epoch badges.
- **WS-F ✅** — restart-after-rotation: `adopt_epoch_signer` rebuilds the live signer at
  the chain's epoch; per-epoch state files resume their own used-leaf counters.
- **R6 ✅ (v0.10.7)** — commit certificates verify against the validator set AS OF their
  height (shared set history at the HkContext/engine seam; decide-path de-panicked) —
  sync/replay crosses every rotation boundary; external validators ungated.
- **R5.2 ✅ (v0.10.8)** — parallel certificate verification: catch-up went from 2 to 71
  blocks/min; **v0.10.9** made sync spend ZERO signer leaves (a syncing node never votes
  on futile rounds).
- **R8 + R1.b ✅ (v0.10.10)** — abstain-while-behind (a validator that is provably behind
  its peers stops spending leaves on rounds it cannot win) and the tick-based threshold
  check (rotation fires even while parked, not only on the commit path).
- **R9 ✅ (v0.12.2)** — stale-issue re-arm: a rotation certificate that never landed is
  re-issued instead of wedging the validator; production-proven the day it shipped (a
  validator that had burned its tree to zero healed itself).
- **R3 ✅ as R10 v2 (v0.13.0)** — the engine resumes at the CHAIN height (snapshot + replay),
  never at a height inferred from the block log; only a bounded window of decided heights
  stays in RAM, older history is served to peers from disk with a certificate re-check.
- **Fresh trees per chain (testnet-1 ceremony, 2026-09-02)** — a stateful tree that signed
  on one chain is never restarted from a reset counter on another; every seat generated
  new keys into a new home and the old home is kept only as an archive.
- **V1 ✅ (v0.14.0, rolled 2026-09-04)** — the validator SET changes on the running chain:
  a seat is admitted or removed by SLH-DSA root approvals from strictly more than ⅔ of the
  current seats, signed on each seat's own host (`hk-node set-change approve` reads that
  host's `priv_validator_key.json`; the key never moves), bound to the chain id and a
  commit-height window. No coordinator key exists. Mainnet: bonded self-admission +
  governance replace the approval rule; the certificate shape stays.
- **K5 ✅ (v0.14.0)** — a node on a genesis that pins its proof system refuses to start
  without a wired verifier (found by the first external operator's wedge at height 479).
- **Issuer keys (X1, v0.15.0)** — an issued asset's issuer is an ordinary account (L-ratchet
  one-time keys, reserve-then-sign); its policy and issuer are immutable after registration
  in v0.15, so an issuer that needs a key change registers under a fresh id until the
  governance path ships. Mainnet issuers hold the account seed in an HSM/systemd credential
  (K2 rules); the attested-mint path (X2) adds the issuer's own attestation key — the one
  classical signature the chain will verify, always paired with a hash-based relayer
  signature and a rate limit.
- R11 CLOSED in v0.17.0 (the node verifies with a verify-only client; the memory floor is
  now the node itself, not a proving engine) · Open: STARK-aggregated commit certificates (below).
- Operator hygiene learned in recovery: `consensus_state.bin` is the signer's spent-leaf
  state — never copy it between nodes; chain-data restores take `blocks/` + `snapshot.bin`
  only, and transplant tars must pack `snapshot.bin` FIRST (ordering skew wedges the engine).

**Mainnet crypto (P2/P3):**
- STARK-aggregated commit certificates (proof of consensus).
- STARK checkpoint proofs to prune signature history.
- HSM custody per SP 800-208; optional epoch tier.
