# HashKinetics — Audit Scope & Trust-Boundary Map

**v0.13.0 (2026-09-02 late; CertiK engaged; testnet-1 live). Purpose: the audit engagement starts from this document.** Since the original v0.9.7 draft the audit surface has GROWN — the usage sprint added consensus-affecting code that belongs in scope: `Tx::AccountCreate` (derived squat-proof account ids, `id = H(DOM_ACCOUNT_ID ‖ auth_commit)`, debit-then-create atomicity), the public `faucet-serve` drip service (rate limits, reserve-then-sign under a shared signer), the self-custody account CLI's reserve-then-sign nonce discipline, and the node-local search indexes (explicitly NOT in the state commitment). Deployed since and therefore IN scope: the v0.12 flat protocol fee (charge-then-refund-on-refusal, burn accounting in the state commitment) and its v0.13 genesis binding (`chain.fee` in genesis, env override refused; `genesis-build --alloc` squat-proof allocations from a nonce-0 auth commitment; `--demo-accounts` with PUBLIC seeds); the R9 rotation re-arm; R10 v2 (bounded decided window, value-sync served from the block log with certificate re-check before a block leaves the node, gap-free-suffix advertising, chain-height restore, background index pass); and the wallet's shielded side (`shield.json` reserve-then-advance counters, prover-side proof generation over HTTPS — the prover is untrusted for soundness, the node verifies). It
inventories every trust boundary, cryptographic primitive, consensus-critical invariant,
and deliberate v0/v1 shortcut — so an auditor's first week is spent auditing, not
archaeology. Maintained alongside the code; the honesty rule applies: nothing below is
audited until a named third party has signed a report saying so.

## 1 · System inventory

| Crate / component | Role | Consensus-critical? |
|---|---|---|
| `hk-spend-circuit` | THE shared statement (spend v3 + mint) + chain-side hash primitives — compiled identically into chain, wallets, zkVM guests | **Yes — soundness root** |
| `hk-state` | Deterministic state machine: accounts (L-ratchet), balances, MandateTree, channels, **shielded pool** | **Yes** |
| `hk-crypto` | SHAKE-256 domains · Lamport/L-ratchet · PayWord · LMS/HSS (`hashsig`) · SLH-DSA root (`slhdsa_adapter`) · ML-KEM adapter (`mlkem`) · SHAKE-AEAD (`noteenc`) | **Yes** |
| `hk-mandate` | MandateTree accounting (drip, envelopes, revocation) | **Yes** |
| `hk-consensus` | Malachite context, hash-based signing provider, RotationCert | **Yes** |
| `hk-node` | Node: batches, streaming, commit path, RPC, **in-node SP1 verifier**, indexes | Verifier + commit path yes; RPC/indexes no |
| `hk-wallet` | Client-side: addresses, sealing, scanning, witness building | No (but key-handling correctness = user-funds-critical) |
| `hk-prove` (`sp1/script/bin/serve.rs`) | GPU proving service | No (untrusted by design — §2) |
| Vendored: Malachite (BFT), SP1 (prover/verifier), fips205, hbs-lms, ml-kem, sha2/sha3 | Upstream dependencies | Verifier + crypto crates yes |

## 2 · Trust boundaries

```
[wallet: master seed, nk, ots indexes, note plaintexts]
      │ witness (contains nk + one WOTS sig)                 TRUSTED: local prover only
      ▼
[hk-prove: sees witnesses it proves]                          UNTRUSTED for integrity
      │ proof (bincode STARK)                                 (self-verify is a courtesy;
      ▼                                                        chain re-verifies)
[node: verifier + state machine]                              TRUSTED CODE, untrusted inputs
      │ every rule checked against chain-DERIVED expectations
      ▼
[consensus: 4+ validators, hash-based votes, app-hash equality]
```

Key boundary facts: the chain NEVER trusts a transaction's claim of public inputs (it
derives `SpendPublic`/`MintPublic` itself, incl. the tx-binding rule `H(credit‖fee)`);
proof bytes, stealth ciphertexts, and relayer identity are all untrusted; a delegated
prover learns nk + one leaf signature (documented residual — local proving is the
deployment posture); the KEM carries **zero** spend authority (lattice break ⇒ metadata
only).

## 3 · Cryptographic inventory

| Primitive | Implementation | Verification status | Audit priority |
|---|---|---|---|
| SHAKE-256 (all non-circuit hashing, domains, AEAD) | `sha3` crate | test-vectored upstream | Medium |
| SHA-256 (in-circuit + chain pool hashing) | `sha2` crate (+ SP1/RISC0 precompile patches, OpenVM lib) | patch-equality observed via cycle counts + identical outputs | **High** (patch paths) |
| Lamport + L-ratchet (account auth v0) | `hk-crypto::lamport` | unit tests; retry-hygiene caveat documented | Medium (replaced by LMS later) |
| LMS/HSS (consensus votes) | vendored `hbs-lms` (RFC 8554) | **KAT-verified**; live on devnet | **High** |
| SLH-DSA-SHAKE-192s (roots) | `fips205` crate | KAT'd upstream; live (RotationCert) | **High** |
| WOTS w=16, 67 chains (in-circuit spend auth) | `hk-spend-circuit` (hand-written) | 16 native tests incl. forgery paths; **NO external KAT (bench-grade plain W-OTS, not WOTS+)** | **Highest** |
| Spend-tree Merkle (depth 10) + address tag + nullifier | `hk-spend-circuit` | native + keystone tests | **Highest** |
| ML-KEM-768 (confidentiality only) | vendored rustcrypto `ml-kem` 0.3.2 | FIPS 203 impl; our adapter tested | Medium |
| SHAKE-AEAD (`noteenc`) | hand-written encrypt-then-MAC | unit tests; **hand-rolled — needs formal review** (nonce = commitment, one-time keys) | **High** |
| STARK verify (SP1 v6.4.0) | vendored/crates.io sp1 | upstream; our byte-match-then-verify wrapper tested live | **High** (wrapper + vk pinning) |

Domain-separation registry: circuit tags 1–12 and every `hk/v1/*` SHAKE domain are
tabulated in `docs/SHIELDED-POOL-SPEC.md` §2; `hk/v1/txid` in `hk-node/src/batch.rs`.
Invariant: no two uses share a domain; auditors should verify the registry is total.

## 4 · Consensus-critical invariants (what an auditor must fail to break)

1. **Determinism** — same blocks ⇒ bit-identical `state_commitment()` on every node (no
   clocks, no randomness, BTree-ordered iteration only; JSON encoding of fixed-field
   structs only).
2. **Atomicity** — a failed tx mutates NOTHING (including the account ratchet); all
   fallible checks precede all effects in every handler.
3. **App-hash binding** — the proposer's parent commitment is bound into the value id;
   divergence is consensus-fatal at commit.
4. **Leaf-index = nonce** — one-time account keys can't be reused (L-ratchet now; the
   same rule guards the consensus signer via reserve-then-sign persistence).
5. **Pool soundness chain** — no mint without a value-binding proof (inflation guard); no
   spend without: recent anchor + fresh nullifier + STARK against chain-derived publics +
   in-proof tx-binding (relayer non-malleability); conservation in = out1 + out2 + fee;
   both outputs appended atomically (capacity pre-checked).
6. **Nullifier privacy** — nf requires the SECRET nk; senders (who know rho) must not be
   able to compute it.
7. **Rotation safety** — RotationCert: root signature + registered root + strictly
   increasing epoch; live signer swap in the same commit as the set update.
8. **Secure defaults** — an unconfigured node (no verifier) REJECTS shielded traffic.

## 5 · Known-unaudited / deliberate shortcuts (dated, tracked)

JSON wire codec (binary codec = WS8; double-hex tax measured) · vk fetch-at-startup on
devnet (mainnet: genesis-pinned vk hashes) · single-asset pool v1 · wallet state
(ots_index, notes) in-memory · node note/leaf indexes in-memory · demo randomness
deterministic · plain W-OTS (not WOTS+ masks) in-circuit — acceptable for bench/devnet,
revisit at audit · L-ratchet rejected-tx retry hygiene (documented in tests) · rotation
hardening list (epoch persistence across restart-after-rotation, pre-gen trees, cert
gossip, real threshold) · per-proof in-node verify until aggregation (P2.3) · no fee
market, no slashing path yet (WS8).

## 6 · Suggested audit work-packages (P3)

1. **Circuit soundness** (highest value): WOTS security argument, spend-tree binding,
   nullifier/owner derivations, conservation, malleability — against
   `SHIELDED-POOL-SPEC.md` §8.
2. **State machine**: invariants §4 as adversarial test campaign (fuzz the tx surface).
3. **Crypto adapters**: KAT campaigns for WOTS (add vectors), noteenc formal review,
   patch-path equivalence (sha2 precompiles), fips205/hbs-lms/ml-kem integration review.
4. **Key management**: SCMS lifecycle (reserve-then-sign, rotation), wallet ots-index
   discipline.
5. **Consensus integration**: Malachite swap surface (signing provider, value id binding,
   codec), gossip limits and DoS (proof-sized txs).
6. **Dependency review**: pinned vendor trees (`vendor/external/PINS.md`), sp1 verifier
   wrapper, supply-chain reproducibility.

Budget line (plan): $400–700k across two firms (one circuit-specialist, one systems).
