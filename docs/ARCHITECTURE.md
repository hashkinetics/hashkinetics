# Architecture map — plan → code

Plan: `../HASHKINETICS-IMPLEMENTATION-PLAN.md` (sections referenced below).

| Plan | Code home | Vendored inputs |
|---|---|---|
| §3.1 Two-hash doctrine | `chain/crates/hk-crypto` (`hash.rs`: SHAKE-256 external; Poseidon2/RPO in-circuit later) | `rustcrypto-hashes`, `plonky3`, `miden-crypto` |
| §3.2 Signature stack | `hk-crypto`: `hashsig.rs` (**LMS/HSS over SHAKE-256, real + KAT-verified, 0.9**) · `traits.rs` · Lamport L-ratchet (`lamport.rs`, account auth) · SLH-DSA/WOTS adapters feature-gated | `hbs-lms-rust` (LMS, wired), `fips205-rust` (SLH-DSA root, live since 0.9.2), `xmss-reference-c` + `lms-hash-sigs-c` (KATs) |
| §3.3 Consensus vote signing | `hk-consensus` provider — **LIVE since 0.9.0** (design record: `docs/HASHSIG-CONSENSUS-SWAP.md`); rotation under SLH-DSA roots since 0.9.3, R-series hardening 0.10.5→0.13.0 | `hashsig` primitive above; `malachite` SigningScheme seam |
| §6 QHT channels + §12 agent GTM | **`hk-facilitator` (RAG-as-a-merchant, 0.8): PayWord-metered paid search settled on-chain** | `agentic/turbovec` (drop-in index), `x402` (facilitator pattern) |
| §3.3 Leaf-index=nonce (enforced in `hk-state` accounts) · equivocation slashing (planned, WS8) | IETF draft-wiggers patterns (research 03) |
| §3.4 ML-KEM confidentiality boundary | `hk-crypto` (feature `mlkem`, live since 0.9.7 — stealth addresses) | `rustcrypto-kems` |
| §4 Shielded pool / CVA | `hk-state::pool` (consensus state) + `hk-wallet` (client) + `zkvm-bakeoff/circuit` (`hk-spend-circuit`, the shared statement) — live since 0.9.6; disclosure 0.9.8; aggregation 0.9.9 | `penumbra` (tct, view service), `librustzcash` (note plumbing), zkVM from bake-off |
| §5 MandateTree v2 | **`chain/crates/hk-mandate` (drip math implemented + tested)** | `docs/carried-specs/MANDATETREE-SPEC.md`, `ap2` (mandate mapping) |
| §6 QHT channels | `hk-crypto/payword.rs` (implemented) + `hk-channels` (P0/P1) | `docs/carried-specs/HYPERTREE-CHANNELS-SPEC.md`, `x402` |
| §7 Chain / consensus | **`hk-consensus` (HkContext, devnet-proven) + `hk-node` (full node: codec/streaming/loop/testnet-gen; LIVE 4-validator devnet 2026-08-15)** | `malachite` (vendored engine) |
| §7.4 Native objects | `hk-primitives` (types) → `hk-state` modules | — |
| Usage layer (0.11+) | `hk-node/src/account.rs` (self-custody accounts, `Tx::AccountCreate`), `faucet.rs` (public drip service), `rpc.rs` (20 JSON-RPC methods — `docs/RPC.md`), `store.rs` + `state.rs` (block log, snapshots, R10 v2 disk-served history), `hk-wallet-gui` (Windows wallet, fee-aware + shielded) | — |
| Fees (0.12.2 / 0.13.0) | `hk-state` (charge → refund-on-refusal → burn, `fees_burned` in C(Σ)); genesis `chain.fee` authoritative (`docs/FEES.md`) | — |
| §9 zkVM bake-off (gate G2 ✅ 1.24 s) | `zkvm-bakeoff/` (RESULTS.md; SP1 chosen, prover service `sp1/script/src/bin/serve.rs`) | `sp1`, `openvm`, `miden-vm`, (`risc0` via .bat) |

Build reality: no Rust toolchain in the Cowork sandbox — **Yadu's machine (ASUS-SERVER, WSL) runs `cargo build`**; the GCP fleet is rolled from there. Current status (2026-09-02 late, v0.13.0 — testnet-1 live): **hash-based BFT consensus live since 0.9** (LMS/HSS over SHAKE-256 under an SLH-DSA root — the Ed25519/empty-blocks day-one note below is retired); shielded pool + aggregation + disclosure live (P2); durable node + staging testnet + R-series rotation production-proven (0.10.x); the usage sprint shipped runtime accounts, a public faucet, a Windows wallet, and universal explorer search (0.11.x); flat protocol fees + rotation re-arm (0.12.2); then **testnet-1** — a ceremony genesis with the fee policy and the faucet treasury bound into it, fresh validator keys, R10 v2 bounded memory with disk-served history, and the fee-aware + shielded Windows wallet (0.13.0). The fleet runs 4 validators on GCP on `hashkinetics-1-4e4ea68d` (staging-1 retired at 107,182, archived). Historical day-one note (2026-08-15): 33/33 tests green, 4-validator devnet via `chain/devnet.ps1`, stock Ed25519 votes and empty blocks — all since superseded. Web demo mirrors of hk-mandate/payword live in `vercel/lib/` — keep byte-compatible when protocol changes.
