# Architecture map — plan → code

Plan: `../HASHKINETICS-IMPLEMENTATION-PLAN.md` (sections referenced below).

| Plan | Code home | Vendored inputs |
|---|---|---|
| §3.1 Two-hash doctrine | `chain/crates/hk-crypto` (`hash.rs`: SHAKE-256 external; Poseidon2/RPO in-circuit later) | `rustcrypto-hashes`, `plonky3`, `miden-crypto` |
| §3.2 Signature stack | `hk-crypto`: `hashsig.rs` (**LMS/HSS over SHAKE-256, real + KAT-verified, 0.9**) · `traits.rs` · Lamport L-ratchet (`lamport.rs`, account auth) · SLH-DSA/WOTS adapters feature-gated | `hbs-lms-rust` (LMS, wired), `fips205-rust` (SLH-DSA, pending), `xmss-reference-c` + `lms-hash-sigs-c` (KATs) |
| §3.3 Consensus vote signing | `docs/HASHSIG-CONSENSUS-SWAP.md` → `hk-consensus` provider (design; live swap next) | `hashsig` primitive above; `malachite` SigningScheme seam |
| §6 QHT channels + §12 agent GTM | **`hk-facilitator` (RAG-as-a-merchant, 0.8): PayWord-metered paid search settled on-chain** | `agentic/turbovec` (drop-in index), `x402` (facilitator pattern) |
| §3.3 Leaf-index=nonce, equivocation slashing | `hk-state` (planned) + consensus rules | IETF draft-wiggers patterns (research 03) |
| §3.4 ML-KEM confidentiality boundary | `hk-crypto` (feature `mlkem`, later) | `rustcrypto-kems` |
| §4 Shielded pool / CVA | `hk-shield` (P2 crate, not yet created) | `penumbra` (tct, view service), `librustzcash` (note plumbing), zkVM from bake-off |
| §5 MandateTree v2 | **`chain/crates/hk-mandate` (drip math implemented + tested)** | `docs/carried-specs/MANDATETREE-SPEC.md`, `ap2` (mandate mapping) |
| §6 QHT channels | `hk-crypto/payword.rs` (implemented) + `hk-channels` (P0/P1) | `docs/carried-specs/HYPERTREE-CHANNELS-SPEC.md`, `x402` |
| §7 Chain / consensus | **`hk-consensus` (HkContext, devnet-proven) + `hk-node` (full node: codec/streaming/loop/testnet-gen; LIVE 4-validator devnet 2026-08-15)** | `malachite` (vendored engine) |
| §7.4 Native objects | `hk-primitives` (types) → `hk-state` modules | — |
| §9 zkVM bake-off (gate G2) | `chain/bench/` (to create at P1) | `sp1`, `openvm`, `miden-vm`, (`risc0` via .bat) |

Build reality: no Rust toolchain in the Cowork sandbox — **Yadu's machine runs `cargo build`**. Status end of day one (2026-08-15): **33/33 tests green; 4-validator devnet LIVE via `chain/devnet.ps1`** (stock Ed25519 votes, empty blocks — 0.7 adds mempool/RPC + app-hash binding; 0.8 swaps in SCMS hash-sig votes). Web demo mirrors of hk-mandate/payword live in `vercel/lib/` — keep byte-compatible when protocol changes.
