# Vendored external sources — pinned commits (2026-08-15)
Source-only snapshots (no .git). Re-fetch full history: tools\DOWNLOAD-VENDOR.bat. Rationale/licenses: ../MANIFEST.md.

| dir | source | branch | commit |
|---|---|---|---|
| malachite | https://github.com/informalsystems/malachite | main | bcac2b2dbd369a6c29b9151fcd0889b133d7221a |
| plonky3 | https://github.com/Plonky3/Plonky3 | main | f5b7977e5c89adc8375b5c63a5a5092985b1f603 |
| miden-vm | https://github.com/0xMiden/miden-vm | next | 036db94bc88d838d6879ba646f3d621d6cd565d6 |
| miden-crypto | https://github.com/0xMiden/crypto | next | 475092a8476bf4c806424579e5d9225b12941c1a |
| fips205-rust | https://github.com/integritychain/fips205 | main | 30bac08580aa61f653e5436d1bbacb5ffac446c4 |
| hbs-lms-rust | https://github.com/Fraunhofer-AISEC/hbs-lms-rust | master | 7063cc8399349bf54fa4e6ca5ffb423d713d30de |
| lms-hash-sigs-c | https://github.com/cisco/hash-sigs | master | 0335491815c908cad85d6035d43785693a4e91f9 |
| xmss-reference-c | https://github.com/XMSS/xmss-reference | master | 171ccbd26f098542a67eb5d2b128281c80bd71a6 |
| rustcrypto-kems | https://github.com/RustCrypto/KEMs | master | 5eeaf46f341dffda03c8e036a50947d811ca6274 |
| rustcrypto-hashes | https://github.com/RustCrypto/hashes | master | f6c786d72ed4d37a32dcd32daa2e7277dd4683e1 |
| x402 | https://github.com/coinbase/x402 | main | dd927a26cfefc98c24b3ec38b3a8f204dad0c60d |
| ap2 | https://github.com/google-agentic-commerce/AP2 | main | e1ea56db72a6385bce3e5c1112b3a56ce60acb43 |
| librustzcash | https://github.com/zcash/librustzcash | main | c9d7f0859322a3ba7b0e0e912e6cca9a34715fa9 |
| sp1 | https://github.com/succinctlabs/sp1 | main | f66b4bff51d0ccff51d152e0f7f66b2ffedf3529 |
| openvm | https://github.com/openvm-org/openvm | main | c65f9fa74c74f57bc94262314b75178f43202757 |
| penumbra | https://github.com/penumbra-zone/penumbra | main | 36a31c17974c23a7e84cc02c64f0062ae57e79b1 |

librustzcash note: first vendoring pass was an incomplete clone; re-vendored clean the same day at the commit above.
openvm/penumbra full hashes verified against `git ls-remote` HEAD 2026-08-15 (prefix-matched the clone).

## rust-libp2p-gossipsub (added 2026-09-13, hk-node v0.19.3)
`libp2p-gossipsub` **0.49.5** as published on crates.io (registry source copied verbatim — `Cargo.toml` is the registry-normalized one; `Cargo.toml.orig` is upstream's), applied through `[patch.crates-io]` in `chain/Cargo.toml`. One patch, marked `HK v0.19.3` in `src/behaviour.rs`: `on_connection_established` re-announces our subscriptions on an additional connection to a known peer instead of returning, and `on_connection_closed` re-announces them when a connection closes while others remain. Reason: upstream sends subscriptions only on the first connection to a peer id, so a peer that restarts and dials in before its previous connection is torn down never receives them and cannot publish (testnet-1 seat #10, 2026-09-13; `ops/1XP-PROPOSER-MISSES-2026-09-13.md`). Upstream: https://github.com/libp2p/rust-libp2p (protocols/gossipsub, tag libp2p-gossipsub-v0.49.5).

## hbs-lms-rust — the HashKinetics patches on the pinned commit (the public tree carries them; `ops/sync-public-freshness.sh` §1c copies every patched file)
- **R15 (hk-node v0.18.2, 2026-09-08):** `src/hss/aux.rs` — the aux-cache MAC is compared over exactly one hash width (an oversized buffer no longer discards the cache); `src/hss/mod.rs` — `HssSigningSession`, the long-lived signing session (byte-identical signatures to `hss_sign`, reserve-then-sign with `commit`/`rollback`).
- **RZ-1 (hk-node v0.19.9, 2026-10-22, external report 2026-10-14):** the in-memory parsers are total. `src/util/helper.rs` — `read`/`read_and_advance` return `Option` (bounds- and overflow-checked), plus `read_u32_and_advance`; `src/lm_ots/signing.rs`, `src/lms/signing.rs`, `src/lms/definitions.rs`, `src/hss/signing.rs`, `src/hss/definitions.rs` — every `InMemory*::new` propagates a short read or an unknown type code as `None` (no raw slice, no `unwrap`), `InMemoryHssSignature::new` refuses a level above `MAX_ALLOWED_HSS_LEVELS − 1` before reading (the fixed level array used to overflow) and refuses trailing bytes after the bottom-tree signature; `src/hss/reference_impl_private_key.rs` and `src/hss/aux.rs` map a short read to their existing error; `src/lib.rs` re-exports `MAX_HSS_SIGNATURE_LENGTH`. Sign and keygen are untouched — signatures are byte-identical. Pinned by `hss::tests::rz1_hss_verify_refuses_malformed_signatures_without_panicking`.

## malachite — the HashKinetics patches on the pinned commit (the public tree carries them; `ops/sync-public-freshness.sh` §1c copies every patched file)
- **Genesis gate + peer table (hk-node v0.15.x → v0.19.3):** `code/crates/network/src/lib.rs`, `behaviour.rs` — identify carries the genesis digest and node version; a consensus-protocol peer on a different genesis is disconnected; the HK peer table behind `hk_getPeers`. **R8 (v0.10.10):** `core-consensus` buffers future-height votes/proposals as height claims and `handle/driver.rs` gates the three leaf-spending arms on `State::should_abstain`; `core-types/src/context.rs` gained `abstain_threshold`, `placeholder_signature` (R5.4) and `validator_set_at` (R6).
- **VZ-2 (hk-node v0.19.10, 2026-11-03, external report 2026-11-03):** `core-consensus/src/state.rs` — a claim is recorded only after the vote's signature verifies (`future_claim_wants_verify`, `note_future_claim_failure`, `CLAIM_VERIFY_BUDGET`), the corroborated tip is power-weighted over `threshold_params.honest`, claims are pruned and the verify budget refills in `reset_and_start_height`, `buffer_input` is bounded per height and only signature-verified votes and proposals occupy slots (`buffer_admission`, `BufferAdmission`, `buffer_verified`, `proposal_slot_admits`); `src/lib.rs` — re-exports the R8/buffer constants and `BufferAdmission`; `handle/vote.rs` — the future-height branch verifies through `verify_signature` before `note_future_height_claim`, round Nil refused at the top, `buffer_vote` verifies before buffering; `handle/proposal.rs` — the proposal claim deleted, round Nil refused, `buffer_proposal`; `handle/sync.rs` — a Nil-round commit certificate refused before the proposer lookup; `handle/driver.rs` — the R8 line names its evidence; `util/bounded_queue.rs` — `get`; `core-types/src/context.rs` — the `abstain_threshold` contract rewritten; `engine/src/node.rs` — D-13, the supervisor exits the process on `ActorFailed`; `network/src/lib.rs` — the genesis gate fails closed (untagged peers and foreign identify protocol versions dropped), the broadcast carrier is Sync-only when consensus runs over gossipsub, two counters.
