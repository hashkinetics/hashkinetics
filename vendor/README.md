# Vendored dependencies

Four external source trees are vendored here so the build is hermetic and the exact
reviewed code is pinned (revisions: `external/PINS.md`). Each tree retains its **own
license and copyright** — they are not covered by this repository's MIT/Apache dual
license, and all upstream notices are preserved in place.

| Tree | What we use it for | Upstream license |
|---|---|---|
| `external/malachite/` | The BFT consensus engine (app-channel, core types, sync, WAL) our `HkContext` plugs into | Apache-2.0 |
| `external/hbs-lms-rust/` | LMS/HSS (RFC 8554) — the stateful hash-based signatures behind every consensus vote | Apache-2.0/MIT (see tree) |
| `external/rustcrypto-kems/` | ML-KEM-768 — note confidentiality (stealth ciphertexts) only, never signatures | Apache-2.0/MIT |
| `external/openvm/` | Toolchain/guest libs used by the zkVM bake-off harnesses | MIT/Apache (see tree) |

Why vendor instead of crates.io: crates.io versions lag the pinned revisions we reviewed,
and consensus software should build from bytes you can read. Updating a tree = update the
pin in `PINS.md` + a PR explaining what changed upstream and why we want it.
