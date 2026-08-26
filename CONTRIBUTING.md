# Contributing to HashKinetics

Thanks for being here. This is consensus software for money — the bar is honest and high.

## The three house rules

1. **Demo-gated or test-gated.** Nothing merges on assertion. A consensus-visible change
   ships with a test (or a runnable demo) that would have caught its absence. The existing
   suite (`cargo test` in `chain/`, plus the circuit tests in `zkvm-bakeoff/circuit`) must
   stay green.
2. **The honesty ledger is part of the product.** If your change opens a caveat (a known
   limit, an unproven path, a deferred hardening), it goes into the README's ledger in the
   same PR. If it closes one, celebrate it there too.
3. **Doctrine F1 is not negotiable:** every signature that moves money is hash-based; ZK
   artifacts are raw STARKs — no pairing-based wraps, no lattice signatures near funds.
   ML-KEM is confidentiality-only. PRs that violate this are closed with a link to the
   whitepaper §doctrine.

## Practicalities

- **Small PRs win.** One concern per PR; refactors separate from behavior changes.
- **Consensus-critical code** (`hk-state`, `hk-consensus`, `hk-node/src/{state,store,codec}.rs`,
  the circuit): expect careful review and requests for invariant tests. The invariants
  themselves are listed in the yellowpaper (I1–I10) and `docs/AUDIT-SCOPE.md`.
- **Determinism rules** (from `hk-state`'s header): no clocks, no randomness, no iteration
  over unordered maps in consensus paths; a failed tx mutates nothing.
- **Wire/state formats**: changes to the codec, `Batch`, snapshots, or the state
  commitment need a migration note — a codec change means a fresh devnet (`--fresh`) and
  is called out loudly in the PR description.
- **Windows + WSL**: the tree builds on both, but the shielded devnet and prover are
  WSL/Linux (sp1 is POSIX-only). Note for Windows git users: a vendored crate ships
  `aux.rs` (a reserved Windows filename) — commit from WSL.
- Style: `cargo fmt` defaults; comments explain *why*, headers explain the module's job.

## Security findings

Never as public issues — see `SECURITY.md` (coordinated disclosure, credited).

## Licensing of contributions

By contributing you agree your contribution is licensed under the repository's dual
license (MIT OR Apache-2.0), without additional terms.
