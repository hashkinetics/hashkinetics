# HashKinetics zkVM Bake-Off (P1 gate G2)

**Goal:** pick the client-side proving stack for the shielded pool by benchmarking **the same
spend circuit** across **SP1 · RISC Zero · OpenVM**, because vendor numbers don't transfer —
you have to measure *our* circuit.

**Gate G2 (must pass to lock the stack):**

| Metric | Target |
|---|---|
| Client proof time | **< 2 s** on an 8-core server |
| Verify time | **< 10 ms** |
| Proof size | **< 300 KB** |

(Agents run on servers with CPU/GPU to spare, so client-side proving that would bother a phone
wallet is fine for them — but it still has to clear these bars for good UX.)

---

## The circuit (shared, one crate)

Everything lives in [`circuit/`](circuit) — a `no_std` crate compiled *inside* every zkVM
guest, so all three provers prove the identical statement over identical inputs. It is a
single-input → single-output shielded spend:

1. **Note commitment** `cm_in = H(value ‖ owner ‖ rho ‖ rcm)`
2. **Merkle membership** — fold `cm_in` up `TREE_DEPTH = 32` levels → `merkle_root` (public;
   the chain checks it against a known anchor)
3. **Spend authority** — an **in-circuit hash-based one-time signature** (Lamport over the tx
   binding): "prove you're allowed to spend this note" (this is the heavy, PQ-relevant part)
4. **Owner binding** — `owner == H(spend public key)`
5. **Nullifier** — `nf = H(spend-key-digest ‖ rho)` (deterministic; double-spend guard)
6. **Value conservation** — `in.value == out.value + fee`, no under/overflow
7. **Output commitment** — `cm_out = H(...)` (public)

Run the circuit's own tests with no zkVM toolchain at all:

```bash
cd circuit && cargo test
```

Six tests cover a valid spend plus every tamper path (bad signature, wrong owner, broken value
conservation, fee underflow, short path).

---

## Methodology — read this before trusting a number

**v1 uses SHA-256 as the circuit hash.** Reason: SP1, RISC Zero, and OpenVM all *accelerate*
the `sha2` crate through precompiles, so one portable implementation gives realistic,
apples-to-apples prover numbers. The in-circuit Lamport verification (256 hashes) and the
Merkle path (32 hashes) are exactly the workload precompiles exist for.

**But HashKinetics' doctrine is Poseidon2 in-circuit** (SHAKE-256 outside). Poseidon2 has **no
RISC-V precompile**, so emulating it in a RISC-V zkVM is expensive. That gap is the bake-off's
headline question:

> Does the spend circuit hit G2 with a **precompiled hash in a RISC-V zkVM** (SP1/RISC0/OpenVM),
> or does the Poseidon2 doctrine push us toward a **STARK-native AIR** (Plonky3 / Miden VM) where
> Poseidon2 is the cheap native hash?

So the plan is two passes:

- **Pass 1 (this scaffold):** SHA-256 everywhere → establishes the pipeline and the achievable
  floor on each prover.
- **Pass 2:** swap the commitment/tree/nullifier hash to Poseidon2 (a one-module change behind
  the same interface) → measures the "doctrine tax," and tells us whether to keep RISC-V zkVMs
  or hand-write a Plonky3/Miden AIR.

Both passes report the same three G2 numbers per prover.

---

## Layout

```
zkvm-bakeoff/
  circuit/            # the shared no_std spend circuit (+ native tests)   ← done, testable now
  sp1/                # SP1 guest (program/) + host bench (script/)
  risc0/              # RISC Zero guest (methods/) + host bench (host/)
  openvm/             # OpenVM guest + host bench
  scripts/setup-wsl.sh    # installs the Rust + SP1 + RISC0 + OpenVM toolchains in WSL2
```

Each prover's host builds a witness with `hk_spend_circuit::build_valid_spend(7)`, proves it,
verifies it, and prints `prove / verify / size` against the G2 bars.

---

## Setup (WSL2 / Ubuntu)

```bash
# from a WSL2 Ubuntu shell, inside this folder:
bash scripts/setup-wsl.sh          # Rust + sp1up + rzup + openvm (one-time, downloads toolchains)
```

Then, per prover:

```bash
# SP1  (most mature — start here to validate the flow)
cd sp1/script && cargo run --release

# RISC Zero
cd risc0/host && cargo run --release

# OpenVM
cd openvm && cargo run --release
```

Each prints a line like:

```
SP1    prove=1840ms  verify=6ms   size=210KB   [G2: PASS prove, PASS verify, PASS size]
```

> **Toolchains move fast.** The circuit crate is version-stable and tested. The three host/guest
> configs are written to current SDK conventions, but zkVM SDK APIs drift between releases — if a
> host fails to build, it's almost always a one-line SDK-version tweak. Paste the error and it's a
> quick fix. Recommended: get **SP1** green first (it's the reference), then the other two.

---

## Status (2026-08-16)

- **`circuit/`** — done, `cargo test` 6/6 green in WSL2. The full statement incl. in-circuit
  hash-based spend auth.
- **`sp1/`** — pipeline LIVE end-to-end (v6.4.0 async API; needs `protobuf-compiler`).
  **Run #1 baseline recorded** (see `RESULTS.md`): 3,433,670 cycles · prove ~26 min · verify
  71 ms · proof 1.24 MB — all G2 bars fail, as an unpatched baseline should. **sha2 precompile
  patch now applied** (`patch-sha2-0.10.8-sp1-6.2.0`); run #2 = patched +
  `RUSTFLAGS="-C target-cpu=native"`.
- **Finding F1 (read `RESULTS.md`):** SNARK-wrapped small proofs are pairing-based → not PQ →
  the <300 KB bar must be met by the raw STARK. OpenVM + Miden/Plonky3 are the size contenders.
- **`risc0/`** — harness built against the vendored v5 tree (guest + methods + host;
  succinct receipt; sha2 accel via `sha2-v0.10.9-risczero.0`). Run:
  `cd risc0/host && cargo run --release` (GPU: `--features cuda`). Needs `rzup install`.
- **`openvm/`** — guest + `openvm.toml` (sha2 extension) + `bench.sh` (build → keygen →
  prove/verify app + aggregated stark, timed, with sizes). Uses the circuit's
  `openvm-accel` feature (OpenVM accelerates via its own drop-in lib, not a patch).
  ⚠ v1 embeds the witness (no `--input` plumbing) — slightly larger workload; sizes exact,
  times approximate. Run: `cd openvm && bash bench.sh`.
- **`sp1/script/src/bin/cuda.rs`** — the RTX 5090 path: `cargo run --release --bin cuda`.
- **Then:** the Poseidon2 pass to price the doctrine tax and issue the G2 verdict
  (GPU proving vs STARK-native AIR vs statement slimming).
