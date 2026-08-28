#!/usr/bin/env bash
# HashKinetics zkVM bake-off — one-time toolchain setup for WSL2 / Ubuntu.
# Installs Rust + the SP1, RISC Zero, and OpenVM prover toolchains, and sanity-checks the
# shared circuit. Re-runnable. Some installers ask you to open a new shell afterwards.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "== system deps =="
sudo apt-get update -y
sudo apt-get install -y build-essential pkg-config libssl-dev git curl protobuf-compiler

echo "== Rust (rustup) =="
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
# shellcheck disable=SC1090
source "$HOME/.cargo/env" 2>/dev/null || true

echo "== circuit sanity check (no zkVM toolchain needed) =="
( cd "$HERE/../circuit" && cargo test ) || { echo "circuit tests failed — stop and fix before proving"; exit 1; }

echo "== SP1 (sp1up) — the reference prover =="
curl -L https://sp1up.succinct.xyz | bash || true
"$HOME/.sp1/bin/sp1up" || echo "  (open a new shell and run: sp1up)"

echo "== RISC Zero (rzup) =="
curl -L https://risczero.com/install | bash || true
"$HOME/.risc0/bin/rzup" install || echo "  (open a new shell and run: rzup install)"

echo "== OpenVM (cargo-openvm) =="
cargo install --locked cargo-openvm || echo "  (see book.openvm.dev for the current install method)"

cat <<'EOF'

Setup attempted. If any installer asked you to open a new shell, do that, then:

  # SP1 first (reference pipeline — validate the flow here):
  cd sp1/script && cargo run --release

Expected line:
  SP1    prove=____ms  verify=__ms  size=___KB   [G2: .. prove, .. verify, .. size]

Once SP1 is green, the RISC0 + OpenVM harnesses drop in with the same shape (they call the same
hk_spend_circuit::run). Paste the SP1 numbers and any build errors and we'll take it from there.
EOF
