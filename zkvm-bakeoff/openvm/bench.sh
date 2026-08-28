#!/usr/bin/env bash
# OpenVM bench: build → keygen → prove/verify (app + aggregated stark), timing each and
# reporting proof sizes against G2. Run from this directory in WSL2. Requires cargo-openvm
# (setup-wsl.sh installs it) — the CLI version should match the vendored tree era (2026-08).
set -euo pipefail

echo "== build guest =="
time cargo openvm build

echo "== keygen (app + aggregation prefix) =="
time cargo openvm keygen

echo "== prove app (application-level proof) =="
time cargo openvm prove app

echo "== verify app =="
time cargo openvm verify app

echo "== prove stark (aggregated root STARK — the PQ-deployable, size-relevant artifact) =="
time cargo openvm prove stark

echo "== verify stark =="
time cargo openvm verify stark

echo "== proof sizes =="
find . target -maxdepth 4 \( -name "*.proof" -o -name "*.stark.proof" -o -name "*.app.proof" \) \
  -exec ls -lh {} \; 2>/dev/null || true
echo
echo "G2 bars: prove < 2 s (8-core) · verify < 10 ms · proof < 300 KB"
echo "NOTE: this guest EMBEDS the witness (see src/main.rs) — cycle workload is slightly"
echo "larger than SP1/RISC0's host-fed variant. Compare sizes exactly; times approximately."
