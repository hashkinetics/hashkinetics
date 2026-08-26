#!/usr/bin/env bash
# HashKinetics local devnet launcher (WSL/Linux) — the shielded-pool path.
# (sp1-sdk needs POSIX (sp1-jit: shm/semaphores), so the STARK-verifying node runs here;
#  devnet.ps1 remains the Windows launcher for transparent-only runs.)
#
# Usage:
#   ./devnet.sh [-n 4] [--fresh] [--rotate-every N] [--prover-url http://127.0.0.1:9911]
#   ./devnet.sh stop     # kill all nodes
#   ./devnet.sh logs     # tail all node logs
#
# Node homes + logs live on the Linux filesystem (fast WAL): $HK_DEVNET_HOME (~/hk-devnet).
# Honors CARGO_TARGET_DIR (recommended: ~/hk-target-chain — keeps target off /mnt/c).

set -euo pipefail
cd "$(dirname "$0")"

N=4
FRESH=0
ROTATE=0
PROVER=""
HOME_DIR="${HK_DEVNET_HOME:-$HOME/hk-devnet}"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"

case "${1:-}" in
    stop)
        pkill -f 'hk-node start' && echo "nodes stopped." || echo "no nodes running."
        exit 0
        ;;
    logs)
        exec tail -n 20 -f "$HOME_DIR"/node*.log
        ;;
esac

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n) N="$2"; shift 2 ;;
        --fresh) FRESH=1; shift ;;
        --rotate-every) ROTATE="$2"; shift 2 ;;
        --prover-url) PROVER="$2"; shift 2 ;;
        *) echo "unknown arg: $1"; exit 1 ;;
    esac
done

echo "Building hk-node (release)..."
cargo build --release -p hk-node
BIN="$TARGET_DIR/release/hk-node"
[[ -x "$BIN" ]] || { echo "binary not found at $BIN (set CARGO_TARGET_DIR?)"; exit 1; }

if [[ "$FRESH" == 1 && -d "$HOME_DIR" ]]; then
    echo "Removing existing devnet state at $HOME_DIR..."
    pkill -f 'hk-node start' 2>/dev/null || true
    sleep 1
    rm -rf "$HOME_DIR"
fi

if [[ ! -d "$HOME_DIR" ]]; then
    if [[ -n "$PROVER" ]]; then
        # P2.5: embed proof-system vk pins into genesis (prover must be up already).
        HK_PROVER_URL="$PROVER" "$BIN" testnet "$N" "$HOME_DIR"
    else
        "$BIN" testnet "$N" "$HOME_DIR"
    fi
fi

ENV_EXTRA=()
if [[ "$ROTATE" -gt 0 ]]; then
    ENV_EXTRA+=("HK_ROTATE_EVERY=$ROTATE")
    echo "SCMS demo: each validator rotates its operational key every $ROTATE blocks."
fi
if [[ -n "$PROVER" ]]; then
    ENV_EXTRA+=("HK_PROVER_URL=$PROVER")
    echo "Shielded pool: nodes will fetch verifying keys from $PROVER and verify STARKs in-node."
    echo "(hk-prove must ALREADY be listening there — nodes fetch vks at startup.)"
fi

echo "Launching $N validators (logs: $HOME_DIR/node<i>.log)..."
for ((i = 0; i < N; i++)); do
    env "${ENV_EXTRA[@]}" RUST_LOG=info \
        nohup "$BIN" start "$HOME_DIR/node$i" >"$HOME_DIR/node$i.log" 2>&1 &
    echo "  node$i pid $!  (rpc :$((26000 + i)))"
done

echo
echo "Done. Watch blocks:   ./devnet.sh logs"
echo "Look for 'SP1 pool verifier wired' at startup and matching app_hash across nodes."
echo "Shielded demo:        $BIN demo-shielded http://127.0.0.1:26000 ${PROVER:-http://127.0.0.1:9911}"
echo "Stop everything:      ./devnet.sh stop"
