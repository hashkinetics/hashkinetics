#!/usr/bin/env bash
# bench-seats.sh -- how does block cadence scale with the NUMBER OF VOTING SEATS? (asked 2026-09-05:
# "is it only 5 seats or can 100 nodes connect?" — seats are not capped; this measures the cost.)
#
#   ./bench-seats.sh [N=8] [DURATION_S=120]         # e.g. ./bench-seats.sh 16 180
#
# Runs an N-validator UNVERIFIED devnet on this machine (no prover, HK_ALLOW_UNVERIFIED=1 — the
# consensus path is what is being measured, not STARK verification), lets it settle, then samples
# the tip for DURATION_S seconds and prints ONE row for docs/CAPACITY-SHEET.md:
#   seats · blocks/s · mean block interval · commit signatures per block (hash-based, one per seat)
#   · bytes of an empty block on disk (≈ the commit certificate) · RSS per node.
# All N nodes share one box, so the number is a LOWER bound on WAN cadence and an upper bound on
# per-block cost — say so when quoting it. Stops the devnet when done (./devnet.sh stop).
set -uo pipefail
cd "$(dirname "$0")"
N="${1:-8}"; DUR="${2:-120}"
H="${HK_DEVNET_HOME:-$HOME/hk-devnet}"
BIN="$(readlink -f "${CARGO_TARGET_DIR:-target}/release/hk-node")"
rpc()  { local p=${3:-}; [[ -z "$p" ]] && p="{}"; curl -s -m 5 -X POST "http://127.0.0.1:$1" -d "{\"method\":\"$2\",\"params\":$p}"; }
jq_()  { python3 -c "import sys,json;r=json.load(sys.stdin)['result'];print($1)" 2>/dev/null; }
h_of() { rpc "$1" hk_chainInfo | jq_ 'r["height"]' || echo 0; }

echo "== bench-seats: $N seats, ${DUR}s sample, unverified devnet (consensus cost only)"
export HK_ALLOW_UNVERIFIED=1
./devnet.sh --fresh -n "$N" >/dev/null || { echo "devnet failed to launch"; exit 1; }
echo "   waiting for height 10 on node0 (keygen + verifier-less start)…"
for _ in $(seq 120); do [[ "$(h_of 26000)" -ge 10 ]] && break; sleep 2; done
[[ "$(h_of 26000)" -ge 10 ]] || { echo "node0 never reached height 10 — check $H/node0.log"; ./devnet.sh stop >/dev/null; exit 1; }
sleep 10   # let every seat join round 0 before sampling

H0=$(h_of 26000); T0=$(date +%s.%N)
sleep "$DUR"
H1=$(h_of 26000); T1=$(date +%s.%N)
BLOCKS=$((H1 - H0))
RATE=$(python3 -c "print(f'{$BLOCKS/($T1-$T0):.3f}')")
INTERVAL=$(python3 -c "print(f'{($T1-$T0)/max($BLOCKS,1):.2f}')")
SIGS=$(rpc 26000 hk_getBlock "{\"height\":$H1}" | jq_ 'r["certificate"]["signatures"]')
ROUND=$(rpc 26000 hk_getBlock "{\"height\":$H1}" | jq_ 'r["certificate"]["round"]')
BYTES=$(stat -c %s "$H/node0/blocks/b$(printf '%012d' "$H1").bin" 2>/dev/null || echo "?")
# RSS: mean over the nodes, MiB
RSS=$(for p in $(pgrep -f "hk-node start $H/node"); do ps -o rss= -p "$p"; done | awk '{s+=$1; n++} END{ if(n) printf "%.0f", s/n/1024; else print "?"}')
# rounds > 0 in the window = seats that missed a proposal (all on one box: scheduler noise, not WAN)
R1=$(for h in $(seq $((H1-19)) $H1); do rpc 26000 hk_getBlock "{\"height\":$h}" | jq_ 'r["certificate"]["round"]'; done | awk '$1>0{c++} END{print c+0}')

echo
echo "seats=$N  window=${DUR}s  blocks=$BLOCKS  blocks/s=$RATE  mean_interval_s=$INTERVAL  commit_sigs/block=$SIGS  empty_block_bytes=$BYTES  rss_per_node_MiB=$RSS  round>0_in_last_20=$R1"
echo
echo "docs/CAPACITY-SHEET.md §f row (single box, unverified devnet — a lower bound on WAN cadence):"
echo "| $(date -u +%F) | $N | ${DUR} s | $RATE | $INTERVAL s | $SIGS | $BYTES | $RSS MiB | $R1/20 | one box, unverified devnet, $(nproc) CPUs |"
./devnet.sh stop >/dev/null
