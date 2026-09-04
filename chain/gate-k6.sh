#!/usr/bin/env bash
# gate-k6.sh -- the K6 receipt (v0.15.1): a node on a pinned genesis verifies WITHOUT a
# prover (the kit's vks.json), the pin check refuses a tampered file, and the node's own
# HTTP client speaks https (the public RPC edge + the public prover).
#
#   ./gate-k6.sh                       # needs hk-prove on 127.0.0.1:9911 (vk pins) + internet for the https checks
#
# What it proves (each line is a PASS/FAIL):
#   1. `hk-node vks-fetch` pulls the three vks from the local prover, checks them against the
#      devnet genesis pins, writes vks.json (675-ish bytes).
#   2. a 4-validator devnet is up; node3 is restarted with HK_VKS_FILE and NO HK_PROVER_URL →
#      it starts, logs "verifying keys MATCH the genesis pins" from the FILE, rejoins and VOTES.
#   3. <HOME>/vks.json with no env at all is picked up (the kit's default path).
#   4. a tampered vks.json → PIN MISMATCH → the node refuses to start (K5 message names HK_VKS_FILE).
#   5. https: `hk-node account-balance https://rpc.hashkinetics.org <treasury>` answers a number,
#      and `hk-node vks-fetch https://prover.hashkinetics.org` fetches the public prover's vks
#      (the two calls the join kit tells an operator to make — impossible before v0.15.1).
set -uo pipefail
cd "$(dirname "$0")"
H="${HK_DEVNET_HOME:-$HOME/hk-devnet}"
BIN="$(readlink -f "${CARGO_TARGET_DIR:-target}/release/hk-node")"
PROVER="${HK_PROVER_URL:-http://127.0.0.1:9911}"
PASS=0; FAIL=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
rpc()  { local p=${3:-}; [[ -z "$p" ]] && p="{}"; curl -s -m 5 -X POST "http://127.0.0.1:$1" -d "{\"method\":\"$2\",\"params\":$p}"; }
h_of() { rpc "$1" hk_chainInfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["height"])' 2>/dev/null || echo 0; }
ah_of(){ rpc "$1" hk_chainInfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["app_hash"])' 2>/dev/null || echo "?"; }
rem_of(){ rpc "$1" hk_chainInfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["signer"]["remaining"])' 2>/dev/null || echo -1; }
wait_h(){ local port=$1 target=$2 tries=${3:-90}; for _ in $(seq "$tries"); do [[ "$(h_of "$port")" -ge "$target" ]] && return 0; sleep 2; done; return 1; }
# the node's tracing writes ANSI colour into files — strip before grepping (rehearsal lesson).
# NOTE: never `grep -q` at the end of this pipe under `pipefail` — grep exits early, sed dies
# of SIGPIPE, the pipeline "fails" (gate-k6 run 1: a PASS reported as FAIL). `has` reads to EOF.
noansi(){ sed -r 's/\x1b\[[0-9;]*[mK]//g' "$1"; }
has(){ noansi "$1" | grep -E -- "$2" >/dev/null; }
# start a node with an explicit environment (no HK_PROVER_URL unless given)
start_env(){ local home=$1 log=$2; shift 2; ( cd "$H" && exec env "$@" RUST_LOG=info nohup "$BIN" start "$home" </dev/null >>"$log" 2>&1 ) & }

echo "== 1 · vks-fetch from the local prover, checked against the devnet genesis pins"
./devnet.sh --fresh -n 4 --prover-url "$PROVER" >/dev/null
wait_h 26000 5 60 && ok "devnet deciding (height $(h_of 26000))" || { bad "devnet did not reach height 5"; exit 1; }
rm -f "$H/vks.json"
OUT=$("$BIN" vks-fetch "$PROVER" -o "$H/vks.json" --genesis "$H/node0/genesis.json" 2>&1)
echo "$OUT" | grep "all three vks match the pins" >/dev/null && ok "vks-fetch: pins match the devnet genesis" || bad "vks-fetch: $OUT"
[[ -s "$H/vks.json" ]] && ok "vks.json written ($(wc -c < "$H/vks.json") bytes)" || bad "no vks.json"
python3 -c "import json,sys;d=json.load(open('$H/vks.json'));assert set(d)=={'spend_vk','mint_vk','agg_vk'} and all(len(v)==208 for v in d.values())" && ok "vks.json shape: three 104-byte keys, hex" || bad "vks.json shape"

echo "== 2 · node3 restarted with HK_VKS_FILE and NO prover URL: verifies from the file, votes again"
pkill -f "hk-node start $H/node3"; sleep 2
: > "$H/node3.log"
start_env "$H/node3" "$H/node3.log" HK_VKS_FILE="$H/vks.json"
T=$(( $(h_of 26000) + 5 )); wait_h 26003 "$T" 120 && ok "node3 back at $T without a prover" || bad "node3 did not rejoin (see $H/node3.log)"
has "$H/node3.log" "verifying keys MATCH the genesis pins.*source=file" && ok "node3 log: pins matched from the FILE" || bad "node3 log lacks the file-sourced pin line: $(noansi "$H/node3.log" | grep -m2 -E 'verifying keys|verifier')"
sleep 3; [[ "$(ah_of 26003)" == "$(ah_of 26000)" ]] && ok "node3 app_hash == node0" || bad "node3 app_hash mismatch"
R0=$(rem_of 26003); H0=$(h_of 26003); sleep 20; R1=$(rem_of 26003); H1=$(h_of 26003)
[[ "$R1" -lt "$R0" && "$H1" -gt "$H0" ]] && ok "node3 VOTING again (remaining $R0 → $R1, height $H0 → $H1)" || bad "node3 not voting (remaining $R0 → $R1, height $H0 → $H1)"

echo "== 3 · the kit's default path: <HOME>/vks.json, no env at all"
pkill -f "hk-node start $H/node3"; sleep 2
cp "$H/vks.json" "$H/node3/vks.json"; : > "$H/node3.log"
start_env "$H/node3" "$H/node3.log"
T=$(( $(h_of 26000) + 5 )); wait_h 26003 "$T" 120 && ok "node3 back at $T from <HOME>/vks.json" || bad "node3 did not rejoin via <HOME>/vks.json"
has "$H/node3.log" "node3/vks.json" && ok "node3 log names <HOME>/vks.json" || bad "node3 log does not mention the default file: $(noansi "$H/node3.log" | grep -m1 -E 'verifier|vks')"

echo "== 4 · a tampered vks.json is refused (pin mismatch → refuse to start)"
pkill -f "hk-node start $H/node3"; sleep 2
python3 - "$H/node3/vks.json" <<'EOF'
import json,sys; p=sys.argv[1]; d=json.load(open(p)); h=d["spend_vk"]; d["spend_vk"]=("0" if h[0]!="0" else "1")+h[1:]; json.dump(d,open(p,"w"))
EOF
: > "$H/node3.log"
start_env "$H/node3" "$H/node3.log"
sleep 25
has "$H/node3.log" "PIN MISMATCH" && ok "tampered file: PIN MISMATCH logged" || bad "no PIN MISMATCH in the log: $(noansi "$H/node3.log" | tail -3)"
has "$H/node3.log" "HK_VKS_FILE" && ok "K5 refusal names HK_VKS_FILE (the fix is in the message)" || bad "K5 message does not mention HK_VKS_FILE"
if pgrep -f "hk-node start $H/node3" >/dev/null; then bad "node3 is RUNNING on a tampered vks file"; pkill -f "hk-node start $H/node3"; else ok "node3 refused to start"; fi
# restore a good node3 for anyone inspecting the devnet afterwards
cp "$H/vks.json" "$H/node3/vks.json"; start_env "$H/node3" "$H/node3.log"

echo "== 5 · https from the stock binary (the public edge + the public prover)"
TREASURY=6c0466c5a22e8c003550165a8aadd8a868aca4657e4c7e9fb48ab14d4df264ad
B=$("$BIN" account-balance https://rpc.hashkinetics.org $TREASURY 2>&1 | tail -1)
[[ "$B" =~ :\ [0-9]+\ micro ]] && ok "https RPC: $B" || bad "https RPC failed: $B"
V=$("$BIN" vks-fetch https://prover.hashkinetics.org -o /tmp/vks-public.json 2>&1 | grep -c "bytes · pin")
[[ "$V" == 3 ]] && ok "https prover: three vks fetched from prover.hashkinetics.org" || bad "https prover fetch failed ($V pin lines)"
KIT=../networks/testnet-1/vks.json
[[ -f "$KIT" ]] && { cmp -s /tmp/vks-public.json "$KIT" && ok "public prover vks == networks/testnet-1/vks.json (the kit file is current)" || bad "kit vks.json differs from the public prover's — regenerate it"; } || echo "  (networks/testnet-1/vks.json not present yet — generate it with: $BIN vks-fetch https://prover.hashkinetics.org -o ../networks/testnet-1/vks.json --genesis ../networks/testnet-1/genesis.json)"

echo
echo "== K6 GATE: $PASS passed, $FAIL failed"
[[ "$FAIL" == 0 ]] && echo "GATE GREEN — a node verifies from the kit's vks.json without a prover; tampering is refused; https works from the stock binary." || echo "GATE RED — read the FAIL lines and $H/node3.log"
