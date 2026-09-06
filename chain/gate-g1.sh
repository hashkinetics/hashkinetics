#!/usr/bin/env bash
# gate-g1.sh -- the G1 receipt (v0.18.0) on a local devnet: BOOTSTRAP GOVERNANCE. At an activation
# height every node re-weights the GENESIS seats (power 1 → 4) by rule, effective the next height;
# from then on the founders alone hold more than 2/3 — no set of external seats can stall the chain
# or block a set change — and `SetChange::SetPower` moves weight by certificate (the handover tool).
#
#   ./gate-g1.sh                       # needs hk-prove listening on 127.0.0.1:9911 (vk pins)
#   HK_PROVER_URL=… ./gate-g1.sh
#
# The devnet's chain id is not testnet-1's, so the activation comes from the environment
# (HK_G1_HEIGHT / HK_G1_POWER); testnet-1 itself is hard-wired in the binary (110,000 / 4) and
# ignores these variables — the same binary, the same code path, a different table entry.
#
# What it proves (each line is a PASS/FAIL):
#   1. before the activation height: 4 seats · power 1 each · founding 4 · quorum 3 · bootstrap
#      {height, founding_power 4, active false} · every seat marked genesis.
#   2. at H+1 on EVERY node: power 4 each, total 16, quorum 11, founders_alone_decide, the log line
#      "G1 BOOTSTRAP GOVERNANCE ACTIVATED"; app_hash identical across the four; the chain keeps deciding.
#   3. a 5th node (external, power 1) is admitted with THREE founding approvals (12 > 2/3 of 16) —
#      founders decide alone; total 17, external 1, max_absent_power 5.
#   4. SetPower: founders re-weight the external seat 1 → 3 by certificate; hk_getBlock shows
#      change "set_power"; total 19, quorum 13; a SetPower to 0 is refused by shape.
#   5. LIVENESS: the external node is killed; the chain keeps advancing on the founders alone
#      (16 > 2/3 of 19); its return costs nothing.
#   6. REPLAY: node0 restarted on its persisted home re-derives the same set (power 4s, the external's
#      3) and app_hash — the re-weight is a rule, not a memory.
#   7. node5, started from GENESIS, syncs across the activation and both certificates (HK-R6).
set -uo pipefail
cd "$(dirname "$0")"
H="${HK_DEVNET_HOME:-$HOME/hk-devnet}"
BIN="$(readlink -f "${CARGO_TARGET_DIR:-target}/release/hk-node")"
PROVER="${HK_PROVER_URL:-http://127.0.0.1:9911}"
export HK_G1_HEIGHT="${HK_G1_HEIGHT:-40}"
export HK_G1_POWER="${HK_G1_POWER:-4}"
PASS=0; FAIL=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
rpc()  { local p=${3:-}; [[ -z "$p" ]] && p="{}"; curl -s -m 5 -X POST "http://127.0.0.1:$1" -d "{\"method\":\"$2\",\"params\":$p}"; }
py()   { rpc "$1" "$2" | python3 -c "import sys,json;r=json.load(sys.stdin)['result'];print($3)" 2>/dev/null; }
h_of() { py "$1" hk_chainInfo 'r["height"]' || echo 0; }
ah_of(){ py "$1" hk_chainInfo 'r["app_hash"]' || echo "?"; }
wait_h(){ local port=$1 target=$2 tries=${3:-90}; for _ in $(seq "$tries"); do [[ "$(h_of "$port")" -ge "$target" ]] && return 0; sleep 2; done; return 1; }
noansi(){ sed -r 's/\x1b\[[0-9;]*[mK]//g' "$1"; }
# app_hash agreement at the SAME height (tip-vs-tip races by a height between two RPC calls):
# polls until both report the same height, then compares; a differing hash at an equal height fails.
same_hash(){ local a=$1 b=$2 ha hb aa ab; for _ in $(seq 20); do
    ha=$(h_of "$a"); aa=$(ah_of "$a"); hb=$(h_of "$b"); ab=$(ah_of "$b")
    if [[ "$ha" == "$hb" && "$ha" != 0 ]]; then [[ "$aa" == "$ab" ]] && return 0 || { echo "    height $ha: $aa vs $ab"; return 1; }; fi
    sleep 1; done; echo "    heights never met ($ha vs $hb)"; return 1; }
has(){ noansi "$1" | grep -E -- "$2" >/dev/null; }
# power view: "total founding external quorum max_absent alone active powers…"
pv(){ py "$1" hk_getValidators 'r["total_power"],r["founding_power"],r["external_power"],r["quorum_power"],r["max_absent_power"],r["founders_alone_decide"],(r.get("bootstrap") or {}).get("active"),"-".join(str(v["voting_power"]) for v in sorted(r["validators"],key=lambda v:v["address"]))'; }
start_node(){ ( cd "$H" && exec env HK_PROVER_URL="$PROVER" RUST_LOG=info nohup "$BIN" start "$1" </dev/null >>"$2" 2>&1 ) & }
submit(){ printf '{"method":"hk_submitSetChange","params":%s}' "$(cat "$1")" | curl -s -m 10 -X POST "http://127.0.0.1:$2" -d @-; }

echo "== 1 · fresh devnet, activation at height $HK_G1_HEIGHT (env; testnet-1 is hard-wired at 110,000)"
./devnet.sh --fresh -n 4 --prover-url "$PROVER" >/dev/null
wait_h 26000 5 60 && ok "devnet deciding (height $(h_of 26000))" || { bad "devnet did not reach height 5"; exit 1; }
V=$(pv 26000); [[ "$V" == "4 4 0 3 1 True False 1-1-1-1" ]] && ok "before H: total 4 · founding 4 · quorum 3 · bootstrap inactive · powers 1-1-1-1" || bad "before H: $V"
B=$(py 26000 hk_getValidators 'r["bootstrap"]["height"],r["bootstrap"]["founding_power"]'); [[ "$B" == "$HK_G1_HEIGHT $HK_G1_POWER" ]] && ok "bootstrap table read back: height $HK_G1_HEIGHT power $HK_G1_POWER" || bad "bootstrap table: $B"
G=$(py 26000 hk_getValidators 'all(v["genesis"] for v in r["validators"])'); [[ "$G" == "True" ]] && ok "every seat marked genesis" || bad "genesis flags: $G"

echo "== 2 · the activation"
wait_h 26000 $((HK_G1_HEIGHT+3)) 120 || bad "chain did not reach H+3"
sleep 3
for p in 26000 26001 26002 26003; do
    V=$(pv $p); [[ "$V" == "16 16 0 11 5 True True 4-4-4-4" ]] && ok "port $p after H: total 16 · quorum 11 · founders alone · powers 4-4-4-4" || bad "port $p after H: $V"
done
for i in 0 1 2 3; do has "$H/node$i.log" "G1 BOOTSTRAP GOVERNANCE ACTIVATED" && ok "node$i logged the activation" || bad "node$i: no activation line"; done
for p in 26001 26002 26003; do same_hash 26000 $p && ok "port $p app_hash == node0 (same height)" || bad "port $p app_hash differs from node0"; done
H0=$(h_of 26000); sleep 12; H1=$(h_of 26000); [[ "$H1" -gt "$H0" ]] && ok "chain keeps deciding after the re-weight ($H0 → $H1)" || bad "chain stalled after H ($H0 → $H1)"

echo "== 3 · admit an external seat with THREE founding approvals (12 > 2/3 of 16)"
rm -rf "$H/node4" "$H/node5"
"$BIN" keygen "$H/node4" ext-4 >/dev/null
cp "$H/node0/genesis.json" "$H/node4/genesis.json"
PEERS=$(for i in 0 1 2 3; do printf '/ip4/127.0.0.1/tcp/%d,' $((27000+i)); done | sed 's/,$//')
"$BIN" config-gen "$H/node4" --listen /ip4/127.0.0.1/tcp/27004 --peers "$PEERS" --rpc 127.0.0.1:26004 --metrics 127.0.0.1:29004 >/dev/null
start_node "$H/node4" "$H/node4.log"
wait_h 26004 $(( $(h_of 26000) + 2 )) 90 && ok "node4 synced as an observer (across the activation)" || bad "node4 did not sync"
NOW=$(h_of 26000)
"$BIN" set-change propose "$H/node0" --admit "$H/node4/validator.json" --power 1 --not-before $((NOW+1)) --not-after $((NOW+400)) >/dev/null || bad "propose failed"
rm -f "$H"/node[0-5]/approval-*.json
for i in 0 1 2; do "$BIN" set-change approve "$H/node$i" "$H/node0/set-change.json" >/dev/null || bad "approve on node$i failed"; done
"$BIN" set-change assemble "$H/node0/set-change.json" "$H"/node[012]/approval-*.json -o "$H/admit.json" >/dev/null || bad "assemble failed"
RESP=$(submit "$H/admit.json" 26000); echo "$RESP" | grep -q '"accepted":true' && ok "3 founding approvals accepted (5 of 6 would have been needed at power 1)" || bad "submit refused: $RESP"
for _ in $(seq 60); do [[ "$(py 26000 hk_getValidators 'r["count"]')" == 5 ]] && break; sleep 2; done
sleep 4
V=$(pv 26000); [[ "$V" == "17 16 1 12 5 True True 4-4-4-4-1"* || "$V" == "17 16 1 12 5 True True "* ]] && ok "5 seats: total 17 · founding 16 · external 1 · quorum 12 · max absent 5 · founders alone" || bad "after admit: $V"
EXT=$(python3 -c "import json;print(bytes(json.load(open('$H/node4/validator.json'))['root_pk']).hex())")
P4=$(py 26000 hk_getValidators "[v['voting_power'] for v in r['validators'] if v['root_pk']=='$EXT'][0]"); [[ "$P4" == 1 ]] && ok "external seat weighs 1" || bad "external power: $P4"
GX=$(py 26000 hk_getValidators "[v['genesis'] for v in r['validators'] if v['root_pk']=='$EXT'][0]"); [[ "$GX" == "False" ]] && ok "external seat is not marked genesis" || bad "genesis flag on external: $GX"

echo "== 4 · SetPower by certificate: the external seat 1 → 3"
rm -f "$H"/node[0-5]/approval-*.json
NOW=$(h_of 26000)
"$BIN" set-change propose "$H/node0" --set-power "$EXT" --power 3 --not-before $((NOW+1)) --not-after $((NOW+400)) | grep -q "SET-POWER" && ok "propose --set-power writes the body" || bad "propose --set-power"
for i in 0 1 2; do "$BIN" set-change approve "$H/node$i" "$H/node0/set-change.json" >/dev/null || bad "approve on node$i failed"; done
"$BIN" set-change assemble "$H/node0/set-change.json" "$H"/node[012]/approval-*.json -o "$H/power.json" >/dev/null || bad "assemble (set-power) failed"
RESP=$(submit "$H/power.json" 26001); echo "$RESP" | grep -q '"accepted":true' && ok "set-power cert accepted (submitted to node1)" || bad "set-power refused: $RESP"
for _ in $(seq 60); do [[ "$(py 26000 hk_getValidators "[v['voting_power'] for v in r['validators'] if v['root_pk']=='$EXT'][0]")" == 3 ]] && break; sleep 2; done
sleep 4
V=$(pv 26000); [[ "$V" == "19 16 3 13 6 True True "* ]] && ok "after set-power: total 19 · external 3 · quorum 13 · founders still alone" || bad "after set-power: $V"
for p in 26001 26002 26003 26004; do [[ "$(pv $p)" == "$(pv 26000)" ]] && ok "port $p: same weights" || bad "port $p: weights differ: $(pv $p)"; done
HB=$(python3 - "$H/node0.log" <<'EOF'
import re,sys
for line in open(sys.argv[1],errors="ignore"):
    line=re.sub(r'\x1b\[[0-9;]*[mK]','',line)          # tracing colours the field names and the '='
    if 'RE-WEIGHTED' in line:
        h=re.search(r'effective_from=(\d+)', line); print(int(h.group(1))-1 if h else ""); break
EOF
)
if [[ -n "$HB" ]]; then
    C=$(rpc 26000 hk_getBlock "{\"height\":$HB}" | python3 -c 'import sys,json;b=json.load(sys.stdin)["result"];print(b["set_changes"][0]["change"] if b.get("set_changes") else "none")' 2>/dev/null)
    [[ "$C" == "set_power" ]] && ok "hk_getBlock $HB carries change \"set_power\"" || bad "block $HB set_changes: $C"
else
    bad "no RE-WEIGHTED line with effective_from in node0.log"
fi
OUT=$("$BIN" set-change propose "$H/node0" --set-power "$EXT" --power 0 --not-before 1 --not-after 2 2>&1); echo "$OUT" | grep -q "voting_power must be" && ok "set-power to 0 refused by shape" || bad "power 0 accepted: $OUT"

echo "== 5 · liveness: the external seat goes down, the founders keep deciding"
PID4=$(pgrep -f "hk-node start $H/node4\$" | head -n1); [[ -n "$PID4" ]] && kill "$PID4" && ok "node4 (power 3 of 19) killed" || bad "could not kill node4"
sleep 4; H0=$(h_of 26000); sleep 20; H1=$(h_of 26000)
[[ "$H1" -gt "$H0" ]] && ok "chain advances without the external seat ($H0 → $H1): 16 > 2/3 of 19" || bad "chain stalled without node4 ($H0 → $H1)"

echo "== 6 · replay: node0 restarted on its persisted home re-derives the weights"
PID0=$(pgrep -f "hk-node start $H/node0\$" | head -n1); [[ -n "$PID0" ]] && kill "$PID0" && sleep 3 && ok "node0 stopped" || bad "could not stop node0"
echo "--- restart $(date -u +%FT%TZ) ---" >>"$H/node0.log"
start_node "$H/node0" "$H/node0.log"
wait_h 26000 $(( $(h_of 26001) )) 60 && ok "node0 back and caught up" || bad "node0 did not come back"
sleep 4; [[ "$(pv 26000)" == "$(pv 26001)" ]] && ok "node0 after restart: same weights as node1 ($(pv 26000))" || bad "node0 weights after restart: $(pv 26000) vs $(pv 26001)"
same_hash 26000 26001 && ok "node0 app_hash == node1 after restart (same height)" || bad "node0 app_hash differs after restart"

echo "== 7 · node5 from GENESIS across the activation and both certificates"
"$BIN" keygen "$H/node5" ext-5 >/dev/null
cp "$H/node0/genesis.json" "$H/node5/genesis.json"
"$BIN" config-gen "$H/node5" --listen /ip4/127.0.0.1/tcp/27005 --peers "$PEERS" --rpc 127.0.0.1:26005 --metrics 127.0.0.1:29005 >/dev/null
start_node "$H/node5" "$H/node5.log"
wait_h 26005 $(( $(h_of 26001) + 1 )) 150 && ok "node5 synced from genesis" || bad "node5 did not sync (see $H/node5.log)"
sleep 3; same_hash 26005 26001 && ok "node5 app_hash == node1 (same height)" || bad "node5 app_hash mismatch"
[[ "$(pv 26005)" == "$(pv 26001)" ]] && ok "node5 derived the weights by replay ($(pv 26005))" || bad "node5 weights: $(pv 26005)"
has "$H/node5.log" "G1 BOOTSTRAP GOVERNANCE ACTIVATED" && has "$H/node5.log" "Validator ADMITTED" && has "$H/node5.log" "RE-WEIGHTED" && ok "node5 log: activation + admit + set-power replayed" || bad "node5 log lacks a replay line"

echo
echo "== gate-g1: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && echo "GATE GREEN — bootstrap governance: founders re-weighted by rule at H, decide alone, set-power by certificate, liveness without externals, replay-safe." || echo "GATE RED — read the FAIL lines and $H/node*.log"
