#!/usr/bin/env bash
# gate-v1.sh -- the V1 receipt on a local devnet (WSL/Linux): a seat admitted to a RUNNING
# chain votes from the next height; removed again; an observer syncs across both boundaries.
#
#   ./gate-v1.sh                       # needs hk-prove listening on 127.0.0.1:9911 (vk pins)
#   HK_PROVER_URL=… ./gate-v1.sh       # or another prover
#
# What it proves (each line is a PASS/FAIL):
#   1. 4-validator devnet up, deciding.
#   2. node4 (fresh keygen, NOT in genesis) syncs as an observer: same app_hash as node0.
#   3. propose --admit node4 → approve on node0/node1/node2 (3 of 4 = 9 > 8) → assemble →
#      hk_submitSetChange on node0 → within the window the cert commits → hk_getValidators
#      count 5 on EVERY node, same address list.
#   4. node4 VOTES: its signer.remaining falls while height advances (leaves are only spent
#      by signing) — an observer never spends one.
#   5. a 2-of-5 cert is refused at submit (6 > 10 is false); a wrong-chain cert is refused.
#   6. propose --remove node4 → approvals from node0/1/2/4 (4 of 5 = 12 > 10) → count 4
#      everywhere; node4 keeps syncing (app_hash matches) but spends no more leaves.
#   7. node5, started from GENESIS after both changes, syncs to the tip: certificates on
#      both sides of both boundaries verified against the right set (HK-R6).
set -uo pipefail
cd "$(dirname "$0")"
H="${HK_DEVNET_HOME:-$HOME/hk-devnet}"
BIN="${CARGO_TARGET_DIR:-target}/release/hk-node"
PROVER="${HK_PROVER_URL:-http://127.0.0.1:9911}"
PASS=0; FAIL=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
rpc()  { local p=${3:-}; [[ -z "$p" ]] && p="{}"; curl -s -m 5 -X POST "http://127.0.0.1:$1" -d "{\"method\":\"$2\",\"params\":$p}"; }
h_of() { rpc "$1" hk_chainInfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["height"])' 2>/dev/null || echo 0; }
ah_of(){ rpc "$1" hk_chainInfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["app_hash"])' 2>/dev/null || echo "?"; }
rem_of(){ rpc "$1" hk_chainInfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["signer"]["remaining"])' 2>/dev/null || echo -1; }
nval() { rpc "$1" hk_getValidators | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["count"])' 2>/dev/null || echo 0; }
addrs(){ rpc "$1" hk_getValidators | python3 -c 'import sys,json;print(",".join(sorted(v["address"] for v in json.load(sys.stdin)["result"]["validators"])))' 2>/dev/null; }
wait_h(){ local port=$1 target=$2 tries=${3:-90}; for _ in $(seq "$tries"); do [[ "$(h_of "$port")" -ge "$target" ]] && return 0; sleep 2; done; return 1; }
start_node(){ local home=$1 log=$2; HK_PROVER_URL="$PROVER" RUST_LOG=info nohup "$BIN" start "$home" >"$log" 2>&1 & echo $!; }

echo "== 1 · fresh 4-validator devnet"
./devnet.sh --fresh -n 4 --prover-url "$PROVER" >/dev/null
wait_h 26000 5 60 && ok "devnet deciding (height $(h_of 26000))" || { bad "devnet did not reach height 5"; exit 1; }
CHAIN=$(rpc 26000 hk_chainInfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["chain_id"])')
echo "  chain id: $CHAIN"

echo "== 2 · node4 joins as an OBSERVER (fresh key, not in genesis)"
rm -rf "$H/node4" "$H/node5"
"$BIN" keygen "$H/node4" ext-4 >/dev/null
cp "$H/node0/genesis.json" "$H/node4/genesis.json"
PEERS=$(for i in 0 1 2 3; do printf '/ip4/127.0.0.1/tcp/%d,' $((27000+i)); done | sed 's/,$//')
"$BIN" config-gen "$H/node4" --listen /ip4/127.0.0.1/tcp/27004 --peers "$PEERS" --rpc 127.0.0.1:26004 --metrics 127.0.0.1:29004 >/dev/null
start_node "$H/node4" "$H/node4.log" >/dev/null
T=$(( $(h_of 26000) + 3 ))
wait_h 26004 "$T" 90 && ok "node4 synced to $T as observer" || bad "node4 did not sync"
sleep 3; [[ "$(ah_of 26004)" == "$(ah_of 26000)" ]] && ok "node4 app_hash == node0 app_hash" || bad "app_hash mismatch node4 vs node0"
R0=$(rem_of 26004); sleep 8; R1=$(rem_of 26004)
[[ "$R1" == "$R0" ]] && ok "observer spends no leaves ($R0 → $R1)" || bad "observer spent leaves ($R0 → $R1)"

echo "== 3 · admit node4 (3 of 4 approve = 9 > 8)"
NOW=$(h_of 26000); NB=$((NOW+1)); NA=$((NOW+400))
"$BIN" set-change propose "$H/node0" --admit "$H/node4/validator.json" --power 1 --not-before "$NB" --not-after "$NA" >/dev/null || bad "propose failed"
for i in 0 1 2; do "$BIN" set-change approve "$H/node$i" "$H/node0/set-change.json" >/dev/null || bad "approve on node$i failed"; done
"$BIN" set-change assemble "$H/node0/set-change.json" "$H"/node[012]/approval-*.json -o "$H/admit.json" >/dev/null || bad "assemble failed"
RESP=$(printf '{"method":"hk_submitSetChange","params":%s}' "$(cat "$H/admit.json")" | curl -s -m 10 -X POST http://127.0.0.1:26000 -d @-)
echo "$RESP" | grep -q '"accepted":true' && ok "hk_submitSetChange accepted" || bad "submit refused: $RESP"
for _ in $(seq 60); do [[ "$(nval 26000)" == 5 ]] && break; sleep 2; done
[[ "$(nval 26000)" == 5 ]] && ok "node0 sees 5 seats" || bad "node0 still $(nval 26000) seats"
sleep 6
A0=$(addrs 26000); for p in 26001 26002 26003 26004; do [[ "$(addrs $p)" == "$A0" ]] && ok "port $p: same 5-seat set" || bad "port $p: set differs"; done

echo "== 4 · node4 VOTES (signer.remaining falls, height advances)"
H0=$(h_of 26004); R0=$(rem_of 26004); sleep 20; H1=$(h_of 26004); R1=$(rem_of 26004)
[[ "$R1" -lt "$R0" && "$H1" -gt "$H0" ]] && ok "node4 voting: remaining $R0 → $R1, height $H0 → $H1" || bad "node4 not voting (remaining $R0 → $R1, height $H0 → $H1)"

echo "== 5 · refusals"
rm -f "$H"/node[0-5]/approval-*.json
NOW=$(h_of 26000)
"$BIN" set-change propose "$H/node0" --remove "$(python3 -c "import json;print(bytes(json.load(open('$H/node4/validator.json'))['root_pk']).hex())")" --not-before "$((NOW+1))" --not-after "$((NOW+400))" >/dev/null
for i in 0 1; do "$BIN" set-change approve "$H/node$i" "$H/node0/set-change.json" >/dev/null; done
"$BIN" set-change assemble "$H/node0/set-change.json" "$H"/node[01]/approval-*.json -o "$H/weak.json" >/dev/null
RESP=$(printf '{"method":"hk_submitSetChange","params":%s}' "$(cat "$H/weak.json")" | curl -s -m 10 -X POST http://127.0.0.1:26000 -d @-)
echo "$RESP" | grep -q '"accepted":false' && ok "2-of-5 refused: $(echo "$RESP" | head -c 120)" || bad "2-of-5 was accepted: $RESP"
python3 - "$H/weak.json" "$H/wrongchain.json" <<'EOF'
import json,sys; c=json.load(open(sys.argv[1])); c["cert"]["body"]["chain_id"]="hashkinetics-1-deadbeef"; json.dump(c,open(sys.argv[2],"w"))
EOF
RESP=$(printf '{"method":"hk_submitSetChange","params":%s}' "$(cat "$H/wrongchain.json")" | curl -s -m 10 -X POST http://127.0.0.1:26000 -d @-)
echo "$RESP" | grep -q '"accepted":false' && ok "wrong-chain cert refused" || bad "wrong-chain cert accepted: $RESP"

echo "== 6 · remove node4 (4 of 5 approve = 12 > 10)"
rm -f "$H"/node[0-5]/approval-*.json
for i in 0 1 2 4; do "$BIN" set-change approve "$H/node$i" "$H/node0/set-change.json" >/dev/null || bad "approve on node$i failed"; done
"$BIN" set-change assemble "$H/node0/set-change.json" "$H"/node[0124]/approval-*.json -o "$H/remove.json" >/dev/null || bad "assemble (remove) failed"
RESP=$(printf '{"method":"hk_submitSetChange","params":%s}' "$(cat "$H/remove.json")" | curl -s -m 10 -X POST http://127.0.0.1:26001 -d @-)
echo "$RESP" | grep -q '"accepted":true' && ok "remove cert accepted (submitted to node1)" || bad "remove submit refused: $RESP"
for _ in $(seq 60); do [[ "$(nval 26000)" == 4 ]] && break; sleep 2; done
[[ "$(nval 26000)" == 4 ]] && ok "back to 4 seats" || bad "still $(nval 26000) seats"
sleep 6; A0=$(addrs 26000); for p in 26001 26002 26003 26004; do [[ "$(addrs $p)" == "$A0" ]] && ok "port $p: same 4-seat set" || bad "port $p: set differs"; done
H0=$(h_of 26004); R0=$(rem_of 26004); sleep 20; H1=$(h_of 26004); R1=$(rem_of 26004)
[[ "$R1" == "$R0" && "$H1" -gt "$H0" ]] && ok "node4 unseated: syncing ($H0 → $H1), spending nothing ($R0)" || bad "node4 after removal: remaining $R0 → $R1, height $H0 → $H1"
[[ "$(ah_of 26004)" == "$(ah_of 26000)" ]] && ok "node4 app_hash still == node0" || bad "node4 app_hash diverged after removal"

echo "== 7 · node5 syncs from GENESIS across both boundaries"
"$BIN" keygen "$H/node5" ext-5 >/dev/null
cp "$H/node0/genesis.json" "$H/node5/genesis.json"
"$BIN" config-gen "$H/node5" --listen /ip4/127.0.0.1/tcp/27005 --peers "$PEERS" --rpc 127.0.0.1:26005 --metrics 127.0.0.1:29005 >/dev/null
start_node "$H/node5" "$H/node5.log" >/dev/null
T=$(( $(h_of 26000) + 2 ))
wait_h 26005 "$T" 150 && ok "node5 synced to $T from genesis" || bad "node5 did not sync (see $H/node5.log)"
sleep 3; [[ "$(ah_of 26005)" == "$(ah_of 26000)" ]] && ok "node5 app_hash == node0" || bad "node5 app_hash mismatch"
[[ "$(nval 26005)" == 4 ]] && ok "node5 derived the 4-seat set by replay" || bad "node5 set count $(nval 26005)"
grep -q "Validator ADMITTED" "$H/node5.log" && grep -q "Validator REMOVED" "$H/node5.log" && ok "node5 log shows both set changes replayed" || bad "node5 log lacks the set-change lines"

echo
echo "== V1 GATE: $PASS passed, $FAIL failed"
[[ "$FAIL" == 0 ]] && echo "GATE GREEN — validator-set changes on a running chain: admit, vote, refuse, remove, sync." || echo "GATE RED — read the FAIL lines and $H/node*.log"
