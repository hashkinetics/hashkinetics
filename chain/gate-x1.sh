#!/usr/bin/env bash
# gate-x1.sh -- the X1 receipt on a local devnet (WSL/Linux): issued assets end to end.
#
#   ./gate-x1.sh                       # needs hk-prove listening on 127.0.0.1:9911 (vk pins)
#   HK_PROVER_URL=… ./gate-x1.sh       # or another prover
#
# What it proves (each line is a PASS/FAIL):
#   1. 4-validator devnet up, deciding; registry empty; app_hash equal on every node.
#   2. `org` registers USDC.t (id = H(issuer, symbol), policy mfps); hk_getAsset finds it
#      by id AND by symbol@issuer; a second issuer registering the same symbol gets a
#      DIFFERENT id (issuer-bound ids, not first-come names).
#   3. mint → alice; conservation (held == circulating) on every node; hk_getAccount
#      lists the balance by asset.
#   4. transfer alice → bob; freeze bob → alice→bob AND bob→alice refused `frozen by
#      issuer`; bob's native balance still moves (the gate is per asset); unfreeze → moves.
#   5. pause → transfer refused `asset paused`, mint refused; unpause → mint lands.
#   6. non-issuer mint refused; burn with a destination → burned counter, conserved.
#   7. every validator reports the same registry + app_hash; a validator restarted from
#      snapshot3.bin rejoins at the same app_hash; a fresh node synced from genesis
#      derives the same registry (replay across the registration).
set -uo pipefail
cd "$(dirname "$0")"
H="${HK_DEVNET_HOME:-$HOME/hk-devnet}"
BIN="$(readlink -f "${CARGO_TARGET_DIR:-target}/release/hk-node")"   # absolute: start_node runs from $H
PROVER="${HK_PROVER_URL:-http://127.0.0.1:9911}"
RPC=http://127.0.0.1:26000
PASS=0; FAIL=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
rpc()  { local p=${3:-}; [[ -z "$p" ]] && p="{}"; curl -s -m 5 -X POST "http://127.0.0.1:$1" -d "{\"method\":\"$2\",\"params\":$p}"; }
h_of() { rpc "$1" hk_chainInfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["height"])' 2>/dev/null || echo 0; }
ah_of(){ rpc "$1" hk_chainInfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["app_hash"])' 2>/dev/null || echo "?"; }
wait_h(){ local port=$1 target=$2 tries=${3:-90}; for _ in $(seq "$tries"); do [[ "$(h_of "$port")" -ge "$target" ]] && return 0; sleep 2; done; return 1; }
# registry view on a port: "count supply burned paused frozen conserved" for ASSET
aview(){ rpc "$1" hk_getAsset "{\"asset\":\"$2\"}" | python3 -c 'import sys,json;r=json.load(sys.stdin)["result"];a=r.get("asset",{});print(r["found"],a.get("supply"),a.get("burned"),a.get("paused"),a.get("frozen_count"),a.get("conserved"))' 2>/dev/null; }
acount(){ rpc "$1" hk_getAssets | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["count"])' 2>/dev/null || echo "?"; }
bal(){ rpc "$1" hk_balance "{\"id\":\"$2\",\"asset\":\"$3\"}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["amount"])' 2>/dev/null || echo "?"; }
# run a CLI verb; echo the receipt line ("ok …" / "rejected: …" / the CLI error)
cli(){ "$BIN" "$@" 2>&1 | grep -E "receipt:|Error|error" | head -1 | sed 's/.*receipt: //'; }
start_node(){ local home=$1 log=$2; ( cd "$H" && exec env HK_PROVER_URL="$PROVER" RUST_LOG=info nohup "$BIN" start "$home" </dev/null >>"$log" 2>&1 ) & }

echo "== 1 · fresh 4-validator devnet"
./devnet.sh --fresh -n 4 --prover-url "$PROVER" >/dev/null
wait_h 26000 5 60 && ok "devnet deciding (height $(h_of 26000))" || { bad "devnet did not reach height 5"; exit 1; }
[[ "$(acount 26000)" == 0 ]] && ok "registry empty at start" || bad "registry not empty: $(acount 26000)"
USD=$(python3 -c 'print("09"*32)')
for name in org agent-a merchant agent-b; do rm -rf "$H/acct-$name"; "$BIN" account-adopt-demo "$H/acct-$name" "$name" "$RPC" >/dev/null || bad "adopt $name"; done
ORG=$(python3 -c "import json;print(json.load(open('$H/acct-org/account.json'))['id'])")
ALICE=$(python3 -c "import json;print(json.load(open('$H/acct-agent-a/account.json'))['id'])")
BOB=$(python3 -c "import json;print(json.load(open('$H/acct-merchant/account.json'))['id'])")
OTHER=$(python3 -c "import json;print(json.load(open('$H/acct-agent-b/account.json'))['id'])")
# fund alice/bob/other with native USD so they can act (devnet is fee-free; the native asset is unregistered)
for who in $ALICE $BOB $OTHER; do "$BIN" account-send "$H/acct-org" "$RPC" "$who" 1000000 >/dev/null 2>&1; done

echo "== 2 · register USDC.t (org) — issuer-bound id"
ASSET=$("$BIN" asset-id "$H/acct-org" USDC.t)
R=$(cli asset register "$H/acct-org" "$RPC" USDC.t 6 mfps)
[[ "$R" == ok* ]] && ok "register USDC.t: $R" || bad "register: $R"
sleep 2
V=$(aview 26000 "$ASSET"); [[ "$V" == "True 0 0 False 0 True" ]] && ok "hk_getAsset by id: $V" || bad "hk_getAsset by id: $V"
S=$(rpc 26000 hk_getAsset "{\"issuer\":\"$ORG\",\"symbol\":\"USDC.t\"}" | python3 -c 'import sys,json;r=json.load(sys.stdin)["result"];print(r["found"], r["asset"]["policy"]["flags"], r["asset"]["asset"])')
[[ "$S" == "True mfps $ASSET" ]] && ok "hk_getAsset by symbol@issuer: policy mfps, same id" || bad "by symbol: $S"
OTHER_ASSET=$("$BIN" asset-id "$H/acct-agent-b" USDC.t)
R=$(cli asset register "$H/acct-agent-b" "$RPC" USDC.t 6 m)
[[ "$R" == ok* && "$OTHER_ASSET" != "$ASSET" ]] && ok "another issuer's USDC.t is a different asset ($OTHER_ASSET != $ASSET)" || bad "second issuer: $R"
sleep 2; [[ "$(acount 26000)" == 2 ]] && ok "registry has 2 assets" || bad "registry count $(acount 26000)"

echo "== 3 · mint → alice; conservation everywhere; balances by asset"
R=$(cli asset mint "$H/acct-org" "$RPC" "$ASSET" "$ALICE" 5000000)
[[ "$R" == ok* ]] && ok "mint 5,000,000 → alice" || bad "mint: $R"
sleep 2
[[ "$(bal 26000 $ALICE $ASSET)" == 5000000 ]] && ok "alice holds 5,000,000 USDC.t" || bad "alice balance $(bal 26000 $ALICE $ASSET)"
for p in 26000 26001 26002 26003; do V=$(aview $p "$ASSET"); [[ "$V" == "True 5000000 0 False 0 True" ]] && ok "port $p: supply 5,000,000 conserved" || bad "port $p: $V"; done
B=$(rpc 26000 hk_getAccount "{\"id\":\"$ALICE\"}" | python3 -c 'import sys,json;r=json.load(sys.stdin)["result"];print(sorted((str(b.get("symbol")),b["amount"]) for b in r["balances"]))')
[[ "$B" == *"('USDC.t', '5000000')"* ]] && ok "hk_getAccount lists USDC.t by symbol: $B" || bad "hk_getAccount balances: $B"

echo "== 4 · transfer, freeze bob (both directions refused), native still moves, unfreeze"
R=$(cli account-send "$H/acct-agent-a" "$RPC" "$BOB" 2000000 "$ASSET"); [[ "$R" == ok* ]] && ok "alice → bob 2,000,000" || bad "transfer: $R"
R=$(cli asset freeze "$H/acct-org" "$RPC" "$ASSET" "$BOB"); [[ "$R" == ok* ]] && ok "freeze bob" || bad "freeze: $R"
sleep 1
R=$(cli account-send "$H/acct-agent-a" "$RPC" "$BOB" 1000000 "$ASSET"); [[ "$R" == *"frozen by issuer"* ]] && ok "alice → bob refused: $R" || bad "alice → frozen bob: $R"
R=$(cli account-send "$H/acct-merchant" "$RPC" "$ALICE" 1000000 "$ASSET"); [[ "$R" == *"frozen by issuer"* ]] && ok "bob → alice refused: $R" || bad "frozen bob → alice: $R"
R=$(cli account-send "$H/acct-merchant" "$RPC" "$ALICE" 1000 "$USD"); [[ "$R" == ok* ]] && ok "bob's native USD still moves (gate is per asset)" || bad "native transfer while frozen: $R"
R=$(cli asset mint "$H/acct-org" "$RPC" "$ASSET" "$BOB" 1); [[ "$R" == *"frozen by issuer"* ]] && ok "mint to frozen bob refused" || bad "mint to frozen: $R"
R=$(cli asset unfreeze "$H/acct-org" "$RPC" "$ASSET" "$BOB"); [[ "$R" == ok* ]] && ok "unfreeze bob" || bad "unfreeze: $R"
sleep 1
R=$(cli account-send "$H/acct-merchant" "$RPC" "$ALICE" 1000000 "$ASSET"); [[ "$R" == ok* ]] && ok "bob → alice 1,000,000 after unfreeze" || bad "after unfreeze: $R"

echo "== 5 · pause / unpause"
R=$(cli asset pause "$H/acct-org" "$RPC" "$ASSET"); [[ "$R" == ok* ]] && ok "pause" || bad "pause: $R"
sleep 1
R=$(cli account-send "$H/acct-agent-a" "$RPC" "$BOB" 1000 "$ASSET"); [[ "$R" == *"asset paused"* ]] && ok "transfer refused while paused" || bad "paused transfer: $R"
R=$(cli asset mint "$H/acct-org" "$RPC" "$ASSET" "$ALICE" 1000); [[ "$R" == *"asset paused"* ]] && ok "mint refused while paused" || bad "paused mint: $R"
V=$(aview 26000 "$ASSET"); [[ "$V" == *"True 0 True"* ]] && ok "hk_getAsset shows paused=True, conserved" || bad "paused view: $V"
R=$(cli asset unpause "$H/acct-org" "$RPC" "$ASSET"); [[ "$R" == ok* ]] && ok "unpause" || bad "unpause: $R"
sleep 1
R=$(cli asset mint "$H/acct-org" "$RPC" "$ASSET" "$ALICE" 1000000); [[ "$R" == ok* ]] && ok "mint lands after unpause (supply 6,000,000)" || bad "mint after unpause: $R"

echo "== 6 · not the issuer; burn with destination"
R=$(cli asset mint "$H/acct-agent-a" "$RPC" "$ASSET" "$ALICE" 1); [[ "$R" == *"not the asset's issuer"* ]] && ok "alice cannot mint org's asset" || bad "non-issuer mint: $R"
R=$(cli asset burn "$H/acct-agent-a" "$RPC" "$ASSET" 1000000 6574683a307861626364); [[ "$R" == ok* ]] && ok "alice burns 1,000,000 → eth:0xabcd" || bad "burn: $R"
sleep 2
V=$(aview 26000 "$ASSET"); [[ "$V" == "True 6000000 1000000 False 0 True" ]] && ok "supply 6,000,000 · burned 1,000,000 · conserved: $V" || bad "after burn: $V"
K=$(rpc 26000 hk_getAccountTxs "{\"id\":\"$ALICE\",\"limit\":20}" | python3 -c 'import sys,json;print(",".join(sorted({t["kind"] for t in json.load(sys.stdin)["result"]["txs"]})))' 2>/dev/null)
[[ "$K" == *asset_burn* && "$K" == *asset_mint* ]] && ok "explorer/tx index names the kinds: $K" || bad "tx index kinds: $K"

echo "== 7 · every node agrees; restart from snapshot3; sync from genesis"
A0=$(ah_of 26000); AGREE=1
for p in 26001 26002 26003; do [[ "$(ah_of $p)" == "$A0" && "$(aview $p "$ASSET")" == "$(aview 26000 "$ASSET")" ]] || AGREE=0; done
[[ "$AGREE" == 1 ]] && ok "4/4 same app_hash + same registry view" || bad "nodes disagree (app_hash/registry)"
T=$(( ($(h_of 26000) / 16 + 1) * 16 + 2 )); wait_h 26000 "$T" 120 || bad "did not reach a snapshot boundary"
pkill -f "hk-node start $H/node1" ; sleep 2
[[ -f "$H/node1/snapshot3.bin" ]] && ok "node1 wrote snapshot3.bin" || bad "no snapshot3.bin on node1 ($(ls $H/node1 | tr '\n' ' '))"
start_node "$H/node1" "$H/node1.log"
T=$(( $(h_of 26000) + 6 )); wait_h 26001 "$T" 120 && ok "node1 back at $T" || bad "node1 did not rejoin"
sleep 3; [[ "$(ah_of 26001)" == "$(ah_of 26000)" ]] && ok "node1 app_hash == node0 after restore" || bad "node1 app_hash mismatch after restore"
grep -q "Snapshot restored" "$H/node1.log" && ok "node1 log shows a restore" || bad "node1 log has no restore line"
rm -rf "$H/node4"; "$BIN" keygen "$H/node4" ext-4 >/dev/null; cp "$H/node0/genesis.json" "$H/node4/genesis.json"
PEERS=$(for i in 0 1 2 3; do printf '/ip4/127.0.0.1/tcp/%d,' $((27000+i)); done | sed 's/,$//')
"$BIN" config-gen "$H/node4" --listen /ip4/127.0.0.1/tcp/27004 --peers "$PEERS" --rpc 127.0.0.1:26004 --metrics 127.0.0.1:29004 >/dev/null
start_node "$H/node4" "$H/node4.log"
T=$(( $(h_of 26000) + 3 )); wait_h 26004 "$T" 150 && ok "node4 synced from genesis to $T" || bad "node4 did not sync (see $H/node4.log)"
sleep 3; [[ "$(ah_of 26004)" == "$(ah_of 26000)" ]] && ok "node4 app_hash == node0" || bad "node4 app_hash mismatch"
[[ "$(acount 26004)" == 2 && "$(aview 26004 "$ASSET")" == "$(aview 26000 "$ASSET")" ]] && ok "node4 derived the registry by replay" || bad "node4 registry: $(acount 26004) $(aview 26004 "$ASSET")"

echo
echo "== X1 GATE: $PASS passed, $FAIL failed"
[[ "$FAIL" == 0 ]] && echo "GATE GREEN — issued assets: register, mint, freeze, pause, burn, conservation, restore, sync." || echo "GATE RED — read the FAIL lines and $H/node*.log"
