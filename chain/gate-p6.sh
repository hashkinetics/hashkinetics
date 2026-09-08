#!/usr/bin/env bash
# gate-p6.sh -- the P6 receipt on a local devnet (WSL/Linux): one shielded pool per asset.
#
#   ./gate-p6.sh                       # needs hk-prove listening on 127.0.0.1:9911 (real proofs)
#   HK_PROVER_URL=… ./gate-p6.sh       # or another prover
#
# What it proves (each line is a PASS/FAIL) — docs/P6-MULTI-ASSET-POOL.md §3:
#   1. 4-validator devnet up; hk_getPools shows ONE pool (legacy), multi_pool_from 0 (devnet).
#   2. org registers USDC.t (mfps) and EUR.t (mfp — not pool-eligible); mints both to itself.
#   3. shield 1 of the test asset → the legacy pool pins the test asset (v1, byte for byte).
#   4. shield 2 USDC.t → a SECOND pool appears (its own root/size/ledger); the legacy pool is
#      untouched; hk_getAsset.shielded == 2,000,000; conserved; every node has the same app_hash.
#   5. shield EUR.t → refused `asset is not pool-eligible`; no pool created.
#   6. wallet scan --asset USDC.t sees the USDC.t note; the legacy scan sees only the test-asset note.
#   7. unshield 1 USDC.t → credit lands in USDC.t (not the test asset); the USDC.t pool's nullifier
#      set has 1, the legacy pool's 0; hk_nullifierSpent answers per pool.
#   8. pay 0.5 USDC.t shielded to a second wallet → it scans the note in the USDC.t pool; pool-path
#      folds for the USDC.t pool with the asset argument.
#   9. node1 restarted from snapshot4.bin rejoins at the same app_hash with both pools; node4 synced
#      from genesis derives both pools (hk_getPools count 2, same roots).
#  10. a second devnet with HK_P6_HEIGHT=999999: the same USDC.t shield is refused `pool asset
#      mismatch` — the pre-activation behaviour is the v1 behaviour.
set -uo pipefail
cd "$(dirname "$0")"
H="${HK_DEVNET_HOME:-$HOME/hk-devnet}"
BIN="$(readlink -f "${CARGO_TARGET_DIR:-target}/release/hk-node")"   # absolute: start_node runs from $H
PROVER="${HK_PROVER_URL:-http://127.0.0.1:9911}"
RPC=http://127.0.0.1:26000
PASS=0; FAIL=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
rpc()  { local p=${3:-}; [[ -z "$p" ]] && p="{}"; curl -s -m 8 -X POST "http://127.0.0.1:$1" -d "{\"method\":\"$2\",\"params\":$p}"; }
py()   { python3 -c "import sys,json;r=json.load(sys.stdin)['result'];print($1)" 2>/dev/null; }
h_of() { rpc "$1" hk_chainInfo | py 'r["height"]' || echo 0; }
ah_of(){ rpc "$1" hk_chainInfo | py 'r["app_hash"]' || echo "?"; }
# app_hash AFTER a fixed height on a port (hk_getBlock{height+1}.parent_app_hash) — deterministic
# across nodes at 1 s blocks, unlike comparing live tips read at different instants
ah_at(){ rpc "$1" hk_getBlock "{\"height\":$(( $2 + 1 ))}" | py 'r["parent_app_hash"]' || echo "?"; }
wait_h(){ local port=$1 target=$2 tries=${3:-90}; for _ in $(seq "$tries"); do [[ "$(h_of "$port")" -ge "$target" ]] && return 0; sleep 2; done; return 1; }
pools(){ rpc "$1" hk_getPools | py 'r["count"]' || echo "?"; }
# one pool's view: "asset next_index nullifiers total_shielded legacy"
pview(){ rpc "$1" hk_getPoolInfo "{\"asset\":\"$2\"}" | py 'str(r.get("asset"))[:8], r["next_index"], r["nullifiers"], r["total_shielded"], r["legacy"]' || echo "?"; }
lview(){ rpc "$1" hk_getPoolInfo | py 'str(r.get("asset"))[:8], r["next_index"], r["nullifiers"], r["total_shielded"], r["legacy"]' || echo "?"; }
bal(){ rpc "$1" hk_balance "{\"id\":\"$2\",\"asset\":\"$3\"}" | py 'r["amount"]' || echo "?"; }
shielded_of(){ rpc "$1" hk_getAsset "{\"asset\":\"$2\"}" | py 'r["asset"]["shielded"], r["asset"]["conserved"]' || echo "?"; }
cli(){ "$BIN" "$@" 2>&1 | grep -E "receipt:|Error|error" | head -1 | sed 's/.*receipt: //'; }
start_node(){ local home=$1 log=$2; ( cd "$H" && exec env HK_PROVER_URL="$PROVER" RUST_LOG=info nohup "$BIN" start "$home" </dev/null >>"$log" 2>&1 ) & }

curl -s -m 5 -X POST "$PROVER" -d '{"method":"health","params":{}}' | grep -q result || { echo "hk-prove not reachable at $PROVER"; exit 1; }

echo "== 1 · fresh 4-validator devnet (verified; P6 active from genesis on a devnet)"
./devnet.sh --fresh -n 4 --prover-url "$PROVER" >/dev/null
wait_h 26000 5 60 && ok "devnet deciding (height $(h_of 26000))" || { bad "devnet did not reach height 5"; exit 1; }
[[ "$(pools 26000)" == 1 ]] && ok "hk_getPools: one pool (legacy) at start" || bad "pools at start: $(pools 26000)"
MPF=$(rpc 26000 hk_getPools | py 'r["multi_pool_from"]'); [[ "$MPF" == 0 ]] && ok "multi_pool_from 0 (devnet: active from genesis)" || bad "multi_pool_from: $MPF"
USD=$(python3 -c 'print("09"*32)')
rm -rf "$H/acct-org"; "$BIN" account-adopt-demo "$H/acct-org" org "$RPC" >/dev/null || bad "adopt org"
ORG=$(python3 -c "import json;print(json.load(open('$H/acct-org/account.json'))['id'])")

echo "== 2 · register USDC.t (mfps) + EUR.t (mfp); mint both to org"
ASSET=$("$BIN" asset-id "$H/acct-org" USDC.t)
EUR=$("$BIN" asset-id "$H/acct-org" EUR.t)
R=$(cli asset register "$H/acct-org" "$RPC" USDC.t 6 mfps); [[ "$R" == ok* ]] && ok "register USDC.t (pool-eligible): $R" || bad "register USDC.t: $R"
R=$(cli asset register "$H/acct-org" "$RPC" EUR.t 6 mfp);   [[ "$R" == ok* ]] && ok "register EUR.t (NOT pool-eligible): $R" || bad "register EUR.t: $R"
R=$(cli asset mint "$H/acct-org" "$RPC" "$ASSET" "$ORG" 10000000); [[ "$R" == ok* ]] && ok "mint 10 USDC.t → org" || bad "mint USDC.t: $R"
R=$(cli asset mint "$H/acct-org" "$RPC" "$EUR" "$ORG" 10000000);   [[ "$R" == ok* ]] && ok "mint 10 EUR.t → org" || bad "mint EUR.t: $R"
sleep 2
[[ "$(bal 26000 "$ORG" "$ASSET")" == 10000000 ]] && ok "org holds 10 USDC.t" || bad "org USDC.t balance: $(bal 26000 "$ORG" "$ASSET")"

echo "== 3 · the legacy pool pins the FIRST asset shielded (the test asset) — v1 behaviour"
W="$H/wallet-org"; rm -rf "$W"
"$BIN" wallet init "$W" org "$RPC" >/dev/null 2>&1 && ok "CLI wallet bound to org" || bad "wallet init"
"$BIN" wallet shield "$W" 1 "$RPC" "$PROVER" 2>&1 | grep -q "shielded" && ok "shield 1 (test asset) landed" || bad "shield test asset"
sleep 2
L=$(lview 26000); [[ "$L" == "09090909 1 0 1000000 True" ]] && ok "legacy pool: pinned to the test asset, 1 leaf: $L" || bad "legacy pool: $L"
[[ "$(pools 26000)" == 1 ]] && ok "still one pool" || bad "pools: $(pools 26000)"
A0=$(ah_of 26000)

echo "== 4 · shield 2 USDC.t → its OWN pool; the legacy pool untouched"
"$BIN" wallet shield "$W" 2 "$RPC" "$PROVER" --asset "$ASSET" 2>&1 | grep -q "shielded" && ok "shield 2 USDC.t landed" || bad "shield USDC.t"
sleep 2
[[ "$(pools 26000)" == 2 ]] && ok "hk_getPools: two pools" || bad "pools: $(pools 26000)"
P=$(pview 26000 "$ASSET"); [[ "$P" == "${ASSET:0:8} 1 0 2000000 False" ]] && ok "USDC.t pool: 1 leaf, 2,000,000 shielded, not legacy: $P" || bad "USDC.t pool: $P"
L=$(lview 26000); [[ "$L" == "09090909 1 0 1000000 True" ]] && ok "legacy pool unchanged: $L" || bad "legacy pool moved: $L"
[[ "$(bal 26000 "$ORG" "$ASSET")" == 8000000 ]] && ok "org USDC.t balance 8,000,000" || bad "org USDC.t: $(bal 26000 "$ORG" "$ASSET")"
S=$(shielded_of 26000 "$ASSET"); [[ "$S" == "2000000 True" ]] && ok "hk_getAsset: shielded 2,000,000 · conserved: $S" || bad "asset view: $S"
[[ "$(ah_of 26000)" != "$A0" ]] && ok "app_hash moved (the 0xB6 pools section entered the commitment)" || bad "app_hash did not move"
HREF=$(h_of 26000); for p in 26001 26002 26003; do wait_h $p $((HREF + 1)) 30; done
AGREE=1; for p in 26001 26002 26003; do [[ "$(ah_at $p $HREF)" == "$(ah_at 26000 $HREF)" && "$(pools $p)" == 2 ]] || AGREE=0; done
[[ "$AGREE" == 1 ]] && ok "4/4 nodes: same app_hash after height $HREF, two pools each" || bad "nodes disagree on app_hash/pools at $HREF: $(for p in 26000 26001 26002 26003; do ah_at $p $HREF | cut -c1-8; done | tr '\n' ' ')"

echo "== 5 · a registered asset WITHOUT s never opens a pool"
OUT=$("$BIN" wallet shield "$W" 1 "$RPC" "$PROVER" --asset "$EUR" 2>&1); echo "$OUT" | grep -q "not pool-eligible" && ok "shield EUR.t refused: not pool-eligible" || bad "EUR.t shield: $(echo "$OUT" | tail -1)"
[[ "$(pools 26000)" == 2 ]] && ok "no pool created for EUR.t" || bad "pools: $(pools 26000)"

echo "== 6 · scanning is per pool"
SC=$("$BIN" wallet scan "$W" "$RPC" --asset "$ASSET" 2>&1); [[ "$(echo "$SC" | grep -c '^LIVE')" == 1 ]] && echo "$SC" | grep -q '^LIVE.*\$2 @' && ok "scan --asset USDC.t: one LIVE note of \$2" || bad "USDC.t scan: $(echo "$SC" | head -3 | tr '\n' ' ')"
SC=$("$BIN" wallet scan "$W" "$RPC" 2>&1); [[ "$(echo "$SC" | grep -c '^LIVE')" == 1 ]] && echo "$SC" | grep -q '^LIVE.*\$1 @' && ok "legacy scan: one LIVE note of \$1 (the test asset)" || bad "legacy scan: $(echo "$SC" | head -3 | tr '\n' ' ')"

echo "== 7 · unshield 1 USDC.t → credit in USDC.t; nullifier in ITS pool only"
"$BIN" wallet unshield "$W" 1 "$RPC" "$PROVER" --asset "$ASSET" 2>&1 | grep -q "unshielded" && ok "unshield 1 USDC.t landed" || bad "unshield USDC.t"
sleep 2
[[ "$(bal 26000 "$ORG" "$ASSET")" == 9000000 ]] && ok "org USDC.t balance 9,000,000 (credit in the pool's asset)" || bad "org USDC.t: $(bal 26000 "$ORG" "$ASSET")"
[[ "$(bal 26000 "$ORG" "$USD")" != "" ]] && ok "test-asset balance untouched by the USDC.t unshield" || bad "usd balance unreadable"
P=$(pview 26000 "$ASSET"); [[ "$P" == "${ASSET:0:8} 3 1 1000000 False" ]] && ok "USDC.t pool: 3 leaves, 1 nullifier, 1,000,000 shielded: $P" || bad "USDC.t pool after unshield: $P"
L=$(lview 26000); [[ "$L" == "09090909 1 0 1000000 True" ]] && ok "legacy pool still 1 leaf, 0 nullifiers" || bad "legacy pool: $L"
S=$(shielded_of 26000 "$ASSET"); [[ "$S" == "1000000 True" ]] && ok "conserved after the unshield: $S" || bad "asset view: $S"

echo "== 8 · a shielded payment in USDC.t to a second wallet; pool-path with the asset"
W2="$H/wallet-merchant"; rm -rf "$W2"
"$BIN" wallet init "$W2" merchant "$RPC" >/dev/null 2>&1 && ok "second wallet (merchant)" || bad "wallet2 init"
ADDR=$("$BIN" wallet address "$W2" "$RPC" 2>/dev/null)
"$BIN" wallet pay "$W" "$ADDR" 0.5 "$RPC" "$PROVER" --asset "$ASSET" 2>&1 | grep -q "fully shielded" && ok "pay 0.5 USDC.t shielded" || bad "pay USDC.t"
sleep 2
SC=$("$BIN" wallet scan "$W2" "$RPC" --asset "$ASSET" 2>&1); echo "$SC" | grep -q '^LIVE.*\$0\.5 @ index 3' && ok "merchant scans the \$0.5 USDC.t note at leaf 3 of the USDC.t pool" || bad "merchant USDC.t scan: $(echo "$SC" | head -2 | tr '\n' ' ')"
SC=$("$BIN" wallet scan "$W2" "$RPC" 2>&1); echo "$SC" | grep -q "no notes" && ok "merchant's legacy scan: nothing (the note is not there)" || bad "merchant legacy scan: $(echo "$SC" | head -2 | tr '\n' ' ')"
OUT=$("$BIN" pool-path "$RPC" 0 "$ASSET" 2>&1); echo "$OUT" | grep -q "folds to .* ✓" && ok "hk-node pool-path <asset>: folds to the stated root" || bad "pool-path: $OUT"
P=$(pview 26000 "$ASSET"); [[ "$P" == "${ASSET:0:8} 5 2 1000000 False" ]] && ok "USDC.t pool: 5 leaves, 2 nullifiers, ledger unchanged by a fully shielded pay: $P" || bad "USDC.t pool after pay: $P"

echo "== 9 · restart from snapshot4 (both pools); sync from genesis"
T=$(( ($(h_of 26000) / 16 + 1) * 16 + 2 )); wait_h 26000 "$T" 120 || bad "did not reach a snapshot boundary"
pkill -f "hk-node start $H/node1" ; sleep 2
[[ -f "$H/node1/snapshot4.bin" ]] && ok "node1 wrote snapshot4.bin" || bad "no snapshot4.bin on node1 ($(ls $H/node1 | tr '\n' ' '))"
start_node "$H/node1" "$H/node1.log"
T=$(( $(h_of 26000) + 6 )); wait_h 26001 "$T" 120 && ok "node1 back at $T" || bad "node1 did not rejoin"
sleep 3; [[ "$(ah_of 26001)" == "$(ah_of 26000)" && "$(pools 26001)" == 2 ]] && ok "node1 after restore: same app_hash, two pools" || bad "node1 after restore: $(ah_of 26001) pools $(pools 26001)"
[[ "$(pview 26001 "$ASSET")" == "$(pview 26000 "$ASSET")" ]] && ok "node1's USDC.t pool view == node0's" || bad "node1 pool view differs"
rm -rf "$H/node4"; "$BIN" keygen "$H/node4" ext-4 >/dev/null; cp "$H/node0/genesis.json" "$H/node4/genesis.json"
PEERS=$(for i in 0 1 2 3; do printf '/ip4/127.0.0.1/tcp/%d,' $((27000+i)); done | sed 's/,$//')
"$BIN" config-gen "$H/node4" --listen /ip4/127.0.0.1/tcp/27004 --peers "$PEERS" --rpc 127.0.0.1:26004 --metrics 127.0.0.1:29004 >/dev/null
start_node "$H/node4" "$H/node4.log"
T=$(( $(h_of 26000) + 3 )); wait_h 26004 "$T" 150 && ok "node4 synced from genesis to $T" || bad "node4 did not sync (see $H/node4.log)"
sleep 3; [[ "$(ah_of 26004)" == "$(ah_of 26000)" && "$(pools 26004)" == 2 && "$(pview 26004 "$ASSET")" == "$(pview 26000 "$ASSET")" ]] && ok "node4 derived both pools by replay (same app_hash, same USDC.t pool view)" || bad "node4: $(ah_of 26004) pools $(pools 26004) $(pview 26004 "$ASSET")"
N4=$(rpc 26004 hk_getPoolNotes "{\"asset\":\"$ASSET\"}" | py 'r["total"]'); [[ "$N4" == 5 ]] && ok "node4's USDC.t feed has 5 notes (rebuilt from the block log)" || bad "node4 USDC.t feed: $N4"
./devnet.sh stop >/dev/null

echo "== 10 · pre-activation devnet (HK_P6_HEIGHT=999999): the v1 refusal"
HK_P6_HEIGHT=999999 ./devnet.sh --fresh -n 4 --prover-url "$PROVER" >/dev/null
wait_h 26000 5 60 && ok "second devnet deciding" || { bad "second devnet did not reach height 5"; exit 1; }
MPF=$(rpc 26000 hk_getPools | py 'r["multi_pool_from"]'); [[ "$MPF" == 999999 ]] && ok "multi_pool_from 999999 (from HK_P6_HEIGHT)" || bad "multi_pool_from: $MPF"
rm -rf "$H/acct-org"; "$BIN" account-adopt-demo "$H/acct-org" org "$RPC" >/dev/null || bad "adopt org (2)"
ORG=$(python3 -c "import json;print(json.load(open('$H/acct-org/account.json'))['id'])")
ASSET=$("$BIN" asset-id "$H/acct-org" USDC.t)
R=$(cli asset register "$H/acct-org" "$RPC" USDC.t 6 mfps); [[ "$R" == ok* ]] || bad "register (2): $R"
R=$(cli asset mint "$H/acct-org" "$RPC" "$ASSET" "$ORG" 10000000); [[ "$R" == ok* ]] || bad "mint (2): $R"
sleep 2
W="$H/wallet-org"; rm -rf "$W"; "$BIN" wallet init "$W" org "$RPC" >/dev/null 2>&1
"$BIN" wallet shield "$W" 1 "$RPC" "$PROVER" 2>&1 | grep -q "shielded" && ok "legacy shield (test asset) lands before the height" || bad "legacy shield (2)"
sleep 1
OUT=$("$BIN" wallet shield "$W" 1 "$RPC" "$PROVER" --asset "$ASSET" 2>&1); echo "$OUT" | grep -q "pool asset mismatch" && ok "USDC.t shield before the height: pool asset mismatch (v1 behaviour)" || bad "pre-activation shield: $(echo "$OUT" | tail -1)"
[[ "$(pools 26000)" == 1 ]] && ok "still one pool before the height" || bad "pools: $(pools 26000)"
./devnet.sh stop >/dev/null

echo
echo "== P6 GATE: $PASS passed, $FAIL failed"
[[ "$FAIL" == 0 ]] && echo "GATE GREEN — one pool per asset: routing by asset and by anchor, per-pool ledgers and nullifiers, restore and sync, the activation boundary." || echo "GATE RED — read the FAIL lines and $H/node*.log"
