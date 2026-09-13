#!/usr/bin/env bash
# gate-p6-2.sh -- the P6.2 receipt: TEST USDC FOR PEOPLE WHO ARE NOT DEVELOPERS. The wallet CORE
# (hk-wallet-core v0.2.0 — what the Windows wallet and the Android app are thin shells over) takes an
# issued asset through the whole journey against a devnet, a faucet that drips that asset, and a prover:
#
#   ./gate-p6-2.sh                       # needs hk-prove on 127.0.0.1:9911 (mint/spend proofs)
#   HK_PROVER_URL=… ./gate-p6-2.sh
#
# What it proves (each line is a PASS/FAIL):
#   1. the crate's unit tests, including the shield.json shape (legacy `scan` + per-asset `pools`) and
#      the rule that the native pool is addressed by OMITTING `asset`;
#   2. on a fresh devnet `org` registers USDC.t (pool-eligible) and mints a FLOAT to the faucet account —
#      the faucet drips it with `--drip-asset` and reports it on /health.assets[]; a drip of an asset the
#      faucet does not serve is refused; the asset drip for an account that does not exist is refused;
#   3. the ignored asset journey: a NEW wallet asks for the asset drip (the core takes the native drip
#      first, then the asset), sees both balances, sends the asset (fee in the native unit), shields it
#      into ITS OWN pool (the native pool stays empty), unshields part, pays the rest shielded with a memo,
#      discloses the payment (the package names its pool), and the notes never leak across pools;
#   4. the CLI wallet reads the same USDC.t pool the core wrote (P6 `--asset`): one implementation of
#      the pool rules, two front ends.
set -uo pipefail
cd "$(dirname "$0")"
H="${HK_DEVNET_HOME:-$HOME/hk-devnet}"
TARGET="${CARGO_TARGET_DIR:-target}"
BIN="$(readlink -f "$TARGET/release/hk-node")"
PROVER="${HK_PROVER_URL:-http://127.0.0.1:9911}"
FAUCET=127.0.0.1:9933
RPC=http://127.0.0.1:26000
PASS=0; FAIL=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
rpc()  { local p=${3:-}; [[ -z "$p" ]] && p="{}"; curl -s -m 8 -X POST "http://127.0.0.1:$1" -d "{\"method\":\"$2\",\"params\":$p}"; }
py()   { python3 -c "import sys,json;r=json.load(sys.stdin)['result'];print($1)" 2>/dev/null; }
h_of() { rpc "$1" hk_chainInfo | py 'r["height"]' || echo 0; }
wait_h(){ local port=$1 target=$2 tries=${3:-90}; for _ in $(seq "$tries"); do [[ "$(h_of "$port")" -ge "$target" ]] && return 0; sleep 2; done; return 1; }
bal(){ rpc "$1" hk_balance "{\"id\":\"$2\",\"asset\":\"$3\"}" | py 'r["amount"]' || echo "?"; }
pview(){ rpc "$1" hk_getPoolInfo "{\"asset\":\"$2\"}" | py 'str(r.get("asset"))[:8], r["next_index"], r["nullifiers"], r["total_shielded"], r["legacy"]' || echo "?"; }
lview(){ rpc "$1" hk_getPoolInfo | py 'str(r.get("asset"))[:8], r["next_index"], r["nullifiers"], r["total_shielded"], r["legacy"]' || echo "?"; }
cli(){ "$BIN" "$@" 2>&1 | grep -E "receipt:|Error|error" | head -1 | sed 's/.*receipt: //'; }

echo "== 1 · unit tests (no network)"
OUT=$(cargo test --release -p hk-wallet-core 2>&1); RC=$?
LINE=$(echo "$OUT" | grep -E "^test result" | head -1)
[[ $RC -eq 0 ]] && echo "$LINE" | grep -qE "ok\. [1-9][0-9]* passed" && ok "hk-wallet-core unit tests: $LINE" || { bad "unit tests: $(echo "$OUT" | grep -E "FAILED|panicked|error" | head -3)"; }
echo "$OUT" | grep -q "p62_shield_file_keeps_the_legacy_shape_and_adds_pools ... ok" && ok "shield.json: legacy scan + per-asset pools, round trip" || bad "shield.json shape test missing"
echo "$OUT" | grep -q "p62_native_pool_is_addressed_without_an_asset_parameter ... ok" && ok "native pool addressed by omitting asset" || bad "native-pool addressing test missing"

echo "== 2 · devnet · USDC.t registered · a FLOAT minted to the faucet account · faucet drips it"
curl -s -m 5 -X POST "$PROVER" -d '{"method":"health","params":{}}' | grep -q result || { echo "hk-prove not reachable at $PROVER"; exit 1; }
./devnet.sh --fresh -n 4 --prover-url "$PROVER" >/dev/null
wait_h 26000 5 60 && ok "devnet deciding (height $(h_of 26000))" || { bad "devnet did not reach height 5"; exit 1; }
USD=$(python3 -c 'print("09"*32)')
rm -rf "$H/acct-org"; "$BIN" account-adopt-demo "$H/acct-org" org "$RPC" >/dev/null || bad "adopt org"
ORG=$(python3 -c "import json;print(json.load(open('$H/acct-org/account.json'))['id'])")
ASSET=$("$BIN" asset-id "$H/acct-org" USDC.t)
EUR=$("$BIN" asset-id "$H/acct-org" EUR.t)
R=$(cli asset register "$H/acct-org" "$RPC" USDC.t 6 mfps); [[ "$R" == ok* ]] && ok "register USDC.t (pool-eligible): $R" || bad "register USDC.t: $R"
R=$(cli asset register "$H/acct-org" "$RPC" EUR.t 6 mfp);   [[ "$R" == ok* ]] && ok "register EUR.t (not served by the faucet): $R" || bad "register EUR.t: $R"
# The faucet is a SECOND demo account (agent-a) so the issuer and the faucet are distinct — on testnet-1
# the float arrives by the bridge (a founder lock naming the faucet account), here the issuer mints it.
FW="$H/wallet-faucet-p62"; rm -rf "$FW"
"$BIN" account-adopt-demo "$FW" agent-a "$RPC" >/dev/null 2>&1 && ok "faucet wallet: demo account agent-a adopted" || bad "could not adopt agent-a"
FID=$(python3 -c "import json;print(json.load(open('$FW/account.json'))['id'])")
# agent-a holds no native units at genesis: the faucet pays every drip's fee and the native drip itself
# from its native balance, so org funds it first (on testnet-1 the hot wallet is refilled from the cold treasury).
OUT=$("$BIN" account-send "$H/acct-org" "$RPC" "$FID" 20000000 2>&1 </dev/null); RC=$?
[[ $RC -eq 0 ]] && echo "$OUT" | grep -q "receipt: " && ! echo "$OUT" | grep -q rejected && ok "faucet account funded with 20 native units from org (org holds 50 on a devnet)" || bad "fund faucet: rc=$RC ${OUT: -160}"
R=$(cli asset mint "$H/acct-org" "$RPC" "$ASSET" "$FID" 50000000); [[ "$R" == ok* ]] && ok "float: 50 USDC.t minted to the faucet account" || bad "mint float: $R"
sleep 2
[[ "$(bal 26000 "$FID" "$ASSET")" == 50000000 ]] && ok "faucet holds 50 USDC.t" || bad "faucet USDC.t balance: $(bal 26000 "$FID" "$ASSET")"
[[ "$(bal 26000 "$FID" "$USD")" == 20000000 ]] && ok "faucet holds 20 native units" || bad "faucet native balance: $(bal 26000 "$FID" "$USD")"
# testnet-1's legacy pool has been PINNED to the test unit since P6 activated; a fresh devnet's is
# unpinned and the first shield on the chain pins it — so org shields one test unit first, exactly
# like gate-p6 does, or the asset journey's USDC.t shield would pin the legacy pool to USDC.t.
W="$H/wallet-p62-cli"; rm -rf "$W"
OUT=$("$BIN" wallet init "$W" "$H/acct-org" "$RPC" 2>&1); echo "$OUT" | grep -qiE "wallet|init" && ok "CLI wallet bound to org" || bad "wallet init: ${OUT: -120}"
"$BIN" wallet shield "$W" 1 "$RPC" "$PROVER" 2>&1 | grep -q "shielded" && ok "org shielded 1 test unit → the legacy pool is pinned to the native asset (as on testnet-1)" || bad "org's native shield"
L=$(lview 26000); [[ "$L" == "09090909 1 0 1000000 True" ]] && ok "legacy pool: pinned to 0909…, 1 leaf: $L" || bad "legacy pool after org's shield: $L"
pkill -f "faucet-serve $FW" 2>/dev/null; sleep 1
( cd "$H" && exec nohup "$BIN" faucet-serve "$FW" "$RPC" --listen $FAUCET --drip 100000 --drip-asset "$ASSET:5000000" --cooldown-secs 0 </dev/null >"$H/faucet-p62.log" 2>&1 ) &
sleep 3
HJ=$(curl -s -m 5 "http://$FAUCET/health")
echo "$HJ" | grep -q '"ok"' && ok "faucet up on $FAUCET (native drip 100000 · USDC.t drip 5000000)" || bad "faucet health: ${HJ:0:200}"
echo "$HJ" | python3 -c "import sys,json;h=json.load(sys.stdin);a=h['assets'][0];assert a['asset']=='$ASSET' and int(a['drips_left'])==10 and a['low']==False;print('  /health.assets[0]: drips_left',a['drips_left'],'low',a['low'])" 2>/dev/null && ok "/health.assets[] reports the USDC.t float (10 drips left)" || bad "/health.assets[]: $(echo "$HJ" | head -c 300)"
# refusals: an asset the faucet does not serve; an asset drip for an account that does not exist
NEW_AUTH=$(python3 -c 'import os;print(os.urandom(32).hex())')
R=$(curl -s -m 10 -X POST "http://$FAUCET/drip" -d "{\"account\":\"$ORG\",\"asset\":\"$EUR\"}")
echo "$R" | grep -q "does not drip that asset" && ok "drip of EUR.t (not served) refused: $(echo "$R" | head -c 80)" || bad "EUR.t drip: $R"
R=$(curl -s -m 10 -X POST "http://$FAUCET/drip" -d "{\"auth_commit\":\"$NEW_AUTH\",\"asset\":\"$ASSET\"}")
echo "$R" | grep -q "take the native drip first" && ok "asset drip for a non-existent account refused (native drip creates it)" || bad "asset drip on new account: $R"

echo "== 3 · the asset journey (ignored test, driven by the env) — the core against the devnet"
OUT=$(HK_CORE_RPC="$RPC" HK_CORE_FAUCET="http://$FAUCET" HK_CORE_PROVER="$PROVER" HK_CORE_ASSET="$ASSET" \
      cargo test --release -p hk-wallet-core -- --ignored p62_devnet_asset_journey --nocapture 2>&1); RC=$?
echo "$OUT" | grep -E "^\s+\[(ok|info|error)\]" | sed 's/^/     /' | head -40
if [[ $RC -eq 0 ]] && echo "$OUT" | grep -qE "test result: ok\. 1 passed"; then ok "asset journey: faucet (native, then USDC.t) → send → shield → scan → unshield → pay → disclose, notes isolated per pool"; else bad "asset journey failed: $(echo "$OUT" | grep -A3 -E "panicked|assertion" | head -8 | tr '\n' ' ' | cut -c1-600)"; fi
echo "$OUT" | grep -q "taking the native drip first" && ok "a new wallet asking for USDC.t took the native drip first (the account has to exist)" || bad "no native-first line"
echo "$OUT" | grep -q "Faucet dripped 5000000 base units of USDC.t" && ok "USDC.t drip landed (5,000,000 base units)" || bad "no USDC.t drip line"
echo "$OUT" | grep -q "Paid 0.001000 USDC.t" && ok "transparent USDC.t send committed (fee in the native unit)" || bad "no USDC.t send receipt"
echo "$OUT" | grep -q "Shielded 0.050000 USDC.t" && ok "shield into the USDC.t pool committed" || bad "no USDC.t shield receipt"
echo "$OUT" | grep -q "Unshielded 0.020000 USDC.t" && ok "unshield from the USDC.t pool committed (change back into hiding)" || bad "no USDC.t unshield receipt"
echo "$OUT" | grep -q "Paid 0.010000 USDC.t shielded" && ok "shielded USDC.t payment committed" || bad "no shielded USDC.t pay receipt"
echo "$OUT" | grep -q "Disclosure package written" && ok "disclosure package written (names its pool)" || bad "no disclosure package"
P=$(pview 26000 "$ASSET"); [[ "$P" == "${ASSET:0:8} "* && "$P" == *" False" ]] && ok "the USDC.t pool is its OWN pool on the chain (not legacy): $P" || bad "USDC.t pool: $P"
L=$(lview 26000); [[ "$L" == "09090909 1 0 1000000 True" ]] && ok "the legacy (native) pool is untouched by the USDC.t journey: $L" || bad "legacy pool touched: $L"
[[ "$(bal 26000 "$FID" "$ASSET")" == 45000000 ]] && ok "the faucet float is down by exactly one drip (45 USDC.t)" || bad "faucet float: $(bal 26000 "$FID" "$ASSET")"

echo "== 4 · the CLI wallet reads the pool the core wrote (P6 --asset)"
SC=$("$BIN" wallet scan "$W" "$RPC" --asset "$ASSET" 2>&1)
echo "$SC" | grep -qiE "pool|note" && ok "CLI scan --asset USDC.t reads the same pool (no notes of org's, as expected): $(echo "$SC" | tail -1 | cut -c1-80)" || bad "CLI scan: $(echo "$SC" | tail -2 | tr '\n' ' ')"
N=$(rpc 26000 hk_getPoolNotes "{\"asset\":\"$ASSET\",\"from\":0,\"limit\":100}" | py 'r["total"]')
[[ "$N" -ge 4 ]] && ok "USDC.t pool carries the core's commitments (total $N)" || bad "USDC.t pool total: $N"

pkill -f "faucet-serve $FW" 2>/dev/null
echo
echo "== gate-p6-2: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && echo "GATE GREEN — a non-developer's wallet can take test USDC from the faucet, send it, shield it, pay it privately and unshield it; the float came from the issuer here and from the bridge on testnet-1." || echo "GATE RED — read the FAIL lines, $H/faucet-p62.log and the journey output above"
