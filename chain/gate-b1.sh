#!/usr/bin/env bash
# gate-b1.sh -- the B1 bridge receipt on a local devnet + a local Ethereum (anvil) — WSL/Linux.
#
#   ./gate-b1.sh                        # needs: hk-prove on 127.0.0.1:9911 (real proofs), foundry (anvil/forge/cast),
#                                       #        bridge/contracts/lib populated (bridge/contracts/README.md §1)
#   HK_PROVER_URL=… ./gate-b1.sh
#
# What it proves (each line PASS/FAIL) — docs/BRIDGE-SEPOLIA-USDC-PLAN.md §5 B1.2:
#   1. anvil up; MockUSDC + HKVault + HKWrapped deployed by the Foundry script; attestor funded; EIP-712 domain check passes at
#      service start (the service refuses to start on a mismatch).
#   2. devnet up; org (the bridge issuer) registers USDC.sep (mfps) and HKT (mfps); the service starts against both chains.
#   3. LOCK → MINT: user locks 20 USDC in the vault naming org's account → after the confirmation depth the service mints
#      20 USDC.sep to org (< 2 min); ledger deposit:confirmed; reserves == supply − burned.
#   4. SHIELDED USDC: org shields 2 USDC.sep into its own pool (P6), pays 0.5 shielded to merchant, unshields 1.
#   5. BURN → UNLOCK: org burns 5 USDC.sep with the user's Ethereum address as destination → the vault releases 5 USDC to
#      the user under the attestation; processed[burnId] true; ledger burn:confirmed.
#   6. REPLAY: a service restart re-scans everything and unlocks/mints nothing twice (reserves and balances unchanged).
#   7. KILL -9 MID-FLOW: a deposit whose mint was submitted but never recorded (HK_ATTEST_CRASH=after-submit) is HELD as
#      needs_review after the restart — exactly one mint happened; the operator resolves it with attest-ledger.
#   8. PAUSED VAULT: a burn while the vault is paused is queued_paused; unpause drains it. DAILY CAP: a burn above the
#      remaining cap is queued_cap; raising the cap drains it.
#   9. REVERSE LEG: org burns 4 HKT with the user's address → HKWrapped mints 4 wHKT.sep to the user; the user burns 1 wHKT.sep
#      naming org → the service mints 1 HKT back to org.
#  10. T-OF-N: a second attestor (attest-cosign, its own key, its own HK check) joins; the vault is set to 2-of-2; a burn
#      unlocks with two signatures; the cosigner refuses a digest whose amount does not match the chain.
#  11. UNBRIDGEABLE: a burn with a 3-byte destination is recorded unbridgeable and never attested.
set -uo pipefail
cd "$(dirname "$0")"
H="${HK_DEVNET_HOME:-$HOME/hk-devnet}"
BIN="$(readlink -f "${CARGO_TARGET_DIR:-target}/release/hk-node")"
PROVER="${HK_PROVER_URL:-http://127.0.0.1:9911}"
RPC=http://127.0.0.1:26000
ETH=http://127.0.0.1:8545
CONTRACTS="$(readlink -f ../bridge/contracts)"
# the gate's own scratch dir — OUTSIDE the devnet home, which `devnet.sh --fresh` wipes
B="${HK_B1_DIR:-$HOME/hk-bridge-gate}"; rm -rf "$B"; mkdir -p "$B"
PASS=0; FAIL=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
rpc()  { local p=${3:-}; [[ -z "$p" ]] && p="{}"; curl -s -m 8 -X POST "http://127.0.0.1:$1" -d "{\"method\":\"$2\",\"params\":$p}"; }
py()   { python3 -c "import sys,json;r=json.load(sys.stdin)['result'];print($1)" 2>/dev/null; }
h_of() { rpc "$1" hk_chainInfo | py 'r["height"]' || echo 0; }
wait_h(){ local port=$1 target=$2 tries=${3:-90}; for _ in $(seq "$tries"); do [[ "$(h_of "$port")" -ge "$target" ]] && return 0; sleep 2; done; return 1; }
bal(){ rpc 26000 hk_balance "{\"id\":\"$1\",\"asset\":\"$2\"}" | py 'r["amount"]' || echo "?"; }
smb(){ rpc 26000 hk_getAsset "{\"asset\":\"$1\"}" | py 'int(r["asset"]["supply"])-int(r["asset"]["burned"])' || echo "?"; }
cli(){ "$BIN" "$@" 2>&1 | grep -E "receipt:|Error|error" | head -1 | sed 's/.*receipt: //'; }
health(){ curl -s -m 5 http://127.0.0.1:9933/health; }
hj(){ health | python3 -c "import sys,json;h=json.load(sys.stdin);print($1)" 2>/dev/null; }
count(){ hj "h['counts'].get('$1',0)"; }
wait_count(){ local k=$1 n=$2 tries=${3:-60}; for _ in $(seq "$tries"); do [[ "$(count "$k")" == "$n" ]] && return 0; sleep 2; done; return 1; }
usdc_of(){ cast call "$USDC" "balanceOf(address)(uint256)" "$1" --rpc-url $ETH 2>/dev/null | awk '{print $1}'; }
wrapped_of(){ cast call "$WRAPPED" "balanceOf(address)(uint256)" "$1" --rpc-url $ETH 2>/dev/null | awk '{print $1}'; }
reserves(){ cast call "$VAULT" "reserves()(uint256)" --rpc-url $ETH 2>/dev/null | awk '{print $1}'; }
processed(){ cast call "$VAULT" "processed(bytes32)(bool)" "0x$1" --rpc-url $ETH 2>/dev/null; }
start_svc(){ ( cd "$B" && exec env ETH_RPC_URL=$ETH ETH_ATTESTOR_KEY_FILE="$B/attestor.key" "$@" nohup "$BIN" attest-serve "$B/attest.toml" </dev/null >>"$B/attest.log" 2>&1 ) & sleep 3; }
stop_svc(){ pkill -f "hk-node attest-serve" ; sleep 1; }

for t in anvil forge cast; do command -v $t >/dev/null || { echo "$t not found — install foundry (bridge/contracts/README.md §1)"; exit 1; }; done
[[ -d "$CONTRACTS/lib/openzeppelin-contracts" ]] || { echo "bridge/contracts/lib missing — run the lib block in bridge/contracts/README.md §1"; exit 1; }
curl -s -m 5 -X POST "$PROVER" -d '{"method":"health","params":{}}' | grep -q result || { echo "hk-prove not reachable at $PROVER"; exit 1; }
pkill -f "anvil --port 8545" 2>/dev/null; stop_svc; pkill -f "attest-cosign" 2>/dev/null

# well-known anvil accounts (never real keys): 0 = deployer/owner, 1 = the user
DEPLOYER_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
OWNER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
USER_PK=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
USER=0x70997970C51812dc3A010C7d01b50e0d17dc79C8

echo "== 1 · anvil + contracts"
( anvil --port 8545 --block-time 1 --chain-id 31337 --silent >"$B/anvil.log" 2>&1 & ) ; sleep 3
cast chain-id --rpc-url $ETH 2>/dev/null | grep -q 31337 && ok "anvil up (chain 31337, 1 s blocks)" || { bad "anvil not answering"; exit 1; }
"$BIN" attest-key-new "$B/attestor.key" >"$B/attestor.txt" 2>&1 && ok "attestor key written 0600: $(cat "$B/attestor.txt" | cut -c1-60)" || bad "attest-key-new: $(cat "$B/attestor.txt")"
ATT=$(grep -oE '0x[0-9a-fA-F]{40}' "$B/attestor.txt" | head -1)
"$BIN" attest-key-new "$B/attestor2.key" >"$B/attestor2.txt" 2>&1; ATT2=$(grep -oE '0x[0-9a-fA-F]{40}' "$B/attestor2.txt" | head -1)
HKT_ID_PLACEHOLDER=0x$(printf '%064d' 0)
( cd "$CONTRACTS" && VAULT_TOKEN=mock HK_GENESIS=0x4e4ea68d48cba1ad4cc7155c19e7768f1fa2cbc99ba0f2b47c58948ec9e971c7 ATTESTORS="$ATT" THRESHOLD=1 DAILY_CAP=1000000000 MIN_LOCK=10000 VAULT_OWNER=$OWNER WRAPPED=1 HK_ASSET=$HKT_ID_PLACEHOLDER WRAPPED_CAP=1000000000 \
  forge script script/Deploy.s.sol:Deploy --rpc-url $ETH --private-key $DEPLOYER_PK --broadcast >"$B/deploy.log" 2>&1 )
USDC=$(grep -oE 'MockUSDC: 0x[0-9a-fA-F]{40}' "$B/deploy.log" | awk '{print $2}')
VAULT=$(grep -oE 'HKVault: 0x[0-9a-fA-F]{40}' "$B/deploy.log" | awk '{print $2}')
WRAPPED=$(grep -oE 'wHKT.sep: 0x[0-9a-fA-F]{40}' "$B/deploy.log" | awk '{print $2}')
[[ -n "$USDC" && -n "$VAULT" && -n "$WRAPPED" ]] && ok "deployed MockUSDC $USDC · HKVault $VAULT · HKWrapped $WRAPPED" || { bad "deploy failed (see $B/deploy.log)"; tail -5 "$B/deploy.log"; exit 1; }
DEPLOY_BLOCK=$(cast block-number --rpc-url $ETH); FROM_BLOCK=$(( DEPLOY_BLOCK > 5 ? DEPLOY_BLOCK - 5 : 1 ))
cast send "$ATT" --value 1ether --rpc-url $ETH --private-key $DEPLOYER_PK >/dev/null 2>&1 && cast send "$ATT2" --value 1ether --rpc-url $ETH --private-key $DEPLOYER_PK >/dev/null 2>&1 && ok "attestors funded with 1 ETH each" || bad "fund attestors"
cast send "$USDC" "mint(address,uint256)" $USER 100000000 --rpc-url $ETH --private-key $DEPLOYER_PK >/dev/null 2>&1 && [[ "$(usdc_of $USER)" == 100000000 ]] && ok "user holds 100 mock USDC" || bad "mint mock USDC: $(usdc_of $USER)"

echo "== 2 · devnet + assets + the service"
./devnet.sh --fresh -n 4 --prover-url "$PROVER" >/dev/null
wait_h 26000 5 60 && ok "devnet deciding (height $(h_of 26000))" || { bad "devnet did not reach height 5"; exit 1; }
for name in org merchant; do rm -rf "$H/acct-$name"; "$BIN" account-adopt-demo "$H/acct-$name" "$name" "$RPC" >/dev/null || bad "adopt $name"; done
ORG=$(python3 -c "import json;print(json.load(open('$H/acct-org/account.json'))['id'])")
USDCSEP=$("$BIN" asset-id "$H/acct-org" USDC.sep); HKT=$("$BIN" asset-id "$H/acct-org" HKT)
R=$(cli asset register "$H/acct-org" "$RPC" USDC.sep 6 mfps); [[ "$R" == ok* ]] && ok "org registered USDC.sep (mfps): $USDCSEP" || bad "register USDC.sep: $R"
R=$(cli asset register "$H/acct-org" "$RPC" HKT 6 mfps);      [[ "$R" == ok* ]] && ok "org registered HKT (mfps): $HKT" || bad "register HKT: $R"
R=$(cli asset mint "$H/acct-org" "$RPC" "$HKT" "$ORG" 10000000); [[ "$R" == ok* ]] && ok "org minted 10 HKT to itself (the reverse-leg float)" || bad "mint HKT: $R"
cat > "$B/attest.toml" <<EOF
[hk]
rpc = "$RPC"
issuer_dir = "$H/acct-org"
usdc_asset = "$USDCSEP"
hkt_asset = "$HKT"
from_height = 1
[eth]
chain_id = 31337
vault = "$VAULT"
wrapped = "$WRAPPED"
from_block = $FROM_BLOCK
confirm = "2"
[service]
ledger = "$B/ledger.jsonl"
listen = "127.0.0.1:9933"
poll_secs = 2
reconcile_secs = 5
EOF
start_svc
sleep 4; hj "h['eth']['attestor']" | grep -qi "${ATT#0x}" && ok "service up: /health answers; attestor $ATT; EIP-712 domain matched the vault" || { bad "service did not start: $(tail -3 "$B/attest.log" | tr '\n' ' ')"; }
# the negative: a wrong vault address must refuse to start (domain mismatch)
sed "s/^vault = .*/vault = \"$WRAPPED\"/" "$B/attest.toml" > "$B/attest-wrong.toml"
( cd "$B" && ETH_RPC_URL=$ETH ETH_ATTESTOR_KEY_FILE="$B/attestor.key" timeout 20 "$BIN" attest-serve "$B/attest-wrong.toml" >"$B/wrong.log" 2>&1 ); grep -q "domain mismatch" "$B/wrong.log" && ok "a wrong vault address is refused at start (EIP-712 domain mismatch)" || bad "wrong-vault start: $(tail -2 "$B/wrong.log" | tr '\n' ' ')"

echo "== 3 · lock 20 USDC → mint 20 USDC.sep"
cast send "$USDC" "approve(address,uint256)" "$VAULT" 100000000 --rpc-url $ETH --private-key $USER_PK >/dev/null 2>&1
cast send "$VAULT" "lock(uint256,bytes32)" 20000000 "0x$ORG" --rpc-url $ETH --private-key $USER_PK >/dev/null 2>&1 && ok "user locked 20 USDC for org" || bad "lock"
[[ "$(reserves)" == 20000000 ]] && ok "vault reserves 20,000,000" || bad "reserves: $(reserves)"
wait_count deposit:confirmed 1 60 && ok "deposit confirmed by the service ($(hj "h['loops']") loops)" || bad "deposit not confirmed: $(health | cut -c1-300)"
[[ "$(bal "$ORG" "$USDCSEP")" == 20000000 ]] && ok "org holds 20 USDC.sep on HashKinetics" || bad "org USDC.sep: $(bal "$ORG" "$USDCSEP")"
sleep 6; [[ "$(hj "h['reconciliation']['ok']")" == True && "$(smb "$USDCSEP")" == "$(reserves)" ]] && ok "reconciled: supply − burned == vault reserves ($(reserves))" || bad "reconciliation: $(hj "h['reconciliation']")"

echo "== 4 · shielded USDC.sep (P6 pool): shield 2, pay 0.5 shielded, unshield 1"
W="$H/wallet-org"; rm -rf "$W"; "$BIN" wallet init "$W" org "$RPC" >/dev/null 2>&1
"$BIN" wallet shield "$W" 2 "$RPC" "$PROVER" --asset "$USDCSEP" 2>&1 | grep -q "shielded" && ok "shield 2 USDC.sep" || bad "shield USDC.sep"
W2="$H/wallet-merchant"; rm -rf "$W2"; "$BIN" wallet init "$W2" merchant "$RPC" >/dev/null 2>&1; ADDR=$("$BIN" wallet address "$W2" "$RPC" 2>/dev/null)
"$BIN" wallet pay "$W" "$ADDR" 0.5 "$RPC" "$PROVER" --asset "$USDCSEP" 2>&1 | grep -q "fully shielded" && ok "pay 0.5 USDC.sep shielded to merchant" || bad "shielded pay"
"$BIN" wallet unshield "$W" 1 "$RPC" "$PROVER" --asset "$USDCSEP" 2>&1 | grep -q "unshielded" && ok "unshield 1 USDC.sep" || bad "unshield"
sleep 2; [[ "$(bal "$ORG" "$USDCSEP")" == 19000000 ]] && ok "org transparent USDC.sep 19,000,000 (20 − 2 + 1); 1 stays shielded" || bad "org USDC.sep: $(bal "$ORG" "$USDCSEP")"
sleep 6; [[ "$(hj "h['reconciliation']['ok']")" == True ]] && ok "still reconciled: the pool is inside supply" || bad "reconciliation after shield: $(hj "h['reconciliation']")"

echo "== 5 · burn 5 USDC.sep → unlock 5 USDC to the user"
R=$(cli asset burn "$H/acct-org" "$RPC" "$USDCSEP" 5000000 "${USER#0x}"); [[ "$R" == ok* ]] && ok "org burned 5 USDC.sep → destination $USER" || bad "burn: $R"
wait_count burn:confirmed 1 60 && ok "unlock confirmed by the service" || bad "burn not confirmed: $(health | cut -c1-400)"
[[ "$(usdc_of $USER)" == 85000000 ]] && ok "user USDC 85,000,000 (100 − 20 + 5)" || bad "user USDC: $(usdc_of $USER)"
BURN_ID=$("$BIN" attest-ledger "$B/ledger.jsonl" list confirmed 2>/dev/null | python3 -c "import sys,json;[print(json.loads(l)['id']) for l in sys.stdin if l.startswith('{') and json.loads(l)['kind']=='burn']" | head -1)
[[ "$(processed "$BURN_ID")" == true ]] && ok "vault.processed[burnId] true" || bad "processed: $(processed "$BURN_ID")"
[[ "$(reserves)" == 15000000 ]] && ok "reserves 15,000,000 == supply − burned $(smb "$USDCSEP")" || bad "reserves $(reserves) vs $(smb "$USDCSEP")"

echo "== 6 · restart: nothing happens twice"
stop_svc; start_svc; sleep 8
[[ "$(reserves)" == 15000000 && "$(bal "$ORG" "$USDCSEP")" == 14000000 && "$(count deposit:confirmed)" == 1 && "$(count burn:confirmed)" == 1 ]] && ok "after a restart: same reserves, same balances, same counts (ledger replayed, cursors kept)" || bad "restart changed something: reserves $(reserves) org $(bal "$ORG" "$USDCSEP") counts $(hj "h['counts']")"

echo "== 7 · kill -9 between submit and record: held, never re-minted"
stop_svc; start_svc HK_ATTEST_CRASH=after-submit
cast send "$VAULT" "lock(uint256,bytes32)" 3000000 "0x$ORG" --rpc-url $ETH --private-key $USER_PK >/dev/null 2>&1 && ok "user locked 3 USDC (the service will crash right after submitting the mint)" || bad "lock 3"
for _ in $(seq 40); do pgrep -f "hk-node attest-serve" >/dev/null || break; sleep 1; done
pgrep -f "hk-node attest-serve" >/dev/null && bad "service did not crash on the hook" || ok "service exited after the submit (exit 9)"
sleep 3; start_svc; sleep 8
[[ "$(count deposit:submitting)" == 1 && "$(hj "len(h['needs_review'])")" == 1 && "$(hj "h['ok']")" == False ]] && ok "the deposit is held in 'submitting' (no txid recorded): 1 needs_review item on /health, ok=false" || bad "counts: $(hj "h['counts']") needs_review $(hj "len(h['needs_review'])") ok $(hj "h['ok']")"
[[ "$(bal "$ORG" "$USDCSEP")" == 17000000 ]] && ok "org USDC.sep 17,000,000 — the mint happened exactly ONCE" || bad "org USDC.sep: $(bal "$ORG" "$USDCSEP")"
DEP_ID=$("$BIN" attest-ledger "$B/ledger.jsonl" list submitting 2>/dev/null | python3 -c "import sys,json;[print(json.loads(l)['id']) for l in sys.stdin if l.startswith('{')]" | head -1)
MINT_TXID=$(rpc 26000 hk_getAccountTxs "{\"id\":\"$ORG\",\"limit\":5}" | python3 -c "import sys,json;r=json.load(sys.stdin)['result'];print([t['txid'] for t in r['txs'] if t['kind']=='asset_mint'][0])")
"$BIN" attest-ledger "$B/ledger.jsonl" resolve deposit "$DEP_ID" confirmed --hk-txid "$MINT_TXID" >/dev/null 2>&1 && ok "operator resolved it: deposit → confirmed with the mint's txid" || bad "resolve"
stop_svc; start_svc; sleep 6; [[ "$(count deposit:confirmed)" == 2 && "$(hj "h['ok']")" == True ]] && ok "/health ok again after the resolution (2 deposits confirmed)" || bad "health: $(health | cut -c1-300)"

echo "== 8 · paused vault queues; daily cap queues"
cast send "$VAULT" "pause()" --rpc-url $ETH --private-key $DEPLOYER_PK >/dev/null 2>&1
R=$(cli asset burn "$H/acct-org" "$RPC" "$USDCSEP" 1000000 "${USER#0x}"); [[ "$R" == ok* ]] || bad "burn while paused: $R"
wait_count burn:queued_paused 1 30 && ok "burn while paused → queued_paused" || bad "expected queued_paused: $(hj "h['counts']")"
cast send "$VAULT" "unpause()" --rpc-url $ETH --private-key $DEPLOYER_PK >/dev/null 2>&1
wait_count burn:confirmed 2 60 && ok "unpause drained the queue (2 burns confirmed)" || bad "not drained: $(hj "h['counts']")"
cast send "$VAULT" "setDailyCap(uint256)" 1000000 --rpc-url $ETH --private-key $DEPLOYER_PK >/dev/null 2>&1
R=$(cli asset burn "$H/acct-org" "$RPC" "$USDCSEP" 2000000 "${USER#0x}"); [[ "$R" == ok* ]] || bad "burn over cap: $R"
wait_count burn:queued_cap 1 30 && ok "burn above the remaining cap → queued_cap" || bad "expected queued_cap: $(hj "h['counts']")"
cast send "$VAULT" "setDailyCap(uint256)" 1000000000 --rpc-url $ETH --private-key $DEPLOYER_PK >/dev/null 2>&1
wait_count burn:confirmed 3 60 && ok "raising the cap drained it (3 burns confirmed)" || bad "not drained: $(hj "h['counts']")"
[[ "$(usdc_of $USER)" == 85000000 ]] && ok "user USDC 85,000,000 (85 − 3 locked in step 7 + 1 + 2)" || bad "user USDC: $(usdc_of $USER)"

echo "== 9 · reverse leg: HKT → wHKT.sep → HKT"
R=$(cli asset burn "$H/acct-org" "$RPC" "$HKT" 4000000 "${USER#0x}"); [[ "$R" == ok* ]] && ok "org locked (burned) 4 HKT → destination $USER" || bad "burn HKT: $R"
wait_count wlock:confirmed 1 60 && ok "HKWrapped.mint confirmed" || bad "wlock not confirmed: $(hj "h['counts']")"
[[ "$(wrapped_of $USER)" == 4000000 ]] && ok "user holds 4 wHKT.sep on Ethereum" || bad "wHKT.sep: $(wrapped_of $USER)"
cast send "$WRAPPED" "burn(uint256,bytes32)" 1000000 "0x$ORG" --rpc-url $ETH --private-key $USER_PK >/dev/null 2>&1 && ok "user burned 1 wHKT.sep naming org" || bad "wrapped burn"
wait_count wburn:confirmed 1 60 && ok "the service minted 1 HKT back on HashKinetics" || bad "wburn not confirmed: $(hj "h['counts']")"
[[ "$(bal "$ORG" "$HKT")" == 7000000 ]] && ok "org HKT 7,000,000 (10 − 4 + 1)" || bad "org HKT: $(bal "$ORG" "$HKT")"

echo "== 10 · a second attestor: 2-of-2"
cat > "$B/cosign.toml" <<EOF
listen = "127.0.0.1:9934"
[hk]
rpc = "http://127.0.0.1:26001"
usdc_asset = "$USDCSEP"
hkt_asset = "$HKT"
[eth]
chain_id = 31337
vault = "$VAULT"
wrapped = "$WRAPPED"
wrapped_name = "Wrapped HashKinetics Test (Sepolia)"
EOF
( cd "$B" && exec env ETH_ATTESTOR_KEY_FILE="$B/attestor2.key" nohup "$BIN" attest-cosign "$B/cosign.toml" </dev/null >>"$B/cosign.log" 2>&1 ) & sleep 2
cast send "$VAULT" "setAttestors(address[],uint256)" "[$ATT,$ATT2]" 2 --rpc-url $ETH --private-key $DEPLOYER_PK >/dev/null 2>&1 && ok "vault attestors = [primary, cosigner], threshold 2" || bad "setAttestors"
stop_svc; sed -i "s|^confirm = .*|confirm = \"2\"\ncosigners = [\"http://127.0.0.1:9934\"]|" "$B/attest.toml"; start_svc; sleep 3
R=$(cli asset burn "$H/acct-org" "$RPC" "$USDCSEP" 1000000 "${USER#0x}"); [[ "$R" == ok* ]] || bad "burn for 2-of-2: $R"
wait_count burn:confirmed 4 60 && ok "unlock under TWO signatures (primary + cosigner, each checked the burn on its own node)" || bad "2-of-2 unlock: $(hj "h['counts']") $(tail -3 "$B/attest.log" | tr '\n' ' ')"
[[ "$(usdc_of $USER)" == 86000000 ]] && ok "user USDC 86,000,000 (85 + 1 under two signatures)" || bad "user USDC: $(usdc_of $USER)"
LAST_BURN=$("$BIN" attest-ledger "$B/ledger.jsonl" list confirmed 2>/dev/null | python3 -c "import sys,json;print([json.loads(l)['id'] for l in sys.stdin if l.startswith('{') and json.loads(l)['kind']=='burn'][-1])")
CO=$(curl -s -m 10 -X POST http://127.0.0.1:9934/sign -d "{\"kind\":\"burn\",\"to\":\"$USER\",\"amount\":\"999999\",\"id\":\"$LAST_BURN\"}")
echo "$CO" | grep -q "amount mismatch" && ok "cosigner refuses an amount the chain does not say: $(echo "$CO" | cut -c1-60)" || bad "cosigner accepted a wrong amount: $CO"

echo "== 11 · an unbridgeable burn"
R=$(cli asset burn "$H/acct-org" "$RPC" "$USDCSEP" 1000000 "aabbcc"); [[ "$R" == ok* ]] || bad "burn 3-byte dest: $R"
wait_count burn:unbridgeable 1 30 && ok "3-byte destination → unbridgeable (never attested; an issuer decision)" || bad "expected unbridgeable: $(hj "h['counts']")"
sleep 6; [[ "$(hj "h['reconciliation']['ok']")" == True && "$(reserves)" == 14000000 ]] && ok "final reconciliation ok: reserves $(reserves) == supply − burned $(smb "$USDCSEP") + the 1,000,000 unbridgeable burn still backed in the vault (23 locked − 9 released)" || bad "final reconciliation: $(hj "h['reconciliation']") reserves $(reserves)"

stop_svc; pkill -f "attest-cosign"; pkill -f "anvil --port 8545"; ./devnet.sh stop >/dev/null
echo; echo "== B1 GATE: $PASS passed, $FAIL failed"
[[ "$FAIL" == 0 ]] && echo "GATE GREEN" || echo "GATE RED"
