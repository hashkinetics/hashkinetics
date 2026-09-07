#!/usr/bin/env bash
# gate-wa1.sh -- the WA1 receipt: the wallet CORE (hk-wallet-core, the library behind the Android app)
# runs the whole journey against a local devnet + faucet + prover, and the files it writes open with
# the CLI — byte-compatible with the desktop wallet and `hk-node account-*`.
#
#   ./gate-wa1.sh                       # needs hk-prove on 127.0.0.1:9911 (mint/spend proofs)
#   HK_PROVER_URL=… ./gate-wa1.sh
#
# What it proves (each line is a PASS/FAIL):
#   1. the crate's unit tests (keychain, sealing with the mobile KDF profile + key file, amounts, endpoints);
#   2. on a fresh 4-node devnet with a faucet (adopted demo account, cooldown 0) the ignored journey test:
#      create → faucet creates+funds → transparent send → shield → scan → unshield (change) → shielded pay
#      with a memo → disclose → protect (sealed files) → lock → unlock → send from the sealed files;
#   3. the directory the core left behind opens with the CLI: `account-info` reads the SEALED account.json
#      with the passphrase (K1 envelope compatibility), refuses without it; `hk-node verify-disclosure`
#      verifies the disclosure package the core wrote (P2.2 format compatibility);
#   4. the cdylib exists (libhk_wallet_core.so) and carries the UniFFI metadata the Kotlin bindgen reads.
set -uo pipefail
cd "$(dirname "$0")"
H="${HK_DEVNET_HOME:-$HOME/hk-devnet}"
TARGET="${CARGO_TARGET_DIR:-target}"
BIN="$(readlink -f "$TARGET/release/hk-node")"
PROVER="${HK_PROVER_URL:-http://127.0.0.1:9911}"
FAUCET=127.0.0.1:9932
PASS=0; FAIL=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
rpc()  { curl -s -m 5 -X POST "http://127.0.0.1:$1" -d "{\"method\":\"$2\",\"params\":${3:-{\}}}"; }
h_of() { rpc "$1" hk_chainInfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["height"])' 2>/dev/null || echo 0; }
wait_h(){ local port=$1 target=$2 tries=${3:-60}; for _ in $(seq "$tries"); do [[ "$(h_of "$port")" -ge "$target" ]] && return 0; sleep 2; done; return 1; }

echo "== 1 · unit tests (no network)"
OUT=$(cargo test --release -p hk-wallet-core 2>&1); RC=$?
LINE=$(echo "$OUT" | grep -E "^test result" | head -1)
[[ $RC -eq 0 ]] && echo "$LINE" | grep -qE "ok\. [1-9][0-9]* passed" && ok "hk-wallet-core unit tests: $LINE" || { bad "unit tests: $(echo "$OUT" | grep -E "FAILED|panicked|error" | head -3)"; }

echo "== 2 · devnet + faucet + prover"
curl -s -m 5 -X POST "$PROVER" -d '{"method":"health","params":{}}' | grep -q result || { echo "hk-prove not reachable at $PROVER"; exit 1; }
./devnet.sh --fresh -n 4 --prover-url "$PROVER" >/dev/null
wait_h 26000 5 60 && ok "devnet deciding (height $(h_of 26000))" || { bad "devnet did not reach height 5"; exit 1; }
FW="$H/wallet-faucet"; rm -rf "$FW"
"$BIN" account-adopt-demo "$FW" org http://127.0.0.1:26000 >/dev/null 2>&1 && ok "faucet wallet: the funded demo account adopted" || bad "could not adopt the demo account"
pkill -f "faucet-serve $FW" 2>/dev/null; sleep 1
( cd "$H" && exec nohup "$BIN" faucet-serve "$FW" http://127.0.0.1:26000 --listen $FAUCET --drip 100000 --cooldown-secs 0 </dev/null >"$H/faucet-wa1.log" 2>&1 ) &
sleep 3
curl -s -m 5 "http://$FAUCET/health" | grep -q '"ok"' && ok "faucet up on $FAUCET (drip 100000, no cooldown)" || bad "faucet health: $(curl -s -m 5 http://$FAUCET/health | head -c 200)"

echo "== 3 · the journey (ignored test, driven by the env) — the core against the devnet"
CORE_DIR="$H/wallet-core"; rm -rf "$CORE_DIR"
OUT=$(HK_CORE_RPC=http://127.0.0.1:26000 HK_CORE_FAUCET="http://$FAUCET" HK_CORE_PROVER="$PROVER" HK_CORE_DIR="$CORE_DIR" \
      cargo test --release -p hk-wallet-core -- --ignored wa1_devnet_journey --nocapture 2>&1); RC=$?
echo "$OUT" | grep -E "^\s+\[(ok|info|error)\]" | sed 's/^/     /' | head -40
if [[ $RC -eq 0 ]] && echo "$OUT" | grep -qE "test result: ok\. 1 passed"; then ok "journey: create → faucet → send → shield → scan → unshield → pay → disclose → protect/lock/unlock → send"; else bad "journey failed: $(echo "$OUT" | grep -E "panicked|FAILED|assertion|Error" | head -4)"; fi
echo "$OUT" | grep -q "Shielded 0.050000" && ok "shield committed with a receipt" || bad "no shield receipt in the log"
echo "$OUT" | grep -q "Unshielded 0.020000" && ok "unshield committed (change back into hiding)" || bad "no unshield receipt"
echo "$OUT" | grep -q "Paid 0.010000 shielded" && ok "shielded payment committed" || bad "no shielded-pay receipt"
echo "$OUT" | grep -q "Disclosure package written" && ok "disclosure package written by the core" || bad "no disclosure package"
echo "$OUT" | grep -q "Protected: 2 file(s) sealed" && ok "protect sealed both files (account.json + shield.json)" || bad "protect did not seal 2 files"

echo "== 4 · byte-compatibility: the CLI opens what the phone core wrote"
PF="$CORE_DIR/.gate-passphrase"
[[ -s "$PF" ]] && ok "core left its passphrase for the gate" || bad "no .gate-passphrase in $CORE_DIR"
python3 -c "import json;e=json.load(open('$CORE_DIR/account.json'));assert e['hke']==1 and e['kdf']=='argon2id';print('  envelope: m_kib',e['m_kib'],'t',e['t'],'p',e['p'])" 2>/dev/null && ok "account.json is an HKE1 envelope (the CLI's format)" || bad "account.json is not an HKE1 envelope"
OUT=$("$BIN" account-info "$CORE_DIR" 2>&1 </dev/null); RC=$?
[[ $RC -ne 0 ]] && echo "$OUT" | grep -q "this file is sealed" && ok "CLI without the passphrase refuses the core's sealed file" || bad "account-info without passphrase: rc=$RC ${OUT: -120}"
OUT=$(HK_WALLET_PASSPHRASE_FILE="$PF" "$BIN" account-info "$CORE_DIR" 2>&1 </dev/null)
echo "$OUT" | grep -q "^account id" && ok "CLI opens the core's sealed account.json with the passphrase file" || bad "account-info with passphrase: ${OUT: -160}"
NN=$(echo "$OUT" | awk '/next nonce/{print $4}')
[[ -n "$NN" && "$NN" -ge 5 ]] && ok "next nonce read back by the CLI: $NN (the core's reserve-then-sign counter)" || bad "next nonce from the CLI: '$NN'"
ID_CLI=$(echo "$OUT" | awk '/account id/{print $4}')
OUT=$(HK_WALLET_PASSPHRASE_FILE="$PF" "$BIN" account-send "$CORE_DIR" http://127.0.0.1:26000 "$ID_CLI" 1000 2>&1 </dev/null); RC=$?
[[ $RC -eq 0 ]] && echo "$OUT" | grep -q "receipt: " && ! echo "$OUT" | grep -q "rejected" && ok "CLI account-send from the core's directory accepted on-chain (same key, same ratchet)" || bad "CLI send from the core dir: rc=$RC ${OUT: -160}"
PKG=$(ls "$CORE_DIR"/disclosure-*.json 2>/dev/null | head -1)
[[ -n "$PKG" ]] && "$BIN" verify-disclosure "$PKG" 2>&1 | grep -qiE "verif|ok|value" && ok "CLI verify-disclosure accepts the core's package ($(basename "$PKG"))" || bad "verify-disclosure on the core's package failed"
SH=$(python3 -c "import json;e=json.load(open('$CORE_DIR/shield.json'));print('sealed' if 'hke' in e else 'plain')" 2>/dev/null)
[[ "$SH" == "sealed" ]] && ok "shield.json sealed under the same passphrase" || bad "shield.json: $SH"

echo "== 5 · the library artifact (what the Android app loads through JNA)"
SO="$TARGET/release/libhk_wallet_core.so"
[[ -f "$SO" ]] && ok "cdylib built: $SO ($(du -h "$SO" | cut -f1))" || bad "no $SO — is [lib] crate-type cdylib?"
# binary-safe grep (no binutils needed): the metadata statics are UNIFFI_META_*, the FFI entry points uniffi_hk_wallet_core_*
[[ -f "$SO" ]] && grep -a -q "UNIFFI_META" "$SO" && ok "UniFFI metadata present in the cdylib (bindgen --library reads it)" || bad "no UniFFI metadata symbols in the cdylib"
[[ -f "$SO" ]] && grep -a -q "uniffi_hk_wallet_core" "$SO" && ok "namespace hk_wallet_core exported ($(grep -a -o 'uniffi_hk_wallet_core_fn_method_wallet_[a-z_]*' "$SO" | sort -u | wc -l) wallet methods)" || bad "namespace symbol missing"

pkill -f "faucet-serve $FW" 2>/dev/null
echo
echo "== gate-wa1: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && echo "GATE GREEN — the wallet core runs the whole journey and its files open with the CLI; the cdylib carries the UniFFI surface." || echo "GATE RED — read the FAIL lines, $H/faucet-wa1.log and the journey output above"
