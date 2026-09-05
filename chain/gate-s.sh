#!/usr/bin/env bash
# gate-s.sh -- the S+K receipt (v0.16.0): storage knobs and keys at rest, measured on a devnet.
#
#   ./gate-s.sh            # needs hk-prove on 127.0.0.1:9911 (vk pins), like gate-n1.sh
#   ./gate-s.sh --long     # + waits ~25 min for the first 1,024-block segment to be compacted
#
# What it proves (each line is a PASS/FAIL):
#   1. S2/S3: with HK_KEEP_PREV_SNAPSHOT=1 and HK_INDEX_PERSIST_EVERY=8 a validator writes
#      index3.bin and snapshot3.prev.bin; hk_chainInfo.history.retain_blocks is null (archive);
#      a restart logs "search index restored from disk (S2)" and RESTORE COMPLETE, keeps deciding.
#   2. C2.8 reporting: an observer started with HK_RETAIN_BLOCKS=64 reports retain_blocks=64.
#   3. K2: a WEAK passphrase is refused before anything is written; `key-seal` turns
#      priv_validator_key.json into an HKE1 envelope (argon2id params in the envelope); `start` without a
#      passphrase refuses ("this file is sealed"); with HK_KEY_PASSPHRASE_FILE it starts AND
#      VOTES (signer.remaining falls while height rises); issue-rotation reads the sealed key;
#      a wrong passphrase is a clean error; key-unseal restores plaintext (on a copy).
#   4. K1: `account-seal` seals account.json; account-info without a passphrase (no TTY)
#      refuses; with HK_WALLET_PASSPHRASE it reads; account-send from the sealed directory is
#      accepted on-chain and the file is STILL sealed afterwards (reserve-then-sign re-sealed it,
#      same salt — the cached key, no second KDF run); a key-file second factor (`keyfile-new`,
#      HK_WALLET_KEYFILE) makes a copied file unopenable with the passphrase alone.
#   5. K3: faucet-serve on the sealed directory (passphrase from the environment): /health
#      carries low/low_watermark_micro/reserve_micro/drips_left; with an absurd reserve the
#      faucet answers 503 and burns no nonce; with the default reserve it drips (200).
#   6. (--long) the first segment appears (blocks/seg000000000.hkb), per-height files below
#      1024 are gone, hk_getBlock 1 is still served — from the segment.
set -uo pipefail
cd "$(dirname "$0")"
H="${HK_DEVNET_HOME:-$HOME/hk-devnet}"
BIN="$(readlink -f "${CARGO_TARGET_DIR:-target}/release/hk-node")"
PROVER="${HK_PROVER_URL:-http://127.0.0.1:9911}"
LONG=0; [[ "${1:-}" == "--long" ]] && LONG=1
PASS=0; FAIL=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
rpc()  { local p=${3:-}; [[ -z "$p" ]] && p="{}"; curl -s -m 5 -X POST "http://127.0.0.1:$1" -d "{\"method\":\"$2\",\"params\":$p}"; }
jq_()  { python3 -c "import sys,json;r=json.load(sys.stdin)['result'];print($1)" 2>/dev/null; }
h_of() { rpc "$1" hk_chainInfo | jq_ 'r["height"]' || echo 0; }
rem_of(){ rpc "$1" hk_chainInfo | jq_ 'r["signer"]["remaining"]' || echo -1; }
wait_h(){ local port=$1 target=$2 tries=${3:-90}; for _ in $(seq "$tries"); do [[ "$(h_of "$port")" -ge "$target" ]] && return 0; sleep 2; done; return 1; }
noansi(){ sed -r 's/\x1b\[[0-9;]*[mK]//g' "$1"; }
has(){ noansi "$1" | grep -E -- "$2" >/dev/null; }
start_env(){ local home=$1 log=$2; shift 2; ( cd "$H" && exec env "$@" HK_PROVER_URL="$PROVER" RUST_LOG=info nohup "$BIN" start "$home" </dev/null >>"$log" 2>&1 ) & }
sealed(){ grep -q '"hke"' "$1"; }
KP="gate seat passphrase for node one"      # strong enough for the strength rule; NOT a real passphrase
WP="gate wallet passphrase for org"
export HK_SEAL_M_KIB=131072                  # 128 MiB during the gate (the default is 512 MiB); the profile rides in the envelope

echo "== 1 · S2/S3 on a fresh 4-validator devnet (HK_SNAPSHOT_EVERY=8 HK_INDEX_PERSIST_EVERY=8 HK_KEEP_PREV_SNAPSHOT=1)"
export HK_SNAPSHOT_EVERY=8 HK_INDEX_PERSIST_EVERY=8 HK_KEEP_PREV_SNAPSHOT=1
./devnet.sh --fresh -n 4 --prover-url "$PROVER" >/dev/null
unset HK_SNAPSHOT_EVERY HK_INDEX_PERSIST_EVERY HK_KEEP_PREV_SNAPSHOT
wait_h 26000 20 90 && ok "devnet deciding (height $(h_of 26000))" || { bad "devnet did not reach height 20"; exit 1; }
sleep 3
[[ -s "$H/node0/index3.bin" ]] && ok "node0 wrote index3.bin (S2 persisted index)" || bad "no index3.bin in node0"
[[ -s "$H/node0/snapshot3.prev.bin" ]] && ok "node0 kept snapshot3.prev.bin (S3 HK_KEEP_PREV_SNAPSHOT=1)" || bad "no snapshot3.prev.bin"
has "$H/node0.log" "search index persisted \(S2\)" && ok "node0 log: search index persisted (S2)" || bad "no S2 persist line in node0.log"
V=$(rpc 26000 hk_chainInfo | jq_ 'r["history"]["retain_blocks"]')
[[ "$V" == "None" ]] && ok "hk_chainInfo.history.retain_blocks = null (archive node)" || bad "retain_blocks on an archive node: $V"
echo "   restarting node0 …"
pkill -f "hk-node start $H/node0"; sleep 2
HB=$(h_of 26001)
: > "$H/node0.restart.log"
start_env "$H/node0" "$H/node0.restart.log" HK_SNAPSHOT_EVERY=8 HK_INDEX_PERSIST_EVERY=8 HK_KEEP_PREV_SNAPSHOT=1
for _ in $(seq 30); do has "$H/node0.restart.log" "PERSISTENCE RESTORE COMPLETE" && break; sleep 2; done
has "$H/node0.restart.log" "PERSISTENCE RESTORE COMPLETE" && ok "node0 restart: RESTORE COMPLETE" || bad "node0 restart never completed restore"
has "$H/node0.restart.log" "search index restored from disk \(S2\)" && ok "node0 restart: search index restored from disk (S2) — no replay" || bad "node0 restart did not restore the index from disk"
wait_h 26000 $((HB + 6)) 60 && ok "node0 deciding again after restart (height $(h_of 26000))" || bad "node0 stuck after restart at $(h_of 26000)"

echo "== 2 · C2.8 reporting: an observer with HK_RETAIN_BLOCKS=64"
rm -rf "$H/obs"; "$BIN" keygen "$H/obs" obs >/dev/null; cp "$H/node0/genesis.json" "$H/obs/genesis.json"
PEERS=$(for i in 0 1 2 3; do printf '/ip4/127.0.0.1/tcp/%d,' $((27000+i)); done | sed 's/,$//')
"$BIN" config-gen "$H/obs" --listen /ip4/127.0.0.1/tcp/27008 --peers "$PEERS" --rpc 127.0.0.1:26008 --metrics 127.0.0.1:29008 >/dev/null
start_env "$H/obs" "$H/obs.log" HK_RETAIN_BLOCKS=64
wait_h 26008 1 60
V=$(rpc 26008 hk_chainInfo | jq_ 'r["history"]["retain_blocks"]')
[[ "$V" == "64" ]] && ok "observer reports history.retain_blocks = 64" || bad "observer retain_blocks: $V"
pkill -f "hk-node start $H/obs"; sleep 1

echo "== 3 · K2: sealed validator key"
pkill -f "hk-node start $H/node1"; sleep 2
KEY="$H/node1/priv_validator_key.json"
PLAIN_SHA=$(sha256sum "$KEY" | cut -c1-16)
OUT=$(HK_KEY_PASSPHRASE=hunter2 "$BIN" key-seal "$H/node1" 2>&1 </dev/null); RC=$?
[[ $RC -ne 0 ]] && echo "$OUT" | grep -q "refused" && [[ "$(sha256sum "$KEY" | cut -c1-16)" == "$PLAIN_SHA" ]] && ok "weak passphrase (hunter2) refused by key-seal, file untouched" || bad "weak passphrase: rc=$RC ${OUT: -120}"
HK_KEY_PASSPHRASE="$KP" "$BIN" key-seal "$H/node1" >/dev/null 2>&1 && sealed "$KEY" && ok "key-seal: priv_validator_key.json is an HKE1 envelope" || bad "key-seal failed or file not sealed"
grep -q '"argon2id"' "$KEY" && grep -q '"m_kib": 131072' "$KEY" && ok "envelope names its kdf (argon2id, 128 MiB as configured) — no seed bytes in the file" || bad "envelope malformed"
: > "$H/node1.nopass.log"
( cd "$H" && env HK_PROVER_URL="$PROVER" RUST_LOG=info "$BIN" start "$H/node1" </dev/null >>"$H/node1.nopass.log" 2>&1 ); RC=$?
[[ $RC -ne 0 ]] && has "$H/node1.nopass.log" "this file is sealed" && ok "start without a passphrase refuses (exit $RC): 'this file is sealed'" || bad "start without passphrase: rc=$RC $(noansi "$H/node1.nopass.log" | tail -1)"
: > "$H/node1.wrong.log"
( cd "$H" && env HK_KEY_PASSPHRASE=nope HK_PROVER_URL="$PROVER" RUST_LOG=info "$BIN" start "$H/node1" </dev/null >>"$H/node1.wrong.log" 2>&1 ); RC=$?
[[ $RC -ne 0 ]] && has "$H/node1.wrong.log" "wrong validator key passphrase" && ok "start with a WRONG passphrase refuses cleanly" || bad "wrong passphrase: rc=$RC $(noansi "$H/node1.wrong.log" | tail -1)"
echo "$KP" > "$H/node1.pass"; chmod 600 "$H/node1.pass"
start_env "$H/node1" "$H/node1.log" HK_KEY_PASSPHRASE_FILE="$H/node1.pass"
wait_h 26001 1 60
sleep 6; R0=$(rem_of 26001); H0=$(h_of 26000); sleep 10; R1=$(rem_of 26001); H1=$(h_of 26000)
[[ "$R1" -lt "$R0" && "$H1" -gt "$H0" ]] && ok "node1 VOTES from the sealed key via HK_KEY_PASSPHRASE_FILE (remaining $R0→$R1, height $H0→$H1)" || bad "node1 not voting: remaining $R0→$R1 height $H0→$H1"
HK_KEY_PASSPHRASE="$KP" "$BIN" issue-rotation "$H/node1" 1 1000000 >/dev/null 2>&1 && [[ -s "$H/node1/rotation_e1.json" ]] && ok "issue-rotation reads the sealed key (cert written, not submitted)" || bad "issue-rotation on a sealed key failed"
rm -f "$H/node1/rotation_e1.json"
OUT=$(HK_KEY_PASSPHRASE=nope "$BIN" issue-rotation "$H/node1" 2 1000000 2>&1 </dev/null); RC=$?
[[ $RC -ne 0 ]] && echo "$OUT" | grep -q "wrong validator key passphrase" && ok "issue-rotation with a wrong passphrase: clean refusal" || bad "issue-rotation wrong passphrase: rc=$RC ${OUT: -120}"
rm -rf "$H/node1.copy"; mkdir -p "$H/node1.copy"; cp "$KEY" "$H/node1.copy/"
HK_KEY_PASSPHRASE="$KP" "$BIN" key-unseal "$H/node1.copy" >/dev/null 2>&1
[[ "$(sha256sum "$H/node1.copy/priv_validator_key.json" | cut -c1-16)" == "$PLAIN_SHA" ]] && ok "key-unseal (on a copy) restores the byte-identical plaintext" || bad "key-unseal mismatch"

echo "== 4 · K1: sealed account.json"
W="$H/wallet-k1"; rm -rf "$W"
"$BIN" account-adopt-demo "$W" org http://127.0.0.1:26000 >/dev/null 2>&1 || bad "could not adopt the demo account (org — the funded one)"
HK_WALLET_PASSPHRASE="$WP" "$BIN" account-seal "$W" >/dev/null 2>&1 && sealed "$W/account.json" && ok "account-seal: account.json is an HKE1 envelope" || bad "account-seal failed"
OUT=$("$BIN" account-info "$W" 2>&1 </dev/null); RC=$?
[[ $RC -ne 0 ]] && echo "$OUT" | grep -q "this file is sealed" && ok "account-info without a passphrase (no TTY) refuses" || bad "account-info without passphrase: rc=$RC"
OUT=$(HK_WALLET_PASSPHRASE="$WP" "$BIN" account-info "$W" 2>&1 </dev/null)
echo "$OUT" | grep -q "^account id" && ok "account-info with HK_WALLET_PASSPHRASE reads the sealed file" || bad "account-info with passphrase: $OUT"
OUT=$(HK_WALLET_PASSPHRASE=bad "$BIN" account-info "$W" 2>&1 </dev/null)
echo "$OUT" | grep -q "wrong wallet passphrase" && ok "wrong wallet passphrase: clean refusal" || bad "wrong wallet passphrase: $OUT"
N0=$(HK_WALLET_PASSPHRASE="$WP" "$BIN" account-info "$W" 2>/dev/null | awk '/next nonce/{print $4}')
rm -rf "$H/wallet-merchant"; "$BIN" account-adopt-demo "$H/wallet-merchant" merchant http://127.0.0.1:26000 >/dev/null 2>&1
BOB=$("$BIN" account-info "$H/wallet-merchant" 2>/dev/null | awk '/account id/{print $4}')
OUT=$(HK_WALLET_PASSPHRASE="$WP" "$BIN" account-send "$W" http://127.0.0.1:26000 "$BOB" 1000 2>&1 </dev/null); RC=$?
[[ $RC -eq 0 ]] && echo "$OUT" | grep -q "receipt: " && ! echo "$OUT" | grep -q "rejected" && ok "account-send from the sealed directory accepted on-chain" || bad "account-send from sealed dir: rc=$RC ${OUT: -160}"
N1=$(HK_WALLET_PASSPHRASE="$WP" "$BIN" account-info "$W" 2>/dev/null | awk '/next nonce/{print $4}')
sealed "$W/account.json" && [[ "$N1" -gt "$N0" ]] && ok "after the send: still sealed, nonce advanced ($N0→$N1) — reserve-then-sign re-sealed it" || bad "post-send state: sealed=$(sealed "$W/account.json" && echo y || echo n) nonce $N0→$N1"
SALT0=$(python3 -c "import json;print(json.load(open('$W/account.json'))['salt'])"); 
HK_WALLET_PASSPHRASE="$WP" "$BIN" account-send "$W" http://127.0.0.1:26000 "$BOB" 1000 >/dev/null 2>&1 </dev/null
SALT1=$(python3 -c "import json;print(json.load(open('$W/account.json'))['salt'])")
[[ "$SALT0" == "$SALT1" ]] && ok "re-seals keep the salt (cached key: no KDF per save)" || bad "salt changed across a save: $SALT0 → $SALT1"
echo "   key file second factor …"
rm -f "$H/wallet.key"; "$BIN" keyfile-new "$H/wallet.key" >/dev/null 2>&1
W2="$H/wallet-k1-kf"; rm -rf "$W2"; "$BIN" account-new "$W2" >/dev/null 2>&1
HK_WALLET_KEYFILE="$H/wallet.key" HK_WALLET_PASSPHRASE="$WP" "$BIN" account-seal "$W2" >/dev/null 2>&1
grep -q '"kf"' "$W2/account.json" && ok "account-seal with HK_WALLET_KEYFILE: envelope names the key file" || bad "no kf in the envelope"
OUT=$(HK_WALLET_PASSPHRASE="$WP" "$BIN" account-info "$W2" 2>&1 </dev/null); RC=$?
[[ $RC -ne 0 ]] && echo "$OUT" | grep -q "key file" && ok "passphrase alone is refused (names the key file) — no brute force possible without it" || bad "keyfile-less open: rc=$RC ${OUT: -120}"
OUT=$(HK_WALLET_KEYFILE="$H/wallet.key" HK_WALLET_PASSPHRASE="$WP" "$BIN" account-info "$W2" 2>&1 </dev/null)
echo "$OUT" | grep -q "^account id" && ok "passphrase + key file opens it" || bad "keyfile open: $OUT"

echo "== 5 · K3: faucet on the sealed directory — /health watermark, 503 below reserve, drip above"
pkill -f "faucet-serve $W" 2>/dev/null; sleep 1
( cd "$H" && exec env HK_WALLET_PASSPHRASE="$WP" nohup "$BIN" faucet-serve "$W" http://127.0.0.1:26000 --listen 127.0.0.1:9932 --drip 100000 --low-micro 999999999999999999 --reserve-micro 999999999999999999 --cooldown-secs 0 </dev/null >"$H/faucet-dry.log" 2>&1 ) &
for _ in $(seq 15); do curl -s -m 2 http://127.0.0.1:9932/health | grep -q '"ok"' && break; sleep 1; done
HJ=$(curl -s -m 5 http://127.0.0.1:9932/health)
echo "$HJ" | python3 -c 'import sys,json;h=json.load(sys.stdin);assert h["low"] is True and h["drips_left"]==0 and "low_watermark_micro" in h and "reserve_micro" in h' 2>/dev/null && ok "/health: low=true drips_left=0 + watermark/reserve fields (sealed wallet opened from the environment)" || bad "/health fields: ${HJ:0:200}"
NA=$(HK_WALLET_PASSPHRASE="$WP" "$BIN" account-info "$W" 2>/dev/null | awk '/next nonce/{print $4}')
FRESH=$("$BIN" account-new "$H/wallet-k3-target" 2>/dev/null | awk '/auth commit  :/{print $4; exit}'); rm -rf "$H/wallet-k3-target"
CODE=$(curl -s -m 10 -o "$H/drip-dry.json" -w '%{http_code}' -X POST http://127.0.0.1:9932/drip -d "{\"auth_commit\":\"$FRESH\"}")
[[ "$CODE" == "503" ]] && grep -q "being refilled" "$H/drip-dry.json" && ok "below the reserve floor: 503 'faucet is being refilled'" || bad "dry faucet answered $CODE $(cat "$H/drip-dry.json")"
NB=$(HK_WALLET_PASSPHRASE="$WP" "$BIN" account-info "$W" 2>/dev/null | awk '/next nonce/{print $4}')
[[ "$NA" == "$NB" ]] && ok "no ratchet index burned on the refusal (nonce $NA)" || bad "nonce moved on a refused drip: $NA→$NB"
pkill -f "faucet-serve $W"; sleep 1
( cd "$H" && exec env HK_WALLET_PASSPHRASE="$WP" nohup "$BIN" faucet-serve "$W" http://127.0.0.1:26000 --listen 127.0.0.1:9932 --drip 100000 --cooldown-secs 0 </dev/null >"$H/faucet.log" 2>&1 ) &
for _ in $(seq 15); do curl -s -m 2 http://127.0.0.1:9932/health | grep -q '"ok"' && break; sleep 1; done
FRESH=$("$BIN" account-new "$H/wallet-k3-target" 2>/dev/null | awk '/auth commit  :/{print $4; exit}')
CODE=$(curl -s -m 40 -o "$H/drip.json" -w '%{http_code}' -X POST http://127.0.0.1:9932/drip -d "{\"auth_commit\":\"$FRESH\"}")
[[ "$CODE" == "200" ]] && grep -q '"txid"' "$H/drip.json" && ok "default reserve: drip 200 with a txid (hot wallet signs from the sealed file)" || bad "drip answered $CODE $(cat "$H/drip.json")"
curl -s -m 5 http://127.0.0.1:9932/health | python3 -c 'import sys,json;h=json.load(sys.stdin);assert h["low"] is False and h["drips_left"]>0' 2>/dev/null && ok "/health after the drip: low=false, drips_left>0" || bad "/health after drip"
pkill -f "faucet-serve $W"; rm -rf "$H/wallet-k3-target"

if [[ $LONG -eq 1 ]]; then
  echo "== 6 · --long: the first segment (1,024 blocks ≈ 25 min at devnet cadence)"
  wait_h 26000 1040 1200 && ok "height 1040 reached" || bad "did not reach 1040"
  for _ in $(seq 60); do [[ -s "$H/node0/blocks/seg000000000.hkb" ]] && break; sleep 5; done
  [[ -s "$H/node0/blocks/seg000000000.hkb" ]] && ok "node0 compacted blocks 0..1023 into blocks/seg000000000.hkb" || bad "no segment file after 5 min past 1024"
  N=$(ls "$H/node0/blocks" | awk '/^b[0-9]{12}\.bin$/{h=substr($0,2,12)+0; if(h<1024)c++} END{print c+0}')
  [[ "$N" -eq 0 ]] && ok "per-height files below 1024 are gone (hot tail only)" || bad "$N per-height files below 1024 remain"
  V=$(rpc 26000 hk_getBlock '{"height":1}' | jq_ 'r["height"]')
  [[ "$V" == "1" ]] && ok "hk_getBlock 1 still served — from the segment" || bad "hk_getBlock 1: $V"
  has "$H/node0.restart.log" "segment" && ok "node0 log mentions the segment compaction" || bad "no compaction line in node0 log"
fi

echo
echo "GATE S+K: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && echo "GATE GREEN" || echo "GATE RED"
[[ $FAIL -eq 0 ]]
