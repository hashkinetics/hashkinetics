#!/usr/bin/env bash
# rehearsal.sh — the v0.13.0 GATE, run locally on WSL before anything touches the fleet:
#
#   1. testnet-1 CEREMONY REHEARSAL: 4 independent `keygen`s → `genesis-build` with the
#      U4.b fee policy (100 micro from height 1) + a funded faucet treasury + the public
#      demo accounts → 4 validators from that exact genesis → first tx pays the fee.
#   2. R10 v2 RESTORE SHAPES on one validator (quorum stays 3/4): full log · suffix-only
#      log · only-block-1 log · wiped log — every shape must resume at the CHAIN tip and
#      rejoin. (v0.12.0's R10 died on exactly this; the devnet then had a full log and hid it.)
#   3. OBSERVER FROM GENESIS with the validators' RAM window at 8 — heights below tip-8
#      are served from DISK, so a full sync proves the disk path end-to-end.
#   4. Genesis-bound fee precedence: a node relaunched with HK_FEE_FROM=999 must IGNORE it.
#
# Usage:  cd chain && ./rehearsal.sh 2>&1 | tee ~/rehearsal.log ; tail -60 ~/rehearsal.log
# Env:    CARGO_TARGET_DIR (default ~/hk-target-chain) · HK_PROVER_URL (default 127.0.0.1:9911)
#         HK_REHEARSAL_HOME (default ~/hk-rehearsal) · SKIP_BUILD=1 to reuse the binary
set -uo pipefail
cd "$(dirname "$0")"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/hk-target-chain}"
BIN="$CARGO_TARGET_DIR/release/hk-node"
H="${HK_REHEARSAL_HOME:-$HOME/hk-rehearsal}"
PROVER="${HK_PROVER_URL:-http://127.0.0.1:9911}"
FAILS=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
say()  { echo; echo "== $*"; }

rpc() { curl -s -m 8 -X POST "http://127.0.0.1:$1" -d "{\"method\":\"$2\",\"params\":${3:-{\}}}"; }
jget() { python3 -c "import sys,json
d=json.load(sys.stdin)
for k in '$1'.split('.'):
    d=d[int(k)] if isinstance(d,list) else d.get(k)
    if d is None: print(''); sys.exit()
print(d)" 2>/dev/null; }
height() { rpc "$1" hk_chainInfo | jget result.height; }
balance() { rpc "$1" hk_balance "{\"id\":\"$2\",\"asset\":\"$USD\"}" | jget result.amount; }
burned() { rpc "$1" hk_chainInfo | jget result.fee.burned_micro; }
USD=$(printf '09%.0s' {1..32})

start_node() { # start_node <i> [extra env assignments...]
    local i=$1; shift
    ( cd "$H" && env HK_PROVER_URL="$PROVER" HK_DECIDED_WINDOW=8 RUST_LOG=info "$@" \
        nohup "$BIN" start "$H/v$i" >> "$H/v$i.log" 2>&1 & )
}
stop_node() { pkill -f "hk-node start $H/v$1" 2>/dev/null; sleep 2; }
wait_height() { # wait_height <port> <min-height> <secs>
    local port=$1 want=$2 secs=$3 h=0
    for _ in $(seq 1 "$secs"); do
        h=$(height "$port"); [[ -n "$h" && "$h" -ge "$want" ]] && { echo "$h"; return 0; }
        sleep 1
    done
    echo "${h:-0}"; return 1
}
caught_up() { # caught_up <port> <label> — the node must be within 3 of validator 0 AND moving
    local port=$1 label=$2 h0 h1 ref
    h0=$(wait_height "$port" 1 60) || { fail "$label: no RPC/height after restart"; return; }
    sleep 12
    h1=$(height "$port"); ref=$(height 26000)
    if [[ -n "$h1" && "$h1" -gt "$h0" && $((ref - h1)) -le 3 ]]; then
        pass "$label: resumed and rejoined — $h0 → $h1 (validator-0 at $ref)"
    else
        fail "$label: stuck or lagging — $h0 → $h1 (validator-0 at $ref)"
    fi
}

# ---- 0. flush whatever devnet is running ------------------------------------------
say "flush"
pkill -f 'hk-node start' 2>/dev/null; sleep 1
rm -rf "$H"; mkdir -p "$H"

# ---- 1. build + unit tests --------------------------------------------------------
if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
    say "build"
    cargo build --release -p hk-node || { echo "BUILD FAILED"; exit 1; }
    say "tests"
    cargo test --release -p hk-state 2>&1 | grep -E "^test result|FAILED|panicked" | head -5
    cargo test --release -p hk-node  2>&1 | grep -E "^test result|FAILED|panicked" | head -5
fi
[[ -x "$BIN" ]] || { echo "no binary at $BIN"; exit 1; }
say "binary"; sha256sum "$BIN"

say "prover"
curl -s -m 5 -X POST "$PROVER" -d '{"method":"health","params":{}}' | grep -q '"ok":true' \
    && pass "prover reachable at $PROVER" || fail "prover NOT reachable at $PROVER (nodes would refuse shielded traffic; pins unavailable)"

# ---- 2. CEREMONY REHEARSAL ---------------------------------------------------------
say "ceremony: 4 independent keygens"
for i in 0 1 2 3; do "$BIN" keygen "$H/v$i" "rehearsal-$i" > /dev/null || fail "keygen v$i"; done
python3 - "$H" <<'EOF'
import json, sys
h = sys.argv[1]
vals = [json.load(open(f"{h}/v{i}/validator.json")) for i in range(4)]
json.dump(vals, open(f"{h}/validators.json", "w"), indent=1)
print(f"collected {len(vals)} validator.json → validators.json")
EOF

say "ceremony: faucet treasury (self-custodied; only its nonce-0 auth commit enters genesis)"
"$BIN" account-new "$H/treasury" > /dev/null || fail "account-new treasury"
TAUTH=$("$BIN" account-info "$H/treasury" | awk '/genesis auth/{print $4}')
TID=$("$BIN" account-info "$H/treasury" | awk '/account id/{print $4}')
echo "treasury id $TID  genesis auth $TAUTH"
[[ ${#TAUTH} -eq 64 && ${#TID} -eq 64 ]] && pass "treasury identity" || fail "treasury identity (auth=$TAUTH id=$TID)"

say "ceremony: genesis-build (fee 100 micro from h1 · treasury 1,000 USD · demo accounts)"
HK_PROVER_URL="$PROVER" HK_CHAIN_START_TIME="$(date +%s)" "$BIN" genesis-build "$H/validators.json" "$H/genesis.json" \
    --fee-micro 100 --fee-from 1 --alloc "$TAUTH:1000000000" --demo-accounts 50 | tee "$H/genesis-build.log"
DIGEST=$(sha256sum "$H/genesis.json" | cut -c1-64)
grep -q "\"fee\"" "$H/genesis.json" && pass "genesis carries the fee policy" || fail "genesis has no fee field"
grep -q "\"vk_pins\": {" "$H/genesis.json" && pass "genesis pins the verifying keys" || fail "genesis UNPINNED"
grep -q "genesis digest   : $DIGEST" "$H/genesis-build.log" && pass "genesis-build printed the true digest" || fail "digest mismatch between genesis-build and sha256sum"

say "ceremony: configs (4 validators, ports 27000-3 / rpc 26000-3)"
for i in 0 1 2 3; do
    PEERS=$(for j in 0 1 2 3; do [[ $j != "$i" ]] && printf "/ip4/127.0.0.1/tcp/2700%s," "$j"; done | sed 's/,$//')
    GOSS=$(for j in 0 1 2 3; do [[ $j != "$i" ]] && printf "http://127.0.0.1:2600%s," "$j"; done | sed 's/,$//')
    "$BIN" config-gen "$H/v$i" --listen "/ip4/127.0.0.1/tcp/2700$i" --peers "$PEERS" --rpc "127.0.0.1:2600$i" \
        --moniker "rh-$i" --gossip-peers "$GOSS" > /dev/null || fail "config-gen v$i"
    cp "$H/genesis.json" "$H/v$i/genesis.json"
done

say "launch: all four validators from the ceremony genesis (SP1 verifier init ≈ 40 s)"
for i in 0 1 2 3; do start_node "$i"; done
H0=$(wait_height 26000 5 150) && pass "chain is live from the ceremony genesis — height $H0" || fail "chain did not reach height 5 in 150 s (height=$H0) — see $H/v0.log"
CID=$(rpc 26000 hk_chainInfo | jget result.chain_id)
[[ "$CID" == "hashkinetics-1-${DIGEST:0:8}" ]] && pass "chain id bound to the genesis digest: $CID" || fail "chain id $CID != hashkinetics-1-${DIGEST:0:8}"
FEE=$(rpc 26000 hk_chainInfo | jget result.fee.micro); FROM=$(rpc 26000 hk_chainInfo | jget result.fee.from_height)
[[ "$FEE" == "100" && "$FROM" == "1" ]] && pass "fee policy from genesis: $FEE micro from height $FROM" || fail "fee policy on chain = $FEE from $FROM"
grep -q "fee policy is genesis-bound" "$H/v0.log" && pass "node log: fee policy is genesis-bound (U4.b)" || fail "node log lacks the genesis-bound fee line"
TB=$(balance 26000 "$TID")
[[ "$TB" == "1000000000" ]] && pass "treasury funded at genesis: $TB micro" || fail "treasury balance $TB"
ORG=$("$BIN" account-adopt-demo "$H/org" org http://127.0.0.1:26000 2>/dev/null | grep -o "([0-9a-f]\{64\})" | tr -d '()')
OB=$(balance 26000 "$ORG")
[[ "$OB" == "50000000" ]] && pass "demo org funded at genesis: \$50" || fail "org balance $OB (id $ORG)"

say "first transaction pays the fee: treasury creates + funds a user (250,000 micro)"
"$BIN" account-new "$H/user" > /dev/null
UAUTH=$("$BIN" account-info "$H/user" | awk '/genesis auth/{print $4}')
UID_=$("$BIN" account-info "$H/user" | awk '/account id/{print $4}')
"$BIN" account-create "$H/treasury" http://127.0.0.1:26000 "$UAUTH" 250000 | tail -2
sleep 3
B1=$(burned 26000); TB2=$(balance 26000 "$TID"); UB=$(balance 26000 "$UID_")
[[ "$B1" == "100" ]] && pass "first fee burned: burned_micro=$B1" || fail "burned_micro=$B1 after the first tx"
[[ "$TB2" == "999749900" ]] && pass "treasury paid amount + fee: $TB2" || fail "treasury balance $TB2 (want 999749900)"
[[ "$UB" == "250000" ]] && pass "user received the full amount: $UB" || fail "user balance $UB"

say "fee-aware refusal: a full-balance sweep refuses; a partial send lands"
SW=$("$BIN" account-send "$H/user" http://127.0.0.1:26000 "$TID" 250000 2>&1)
echo "$SW" | grep -qi "protocol fee\|chain refused" && pass "sweep refused (fee-aware balance): $(echo "$SW" | grep -o 'rejected:[^)]*' | head -1)" || fail "sweep did not refuse: $(echo "$SW" | tail -1)"
"$BIN" account-send "$H/user" http://127.0.0.1:26000 "$TID" 100000 | tail -1
sleep 3
B2=$(burned 26000); UB2=$(balance 26000 "$UID_")
[[ "$B2" == "200" && "$UB2" == "149900" ]] && pass "partial landed: user $UB2, burned $B2" || fail "partial: user=$UB2 burned=$B2"

# ---- 3. R10 v2 RESTORE SHAPES (validator 3; quorum holds 3/4) -----------------------
say "R10 v2 — shape A: full log restart"
sleep 20   # let a couple of snapshots land (every 16 heights)
stop_node 3
echo "v3 block files: $(ls "$H/v3/blocks" | wc -l)"
start_node 3
caught_up 26003 "shape A (full log)"
grep -q "R10 v2: history stays on disk" "$H/v3.log" && pass "restore did not rehydrate history" || fail "R10 v2 restore line missing"
grep -q "index pass COMPLETE" "$H/v3.log" && pass "background index pass completed" || fail "index pass did not complete"

say "R10 v2 — shape B: only block #1 on disk + snapshot (the v0.12.0 killer)"
stop_node 3
find "$H/v3/blocks" -name 'b*.bin' ! -name 'b000000000001.bin' -delete
echo "v3 block files now: $(ls "$H/v3/blocks")"
start_node 3
caught_up 26003 "shape B (only block 1)"
RL=$(grep "R10 v2: history stays on disk" "$H/v3.log" | tail -1)
RT=$(echo "$RL" | grep -o 'tip=[0-9]*' | cut -d= -f2); RF=$(echo "$RL" | grep -o 'disk_files=[0-9]*' | cut -d= -f2)
[[ -n "$RT" && "$RT" -ge 16 && "$RF" == "1" ]] && pass "restore resumed at the CHAIN height (tip=$RT) with only $RF block file on disk (the log said nothing; the snapshot did)" || fail "restore line: $RL"
grep -q "Consensus is ready" "$H/v3.log" && echo "  engine: $(grep 'Consensus is ready' "$H/v3.log" | tail -1 | sed 's/.*INFO//')"

say "R10 v2 — shape C: suffix-only log (delete everything below tip-6)"
stop_node 3
TIP=$(ls "$H/v3/blocks" | grep '\.bin$' | tail -1 | sed 's/b0*//;s/.bin//')
ls "$H/v3/blocks" | head -n -6 | sed "s#^#$H/v3/blocks/#" | xargs -r rm
echo "v3 block files now: $(ls "$H/v3/blocks" | wc -l) (tip $TIP)"
start_node 3
caught_up 26003 "shape C (suffix-only log)"
DF=$(rpc 26003 hk_chainInfo | jget result.history.disk_from)
NOW=$(height 26003)
GAPS=$(ls "$H/v3/blocks" | sed 's/b0*//;s/.bin//' | sort -n | awk -v df="$DF" -v tip="$NOW" '$1>=df && $1<=tip {n++} END{print (tip-df+1)-n}')
if [[ -n "$DF" && "$DF" -gt 1 && "$GAPS" == "0" ]]; then
    pass "advertises servable history from $DF (replay stopped at the snapshot; the synced gap was persisted) — every file $DF..$NOW present"
else
    fail "disk_from=$DF tip=$NOW missing_files=$GAPS (tip at stop was $TIP)"
fi
EARLIEST=$(rpc 26003 hk_getBlocks '{"limit":3}' | jget result.earliest)
[[ "$EARLIEST" == "$DF" ]] && pass "hk_getBlocks.earliest agrees: $EARLIEST" || fail "hk_getBlocks.earliest=$EARLIEST vs disk_from=$DF"

say "R10 v2 — shape D: wiped block log, snapshot kept + HK_FEE_FROM=999 must be IGNORED"
stop_node 3
rm -f "$H/v3/blocks"/*.bin
start_node 3 HK_FEE_FROM=999
caught_up 26003 "shape D (wiped log)"
grep -q "ignored — the fee policy is bound to this genesis" "$H/v3.log" && pass "HK_FEE_FROM override refused (genesis wins)" || fail "no 'ignored' warning for HK_FEE_FROM"
grep -q "app_hash divergence" "$H/v3.log" && fail "v3 diverged" || pass "no divergence with the env override present"

# ---- 4. OBSERVER FROM GENESIS (validators serve below tip-8 from DISK) ---------------
say "observer from genesis via disk-served value-sync"
"$BIN" keygen "$H/v4" observer > /dev/null
PEERS=$(for j in 0 1 2 3; do printf "/ip4/127.0.0.1/tcp/2700%s," "$j"; done | sed 's/,$//')
"$BIN" config-gen "$H/v4" --listen /ip4/127.0.0.1/tcp/27004 --peers "$PEERS" --rpc 127.0.0.1:26004 --moniker observer > /dev/null
cp "$H/genesis.json" "$H/v4/genesis.json"
start_node 4
REF=$(height 26000)
OH=$(wait_height 26004 "$REF" 300) && pass "observer synced from genesis to $OH (validators' RAM window = 8 → disk served the rest)" || fail "observer at $OH, validators at $(height 26000)"
grep -q "not serving\|refusing to serve" "$H"/v[0-3].log && fail "a validator refused to serve a block" || pass "no serve refusals on any validator"
grep -q "app_hash divergence" "$H/v4.log" && fail "observer diverged" || pass "observer verified every block from disk-served history"
RW=$(rpc 26000 hk_chainInfo | jget result.history.ram_window)
[[ "$RW" == "8" ]] && pass "hk_chainInfo.history.ram_window = $RW" || fail "ram_window=$RW"

say "memory (RSS kB) — validators after $(height 26000) heights with window 8 (NOTE: the SP1 verifier client's fixed footprint dominates and varies by machine; the decided window itself is ~8 blocks)"
for i in 0 1 2 3; do printf "  v%s  %s kB\n" "$i" "$(ps -o rss= -p "$(pgrep -f "hk-node start $H/v$i" | head -1)" 2>/dev/null | tr -d ' ')"; done

# ---- 5. verdict ----------------------------------------------------------------------
say "verdict"
if [[ $FAILS -eq 0 ]]; then
    echo "GATE GREEN — v0.13.0 rehearsal passed every check. binary: $(sha256sum "$BIN" | cut -c1-16)…  genesis digest (rehearsal): $DIGEST"
else
    echo "GATE RED — $FAILS failing check(s). Logs: $H/v*.log"
fi
echo "(nodes left running for inspection; stop with:  pkill -f 'hk-node start')"
