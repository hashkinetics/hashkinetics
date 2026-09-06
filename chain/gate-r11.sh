#!/usr/bin/env bash
# gate-r11.sh -- the R11 receipt (v0.17.0) on a local devnet: the node VERIFIES STARKs with a verify-only
# SP1 client — seconds to start, a resident set a stranger's 8 GB box can carry — and it still accepts
# exactly what it accepted before and refuses exactly what it refused.
#
#   ./gate-r11.sh                       # needs hk-prove on 127.0.0.1:9911 (mint/spend/aggregate proofs), like gate-s.sh
#   HK_PROVER_URL=… ./gate-r11.sh
#
# What it proves (each line is a PASS/FAIL):
#   1. 4-validator devnet: every node logs "verify-only SP1 client ready" and never "initializing cpu prover";
#      hk_chainInfo.process reports verifier_init_ms < 10 000, rss_bytes < 1.5 GiB, uptime_secs; the first
#      log line → "RPC listening" is under 60 s (was 3–6 min per host on the fleet with the full client).
#   2. demo-shielded under the light client: mint + two spends (CORE proofs) commit; a nullifier replay is
#      refused at the door (mempool admission mirrors apply since v0.10.4 — it never reaches a block) and a
#      FORGED proof (one byte flipped) passes admission and is refused BY CONSENSUS with a receipt — the
#      accept-set and both refuse paths unchanged.
#   3. demo-agg under the light client: three COMPRESSED spends folded into ONE aggregate STARK commit in one
#      block (node logs "Aggregate STARK verified"); the classic per-proof fallback still works. The compressed
#      path is the one that checks the recursion vk against the SDK's pinned root — proven live here.
#   4. steady-state RSS after all that verifying: every node < 1.5 GiB (the numbers are printed — receipts).
#   5. node0 restarted on its persisted home: RPC back in < 30 s, verifier_init_ms again < 10 s, and it
#      re-joins consensus (height keeps pace with node1 within 60 s).
set -uo pipefail
cd "$(dirname "$0")"
H="${HK_DEVNET_HOME:-$HOME/hk-devnet}"
BIN="$(readlink -f "${CARGO_TARGET_DIR:-target}/release/hk-node")"
PROVER="${HK_PROVER_URL:-http://127.0.0.1:9911}"
RPC=http://127.0.0.1:26000
RSS_MAX=$((1536 * 1024 * 1024))   # 1.5 GiB — the P3.2 acceptance line
PASS=0; FAIL=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
rpc()  { local p=${3:-}; [[ -z "$p" ]] && p="{}"; curl -s -m 10 -X POST "http://127.0.0.1:$1" -d "{\"method\":\"$2\",\"params\":$p}"; }
py()   { rpc "$1" "$2" | python3 -c "import sys,json;r=json.load(sys.stdin)['result'];print($3)" 2>/dev/null; }
h_of() { py "$1" hk_chainInfo 'r["height"]' || echo 0; }
wait_h(){ local port=$1 target=$2 tries=${3:-90}; for _ in $(seq "$tries"); do [[ "$(h_of "$port")" -ge "$target" ]] && return 0; sleep 2; done; return 1; }
noansi(){ sed -r 's/\x1b\[[0-9;]*[mK]//g' "$1"; }
has(){ noansi "$1" | grep -E -- "$2" >/dev/null; }
# seconds between the first log line and the first line matching $2 (tracing's RFC3339 stamps)
log_secs(){ noansi "$1" | python3 -c "
import sys,re,datetime
pat=re.compile(sys.argv[1]); first=None
for line in sys.stdin:
    m=re.match(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?)Z',line.strip())
    if not m: continue
    t=datetime.datetime.fromisoformat(m.group(1))
    first=first or t
    if pat.search(line): print(int((t-first).total_seconds())); break
else: print(-1)
" "$2"; }
# the process block, one line: "<init_ms> <rss_bytes> <uptime_secs>" (None for null)
proc(){ py "$1" hk_chainInfo 'r["process"]["verifier_init_ms"],r["process"]["rss_bytes"],r["process"]["uptime_secs"]'; }
mib(){ python3 -c "import sys;print('%.0f MiB' % (int(sys.argv[1])/1048576))" "$1" 2>/dev/null || echo "?"; }
start_node(){ ( cd "$H" && exec env HK_PROVER_URL="$PROVER" RUST_LOG=info nohup "$BIN" start "$H/node$1" </dev/null >>"$H/node$1.log" 2>&1 ) & }

echo "== 1 · fresh devnet on the verify-only client"
curl -s -m 5 -X POST "$PROVER" -d '{"method":"health","params":{}}' | grep -q result || { echo "hk-prove not reachable at $PROVER"; exit 1; }
./devnet.sh --fresh -n 4 --prover-url "$PROVER" >/dev/null
wait_h 26000 5 60 && ok "devnet deciding (height $(h_of 26000))" || { bad "devnet did not reach height 5"; exit 1; }
for i in 0 1 2 3; do
    has "$H/node$i.log" "verify-only SP1 client ready" && ok "node$i logged 'verify-only SP1 client ready'" || bad "node$i: no verify-only line"
    has "$H/node$i.log" "initializing cpu prover" && bad "node$i built the FULL cpu prover" || ok "node$i never built a proving engine"
done
read -r INIT RSS UP <<<"$(proc 26000)"
[[ "$INIT" =~ ^[0-9]+$ && "$INIT" -lt 10000 ]] && ok "node0 verifier_init_ms = $INIT (< 10 000)" || bad "node0 verifier_init_ms = $INIT"
[[ "$RSS" =~ ^[0-9]+$ && "$RSS" -lt "$RSS_MAX" ]] && ok "node0 rss_bytes = $RSS ($(mib "$RSS") < 1.5 GiB)" || bad "node0 rss_bytes = $RSS"
[[ "$UP" =~ ^[0-9]+$ ]] && ok "node0 uptime_secs = $UP" || bad "node0 uptime_secs = $UP"
S=$(log_secs "$H/node0.log" "RPC listening"); [[ "$S" =~ ^[0-9]+$ && "$S" -lt 60 ]] && ok "node0 first log line → RPC listening in $S s (< 60 s)" || bad "node0 start → RPC: $S s"

echo "== 2 · core proofs + refusals (demo-shielded) under the light client"
OUT=$("$BIN" demo-shielded "$RPC" "$PROVER" 2>&1); RC=$?
[[ $RC -eq 0 ]] && echo "$OUT" | grep -q "That's P2.1" && ok "demo-shielded completed (mint + two core-proof spends committed)" || { bad "demo-shielded rc=$RC"; echo "$OUT" | tail -n 12; }
# the replay of a spent nullifier is refused AT ADMISSION ("submit FAILED … nullifier already spent on-chain"):
echo "$OUT" | grep -q "nullifier already" && ok "nullifier replay refused at admission (never entered the mempool)" || { bad "nullifier replay not refused"; echo "$OUT" | grep -A2 "replaying" | sed 's/^/        /'; }
# the forged proof passes admission (proofs are judged at apply) and is refused BY CONSENSUS, with a receipt:
echo "$OUT" | grep -q "⛔.*pool proof rejected" && ok "forged proof refused by consensus: $(echo "$OUT" | grep -o '⛔.*pool proof rejected[^)]*)' | head -n1)" || { bad "forged proof not refused by consensus"; echo "$OUT" | grep -A2 "FORGED" | sed 's/^/        /'; }

echo "== 3 · compressed aggregate (demo-agg): the recursion-vk check runs against the SDK's pinned root"
OUT=$("$BIN" demo-agg "$RPC" "$PROVER" 2>&1); RC=$?
[[ $RC -eq 0 ]] && echo "$OUT" | grep -q "per-proof path verified as always" && ok "demo-agg completed (3 compressed spends in ONE aggregate + the classic fallback)" || { bad "demo-agg rc=$RC"; echo "$OUT" | tail -n 12; }
sleep 2
for i in 0 1 2 3; do has "$H/node$i.log" "Aggregate STARK verified" && ok "node$i verified the aggregate STARK (compressed path)" || bad "node$i: no aggregate verify line"; done

echo "== 4 · steady-state memory after real verification work"
for i in 0 1 2 3; do
    read -r INIT RSS UP <<<"$(proc $((26000+i)))"
    [[ "$RSS" =~ ^[0-9]+$ && "$RSS" -lt "$RSS_MAX" ]] && ok "node$i rss $(mib "$RSS") · verifier_init ${INIT} ms · up ${UP} s" || bad "node$i rss_bytes = $RSS"
done

echo "== 5 · restart node0 on its persisted home: seconds to RPC, back in consensus"
PID=$(pgrep -f "hk-node start $H/node0\$" | head -n1)
[[ -n "$PID" ]] && kill "$PID" && sleep 3 && ok "node0 stopped (pid $PID)" || bad "could not find/stop node0"
HB=$(h_of 26001)
echo "--- restart $(date -u +%FT%TZ) ---" >>"$H/node0.log"
T0=$(date +%s); start_node 0
UPOK=0; for _ in $(seq 30); do [[ "$(h_of 26000)" -gt 0 ]] && { UPOK=1; break; }; sleep 1; done
T1=$(date +%s); D=$((T1-T0))
[[ "$UPOK" == 1 && "$D" -lt 30 ]] && ok "node0 RPC back in $D s (< 30 s)" || bad "node0 RPC after restart: up=$UPOK in $D s"
read -r INIT RSS UP <<<"$(proc 26000)"
[[ "$INIT" =~ ^[0-9]+$ && "$INIT" -lt 10000 ]] && ok "node0 verifier_init_ms after restart = $INIT" || bad "node0 verifier_init_ms after restart = $INIT"
JOIN=0; for _ in $(seq 30); do H0=$(h_of 26000); H1=$(h_of 26001); [[ "$H0" -ge "$HB" && "$H0" -ge $((H1-2)) && "$H1" -gt "$HB" ]] && { JOIN=1; break; }; sleep 2; done
[[ "$JOIN" == 1 ]] && ok "node0 keeps pace again (node0 $H0 · node1 $H1 · was $HB at the stop)" || bad "node0 not back in step (node0 $(h_of 26000) · node1 $(h_of 26001))"

echo
echo "== gate-r11: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && echo "GATE GREEN" || echo "GATE RED"
