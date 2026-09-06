#!/usr/bin/env bash
# gate-h3.sh -- the H3 receipt (v0.16.1) on a local devnet: a PAGED pool feed + ONE-PATH spends.
#
#   ./gate-h3.sh                       # needs hk-prove on 127.0.0.1:9911 (mint/spend proofs), like gate-s.sh
#   HK_PROVER_URL=… ./gate-h3.sh
#
# What it proves (each line is a PASS/FAIL):
#   1. 4-validator devnet up; the CLI wallet shields three notes (three mint proofs).
#   2. hk_getPoolNotes is paged: {} → the 3 notes, total 3, next null · {limit:2} → indices 0,1 and
#      next 2 · {from:2,limit:2} → index 2, next null · {from:99} → an empty page that still says
#      total 3 · limit 0 → one note (never an unbounded page).
#   3. hk_getPoolLeaves pages the same way and its pages concatenate to the whole list.
#   4. hk_getPoolPath {index:1} → 32 siblings; `hk-node pool-path` re-folds them to the stated
#      root, which is hk_getPoolInfo.root; an out-of-range index is an error, not a panic.
#   5. The CLI wallet (whole-feed reader) still spends against the paged node: unshield 1 →
#      two new commitments; the path for the newest leaf folds to the NEW root; `wallet scan`
#      still finds the change note. (The GUI's path-based spend is the same lib call —
#      `build_spend_with_path` — unit-tested equal to the leaf-list spend.)
set -uo pipefail
cd "$(dirname "$0")"
H="${HK_DEVNET_HOME:-$HOME/hk-devnet}"
BIN="$(readlink -f "${CARGO_TARGET_DIR:-target}/release/hk-node")"
PROVER="${HK_PROVER_URL:-http://127.0.0.1:9911}"
RPC=http://127.0.0.1:26000
PASS=0; FAIL=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
rpc()  { local p=${2:-}; [[ -z "$p" ]] && p="{}"; curl -s -m 20 -X POST "$RPC" -d "{\"method\":\"$1\",\"params\":$p}"; }
jq_()  { python3 -c "import sys,json;r=json.load(sys.stdin)['result'];print($1)" 2>/dev/null; }
h_of() { rpc hk_chainInfo | jq_ 'r["height"]' || echo 0; }
wait_h(){ local target=$1 tries=${2:-90}; for _ in $(seq "$tries"); do [[ "$(h_of)" -ge "$target" ]] && return 0; sleep 2; done; return 1; }
notes_view(){ rpc hk_getPoolNotes "$1" | jq_ '(" ".join(str(n["index"]) for n in r["notes"]), r.get("count"), r.get("total"), r.get("next"))'; }
leaves_view(){ rpc hk_getPoolLeaves "$1" | jq_ '(",".join(r["leaves"]), r.get("count"), r.get("total"), r.get("next"))'; }

echo "== 1 · fresh devnet + three shielded notes"
curl -s -m 5 -X POST "$PROVER" -d '{"method":"health","params":{}}' | grep -q result || { echo "hk-prove not reachable at $PROVER"; exit 1; }
./devnet.sh --fresh -n 4 --prover-url "$PROVER" >/dev/null
wait_h 5 60 && ok "devnet deciding (height $(h_of))" || { bad "devnet did not reach height 5"; exit 1; }
W="$H/wallet-org"; rm -rf "$W"
"$BIN" wallet init "$W" org "$RPC" >/dev/null 2>&1 && ok "CLI wallet bound to org" || bad "wallet init"
for i in 1 2 3; do "$BIN" wallet shield "$W" 1 "$RPC" "$PROVER" 2>&1 | grep -q "shielded" && ok "shield #$i landed" || bad "shield #$i"; done
sleep 2
N=$(rpc hk_getPoolInfo | jq_ 'r["next_index"]'); [[ "$N" == 3 ]] && ok "pool has 3 commitments" || bad "pool next_index = $N"

echo "== 2 · hk_getPoolNotes pages"
V=$(notes_view '{}');                    [[ "$V" == "('0 1 2', 3, 3, None)" ]] && ok "{} → all three, total 3, next null: $V" || bad "{} → $V"
V=$(notes_view '{"limit":2}');           [[ "$V" == "('0 1', 2, 3, 2)" ]] && ok "{limit 2} → 0 1, next 2: $V" || bad "{limit 2} → $V"
V=$(notes_view '{"from":2,"limit":2}');  [[ "$V" == "('2', 1, 3, None)" ]] && ok "{from 2} → 2, next null: $V" || bad "{from 2} → $V"
V=$(notes_view '{"from":99}');           [[ "$V" == "('', 0, 3, None)" ]] && ok "{from 99} → empty page, total 3: $V" || bad "{from 99} → $V"
V=$(notes_view '{"limit":0}');           [[ "$V" == "('0', 1, 3, 1)" ]] && ok "{limit 0} → one note, never unbounded: $V" || bad "{limit 0} → $V"

echo "== 3 · hk_getPoolLeaves pages concatenate to the whole"
ALL=$(leaves_view '{}' | python3 -c "import sys,ast;print(ast.literal_eval(sys.stdin.read())[0])")
P1=$(leaves_view '{"limit":2}' | python3 -c "import sys,ast;t=ast.literal_eval(sys.stdin.read());print(t[0],t[3])")
P2=$(leaves_view '{"from":2,"limit":2}' | python3 -c "import sys,ast;t=ast.literal_eval(sys.stdin.read());print(t[0],t[3])")
[[ "${P1#* }" == 2 && "${P2#* }" == None && "${P1% *},${P2% *}" == "$ALL" ]] && ok "leaves: page(0..2) + page(2..) == whole" || bad "leaves pages: [$P1] [$P2] vs [$ALL]"

echo "== 4 · hk_getPoolPath folds to the pool root"
S=$(rpc hk_getPoolPath '{"index":1}' | jq_ 'len(r["siblings"])'); [[ "$S" == 32 ]] && ok "path has 32 siblings" || bad "siblings: $S"
OUT=$("$BIN" pool-path "$RPC" 1 2>&1); echo "$OUT" | grep -q "folds to .* ✓" && ok "hk-node pool-path: folds to the stated root" || bad "pool-path: $OUT"
echo "$OUT" | grep -q "✓ current" && ok "stated root == hk_getPoolInfo.root" || bad "root differs: $OUT"
E=$(rpc hk_getPoolPath '{"index":7}'); echo "$E" | grep -q "out of range" && ok "out-of-range index → error" || bad "index 7: $E"
E=$(rpc hk_getPoolPath '{}'); echo "$E" | grep -q "index" && ok "missing index → error" || bad "no index: $E"

echo "== 5 · a spend against the paged node, then a path for the newest leaf"
"$BIN" wallet unshield "$W" 1 "$RPC" "$PROVER" 2>&1 | grep -q "unshielded to your transparent account" && ok "CLI wallet unshield 1 landed (reads the feed page by page)" || bad "unshield"
sleep 2
N=$(rpc hk_getPoolInfo | jq_ 'r["next_index"]'); [[ "$N" == 5 ]] && ok "pool has 5 commitments (spend appended two)" || bad "pool next_index = $N"
V=$(notes_view '{"from":3}'); [[ "$V" == "('3 4', 2, 5, None)" ]] && ok "a wallet with cursor 3 gets exactly the two new entries: $V" || bad "{from 3} → $V"
OUT=$("$BIN" pool-path "$RPC" 4 2>&1); echo "$OUT" | grep -q "✓ current" && ok "path for leaf 4 folds to the new pool root" || bad "pool-path 4: $OUT"
SC=$("$BIN" wallet scan "$W" "$RPC" 2>&1); L=$(echo "$SC" | grep -c "^LIVE"); S2=$(echo "$SC" | grep -c "^SPENT"); [[ "$L" == 3 && "$S2" == 1 ]] && ok "wallet scan (whole feed, paged): 3 LIVE (two untouched + the change note) · 1 SPENT" || bad "scan: LIVE=$L SPENT=$S2"

echo
echo "== gate-h3: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && echo "GATE GREEN" || echo "GATE RED"
