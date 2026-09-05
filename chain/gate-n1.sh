#!/usr/bin/env bash
# gate-n1.sh -- the N1 receipt (v0.15.2): a node's live p2p peer table is measured, not
# configured — `hk_getPeers` shows who is connected, which way, from where (masked), on which
# genesis and node version; peers appear when they connect and vanish when they leave; an
# island chain (different genesis) is refused and COUNTED, never listed as a peer.
#
#   ./gate-n1.sh                       # needs hk-prove on 127.0.0.1:9911 (vk pins)
#
# What it proves (each line is a PASS/FAIL):
#   1. 4-validator devnet: node0 sees exactly 3 peers, every one identified, version = the binary's,
#      genesis "match", private (loopback) masked address; hk_chainInfo carries node_version + peers.
#   2. a 5th node joins from genesis → node0 lists it as INBOUND within seconds; node4 lists the
#      four validators as OUTBOUND; connected_secs climbs.
#   3. the 5th node stops → node0's table drops back to 3 (no stale entries).
#   4. an ISLAND (fresh genesis, same binary) dials node0 → refused by the genesis gate,
#      islands_refused >= 1, identified peers still 3; the island sees 0 identified peers.
#   5. every validator's table names the other three by the peer ids they report as `self`.
set -uo pipefail
cd "$(dirname "$0")"
H="${HK_DEVNET_HOME:-$HOME/hk-devnet}"
BIN="$(readlink -f "${CARGO_TARGET_DIR:-target}/release/hk-node")"
PROVER="${HK_PROVER_URL:-http://127.0.0.1:9911}"
# the version tag every peer must advertise = the binary's own (`hk-node version` prints "hk-node vX.Y.Z")
VER="$("$BIN" version 2>/dev/null | awk '{print $2}')"; [[ -z "$VER" ]] && VER=$(grep -o 'NODE_VERSION: &str = "[^"]*"' crates/hk-node/src/main.rs | cut -d'"' -f2)
PASS=0; FAIL=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
rpc()  { local p=${3:-}; [[ -z "$p" ]] && p="{}"; curl -s -m 5 -X POST "http://127.0.0.1:$1" -d "{\"method\":\"$2\",\"params\":$p}"; }
h_of() { rpc "$1" hk_chainInfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["height"])' 2>/dev/null || echo 0; }
wait_h(){ local port=$1 target=$2 tries=${3:-90}; for _ in $(seq "$tries"); do [[ "$(h_of "$port")" -ge "$target" ]] && return 0; sleep 2; done; return 1; }
# peer-table views: py PORT EXPR  (EXPR runs with r = hk_getPeers.result; a comma-separated EXPR
# prints SPACE-separated values — print(a,b) — so expectations below are "3 3 3 0 0", not tuples)
py(){ rpc "$1" hk_getPeers | python3 -c "import sys,json;r=json.load(sys.stdin)['result'];print($2)" 2>/dev/null; }
# wait until EXPR on PORT prints WANT (polled every 2 s)
wait_py(){ local port=$1 expr=$2 want=$3 tries=${4:-25}; for _ in $(seq "$tries"); do [[ "$(py "$port" "$expr")" == "$want" ]] && return 0; sleep 2; done; return 1; }
noansi(){ sed -r 's/\x1b\[[0-9;]*[mK]//g' "$1"; }
has(){ noansi "$1" | grep -E -- "$2" >/dev/null; }
start_env(){ local home=$1 log=$2; shift 2; ( cd "$H" && exec env "$@" HK_PROVER_URL="$PROVER" RUST_LOG=info nohup "$BIN" start "$home" </dev/null >>"$log" 2>&1 ) & }

echo "== 1 · fresh 4-validator devnet: the table is measured"
./devnet.sh --fresh -n 4 --prover-url "$PROVER" >/dev/null
wait_h 26000 5 60 && ok "devnet deciding (height $(h_of 26000))" || { bad "devnet did not reach height 5"; exit 1; }
wait_py 26000 "r['identified']" 3 15
V=$(py 26000 "r['count'],r['identified'],r['inbound']+r['outbound'],r['public_addr'],r['islands_refused']")
[[ "$V" == "3 3 3 0 0" ]] && ok "node0: 3 peers, 3 identified, 0 public addresses, 0 islands: $V" || bad "node0 table: $V"
V=$(py 26000 "sorted({(p['version'],p['genesis'],p['private_addr']) for p in r['peers']})")
[[ "$V" == "[('$VER', 'match', True)]" ]] && ok "every peer: version $VER · genesis match · private addr" || bad "peer tags: $V"
V=$(py 26000 "sorted({p['addr'].rsplit('/',1)[0] for p in r['peers']})")
[[ "$V" == "['/ip4/127.0.0.0/tcp']" ]] && ok "addresses masked to the /24: $V" || bad "masking: $V"
S=$(py 26000 "r['self']['peer_id'][:8]+' '+r['self']['version']+' '+r['self']['genesis_digest'][:8]")
[[ "$S" == 12D3KooW*" $VER "* ]] && ok "self: $S" || bad "self block: $S"
C=$(rpc 26000 hk_chainInfo | python3 -c 'import sys,json;r=json.load(sys.stdin)["result"];print(r["node_version"],r["peers"])' 2>/dev/null)
[[ "$C" == "$VER 3" ]] && ok "hk_chainInfo.node_version + peers: $C" || bad "chainInfo: $C"

echo "== 2 · a 5th node joins: inbound on node0, outbound on node4"
rm -rf "$H/node4"; "$BIN" keygen "$H/node4" ext-4 >/dev/null; cp "$H/node0/genesis.json" "$H/node4/genesis.json"
PEERS=$(for i in 0 1 2 3; do printf '/ip4/127.0.0.1/tcp/%d,' $((27000+i)); done | sed 's/,$//')
"$BIN" config-gen "$H/node4" --listen /ip4/127.0.0.1/tcp/27004 --peers "$PEERS" --rpc 127.0.0.1:26004 --metrics 127.0.0.1:29004 >/dev/null
start_env "$H/node4" "$H/node4.log"
wait_py 26000 "r['identified']" 4 30 && ok "node0 sees 4 identified peers within $((30*2)) s" || bad "node0 identified: $(py 26000 "r['identified']")"
wait_py 26004 "len(r['self']['peer_id'])>0" True 30 || bad "node4 RPC never answered hk_getPeers"
N4=$(py 26004 "r['self']['peer_id']")
V=$(py 26000 "next(((p['direction'],p['version'],p['genesis']) for p in r['peers'] if p['peer_id']=='$N4'),None)")
[[ "$V" == "('inbound', '$VER', 'match')" ]] && ok "node0 lists node4 as inbound · $VER · match" || bad "node4 on node0: $V"
wait_py 26004 "r['identified']" 4 30
V=$(py 26004 "sorted({p['direction'] for p in r['peers']}),r['count']")
[[ "$V" == "['outbound'] 4" ]] && ok "node4 lists the four validators, all outbound" || bad "node4 table: $V"
A=$(py 26000 "next((p['connected_secs'] for p in r['peers'] if p['peer_id']=='$N4'),-1)"); sleep 4
B=$(py 26000 "next((p['connected_secs'] for p in r['peers'] if p['peer_id']=='$N4'),-1)")
[[ "$B" -gt "$A" ]] && ok "connected_secs climbs ($A → $B)" || bad "connected_secs $A → $B"
T=$(( $(h_of 26000) + 3 )); wait_h 26004 "$T" 150 && ok "node4 synced from genesis to $T (a peer, not just a socket)" || bad "node4 did not sync"

echo "== 3 · the 5th node leaves: no stale entries"
pkill -f "hk-node start $H/node4"; sleep 1
wait_py 26000 "r['count']" 3 30 && ok "node0 back to 3 peers after node4 stopped" || bad "node0 count after node4 left: $(py 26000 "r['count']")"
V=$(py 26000 "any(p['peer_id']=='$N4' for p in r['peers'])")
[[ "$V" == "False" ]] && ok "node4's entry is gone" || bad "node4 still listed"

echo "== 4 · an island chain is refused and counted, never listed"
rm -rf "$H/island"; HK_PROVER_URL="$PROVER" "$BIN" testnet 1 "$H/island" >/dev/null
"$BIN" config-gen "$H/island/node0" --listen /ip4/127.0.0.1/tcp/27010 --peers /ip4/127.0.0.1/tcp/27000 --rpc 127.0.0.1:26010 --metrics 127.0.0.1:29010 >/dev/null
GI=$(python3 -c "import hashlib;print(hashlib.sha256(open('$H/island/node0/genesis.json','rb').read()).hexdigest()[:8])")
G0=$(python3 -c "import hashlib;print(hashlib.sha256(open('$H/node0/genesis.json','rb').read()).hexdigest()[:8])")
[[ "$GI" != "$G0" ]] && ok "island genesis $GI != devnet genesis $G0" || bad "island genesis equals the devnet's"
: > "$H/island.log"; start_env "$H/island/node0" "$H/island.log"
wait_py 26000 "r['islands_refused']>=1" True 30 && ok "node0 refused the island (islands_refused=$(py 26000 "r['islands_refused']"))" || bad "node0 never refused the island"
sleep 3
V=$(py 26000 "r['identified'],sorted({p['genesis'] for p in r['peers'] if p['identified']})")
[[ "$V" == "3 ['match']" ]] && ok "node0 still 3 identified peers, all genesis match" || bad "node0 after island: $V"
has "$H/node0.log" "refusing island chain" && ok "node0 log: 'refusing island chain'" || bad "no refusal line in node0.log"
wait_py 26010 "r['islands_refused']>=1" True 30
V=$(py 26010 "r['identified'],r['islands_refused']>=1")
[[ "$V" == "0 True" ]] && ok "the island sees 0 identified peers and refuses us too" || bad "island table: $V"
pkill -f "hk-node start $H/island/node0"; sleep 1

echo "== 5 · every validator names the other three by their own ids"
AGREE=1
declare -A SELF
for p in 26000 26001 26002 26003; do SELF[$p]=$(py $p "r['self']['peer_id']"); done
for p in 26000 26001 26002 26003; do
    WANT=$(for q in 26000 26001 26002 26003; do [[ $q != $p ]] && echo "${SELF[$q]}"; done | sort | tr '\n' ' ')
    GOT=$(py $p "' '.join(sorted(p['peer_id'] for p in r['peers']))+' '")
    [[ "$GOT" == "$WANT" ]] || { AGREE=0; echo "  port $p: got [$GOT] want [$WANT]"; }
done
[[ "$AGREE" == 1 ]] && ok "4/4 tables are exactly the other three self ids" || bad "peer ids disagree"
U=$(printf '%s\n' "${SELF[@]}" | sort -u | wc -l)
[[ "$U" == 4 ]] && ok "four distinct self peer ids" || bad "self ids not distinct ($U)"

echo
echo "== N1 GATE: $PASS passed, $FAIL failed"
[[ "$FAIL" == 0 ]] && echo "GATE GREEN — the peer table is live: joins appear, leaves vanish, islands are refused and counted, versions and genesis tags are visible." || echo "GATE RED — read the FAIL lines and $H/node*.log"
