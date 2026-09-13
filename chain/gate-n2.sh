#!/usr/bin/env bash
# gate-n2.sh -- the N2 receipt (v0.19.3): a validator that RESTARTS and dials in before its previous
# connection has died still learns its peer's gossipsub subscriptions — and therefore still proposes.
#
# The bug (testnet-1 seat #10, 2026-09-13): rust-libp2p gossipsub 0.49.5 sends its subscriptions to
# a peer only on the FIRST connection to that peer id (`on_connection_established`:
# `if other_established > 0 { return }`). A node whose old socket lingered while its new process
# dialed in was treated as an additional connection: it never received the hello, held the gateway
# with an empty topic set, and `publish()` failed with NoPeersSubscribedToTopic on every topic
# (proposal parts AND votes) for eight hours while it kept receiving everything and looked in sync.
# The v0.19.3 patch (vendor/external/rust-libp2p-gossipsub, marked `HK v0.19.3`) re-announces the
# subscriptions on every additional connection and whenever a connection closes while others remain.
#
#   ./gate-n2.sh                       # needs hk-prove on 127.0.0.1:9911 (vk pins for the devnet genesis)
#
# What it proves (each line is a PASS/FAIL):
#   1. 4-validator devnet; node3's proposer slots (heights with h % 4 == 0) commit in round 0.
#   2. THE RACE, reproduced: node3 is frozen with SIGSTOP (its sockets stay open — no FIN, no RST, exactly a
#      process that has not been torn down yet); a copy of its home starts as node3b (same p2p identity,
#      same consensus key — node3 is frozen, so nothing double-signs) on other ports, dialing node0 only.
#      node0 sees "New connection from known peer" while node3's frozen connection still lives.
#   3. THE FIX: node0 (patched) re-announces its subscriptions on the additional connection and again when
#      the frozen connection dies (ping timeout, ~25 s); node3b's slots commit in round 0 afterwards and its
#      log has no NoPeersSubscribedToTopic after the stale close. (Before the patch: every node3b slot in
#      round 1, NoPeersSubscribedToTopic on each — the 1XP picture.)
#   4. node0's peer table shows the restart that connected_secs alone hid: reconnects >= 1,
#      last_connection_secs small, one live connection.
set -uo pipefail
cd "$(dirname "$0")"
H="${HK_DEVNET_HOME:-$HOME/hk-devnet}"
BIN="$(readlink -f "${CARGO_TARGET_DIR:-target}/release/hk-node")"
PROVER="${HK_PROVER_URL:-http://127.0.0.1:9911}"
VER="$("$BIN" version 2>/dev/null | awk '{print $2}')"; [[ -z "$VER" ]] && VER=$(grep -o 'NODE_VERSION: &str = "[^"]*"' crates/hk-node/src/main.rs | cut -d'"' -f2)
PASS=0; FAIL=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
note() { echo "  INFO  $*"; }
rpc()  { local p=${3:-}; [[ -z "$p" ]] && p="{}"; curl -s -m 5 -X POST "http://127.0.0.1:$1" -d "{\"method\":\"$2\",\"params\":$p}"; }
h_of() { rpc "$1" hk_chainInfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["height"])' 2>/dev/null || echo 0; }
wait_h(){ local port=$1 target=$2 tries=${3:-90}; for _ in $(seq "$tries"); do [[ "$(h_of "$port")" -ge "$target" ]] && return 0; sleep 2; done; return 1; }
py(){ rpc "$1" hk_getPeers | python3 -c "import sys,json;r=json.load(sys.stdin)['result'];print($2)" 2>/dev/null; }
wait_py(){ local port=$1 expr=$2 want=$3 tries=${4:-25}; for _ in $(seq "$tries"); do [[ "$(py "$port" "$expr")" == "$want" ]] && return 0; sleep 2; done; return 1; }
noansi(){ sed -r 's/\x1b\[[0-9;]*[mK]//g' "$1"; }
has(){ noansi "$1" | grep -E -- "$2" >/dev/null; }
cnt(){ noansi "$1" | grep -cE -- "$2"; }
# the commit round of a height (from node0's view)
round_of(){ rpc 26000 hk_getBlock "{\"height\":$1}" | python3 -c 'import sys,json;r=json.load(sys.stdin)["result"];print(r["certificate"]["round"] if r.get("found") else "?")' 2>/dev/null; }
# rounds of the slots with residue R (h % 4 == R) in [from, to] — printed as "h:r h:r …"
slots(){ local from=$1 to=$2 R=$3 out=""; for ((h=from; h<=to; h++)); do (( h % 4 == R )) || continue; out+="$h:$(round_of $h) "; done; echo "$out"; }
# rounds of every height in [from, to] — "h:r h:r …"
rounds(){ local from=$1 to=$2 out=""; for ((h=from; h<=to; h++)); do out+="$h:$(round_of $h) "; done; echo "$out"; }
start_env(){ local home=$1 log=$2; shift 2; ( cd "$H" && exec env "$@" HK_PROVER_URL="$PROVER" nohup "$BIN" start "$home" </dev/null >>"$log" 2>&1 ) & }

curl -s -m 5 -X POST "$PROVER" -d '{"method":"health","params":{}}' | grep -q result || { echo "hk-prove not reachable at $PROVER"; exit 1; }

echo "== 1 · fresh 4-validator devnet: node3 proposes in round 0"
./devnet.sh --fresh -n 4 --prover-url "$PROVER" >/dev/null
wait_h 26000 12 60 && ok "devnet deciding (height $(h_of 26000))" || { bad "devnet did not reach height 12"; exit 1; }
# node0 with gossipsub at debug so the two HK re-announce lines are visible (info elsewhere)
pkill -f "hk-node start $H/node0"; sleep 2
: > "$H/node0.log"; start_env "$H/node0" "$H/node0.log" RUST_LOG=info,libp2p_gossipsub=debug
wait_py 26000 "r['identified']" 3 30 && ok "node0 restarted with gossipsub=debug, 3 peers identified" || { bad "node0 did not come back"; exit 1; }
N=$(rpc 26000 hk_getValidators | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["count"])')
[[ "$N" == 4 ]] && ok "4 seats, equal power — the proposer of height h is seat (h-1) % 4 in the set's order" || bad "seat count $N"
# node0 just restarted: its own first slot after the restart can time out (it was still wiring the
# verifier) — let a full rotation pass before sampling the baseline (first run: 15:1 for exactly that)
T=$(h_of 26000); wait_h 26000 $((T+6)) 60
T=$(h_of 26000); wait_h 26000 $((T+9)) 60
S=$(rounds $((T+1)) $((T+9)))
[[ "$S" != *":1"* && "$S" != *":?"* ]] && ok "baseline: every height in round 0: $S" || bad "baseline rounds: $S"
P3=$(py 26003 "r['self']['peer_id']")
[[ "$P3" == 12D3KooW* ]] && ok "node3 peer id $P3" || bad "node3 peer id: $P3"
# node3's seat: its consensus address (SHAKE-256 over "hk/v1/validator-address", the same derivation as
# hk-node keygen prints) looked up in the set's order (power desc, then address) → its slots are h % 4 == R
A3=$(python3 - "$H/node3/genesis.json" <<'EOF2'
import json,hashlib,struct,sys
g=json.load(open(sys.argv[1])); pk=bytes(g['validators'][3]['public_key'])
h=hashlib.shake_256(); h.update(b'hk/v1/validator-address'); h.update(b'\x00'); h.update(struct.pack('<Q',len(pk))); h.update(pk)
print(h.digest(32)[:20].hex().upper())
EOF2
)
R=$(rpc 26000 hk_getValidators | python3 -c "import sys,json;v=[x['address'] for x in json.load(sys.stdin)['result']['validators']];i=v.index('$A3');print((i+1)%4)")
[[ "$R" =~ ^[0-3]$ ]] && ok "node3 = seat $A3 → proposer of the heights with h % 4 == $R" || { bad "node3's seat index (address $A3): '$R'"; R=0; }

echo "== 2 · the race: freeze node3 (sockets stay open), start its twin node3b dialing node0 only"
PID3=$(pgrep -f "hk-node start $H/node3\$" | head -1); [[ -z "$PID3" ]] && PID3=$(pgrep -f "hk-node start $H/node3 " | head -1)
[[ -n "$PID3" ]] && ok "node3 pid $PID3" || { bad "node3 pid not found"; exit 1; }
kill -STOP "$PID3" && ok "node3 frozen with SIGSTOP (no FIN, no RST — the connection lingers; ping times it out in ~25 s, so the twin dials in NOW)" || bad "SIGSTOP failed"
rm -rf "$H/node3b"; cp -a "$H/node3" "$H/node3b"   # a consistent copy: nothing writes while node3 is stopped
python3 - "$H/node3b/config.toml" <<'EOF'
import re,sys
p=sys.argv[1]; s=open(p).read()
s=s.replace('/tcp/27003"','/tcp/27013"').replace('127.0.0.1:26003"','127.0.0.1:26013"').replace('127.0.0.1:29003"','127.0.0.1:29013"')
s=re.sub(r'persistent_peers = \[[^\]]*\]', 'persistent_peers = ["/ip4/127.0.0.1/tcp/27000"]', s)
open(p,'w').write(s)
EOF
grep -q '/tcp/27013"' "$H/node3b/config.toml" && grep -q 'persistent_peers = \["/ip4/127.0.0.1/tcp/27000"\]' "$H/node3b/config.toml" && ok "node3b: same home, ports 27013/26013/29013, peers = node0 only" || bad "node3b config rewrite"
# counts BEFORE the twin dials in: node0's own restart above produced mutual dials (2 connections per peer),
# so both re-announce lines and a "Connection closed" for node3 may already be in the log — only INCREASES count
K0=$(cnt "$H/node0.log" "New connection from known peer.*$P3"); A0=$(cnt "$H/node0.log" "Additional connection to a known peer: re-announcing subscriptions")
C0=$(cnt "$H/node0.log" "Connection closed with $P3"); X0=$(cnt "$H/node0.log" "A connection closed while others remain: re-announcing subscriptions")
PT0=$(py 26000 "next(((p['connections'],p['reconnects']) for p in r['peers'] if p['peer_id']=='$P3'),None)")
note "node0 peer table for node3's id before the twin: (connections, reconnects) = $PT0 (the mutual dial after node0's restart already counts)"
: > "$H/node3b.log"; start_env "$H/node3b" "$H/node3b.log" RUST_LOG=info
T0=$(date +%s)
for _ in $(seq 30); do [[ "$(cnt "$H/node0.log" "New connection from known peer.*$P3")" -gt "$K0" ]] && break; sleep 1; done
[[ "$(cnt "$H/node0.log" "New connection from known peer.*$P3")" -gt "$K0" ]] && ok "node0: 'New connection from known peer' for node3's id while the frozen connection lives ($(( $(date +%s) - T0 )) s)" || bad "node0 never logged the additional connection"
V=$(py 26000 "next(((p['connections'],p['reconnects']) for p in r['peers'] if p['peer_id']=='$P3'),None)")
W=$(python3 -c "c,r=$PT0;print((c+1,r+1))")
[[ "$V" == "$W" ]] && ok "node0 peer table: one more connection and one more reconnect for node3's id: $V" || note "node0 peer table right after the dial: $V (expected $W; the frozen connection may already be gone)"
sleep 1
[[ "$(cnt "$H/node0.log" "Additional connection to a known peer: re-announcing subscriptions")" -gt "$A0" ]] && ok "node0 (patched): re-announced its subscriptions on the additional connection" || bad "no re-announce on the additional connection (is node0 the patched binary?)"

echo "== 3 · the fix: the frozen connection dies on ping timeout; node0 re-announces; node3b proposes"
for _ in $(seq 60); do [[ "$(cnt "$H/node0.log" "Connection closed with $P3")" -gt "$C0" ]] && break; sleep 1; done
[[ "$(cnt "$H/node0.log" "Connection closed with $P3")" -gt "$C0" ]] && ok "node0: the frozen connection closed ($(( $(date +%s) - T0 )) s after the twin dialed in)" || bad "the frozen connection never closed (ping timeout?)"
sleep 1
[[ "$(cnt "$H/node0.log" "A connection closed while others remain: re-announcing subscriptions")" -gt "$X0" ]] && ok "node0 (patched): re-announced its subscriptions after the stale close" || bad "no re-announce after the stale close"
E0=$(cnt "$H/node3b.log" "NoPeersSubscribedToTopic")
note "node3b logged NoPeersSubscribedToTopic $E0 time(s) while the frozen connection lived (the 1XP symptom; 0 only means no slot fell in that window)"
sleep 6
# node3b must be at the tip and at least two of its slots must commit in round 0 from here
T=$(h_of 26000); wait_h 26013 "$T" 60 && ok "node3b at the tip ($T)" || bad "node3b behind: $(h_of 26013) vs $T"
T=$(h_of 26000); wait_h 26000 $((T+12)) 90
S=$(slots $((T+4)) $((T+12)) "$R")
[[ -n "$S" && "$S" != *":1"* && "$S" != *":?"* ]] && ok "after the fix: node3b's slots (h % 4 == $R) in round 0: $S" || bad "node3b slots after the fix: $S"
E1=$(cnt "$H/node3b.log" "NoPeersSubscribedToTopic")
[[ "$E1" == "$E0" ]] && ok "no new NoPeersSubscribedToTopic on node3b after the stale close ($E0 → $E1)" || bad "node3b still cannot publish: NoPeersSubscribedToTopic $E0 → $E1"
V=$(py 26000 "next(((p['connections'],p['reconnects'],p['last_connection_secs']<120,p['connected_secs']>p['last_connection_secs']) for p in r['peers'] if p['peer_id']=='$P3'),None)")
W=$(python3 -c "c,r=$PT0;print((1,r+1,True,True))")
[[ "$V" == "$W" ]] && ok "node0 peer table: 1 live connection · reconnects $(python3 -c "c,r=$PT0;print(r+1)") · last_connection_secs recent · connected_secs kept (the restart is visible now)" || bad "peer table after the race: $V (expected $W)"

echo "== 4 · cleanup"
kill -KILL "$PID3" 2>/dev/null; pkill -f "hk-node start $H/node3b"; sleep 1
note "node3 killed, node3b stopped; the devnet keeps running on node0..2 (./devnet.sh stop to end it)"

echo
echo "== N2 GATE: $PASS passed, $FAIL failed"
[[ "$FAIL" == 0 ]] && echo "GATE GREEN — a restarted validator behind a lingering connection learns its peer's subscriptions and proposes again." || echo "GATE RED — read the FAIL lines, $H/node0.log (grep re-announcing) and $H/node3b.log (grep NoPeersSubscribedToTopic)"
