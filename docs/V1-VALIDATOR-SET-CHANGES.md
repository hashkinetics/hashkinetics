# V1 — validator-set changes on a running chain

**Status: implemented 2026-09-04 (v0.14.0); devnet gate `chain/gate-v1.sh` 25/25; rolled to every testnet-1 seat on 2026-09-04 (R7, one voter at a time, heights 55641 → 56023, chain never paused; `hk_getValidators.pending_set_changes` live on the public RPC). Activated: the first set change may now commit; minimum node version for testnet-1 becomes v0.14.0 at that moment.** This is the item that gated the soak clock: until it ships, every external cohort needs a new genesis, so no external voter can ever join testnet-1. After it, a seat is admitted or removed by a certificate that rides an ordinary block.

## 1 · The rule

A **`SetChangeCert`** admits one seat (`Admit { root_pk, public_key, voting_power }` — exactly the `validator.json` that `hk-node keygen` prints, plus a power) or removes one (`Remove { root_pk }`). It is authorized by **approvals from the current seats' stateless SLH-DSA-192s roots** — the same keys that certify each seat's own rotations — and it is valid only if

- `body.chain_id` is this chain's id (no cross-network replay; the id is the SHA-256 of the genesis file),
- every approval comes from a **distinct seat of the set as it stands**, with a valid root signature over the domain-separated body (`hk/v1/set-change` ‖ chain id ‖ change ‖ window),
- the approving voting power is **strictly more than ⅔** of the set's total (3·approving > 2·total),
- the commit height lies inside `[not_before, not_after]` (a certificate expires — one approved and forgotten cannot surface months later),
- application is idempotent (admitting a seated root or removing an unseated one is a no-op), a removal can never empty the set, and an admitted operational key may not collide with a seated address.

No coordinator key, no new genesis field. The seats that hold the chain today vote a seat in or out, offline. Mainnet replaces the approval rule with bonded self-admission + governance; the certificate shape, the window and the per-height set history stay.

## 2 · How it moves

`RotationCert` was the template: the cert rides a block (`Batch.set_changes`), every node re-verifies it **against the set as it stands at that commit height** (a block may carry several — they apply sequentially), a valid one changes the set **for `height + 1`**, and the change is recorded in the HK-R6 per-height set history so commit certificates on either side of the boundary verify against the right keys. Live commits and restore-from-store replay run the same code; a node syncing from genesis derives the same set.

**Wire:** a batch with no set change encodes **byte-identical to the v1 wire** (every block before the first admission keeps its bytes; a pre-v0.14 node keeps decoding). A batch that carries one is framed as v2 (8-byte magic `HK-BLK-2`). Hence the activation rule, same as `AccountCreate` in v0.11.0: **every node must run ≥ v0.14.0 before the first set change commits.** A v0.13 node would fail to decode that block, apply an empty batch, diverge on the parent commitment and halt — loudly, by design.

**The newly seated node** was already running as an observer with the same key: it has been verifying every block; from `height + 1` the engine finds its address in the set and it signs. Its log says `THIS NODE now holds a voting seat`. An unseated node keeps verifying as an observer and spends no more one-time leaves.

## 3 · Operator runbook (testnet-1)

The founder seats are `hk-val-0/1/2` and `hk-gateway`; approvals from any three (3·3 = 9 > 2·4 = 8) admit a seat. Every step below is offline except the last.

```bash
# 0 · the candidate ran `hk-node keygen` and sent validator.json (public halves only)
#     and has been syncing as an observer with THAT key (its app_hash matches ours).

# 1 · propose (any host with the network's genesis.json; window = commit heights)
TIP=$(curl -s -X POST http://127.0.0.1:26000 -d '{"method":"hk_chainInfo","params":{}}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["height"])')
hk-node set-change propose ~/hk-node --admit candidate-validator.json --power 1 --not-before $((TIP+50)) --not-after $((TIP+5000))
#   → ~/hk-node/set-change.json  (chain id read from ~/hk-node/genesis.json)

# 2 · approve — ON EACH APPROVING SEAT'S HOST (needs its priv_validator_key.json; the key never moves)
hk-node set-change approve ~/hk-node set-change.json        # → approval-<root8>.json (an SLH-DSA signature, ~16 KB)

# 3 · assemble (anywhere): verifies each approval over the body, prints the cert
hk-node set-change assemble set-change.json approval-*.json -o cert.json

# 4 · submit through ANY live seat — it rides that seat's next proposal inside the window
printf '{"method":"hk_submitSetChange","params":%s}' "$(cat cert.json)" | curl -s -X POST http://127.0.0.1:26000 -d @-
curl -s -X POST http://127.0.0.1:26000 -d '{"method":"hk_getValidators","params":{}}'    # count, seats, pending_set_changes
```

Receipt of a seat: `hk_getValidators.count` up by one on every node at the same height; the candidate's `hk_chainInfo.signer.remaining` starts **falling** (leaves are only spent by signing; an observer's never moves); its log line `THIS NODE now holds a voting seat`. Removal mirrors it (`--remove <root_pk hex>`; the departing seat may approve its own removal — it counts toward the ⅔ while it is seated).

**Discipline.** One change at a time on the live network; wait for the receipt before the next. Never approve a body you did not read (`set-change.json` is plain JSON: chain id, change, window). The candidate's node must be at the tip and on our `app_hash` **before** the window opens; a seated node that is not running costs liveness — with 5 seats, ⅔ of 5 is 4, so one absent seat is survivable, two are not.

## 4 · Files

`chain/crates/hk-consensus/src/setchange.rs` (certificate, verification, application, tests) · `hk-node/src/batch.rs` (v1/v2 wire) · `hk-node/src/state.rs` (`pending_set_changes`, proposer inclusion, `apply_set_changes` on commit + replay, HK-R6 history) · `hk-node/src/rpc.rs` (`hk_submitSetChange`, `hk_getValidators.pending_set_changes`) · `hk-node/src/main.rs` (`set-change propose|approve|assemble`) · `chain/gate-v1.sh` (the devnet receipt: admit → vote → refusals → remove → sync from genesis across both boundaries).

## 5 · Honesty

Voting power is 1 per seat and the approval rule is a supermajority of seats — a testnet governance, not the mainnet one (bonds, slashing, governance are P-lane). Proposer scheduling is round-robin over the set, so admitting a seat shifts the schedule by construction. Nothing here changes the state machine or the state commitment; the validator set is not part of `app_hash` (it never was), it is derived deterministically by every node from the same certificates.
