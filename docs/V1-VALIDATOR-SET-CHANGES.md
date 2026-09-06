# V1 — validator-set changes on a running chain

**Status: implemented 2026-09-04 (v0.14.0); devnet gate `chain/gate-v1.sh` 25/25; rolled to every testnet-1 seat on 2026-09-04 (R7, one voter at a time, heights 55641 → 56023, chain never paused; `hk_getValidators.pending_set_changes` live on the public RPC). Activated: the first set change may now commit; minimum node version for testnet-1 becomes v0.14.0 at that moment.** This is the item that gated the soak clock: until it ships, every external cohort needs a new genesis, so no external voter can ever join testnet-1. After it, a seat is admitted or removed by a certificate that rides an ordinary block. **G1 (v0.18.0 → v0.18.1, 2026-09-06): bootstrap governance — at testnet-1 height 110,000 the four genesis seats are re-weighted to power 4 by rule (§6), and a third certificate kind, `SetPower`, moves weight by approval; devnet gate `chain/gate-v1.sh` + `chain/gate-g1.sh`.**

## 1 · The rule

A **`SetChangeCert`** admits one seat (`Admit { root_pk, public_key, voting_power }` — exactly the `validator.json` that `hk-node keygen` prints, plus a power), removes one (`Remove { root_pk }`) or, since v0.18.0, re-weights one in place (`SetPower { root_pk, voting_power }`, power ≥ 1; operational key, epoch and address untouched — §6). It is authorized by **approvals from the current seats' stateless SLH-DSA-192s roots** — the same keys that certify each seat's own rotations — and it is valid only if

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

**Discipline.** One change at a time on the live network; wait for the receipt before the next. Never approve a body you did not read (`set-change.json` is plain JSON: chain id, change, window). The candidate's node must be at the tip and on our `app_hash` **before** the window opens; a seated node that is not running costs liveness — at power 1 per seat, ⅔ of 5 is 4 and ⅔ of 6 is 5, so one absent seat is survivable, two are not. `hk_getValidators.max_absent_power` says how much power may be absent right now; after G1 (§6) the founding seats carry the line themselves.

## 4 · Files

`chain/crates/hk-consensus/src/setchange.rs` (certificate, verification, application, tests) · `hk-node/src/batch.rs` (v1/v2 wire) · `hk-node/src/state.rs` (`pending_set_changes`, proposer inclusion, `apply_set_changes` on commit + replay, HK-R6 history) · `hk-node/src/rpc.rs` (`hk_submitSetChange`, `hk_getValidators.pending_set_changes`) · `hk-node/src/main.rs` (`set-change propose|approve|assemble`) · `chain/gate-v1.sh` (the devnet receipt: admit → vote → refusals → remove → sync from genesis across both boundaries). G1: `hk-consensus/src/setchange.rs` (`SetPower`, `reweight_roots`, `quorum_power`) · `hk-node/src/genesis.rs` (`bootstrap_for`: the activation table) · `hk-node/src/state.rs` (the re-weight at the activation height, live + replay) · `hk-node/src/rpc.rs` (`hk_getValidators` power view) · `hk-node/src/main.rs` (`set-change propose --set-power`) · `chain/gate-g1.sh`.

## 5 · Honesty

Voting power was 1 per seat until v0.18.0; from testnet-1 height 110,000 the four genesis seats weigh 4 each (§6) and the approval rule is a supermajority of **power** — a bootstrap governance with a published, dated handover, not the mainnet one (bonds, slashing, governance are P-lane). Proposer scheduling is round-robin over the set, so admitting a seat shifts the schedule by construction. Nothing here changes the state machine or the state commitment; the validator set is not part of `app_hash` (it never was), it is derived deterministically by every node from the same certificates.

## 6 · Bootstrap governance (G1, v0.18.0 → v0.18.1)

**What forced it (2026-09-06).** Two external seats had joined at power 1 (§3 receipts in `CHANGELOG.md` 0.15.2): six seats, six power, quorum 5. Two consequences the founders had not intended: (a) a set change now needed an external co-signature (4 of 6 is not > ⅔), so the seventh operator's admission would have hung on a seat that was three days old; (b) **liveness depended on external machines** — both external VPSs down = the chain halts. A seat this young must hold neither a veto nor a liveness lever while the network is this small; the honest fix is at the protocol level, published, dated, and undone by the same mechanism.

**The rule.** At the **activation height** every node re-weights the **genesis seats** — the roots listed in `genesis.json` `validators[]`, the four ceremony keys — to the **founding power**, in place (operational key, epoch, address untouched), effective `height + 1`, recorded in the HK-R6 set history like any certificate. No proposal, no signatures: the rule is in the binary every node runs, so it is exactly as authoritative as the genesis itself and applies identically on a live commit, on restore-from-store replay and on a sync from genesis. A genesis seat that had been removed before the height is not re-seated; a seat admitted by certificate is never touched.

| network | activation height | founding power | source |
|---|---|---|---|
| testnet-1 `hashkinetics-1-4e4ea68d` | **110,000** | **4** | hard-wired by chain id (`hk-node/src/genesis.rs`; the environment cannot move it) |
| any other chain id (devnets) | `HK_G1_HEIGHT` | `HK_G1_POWER` (default 4) | environment; unset = no activation |

**The arithmetic (testnet-1, power 1 per external seat).** Founding power 16; quorum `2·total/3 + 1`.

| external seats | total | quorum | founders alone decide? | founders can pass a set change alone? | max absent power |
|---|---|---|---|---|---|
| 0 | 16 | 11 | yes (3 of 4 suffice) | yes | 5 |
| 2 (today) | 18 | 13 | yes — all four; 3 founders + 1 external also | yes (16 > 12) | 5 |
| 3 (after seat #7) | 19 | 13 | yes — all four; 3 + 1 also | yes | 6 |
| 7 | 23 | 16 | yes — all four | yes (3·16 = 48 > 46) | 7 |
| 8 | 24 | 17 | **no** (16 < 17) | **no** (48 = 48) | 7 |

So weight 4 holds strict > ⅔ up to **seven** external seats of power 1; the eighth seat, or any earlier handover, is a `SetPower` certificate, never a binary. What the founders give up: one founding seat absent **and** every external seat absent still halts the chain (12 of 18 is not > ⅔) — the founding fleet keeps its four seats up as it always has; what nobody can do any more: stall the chain or block a change by switching off external machines.

**`SetPower` — the handover tool.** `SetChange::SetPower { root_pk, voting_power }` (signing tag `0x03`, power ≥ 1 — use `Remove` to unseat) re-weights one seated root in place under the same approval rule (> ⅔ of the current power, window, chain id, idempotent when the power already matches). `hk-node set-change propose <HOME> --set-power <root_pk hex> --power N …`, then approve / assemble / submit exactly as §3. The handover schedule is a dated milestone in `docs/MASTER-BUILD-PLAN.md`: founding weight lowered by certificate (4 → 1, one seat per change) once external seats have proved a soak — never silently, always with a receipt in `CHANGELOG.md`.

**Read it back.** `hk_getValidators` now answers `total_power, founding_power, external_power, quorum_power, max_absent_power, founders_alone_decide, bootstrap {height, founding_power, active}` and marks each validator `genesis: true|false` (`docs/RPC.md`). The activation logs `G1 BOOTSTRAP GOVERNANCE ACTIVATED — genesis seats re-weighted` on every node at the same height; a `SetPower` commit logs `Validator RE-WEIGHTED (G1 set-power)` and `hk_getBlock.set_changes[].change` reads `set_power`.

**Activation discipline (the third one, after `AccountCreate` and V1).** Every node must run **≥ v0.18.1 before height 110,000** (v0.18.0 named 200,000 and was withdrawn the same evening, never rolled — the number moved BEFORE it was reached, as the rule allows; it never moves after). A v0.17 node keeps counting power 1 per seat: the first commit certificate after the height that carries founding votes only (16 of 18 — valid) fails its ⅔ check at power 1 (4 of 6 — not valid) and that node stops following, loudly. It also cannot decode a block carrying a `SetPower` certificate. Announcement, checksums and the roll order are in `ops/RELEASE-NOTES-v0.18.1.md`; the founding fleet rolls first, one voter at a time, each proven voting; the external operators are told the height and the day, and the `/network` page says which versions are seen.

**Gate.** `chain/gate-g1.sh` (activation at devnet height 40 from the environment): before the height 4 seats · power 1 · quorum 3 · `bootstrap.active false`; at H+1 on every node power 4-4-4-4, total 16, quorum 11, `founders_alone_decide`, the log line, identical `app_hash`, the chain keeps deciding; a fifth (external) seat admitted with **three** founding approvals; `SetPower` 1 → 3 by certificate (`set_power` in the block; power 0 refused by shape); the external node killed — the chain advances on the founders; node0 restarted on its persisted home re-derives the weights; node5 from genesis syncs across the activation and both certificates.
