# Security Policy

HashKinetics is a settlement layer: bugs here can move money. We take reports seriously
and we pay attention fast.

## Reporting a vulnerability

**Email: security@hashkinetics.org** (PGP key on request).
Do not open public issues for security-relevant findings.

- Acknowledgement within **48 hours**, an assessment within **7 days**.
- **Coordinated disclosure:** give us **90 days** (or agree a timeline with us) before
  any public disclosure. We credit reporters in the release notes and the CHANGELOG (as for R15 — Eddy, an external operator; R16 — an independent researcher, named as soon as they say so; R17 — Alboy, with its M-1 and L-1 (the voting-power bound, the atomic write) also reported independently by Mansor; R18 — secwatch-hunt; RZ-1 — Reza; M-1, the prover trust model — Tuan Berdasi, the documents corrected 2026-10-23 and the circuit change pending)
  unless you prefer anonymity.
- Testnet findings are in scope and valued — that is what the testnet is *for*.

## Scope

Everything in this repository, with special interest in: the state machine and its
commitment (`hk-state`), consensus signing and rotation (`hk-consensus`, `hk-crypto::hashsig`
— stateful signatures: leaf reuse leaks one-time key material (repeated reuse of one leaf
makes forgery cheap) and is defended by reserve-then-sign with a directory-fsynced state
write — R16, reported 2026-09-22, fixed in v0.19.4 (released the same day); follow-ups: a
floor from the node's own evidence and a reservation window; R17, reported 2026-10-04 by Alboy (read 10-06), nine
findings fixed in v0.19.6 the same day (the asset-bound mandate rule activates at testnet-1
height 1,872,500); R18, reported 2026-10-04 by secwatch-hunt, fixed in v0.19.8 (settlement
hashing bounded; consensus rule at testnet-1 height 2038500); RZ-1, reported 2026-10-14 by Reza,
fixed in v0.19.9 (a malformed consensus signature is refused, never a
panic — the vendored parser made total, length gates at decode and before parsing, a panic
boundary around the verify; client-only, every node restarts on it)), the spend/mint circuits and
aggregation digests (`zkvm-bakeoff/circuit` — M-1, reported 2026-10-14 by Tuan Berdasi: the spend
signature covers only `credit ‖ fee`, so until circuit v4 the prover a wallet sends its witness to is
trusted with the value of every spend it proves — the documents corrected 2026-10-23, the circuit
change on testnet-1 through the planned verifying-key schedule and on mainnet at the genesis pin),
the durable store and replay path (`hk-node/src/store.rs`, `state.rs`), the disclosure
machinery (`hk-wallet`), and the Node Key sale contract `HKNodeKey` (Ethereum mainnet
`0x36edb45c4610AE2A7FE6334343D9D958Fb81EC84`, source verified on Etherscan and Sourcify;
bug bounty up to 1 ETH for a report that shows how funds could be lost or locked — paid
from proceeds at our discretion; do not test against the live contract with other people's
money). The ten consensus-critical invariants an attacker should try to
break are enumerated in `docs/AUDIT-SCOPE.md` and the yellowpaper — consider that a map.

## Honest status

**Nothing here is audited yet.** This code runs a public testnet with valueless test units (the network has no token);
professional audits and a public bug bounty on the audit-freeze code are scheduled ahead of any
value-bearing mainnet, and mainnet launches with value caps enforced by consensus (plan); each
lift is published with its reason. Do not deploy this to hold real value in the meantime. The full list of open
caveats lives in the README's honesty ledger — we keep it current on purpose.

## Bounties

The Node Key sale contract (`HKNodeKey`) carries a bug bounty of up to 1 ETH today. A funded bug bounty for the chain, on the audit-freeze code, is planned alongside the audit campaign;
until it opens, exceptional reports will be recognized retroactively when the program
launches.

## Reports, not code

We accept reports, not code: security findings and reproductions are credited; every fix and its tests are written in-house. External pull requests are closed with a pointer to this section; the finding inside them is handled like any report.
