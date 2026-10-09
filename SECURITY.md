# Security Policy

HashKinetics is a settlement layer: bugs here can move money. We take reports seriously
and we pay attention fast.

## Reporting a vulnerability

**Email: security@hashkinetics.org** (PGP key on request).
Do not open public issues for security-relevant findings.

- Acknowledgement within **48 hours**, an assessment within **7 days**.
- **Coordinated disclosure:** give us **90 days** (or agree a timeline with us) before
  any public disclosure. We credit reporters in the release notes and the CHANGELOG (as for R15, R16 and R17 — Alboy; R18 — secwatch-hunt)
  unless you prefer anonymity.
- Testnet findings are in scope and valued — that is what the testnet is *for*.

## Scope

Everything in this repository, with special interest in: the state machine and its
commitment (`hk-state`), consensus signing and rotation (`hk-consensus`, `hk-crypto::hashsig`
— stateful signatures: leaf reuse leaks one-time key material (repeated reuse of one leaf
makes forgery cheap) and is defended by reserve-then-sign with a directory-fsynced state
write — R16, reported 2026-09-22, fixed in v0.19.4 (released the same day); follow-ups: a
floor from the node's own evidence and a reservation window; R17, reported 2026-10-06 by Alboy, nine
findings fixed in v0.19.6 the same day (the asset-bound mandate rule activates at testnet-1
height 1,872,500); R18, reported 2026-10-04 by secwatch-hunt, fixed in v0.19.8 (settlement
hashing bounded; consensus rule at testnet-1 height 2038500)), the spend/mint circuits and aggregation digests (`zkvm-bakeoff/circuit`),
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
