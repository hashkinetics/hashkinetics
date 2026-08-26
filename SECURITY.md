# Security Policy

HashKinetics is a settlement layer: bugs here can move money. We take reports seriously
and we pay attention fast.

## Reporting a vulnerability

**Email: security@hashkinetics.org** (PGP key published in this file after launch week).
Do not open public issues for security-relevant findings.

- Acknowledgement within **48 hours**, an assessment within **7 days**.
- **Coordinated disclosure:** give us **90 days** (or agree a timeline with us) before
  any public disclosure. We credit reporters in the release notes and the hall of record
  unless you prefer anonymity.
- Testnet findings are in scope and valued — that is what the testnet is *for*.

## Scope

Everything in this repository, with special interest in: the state machine and its
commitment (`hk-state`), consensus signing and rotation (`hk-consensus`, `hk-crypto::hashsig`
— stateful signatures: leaf reuse is catastrophic by design and defended by
reserve-then-sign), the spend/mint circuits and aggregation digests (`zkvm-bakeoff/circuit`),
the durable store and replay path (`hk-node/src/store.rs`, `state.rs`), and the disclosure
machinery (`hk-wallet`). The ten consensus-critical invariants an attacker should try to
break are enumerated in `docs/AUDIT-SCOPE.md` and the yellowpaper — consider that a map.

## Honest status

**Nothing here is audited yet.** This code runs a public testnet with valueless tokens;
professional audits and a public audit competition are scheduled ahead of any
value-bearing mainnet, and mainnet launches guarded (value caps that lift as findings
close). Do not deploy this to hold real value in the meantime. The full list of open
caveats lives in the README's honesty ledger — we keep it current on purpose.

## Bounties

A funded bug-bounty / audit-competition program is planned alongside the audit campaign;
until it opens, exceptional reports will be recognized retroactively when the program
launches.
