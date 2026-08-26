# HashKinetics — The Lawful-Access Model

**One page for regulators, law enforcement, and diligence. Decision D8 (2026-08-26, constitutional): there is no master view key, and one can never be added — the commitment scheme has no slot for it. What exists instead is stronger for lawful process. ⚠ DRAFT — counsel review required before use with any official.**

## The principle

Disclosure on HashKinetics is **selective, process-bound, and cryptographically verifiable**. Every private payment carries a disclosure capability held by its parties; every regulated surface has visibility enforced by consensus itself; nobody — including the founding team — holds bulk access. Lawful authority flows the way it does in banking: through *legal process against identified persons and regulated entities*, not through a skeleton key to the vault.

## Who can see what, under which process

| Need | Instrument | Process | Scope | Status |
|---|---|---|---|---|
| Contents of one payment | **One-time disclosure package** — offline-verifiable (amount, memo, commitment, inclusion proof, all hash-bound) | Court order / subpoena against a payment's sender or recipient | Exactly one payment; the key opens nothing else (measured: 0 of 21 others) | **LIVE** |
| A subject's incoming activity over a period | **Epoch viewing keys** — discovery + decryption for one epoch, no spend authority | Warrant / compelled production against the holder | That wallet, those epochs, incoming only | **LIVE** |
| An organization's full agent-fleet flows | **Parent-mandate standing viewing key** over the delegation subtree | Regulatory requirement on the entity (charter, license condition, examination) | The org's own subtree, continuously | P3.3 (machinery live; subtree derivation in build) |
| Originator/beneficiary data at exchanges | **CASP disclosure envelopes** — IVMS-101 travel-rule payloads sealed between regulated counterparties, required by consensus rule at registered ramps | Existing VASP obligations (FinCEN travel rule / FATF R.16 / EU TFR) | Every flow crossing a regulated boundary | P3.3 |
| A stablecoin issuer's regulatory view | **Issuer-scoped standing key** over its own issuance | Issuer partnership terms | The issuer's asset, all of it | P3 (WS-E) |
| "Did they show us everything?" | **Bonded completeness attestations** — the holder stakes a bond slashed on any contradicting evidence | Attached to compelled disclosures | Makes partial disclosure economically suicidal | P3.3 (v0) → provable completeness (P4 research) |
| Non-cooperative / deceased subject, envelope tier | **Threshold committee** — multiple independent parties jointly act under process; no single party can act alone | Committee policy + legal process | Envelope-tier records | Policy design (founder-owned) |
| Systemic integrity | The **transparent skeleton**: pool conservation total, nullifier set, validator set — public | None needed | No hidden inflation is possible | **LIVE** |

## Why there is no master key — stated plainly

1. **It would be the highest-value theft target in the system's history.** One leak, one coerced insider, one hostile state, and every user's privacy is destroyed *retroactively* — adversaries already harvest ciphertexts today to decrypt later. A master key converts one bad day into total, permanent compromise.
2. **Capability creates obligation — to every jurisdiction at once.** Whoever *can* decrypt *must* answer compulsion from any government that can reach them (incl. key-disclosure statutes abroad). Structural inability to perform bulk decryption is what keeps the operator answerable to *process* rather than to *pressure* — from anyone.
3. **It answers the question badly.** There are no account balances in the shielded pool to look up — only notes. "This person's finances" is correctly and completely reconstructed by process against the person and their counterparties (the instruments above), which also produces *court-grade evidence*: every disclosed fact re-verifies offline from hashes, versus the probabilistic clustering heuristics transparent-chain forensics rely on and defense counsel increasingly defeat.
4. **It would end the institutional use case** — treasuries will not transact where an operator (or its compromiser) sees everything — and with it the network the compliance regime is supposed to oversee.

## What law enforcement gains here vs. transparent chains

Deterministic, self-verifying evidence instead of heuristics · mandatory, consensus-enforced travel-rule data at ramps instead of best-effort VASP compliance · bonded truthfulness of compelled disclosures · regulator-required standing visibility over regulated entities' agent fleets · and a clean legal theory: the subpoena target is always an identifiable person or licensed entity, exactly as in banking.

*Confidential draft · not legal advice · counsel sign-off required before external use · provenance: LIVE items are demo-gated on the running devnet; P3/P4 items carry their build-plan references.*
