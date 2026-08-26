# HashKinetics: A Post-Quantum, Shielded-by-Default Settlement Layer for the AI-Agent Economy

**Whitepaper v1.0 · 2026-08-18 · Yaduvendra Mukherjee, HashKinetics**
**Token: $HKN · Network: HashKinetics mainnet (shielded by default)**

---

## Abstract

Autonomous software agents have become economic actors: they hold budgets, purchase services from one another at machine speed, and fail in ways that human-oriented payment infrastructure was never designed to contain. HashKinetics is a sovereign Layer-1 blockchain purpose-built for this population. It combines three properties that no other production network offers simultaneously: **post-quantum settlement** (every signature that moves money or secures consensus is hash-based; no elliptic curves, no lattice signatures), **shielded-by-default balances** (agent budgets, counterparties, and payment flows are hidden behind hash commitments and verified by STARK proofs — with scoped, holder-initiated, offline-verifiable lawful disclosure), and **consensus-enforced spending hierarchies** (organizations delegate budgets to agents through MandateTrees whose caps are enforced by validators themselves, over balances the chain cannot see). Payments meter through hash-chain micropayment channels at effectively unbounded rates and settle on-chain in single transactions. The proof system is deliberately pairing-free: the deployable artifact is always a raw STARK, and per-block recursive aggregation gives every validator exactly one constant-size proof to verify regardless of transaction count. This paper specifies the full protocol as deployed on mainnet, its cryptographic doctrine and threat model, its economics and governance, the measured performance envelope it was built against, and the phased, demo-gated engineering history that produced it.

---

## 0 · Status and provenance

This whitepaper describes the complete HashKinetics protocol in the present tense of a running mainnet. In keeping with the project's documentation doctrine — dated claims, measured numbers, no promises dressed as facts — readers should note the provenance of every quantitative statement:

- **Measured** numbers (proof latencies, block cadence, aggregate sizes, test counts, demo transcripts) originate from the 2026 development network on documented hardware (AMD Threadripper PRO 7995WX, NVIDIA RTX 5090, WSL2), recorded in the repository's engineering logs (`docs/MASTER-BUILD-PLAN.md`, `zkvm-bakeoff/RESULTS.md`). They are facts about that environment.
- **Configured** numbers (block capacity, timeout pacing, tree depths, window sizes) are protocol constants chosen deliberately and changeable by the documented upgrade paths.
- **Design targets** (mainnet-scale throughput, validator-set size, market behavior of fee and bond mechanisms) are engineering projections with named assumptions, validated progressively through the gate process described in §17.

Nothing in this document is an offer of tokens or securities. The honesty ledger that accompanied every development release remains a maintained artifact in the repository.

---

## 1 · Introduction: two clocks

Two independent developments define the moment this network was built for.

**The first clock: machine customers arrived.** Payment-protocol consortia for agent commerce (x402 and its foundation, with premier members spanning card networks, processors, and cloud providers; Google's AP2; the ERC-8004 identity registry) moved agent payments from thesis to industry. Cumulative agent-initiated transactions crossed the hundreds of millions. And the failure data arrived on schedule: a majority of enterprises deploying agents report at least one agent-caused incident, and a third report direct financial loss. Every widely deployed mitigation shares one architectural weakness — spending caps live in the application layer, in dashboards, SDKs, and policy engines that a compromised or jailbroken agent simply ignores. An agent holding raw key material *is* its principal; nothing between it and the ledger says otherwise.

**The second clock: the quantum deadline became official.** Regulators and standards bodies stopped treating post-quantum migration as optional. The IETF drafts post-quantum requirements for x402 payment *receipts*; the EU's AMLR Article 79 regime (applicable July 1, 2027) reaches crypto-asset service providers and explicitly contemplates "optional privacy features"; Ethereum's own long-horizon roadmap (the "Lean" program) converges on hash-based signatures and STARK proofs — the exact stack this network launched with. Meanwhile the harvest-now-decrypt-later problem makes *confidentiality* migration urgent even before signature forgery is feasible: everything encrypted to classical KEMs today is a future plaintext.

At the intersection sits an unoccupied position. Post-quantum **settlement** (not just receipts). Privacy that is **native and default** (not bolted on, and not the un-listable absolutism that gets networks delisted). Spending authority that is **a consensus rule** (not an app-layer suggestion). Each pairwise combination is structurally hard: post-quantum privacy requires proof systems without pairings; consensus-enforced caps over hidden balances require careful composition of public authorization with private value; post-quantum consensus requires taming stateful hash-based signatures inside a BFT engine. HashKinetics is the demonstration that all three compose.

The design brief, fixed at inception and unchanged since: *allowances for AI agents, enforced at the protocol level — confidential like a bank account, disclosable like one too.*

---

## 2 · Design doctrine

Six invariants govern every design decision. They are constitutional in the governance sense of §14: no parameter vote can remove them.

**D-1 · Pure hash-based signatures.** Every signature that authorizes value movement or secures consensus rests on the collision/preimage resistance of standardized hash functions alone: SLH-DSA-SHAKE-192s (FIPS 205) stateless roots as permanent identities; LMS/HSS (RFC 8554, over SHAKE-256) for consensus votes; WOTS one-time signatures for shielded spend authorization inside the circuit; PayWord hash chains for channel micropayments. There are **no lattice signatures anywhere** — not as a fallback, not in a hybrid. Hash-based signatures are the most conservative post-quantum assumption in existence; Grover-type attacks are answered by parameter size, and there is no algebraic structure to break.

**D-2 · The doctrine split: ML-KEM is confidentiality-only.** The single non-hash primitive in the system is ML-KEM-768 (FIPS 203), used exclusively for note encryption and stealth-address key agreement. The asymmetry is deliberate and load-bearing: if lattice cryptanalysis ever breaks ML-KEM, an adversary can *read metadata* — payment discovery, memos — but can never *move funds*, because spend authority never touches a lattice. Privacy degrades gracefully; custody does not degrade at all.

**D-3 · F1: no pairing-based proof wraps, ever.** The popular "small proof" paths of general-purpose zkVMs (Groth16/PLONK wraps over BN254) are pairing-based and therefore not post-quantum. HashKinetics bans them outright. The deployable proof artifact is always a **raw compressed STARK** (hashes and field arithmetic only), and the size/verification targets that wraps usually solve are met instead by recursive STARK aggregation (§8). F1 was adopted the day it was discovered during the proving bake-off and has shaped every proving decision since.

**D-4 · Shielded by default.** Privacy is the product, not a mode. At mainnet, value lives in the shielded pool unless a holder explicitly unshields. Development networks ran transparent-first while circuits hardened — and were never marketed otherwise.

**D-5 · CVA: disclosure is scoped, holder-initiated, and offline-verifiable.** The network rejects both surveillance-by-default and privacy-that-cannot-comply. Disclosure granularity is one payment or one epoch; packages verify with no chain access; **no master viewing key exists structurally** (§11). This is the Compliant Virtual Asset design.

**D-6 · Consensus-guarded stateful signatures.** Stateful hash signatures are traditionally considered operationally hazardous (reuse a one-time leaf and you leak key material). HashKinetics inverts the hazard into protocol rules: leaf index = account nonce as a consensus rule, so the ledger itself polices one-time-ness; observed reuse (equivocation) is slashable evidence; signers persist state with reserve-then-sign discipline — the durable record advances *before* a signature is released, so a crash can never replay a leaf.

Two hash functions serve the whole system: **SHAKE-256, domain-separated, everywhere outside circuits** (a registry of domain tags covers every use: transaction digests, tree nodes, nullifiers, key derivation, wire identifiers), and **SHA-256 inside circuits** for pool v1 — chosen by measurement, not ideology (§8.5), and rotatable through version pools if a future proof tier makes an arithmetization-friendly hash the better trade.

---

## 3 · System overview

The chain is two planes with a value-conserving bridge:

```
            TRANSPARENT SKELETON  (the machine plane)
   validators & staking · MandateTree skeletons · channel anchors
   CASP envelope registry · account nonces & key commitments
                       │  mint / burn  (bridge)
                       ▼
            SHIELDED POOL  (the user plane)
   notes (hash commitments) — append-only commitment tree — nullifier set
        every spend: a STARK proof, verified by every validator
        every block: ONE recursive aggregate proof covers them all
```

The **transparent skeleton** carries what must be public for the machine economy to function: who the validators are, which mandate envelopes exist and their public caps, where channels are anchored, which compliance envelopes a service provider has registered. It deliberately carries no user balances.

The **shielded pool** carries value. A unit of value is a *note* — a hash commitment binding an amount, an owner address tag, and blinding randomness. Notes enter the pool by minting (shielding transparent value; the mint proof is the inflation guard), move by shielded spends (consuming a note via a nullifier, producing two output notes — payment and change), and exit by unshielding (a spend whose public `fee` component credits a transparent account). A fully shielded transfer (`fee = 0`) leaves **no transparent residue whatsoever**: the chain records one nullifier, two commitments, and nothing else. Who paid whom is cryptographically absent.

Three actor roles surround the ledger. **Agents** hold wallet key material, prove their own spends locally (~1.2 s on workstation-class GPUs, measured), and meter high-frequency commerce through channels. **Validators** run BFT consensus with hash-based votes and verify STARKs in-node; they never see balances. **Aggregators** (the proposer in v1; a bonded, fee-earning role at scale) fold a block's individual proofs into one recursive aggregate. Facilitators, view services, and watchtowers are permissionless service roles built on the same primitives.

---

## 4 · Cryptographic foundations

### 4.1 The key hierarchy

Every long-lived identity in the system is anchored by a **stateless SLH-DSA-SHAKE-192s root** (48-byte public key, category-3 security). Stateless roots never exhaust and never carry reuse hazards; they sign rarely and only to *certify* — primarily, rotations of operational keys. Beneath each root live **stateful operational trees**:

- Validators: LMS/HSS trees (RFC 8554 over SHAKE-256) sign every consensus vote and proposal. The deployed profile gives tens of thousands of signatures per tree at ~millisecond sign/verify; when a tree nears exhaustion, the root certifies a successor (§5.3) — **there is no root exhaustion**, and therefore no end-of-life for a validator identity.
- Agent accounts: hash-based account keys whose **leaf index is the account nonce** by consensus rule (§2, D-6). The development-era Lamport ratchet (each transaction opens the current key commitment and commits to the next) matured into multi-use XMSS/LMS account keys with the same consensus-guarded discipline.
- Shielded spend authority: per-address **WOTS one-time keys** organized in spend trees (§7.4) — the circuit itself enforces one-time semantics.
- Channels: **PayWord hash chains** — a payment is the preimage of the previous payment, verification is one hash.

A single 32-byte master seed derives a validator's entire identity family (root, operational tree, network transport key); agent wallets similarly derive spend trees, nullifier keys, and per-epoch KEM keys from one seed.

### 4.2 Domain separation

Every hash application in the protocol is domain-separated: `H(tag ‖ data)` with `tag` drawn from a registry of versioned ASCII tags (`hk/v1/…`) covering transaction signing digests, transaction identifiers, block values, tree nodes, nullifiers, address tags, key derivations, note encryption keys and MACs, aggregation coverage, and verifying-key pins. Two different uses of SHAKE-256 can never collide by construction; the registry is part of the protocol specification and audit surface.

### 4.3 Ed25519, demoted

Ed25519 exists in exactly one place: libp2p transport identity (peer authentication for the gossip layer). It secures no ledger state and signs no consensus message. A discrete-log break would let an adversary impersonate a *network endpoint* — annoying, detectable, and harmless to funds. This demotion was completed in development (release 0.9.0) and is a permanent property of the network.

---

## 5 · Consensus

### 5.1 Engine and votes

HashKinetics runs Malachite, a Rust BFT engine implementing Tendermint-lineage consensus, instantiated with a custom signing scheme: **every prevote, precommit, and proposal is signed with LMS/HSS**. Vote signing and verification cost ~milliseconds; the measured development cadence was **~1.4 s blocks at round 0** with four validators, dominated by deliberately conservative timeout pacing rather than cryptography. Consensus sign-bytes are manual, domain-tagged byte layouts — independent of any serialization codec by construction (§12.2).

### 5.2 State binding: divergence is consensus-fatal

The proposer binds its **parent application hash** (the state commitment it built on) into the block batch, and the batch bytes are hashed into the value identifier that validators vote on. A validator whose state has diverged computes a different commitment and *cannot* vote for the proposal — state divergence is not a log line, it is a consensus failure, surfaced immediately.

### 5.3 SCMS: rotation under a stateless root

The Stateful Consensus-key Management System answers the operational objection to stateful signatures in consensus:

1. Each validator's genesis entry carries its permanent SLH-DSA root public key alongside its initial operational LMS/HSS key.
2. When an operational tree approaches exhaustion (or on demand), the validator's root signs a **RotationCert** — `{root_pk, new_op_pk, epoch, valid_from_height, root_sig}` — with strictly monotone epochs (replay and rollback are rejected).
3. The cert rides in a block. On commit, *every* node applies the rotation to its validator set; the owning validator swaps its live signer in the same commit, in lockstep. This was demonstrated live in development: rotation mid-chain with zero missed blocks and continued round-0 commits.
4. The engine is the **single consensus signer** per node, and its monotone `used ‖ state` record is fsynced *before* any signature is released (reserve-then-sign). This closed a real bug found by treating the devnet as mainnet — two signers briefly derived from one seed had reused a leaf — and the fix (plus its disclosure) is part of the network's verification culture (§16.3).

### 5.4 Signature bandwidth

Hash-based votes are kilobytes, not bytes. At mainnet scale the answer is structural, not apologetic: **STARK-compressed quorum certificates** — a checkpoint proof attesting that a supermajority of the registered validator set signed, so light clients and history sync verify one recursive proof instead of storing every vote (§18, P4 track). Full nodes retain full vote sets over a rolling window.

---

## 6 · The transparent skeleton: accounts, mandates, channels

### 6.1 Accounts

A transparent account is an identifier, a balance map, a nonce, and a hash commitment to its current authentication key. Transactions open the commitment, sign the payload together with the commitment to the *next* key, and advance the nonce — the leaf-index-equals-nonce rule making one-time-ness a ledger property. Account creation, fee mechanics, and the merkleized global commitment follow the hardening track (§17.4).

### 6.2 MandateTree v2 — spending hierarchies in consensus

The MandateTree is the network's signature primitive: a tree of budget envelopes, created and funded by an organization, delegated downward, and **enforced by validators at transaction admission**.

Each node (mandate) carries: a holder (the principal allowed to spend under it), an asset, a **drip rate** (budget accrues continuously, `rate_per_sec`, up to `buffer_max` — allowances refill rather than reset), a **per-transaction cap**, an expiry, and a parent link. The semantics that make it an economic instrument rather than a limiter:

- **Attenuation at creation:** a child's per-transaction cap can never exceed its parent's. Enforced when the tree is built, not discovered at spend time.
- **Deliberate oversubscription, global enforcement:** a root with a $45 envelope may promise its children $65 in aggregate. Every spend walks the **entire ancestor chain**, drawing down each level's buffer; the first level with insufficient buffer refuses the spend. Delegation is a promise; the envelope is the law.
- **Org pays, agent authorizes:** funds move from the root's funding account, but authority comes from the leaf holder's signature — exactly the allowance model: the child never holds the vault key.
- **Two-phase atomicity:** authorization (`check`, read-only) strictly precedes effects; a refusal never half-mutates state. The refusal is itself a first-class artifact — a typed, human-readable receipt: `rejected: mandate: insufficient buffer at depth 1 from leaf (have 5000000, need 10000000)`.
- **Cascade revocation:** revoking a node severs every descendant instantly, because every descendant spend must walk through it.

Section §10 composes this machinery with the shielded pool — the network's defining feature.

### 6.3 QHT channels: machine-speed micropayments

On-chain settlement at machine speed is neither necessary nor desirable; channels do the metering. A channel opens **under a mandate leaf** (escrow = `unit_price × max_steps`, drawn through the ancestor walk exactly once, at funding), anchored by the tip of a PayWord hash chain. Each micropayment reveals the next preimage — one 32-byte word, one hash to verify, no signatures at all in the hot loop. Settlement is proof-carrying: *any* sender (the payee, or a watchtower acting for it) submits the deepest word received, and the chain pays `steps × unit_price` in one transaction. Expiry refunds unspent escrow to the payer.

The measured development demonstration settled **1,000 metered API calls in a single on-chain transaction**; a facilitator ran a real retrieval service priced per query on this exact loop and earned on-chain. Chain-side, a settle costs the same as any transaction — which is why channels are the throughput multiplier of §13. Longer chains (the step counter is a 32-bit integer) and the hypertree-channel upgrade (re-arming chains under one anchor for long-lived relationships) extend the same construction.

---

## 7 · The shielded pool

### 7.1 Notes and commitments

A note is `(value, owner, ρ, rcm)`: a 64-bit amount, a 32-byte owner address tag, a uniqueness nonce ρ, and commitment randomness. Its on-chain form is the hash commitment `cm = H_note(value ‖ owner ‖ ρ ‖ rcm)` (canonical encoding; SHA-256 in-circuit, per §8.5). Commitments reveal nothing; ownership and value exist only inside proofs.

### 7.2 The commitment tree, anchors, and nullifiers

Commitments append to a depth-32 Merkle tree maintained in **frontier form** — O(32) hashes and O(32) stored nodes per insertion. Every block seals the current root as an **anchor**; a 128-block anchor window lets spenders prove membership against any recent root (proof-building race tolerance) while bounding validator anchor storage.

Double-spends are prevented by **nullifiers**: spending a note publishes `nf = H_nf(nk ‖ ρ)`, where `nk` is the owner's *secret* nullifier key. The nullifier set is forever; a repeated nullifier is refused with a typed receipt. Two properties are deliberate: a nullifier is *unlinkable* to its commitment without `nk`, and — because `nk` never leaves the owner — **not even the sender of a payment can watch for its spend**. (The sender knows ρ; without `nk` that knowledge is inert. This closed a real linkage-analysis review flag during development.)

Conservation is tracked publicly in aggregate only: the pool's `total_shielded` moves at mints and unshields, so the transparent world always knows *how much* the pool holds and never *whose*.

### 7.3 Transactions

**MintToPool (shield).** Debits `value` from the sender's transparent balance and appends `cm`. The accompanying mint proof is the **inflation guard**: it attests `cm` opens to exactly `value` — no hidden extra — while `owner, ρ, rcm` stay private. The first mint pins the pool's asset (single-asset v1; multi-asset is a versioned upgrade).

**ShieldedSpend.** Publishes `(anchor, nf, cm₁, cm₂, fee, credit?, mandate?)` plus a proof (or aggregate coverage, §8.3). Value equation: `v_in = v_out1 + v_out2 + fee` — payment plus change plus an optional public component. `fee > 0` with a `credit` account is the **unshield channel**; `fee = 0` is a fully shielded transfer. Spends are **proof-carrying and relayable**: any account may carry the envelope, because authority lives in the proof, not the envelope signature.

**The binding rule (anti-malleability).** The circuit commits to `tx_binding = H_bind(credit ‖ fee)`, and the chain *derives the expected public statement from the transaction's own fields* before verifying. A relayer that alters where unshielded value lands changes the expectation and the proof no longer verifies. Nothing about the public effects of a spend is malleable in transit.

### 7.4 Addresses and spend authority: the spend tree

An address is `(tag, kem_pk)`: a public **address tag** plus an ML-KEM public key for note delivery (§9). The tag is

```
tag = H_addr( spend_root ‖ H_nk(nk) )
```

binding two secrets' fingerprints: the root of the holder's **spend tree** and the hash of the nullifier key. A spend tree is a Merkle tree (protocol depth 10) over WOTS one-time public keys, all derived from the wallet's master seed; wallets choose an actual capacity `2^h ≤ 2^10` and pad with a precomputed empty ladder, making addresses cheap to generate and rotate. Spending note `n` under `tag`:

1. The wallet signs the spend statement digest with the next unused WOTS leaf (reserve-then-sign; the leaf index persists before signing).
2. **In-circuit**, the WOTS public key is *recovered from the signature itself* (chains completed to their ends; the checksum blocks walk-forward forgery) — no public key travels in the witness, which cut witness size by ~85% during development.
3. The recovered key is folded up the spend tree along an authentication path to `spend_root`, and the circuit checks `tag = H_addr(spend_root ‖ H_nk(nk))` against the note's owner field.

Result: addresses are *public and reusable*; each **spend** consumes a fresh one-time key enforced by the statement itself; and payment requires only the tag — the payer cannot spend, track (no `nk`), or claw back. Lifetime-unbounded addresses via an XMSS^MT hypertree layer are a measured-before-merged upgrade (decision D5): host-side keygen, not circuit cost, is the binding constraint.

### 7.5 The spend statement (circuit v3)

Public inputs: `(anchor, nf, cm₁, cm₂, fee, tx_binding)`. Witness: input note `(v, tag, ρ, rcm)` + Merkle path; WOTS signature + spend-tree path; `nk`; output notes. The circuit enforces:

```
cm_in  = H_note(v ‖ tag ‖ ρ ‖ rcm)          and  Merkle(cm_in, path) = anchor
wots_pk = Recover(sig, digest)               and  Fold(wots_pk, ots_path) = spend_root
tag    = H_addr(spend_root ‖ H_nk(nk))       (ownership binds to BOTH secrets)
nf     = H_nf(nk ‖ ρ)                        (secret-key nullifier)
cm₁    = H_note(out₁),  cm₂ = H_note(out₂)   (two outputs: payment + change)
v      = v₁ + v₂ + fee                       (conservation; 64-bit range discipline)
tx_binding = H_bind(credit ‖ fee)            (public-effect binding)
```

The same `no_std` circuit crate is compiled into the prover guests **and** linked by the chain's state machine as its hashing library — tree bytes on-chain and in-circuit cannot diverge, a property pinned by a keystone test that feeds a chain-built path into the circuit and demands the identical root and nullifier.

---

## 8 · The proving system

### 8.1 Stack and the bake-off

The client prover is **SP1** (a RISC-V zkVM), selected by a measured bake-off of the *actual* spend statement across SP1, RISC Zero, and OpenVM rather than by vendor benchmarks. The journey defines the envelope: the unoptimized baseline proved the full statement in ~26 minutes; the SHA-256 precompile removed 60% of cycles; the WOTS witness redesign (recover-the-key) removed 56% more; CUDA delivered the rest. **Final: 604,993 cycles, proving in ~1.24 s** (core mode, RTX 5090, warm) — and the production circuit v3, a strictly larger statement, holds at **1.19–1.38 s**. Agents prove their own payments on workstation-class GPUs; a documented hardware requirement, not a footnote.

### 8.2 F1 in practice

Under F1 (§2, D-3), the network never emits or verifies a pairing wrap. Core proofs (~2.7 MB) and compressed proofs (~1.24 MB) are raw STARKs; validators verify them in-node (~87 ms) against pinned keys. The size problem that wraps normally solve is answered by recursion:

### 8.3 The aggregation tier: one proof per block

An **aggregator guest** — itself an SP1 program — *verifies N compressed spend/mint proofs inside the zkVM* and commits a digest that binds, in order: each statement's kind, its verifying key, and its public values, plus the count. The block then carries the N transactions **proof-less** alongside ONE aggregate STARK. Validators verify the aggregate once and install per-block **coverage**: a proof-less pool transaction is valid *iff* the verified aggregate covered exactly the statement the chain derives from that transaction's fields. Coverage clears at block end; nothing about the trust model changes — a transaction may always carry its own proof instead (the per-proof fallback is legal, and was exercised live in the same demonstration).

Measured: the aggregate is **1,242 KB — constant regardless of N** — proved in ~2.9 s at N=3 on one development GPU. At N=50 that is ~25 KB of wire per spend; at a full 256-transaction block, ~1.9 MB total. Verification cost per validator per block: one STARK, ~100 ms. Aggregation composes recursively — aggregates of aggregates — so aggregator throughput scales approximately linearly with proving hardware (§13, stage C3). In v1 the proposer aggregates; at scale the aggregator is a **bonded, fee-earning, slashable role** (decision D2) — proving capacity as a market.

### 8.4 Verifying-key pinning and version pools

The proof system a chain accepts is a **genesis fact**, not an operator convenience. Genesis embeds SHAKE-256 pins of the spend, mint, and aggregator verifying keys; a node whose fetched keys mismatch **refuses to start** (`vk PIN MISMATCH … refusing to start`). Circuit evolution happens through **version pools**: a new statement (or a new in-circuit hash) arrives as a new pool version with its own pins, an explicit, auditable upgrade event — hash agility as a first-class mechanism rather than a fork of meaning.

### 8.5 The in-circuit hash decision (D1)

Doctrine prefers a single hash family everywhere; measurement chose SHA-256 inside circuits for pool v1: on the locked RISC-V prover it is precompiled and measured at the numbers above, while arithmetization-friendly hashes (Poseidon2) have no precompile there and pay an order-of-magnitude penalty. The honest framing is *hash-agility over hash-dogma*: the doctrine's substance — no algebraic trapdoors, quantum-conservative assumptions — is preserved, and version pools make the in-circuit hash rotatable if a future STARK-native AIR tier changes the trade.

---

## 9 · Confidentiality and discovery

### 9.1 Stealth delivery

Every payment output carries an advisory ciphertext delivering the note to its recipient: an **ML-KEM-768 encapsulation** to the recipient's per-epoch KEM key (FIPS-203 deterministic encapsulation — reproducible from wallet state), followed by the note plaintext sealed under **SHAKE-AEAD** — an encrypt-then-MAC construction from domain-separated SHAKE-256, one-time keys, nonce bound to the commitment. No AES, no polynomial MACs; the confidentiality layer honors the same hash-first doctrine, with ML-KEM confined per D-2.

**Discovery is trial decapsulation.** A wallet scans pool ciphertexts, decapsulating each with its epoch secret; implicit rejection makes failure indistinguishable from noise. On success it decrypts, then — critically — **recomputes the commitment** and demands it match the on-chain leaf: a lying ciphertext cannot plant phantom funds. The measured demonstration is the network's signature moment: a fee-0 payment with zero transparent residue, whose recipient's wallet reported `BOB DISCOVERED: $2 — memo intact` while a third wallet scanning the same pool found nothing.

**The advisory-blob rule:** consensus stores and gossips ciphertexts but never interprets them. A malformed blob hurts only its sender (the recipient simply never discovers the payment). Scanning cost is O(outputs) per epoch key; epoch bucketing and batched view services amortize it, and oblivious message retrieval is the researched successor (§18).

### 9.2 Epoch keys

KEM keys rotate per **epoch** (a protocol-length block window); the address *tag* is epoch-stable. This yields time-scoped visibility for free: possession of one epoch's incoming viewing key grants discovery+decryption for that epoch alone — the unit of auditability in §11.

---

## 10 · Mandates × shielded: caps over invisible balances

The composition that defines the network: hierarchical spending caps, enforced by consensus, over balances nobody — including the validators enforcing them — can see.

**Mechanism (public-skeleton mode).** A `ShieldedSpend` may reference a mandate leaf. The rule set: the transaction's *envelope sender* must be the leaf's registered holder (the relayer **is** the authorizer for mandated spends); the mandate authorizes the spend's **public component** — the `fee`/unshield amount — through the full ancestor walk, drawing down every envelope on the path; authorization runs before any effect and the nullifier burns only on success. The mandate reference sits *outside* the proof, so mandated spends aggregate exactly like any other (§8.3) and the circuit is unchanged.

**What this yields.** An organization shields its treasury once. It deals allowances to agents as stealth notes — invisible amounts, invisible recipients. Agents unshield to merchants under their leaves. The org's envelope keeps its books over hidden state, and when an agent exceeds the *family's* remaining envelope — even within its own leaf cap — consensus refuses with the canonical receipt:

```
rejected: mandate: insufficient buffer at depth 1 from leaf (have 5000000, need 10000000)
```

The refused agent's note survives untouched. In the live demonstration, agents a and b unshielded $20 each under a $45 root; agent c's $10 — allowed by its own $20 leaf — died at depth 1 with $5 remaining. Hierarchy and privacy, simultaneously; the receipt is the thesis in one line.

**Hidden-amounts mode (vNext, D3).** Extending cap accounting *into* the STARK — per-mandate committed accumulators, range-proved draw-downs, so even the public `fee` skeleton disappears for shielded-to-shielded mandated flows — is specified and deliberately gated behind external circuit review. The public-skeleton mode ships the product story with the smaller proof surface.

---

## 11 · CVA: lawful disclosure without master keys

Privacy that cannot comply gets delisted; transparency that cannot be scoped is surveillance. The Compliant Virtual Asset design threads the needle with three instruments, all holder-initiated, all cryptographically scoped:

**One-time disclosure packages.** For exactly one payment, the recipient (or sender) exports a small file: the note's one-time AEAD key, the ciphertext, the commitment's Merkle inclusion path, and an anchor. Verification is a **pure offline function** — open the AEAD, recompute the commitment from the disclosed plaintext, fold the path, compare the anchor (checkable against any public chain view later). No chain access, no interaction, no verifier account. The key is one-time by construction: in the measured demonstration it opened **0 of the 21 other ciphertexts** in the pool. An auditor learns amount, memo, commitment position — and nothing else, ever.

**Epoch viewing keys (IVK).** One epoch's discovery+decryption capability: no spend authority, no nullifier key (disclosed history does not reveal *spending* of it), no other epochs. Measured: an epoch-0 IVK saw exactly the epoch-0 notes; a fresh epoch-1 payment remained invisible to it while the holder's own wallet saw it at once. Parent-mandate viewing keys extend the same shape along the delegation tree: an organization can grant an auditor its *subtree's* incoming view without touching unrelated flows.

**CASP envelopes.** For regulated service providers under AMLR Article 79 / IVMS-101 obligations, the transparent skeleton carries an envelope registry binding provider identities to disclosure commitments, so originator/beneficiary information travels as sealed, scoped attachments verifiable by the counterparty CASP — compliance data flows between the regulated parties, not into public state.

**What does not exist:** any master viewing key, any involuntary disclosure path, any governance mechanism capable of creating either (§14). **The open problem, stated as such:** disclosure *completeness* — proving a produced view is the whole truth rather than a curated subset — is handled today by bonded attestations (a provider stakes value on completeness; contradiction slashes) and is the network's flagship research program toward proof-carrying completeness (§18).

The regulatory posture is offensive, not defensive: AMLR Article 79 applies July 1, 2027, and explicitly reaches "optional privacy features." Scoped, holder-initiated, offline-verifiable disclosure is the *listing strategy* — the network launched into that news cycle with the compliance architecture as the headline.

---

## 12 · Node, wire, and the engineering it took

### 12.1 The node

A single Rust workspace: deterministic state machine (accounts, mandates, channels, pool) with typed per-transaction receipts; the Malachite engine with the hash-based signing provider; in-node STARK verification against pinned keys; mempool and JSON-RPC for wallets and services; a per-block receipt log. The state machine's proof interface defaults to **RejectAll** — an unwired verifier refuses shielded traffic rather than trusting it. Every consensus-relevant invariant is exercised by the test suite (76 tests at the mainnet-candidate snapshot), including keystone chain↔circuit consistency, two-node determinism replays, and wire-codec roundtrips.

### 12.2 The wire

The consensus wire and WAL are **binary (bincode)**; byte fields are format-aware — hex in human surfaces (RPC, receipts, genesis), raw on the wire — so a 2.7 MB proof costs ~2.7 MB, not the ~4× a naive JSON encoding measurably imposed in development (the failure was observed as gossip-limit rejections and is memorialized in the troubleshooting runbook). Two hashes are codec-independent by construction: transaction signing digests/txids (canonical JSON of fixed-field structs) and consensus sign-bytes (manual layouts) — **no signature domain can depend on the wire format**, a property enforced by tests.

### 12.3 Demo-gated engineering

The network's development discipline is part of its trust story: *nothing counts as done until it runs live.* Every increment shipped with a scripted demonstration including adversarial steps — double spends, forged proofs, lying ciphertexts, over-cap spends — shown **refused with named receipts**. Found bugs (the leaf-reuse incident; a demo-suite cross-contamination) were fixed and disclosed in the changelog rather than buried. The honesty ledger — a maintained list of what is real, measured, designed, and open — has accompanied every release since the first.

---

## 13 · Performance and capacity

### 13.1 Measured envelope (development hardware, documented in-repo)

| Metric | Value |
|---|---|
| Block cadence (4 validators, hash-signed votes) | ~1.4 s, round 0 |
| Client spend proof (core, RTX 5090) | 1.19–1.38 s |
| Mint proof | ~1.05–1.19 s |
| Compressed proof (recursion input) | 1.8–2.2 s · 1,242 KB |
| **Aggregate STARK (any N)** | **1,242 KB constant · ~2.9 s @ N=3** |
| In-node verify | ~87 ms/proof; ONE aggregate/block |
| Shielded tx, proof-less (with stealth cts) | ~2.7 KB |
| Proof on the binary wire | ~1× raw size |

### 13.2 The capacity model, tiered honestly

**Tier 1 — configured chain ceiling: ~183 TPS** (256 transactions/block ÷ 1.4 s). Both constants are deliberate development settings, not physics: the crypto in a block is milliseconds; pacing is headroom.

**Tier 2 — per-proof fallback: ~8–18 TPS** (2.7/1.24 MB per transaction against wire budgets and 87 ms serial verifies). Exists as the legal fallback; aggregation is the design path.

**Tier 3 — aggregated: chain-side returns to the batch cap** (256 × 2.7 KB + one 1.24 MB aggregate ≈ 1.9 MB/block; one verify; ~64 domain-separated hashes per transaction of state work). The binding constraint moves off-chain to **aggregator proving**; recursion trees scale it with GPUs, and client proving is distributed by construction (each agent proves its own — ~183 TPS corresponds to a few hundred concurrently proving agents).

**Tier 4 — configuration lifted: thousands of TPS, unproven.** Next walls: gossip bandwidth (10k shielded TPS ≈ 27 MB/s sustained), single-threaded apply rate, aggregator farm scale, WAN pacing floor. These are exactly what the public-testnet load benches measured before mainnet parameters were set.

**Tier 5 — effective payments: ~1,000× the settle rate.** Channels meter payments at hash speed and settle in one transaction. At the development configuration that is **~183,000 payments/s**; the multiplier is channel depth, and the step counter is 32-bit.

### 13.3 The throughput program ("the 183k plan")

Capacity work is staged and demo-gated like everything else: **C1** measure (storm harness; the aggregation scaling curve at N=10→256; apply-rate and WAN floors — producing the capacity sheet that replaces Tier-4 arithmetic), **C2** lift configuration (batch 1024+, ~1 s pacing, parallel fallback verification, admission pre-checks), **C3** aggregation at scale (tree-of-aggregates; multi-GPU scheduling; the bonded aggregator market), **C4** channel depth (10k-step ladders, watchtower settlement defaults, hypertree channels for long-lived relationships), **C5** state-machine scaling only if C1 proves it binding (merkleized commitment, parallel disjoint-nullifier apply lanes — shielded spends on distinct nullifiers commute). Milestones: M1 sustained 183 TPS · M2 full blocks under one root aggregate · M3 **≥183,000 effective payments/s demonstrated** · M4 1M+/s at lifted configuration. M1–M3 require no protocol changes.

---

## 14 · Economics and governance

### 14.1 Money on the chain

**Stablecoins are the product currency.** Agents budget, price, and settle in stables (bridged issuance first, issuer partnerships with issuer-scoped visibility as the compliance-native path). **$HKN is the security and work token:**

- **Staking** — validators bond HKN; delegation extends it; equivocation (including one-time-leaf reuse, by D-6) is slashable evidence.
- **Surety bonds** — organizations post slashable HKN behind agent-fleet envelopes: caps with skin in the game, priced by the market.
- **Aggregator work** — the fee-earning aggregation role is bonded in HKN: fold proofs, earn fees, produce garbage and be slashed.
- **Fees** — settlement fees denominated per transaction class; aggregate economics keep verification costs flat as volume grows.

Revenue streams in deployment order: settlement fees and facilitator take (bps on metered machine commerce — the paid-search loop ran in development), then bonds, staking economics, and institutional envelope integrations. Illustrative economics are labeled as such wherever they appear; the network claims no revenue it has not settled.

### 14.2 Governance: parameters vs constitution

Governance is real where it is safe and absent where it must be:

**Governable** — fee schedules, staking/bond minimums, slashing ratios, aggregator-market parameters; envelope defaults (depths, anchor-window length, epoch length); treasury and grants; **circuit/pool upgrades via version pools** (a new proof system or in-circuit hash arrives as a new pool version with fresh genesis-grade pins — explicit, auditable, opt-in migration).

**Constitutional (not up for vote)** — the six doctrines of §2. No vote can introduce a pairing wrap, admit a lattice signature to a money path, create a master viewing key or involuntary disclosure, or flip the network transparent. A governance process able to un-quantum-proof the chain or un-scope disclosure would be a bug in the constitution, not an exercise of it.

Decentralization posture is stated plainly at every stage (the development network was founder-operated and said so); the mainnet path ran founder-devnet → public incentivized testnet with external validators → post-audit mainnet with rotation-native validator operations, with each step's evidence public.

---

## 15 · Security analysis

### 15.1 Threat model against a quantum adversary

| Surface | Primitive | Quantum posture |
|---|---|---|
| Consensus votes | LMS/HSS over SHAKE-256 | Hash-based; Grover answered by parameters |
| Validator identity / rotation | SLH-DSA-SHAKE-192s | Stateless hash-based; category 3 |
| Account/spend authority | WOTS + spend trees, consensus-guarded | Hash-based; one-time enforced in-circuit |
| Channel payments | PayWord chains | Hash preimage |
| Spend validity | STARK (FRI/hashes; **no pairings**, F1) | Post-quantum sound |
| Note confidentiality | ML-KEM-768 + SHAKE-AEAD | Lattice KEM: **break leaks metadata, never funds** (D-2) |
| Transport identity | Ed25519 (libp2p only) | Classical; endpoint impersonation only — no ledger authority |

Harvest-now-decrypt-later touches only the confidentiality column, and the doctrine split (D-2) bounds its blast radius to privacy, with epoch keys already limiting any single compromise's window.

### 15.2 Protocol-level defenses

Double-spends: the forever nullifier set (replays refused, receipt-named). Proof forgery: raw STARK soundness plus byte-exact public-statement derivation — a proof is checked against what the *chain* says the transaction claims, never against prover-supplied statements. Malleability: the binding rule (§7.3). Inflation: the mint proof plus the public conservation ledger. State divergence: consensus-fatal by value-id binding (§5.2). Stateful-signature hazards: inverted into consensus rules and reserve-then-sign persistence (§2 D-6, §5.3). Lying ciphertexts: re-commitment checks at scan. Aggregate smuggling: coverage keys derive from chain-derived statements; kind, key, order, and count are digest-bound. Wire/domain confusion: signing digests are codec-independent; every hash is domain-tagged.

### 15.3 Assurance

Three independent audit tracks (consensus + state machine; STARK circuits; the stateful-key manager) gate mainnet-critical claims, with trust boundaries, a crypto inventory with KAT status, and eight consensus-critical invariants pre-mapped in the audit scope. Residual disclosures the network maintains in public: GPU-class hardware is assumed for agent-side proving; development numbers are single-machine WSL2 measurements; in-circuit WOTS awaits its full KAT campaign; the disclosure-completeness problem is open and stated as such.

---

## 16 · The road here: phases and gates

The network was built gate-by-gate, each phase exiting only on live demonstration. Dates are the engineering record.

- **P0 — the fundable demo (complete 2026-08-16).** Sovereign 4-validator devnet; MandateTree and channels as native modules; the $50 storyline executed as real transactions — including the canonical refused overspend — and 1,000 micropayments settled in one transaction; a working paid-search facilitator. *Gate G0: passed on the live demo.*
- **P1 — quantum-secure core (complete 2026-08-17).** Consensus votes swapped to LMS/HSS live (~1.4 s blocks); single-signer + reserve-then-sign after a found-and-disclosed leaf-reuse bug; SLH-DSA roots and live mid-chain rotation. The proving bake-off produced F1, the locked SP1 stack, and the 1.24 s spend proof. *Gates G1, G2: passed on measurement.*
- **P2 — the private bank opens (complete 2026-08-17).** The shielded pool as consensus state; real STARKs verified in-node; stealth payments with scanning discovery; one-time disclosure and epoch IVKs verified offline; the aggregation tier live (one constant-size proof per block); mandates composed with the pool (the thesis receipt); binary wire; vk-pinned genesis. Every increment demo-gated; the suite re-runs on command.
- **P3 — hardening to mainnet.** Public incentivized testnet (external validators, 30-day incident-free soak, load benches producing the capacity sheet of §13); the three audits; CASP envelope registry and IVMS-101 binding; stablecoin issuance path; TGE under the raise plan; **mainnet launch, shielded by default, into the AMLR Article 79 window** — with the compliance architecture as the headline.
- **P4 — scale and moats (the live roadmap).** Oblivious message retrieval replacing trial-decap scanning at population scale; **STARK-compressed quorum certificates** (light clients verify one proof; the mainnet answer to hash-signature bandwidth); hidden-structure MandateTrees and the hidden-amounts mandate circuit (D3) behind review; **disclosure-completeness proofs v1** — the research program whose bonded-attestation v0 ships today; private KYA credentials; ISO 20022 gateway pilots only with signed banking partners; an own-issuer stablecoin track.

The founding plan budgeted roughly eleven months for P0–P2; the demo-gated build delivered them in three days of founder+AI execution. That velocity — with its test culture, receipts, and disclosed bugs — is documented in the repository and is itself part of the network's case: the discipline that built it is the discipline that runs it.

---

## 17 · Related work

**Zcash / Orchard** pioneered shielded pools and viewing keys; its own improvement process concedes the commitment scheme's bindingness is not post-quantum, and its disclosure story stops short of offline-verifiable single-payment packages. **Penumbra** contributed the tiered-commitment-tree pattern this design's frontier tree simplifies from, in a Cosmos context without PQ signatures. **Monero** demonstrates the delisting cost of unscopeable privacy. **Ethereum's Lean roadmap** validates hash-based signatures + STARKs as the endgame stack — years out; HashKinetics launched there. **x402 / AP2 / ERC-8004** define agent payment, mandate, and identity envelopes at the application layer; HashKinetics is settlement infrastructure beneath them, and speaks their formats at its edges (import/export adapters, PQ receipts per the IETF drafting direction). **Mastercard's agent programs** put caps in the processor; **app-layer agent-wallet vendors** put them in dashboards — both are the foil: HashKinetics puts them in consensus. **Arcium and private-compute L1/L2s** offer privacy without post-quantum settlement. The unoccupied intersection — PQ settlement × native shielded balances × consensus-enforced hierarchy — is this network's position, and each pairwise combination is hard for structural reasons documented throughout this paper.

---

## 18 · Conclusion

HashKinetics exists because the agent economy needs what neither transparent chains nor classical privacy coins nor app-layer guardrails can provide: an allowance, not a vault key — enforced by the ledger, invisible to competitors, disclosable to the law, and secure against the adversary that arrives with a quantum computer. The network's answer is deliberately conservative cryptography composed ambitiously: hashes for authority, a lattice for nothing but secrecy, STARKs for truth, recursion for scale, hierarchy for control, and scoped disclosure for legitimacy. Every load-bearing claim in this paper traces to a measured demonstration or a named, gated plan — the receipts, literal and figurative, are in the repository.

The chain refused an overspend it could not see. Everything else follows from taking that sentence seriously.

---

## References

1. NIST FIPS 205, *Stateless Hash-Based Digital Signature Standard* (SLH-DSA), 2024.
2. NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard* (ML-KEM), 2024.
3. RFC 8554, *Leighton-Micali Hash-Based Signatures* (LMS/HSS), 2019.
4. NIST SP 800-208, *Recommendation for Stateful Hash-Based Signature Schemes*, 2020.
5. Malachite BFT engine (Informal Systems), Apache-2.0; production validation incl. Circle's Arc (2026 reporting).
6. SP1 zkVM (Succinct), v6.x; RISC Zero; OpenVM — bake-off subjects, `zkvm-bakeoff/RESULTS.md`.
7. x402 Foundation launch and membership (2026-07); IETF draft-vauban-x402 (PQ receipts); Google AP2; ERC-8004.
8. EU Anti-Money Laundering Regulation, Art. 79 (application 2027-07-01).
9. Zcash ZIP 2005 (post-quantum considerations, commitment bindingness).
10. Penumbra protocol documentation (tiered commitment tree).
11. Rivest & Shamir, *PayWord and MicroMint*, 1996.
12. Ethereum Foundation, Lean roadmap materials (hash-based signatures + STARK direction).
13. HashKinetics repository: `HASHKINETICS-IMPLEMENTATION-PLAN.md` · `docs/MASTER-BUILD-PLAN.md` (consolidated version/phase tracker) · `docs/SHIELDED-POOL-SPEC.md` · `docs/TECHNOTE-CONSENSUS-GUARDED-STATEFUL-HASH-SIGNATURES.md` · `docs/AUDIT-SCOPE.md` · `zkvm-bakeoff/RESULTS.md` · market/design research 01–03 (2026-08-15, sourced and dated).

*HashKinetics · $HKN · whitepaper v1.0 (2026-08-18). Confidential where so marked; not an offer.*
