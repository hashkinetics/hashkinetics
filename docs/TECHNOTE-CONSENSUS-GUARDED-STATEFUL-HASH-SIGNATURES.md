# Consensus-Guarded Stateful Hash Signatures
### Turning the stateful-HBS hazard into a protocol feature

**HashKinetics technical note v1.0 · 2026-08-16 · audience: cryptographers & protocol reviewers**
**Status labels used throughout: [LIVE] running on our devnet today · [KAT] implemented + test-verified · [SPEC] designed, not yet wired.**

---

## 1 · The problem everyone routes around

Stateful hash-based signatures (LMS/HSS — RFC 8554; XMSS/XMSS^MT — RFC 8391) offer the most conservative post-quantum security available — unforgeability from hash-function properties alone — at small sizes (~1–2.5 KB) and microsecond-class verification. Their disqualifying hazard is state: each leaf is one-time, and **signing twice with one leaf can reveal enough one-time-key material to enable forgery**. NIST SP 800-208 consequently confines them to firmware-signing-style deployments with hardened state management, and general-purpose chains avoid them for user keys (QRL, the longest-running XMSS chain, is migrating *user* accounts away from XMSS — while Ethereum's Lean roadmap adopts an XMSS-style scheme for *validators*, where the environment is controlled).

That split is the insight. **Stateful HBS is wrong for humans and right for machines** — and a blockchain is precisely a machine environment with a global, ordered, replicated log. HashKinetics makes the *chain itself* the state discipline.

## 2 · The inversion: three rules

**Rule 1 — leaf index = account nonce.** [LIVE for accounts, SPEC for consensus votes] A transaction signed at leaf *i* is valid only when the account's on-chain nonce equals *i*. Index reuse isn't a caught error; it's an *invalid transaction by consensus rule*. The global ordered log — the thing a chain uniquely has — becomes the authoritative copy of every signer's state. (This matches the "pre-assigned states + public signature log" pattern blessed in IETF draft-wiggers-hbs-state, authored by PQShield/BSI/Google engineers.)

**Rule 2 — equivocation is evidence, and evidence is slashable.** [SPEC] Two valid signatures at the same leaf over different messages are a compact, self-authenticating fraud proof. The protocol response is twofold: economic (stake/bond slashing) and cryptographic (the key is treated as compromised — frozen, with recovery flowing through the account's stateless SLH-DSA root). The classic silent catastrophe becomes a detectable, attributable, punishable event.

**Rule 3 — reserve-then-sign, never roll back.** [LIVE in our signer implementations] The signer durably advances its state *before* releasing a signature; a persistence failure blocks the signature rather than risking reuse. State loss is thereby demoted from a *safety* fault (forgery risk) to a *liveness* fault (can't sign until re-provisioned via the root key). Backups of signer state must never be restored over a newer state; the persisted file is monotone.

## 3 · Implemented instances

### 3.1 The L-ratchet (account authentication) — [LIVE]
Every HashKinetics devnet account is secured by a Lamport-OTS chain: account state holds a 32-byte commitment to the *current* one-time public key; each transaction opens that commitment (reveals the full key), signs `payload ‖ next_commitment` at the current nonce, and — on success — ratchets the account to the next commitment. One key, one nonce, one use; the chain enforces the sequence. This scheme authenticated **every transaction** in our live demos: the $50 mandate storyline (including the consensus-refused overspend) and the paid-search session. Security reduces to second-preimage resistance of SHAKE-256; cost is ~24 KB/tx (pk 16 KB + sig 8 KB), acceptable for a devnet and instructive as the minimal viable instance of the discipline. Production accounts move to multi-use LMS/XMSS under the same nonce rule.

*Honest caveat (wallet hygiene):* if a transaction is *rejected*, the chain doesn't ratchet — a naïve wallet retrying a **different** payload at the same index signs twice with one Lamport key. Revealing two signatures leaks additional one-time chunks (a probabilistic weakening, not an immediate break). Our devnet wallets do exactly this and we say so; production wallet rules are burn-on-reject (rotate via a self-transaction) or identical-intent-only retry. Multi-use LMS keys shrink this to the standard one-leaf-one-message rule enforced by Rule 1.

### 3.2 LMS/HSS over SHAKE-256 (`hk-crypto::hashsig`) — [KAT]
Real RFC 8554 signing via a vendored, RFC-test-vector-validated Rust implementation (`hbs-lms`), instantiated over SHAKE-256 to match our chain-wide hash doctrine. Deterministic seed-based keygen (reproducible KATs; root-seed recovery); signing consumes the current private-key bytes and delivers advanced bytes through a callback — which is exactly where Rule 3's durable persist hooks in. Our KATs verify: sign/verify round-trip; **state advance per signature** (two signatures from one signer use different leaves and both verify); tamper, wrong-message, and wrong-key rejection. Operational note for integrators: LMS keygen/sign use large stack frames — run signers on ≥8 MiB stacks.

### 3.3 MandateTree binding: capacity *is* policy — [LIVE for value caps · SPEC for cert-carried count caps]
Because a stateful key's leaf count is finite, **key capacity is a spend-count budget enforced by mathematics**: delegate an H=10 tree and the agent can sign at most 1,024 transactions, ever. HashKinetics pairs this with MandateTree, where value caps (drip rate, buffer, per-tx max, expiry) are consensus objects walked on every spend — live today, demonstrated by the refused-overspend receipt. The full design carries value caps in parent-signed delegation certificates (attenuation-only, Biscuit-style) alongside count caps in the child key itself: one hash-based object hierarchy expressing *who may spend, how much, how often, until when*.

## 4 · Consensus votes on stateful HBS — the swap [LIVE]

**Done (2026-08-16): a 4-validator devnet runs full BFT consensus where every prevote, precommit, and proposal is signed with the §3.2 primitive and verified across validators.** Blocks commit with matching state commitments; a height-5 proposer-timeout round-change recovered cleanly, so liveness holds under the heavier signatures.

Implementation (full detail: `HASHSIG-CONSENSUS-SWAP.md`): the engine's signing scheme is a type parameter; we set `HkContext::SigningScheme = HkHashScheme` behind byte-newtype signature/pubkey wrappers and a **non-cloning signer handle** (`Arc<Mutex<HashSigner>>` — cloning shares the handle, never forks leaf state; the mutex serializes a validator's own signing, which is semantically required anyway). Validator key material splits from a single 32-byte seed: network/transport identity is libp2p Ed25519 (peer auth — not ledger security); vote signing is LMS/HSS (two H10 layers ≈ 2^20 signatures/validator). Signing and keygen run on an enlarged stack (LMS uses large frames).

Both halves of the key-management story are now running. **Persistence [LIVE]:** the node runs a single advancing signer whose monotone `used ‖ state` is written atomically (tmp + fsync + rename) *before* each signature is released, and reloaded on restart — leaf reuse across crashes is impossible by construction, proven by a restart-safety test. (Mainnet-grade review here surfaced and fixed a real bug: two signers derived from one seed had both consumed leaf 0 — the one-key-one-signer rule is now structural.) **Rotation [LIVE]:** each validator's permanent identity is a stateless SLH-DSA-SHAKE-192s root registered in genesis; a root-signed `RotationCert{new_op_pk, epoch, valid_from_height}` rides in a block, every node verifies it (signature, registered root, strictly-increasing epoch) and swaps that validator's operational key at commit, and the owner swaps its live signer in lockstep — demonstrated on the 4-validator devnet with zero missed blocks. Exhaustion and key loss are thereby liveness faults, never safety faults. Remaining hardening: epoch persistence across a restart-after-rotation, pre-generated trees off the hot path, certificate gossip, rotation on the real remaining-capacity threshold. A single HSS signature is a few KB, so the mainnet path remains SCMS aggregation + STARK checkpoint pruning.

**With this live and green, HashKinetics' consensus is quantum-secure — money path and consensus rest on hash functions alone.**

## 5 · Positioning

The same architecture is arriving from multiple directions — Ethereum's leanSig (XMSS-style, slot-indexed leaves) for validators; IETF operational guidance for pre-assigned state; SP 800-208-capable HSMs (Marvell LiquidSecurity, Thales) making institutional custody of hash-based keys practical today. HashKinetics' contribution is the **binding**: leaf-index-as-nonce in consensus, equivocation as slashable fraud proof, key capacity as delegated spend policy, and a live chain where all account traffic already runs on one-time hash signatures. To our knowledge no production chain enforces stateful-HBS state at the consensus layer today; corrections welcome.

## 6 · Status summary

| Component | Status |
|---|---|
| L-ratchet account auth (Lamport-OTS chain, nonce-enforced) | [LIVE] — all devnet txs, both public demos |
| LMS/HSS over SHAKE-256 signer | [KAT] — 4 tests green |
| **Consensus votes signed by LMS/HSS (prevote/precommit/proposal)** | **[LIVE] — 4-validator devnet, full BFT** |
| MandateTree value caps in consensus | [LIVE] — refused-overspend receipt on-chain |
| Reserve-then-sign LMS state persistence | **[LIVE] — atomic persist-before-release; restart-safety proven by test** |
| SLH-DSA root certification of operational keys (RotationCert) | **[LIVE] — real FIPS 205 root; monotone-epoch verification; tested** |
| Live operational-key rotation (validator-set swap + signer swap) | **[LIVE] — demonstrated on the 4-validator devnet, zero missed blocks** |
| Leaf-budget count caps via delegated key capacity | [SPEC] |
| Equivocation fraud-proof + slashing path | [SPEC] |

*Companion documents: `HASHKINETICS-IMPLEMENTATION-PLAN.md` (architecture), `HASHSIG-CONSENSUS-SWAP.md` (swap detail), research reports 01–03 (sourced market/crypto landscape). Reproduction: `chain/devnet.ps1`, then the `hk-node demo` and `hk-facilitator demo` drivers.*
