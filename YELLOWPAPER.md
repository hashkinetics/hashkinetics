# HashKinetics Yellowpaper — Formal Protocol Specification

**v1.0 · 2026-08-18 · specification of the HashKinetics ledger, transaction validity, shielded pool, proof relations, and consensus interface.**
Companion to the whitepaper (motivation, economics, history). Where prose and this specification disagree, this specification governs; where this specification and the reference implementation disagree, the implementation's test suite is the arbiter until the discrepancy is resolved and recorded.

---

## 1 · Scope and conventions

This document specifies: the world state and its commitment; transaction syntax, authentication, and the state transition function; MandateTree accounting; PayWord channels; the shielded pool including the mint and spend proof relations; the aggregation and coverage mechanism; block structure, consensus signing layouts, and per-block processing order; wire encodings and hash-domain registries; the confidentiality layer (sealing, scanning, epoch keys) and the disclosure verification algorithm; verifying-key pinning; and the consensus-critical invariants.

Normative keywords MUST / MUST NOT / SHOULD follow RFC 2119 usage. The reference implementation is the Rust workspace `chain/` plus the circuit crate `zkvm-bakeoff/circuit` (the *single hashing truth*: the same crate is compiled into prover guests and linked by the state machine).

## 2 · Notation

- `𝔹` — byte strings; `a ‖ b` — concatenation; `|a|` — length in bytes.
- `H32(tag, m₁, …, mₖ)` — SHAKE-256 with 32-byte output over `tag ‖ m₁ ‖ … ‖ mₖ`, `tag` an ASCII string from the registry (§18.1). All chain-side hashing uses `H32`.
- `Hc(d, m₁, …, mₖ)` — SHA-256 over `d ‖ m₁ ‖ … ‖ mₖ`, `d` a single domain byte from the registry (§18.2). All in-circuit hashing uses `Hc` (pool v1; rotatable per §16).
- `u64ᴸᴱ(x)`, `i64ᴸᴱ(x)` — 8-byte little-endian encodings. `u32ᴮᴱ`, `u64ᴮᴱ` — big-endian where stated.
- `H256` — a 32-byte value. `𝔸 = H256` — account, mandate, channel, and asset identifiers are 32-byte values. `Amount = u128` micro-units (1 token = 10⁶ micro). `Timestamp = u64` seconds.
- `JSONc(x)` — the canonical JSON serialization of a fixed-field structure (field order = declaration order; no maps; byte fields as lowercase hex). Used **only** for signing digests and transaction identifiers; never on the wire.
- `Σ` — world state; `Υ(Σ, T) → (Σ′, r)` — the transition function producing a post-state and a typed receipt `r ∈ {ok(events), rejected(reason)}`. A rejected transaction MUST leave `Σ` unmodified (atomicity).

## 3 · Cryptographic primitives

**3.1 SHAKE-256 (FIPS 202)** instantiates `H32`. Distinct registry tags yield independent oracles; an implementation MUST NOT hash untagged data.

**3.2 SLH-DSA-SHAKE-192s (FIPS 205).** Stateless signatures for root identities. Public key 48 B; signature 16,224 B; deterministic keygen from a 32-byte seed via `H32` expansion; non-hedged signing. Roots sign only certificates (§13.4).

**3.3 LMS/HSS (RFC 8554, SHAKE-256 parameter sets).** Stateful consensus signatures. Deployed profile: two-level HSS `[H10, H5]` (2¹⁵ ≈ 32,768 signatures per operational key). The signer state is monotone; §13.5 makes advancement durable *before* signature release (reserve-then-sign). Verification is stateless.

**3.4 WOTS (w = 16).** One-time signatures used inside the spend circuit. A message digest `d ∈ 𝔹³²` is parsed as 64 base-16 digits `m₁…m₆₄`; checksum `C = Σᵢ (15 − mᵢ)` appends 3 further digits; 67 chains total. Chain step: `chainⱼ(x, k) = Hc(DOM_OTS, …)` iterated `k` times (position-bound). Signing reveals `σⱼ = chainⱼ(skⱼ, mⱼ)`; verification **recovers** the public key by completing every chain to 15 and digesting: `pk = Hc(DOM_PKD, σ′₁ ‖ … ‖ σ′₆₇)` where `σ′ⱼ = chainⱼ(σⱼ, 15 − mⱼ)`. The checksum makes digit inflation infeasible (any increase in some `mᵢ` forces a decrease in a checksum digit, which cannot be walked forward). No public key is transmitted.

**3.5 PayWord.** A channel chain of length `n` from seed `s`: `w₀ = H32(DOM_PAYWORD_SEED, s)`, `wᵢ = H32(DOM_PAYWORD_LINK, wᵢ₋₁)`; the **tip** is `w_n`. Revealing `w_{n−k}` proves `k` payments: verification iterates `k` links and compares to the tip (or to the last settled word).

**3.6 Lamport ratchet (account tier v0).** An account's `auth_commit` is `H32(DOM_LAMPORT_PK, pk)` for a one-time Lamport public key derived from the account seed at index = nonce. A transaction reveals `pk`, signs `H32(DOM_TX_MSG, JSONc(payload ‖ sender ‖ nonce ‖ next_auth))`, and installs `next_auth`. Leaf index = nonce is thereby a ledger rule. (Multi-use XMSS/LMS account keys replace this tier under the same discipline; the envelope format is unchanged.)

**3.7 ML-KEM-768 (FIPS 203).** `EK` 1184 B, ciphertext 1088 B. Keygen is deterministic from wallet state: `(ek_e, dk_e) = KEM.KeyGen(H32(DOM_MLKEM_SEED, master ‖ u32ᴮᴱ(e)))` for epoch `e`. Encapsulation is the FIPS-203 deterministic form with encapsulator-chosen coins (reproducibility for the sender); decapsulation uses implicit rejection.

**3.8 SHAKE-AEAD.** For key `k`, nonce `ν` (= the note commitment), plaintext `p`: keystream `H32(DOM_NOTE_ENC, k ‖ ν ‖ ctr)` XORed over `p`; tag `τ = H32(DOM_NOTE_MAC, k ‖ ν ‖ c)`; output `c ‖ τ` (TAG_LEN = 32). `open` recomputes and constant-time-compares `τ` before releasing plaintext. Keys are one-time (per note); `k = H32(DOM_NOTE_KEY, ss ‖ context)` from the KEM shared secret.

**3.9 STARK proof system.** SP1 zkVM proofs over the circuit crate. Modes: `core` (≈2.7 MB) and `compressed` (≈1.24 MB, recursion-ready). **F1 (normative): pairing-based wraps MUST NOT be emitted, transmitted, or accepted.** Verification interface: `Verify(vk, π, P) ∈ {0,1}` where `P` is the byte-exact committed public-value string.

## 4 · Protocol constants

| Constant | Value | Meaning |
|---|---|---|
| `M` | 10⁶ | micro-units per token |
| `POOL_DEPTH` | 32 | commitment-tree depth (capacity 2³² − 1 leaves) |
| `ANCHOR_WINDOW` | 128 | blocks of valid anchors |
| `SPEND_TREE_DEPTH` | 10 | statement-side spend-tree depth (wallet capacity 2^h ≤ 2¹⁰) |
| `EPOCH_BLOCKS` | 1,000 | KEM-key epoch length |
| `MAX_TXS_PER_BLOCK` | 256 | batch capacity (configuration tier; see capacity program) |
| `EK_LEN / CT_LEN / TAG_LEN` | 1184 / 1088 / 32 | ML-KEM-768 sizes; AEAD tag |
| WOTS | w=16, 67 chains | §3.4 |
| HSS profile | [H10, H5] | ≈32.7 k sigs/operational key |
| SLH-DSA | 192s: pk 48 B, sig 16,224 B | root tier |
| Block time (dev config) | ≈1.4 s | pacing constant, not a protocol rule |

## 5 · World state

`Σ = (Acc, Man, Chan, Pool, Val)`:

- `Acc : 𝔸 → (bal : Asset → Amount, nonce : u64, auth_commit : H256)`.
- `Man : 𝔸 → MandateNode` where `MandateNode = (parent : 𝔸?, holder, asset, rate_per_sec, buffer, buffer_max, per_tx_max, last_accrual : Timestamp, expiry, revoked : bool, tier)`. Roots additionally bind a funding account (the creator).
- `Chan : 𝔸 → (payer, payee, asset, mandate, tip : H256, unit_price, max_steps : u32, highest_step_settled : u32, escrow_remaining, expiry)`.
- `Pool = (F : Frontier₃₂, A : ring of ≤128 anchors, N : set of H256 nullifiers, total_shielded : Amount, asset : Asset?, version)`. `F` stores the current root, `next_index`, and one frontier node per level.
- `Val`: the validator set (per validator: stable address, `root_pk` (SLH-DSA), current operational `op_pk` (HSS), `epoch`, voting power).
- **Transient (excluded from commitment):** `agg_cover` — the per-block coverage set (§12).

**State commitment.** `C(Σ) = H32(DOM_STATE_COMMIT, enc(Σ))` over a canonical encoding of all non-transient components. (v1 hashes the whole canonical state; a merkleized commitment is a scheduled replacement with the same interface.)

## 6 · Transactions

**6.1 Envelope.**

```
SignedTx = { sender : 𝔸, nonce : u64, payload : Tx, next_auth : H256,
             lamport_pk : 𝔹, sig : 𝔹 }
```

**Signing digest** `d(T) = H32(DOM_TX_MSG, JSONc(T without sig))`; **txid** `= H32("hk/v1/txid", JSONc(T))`. Both use `JSONc` and are therefore wire-codec-independent (Invariant I9).

**6.2 Payload syntax.**

```
Tx ::= Transfer      { to, asset, amount }
     | MandateCreate { id, parent?, holder, asset, rate_per_sec, buffer_max,
                       per_tx_max, initial_buffer, expiry, tier }
     | MandateSpend  { leaf, to, amount }
     | MandateRevoke { target }
     | ChannelOpen   { id, mandate, payee, asset, tip, unit_price, max_steps, expiry }
     | ChannelSettle { id, word, step }
     | ChannelRefund { id }
     | MintToPool    { asset, value, commitment, proof, stealth_ct }
     | ShieldedSpend { anchor, nullifier, out_commitment, out2_commitment,
                       fee, credit?, mandate?, proof, stealth_ct, stealth_ct2 }
```

`proof` and `stealth_ct*` are byte fields (format-aware encoding, §14.2). `stealth_ct*` are **advisory**: consensus stores and gossips but never interprets them (Invariant I8).

**6.3 Envelope validity (all payloads).** V-E1 `Acc[sender]` exists. V-E2 `nonce = Acc[sender].nonce`. V-E3 `H32(DOM_LAMPORT_PK, lamport_pk) = Acc[sender].auth_commit`. V-E4 `sig` verifies over `d(T)` under `lamport_pk`. Effects on success: `nonce += 1`, `auth_commit ← next_auth` (the ratchet advances even for payloads that later reject — a *rejected* payload still consumed an envelope iff the envelope itself was valid; implementations MUST apply envelope effects and payload effects in one atomic decision per the reference semantics: envelope validity gates inclusion-level acceptance, payload validity yields the receipt).

## 7 · Mandate semantics

**7.1 Accrual.** Available budget of node `n` at time `t`:

```
avail(n, t) = min(buffer_max, buffer + rate_per_sec · (t − last_accrual))
```

Accrual is drip-not-reset: settlement updates `buffer ← avail(n,t) − draw` and `last_accrual ← t`.

**7.2 Authorization walk.** For leaf `ℓ`, amount `a`, time `t`: let `chain(ℓ) = [ℓ, parent(ℓ), …, root]`. `check(ℓ, a, t)` fails with the **first** violated condition, reported with its depth `k` (0 = leaf):

- `Revoked(k)` if any node on the chain is revoked;
- `Expired(k)` if `t ≥ expiry`;
- `PerTxCap(k)` if `a > per_tx_max`;
- `Buffer(k)` if `a > avail(node_k, t)` — rendered as `insufficient buffer at depth k from leaf (have …, need …)`.

**7.3 Rules.** *Create:* root ⇒ sender becomes holder and funding account; child ⇒ sender MUST be the parent's holder, and `per_tx_max(child) ≤ per_tx_max(parent)` (attenuation, at creation). Oversubscription of `buffer_max` across siblings is legal by design. *Spend:* sender MUST be the leaf holder; `check` first; then funds move **from the root's funding account** to the recipient; then every node on the chain draws down (two-phase: no partial effects). *Revoke:* sender MUST hold the target's parent (root: the root itself); revocation cascades implicitly (every descendant's walk crosses the revoked node).

## 8 · Channels

*Open:* sender = mandate-leaf holder; `escrow = unit_price × max_steps` is drawn through the mandate walk **once, at open**; `id` MUST equal the derived channel id (`H32(DOM_CHANNEL_ID, …)`); tip anchors the PayWord chain. *Settle (proof-carrying; any sender):* for claimed step `s > highest_step_settled`, verify `H32-iterated (s − highest) links of word = last settled word (or tip)`; pay `payee (s − highest) × unit_price` from escrow; update. *Refund:* after expiry, payer reclaims `escrow_remaining`. Measured reference: 1,000 steps settled by one 32-byte word in one transaction.

## 9 · The shielded pool

**9.1 Note and commitment.** `note = (v : u64, tag : H256, ρ : H256, rcm : H256)`; `cm = Hc(DOM_CM, u64ᴸᴱ(v) ‖ tag ‖ ρ ‖ rcm)`.

**9.2 Frontier insertion.** With empty-subtree ladder `E₀…E₃₂` (`E₀ = Hc-zero leaf`, `Eₗ₊₁ = Hc(DOM_NODE, Eₗ ‖ Eₗ)`), inserting `cm` at `next_index` updates one frontier node per level and recomputes the root in ≤32 `Hc(DOM_NODE, L ‖ R)` steps. At every block end (and at genesis) the root is sealed into `A` (dedup; evict beyond 128).

**9.3 Nullifiers.** `nf = Hc(DOM_NF, nk ‖ ρ)` with `nk` secret to the owner (`nk = H32(DOM_NK_SEED-derived)` wallet-side; its public fingerprint is `Hc(DOM_NK, nk)`). `N` grows forever; membership ⇒ rejection `nullifier already spent`.

**9.4 Address tag and spend tree.** `tag = Hc(DOM_ADDR, spend_root ‖ Hc(DOM_NK, nk))`. The spend tree is a depth-10 Merkle tree over WOTS public-key digests (`Hc(DOM_OTS_NODE, ·‖·)` inner nodes), wallet capacity `2^h` padded by the empty ladder.

**9.5 The spend relation `R_spend`.** Public `P = (anchor, nf, cm₁, cm₂, fee, b)`; witness `w = (note_in, path, σ_WOTS, ots_path, leaf_index, nk, out₁, out₂, credit)`. `R_spend(P, w) = 1` iff:

1. `cm_in = Hc(DOM_CM, note_in)` and folding `path` from `cm_in` yields `anchor`;
2. `pk = Recover(σ_WOTS, digest(P-binding portion))` and folding `ots_path` from `Hc(DOM_PKD, pk)` yields `spend_root`;
3. `note_in.tag = Hc(DOM_ADDR, spend_root ‖ Hc(DOM_NK, nk))`;
4. `nf = Hc(DOM_NF, nk ‖ note_in.ρ)`;
5. `cm₁ = Hc(DOM_CM, out₁)`, `cm₂ = Hc(DOM_CM, out₂)`;
6. `note_in.v = out₁.v + out₂.v + fee` with all values in u64 range;
7. `b = Hc(DOM_TXBIND, credit ‖ u128(fee))` (absent credit encodes canonically).

**9.6 The mint relation `R_mint`.** Public `(cm, v)`; witness `(tag, ρ, rcm)`; holds iff `cm = Hc(DOM_CM, u64ᴸᴱ(v) ‖ tag ‖ ρ ‖ rcm)` — the inflation guard: a commitment provably carries exactly the debited value.

**9.7 Expected publics (chain-derived).** For a `MintToPool`: `P̂ = (commitment, value)`. For a `ShieldedSpend`: `P̂ = (anchor, nullifier, out_commitment, out2_commitment, fee, Hc(DOM_TXBIND, credit ‖ fee))`. Verification compares the proof's committed bytes to `bincode(P̂)` **byte-exactly** and then checks the STARK. Prover-supplied statements are never trusted (Invariant I4).

**9.8 Transition rules.** *MintToPool:* V-M1 pool has capacity; V-M2 `asset` matches the pool asset (first mint pins it); V-M3 sender balance ≥ value; V-M4 proof valid for `P̂` **or** coverage holds (§12). Effects: debit; insert `cm`; `total_shielded += value`. *ShieldedSpend:* V-S1 `anchor ∈ A`; V-S2 `nf ∉ N`; V-S3 `fee > 0 ⇒ credit` present; V-S4 if `mandate` present: envelope `sender = holder(leaf)` and `check(leaf, fee, t)` passes (public-skeleton mode: the mandate governs the **public** component); V-S5 proof valid for `P̂` or coverage holds. Effects (order fixed): mandate draw-down (if any) → `N ∪= {nf}` → insert `cm₁, cm₂` → if `fee > 0`: credit `fee` transparently and `total_shielded −= fee`.

## 10 · Aggregation and coverage

**10.1 Digest.** For statement kinds `KIND_SPEND = 1`, `KIND_MINT = 2` and verifying key `vk` (as its 8×u32 hash words serialized big-endian):

```
leafᵢ  = Hc( kindᵢ ‖ vkbytes(vkᵢ) ‖ u32ᴮᴱ(|Pᵢ|) ‖ Pᵢ )
digest = Hc( u32ᴮᴱ(n) ‖ leaf₁ ‖ … ‖ leafₙ )
```

binding kind, key, content, order, and count.

**10.2 The aggregator statement.** The aggregation guest receives `(kindᵢ, vkᵢ, Pᵢ)ᵢ` and the `n` compressed proofs; it runs `verify_sp1_proof(vkᵢ, SHA256(Pᵢ))` for each (in-zkVM recursive verification) and commits `digest`. The emitted aggregate is itself a compressed raw STARK (F1 applies).

**10.3 Block rule.** A batch MAY carry `agg_proof`. At commit, each validator verifies it once against the digest recomputed from the block's proof-less pool transactions **in block order**, deriving each `Pᵢ = P̂(txᵢ)` per §9.7. On success it installs `agg_cover = { H32(DOM_AGG_COVER, kind ‖ bincode(P̂)) }`. A proof-less pool transaction is valid iff its coverage key ∈ `agg_cover`. `agg_cover` clears at block end (Invariant I6). The per-proof path remains legal for any transaction.

## 11 · Blocks

**11.1 Batch.** `Batch = { parent_app_hash : H256, txs : [SignedTx], rotations : [RotationCert], agg_proof : 𝔹 }`, encoded with bincode (§14). The consensus **value id** is `H32(DOM_BLOCK_VALUE, batchbytes)`; since `parent_app_hash` is inside, **a vote for a block is a vote for its parent state** (Invariant I2).

**11.2 Per-block processing (normative order).** (1) check `parent_app_hash = C(Σ)` — mismatch is consensus-fatal; (2) verify `agg_proof` if present; install coverage; (3) apply `txs` in order via Υ, recording receipts; (4) apply `rotations` (§13.4); (5) seal the pool anchor; (6) clear coverage; (7) publish `C(Σ′)` as the next parent.

## 12 · Consensus interface

**12.1 Vote sign-bytes** (`DOM_SIGN_VOTE`):

```
tag ‖ 0x00 ‖ type(1B: 0=prevote,1=precommit) ‖ u64ᴸᴱ(height) ‖ i64ᴸᴱ(round)
    ‖ (0x00 | 0x01 ‖ value_id) ‖ validator_address
```

**12.2 Proposal sign-bytes** (`DOM_SIGN_PROPOSAL`): `tag ‖ 0x00 ‖ u64ᴸᴱ(height) ‖ i64ᴸᴱ(round) ‖ i64ᴸᴱ(pol_round) ‖ value_id`.

**12.3 Proposal-part sign-bytes** (`DOM_SIGN_PART`): `tag ‖ 0x00 ‖` part tag `0` (Init: height, round, pol_round, proposer), `1` (TxBatch chunk: u64ᴸᴱ length ‖ bytes), `2` (Fin: value_id). The Fin carries the value id only — proposal authenticity is the engine's signed proposal; a second signature would double-spend a one-time leaf (Invariant I3: **one key, one signer**).

**12.4 Rotation.** `RotationCert = { root_pk, new_op_pk, epoch, valid_from_height, root_sig }`. Valid iff `root_pk` is the validator's registered root, `epoch` strictly exceeds the current epoch, and `root_sig` (SLH-DSA) verifies. On commit, all nodes swap `op_pk`; the owner swaps its live signer in the same commit.

**12.5 Reserve-then-sign (normative).** A signer MUST durably persist `used ‖ state` (write, fsync, atomic rename) *before* releasing any signature; on restart it MUST resume from the persisted record. Observed one-time-leaf reuse by a validator is equivocation evidence (slashable).

## 13 · Wire and digest encodings

**13.1 Wire.** Consensus wire and WAL use bincode over fixed-field structures (deterministic; no maps). Byte fields (`proof`, `stealth_ct*`, `agg_proof`, keys, signatures) are **format-aware**: raw bytes in binary formats, lowercase hex in human-readable formats (RPC, receipts, genesis).

**13.2 Codec independence (Invariant I9).** `d(T)`, txid (canonical JSON), and all §12 sign-bytes (manual layouts) are independent of the wire codec. Changing the codec MUST NOT change any signature or identifier; it does change WAL/wire compatibility (fresh-start or migration required).

## 14 · Confidentiality layer

**14.1 Sealing (sender).** For output note `o` to address `(tag, ek_e)`: `(ss, kem_ct) = Encaps(ek_e; coins)`; `k = H32(DOM_NOTE_KEY, ss ‖ ctx)`; `c ‖ τ = Seal(k, ν = cm(o), plaintext(o ‖ memo))`; publish `stealth_ct = kem_ct ‖ c ‖ τ`.

**14.2 Scanning (recipient).** For each pool entry `(i, cm, stealth_ct)`: split at `CT_LEN`; `ss′ = Decaps(dk_e, kem_ct)` (implicit rejection); `k′ = H32(DOM_NOTE_KEY, ss′ ‖ ctx)`; if `Open(k′, cm, ·)` succeeds, parse the note and **require `Hc(DOM_CM, note) = cm`** — a ciphertext that decrypts but mismatches is discarded (lying-ciphertext rule). Epoch keys scope scanning; the address tag is epoch-stable.

**14.3 Incoming viewing key.** `IVK_e = dk_e` (plus context): grants discovery + decryption for epoch `e` only; contains no spend authority and no `nk`.

**14.4 Disclosure package.** `D = { chain_id, note_key k, stealth-ct payload, cm, leaf_index, path, anchor }`. **Verify(D)** (offline, pure): (1) `Open(k, cm, payload)` → note+memo; (2) `Hc(DOM_CM, note) = cm`; (3) fold `path` from `(cm, leaf_index)` → root `= anchor`. Output: value, memo, recipient tag, position, anchor (to be cross-checked against any public chain view). One key opens exactly one payment.

## 15 · Verifying-key pinning and version pools

Genesis MAY (mainnet: MUST) carry `vk_pins = { spend, mint, agg }` where each pin `= hex(H32(DOM_VK_PIN, vkbytes))`. At startup a verifying node compares fetched keys and MUST refuse to run on mismatch. Statement changes ship as **new pool versions** with fresh pins — explicit, auditable upgrade events; old-version notes migrate by spend-into-new-pool.

## 16 · Consensus-critical invariants

- **I1 Determinism.** Υ and block processing are pure functions of `(Σ, block)`; two honest nodes replay to identical `C(Σ)` (tested by two-node replays).
- **I2 Parent binding.** The value id commits to `parent_app_hash`; divergence cannot gather votes.
- **I3 Single signer / one-time leaves.** One consensus signer per node; leaf reuse is equivocation.
- **I4 Chain-derived statements.** Proofs verify only against `P̂` computed from transaction fields.
- **I5 Conservation.** `Σ transparent + total_shielded` is preserved by every rule; mints/unshields move value across the bridge only.
- **I6 Coverage locality.** `agg_cover` never survives its block and never enters `C(Σ)`.
- **I7 Nullifier permanence.** `N` is append-only; anchor eviction never removes nullifiers.
- **I8 Advisory blobs.** No consensus rule depends on stealth-ct contents.
- **I9 Codec independence.** Signatures and identifiers are invariant under wire-codec change.
- **I10 Atomic refusal.** A rejected payload mutates nothing (mandate walks pre-check; nullifiers burn only on success).

## 17 · Receipts (normative strings, excerpt)

`ok: <n> event(s)` · `rejected: mandate: insufficient buffer at depth <k> from leaf (have <a>, need <b>)` · `rejected: mandate: per-tx cap at depth <k>` · `rejected: mandate: revoked at depth <k>` · `rejected: nullifier already spent (double spend)` · `rejected: unknown anchor` · `rejected: pool proof rejected (invalid, or no verifier wired)` · `rejected: fee requires a credit account` · channel and envelope analogues per the reference implementation's typed error set.

## 18 · Domain registries

**18.1 Chain-side string tags (SHAKE-256), excerpt (normative list: `hk-crypto::hash`).** `hk/v1/tx` · `hk/v1/txid` · `hk/v1/state-commit` · `hk/v1/account-id` · `hk/v1/mandate-id` · `hk/v1/channel-id` · `hk/v1/delegation-cert` · `hk/v1/payword-seed` · `hk/v1/payword-link` · `hk/v1/lamport-{sk,leaf,pk-commit}` · `hk/v1/mlkem-note-seed` · `hk/v1/note-{key,enc,mac}` · `hk/v1/agg-cover` · `hk/v1/vk-pin` · block/value and consensus signing tags (`DOM_BLOCK_VALUE`, `DOM_SIGN_{VOTE,PROPOSAL,PART}`).

**18.2 In-circuit byte domains (SHA-256).** `1` note commitment · `2` commitment-tree node · `3` WOTS pk digest/owner · `4` nullifier · `5` WOTS chain step · `6` WOTS sk derivation (host) · `7` tx binding · `8` spend-tree node · `9` address tag · `10` nk commitment · `11` nk seed (host) · `12` per-leaf WOTS seed (host).


## 19 · Addenda — rules shipped after v1.0 (normative; v1.2 · 2026-09-04)

Each item below is consensus-visible on testnet-1 (`hashkinetics-1-4e4ea68d`) and is specified here at the level of §5–§12; the reference implementation is `chain/crates/hk-state/src/lib.rs`.

**19.1 Permissionless accounts (v0.11.0).** The payload union of §6 gains `AccountCreate { id, auth_commit, asset, amount }`. Validity: `id = H32(hk/v1/account-id ‖ auth_commit)` (the sender cannot choose an id it does not hold the key material for — squat-proof); `id ∉ dom(Acc)`; if `amount > 0`, the SENDER is debited `amount` of `asset` and the new account credited, atomically; the new account starts at `nonce = 0` with `auth_commit` as its first committed key. Structural refusals precede money movement. Event: `AccountCreated { id, creator, asset, funded }`.

**19.2 The envelope fee (v0.12.2; genesis-bound v0.13.0).** Constants: `FEE_MICRO ∈ ℕ` (testnet-1: 100), `fee_from_height ∈ ℕ` (testnet-1: 1), `FEE_ASSET = 0x09^32` (the transparent test unit). For every signed envelope applied at height `h ≥ fee_from_height`: (i) require `bal(sender, FEE_ASSET) ≥ FEE_MICRO`, else refuse with `rejected: insufficient balance for the protocol fee (have <a>, need <FEE_MICRO>)` and mutate nothing; (ii) debit the fee FIRST, so the payload's own checks see the post-fee balance; (iii) dispatch the payload; on refusal credit the fee back — the state is exactly as before the envelope (the atomicity contract of §16 I2 holds for fees); (iv) on success the fee is burned: `fees_burned ← fees_burned + FEE_MICRO`, credited nowhere. The ratchet (§6, leaf-index = nonce) advances only on success. `fees_burned` is a component of Σ and enters `C(Σ)` as a trailing section tagged `0xFE ‖ LE64(fees_burned)` **only when nonzero**, which keeps the pre-fee commitment layout byte-identical until the first fee burns (a rolling upgrade cannot fork before activation).

**19.3 Fee policy as a genesis fact (v0.13.0, U4.b).** The genesis document (§11.1) carries an optional `chain.fee = { micro, from_height }`. When present it is authoritative: a node's local configuration (`HK_FEE_MICRO`, `HK_FEE_FROM`) is ignored and the node logs that the override was refused. When absent, the v0.12 behaviour stands (local configuration decides, default activation height 110,000 on legacy networks). A network whose genesis carries the policy therefore has no activation-height coordination problem and no honest way for a validator to run a different fee schedule.

**19.4 Genesis allocations (v0.13.0).** `genesis-build --alloc <auth_commit>:<micro>` creates, at height 0, the account `id = H32(hk/v1/account-id ‖ auth_commit)` with balance `micro` of `FEE_ASSET` — the same derivation as 19.1, so a genesis allocation is indistinguishable from a runtime-created account and cannot be squatted. `--demo-accounts [org-usd]` seeds the five public-seed demo accounts (demo money only).

**19.5 Chain identity (v0.10.6).** `chain_id = "hashkinetics-1-" ‖ hex(SHA-256(genesis.json))[0..8]`; the full digest is `genesis_digest` in `hk_chainInfo`. Nodes refuse to establish consensus or value-sync sessions with peers whose genesis digest differs. Consequently a network is its genesis bytes; changing any byte (including the fee policy or an allocation) is a new network.

**19.6 Certificate verification against the historical set (v0.10.7, R6).** A commit certificate for height `h` is verified against the validator set **as of `h`** (the set produced by applying every rotation certificate committed at heights `< h`, §12), never against the current set. A node syncing from genesis therefore verifies across every rotation boundary; a rotation applied at height `h` takes effect for the certificate of `h+1`.

**19.7 Bounded decided window (v0.13.0, R10 v2) — non-consensus, stated for completeness.** A node keeps at most `HK_DECIDED_WINDOW` (default 512) recent decided values in memory and serves older heights to peers from its block log after re-checking each block against its stored certificate; the engine's start height on restart is the chain height (snapshot + replay), never a height inferred from the shape of the log; only the gap-free suffix of block files reaching the tip is advertised as servable. None of this changes validity or `C(Σ)`.

**19.8 Receipts (extends §17).** `rejected: insufficient balance for the protocol fee (have <a>, need <b>)` (fee shortfall — the envelope is refused before any payload check, so the wallet's own pre-check mirrors it: amount + fee > balance) · `rejected: insufficient balance: have <a>, need <b>` (payload shortfall after the fee was debited — e.g. a full-balance sweep: `have 249900, need 250000`) · `rejected: account already exists` · `rejected: account id does not match H(auth_commit)` (19.1). There is no in-block receipt for a fee-policy override — the override is refused at node start, never inside a block.

**19.9 Validator-set changes on a running chain (v0.14.0, V1).** A block's batch may carry a sequence of `SetChangeCert = { body, approvals }` with `body = { chain_id, change, not_before, not_after }` and `change ∈ { Admit { root_pk, op_pk, voting_power }, Remove { root_pk } }`. Sign-bytes (`hk/v1/set-change`; `⟨x⟩` = `u64ᴸᴱ(|x|) ‖ x`): `tag ‖ 0x00 ‖ ⟨chain_id⟩ ‖ 0x01 ‖ ⟨root_pk⟩ ‖ ⟨op_pk⟩ ‖ u64ᴸᴱ(voting_power)` for an admission, `tag ‖ 0x00 ‖ ⟨chain_id⟩ ‖ 0x02 ‖ ⟨root_pk⟩` for a removal, each followed by `u64ᴸᴱ(not_before) ‖ u64ᴸᴱ(not_after)`. A certificate committed at height `h` is valid iff `body.chain_id` equals the chain id of §19.5; every approval is an SLH-DSA-192s signature over the body by a **distinct seat of `Val` as it stands at `h`**; `3·Σ power(approving) > 2·Σ power(Val)`; `not_before ≤ h ≤ not_after`; an admission does not collide with a seated address; a removal does not empty the set. Application is idempotent (admitting a seated root or removing an unseated one is a no-op) and takes effect for the certificate of `h+1`, recorded in the per-height set history of §19.6 — sync across the boundary needs no other data. A batch that carries no set change is encoded exactly as before (v1 wire); one that does is framed with the magic `HK-BLK-2`, hence the activation rule: every node ≥ v0.14.0 before the first set change commits. Voting power is 1 per seat on testnet-1; `Val` is not part of `C(Σ)` (it never was) — it is derived deterministically by every node from genesis and the committed certificates.

**19.10 Issued assets (v0.15.0, X1).** `Σ` gains `Reg : Asset → (symbol, decimals, issuer : 𝔸, policy, supply, burned, paused : bool, frozen ⊆ 𝔸, registered_at)` with `policy = (mintable, freezable, pausable, pool_eligible)`. The payload union of §6 gains five variants, appended after `AccountCreate` in this order: `AssetRegister { asset, symbol, decimals, policy }` valid iff `asset = H32(hk/v1/asset-id ‖ sender ‖ symbol)`, `asset ∉ dom(Reg)`, `symbol` matches `[A-Za-z][A-Za-z0-9._-]{0,15}` and `decimals ≤ 18` — the sender becomes the issuer and the policy is immutable; `AssetMint { asset, to, amount }` (sender = issuer, `mintable`, `amount > 0`, `supply + amount` does not overflow) credits `to` and adds to `supply`; `AssetBurn { asset, amount, destination }` (any holder, `|destination| ≤ 64`) debits the sender and adds to `burned`; `AssetFreeze { asset, account, frozen }` (issuer, `freezable`) edits `frozen`; `AssetPause { asset, paused }` (issuer, `pausable`) edits `paused`. **Gate.** Every movement of an asset `a ∈ dom(Reg)` — `Transfer`, the funding leg of `AccountCreate`, `MandateSpend` (payer = the root's funding account), `ChannelOpen` (payer = funder), `ChannelSettle` (payee), `ChannelRefund` (payer), `MintToPool` (sender; additionally requires `policy.pool_eligible`), the unshield credit of `ShieldedSpend` (credit account), `AssetMint` (recipient), `AssetBurn` (sender) — is refused with `asset paused` while `Reg[a].paused`, and with `frozen by issuer` when the paying or the receiving account is in `Reg[a].frozen`. Assets outside `dom(Reg)` are ungated (pre-v0.15 behaviour). The envelope fee (§19.2) is not gated; a genesis that registers the fee asset with `pausable ∨ freezable` is invalid. Genesis gains `chain.assets` (entries under any id — genesis is the trust root) and `chain.fee.asset` (absent = `FEE_ASSET`); allocations of a genesis-registered asset count toward its `supply`. **Commitment.** `enc(Σ)` appends, only when `Reg ≠ ∅`, the tag `0xA5`, `u64ᴸᴱ(|Reg|)`, and for each asset in id order `asset ‖ issuer ‖ u8(|symbol|) ‖ symbol ‖ u8(decimals) ‖ u8(policy bits: mintable=1, freezable=2, pausable=4, pool_eligible=8) ‖ u8(paused) ‖ u128ᴸᴱ(supply) ‖ u128ᴸᴱ(burned) ‖ u64ᴸᴱ(registered_at) ‖ u64ᴸᴱ(|frozen|) ‖ frozen in id order`; with `Reg = ∅` the encoding is byte-identical to v1.1, so nodes on either side of the upgrade agree until the first registration commits — the activation rule is the one of §19.1: every node ≥ v0.15.0 before the first asset transaction. **Invariant I5′ (conservation per registered asset).** For every `a ∈ dom(Reg)`: `Σ_x bal(x, a) + Σ_{open channels in a} escrow_remaining + [Pool.asset = a]·total_shielded = supply − burned − [a = FEE_ASSET]·fees_burned`. Events: `AssetRegistered { asset, issuer, symbol }`, `AssetMinted { asset, to, amount }`, `AssetBurned { asset, from, amount, destination }`, `AssetFrozen { asset, account, frozen }`, `AssetPaused { asset, paused }`.

**19.11 Receipts (extends §17 and §19.8).** `rejected: asset paused` · `rejected: frozen by issuer` · `rejected: sender is not the asset's issuer` · `rejected: asset policy forbids this (not mintable / freezable / pausable)` · `rejected: asset is not pool-eligible` · `rejected: asset id does not match H(issuer, symbol)` · `rejected: asset already registered` · `rejected: unknown asset (not registered)` · `rejected: bad asset symbol (1-16 of [A-Za-z0-9._-], letter first)` · `rejected: burn destination too long (max 64 bytes)`. Set-change certificates produce no in-block receipt; a refused submission answers `accepted: false` with the reason at the RPC.

**18.1 (amended).** The chain-side registry gains `hk/v1/set-change` (SLH-DSA approvals over a set-change body, §19.9) and `hk/v1/asset-id` (§19.10).

---

*HashKinetics yellowpaper v1.0 (2026-08-18) + §19 addenda v1.2 (2026-09-04: 19.9 validator-set changes, 19.10 issued assets, 19.11 receipts). Normative companion: the reference implementation and its test suite (hk-state 21 incl. the I5′ conservation tests, hk-node 19, hk-consensus 3 set-change tests, + 17 circuit at v0.15.0); `docs/SHIELDED-POOL-SPEC.md` for narrative protocol detail; the whitepaper for motivation, economics, and history.*
