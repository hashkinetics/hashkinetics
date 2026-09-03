# HashKinetics Shielded Pool — Protocol Specification

**Status: v0.9.7 (2026-08-17) · everything in this document is BUILT and LIVE — on the public
testnet since 2026-08-27 (staging-1) and on testnet-1 since 2026-09-02 — unless marked otherwise.
Since this revision: the consensus wire is bincode (0.9.11), verifying keys are pinned in the
genesis (P2.5), one aggregate STARK covers a block's spends (0.9.9), a flat 100-micro envelope
fee applies to every transaction including pool ones (0.12.2; genesis-bound 0.13.0 —
`FEES.md`), and the Windows wallet drives every operation here (0.13.0).** This is the single source of truth for the pool as implemented —
the reference for auditors (P3), integrating partners, wallet implementers, and the future
public protocol spec. Code is authoritative where they disagree; file an issue in
`CLAUDE.md` decisions if you find such a disagreement.

Implementation map: circuit = `zkvm-bakeoff/circuit/src/lib.rs` (crate `hk-spend-circuit`,
compiled identically into the chain, the wallets, and every zkVM guest — the "single
hashing truth" rule) · consensus state = `chain/crates/hk-state/src/pool.rs` + `lib.rs` ·
wallet = `chain/crates/hk-wallet` · KEM/AEAD = `chain/crates/hk-crypto/src/{mlkem,noteenc}.rs`.

---

## 1 · Overview

```
sender wallet                      chain (consensus)                    recipient wallet
─────────────                      ─────────────────                    ────────────────
build note ──► commitment ───────► append-only Merkle tree (depth 32)
            └► stealth ct ───────► stored alongside (advisory) ───────► trial-decap SCAN
build witness ─► hk-prove (GPU) ─► STARK verified IN-CONSENSUS          └► note discovered
                                   nullifier set (forever)              └► spend it (own key)
                                   conservation ledger (Σ minted − Σ unshielded)
```

Design lineage: Zcash-style note/nullifier UTXO semantics, Penumbra-style incremental
tree thinking — rebuilt on a **pure hash-based spend-authority stack** (WOTS one-time keys
under Merkle spend trees; no elliptic curves anywhere near value) with **ML-KEM-768 for
confidentiality only** and **raw hash-based STARKs** (no pairing wraps — finding F1).

## 2 · Primitives and domain separation

In-circuit hash: **SHA-256** (pool v1; Decision D1 — SP1-accelerated, 1.2–1.3 s proofs
measured; hash-agility via version pools §12). Outside circuits: SHAKE-256 everywhere.

Circuit-side domain tags (single leading byte; `circuit/src/lib.rs`):

| Tag | Name | Use |
|---|---|---|
| 1 | DOM_CM | note commitment |
| 2 | DOM_NODE | commitment-tree inner node |
| 3 | DOM_PKD | WOTS public-key digest (spend-tree leaf tag) |
| 4 | DOM_NF | nullifier |
| 5 | DOM_OTS | WOTS chain step |
| 6 | DOM_SK | WOTS secret-key derivation (host side) |
| 7 | DOM_TXBIND | chain-side tx-binding rule |
| 8 | DOM_OTS_NODE | spend-tree inner node (distinct from tag 2 — no cross-tree splices) |
| 9 | DOM_ADDR | address tag |
| 10 | DOM_NK | nullifier-key commitment |
| 11 | DOM_NK_SEED | wallet-side nk derivation |
| 12 | DOM_LEAF_SEED | wallet-side per-leaf WOTS seed |

Wallet/crypto-side SHAKE-256 domains (`hk-crypto/src/hash.rs`): `hk/v1/mlkem-note-seed`,
`hk/v1/note-key`, `hk/v1/note-enc`, `hk/v1/note-mac`, plus `hk/wallet/rho/v2` and
`hk/wallet/rcm/v2` in `hk-wallet`.

## 3 · Notes and commitments

```
Note      = { value: u64, owner: [u8;32], rho: [u8;32], rcm: [u8;32] }
cm(Note)  = SHA-256( DOM_CM ‖ value_le ‖ owner ‖ rho ‖ rcm )
```

`owner` is an **address tag** (§4), `rho` the unique nullifier seed, `rcm` the commitment
randomness (hiding). rho/rcm are chosen by the note's CREATOR (sender for payments) and
transported to the recipient inside the stealth ciphertext (§9). **rho uniqueness is a
wallet duty** — a repeated rho repeats the nullifier and strands one of the two notes.

## 4 · Addresses (circuit v3)

A stealth address has two public components:

```
Address = ( tag: [u8;32], kem_pk: [u8;1184] )      // ML-KEM-768 encapsulation key
tag     = SHA-256( DOM_ADDR ‖ spend_root ‖ SHA-256(DOM_NK ‖ nk) )
```

- **spend_root** — root of a Merkle tree (node domain 8) over one-time WOTS public-key
  digests. Statement depth is `SPEND_TREE_DEPTH = 10` (Yadu, 2026-08-17; Decision D5 keeps
  hypertree/XMSS^MT expansion open for lifetime capacity). Wallets choose real capacity
  **2^h ≤ 2^10** at address creation and pad the remaining levels with the ots empty
  ladder (E0 = zero leaf, E_{l+1} = ots_node(E_l, E_l)); the subtree sits leftmost.
- **nk** — the SECRET nullifier key, committed into the tag. Never on-chain, never in any
  ciphertext; appears only inside spend witnesses.
- Wallet derivation (all from one master seed): `nk = SHA(DOM_NK_SEED ‖ master)`;
  leaf i seed = `SHA(DOM_LEAF_SEED ‖ master ‖ i_le)`; KEM seed = SHAKE-256₆₄ of master
  (FIPS 203 seed keys — the 64-byte seed IS the private key; restores from backup).

**One-time discipline:** every spend consumes one WOTS leaf (`ots_index`); wallets MUST
persist the next index reserve-then-sign — same rule as the consensus signer. Leaf reuse
hands the leaf key to anyone who sees both signatures (including a delegated prover).
Addresses are cheap to rotate (address #k from the same master); the sender-facing tag
changes, unlinkably.

Why the sender can't steal or claw back: the sender pays a PUBLIC tag; producing a spend
requires a WOTS signature whose recovered key folds to `spend_root` — only the master-seed
holder can do that. The KEM shared secret (which the sender also knows) carries no spend
authority whatsoever.

## 5 · The commitment tree (consensus state)

Append-only Merkle tree, depth 32, **frontier representation** (O(32) hashes per insert,
O(32) memory, no leaf storage in consensus). Empty subtrees stand in as the ladder
E0 = 32 zero bytes, E_{l+1} = merkle_node(E_l, E_l). Capacity is 2^32 − 1 (one slot
sacrificed so the root fold needs no full-tree case).

**Anchors:** at every block end (and once at genesis) the current root is pushed into a
128-entry ring window (deduped when unchanged — ~3 min of history at 1.4 s blocks). A
spend must reference an anchor inside the window. **Nullifier set:** spent nullifiers are
kept forever (BTreeSet — deterministic iteration for the state commitment).
**Conservation ledger:** `total_shielded = Σ minted − Σ unshielded fees` — the transparent
world always knows how much the pool holds, never whose it is.

Wallets rebuild auth paths from the full leaf list (node index, §10 RPC) via
`pool::full_tree_path`; consensus itself never needs a path.

## 6 · Nullifiers

```
nf = SHA-256( DOM_NF ‖ nk ‖ rho )
```

The circuit proves nk belongs to the note's address (via the tag binding, §7). Since the
sender of a note knows rho but never nk, **nobody except the owner can precompute a
note's nullifier or watch for its spend** (the classic sender-tracking leak, closed —
review flag 1, 2026-08-17). Residual exposure: a spend WITNESS contains nk + one WOTS
signature; an untrusted delegated prover therefore sees them. Posture: **local proving**
(GPU-class agent hardware is the documented G2 requirement); nk sits on the viewing side
of the P2.2 IVK/OVK split.

## 7 · Transactions and chain rules

Both are verified against public inputs **the chain derives itself** — never against the
transaction's claim of them.

**MintToPool { asset, value, commitment, proof, stealth_ct }** — shield.
Rules: value > 0 and ≤ u64::MAX; single-asset pool v1 — the FIRST mint pins `pool.asset`;
tree capacity ≥ 1; the mint proof must verify for `MintPublic { commitment, value }`
(the **inflation guard**: the commitment provably opens to exactly the debited value while
owner/rho/rcm never touch the chain). Effects: debit sender, append commitment,
`total_shielded += value`.

**ShieldedSpend { anchor, nullifier, out_commitment, out2_commitment, fee, credit, proof,
stealth_ct, stealth_ct2 }** — proof-carrying: ANY account may relay; authority is the
STARK. Rules: fee ≤ u64::MAX; fee > 0 ⇒ credit is Some (the unshield channel; fee = 0 ⇒
fully shielded transfer, zero transparent trace); anchor ∈ recent window; nullifier fresh;
tree capacity ≥ 2. The proof must verify for

```
SpendPublic { merkle_root = anchor, nullifier, out_commitment, out2_commitment,
              fee, tx_binding = SHA-256(DOM_TXBIND ‖ credit_or_zeros ‖ fee_le) }
```

The **binding rule** puts the transparent effects INSIDE the proof: a relayer cannot
redirect the unshielded value or alter the fee without breaking the STARK (and the WOTS
signature signs the same binding — non-malleable end to end). Effects: insert nullifier,
append BOTH output commitments (in order), credit fee, `total_shielded −= fee`.

`stealth_ct*` are **advisory**: consensus stores and gossips them, scanners read them, a
lying blob only hurts its sender (§9). Failed transactions mutate NOTHING (including the
sender's account ratchet).

## 8 · Circuit statements (v3 — both vks changed 2026-08-17)

**Spend** (`run`): witness = { in_note, path(32), sig(67-chain WOTS), ots_path(10), nk,
out_note, out2_note, fee, tx_binding }.

1. fold cm(in_note) up `path` → `merkle_root` (public);
2. recover the one-time key from `sig` over `tx_binding` (chains completed in-circuit;
   checksum blocks walk-forward forgery), digest it, fold up `ots_path` → recovered root;
3. **owner binding:** `address_tag(recovered_root, nk) == in_note.owner` — ties the
   signing tree AND the nullifier key to the address the sender paid;
4. `nf = H(DOM_NF ‖ nk ‖ rho)` (public);
5. conservation: `in.value == out.value + out2.value + fee` (u64, overflow-checked);
6. output commitments (both public).

Errors ⇒ panic in-guest ⇒ no proof: BadPathLength · BadOtsPath · BadSpendSig ·
OwnerMismatch (forged sig, wrong leaf, foreign nk all land here) · ValueConservation.

**Mint** (`run_mint`): total function — commits `MintPublic { cm(note), note.value }`;
soundness comes from the chain matching both fields (§7).

Cost: v2 measured 604,993 cycles / 1,236 ms core (RTX 5090); v3 adds ~11 hashes — live
runs show 1.19–1.31 s. (Formal v3 re-bench = pass-2 backlog.)

## 9 · Stealth ciphertexts and the scanner

```
stealth_ct = kem_ct (1088 B, ML-KEM-768) ‖ AEAD_ct ‖ tag (32 B)
AEAD: SHAKE-256 encrypt-then-MAC (doctrine-pure, no AES):
  key       = SHAKE-256₃₂( "hk/v1/note-key" ‖ shared_secret ‖ cm )   // cm binds position
  keystream = SHAKE-256-XOF( "hk/v1/note-enc" ‖ key ‖ cm )
  tag       = SHAKE-256₃₂( "hk/v1/note-mac" ‖ key ‖ cm ‖ ciphertext )
plaintext  = value_le(8) ‖ rho(32) ‖ rcm(32) ‖ memo(rest)
```

Scanner (per wallet, per entry `(leaf_index, cm, stealth_ct)`): decapsulate (FIPS 203
implicit rejection always yields 32 bytes — garbage if not ours), derive key, open AEAD
(tag failure = "not mine"), decode, and **require `cm(decoded note with my tag) == cm`** —
a ciphertext that lies about its note is discarded (it was never spendable). Cost is one
decap + one AEAD per output; epoch-bucketing and view-service batching are the scaling
path (plan WS4), lattice-OMR the research upgrade.

Threat model (doctrine split): a future lattice break of ML-KEM leaks old **metadata**
(who/what in ciphertexts) — it can never forge a signature or steal a coin, because spend
authority never touches the KEM.

## 10 · Proof system and verification

- **Prover:** SP1 (stack locked at G2), CUDA, core mode ~1.2–1.3 s / compressed ~2 s.
  `hk-prove` (`zkvm-bakeoff/sp1/script/src/bin/serve.rs`) serves spend + mint proofs and
  self-verifies before returning. Proof bytes on the wire = bincode of
  `SP1ProofWithPublicValues`.
- **In-node verification** (`hk-node/src/verifier.rs`, feature `sp1-verify`): the proof's
  committed public values must BYTE-MATCH the chain-derived expectation (guests commit
  bincode), then the raw STARK verifies under the pinned vk. **Secure default:** without a
  wired verifier the state machine's `RejectAllVerifier` refuses all pool traffic.
- **vk provenance:** devnet fetches vks from hk-prove at node startup (`HK_PROVER_URL`);
  **mainnet pins vk hashes in genesis** (WS8 hardening item).
- Node RPCs: `hk_getPoolInfo` (root, latest anchor, sizes, ledger) ·
  `hk_getPoolLeaves` · `hk_getPoolNotes` (the scanner feed: index + commitment +
  stealth_ct, built from committed txs — a node-level index, derivable by any replayer).

## 11 · State commitment

The pool folds into the global SHAKE-256 state commitment deterministically: version byte,
asset (option-tagged), tree `next_index` + root, anchor window (len + entries, order),
nullifier set (len + sorted entries), `total_shielded`. Two nodes replaying the same
blocks reach bit-identical commitments (tested, incl. the verifier-schedule caveat: the
verifier config is node-local; replays must apply the same config timeline).

## 12 · Versioning and upgrades

- **Version pools:** a circuit/hash upgrade opens a NEW pool (v2) beside v1; balances
  migrate by unshield→shield. `PoolState.version` tags the circuit; nothing else changes.
- **D1** (in-circuit hash): SHA-256 for pool v1 (locked stack, measured); Poseidon2 tax
  measured in the pass-2 bench before any change.
- **D5** (spend-tree capacity): depth-10 single tree now; XMSS^MT hypertree (+1 in-circuit
  WOTS verify ≈ +15% cycles, estimate) for lifetime addresses — measured before it
  changes the vk.
- Any vk change (v2→v3 happened 2026-08-17) requires: prover restart, node vk refetch
  (devnet) / genesis pin update (mainnet), fresh witness shapes in wallets.

## 13 · Known v1 limits (deliberate, dated)

Single-asset pool (first mint pins) · stealth randomness is caller-supplied (demo
deterministic; production = CSPRNG) · wallet `ots_index`/note tracking in-memory
(persist reserve-then-sign before value) · node note index in-memory, fresh per run ·
JSON wire codec double-hexes proofs (~2.7 MB → ~11 MB; devnet gossip caps at 32 MiB;
binary codec WS8 + aggregation P2.3 are the fixes) · per-proof in-node verify (~10² ms/
validator; ONE aggregate per block is P2.3) · viewing keys / disclosure = P2.2 · nothing
audited (see `docs/AUDIT-SCOPE.md`).

## 14 · Measured (live devnet, 2026-08-17, RTX 5090 / WSL2)

| Operation | Time | Notes |
|---|---|---|
| Mint proof (core) | 1,054–1,193 ms | inflation guard |
| Spend proof v2 (core) | 1,236–1,274 ms | 604,993 cycles |
| Spend proof v3 (core) | 1,311–1,314 ms | spend-tree + 2-out + nk (+~40 ms) |
| In-node verify | ~10² ms / validator | per proof; aggregation = P2.3 |
| Trial-decap scan | 1 decap + 1 AEAD / output | Bob found $2 among 3 outputs |
| Block cadence under proof traffic | ~1.4 s held | 4 validators |
