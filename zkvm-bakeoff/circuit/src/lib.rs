//! hk-spend-circuit — the HashKinetics shielded-spend statement (gate G2).
//!
//! **Statement v2 (WOTS).** One crate, compiled inside every zkVM guest (SP1 / RISC Zero /
//! OpenVM). The guest reads a [`SpendWitness`], calls [`run`], and commits the returned
//! [`SpendPublic`]; the proof attests "I know a witness such that `run(witness)` produced
//! these public outputs" — a valid shielded spend — without revealing amounts, keys, or
//! which note was spent.
//!
//! The statement (single-input → single-output note):
//!   1. input note commitment   cm_in = H(value ‖ owner ‖ rho ‖ rcm)
//!   2. Merkle-path membership   fold cm_in up `TREE_DEPTH` levels → merkle_root (public)
//!   3. spend authority          IN-CIRCUIT **WOTS** one-time signature over the tx binding
//!                               (w = 16: 64 message digits + 3 checksum digits = 67 chains).
//!                               The public key is **recomputed from the signature** by
//!                               completing each chain — no pk travels in the witness.
//!   4. owner binding            note.owner == H(recomputed WOTS public key)
//!   5. nullifier                nf = H(owner ‖ rho)  (deterministic; double-spend guard)
//!   6. value conservation       in.value == out.value + fee, no under/overflow
//!   7. output note commitment   cm_out = H(...) (public; added to the tree)
//!
//! v1 → v2 (why WOTS replaced Lamport): Lamport carried ~25 KB of key material (512-entry pk
//! + 256 reveals) through the VM — deserialization dominated the post-precompile cycle count.
//! WOTS carries a 67×32 B signature (~2.1 KB), recomputes pk in-circuit (~500 chain hashes,
//! comparable hash work), and matches the production keychain design (WOTS at the session
//! layer, plan §2). Bench-grade plain W-OTS chains (not WOTS+ masks); chain index is bound
//! into every step. v1 numbers in RESULTS.md remain labeled "circuit v1 (Lamport)".
//!
//! v2 → v3 (P2.1, stealth payments): (a) the note's `owner` is now an ADDRESS TAG
//! H(spend_root ‖ H(nk)) — spend authority = a small Merkle tree of one-time WOTS keys
//! (the sender pays a PUBLIC address; only the tree holder can ever sign; the sender can
//! never claw back), and the nullifier derives from the SECRET nk (the sender knows rho
//! but can never watch for the spend); (b) TWO outputs (pay + change),
//! in = out1 + out2 + fee. Cost over v2: ~11 extra hashes — noise on 605K cycles.
//!
//! HASH CHOICE (unchanged): SHA-256 via the `sha2` crate (SP1/RISC0 accelerate it through
//! patches; OpenVM via its drop-in lib behind the `openvm-accel` feature). The Poseidon2 pass
//! measures the doctrine tax separately. See ../README.md.
//!
//! P2.0: this crate is ALSO the chain's hashing source of truth. `hk-state`'s pool imports
//! [`commit_note`] / [`merkle_node`] / [`nullifier`] / [`empty_roots`] / [`tx_binding_for`]
//! and the MINT statement ([`run_mint`]) from here — commitment-tree bytes on-chain and
//! in-circuit can never diverge, because only one implementation exists.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

/// Aggregation-tier glue (P2.3) — shared by the aggregator guest, hk-prove, and the node.
pub mod agg;

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

// One hash implementation per prover family, same API + identical output:
// default = the `sha2` crate (SP1/RISC0 accelerate it via crates.io patches);
// `openvm-accel` = OpenVM's drop-in guest lib (its extension-based accelerator).
#[cfg(not(feature = "openvm-accel"))]
use sha2::{Digest, Sha256};
#[cfg(feature = "openvm-accel")]
use openvm_sha2::Sha256; // inherent new/update/finalize — no Digest trait needed

/// Commitment-tree depth (2^32 notes). Fixed for the benchmark.
pub const TREE_DEPTH: usize = 32;

/// WOTS parameters: w = 16 ⇒ 64 message digits (nibbles of a 32-byte binding) plus 3
/// checksum digits (max checksum 64×15 = 960 < 16³) = 67 chains, 15 steps max per chain.
pub const WOTS_MSG_DIGITS: usize = 64;
pub const WOTS_CSUM_DIGITS: usize = 3;
pub const WOTS_CHAINS: usize = WOTS_MSG_DIGITS + WOTS_CSUM_DIGITS; // 67
pub const WOTS_W: u16 = 16;

/// 32-byte hash / field element.
pub type Hash = [u8; 32];

// Domain-separation tags (distinct first byte per hash use — no cross-protocol collisions).
const DOM_CM: u8 = 1; // note commitment
const DOM_NODE: u8 = 2; // Merkle inner node
const DOM_PKD: u8 = 3; // WOTS public-key digest / owner
const DOM_NF: u8 = 4; // nullifier
const DOM_OTS: u8 = 5; // WOTS chain step
const DOM_SK: u8 = 6; // WOTS secret-key derivation (host side)
const DOM_TXBIND: u8 = 7; // chain-side tx-binding rule (credit account + fee)
const DOM_OTS_NODE: u8 = 8; // spend-tree inner node (distinct from the commitment tree)
const DOM_ADDR: u8 = 9; // address tag = H(spend_root ‖ nk_commit)
const DOM_NK: u8 = 10; // nullifier-key commitment
const DOM_NK_SEED: u8 = 11; // wallet-side nk derivation
const DOM_LEAF_SEED: u8 = 12; // wallet-side per-leaf WOTS seed

/// Spend-tree depth: 2^10 = 1,024 one-time spends per address (v1).
///
/// Why not 25–30 for a "lifetime" address? The CIRCUIT cost of depth is trivial (D
/// hashes), but the WALLET must derive every leaf to compute the root: 2^D WOTS keygens
/// ≈ 2^D × 1,000 hashes. Depth 10 ⇒ ~1M hashes ≈ instant; depth 25 ⇒ ~3×10^10 hashes ≈
/// hours. Lifetime addresses therefore need a HYPERTREE (top tree certifies bottom trees,
/// derived lazily — XMSS^MT shape, +1 in-circuit WOTS verify ≈ +15% cycles): that is
/// decision D5, measured in the P2 bench pass before it changes the vk. v1 posture:
/// addresses are CHEAP TO ROTATE (address #k from the same master, unlinkable), and the
/// wallet must persist its next leaf index reserve-then-sign — leaf reuse hands the leaf
/// key to whoever sees both signatures (same discipline as the consensus signer).
pub const SPEND_TREE_DEPTH: usize = 10;

pub(crate) fn sha(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

// ---------------------------------------------------------------------------
// Data types (witness = private, public = committed by the proof)
// ---------------------------------------------------------------------------

/// A shielded note: a hidden coin owned by whoever controls `owner`'s spend key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub value: u64,
    /// H(WOTS public key) — binds the note to a one-time spend key.
    pub owner: Hash,
    /// Nullifier seed (unique per note).
    pub rho: Hash,
    /// Commitment randomness (hides the note).
    pub rcm: Hash,
}

/// Authentication path from a note commitment to the tree root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePath {
    /// One sibling per level, bottom → top; length must equal `TREE_DEPTH`.
    pub siblings: Vec<Hash>,
    /// Leaf position; bit `l` selects whether the node is the left (0) or right (1) child.
    pub index: u64,
}

/// A WOTS (w=16) one-time signature: one chain value per digit, 67 total (~2.1 KB).
/// The verifier completes each chain and recomputes the public key — no pk in the witness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WotsSig {
    pub sig: Vec<Hash>,
}

/// Everything private the prover knows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendWitness {
    pub in_note: Note,
    pub path: MerklePath,
    /// One-time spend authorization: a WOTS signature over `tx_binding`...
    pub sig: WotsSig,
    /// ...plus the auth path from that one-time key's digest up to the address's
    /// spend-tree root (v3 — only the tree holder can produce both).
    pub ots_path: MerklePath,
    /// The address's SECRET nullifier key (nf = H(nk ‖ rho)).
    pub nk: Hash,
    /// Output 1 — the payment.
    pub out_note: Note,
    /// Output 2 — the change (zero-value dummy when not needed).
    pub out2_note: Note,
    pub fee: u64,
    /// Message the spend signature authorizes (binds this proof to one transaction).
    pub tx_binding: Hash,
}

/// What the proof reveals (and the chain checks): the anchor it spent under, the nullifier
/// it burns, the two notes it creates, the fee, and the tx it is bound to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendPublic {
    pub merkle_root: Hash,
    pub nullifier: Hash,
    pub out_commitment: Hash,
    pub out2_commitment: Hash,
    pub fee: u64,
    pub tx_binding: Hash,
}

/// Why an invalid witness was rejected. In a zkVM guest, any of these should `panic!` (which
/// makes proving fail) — a proof only exists for a witness that satisfies every check.
/// Note: a *tampered* WOTS signature surfaces as `OwnerMismatch` (the recomputed public key
/// no longer digests to the note's owner); `BadSpendSig` covers malformed shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendError {
    BadPathLength,
    BadOtsPath,
    BadSpendSig,
    OwnerMismatch,
    ValueConservation,
}

// ---------------------------------------------------------------------------
// WOTS primitives
// ---------------------------------------------------------------------------

/// One chain step, with the chain index bound into the hash.
fn wots_step(chain: u8, x: &Hash) -> Hash {
    sha(&[&[DOM_OTS], &[chain], x])
}

/// Apply `n` chain steps starting from `x`.
fn wots_chain(chain: u8, x: &Hash, n: u16) -> Hash {
    let mut cur = *x;
    let mut i = 0u16;
    while i < n {
        cur = wots_step(chain, &cur);
        i += 1;
    }
    cur
}

/// Message digits: 64 nibbles (hi-first) + 3 base-16 checksum digits of C = Σ(15 − dᵢ).
fn wots_digits(msg: &Hash) -> [u8; WOTS_CHAINS] {
    let mut d = [0u8; WOTS_CHAINS];
    for (i, byte) in msg.iter().enumerate() {
        d[2 * i] = byte >> 4;
        d[2 * i + 1] = byte & 0x0f;
    }
    let mut csum: u16 = 0;
    for &digit in d[..WOTS_MSG_DIGITS].iter() {
        csum += (WOTS_W - 1) - digit as u16;
    }
    d[WOTS_MSG_DIGITS] = ((csum >> 8) & 0x0f) as u8;
    d[WOTS_MSG_DIGITS + 1] = ((csum >> 4) & 0x0f) as u8;
    d[WOTS_MSG_DIGITS + 2] = (csum & 0x0f) as u8;
    d
}

/// Digest of the full one-time public key → the note's `owner` and the nullifier's key part.
fn pk_digest(pk: &[Hash; WOTS_CHAINS]) -> Hash {
    let mut h = Sha256::new();
    h.update(&[DOM_PKD]); // borrowed: openvm-sha2's update takes &[u8] (no AsRef sugar)
    for c in pk.iter() {
        h.update(c);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Public-key digest of the WOTS keypair derived from `seed` — in v3 this is a spend-tree
/// LEAF tag. ONE-TIME key — sign exactly one message per seed (standard OTS rule).
pub fn wots_owner(seed: &[u8]) -> Hash {
    let mut pk = [[0u8; 32]; WOTS_CHAINS];
    for (i, slot) in pk.iter_mut().enumerate() {
        let sk_i = sha(&[&[DOM_SK], seed, &[i as u8]]);
        *slot = wots_chain(i as u8, &sk_i, WOTS_W - 1);
    }
    pk_digest(&pk)
}

/// Sign `msg` with the keypair derived from `seed`: walk each chain to its message digit.
pub fn wots_sign(seed: &[u8], msg: &Hash) -> WotsSig {
    let digits = wots_digits(msg);
    let mut sig: Vec<Hash> = Vec::with_capacity(WOTS_CHAINS);
    for i in 0..WOTS_CHAINS {
        let sk_i = sha(&[&[DOM_SK], seed, &[i as u8]]);
        sig.push(wots_chain(i as u8, &sk_i, digits[i] as u16));
    }
    WotsSig { sig }
}

// ---------------------------------------------------------------------------
// Spend tree (v3) — wallet-side derivation. The address's spend component is the root of
// a small Merkle tree over one-time WOTS key digests; the circuit folds a leaf's auth
// path to reconstruct it. Single source of truth for wallets AND tests.
// ---------------------------------------------------------------------------

/// Per-leaf WOTS seed of a wallet's spend tree.
pub fn spend_leaf_seed(master: &[u8], index: u32) -> Hash {
    sha(&[&[DOM_LEAF_SEED], master, &index.to_le_bytes()])
}

/// Empty ladder for the spend tree (its own node domain): E[0] = zero leaf,
/// E[l+1] = ots_node(E[l], E[l]). Pads a 2^h wallet subtree up to the statement's 32.
pub fn ots_empty_roots() -> [Hash; SPEND_TREE_DEPTH + 1] {
    let mut e = [[0u8; 32]; SPEND_TREE_DEPTH + 1];
    for l in 0..SPEND_TREE_DEPTH {
        e[l + 1] = ots_node(&e[l], &e[l]);
    }
    e
}

/// Every REAL leaf tag of a capacity-2^h spend tree (host-side; 2^h WOTS keygens — the
/// one-time address-creation cost; parallelize for big h).
pub fn spend_tree_leaves(master: &[u8], h: u32) -> Vec<Hash> {
    (0..(1u32 << h)).map(|i| wots_owner(&spend_leaf_seed(master, i))).collect()
}

/// The spend-tree root for a capacity-2^h address: fold the real subtree, then pad with
/// the empty ladder up to SPEND_TREE_DEPTH. The address's spend component.
pub fn spend_root(master: &[u8], h: u32) -> Hash {
    let mut level = spend_tree_leaves(master, h);
    for _ in 0..h {
        level = level.chunks(2).map(|p| ots_node(&p[0], &p[1])).collect();
    }
    let ladder = ots_empty_roots();
    let mut root = level[0];
    for l in (h as usize)..SPEND_TREE_DEPTH {
        root = ots_node(&root, &ladder[l]);
    }
    root
}

/// The wallet's secret nullifier key.
pub fn derive_nk(master: &[u8]) -> Hash {
    sha(&[&[DOM_NK_SEED], master])
}

/// Sign `msg` with spend-tree leaf `index` of a capacity-2^h address and produce the
/// 32-level auth path (h real siblings + empty-ladder padding).
/// ONE-TIME per leaf — the wallet must never reuse an index.
pub fn spend_auth(master: &[u8], h: u32, index: u32, msg: &Hash) -> (WotsSig, MerklePath) {
    let sig = wots_sign(&spend_leaf_seed(master, index), msg);
    let mut level = spend_tree_leaves(master, h);
    let mut idx = index as usize;
    let mut siblings = Vec::with_capacity(SPEND_TREE_DEPTH);
    for _ in 0..h {
        siblings.push(level[idx ^ 1]);
        level = level.chunks(2).map(|p| ots_node(&p[0], &p[1])).collect();
        idx >>= 1;
    }
    let ladder = ots_empty_roots();
    for l in (h as usize)..SPEND_TREE_DEPTH {
        siblings.push(ladder[l]); // subtree sits leftmost — upper path bits are 0
    }
    (sig, MerklePath { siblings, index: index as u64 })
}

/// Complete every chain from the signature values and digest the recomputed public key.
/// Security note: an attacker can only walk chains FORWARD (increase a digit), but any
/// increased message digit strictly decreases the checksum — whose chains they cannot walk
/// backward. Standard W-OTS argument.
fn wots_recover_owner(sig: &[Hash], msg: &Hash) -> Option<Hash> {
    if sig.len() != WOTS_CHAINS {
        return None;
    }
    let digits = wots_digits(msg);
    let mut pk = [[0u8; 32]; WOTS_CHAINS];
    for i in 0..WOTS_CHAINS {
        let remaining = (WOTS_W - 1) - digits[i] as u16;
        pk[i] = wots_chain(i as u8, &sig[i], remaining);
    }
    Some(pk_digest(&pk))
}

// ---------------------------------------------------------------------------
// The statement
// ---------------------------------------------------------------------------

/// Evaluate the shielded-spend statement. Returns the public outputs on success, or the first
/// failed check. The zkVM guest commits the `Ok` value; there is no proof for an `Err`.
pub fn run(w: &SpendWitness) -> Result<SpendPublic, SpendError> {
    if w.path.siblings.len() != TREE_DEPTH {
        return Err(SpendError::BadPathLength);
    }
    if w.ots_path.siblings.len() != SPEND_TREE_DEPTH {
        return Err(SpendError::BadOtsPath);
    }

    // (1) input commitment, (2) fold to the Merkle root (a public output the chain matches
    // against a known anchor).
    let cm_in = commit_note(&w.in_note);
    let mut cur = cm_in;
    for (level, sib) in w.path.siblings.iter().enumerate() {
        let go_right = (w.path.index >> level) & 1 == 1;
        cur = if go_right { merkle_node(sib, &cur) } else { merkle_node(&cur, sib) };
    }
    let merkle_root = cur;

    // (3) spend authority, v3: complete the WOTS chains from the signature (one-time key
    // recovery), then fold the key's digest up the address's SPEND TREE.
    let leaf = wots_recover_owner(&w.sig.sig, &w.tx_binding).ok_or(SpendError::BadSpendSig)?;
    let mut node = leaf;
    for (level, sib) in w.ots_path.siblings.iter().enumerate() {
        let go_right = (w.ots_path.index >> level) & 1 == 1;
        node = if go_right { ots_node(sib, &node) } else { ots_node(&node, sib) };
    }
    let recovered_root = node;

    // (4) owner binding: the address tag over (recovered spend root, nk) must equal the
    // note's owner — ties the signing tree AND the nullifier key to the address the
    // sender paid. A forged sig, wrong leaf, or foreign nk all land here → no proof.
    if address_tag(&recovered_root, &w.nk) != w.in_note.owner {
        return Err(SpendError::OwnerMismatch);
    }

    // (5) nullifier from the SECRET nk (sender knows rho, never nk).
    let nf = nullifier(&w.nk, &w.in_note.rho);

    // (6) value conservation over TWO outputs: in = out1 + out2 + fee (u64, overflow-safe).
    let outs = match w.out_note.value.checked_add(w.out2_note.value) {
        Some(v) => v,
        None => return Err(SpendError::ValueConservation),
    };
    let total = match outs.checked_add(w.fee) {
        Some(v) => v,
        None => return Err(SpendError::ValueConservation),
    };
    if w.in_note.value != total {
        return Err(SpendError::ValueConservation);
    }

    // (7) output commitments (both enter the tree).
    Ok(SpendPublic {
        merkle_root,
        nullifier: nf,
        out_commitment: commit_note(&w.out_note),
        out2_commitment: commit_note(&w.out2_note),
        fee: w.fee,
        tx_binding: w.tx_binding,
    })
}

/// Note commitment: cm = H(DOM_CM ‖ value ‖ owner ‖ rho ‖ rcm). The chain's tree leaves.
pub fn commit_note(n: &Note) -> Hash {
    sha(&[&[DOM_CM], &n.value.to_le_bytes(), &n.owner, &n.rho, &n.rcm])
}

/// Merkle inner node: H(DOM_NODE ‖ left ‖ right). The chain's tree AND the in-circuit
/// path fold both use exactly this.
pub fn merkle_node(left: &Hash, right: &Hash) -> Hash {
    sha(&[&[DOM_NODE], left, right])
}

/// nf = H(DOM_NF ‖ nk ‖ rho). `nk` is the address's SECRET nullifier key: the sender of a
/// note knows rho but never nk, so nobody but the owner can watch for the spend. The chain
/// stores spent nullifiers forever.
pub fn nullifier(nk: &Hash, rho: &Hash) -> Hash {
    sha(&[&[DOM_NF], nk, rho])
}

/// Spend-tree inner node — domain-distinct from the commitment tree.
pub fn ots_node(left: &Hash, right: &Hash) -> Hash {
    sha(&[&[DOM_OTS_NODE], left, right])
}

/// The ADDRESS TAG a sender uses as the note's `owner`:
/// H(DOM_ADDR ‖ spend_root ‖ H(DOM_NK ‖ nk)) — binds the signing tree AND the nullifier
/// key into one public 32-byte owner. Published as part of the stealth address.
pub fn address_tag(spend_root: &Hash, nk: &Hash) -> Hash {
    let nk_commit = sha(&[&[DOM_NK], nk]);
    sha(&[&[DOM_ADDR], spend_root, &nk_commit])
}

/// Empty-subtree ladder: E[0] = 32 zero bytes (an empty LEAF slot), E[l+1] = H(E[l] ‖ E[l]).
/// `E[TREE_DEPTH]` is the root of an empty commitment tree; the chain's incremental tree
/// substitutes E[l] for every unfilled subtree.
pub fn empty_roots() -> [Hash; TREE_DEPTH + 1] {
    let mut e = [[0u8; 32]; TREE_DEPTH + 1];
    for l in 0..TREE_DEPTH {
        e[l + 1] = merkle_node(&e[l], &e[l]);
    }
    e
}

/// The transaction binding a spend's WOTS signature signs and the proof exposes publicly.
/// CHAIN RULE (P2.0): binding = H(DOM_TXBIND ‖ credit_account ‖ fee_le) — `credit_account`
/// is the transparent account the public `fee` is paid to (all-zero when the spend is fully
/// shielded). Because the binding sits INSIDE the proof, the transparent effects are
/// non-malleable: a relayer cannot redirect the unshielded value without breaking the proof.
pub fn tx_binding_for(credit_account: &Hash, fee: u64) -> Hash {
    sha(&[&[DOM_TXBIND], credit_account, &fee.to_le_bytes()])
}

// ---------------------------------------------------------------------------
// Witness builder (prover side) — used by tests AND by every host harness so all provers
// prove the *same* statement over the *same* inputs. Deterministic from a seed.
// ---------------------------------------------------------------------------

/// Build a valid spend witness deterministically from `seed`: derive a fresh WOTS keypair,
/// sign the tx binding (walk each chain to its digit), set the note's owner to the pk digest,
/// and balance value = out + fee. Any host can call this to have something real to prove.
pub fn build_valid_spend(seed: u8) -> SpendWitness {
    let master = [seed];
    let tx_binding = sha(&[&[0xAA], &[seed]]);

    // The address: spend-tree root + secret nullifier key → owner tag. One-time
    // authorization from leaf 0 of a small (2^2) test-capacity tree — the STATEMENT
    // always folds 32 levels, so bench cycles are capacity-independent.
    let root = spend_root(&master, 2);
    let nk = derive_nk(&master);
    let owner = address_tag(&root, &nk);
    let (sig, ots_path) = spend_auth(&master, 2, 0, &tx_binding);

    let in_note = Note {
        value: 1000,
        owner,
        rho: sha(&[&[0x11], &[seed]]),
        rcm: sha(&[&[0x22], &[seed]]),
    };
    let fee: u64 = 10;
    let out_note = Note {
        value: 700,
        owner: sha(&[&[0x33], &[seed]]), // recipient's address tag (any)
        rho: sha(&[&[0x44], &[seed]]),
        rcm: sha(&[&[0x66], &[seed]]),
    };
    let out2_note = Note {
        value: 290, // change back to our own address
        owner,
        rho: sha(&[&[0x56], &[seed]]),
        rcm: sha(&[&[0x78], &[seed]]),
    };
    // Arbitrary but well-formed authentication path; the folded root is a public output.
    let siblings: Vec<Hash> =
        (0..TREE_DEPTH).map(|l| sha(&[&[0x77], &[seed], &(l as u32).to_le_bytes()])).collect();

    SpendWitness {
        in_note,
        path: MerklePath { siblings, index: 0 },
        sig,
        ots_path,
        nk,
        out_note,
        out2_note,
        fee,
        tx_binding,
    }
}

// ---------------------------------------------------------------------------
// The MINT statement (shield, t→z) — small companion circuit (P2.0)
// ---------------------------------------------------------------------------

/// Private input of a mint: the full note being shielded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintWitness {
    pub note: Note,
}

/// Public output of a mint: the commitment entering the tree and the transparent value it
/// locks. The chain debits exactly `value`; the proof guarantees the commitment opens to
/// exactly `value` (the inflation guard) while owner/rho/rcm stay hidden.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintPublic {
    pub commitment: Hash,
    pub value: u64,
}

/// Evaluate the mint statement. Total function — any note yields ITS commitment and value;
/// soundness comes from the chain matching both against the transaction's public fields.
pub fn run_mint(w: &MintWitness) -> MintPublic {
    MintPublic { commitment: commit_note(&w.note), value: w.note.value }
}

/// Deterministic valid mint witness (host harnesses + tests). Owner = the same address
/// `build_valid_spend` derives from this seed, so a minted note is spendable in tests.
pub fn build_valid_mint(seed: u8, value: u64) -> MintWitness {
    let master = [seed];
    let owner = address_tag(&spend_root(&master, 2), &derive_nk(&master));
    MintWitness {
        note: Note {
            value,
            owner,
            rho: sha(&[&[0x55], &[seed]]),
            rcm: sha(&[&[0x88], &[seed]]),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_spend_is_accepted() {
        let w = build_valid_spend(7);
        let out = run(&w).expect("valid witness must prove");
        assert_eq!(out.fee, 10);
        assert_eq!(out.tx_binding, w.tx_binding);
        assert_eq!(out.out_commitment, commit_note(&w.out_note));
        assert_eq!(out.out2_commitment, commit_note(&w.out2_note));
        // Deterministic in the seed.
        let again = run(&build_valid_spend(7)).unwrap();
        assert_eq!(out.nullifier, again.nullifier);
        assert_eq!(out.merkle_root, again.merkle_root);
        // A different note/key yields a different nullifier.
        let other = run(&build_valid_spend(8)).unwrap();
        assert_ne!(out.nullifier, other.nullifier);
        // The nullifier comes from the SECRET nk — the sender-side data (owner tag + rho)
        // cannot reproduce it.
        assert_eq!(out.nullifier, nullifier(&w.nk, &w.in_note.rho));
        assert_ne!(out.nullifier, nullifier(&w.in_note.owner, &w.in_note.rho));
    }

    #[test]
    fn spend_from_a_different_leaf_also_proves() {
        // Leaf 3 of the same capacity-4 tree: fresh one-time key, same address.
        let mut w = build_valid_spend(7);
        let (sig, ots_path) = spend_auth(&[7], 2, 3, &w.tx_binding);
        w.sig = sig;
        w.ots_path = ots_path;
        run(&w).expect("any leaf of the spend tree can authorize");
    }

    #[test]
    fn wrong_leaf_index_is_rejected() {
        // A valid leaf-0 signature with a leaf-1 path folds to a different root.
        let mut w = build_valid_spend(7);
        w.ots_path.index = 1;
        assert_eq!(run(&w), Err(SpendError::OwnerMismatch));
    }

    #[test]
    fn foreign_nullifier_key_is_rejected() {
        // Right tree, wrong nk ⇒ the address tag no longer matches the note's owner.
        let mut w = build_valid_spend(7);
        w.nk[0] ^= 1;
        assert_eq!(run(&w), Err(SpendError::OwnerMismatch));
    }

    #[test]
    fn short_ots_path_is_rejected() {
        let mut w = build_valid_spend(7);
        w.ots_path.siblings.pop();
        assert_eq!(run(&w), Err(SpendError::BadOtsPath));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        // A flipped signature byte changes the recomputed pk → owner mismatch → no proof.
        let mut w = build_valid_spend(7);
        w.sig.sig[0][0] ^= 1;
        assert_eq!(run(&w), Err(SpendError::OwnerMismatch));
    }

    #[test]
    fn signature_for_a_different_message_is_rejected() {
        // A valid signature transplanted onto a different tx binding must fail: digits differ
        // and the checksum blocks the walk-forward forgery.
        let w7 = build_valid_spend(7);
        let mut w = build_valid_spend(9);
        w.sig = w7.sig.clone(); // sig from seed-7's key over seed-7's binding
        assert_eq!(run(&w), Err(SpendError::OwnerMismatch));
    }

    #[test]
    fn malformed_signature_shape_is_rejected() {
        let mut w = build_valid_spend(7);
        w.sig.sig.pop(); // 66 chains instead of 67
        assert_eq!(run(&w), Err(SpendError::BadSpendSig));
    }

    #[test]
    fn wrong_owner_is_rejected() {
        let mut w = build_valid_spend(7);
        w.in_note.owner[0] ^= 1;
        assert_eq!(run(&w), Err(SpendError::OwnerMismatch));
    }

    #[test]
    fn value_must_be_conserved() {
        let mut w = build_valid_spend(7);
        w.out_note.value += 1; // in.value != out.value + fee
        assert_eq!(run(&w), Err(SpendError::ValueConservation));
    }

    #[test]
    fn fee_beyond_input_breaks_conservation() {
        let mut w = build_valid_spend(7);
        w.fee = w.in_note.value + 1;
        assert_eq!(run(&w), Err(SpendError::ValueConservation));
    }

    #[test]
    fn short_path_is_rejected() {
        let mut w = build_valid_spend(7);
        w.path.siblings.pop();
        assert_eq!(run(&w), Err(SpendError::BadPathLength));
    }

    #[test]
    fn empty_ladder_is_consistent() {
        let e = empty_roots();
        assert_eq!(e[0], [0u8; 32]);
        for l in 0..TREE_DEPTH {
            assert_eq!(e[l + 1], merkle_node(&e[l], &e[l]));
        }
    }

    #[test]
    fn mint_commits_to_its_value() {
        let w = build_valid_mint(3, 777);
        let p = run_mint(&w);
        assert_eq!(p.value, 777);
        assert_eq!(p.commitment, commit_note(&w.note));
        // Hiding: same value, different randomness ⇒ different commitment.
        let mut w2 = w.clone();
        w2.note.rcm[0] ^= 1;
        assert_ne!(run_mint(&w2).commitment, p.commitment);
        // A minted note is owned by the ADDRESS of the same seed (v3).
        assert_eq!(w.note.owner, address_tag(&spend_root(&[3], 2), &derive_nk(&[3])));
    }

    #[test]
    fn spend_tree_root_matches_leaf_fold_at_any_capacity() {
        // spend_auth's 32-level path folds to spend_root — the exact circuit check —
        // for different wallet-chosen capacities.
        let master = b"tree-consistency";
        let msg = [0xAB; 32];
        for (h, index) in [(0u32, 0u32), (2, 3), (4, 11)] {
            let (sig, path) = spend_auth(master, h, index, &msg);
            assert_eq!(path.siblings.len(), SPEND_TREE_DEPTH);
            let leaf = wots_recover_owner(&sig.sig, &msg).unwrap();
            let mut node = leaf;
            for (l, s) in path.siblings.iter().enumerate() {
                node = if (index as u64 >> l) & 1 == 1 {
                    ots_node(s, &node)
                } else {
                    ots_node(&node, s)
                };
            }
            assert_eq!(node, spend_root(master, h), "h={h} index={index}");
        }
    }

    #[test]
    fn binding_rule_sign_recover_roundtrip() {
        // Chain-side binding rule + wallet-side sign + circuit-side recover must agree.
        let credit = [9u8; 32];
        let b = tx_binding_for(&credit, 12_345);
        let sig = wots_sign(b"acct-seed", &b);
        assert_eq!(wots_recover_owner(&sig.sig, &b), Some(wots_owner(b"acct-seed")));
        // Different fee ⇒ different binding ⇒ the signature no longer recovers the owner.
        let b2 = tx_binding_for(&credit, 12_346);
        assert_ne!(wots_recover_owner(&sig.sig, &b2), Some(wots_owner(b"acct-seed")));
    }
}
