//! pool — shielded-pool consensus state (P2.0; plan: docs/P2-BUILD-PLAN.md WS1).
//!
//! What consensus keeps per pool:
//!   1. an APPEND-ONLY commitment tree, depth 32, in frontier form — O(32) hashes per
//!      insert, O(32) memory, no leaf storage (wallets keep their own view);
//!   2. the recent-ANCHOR window: a spend proof is built against a slightly stale root,
//!      so any block-end root from the last [`ANCHOR_WINDOW`] blocks is spendable-under;
//!   3. the NULLIFIER set — the double-spend guard, kept forever;
//!   4. `total_shielded` (Σ minted − Σ unshielded): the transparent side always knows how
//!      much value the pool holds without knowing whose it is.
//!
//! HASHING IS THE CIRCUIT'S. Every commitment/node/nullifier byte here comes from
//! `hk-spend-circuit` — the exact crate the zkVM guests compile. One implementation, one
//! truth: the tests below feed a chain-built auth path into the circuit's `run()` and
//! require the identical root. Divergence would mean proofs verifying against anchors the
//! chain never had, or honest wallets unable to spend — neither can happen when the bytes
//! have a single source.
//!
//! VERSION POOLS (plan decision): a future circuit/hash upgrade opens a NEW pool (v2)
//! beside this one; balances migrate by unshield→shield. `PoolState.version` tags this
//! pool's circuit; nothing else needs to change.

use hk_primitives::{Amount, AssetId};
use hk_spend_circuit::{empty_roots, merkle_node, Hash, MintPublic, SpendPublic, TREE_DEPTH};
use std::collections::{BTreeSet, VecDeque};

/// How many recent block-end roots remain valid spend anchors (~3 min at 1.4 s blocks):
/// long enough to prove against, short enough to bound consensus memory.
pub const ANCHOR_WINDOW: usize = 128;

/// Proof verification, injected by the NODE (hk-state stays prover-agnostic and light).
/// WS2 wires the real SP1 STARK verifier here; tests inject stubs.
pub trait ProofVerifier: Send + Sync {
    fn verify_spend(&self, proof: &[u8], expected: &SpendPublic) -> bool;
    fn verify_mint(&self, proof: &[u8], expected: &MintPublic) -> bool;
}

/// The SECURE DEFAULT: no verifier wired ⇒ every pool tx is rejected. A node that forgets
/// to inject the real verifier refuses shielded traffic rather than accepting anything.
pub struct RejectAllVerifier;

impl ProofVerifier for RejectAllVerifier {
    fn verify_spend(&self, _: &[u8], _: &SpendPublic) -> bool {
        false
    }
    fn verify_mint(&self, _: &[u8], _: &MintPublic) -> bool {
        false
    }
}

/// Append-only Merkle tree over 2^32 leaf slots, frontier representation (Zcash-style):
/// `frontier[l]` holds the pending LEFT-subtree hash at level `l` along the insertion
/// path; unfilled subtrees stand in as the circuit's empty ladder E[l].
///
/// Capacity note: we cap at 2^32 − 1 leaves (one slot sacrificed) so `root()`'s fold is
/// valid for every reachable state without a special full-tree case.
///
/// Serde (P3.0/WS-B): the FRONTIER + next_index are the persistent facts (the state
/// commitment covers only next_index + root, so a snapshot MUST carry the frontier or
/// the next append would produce a wrong root). The empty ladder is derived data —
/// never persisted, always recomputed from the circuit crate.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct IncrementalTree {
    frontier: Vec<Hash>,
    next_index: u64,
    #[serde(skip, default = "empty_ladder")]
    empty: Vec<Hash>, // E[l] ladder, computed once at construction
}

fn empty_ladder() -> Vec<Hash> {
    empty_roots().to_vec()
}

impl Default for IncrementalTree {
    fn default() -> Self {
        Self::new()
    }
}

impl IncrementalTree {
    pub fn new() -> Self {
        Self {
            frontier: vec![[0u8; 32]; TREE_DEPTH],
            next_index: 0,
            empty: empty_roots().to_vec(),
        }
    }

    /// Number of commitments inserted so far (also: the next leaf index).
    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    pub fn is_full(&self) -> bool {
        !self.has_capacity(1)
    }

    /// Room for `n` more commitments? (v3 spends append TWO outputs atomically.)
    pub fn has_capacity(&self, n: u64) -> bool {
        self.next_index.saturating_add(n) <= (1u64 << TREE_DEPTH) - 1
    }

    /// Append a commitment; returns its leaf index, or `None` when full.
    pub fn append(&mut self, leaf: Hash) -> Option<u64> {
        if self.is_full() {
            return None;
        }
        let pos = self.next_index;
        let mut cur = leaf;
        let mut idx = pos;
        for l in 0..TREE_DEPTH {
            if idx & 1 == 0 {
                // We are a left child at this level: park the hash and stop — everything
                // above only changes when our right sibling arrives.
                self.frontier[l] = cur;
                break;
            }
            // Right child: merge with the parked left sibling and carry upward.
            cur = merkle_node(&self.frontier[l], &cur);
            idx >>= 1;
        }
        self.next_index = pos + 1;
        Some(pos)
    }

    /// Current root: fold the frontier against the empty ladder. `cur` starts as the
    /// empty subtree covering the (unfilled) slot at `next_index` and absorbs a parked
    /// left sibling wherever the insertion path went right.
    pub fn root(&self) -> Hash {
        let mut cur = self.empty[0];
        let mut idx = self.next_index;
        for l in 0..TREE_DEPTH {
            cur = if idx & 1 == 1 {
                merkle_node(&self.frontier[l], &cur)
            } else {
                merkle_node(&cur, &self.empty[l])
            };
            idx >>= 1;
        }
        cur
    }
}

/// One shielded pool: tree + anchors + nullifiers + conservation ledger.
///
/// Serde (P3.0/WS-B): serialized whole for node snapshots, INCLUDING the private
/// anchor VecDeque — its order drives eviction, so membership alone is not enough.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PoolState {
    /// Circuit version this pool verifies against (version-pool upgrade path).
    pub version: u8,
    /// v1: single-asset pool; `None` until the first mint pins it.
    pub asset: Option<AssetId>,
    pub tree: IncrementalTree,
    /// Spent nullifiers — forever. BTreeSet: deterministic iteration for the commitment.
    pub nullifiers: BTreeSet<Hash>,
    /// Σ minted − Σ unshielded: what the transparent world knows about the pool.
    pub total_shielded: Amount,
    /// Recent block-end roots (deduped, oldest evicted); private — go through methods.
    anchors: VecDeque<Hash>,
}

impl Default for PoolState {
    fn default() -> Self {
        Self {
            version: 1,
            asset: None,
            tree: IncrementalTree::new(),
            nullifiers: BTreeSet::new(),
            total_shielded: 0,
            anchors: VecDeque::new(),
        }
    }
}

impl PoolState {
    /// Called at every block end (and once at genesis): the current root becomes a valid
    /// spend anchor. Consecutive identical roots dedupe (blocks without pool activity),
    /// so the window covers more real history.
    pub fn seal_anchor(&mut self) {
        let r = self.tree.root();
        if self.anchors.back() != Some(&r) {
            self.anchors.push_back(r);
            if self.anchors.len() > ANCHOR_WINDOW {
                self.anchors.pop_front();
            }
        }
    }

    pub fn is_recent_anchor(&self, root: &Hash) -> bool {
        self.anchors.contains(root)
    }

    pub fn latest_anchor(&self) -> Option<&Hash> {
        self.anchors.back()
    }

    pub fn anchors(&self) -> impl Iterator<Item = &Hash> {
        self.anchors.iter()
    }
}

/// Coverage key for batch-level aggregated verification (P2.3): the state machine
/// accepts a PROOF-LESS pool tx iff the block's verified aggregate covered exactly this
/// (statement kind, expected public bytes) pair. Kind tags: `hk_spend_circuit::agg`.
pub fn cover_key(kind: u8, expected_publics: &[u8]) -> [u8; 32] {
    hk_crypto::hash::shake256_32(hk_crypto::hash::DOM_AGG_COVER, &[&[kind], expected_publics])
}

/// Rebuild an authentication path from the full leaf list. WALLET-side (wallets scan
/// `PoolMinted`/`PoolSpent` events and keep every commitment); consensus nodes never need
/// this — they keep only the frontier. Returns (siblings bottom→top, root).
///
/// Panics if `leaves` is empty or `index` out of range — caller bug, not chain input.
pub fn full_tree_path(leaves: &[Hash], index: u64) -> (Vec<Hash>, Hash) {
    assert!(!leaves.is_empty(), "full_tree_path: no leaves");
    let index = usize::try_from(index).expect("index fits usize");
    assert!(index < leaves.len(), "full_tree_path: index out of range");
    let empty = empty_roots();
    let mut level: Vec<Hash> = leaves.to_vec();
    let mut idx = index;
    let mut siblings = Vec::with_capacity(TREE_DEPTH);
    for l in 0..TREE_DEPTH {
        let sib = if idx ^ 1 < level.len() { level[idx ^ 1] } else { empty[l] };
        siblings.push(sib);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { empty[l] };
            next.push(merkle_node(&left, &right));
            i += 2;
        }
        level = next;
        idx >>= 1;
    }
    (siblings, level[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use hk_spend_circuit::{
        address_tag, commit_note, derive_nk, nullifier, run, spend_auth, spend_root,
        tx_binding_for, MerklePath, Note, SpendWitness,
    };

    fn leaf(n: u8) -> Hash {
        commit_note(&Note { value: n as u64 + 1, owner: [n; 32], rho: [n; 32], rcm: [n; 32] })
    }

    #[test]
    fn empty_tree_root_is_the_empty_ladder_root() {
        assert_eq!(IncrementalTree::new().root(), empty_roots()[TREE_DEPTH]);
    }

    #[test]
    fn frontier_root_matches_full_rebuild_at_every_size_and_index() {
        let mut tree = IncrementalTree::new();
        let mut leaves = Vec::new();
        for n in 0u8..12 {
            let l = leaf(n);
            assert_eq!(tree.append(l), Some(n as u64), "indices are sequential");
            leaves.push(l);
            for i in 0..leaves.len() {
                let (sibs, root) = full_tree_path(&leaves, i as u64);
                assert_eq!(root, tree.root(), "n={n} i={i}: frontier == full rebuild");
                // Fold the path exactly the way the CIRCUIT does and land on the root.
                let mut cur = leaves[i];
                for (l, s) in sibs.iter().enumerate() {
                    cur = if (i >> l) & 1 == 1 { merkle_node(s, &cur) } else { merkle_node(&cur, s) };
                }
                assert_eq!(cur, tree.root(), "n={n} i={i}: circuit-style fold reaches root");
            }
        }
    }

    /// THE KEYSTONE (P2.0/P2.1 quality bar): a commitment inserted by the CHAIN's tree,
    /// a path rebuilt wallet-side, fed into the CIRCUIT's `run()` — same root, same
    /// nullifier. This is the property that makes shielded spends verifiable at all.
    #[test]
    fn chain_tree_and_circuit_agree_end_to_end() {
        let master: &[u8] = b"consistency-key";
        let nk = derive_nk(master);
        let owner = address_tag(&spend_root(master, 2), &nk);
        let note = Note { value: 1_000, owner, rho: [3u8; 32], rcm: [4u8; 32] };
        let cm = commit_note(&note);

        let mut tree = IncrementalTree::new();
        tree.append(leaf(0xF0)).unwrap();
        assert_eq!(tree.append(cm), Some(1));
        tree.append(leaf(0xF2)).unwrap();

        let leaves = [leaf(0xF0), cm, leaf(0xF2)];
        let (siblings, rebuilt_root) = full_tree_path(&leaves, 1);
        assert_eq!(rebuilt_root, tree.root(), "wallet rebuild == consensus frontier");

        let credit = [7u8; 32];
        let fee = 25u64;
        let binding = tx_binding_for(&credit, fee);
        let (sig, ots_path) = spend_auth(master, 2, 0, &binding);
        let w = SpendWitness {
            in_note: note,
            path: MerklePath { siblings, index: 1 },
            sig,
            ots_path,
            nk,
            out_note: Note { value: 900, owner: [9; 32], rho: [8; 32], rcm: [6; 32] },
            out2_note: Note { value: 75, owner, rho: [5; 32], rcm: [4; 32] },
            fee,
            tx_binding: binding,
        };
        let p = run(&w).expect("chain-built path must satisfy the circuit");
        assert_eq!(p.merkle_root, tree.root(), "circuit root == chain root");
        assert_eq!(p.nullifier, nullifier(&nk, &[3u8; 32]));
    }

    #[test]
    fn anchor_window_dedups_and_evicts() {
        let mut p = PoolState::default();
        p.seal_anchor();
        p.seal_anchor(); // no pool activity → same root → dedup
        assert_eq!(p.anchors().count(), 1);
        let genesis_anchor = *p.latest_anchor().unwrap();
        assert!(p.is_recent_anchor(&genesis_anchor));

        for n in 0..(ANCHOR_WINDOW as u8 + 5) {
            p.tree.append([n; 32]).unwrap();
            p.seal_anchor();
        }
        assert_eq!(p.anchors().count(), ANCHOR_WINDOW);
        assert!(!p.is_recent_anchor(&genesis_anchor), "old anchors expire");
        assert!(p.is_recent_anchor(&p.tree.root()), "latest root is always valid");
    }
}
