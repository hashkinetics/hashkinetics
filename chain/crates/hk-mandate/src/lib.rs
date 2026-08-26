//! hk-mandate — MandateTree v2 accounting engine (plan §5; carried spec
//! docs/carried-specs/MANDATETREE-SPEC.md). This is the consensus-native
//! hierarchical budget system: the thing no other chain has (research 03).
//!
//! Mechanics implemented here, exactly per spec:
//! - **Drip not reset:** allowance accrues per-second into a capped buffer, O(1) lazy.
//! - **Oversubscribe children, enforce globally:** children's rates may sum past the
//!   parent envelope; every spend must clear the ENTIRE ancestor chain.
//! - **Cascade revocation:** revoking a node kills its whole subtree (any descendant
//!   spend walks through the revoked ancestor and fails).
//! - **Two-phase spend:** validate the whole chain first, then debit — a failed spend
//!   never mutates state (consensus determinism).
//!
//! Concurrency note (plan §5.3): within a block, all spends touching a mandate node are
//! sequenced per-node (Sui-style); this module is the single-threaded core those
//! batches run through.

use hk_primitives::{Amount, MandateId, MandateNode, Timestamp};
use std::collections::BTreeMap;

pub const MAX_DEPTH: usize = 64;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpendError {
    #[error("mandate not found")]
    NotFound,
    #[error("mandate revoked at depth {0} from leaf")]
    Revoked(usize),
    #[error("mandate expired at depth {0} from leaf")]
    Expired(usize),
    #[error("amount exceeds per_tx_max at depth {0} from leaf")]
    PerTxCap(usize),
    #[error("insufficient buffer at depth {depth} from leaf (have {have}, need {need})")]
    Insufficient { depth: usize, have: Amount, need: Amount },
    #[error("mandate chain exceeds MAX_DEPTH or contains a cycle")]
    BadChain,
    #[error("child policy exceeds parent (attenuation violated): {0}")]
    Attenuation(&'static str),
}

/// The in-memory tree. In the node this sits behind the state machine's storage
/// layer; the logic must stay identical (this crate IS the reference semantics).
///
/// Serde (P3.0/WS-B): serialized whole for node snapshots. The BTreeMap keeps
/// deterministic order; restore round-trips to an identical state commitment
/// (guarded by the snapshot integrity check in hk-state).
#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct MandateTree {
    nodes: BTreeMap<MandateId, MandateNode>,
}

impl MandateTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a node. Enforces Biscuit-style attenuation: a child may only narrow.
    pub fn insert(&mut self, node: MandateNode) -> Result<(), SpendError> {
        if let Some(pid) = node.parent {
            let parent = self.nodes.get(&pid).ok_or(SpendError::NotFound)?;
            if node.expiry > parent.expiry {
                return Err(SpendError::Attenuation("child expiry outlives parent"));
            }
            if node.per_tx_max > parent.per_tx_max {
                return Err(SpendError::Attenuation("child per_tx_max exceeds parent"));
            }
            // NOTE: child rate/buffer_max may EXCEED parent's (oversubscription is a
            // feature — spec §oversubscribe); global safety comes from the chain walk.
        }
        self.nodes.insert(node.id, node);
        Ok(())
    }

    pub fn get(&self, id: &MandateId) -> Option<&MandateNode> {
        self.nodes.get(id)
    }

    pub fn revoke(&mut self, id: &MandateId) -> Result<(), SpendError> {
        self.nodes.get_mut(id).map(|n| n.revoked = true).ok_or(SpendError::NotFound)
    }

    /// Lazy drip accrual — O(1) (spec: "drip not reset").
    fn accrue(node: &mut MandateNode, now: Timestamp) {
        if now > node.last_accrual {
            let dt = (now - node.last_accrual) as u128;
            node.buffer = node
                .buffer
                .saturating_add(node.rate_per_sec.saturating_mul(dt))
                .min(node.buffer_max);
            node.last_accrual = now;
        }
    }

    /// Leaf→root chain of ids, with cycle/depth guard.
    fn chain_of(&self, leaf: &MandateId) -> Result<Vec<MandateId>, SpendError> {
        let mut chain = Vec::with_capacity(8);
        let mut cur = *leaf;
        for _ in 0..MAX_DEPTH {
            let node = self.nodes.get(&cur).ok_or(SpendError::NotFound)?;
            chain.push(cur);
            match node.parent {
                Some(p) => cur = p,
                None => return Ok(chain),
            }
        }
        Err(SpendError::BadChain)
    }

    /// Read-only validation of a prospective spend — phase 1 only, mutates nothing.
    /// Callers that must sequence other checks (e.g. funder balance) AFTER mandate
    /// authorization call this first: the mandate is the authorization layer, so its
    /// verdict surfaces before settlement-layer errors.
    pub fn check(&self, leaf: &MandateId, amount: Amount, now: Timestamp) -> Result<(), SpendError> {
        let chain = self.chain_of(leaf)?;
        for (depth, id) in chain.iter().enumerate() {
            let n = &self.nodes[id];
            if n.revoked {
                return Err(SpendError::Revoked(depth));
            }
            if now >= n.expiry {
                return Err(SpendError::Expired(depth));
            }
            if amount > n.per_tx_max {
                return Err(SpendError::PerTxCap(depth));
            }
            let dt = now.saturating_sub(n.last_accrual) as u128;
            let projected = n
                .buffer
                .saturating_add(n.rate_per_sec.saturating_mul(dt))
                .min(n.buffer_max);
            if projected < amount {
                return Err(SpendError::Insufficient { depth, have: projected, need: amount });
            }
        }
        Ok(())
    }

    /// THE core operation: spend `amount` from `leaf` at time `now`.
    /// Validates (via `check`) and debits the entire ancestor chain, atomically.
    pub fn spend(&mut self, leaf: &MandateId, amount: Amount, now: Timestamp) -> Result<(), SpendError> {
        self.check(leaf, amount, now)?;
        // Commit: accrue + debit every node. Cannot fail after check.
        let chain = self.chain_of(leaf)?;
        for id in &chain {
            let n = self.nodes.get_mut(id).expect("validated by check");
            Self::accrue(n, now);
            n.buffer -= amount;
        }
        Ok(())
    }

    /// Root mandate id of `leaf`'s chain (the node with no parent).
    pub fn root_of(&self, leaf: &MandateId) -> Result<MandateId, SpendError> {
        let chain = self.chain_of(leaf)?;
        Ok(*chain.last().expect("chain is never empty"))
    }

    /// Deterministic iteration over all nodes (BTreeMap order) — used for state commitments.
    pub fn iter(&self) -> impl Iterator<Item = (&MandateId, &MandateNode)> {
        self.nodes.iter()
    }

    /// Read-only availability at `now` (min over the whole chain of projected buffers,
    /// bounded by min per_tx_max) — what a wallet/agent shows as "spendable right now".
    pub fn available(&self, leaf: &MandateId, now: Timestamp) -> Result<Amount, SpendError> {
        let chain = self.chain_of(leaf)?;
        let mut avail = Amount::MAX;
        for (depth, id) in chain.iter().enumerate() {
            let n = &self.nodes[id];
            if n.revoked {
                return Err(SpendError::Revoked(depth));
            }
            if now >= n.expiry {
                return Err(SpendError::Expired(depth));
            }
            let dt = now.saturating_sub(n.last_accrual) as u128;
            let projected = n
                .buffer
                .saturating_add(n.rate_per_sec.saturating_mul(dt))
                .min(n.buffer_max);
            avail = avail.min(projected).min(n.per_tx_max);
        }
        Ok(avail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hk_primitives::{H256, SigScheme};

    fn id(b: u8) -> MandateId {
        H256([b; 32])
    }

    fn node(i: u8, parent: Option<u8>, rate: Amount, buf_max: Amount, per_tx: Amount, expiry: Timestamp) -> MandateNode {
        MandateNode {
            id: id(i),
            parent: parent.map(id),
            holder_key: vec![i],
            scheme: SigScheme::Lms,
            asset: id(0xAA),
            rate_per_sec: rate,
            buffer_max: buf_max,
            per_tx_max: per_tx,
            expiry,
            revoked: false,
            buffer: 0,
            last_accrual: 0,
            tier: 0,
        }
    }

    /// org(1) → team(2) → {agent(3), agent(4)} — the demo tree.
    fn demo_tree() -> MandateTree {
        let mut t = MandateTree::new();
        t.insert(node(1, None, 100, 10_000, 5_000, 1_000_000)).unwrap();
        t.insert(node(2, Some(1), 80, 8_000, 4_000, 1_000_000)).unwrap();
        t.insert(node(3, Some(2), 60, 6_000, 3_000, 1_000_000)).unwrap();
        t.insert(node(4, Some(2), 60, 6_000, 3_000, 1_000_000)).unwrap(); // oversubscribed: 60+60 > 80
        t
    }

    #[test]
    fn drip_accrues_and_caps_at_buffer_max() {
        let mut t = demo_tree();
        // at t=200: leaf3 projected = min(6000, 60*200=12000) = 6000
        assert_eq!(t.available(&id(3), 200).unwrap(), 3_000); // clamped by per_tx_max
        t.spend(&id(3), 3_000, 200).unwrap();
    }

    #[test]
    fn spend_debits_every_ancestor() {
        let mut t = demo_tree();
        t.spend(&id(3), 1_000, 100).unwrap();
        assert_eq!(t.get(&id(1)).unwrap().buffer, 10_000u128.min(100 * 100) - 1_000); // 10000cap? 100*100=10000 → 9000
        assert_eq!(t.get(&id(2)).unwrap().buffer, 8_000 - 1_000);
        assert_eq!(t.get(&id(3)).unwrap().buffer, 6_000 - 1_000);
    }

    #[test]
    fn oversubscribed_siblings_drain_the_parent_envelope() {
        let mut t = demo_tree();
        // At t=100: parent2 projected = min(8000, 80*100)=8000. Siblings each try 3000 twice.
        t.spend(&id(3), 3_000, 100).unwrap(); // parent2: 5000 left
        t.spend(&id(4), 3_000, 100).unwrap(); // parent2: 2000 left
        // Sibling 3 has 3000 locally (6000-3000) but parent2 only 2000 → global enforcement:
        let err = t.spend(&id(3), 3_000, 100).unwrap_err();
        assert_eq!(err, SpendError::Insufficient { depth: 1, have: 2_000, need: 3_000 });
    }

    #[test]
    fn revoked_ancestor_kills_subtree() {
        let mut t = demo_tree();
        t.revoke(&id(2)).unwrap();
        assert_eq!(t.spend(&id(3), 1, 100).unwrap_err(), SpendError::Revoked(1));
        assert_eq!(t.spend(&id(4), 1, 100).unwrap_err(), SpendError::Revoked(1));
        // Root itself still works:
        t.spend(&id(1), 1_000, 100).unwrap();
    }

    #[test]
    fn expiry_blocks_and_is_attenuated() {
        let mut t = demo_tree();
        assert_eq!(t.spend(&id(3), 1, 2_000_000).unwrap_err(), SpendError::Expired(0));
        // Child may not outlive parent:
        let bad = node(9, Some(2), 1, 1, 1, 2_000_000);
        assert!(matches!(t.insert(bad), Err(SpendError::Attenuation(_))));
    }

    #[test]
    fn per_tx_cap_checks_whole_chain() {
        let mut t = demo_tree();
        // 3500 ≤ leaf3.per_tx? No — 3000 cap at depth 0:
        assert_eq!(t.spend(&id(3), 3_500, 100).unwrap_err(), SpendError::PerTxCap(0));
    }

    #[test]
    fn failed_spend_mutates_nothing() {
        let mut t = demo_tree();
        t.spend(&id(3), 3_000, 100).unwrap();
        t.spend(&id(4), 3_000, 100).unwrap();
        let before: Vec<Amount> = [1, 2, 3, 4].iter().map(|i| t.get(&id(*i)).unwrap().buffer).collect();
        assert!(t.spend(&id(3), 3_000, 100).is_err()); // parent envelope dry
        let after: Vec<Amount> = [1, 2, 3, 4].iter().map(|i| t.get(&id(*i)).unwrap().buffer).collect();
        assert_eq!(before, after);
    }

    #[test]
    fn check_is_read_only_and_matches_spend() {
        let mut t = demo_tree();
        t.spend(&id(3), 3_000, 100).unwrap();
        t.spend(&id(4), 3_000, 100).unwrap();
        let before = t.get(&id(2)).unwrap().buffer;
        let c = t.check(&id(3), 3_000, 100).unwrap_err();
        assert_eq!(c, SpendError::Insufficient { depth: 1, have: 2_000, need: 3_000 });
        assert_eq!(t.get(&id(2)).unwrap().buffer, before); // untouched
        assert_eq!(t.spend(&id(3), 3_000, 100).unwrap_err(), c); // verdicts agree
        t.check(&id(3), 1_000, 100).unwrap(); // ok-case also read-only
        assert_eq!(t.get(&id(2)).unwrap().buffer, before);
    }

    #[test]
    fn drip_refills_over_time() {
        let mut t = demo_tree();
        t.spend(&id(3), 3_000, 100).unwrap();
        t.spend(&id(4), 3_000, 100).unwrap();
        // parent2 dry-ish at t=100 (2000). By t=150, parent2 += 80*50 = +4000 → 6000; leaf3 += 60*50=+3000 → 6000cap.
        t.spend(&id(3), 3_000, 150).unwrap();
    }
}
