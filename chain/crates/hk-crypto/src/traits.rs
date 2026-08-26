//! Signer traits — the keychain layers of plan §3.2 (§2.1 "The Keychain").

use crate::CryptoError;

/// Stateless root identity (SLH-DSA-SHAKE-192s default; 128s for T0 tier).
/// Rare, cold, human/org-held. Certifies operational keys + mandate roots.
pub trait RootSigner {
    fn public_key(&self) -> &[u8];
    fn sign(&self, msg32: &[u8; 32]) -> Result<Vec<u8>, CryptoError>;
}

pub trait RootVerifier {
    fn verify(pk: &[u8], msg32: &[u8; 32], sig: &[u8]) -> Result<(), CryptoError>;
}

/// Stateful hash-based signer (XMSS/LMS): machine-held agent operational keys.
/// LEAF COUNT = HARD TRANSACTION-COUNT BUDGET (h=10 → 1,024 spends).
///
/// Consensus contract (plan §3.3, IETF draft-wiggers "pre-assigned state" pattern):
/// - the chain enforces leaf index == account nonce;
/// - two signatures with one index = equivocation ⇒ slashable fraud proof,
///   key treated as compromised, auto-freeze, recover via root key.
///
/// Implementations MUST persist state BEFORE releasing a signature
/// (reserve-then-sign), never after.
pub trait StatefulSigner {
    fn public_key(&self) -> &[u8];
    /// Leaves remaining — the live spend-count budget.
    fn remaining(&self) -> u64;
    /// Index the next signature will consume (== expected account nonce).
    fn next_index(&self) -> u64;
    /// Reserve the next leaf durably, then sign. Returns (index, signature).
    fn sign_next(&mut self, msg32: &[u8; 32]) -> Result<(u64, Vec<u8>), CryptoError>;
}

/// Durable leaf-state guard — the reserve-then-sign discipline as a type.
/// Wrap the platform persistence (file+fsync, HSM counter, cloud KV w/ CAS) behind `persist`.
pub struct LeafBudget<P: FnMut(u64) -> Result<(), CryptoError>> {
    next: u64,
    max: u64,
    persist: P,
}

impl<P: FnMut(u64) -> Result<(), CryptoError>> LeafBudget<P> {
    pub fn new(next: u64, max: u64, persist: P) -> Self {
        Self { next, max, persist }
    }
    pub fn remaining(&self) -> u64 {
        self.max.saturating_sub(self.next)
    }
    pub fn peek(&self) -> u64 {
        self.next
    }
    /// Durably advance state and hand out the reserved index.
    pub fn reserve(&mut self) -> Result<u64, CryptoError> {
        if self.next >= self.max {
            return Err(CryptoError::KeyExhausted);
        }
        let idx = self.next;
        (self.persist)(idx + 1)?; // persist FIRST —
        self.next = idx + 1; //          — then advance in memory
        Ok(idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_exhausts_and_persists_first() {
        let mut log: Vec<u64> = vec![];
        {
            let mut b = LeafBudget::new(0, 3, |n| {
                log.push(n);
                Ok(())
            });
            assert_eq!(b.reserve().unwrap(), 0);
            assert_eq!(b.reserve().unwrap(), 1);
            assert_eq!(b.reserve().unwrap(), 2);
            assert!(matches!(b.reserve(), Err(CryptoError::KeyExhausted)));
        }
        assert_eq!(log, vec![1, 2, 3]);
    }

    #[test]
    fn persist_failure_blocks_index_release() {
        let mut b = LeafBudget::new(0, 3, |_n| Err(CryptoError::Unimplemented("disk full")));
        assert!(b.reserve().is_err());
        assert_eq!(b.peek(), 0); // nothing consumed — no index ever escapes unpersisted
    }
}
