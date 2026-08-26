//! PayWord chains — P-chains of plan §6 (carried spec: HYPERTREE-CHANNELS-SPEC.md).
//! The cheapest possible pay-per-call primitive: payment = one 32-byte preimage,
//! verification = hash loops. "Preimage = money, cap literally cryptographic."
//!
//! Chain: w_n ← seed;  w_{i-1} = H_link(w_i);  tip = w_0 goes on-chain at channel open.
//! Paying step k reveals w_k. Verifier holding (w_j, j) accepts w_k (k > j) iff
//! hashing w_k forward (k - j) times reaches w_j. Steps are cumulative: k preimages
//! revealed ⇒ k * unit_price owed. Skipped intermediate reveals are fine.

use crate::hash::{shake256_32, DOM_PAYWORD_LINK, DOM_PAYWORD_SEED};

/// Payer-side chain. n=10_000 → 320 KB memory: trivial for server agents.
/// (Pebbling/checkpointing optimization is a TODO, not needed at agent scale.)
pub struct PaywordChain {
    /// words[i] = w_i; words[0] is the public tip.
    words: Vec<[u8; 32]>,
}

impl PaywordChain {
    /// Mint a fresh chain of `n` payable steps from a secret seed and a channel context.
    /// Sub-millisecond for n in the thousands (plan §6: "one P-chain per session").
    pub fn mint(seed: &[u8], channel_context: &[u8], n: u32) -> Self {
        assert!(n > 0, "empty chain");
        let mut words = vec![[0u8; 32]; (n + 1) as usize];
        words[n as usize] = shake256_32(DOM_PAYWORD_SEED, &[seed, channel_context, &n.to_le_bytes()]);
        for i in (0..n as usize).rev() {
            words[i] = shake256_32(DOM_PAYWORD_LINK, &[&words[i + 1]]);
        }
        Self { words }
    }

    /// The public tip w_0 — committed on-chain in `ChannelState.tip`.
    pub fn tip(&self) -> [u8; 32] {
        self.words[0]
    }

    /// Reveal the preimage paying up to step `k` (1-based; k ≤ n).
    pub fn pay(&self, k: u32) -> Option<[u8; 32]> {
        self.words.get(k as usize).copied()
    }

    pub fn max_steps(&self) -> u32 {
        (self.words.len() - 1) as u32
    }
}

/// Merchant-side verifier state: last accepted (word, step). Starts at (tip, 0).
/// Replay protection = monotone `step` (the "one highestIndex counter per channel" of the spec).
pub struct PaywordVerifier {
    last_word: [u8; 32],
    last_step: u32,
    max_steps: u32,
}

impl PaywordVerifier {
    pub fn new(tip: [u8; 32], max_steps: u32) -> Self {
        Self { last_word: tip, last_step: 0, max_steps }
    }

    /// Accept payment up to step `k` with revealed preimage `w_k`.
    /// Returns Ok(steps_newly_paid) or Err(()) if invalid/stale.
    pub fn accept(&mut self, k: u32, w_k: [u8; 32]) -> Result<u32, ()> {
        if k <= self.last_step || k > self.max_steps {
            return Err(());
        }
        // Hash forward (k - last_step) times; must land on last accepted word.
        let mut cur = w_k;
        for _ in 0..(k - self.last_step) {
            cur = shake256_32(DOM_PAYWORD_LINK, &[&cur]);
        }
        if cur != self.last_word {
            return Err(());
        }
        let newly = k - self.last_step;
        self.last_word = w_k;
        self.last_step = k;
        Ok(newly)
    }

    pub fn steps_paid(&self) -> u32 {
        self.last_step
    }

    /// (word, step) pair the merchant submits on-chain to settle (plan §6 settlement).
    pub fn settlement_claim(&self) -> ([u8; 32], u32) {
        (self.last_word, self.last_step)
    }
}

/// Chain-side settlement check (what the hk-channels module/state machine runs):
/// verify `word` at claimed `step` against the on-chain `tip`. O(step) hashes.
pub fn verify_settlement(tip: [u8; 32], word: [u8; 32], step: u32) -> bool {
    if step == 0 {
        return word == tip;
    }
    let mut cur = word;
    for _ in 0..step {
        cur = shake256_32(DOM_PAYWORD_LINK, &[&cur]);
    }
    cur == tip
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain() -> (PaywordChain, PaywordVerifier) {
        let c = PaywordChain::mint(b"test-seed-0000", b"channel-ctx", 100);
        let v = PaywordVerifier::new(c.tip(), 100);
        (c, v)
    }

    #[test]
    fn sequential_payments_verify() {
        let (c, mut v) = chain();
        for k in 1..=5u32 {
            assert_eq!(v.accept(k, c.pay(k).unwrap()), Ok(1));
        }
        assert_eq!(v.steps_paid(), 5);
    }

    #[test]
    fn skip_ahead_payment_counts_cumulatively() {
        let (c, mut v) = chain();
        assert_eq!(v.accept(37, c.pay(37).unwrap()), Ok(37));
        assert_eq!(v.accept(40, c.pay(40).unwrap()), Ok(3));
    }

    #[test]
    fn tampered_word_rejected() {
        let (c, mut v) = chain();
        let mut w = c.pay(3).unwrap();
        w[0] ^= 1;
        assert!(v.accept(3, w).is_err());
        assert_eq!(v.steps_paid(), 0); // state untouched on failure
    }

    #[test]
    fn replay_and_regress_rejected() {
        let (c, mut v) = chain();
        v.accept(10, c.pay(10).unwrap()).unwrap();
        assert!(v.accept(10, c.pay(10).unwrap()).is_err());
        assert!(v.accept(4, c.pay(4).unwrap()).is_err());
    }

    #[test]
    fn overclaim_beyond_max_rejected() {
        let (c, mut v) = chain();
        assert!(v.accept(101, c.pay(100).unwrap()).is_err());
    }

    #[test]
    fn settlement_check_matches() {
        let (c, mut v) = chain();
        v.accept(42, c.pay(42).unwrap()).unwrap();
        let (word, step) = v.settlement_claim();
        assert!(verify_settlement(c.tip(), word, step));
        assert!(!verify_settlement(c.tip(), word, step + 1));
    }

    #[test]
    fn distinct_contexts_give_distinct_chains() {
        let a = PaywordChain::mint(b"s", b"ctx-a", 10);
        let b = PaywordChain::mint(b"s", b"ctx-b", 10);
        assert_ne!(a.tip(), b.tip()); // channel binding — no cross-channel replay
    }
}
