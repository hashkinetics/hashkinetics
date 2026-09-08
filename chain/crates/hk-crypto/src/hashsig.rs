//! hashsig — the hash-based signature primitive for HashKinetics consensus votes
//! and agent operational keys (0.9). Backed by the vendored `hbs-lms` crate
//! (RFC 8554 LMS/HSS) over **SHAKE-256**, consistent with the two-hash doctrine
//! (SHAKE outside circuits). Feature-gated behind `lms`.
//!
//! This is the SCMS operational-signing primitive: a STATEFUL hash signature whose
//! private key advances every time it signs (leaf index = one-time use). `hbs-lms`
//! exposes exactly the right shape — signing takes the key bytes plus a callback
//! that hands back the NEW key bytes, so state advancement is explicit and
//! persistable. HashKinetics' consensus rule (leaf index = nonce, equivocation =
//! slashable fraud proof) turns the classic stateful-HBS hazard into a detectable,
//! punishable event (plan §3.3).
//!
//! Parameter set here: LM-OTS W2 + LMS H5 (32 signatures/tree) over SHAKE-256 — a
//! small tree suitable for KATs and short-lived session keys. Consensus validators
//! use a taller HSS multi-tree (see docs/HASHSIG-CONSENSUS-SWAP.md).
//!
//! ⚠ Reserve-then-sign: production signers MUST persist the advanced key bytes
//! (inside the update callback) BEFORE releasing the signature. The in-memory
//! signer below advances its own state; wire the callback to durable storage for
//! real validators.

use std::path::PathBuf;

use hbs_lms::{
    keygen, verify as hss_verify, HssParameter, HssSigningSession, LmotsAlgorithm, LmsAlgorithm,
    Seed, Shake256_256,
};

use crate::hash::shake256_n;

type H = Shake256_256;

const DOM_HASHSIG_SEED: &str = "hk/v1/hashsig-seed";

/// Consensus-grade capacity: two-level HSS (W2/H10 over W2/H10) over SHAKE-256 =
/// 2^20 ≈ 1,048,576 signatures per validator key (~4 days at 3 sigs/s). The top
/// tree is built at keygen; bottom trees are built lazily (~sub-second, once per
/// 1,024 signatures). See docs/HASHSIG-CONSENSUS-SWAP.md for the parameter rationale.
pub const CONSENSUS_CAPACITY: u64 = 1 << 15;

/// Aux-data cache size (bytes). hbs-lms caches upper Merkle-tree nodes here so signing
/// is O(tree-height) instead of O(2^height) — the difference between ~800 ms/sig and
/// ~tens of ms/sig for our H10 trees. 256 KiB comfortably caches useful levels.
///
/// R15 (2026-09-08, found by testnet-1 seat #1): until v0.18.2 this cache was silently
/// DISCARDED at every signature — hbs-lms compared its HMAC against everything after the
/// stored layers, and this buffer is longer than the finalized cache — so every vote
/// rebuilt the H10 authentication path from ~1,000 LM-OTS key generations (~450 ms).
/// Fixed in the vendored crate (`hss/aux.rs`), and the signer now keeps the expanded key
/// alive between signatures (`HssSigningSession`) instead of rebuilding the bottom tree
/// and re-signing its public key on every call.
pub const AUX_CACHE_SIZE: usize = 256 * 1024;

/// A stateful hash-based signer. `state` is the LMS/HSS private key bytes (advances on
/// every `sign`); `aux` is the hbs-lms authentication-path cache (empty ⇒ no cache);
/// `capacity` is the total signatures the tree can ever produce; `persist`, when set,
/// is the file the monotone state is durably written to BEFORE each signature is
/// released (reserve-then-sign — a restart never reuses a leaf).
pub struct HashSigner {
    state: Vec<u8>,
    aux: Vec<u8>,
    used: u64,
    capacity: u64,
    persist: Option<PathBuf>,
    /// The expanded HSS key kept between signatures (R15). Always derived from `state`;
    /// dropped whenever `state` is replaced from outside or a persistence write fails.
    session: Option<HssSigningSession<H>>,
}

/// Public verifying key bytes (LMS/HSS public key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashSigPublic(pub Vec<u8>);

/// `aux_size == 0` ⇒ no cache (fine for tiny H5 keys). Otherwise keygen fills an
/// `aux_size`-byte cache that signing reuses.
fn gen_with(
    params: &[HssParameter<H>],
    capacity: u64,
    aux_size: usize,
    seed32: &[u8; 32],
) -> (HashSigner, HashSigPublic) {
    let mut seed = Seed::<H>::default();
    let need = seed.as_mut_slice().len();
    let expanded = shake256_n(DOM_HASHSIG_SEED, &[seed32], need);
    seed.as_mut_slice().copy_from_slice(&expanded);

    let mut aux = vec![0u8; aux_size];
    let (sk, vk) = if aux_size > 0 {
        let mut a: &mut [u8] = &mut aux;
        keygen::<H>(params, &seed, Some(&mut a)).expect("hbs-lms keygen (aux)")
    } else {
        keygen::<H>(params, &seed, None).expect("hbs-lms keygen")
    };
    (
        HashSigner { state: sk.as_slice().to_vec(), aux, used: 0, capacity, persist: None, session: None },
        HashSigPublic(vk.as_slice().to_vec()),
    )
}

/// Serialize the monotone signer state as `used(8 LE) ‖ hbs-lms-state`.
fn encode_blob(used: u64, state: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + state.len());
    v.extend_from_slice(&used.to_le_bytes());
    v.extend_from_slice(state);
    v
}

/// Atomically write `bytes` to `path` (tmp + fsync + rename). Rename replaces the
/// destination on both Unix and Windows, so a crash leaves either the old or the new
/// file — never a torn one.
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Deterministically generate a KAT/session keypair from a 32-byte seed.
/// Single LMS tree, H5 = 32 signatures — for tests and short-lived session keys.
pub fn generate(seed32: &[u8; 32]) -> (HashSigner, HashSigPublic) {
    let params = [HssParameter::<H>::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5)];
    gen_with(&params, 32, 0, seed32)
}

/// Deterministically generate a **consensus** keypair (two-level HSS, ~1M signatures)
/// from a 32-byte seed, WITH the aux cache so per-vote signing is fast. The public key
/// is recoverable from the seed; the advancing private state persists separately.
pub fn generate_consensus(seed32: &[u8; 32]) -> (HashSigner, HashSigPublic) {
    // HSS top H10 / bottom H5 = 2^15 ≈ 32,768 signatures/validator. The BOTTOM tree is
    // the one rebuilt frequently (every 32 sigs), so keeping it small (H5 = 32 leaves)
    // is what makes per-signature signing fast (~ms) instead of rebuilding a 1,024-leaf
    // H10 subtree every time. The top H10 is rebuilt rarely and its path is aux-cached.
    // 32K sigs ≈ many hours of blocks; validators rotate to a fresh tree via the
    // SLH-DSA root before exhaustion (SCMS, plan §3.3).
    let params = [
        HssParameter::<H>::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH10),
        HssParameter::<H>::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
    ];
    gen_with(&params, CONSENSUS_CAPACITY, AUX_CACHE_SIZE, seed32)
}

impl HashSigner {
    /// Signatures remaining before the key is exhausted (the built-in count cap).
    pub fn remaining(&self) -> u64 {
        self.capacity.saturating_sub(self.used)
    }

    /// Current private-key state bytes — persist these (atomically) after every sign
    /// so a restart never reuses a leaf. This IS the monotone signer state.
    pub fn state_bytes(&self) -> &[u8] {
        &self.state
    }

    /// Reload persisted state (e.g. on validator restart). The advancing hbs-lms
    /// private-key bytes encode the leaf position; the public key is unchanged.
    /// ⚠ Never load an OLDER state than the last one persisted — that reuses leaves.
    pub fn load_state(&mut self, bytes: Vec<u8>) {
        self.state = bytes;
        self.session = None;
    }

    /// Signatures already produced by this tree.
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Attach a durable state file and adopt any state already on disk. Call this once,
    /// right after keygen, on the ONE signer that will advance this tree:
    /// - if `path` exists, load `used ‖ state` from it (resume past the last durable
    ///   leaf — the whole point of surviving a restart);
    /// - otherwise leave the fresh state in place; the first `sign` creates the file.
    ///
    /// The public key is seed-derived and unchanged; only the leaf position moves.
    pub fn attach_persistence(&mut self, path: PathBuf) -> std::io::Result<()> {
        if path.exists() {
            let blob = std::fs::read(&path)?;
            if blob.len() >= 8 {
                let mut u = [0u8; 8];
                u.copy_from_slice(&blob[..8]);
                self.used = u64::from_le_bytes(u);
                self.state = blob[8..].to_vec();
                self.session = None;
            }
        }
        self.persist = Some(path);
        Ok(())
    }

    /// Sign `msg`, advancing the key state. Returns the signature bytes, or `None`
    /// if the key is exhausted or signing fails.
    ///
    /// R15: the expanded HSS key lives in `self.session` between calls, so a signature costs
    /// one LM-OTS signature plus the bottom tree's authentication path — not a rebuild of the
    /// bottom tree and a fresh top-tree signature over it (that only happens on rollover,
    /// once per 32 signatures, and after a restart).
    ///
    /// Reserve-then-sign discipline, unchanged: the ADVANCED compressed state is written
    /// durably BEFORE the signature is released and before the in-memory key adopts it. If
    /// the durable write fails we release nothing, roll the session back (the next call
    /// rebuilds it from the persisted state) and the same leaf is retried — never reused,
    /// because the signature computed here never leaves this function.
    pub fn sign(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        if self.remaining() == 0 {
            return None;
        }
        if self.session.is_none() {
            self.session = Some(HssSigningSession::<H>::open(&self.state).ok()?);
        }
        let sig = {
            let session = self.session.as_mut()?;
            let res = if self.aux.is_empty() {
                session.sign(msg, None)
            } else {
                // Use the aux cache when present (consensus keys) — O(height) top-tree paths.
                let mut a: &mut [u8] = &mut self.aux;
                session.sign(msg, Some(&mut a))
            };
            match res {
                Ok(sig) => sig,
                Err(_) => {
                    self.session = None;
                    return None;
                }
            }
        };
        let next = self.session.as_ref()?.pending_private_key()?.as_slice().to_vec();
        if let Some(path) = &self.persist {
            if write_atomic(path, &encode_blob(self.used + 1, &next)).is_err() {
                if let Some(session) = self.session.as_mut() {
                    session.rollback();
                }
                return None;
            }
        }
        self.session.as_mut()?.commit();
        self.state = next;
        self.used += 1;
        Some(sig.as_ref().to_vec())
    }

    /// The pre-R15 signing path — a fresh expansion through `hbs_lms::sign` on every call.
    /// Kept as the reference the cached path is tested against (byte-identical signatures,
    /// identical state advance); not used by the node.
    #[cfg(test)]
    fn sign_uncached(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        use hbs_lms::sign as hss_sign;
        if self.remaining() == 0 {
            return None;
        }
        let current = self.state.clone();
        let mut advanced: Option<Vec<u8>> = None;
        let mut update = |new_key: &[u8]| {
            advanced = Some(new_key.to_vec());
            Ok(())
        };
        let sig = if self.aux.is_empty() {
            hss_sign::<H>(msg, &current, &mut update, None).ok()?
        } else {
            let mut a: &mut [u8] = &mut self.aux;
            hss_sign::<H>(msg, &current, &mut update, Some(&mut a)).ok()?
        };
        if let Some(ns) = advanced {
            if let Some(path) = &self.persist {
                if write_atomic(path, &encode_blob(self.used + 1, &ns)).is_err() {
                    return None;
                }
            }
            self.state = ns;
            self.used += 1;
            self.session = None;
        }
        Some(sig.as_ref().to_vec())
    }
}

/// Verify a signature against a public key. Stateless, order-free.
pub fn verify(msg: &[u8], sig: &[u8], public: &HashSigPublic) -> bool {
    hss_verify::<H>(msg, sig, &public.0).is_ok()
}

// ⚠ Stack note: hbs-lms keygen/sign allocate large fixed arrays on the stack.
// Run LMS operations on a thread with a generous stack (≥ 8 MiB). The consensus
// signing provider (0.9 swap) must build its tokio runtime / signer thread with an
// enlarged stack for the same reason — see docs/HASHSIG-CONSENSUS-SWAP.md.
#[cfg(test)]
fn on_big_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip_and_state_advances() {
        on_big_stack(|| {
            let (mut signer, pk) = generate(&[7u8; 32]);
            assert_eq!(signer.remaining(), 32);

            let m1 = b"hashkinetics prevote height=1";
            let s1 = signer.sign(m1).expect("sign 1");
            assert!(verify(m1, &s1, &pk));
            assert_eq!(signer.remaining(), 31);

            // A second signature uses a DIFFERENT leaf (state advanced) and still verifies.
            let m2 = b"hashkinetics precommit height=1";
            let s2 = signer.sign(m2).expect("sign 2");
            assert!(verify(m2, &s2, &pk));
            assert_ne!(s1, s2);
            assert_eq!(signer.remaining(), 30);
        });
    }

    #[test]
    fn tampered_signature_and_wrong_message_rejected() {
        on_big_stack(|| {
            let (mut signer, pk) = generate(&[9u8; 32]);
            let msg = b"authorize spend";
            let mut sig = signer.sign(msg).unwrap();
            assert!(verify(msg, &sig, &pk));

            // Flip a byte in the middle of the signature.
            let mid = sig.len() / 2;
            sig[mid] ^= 1;
            assert!(!verify(msg, &sig, &pk));

            // Original-shaped but wrong message.
            let (mut s2, pk2) = generate(&[9u8; 32]);
            let good = s2.sign(msg).unwrap();
            assert!(!verify(b"different message", &good, &pk2));
        });
    }

    #[test]
    fn deterministic_keygen() {
        on_big_stack(|| {
            let (_, a) = generate(&[1u8; 32]);
            let (_, b) = generate(&[1u8; 32]);
            let (_, c) = generate(&[2u8; 32]);
            assert_eq!(a, b);
            assert_ne!(a, c);
        });
    }

    #[test]
    fn wrong_key_rejected() {
        on_big_stack(|| {
            let (mut s1, _pk1) = generate(&[3u8; 32]);
            let (_s2, pk2) = generate(&[4u8; 32]);
            let msg = b"cross-key check";
            let sig = s1.sign(msg).unwrap();
            assert!(!verify(msg, &sig, &pk2));
        });
    }

    #[test]
    fn consensus_key_signs_verifies_advances_and_persists() {
        on_big_stack(|| {
            let (mut signer, pk) = generate_consensus(&[42u8; 32]);
            assert_eq!(signer.remaining(), CONSENSUS_CAPACITY);

            // Two consensus messages (a prevote + a precommit).
            let m1 = b"hk consensus prevote h=1 r=0";
            let s1 = signer.sign(m1).expect("consensus sign 1");
            assert!(verify(m1, &s1, &pk));

            // Persist state after signing (the reserve-then-sign discipline),
            // then reconstruct a fresh signer from seed + persisted state.
            let persisted = signer.state_bytes().to_vec();
            let m2 = b"hk consensus precommit h=1 r=0";
            let s2 = signer.sign(m2).expect("consensus sign 2");
            assert!(verify(m2, &s2, &pk));
            assert_ne!(s1, s2);

            // A restarted validator: same seed → same public key; load persisted state.
            let (mut restarted, pk2) = generate_consensus(&[42u8; 32]);
            assert_eq!(pk, pk2); // public key is seed-derived, restart-stable
            restarted.load_state(persisted);
            let s2b = restarted.sign(m2).expect("post-restart sign");
            assert!(verify(m2, &s2b, &pk));
        });
    }

    #[test]
    fn file_persistence_survives_restart_without_leaf_reuse() {
        on_big_stack(|| {
            let path = std::env::temp_dir()
                .join(format!("hk_consensus_state_{}.bin", std::process::id()));
            let _ = std::fs::remove_file(&path);

            // Fresh signer; attach the durable file (absent ⇒ starts at leaf 0).
            let (mut s1, pk) = generate_consensus(&[77u8; 32]);
            s1.attach_persistence(path.clone()).unwrap();
            assert_eq!(s1.used(), 0);

            let a = s1.sign(b"h=1 prevote").expect("sign a");
            let b = s1.sign(b"h=1 precommit").expect("sign b");
            assert!(verify(b"h=1 prevote", &a, &pk));
            assert!(verify(b"h=1 precommit", &b, &pk));
            assert_eq!(s1.used(), 2); // file now records used = 2
            drop(s1);

            // "Restart": a new signer from the SAME seed re-attaches the SAME file and
            // must resume PAST the last durable leaf — never reusing leaves 0 or 1.
            let (mut s2, pk2) = generate_consensus(&[77u8; 32]);
            assert_eq!(pk, pk2); // seed-derived, restart-stable
            s2.attach_persistence(path.clone()).unwrap();
            assert_eq!(s2.used(), 2);

            let c = s2.sign(b"h=2 prevote").expect("post-restart sign");
            assert!(verify(b"h=2 prevote", &c, &pk));
            assert_ne!(a, c);
            assert_ne!(b, c);
            assert_eq!(s2.used(), 3);

            let _ = std::fs::remove_file(&path);
        });
    }

    /// R15: the cached session path must be byte-identical to the pre-R15 fresh-expansion
    /// path for the same seed — signatures AND advancing state — across two bottom-tree
    /// rollovers (H5 = 32 leaves; 70 signatures cross 32 and 64).
    #[test]
    fn r15_cached_signing_matches_uncached_across_rollover() {
        on_big_stack(|| {
            let (mut cached, pk) = generate_consensus(&[15u8; 32]);
            let (mut reference, pk2) = generate_consensus(&[15u8; 32]);
            assert_eq!(pk, pk2);
            for i in 0u32..70 {
                let msg = format!("hk vote h={} r=0", i);
                let a = cached.sign(msg.as_bytes()).expect("cached sign");
                let b = reference.sign_uncached(msg.as_bytes()).expect("uncached sign");
                assert_eq!(a, b, "signature {} differs between cached and uncached", i);
                assert_eq!(cached.state_bytes(), reference.state_bytes(), "state {} differs", i);
                assert_eq!(cached.used(), reference.used());
                assert!(verify(msg.as_bytes(), &a, &pk), "signature {} must verify", i);
            }
            assert_eq!(cached.remaining(), CONSENSUS_CAPACITY - 70);
        });
    }

    /// R15: a failed durable write releases nothing and retries the SAME leaf next time.
    #[test]
    fn r15_persistence_failure_retries_the_same_leaf() {
        on_big_stack(|| {
            let (mut signer, pk) = generate_consensus(&[16u8; 32]);
            let (mut reference, _) = generate_consensus(&[16u8; 32]);
            // One good signature first so the session is warm.
            let m0 = b"h=1 prevote";
            assert_eq!(signer.sign(m0).unwrap(), reference.sign_uncached(m0).unwrap());

            // A persistence path whose parent directory does not exist: write_atomic fails.
            let bad = std::env::temp_dir()
                .join(format!("hk_r15_missing_dir_{}", std::process::id()))
                .join("state.bin");
            signer.persist = Some(bad);
            let m1 = b"h=1 precommit";
            assert!(signer.sign(m1).is_none(), "a failed durable write must release nothing");
            assert_eq!(signer.used(), 1, "the leaf counter must not advance");

            // Persistence restored: the same leaf signs — identical bytes to the reference,
            // which never failed.
            signer.persist = None;
            let again = signer.sign(m1).expect("sign after the failure");
            assert_eq!(again, reference.sign_uncached(m1).unwrap(), "the same leaf must be used");
            assert!(verify(m1, &again, &pk));
            assert_eq!(signer.state_bytes(), reference.state_bytes());
        });
    }

    /// R15: a restart (fresh keygen + persisted state) continues with the session exactly
    /// where the reference path would — no leaf skipped, none reused.
    #[test]
    fn r15_restart_resumes_identically() {
        on_big_stack(|| {
            let path = std::env::temp_dir()
                .join(format!("hk_r15_restart_{}.bin", std::process::id()));
            let _ = std::fs::remove_file(&path);
            let (mut s1, pk) = generate_consensus(&[17u8; 32]);
            let (mut reference, _) = generate_consensus(&[17u8; 32]);
            s1.attach_persistence(path.clone()).unwrap();
            for i in 0..40u32 {
                let msg = format!("h={} vote", i);
                assert_eq!(s1.sign(msg.as_bytes()).unwrap(), reference.sign_uncached(msg.as_bytes()).unwrap());
            }
            drop(s1);
            let (mut s2, pk2) = generate_consensus(&[17u8; 32]);
            assert_eq!(pk, pk2);
            s2.attach_persistence(path.clone()).unwrap();
            assert_eq!(s2.used(), 40);
            for i in 40..45u32 {
                let msg = format!("h={} vote", i);
                let a = s2.sign(msg.as_bytes()).expect("post-restart sign");
                assert_eq!(a, reference.sign_uncached(msg.as_bytes()).unwrap(), "post-restart {} differs", i);
                assert!(verify(msg.as_bytes(), &a, &pk));
            }
            let _ = std::fs::remove_file(&path);
        });
    }

    /// R15 receipt: cached signing must be at least 5x faster than the fresh-expansion path
    /// (the fresh path does a whole bottom-tree build + a top-tree signature per call).
    /// Prints both medians; run with `-- --nocapture` for the numbers.
    #[test]
    fn r15_cached_signing_is_faster() {
        on_big_stack(|| {
            let (mut cached, _) = generate_consensus(&[18u8; 32]);
            let (mut reference, _) = generate_consensus(&[18u8; 32]);
            let n = 12u32;
            let bench = |f: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>| -> u128 {
                let mut samples: Vec<u128> = Vec::new();
                for i in 0..n {
                    let msg = format!("bench {}", i);
                    let t = std::time::Instant::now();
                    f(msg.as_bytes()).expect("sign");
                    samples.push(t.elapsed().as_micros());
                }
                samples.sort();
                samples[samples.len() / 2]
            };
            let warm = cached.sign(b"warm").unwrap();
            assert!(!warm.is_empty());
            let fast = bench(&mut |m| cached.sign(m));
            let slow = bench(&mut |m| reference.sign_uncached(m));
            println!("R15 median per signature: cached {} us, uncached {} us", fast, slow);
            assert!(fast * 5 <= slow, "cached ({} us) should be >= 5x faster than uncached ({} us)", fast, slow);
        });
    }
}
