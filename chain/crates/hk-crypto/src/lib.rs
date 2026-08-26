//! hk-crypto — the hash-based cryptography layer of HashKinetics.
//! Plan §3: pure hash-based signatures; SHAKE-256 everywhere outside circuits.
//!
//! REAL today: domain-separated SHAKE-256 hashing (`hash`), PayWord chains (`payword`, tested),
//! `hashsig` (LMS/HSS operational keys, feature `lms`), `slhdsa_adapter` (SLH-DSA-SHAKE-192s
//! stateless ROOT, feature `slhdsa` — certifies/rotates operational trees; never exhausts).
//! TRAITS today: `traits` (RootSigner / StatefulSigner / LeafBudget).
//! FEATURE-GATED (work queue): `mlkem` (ml-kem crate, P2 note encryption). XMSS: implement
//! against vendor/external/xmss-reference-c KATs — no mature Rust crate (research 03); LMS
//! covers agent keys until then.
//!
//! ⚠ Honesty guard: nothing in this crate is audited. KAT cross-checks against the
//! FIPS 205 reference implementation and the C references are REQUIRED before any key
//! holds value.

pub mod hash;
pub mod lamport;
/// SHAKE-256 authenticated encryption for note ciphertexts (P2.1) — pure hash, no AES dep.
pub mod noteenc;
pub mod payword;
pub mod traits;
pub mod wots; // types + spec notes only — no fake implementations

/// ML-KEM-768 stealth-address adapter (P2.1) — note CONFIDENTIALITY only per the threat
/// model: a future lattice break leaks old metadata, never forges or steals.
#[cfg(feature = "mlkem")]
pub mod mlkem;

#[cfg(feature = "slhdsa")]
pub mod slhdsa_adapter;
#[cfg(feature = "lms")]
pub mod lms_adapter;
/// Real stateful hash-based signatures (LMS/HSS over SHAKE-256) — the SCMS
/// operational-signing primitive for consensus votes + agent keys (0.9).
#[cfg(feature = "lms")]
pub mod hashsig;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("verification failed")]
    VerifyFailed,
    #[error("stateful key exhausted (leaf budget spent)")]
    KeyExhausted,
    #[error("leaf index {0} already used — equivocation hazard, freeze key")]
    IndexReused(u64),
    #[error("not yet implemented: {0}")]
    Unimplemented(&'static str),
}
