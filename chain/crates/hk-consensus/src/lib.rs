//! hk-consensus — HashKinetics' Malachite BFT integration (plan §7.1/§7.2).
//!
//! STATUS: HkContext slice — all consensus datatypes + signing provider, mirrored
//! faithfully from the engine's reference implementation (vendor/external/malachite/
//! code/crates/test/src/*), minus the protobuf codec layer (we use manual
//! deterministic sign-bytes with hk/v1 domain tags; a wire codec arrives with the
//! app-channel wiring, template: vendor/external/malachite/code/examples/channel).
//!
//! STATUS (0.9.1): consensus votes are hash-based (`HkContext::SigningScheme =
//! HkHashScheme`, LMS/HSS over SHAKE-256) — quantum-secure, live on the 4-validator
//! devnet. Operational state is persisted (reserve-then-sign). `rotation` adds the
//! SLH-DSA-192s root + RotationCert so operational trees rotate before exhaustion; the
//! live validator-set swap is the remaining integration step (docs/MAINNET-KEY-MANAGEMENT.md).
//! Ed25519 survives ONLY as libp2p transport identity, never ledger security.

pub mod context;
/// HK-R5.2: the dedicated verification thread pool (32 MiB stacks — hbs-lms needs them).
pub mod par;
pub mod provider;
/// Hash-based consensus signing scheme (LMS/HSS over SHAKE-256) — LIVE as
/// `HkContext::SigningScheme`.
pub mod hashsig_scheme;
/// SCMS validator key rotation — the stateless SLH-DSA-192s root certifies fresh
/// stateful operational trees before they exhaust (docs/MAINNET-KEY-MANAGEMENT.md).
pub mod rotation;
/// V1: validator-set changes on a running chain — a seat admitted or removed by a
/// supermajority of the current seats' roots (docs/V1-VALIDATOR-SET-CHANGES.md).
pub mod setchange;

pub use context::*;
pub use hashsig_scheme::{op_seed, HkHashScheme, HkPriv, HkPub, HkSig};
pub use provider::HkSigningProvider;
pub use rotation::RotationCert;
pub use setchange::{apply_set_change, Approval, SetChange, SetChangeBody, SetChangeCert};

/// The stateless SLH-DSA-192s validator root (re-exported for the node's genesis + rotation
/// issuance). Certifies operational trees; never exhausts (docs/MAINNET-KEY-MANAGEMENT.md).
pub use hk_crypto::slhdsa_adapter::RootSecret;
