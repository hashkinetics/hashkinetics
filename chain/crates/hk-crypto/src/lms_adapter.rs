//! LMS/HSS stateful-signer adapter over the `hbs-lms` crate (vendored:
//! vendor/external/hbs-lms-rust). Work queue (P1): implement StatefulSigner with
//! LeafBudget persistence wired to reserve-then-sign; KAT cross-check against
//! vendor/external/lms-hash-sigs-c (Cisco reference). Parameter target: n=24 sets
//! (~0.9–1.1 KB sigs, plan §3.2).

use crate::CryptoError;

pub fn todo_marker() -> Result<(), CryptoError> {
    Err(CryptoError::Unimplemented("lms_adapter: KAT-gated, see module docs"))
}
