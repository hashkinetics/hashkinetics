//! SCMS validator key rotation — the "after exhaustion" mechanism.
//!
//! A validator's permanent identity is a STATELESS SLH-DSA-SHAKE-192s root key. When its
//! stateful LMS/HSS operational tree nears exhaustion, the validator generates a fresh
//! operational tree and the root signs a [`RotationCert`] binding the new operational
//! public key. Because the root never exhausts, this repeats forever — the finite
//! operational key is renewed by the inexhaustible root. See docs/MAINNET-KEY-MANAGEMENT.md.
//!
//! Verification is stateless and order-free: any party checks (1) the root signature,
//! (2) that the cert's root matches the validator's registered identity, and (3) that the
//! epoch strictly increases (monotone — rollback/replay rejected).

use serde::{Deserialize, Serialize};

use hk_crypto::slhdsa_adapter::{root_verify, RootSecret, ROOT_PK_LEN, ROOT_SIG_LEN};

use crate::hashsig_scheme::HkPub;

const DOM_ROTATION: &str = "hk/v1/rotation-cert";

/// A root-signed certificate delegating consensus authority to a fresh operational key.
///
/// `root_pk` is the validator's permanent SLH-DSA identity (48 bytes); `new_op_pk` is the
/// fresh HSS operational public key; `epoch` is a strictly increasing rotation counter;
/// `valid_from_height` is the height at which the new key takes over; `root_sig` is the
/// SLH-DSA signature (~16 KB) over the domain-separated body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationCert {
    pub root_pk: Vec<u8>,
    pub new_op_pk: HkPub,
    pub epoch: u64,
    pub valid_from_height: u64,
    pub root_sig: Vec<u8>,
}

impl RotationCert {
    /// The exact bytes the root signs: domain tag ‖ length-prefixed root_pk ‖
    /// length-prefixed operational pubkey ‖ epoch ‖ valid_from_height.
    pub fn signing_bytes(
        root_pk: &[u8],
        new_op_pk: &HkPub,
        epoch: u64,
        valid_from_height: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(DOM_ROTATION.len() + 1 + root_pk.len() + new_op_pk.0.len() + 32);
        buf.extend_from_slice(DOM_ROTATION.as_bytes());
        buf.push(0x00);
        buf.extend_from_slice(&(root_pk.len() as u64).to_le_bytes());
        buf.extend_from_slice(root_pk);
        buf.extend_from_slice(&(new_op_pk.0.len() as u64).to_le_bytes());
        buf.extend_from_slice(&new_op_pk.0);
        buf.extend_from_slice(&epoch.to_le_bytes());
        buf.extend_from_slice(&valid_from_height.to_le_bytes());
        buf
    }

    /// Issue (sign) a rotation certificate with the validator's root secret.
    pub fn issue(root: &RootSecret, new_op_pk: HkPub, epoch: u64, valid_from_height: u64) -> Self {
        let root_pk = root.public_bytes().to_vec();
        let msg = Self::signing_bytes(&root_pk, &new_op_pk, epoch, valid_from_height);
        let root_sig = root.sign(&msg);
        Self { root_pk, new_op_pk, epoch, valid_from_height, root_sig }
    }

    /// Check only that the root signature is well-formed and authentic (not epoch or
    /// identity — see [`verify_against`]).
    pub fn verify_sig(&self) -> bool {
        if self.root_pk.len() != ROOT_PK_LEN || self.root_sig.len() != ROOT_SIG_LEN {
            return false;
        }
        let msg = Self::signing_bytes(&self.root_pk, &self.new_op_pk, self.epoch, self.valid_from_height);
        root_verify(&self.root_pk, &msg, &self.root_sig)
    }

    /// Full acceptance check against the validator's registered root identity and the last
    /// accepted epoch: signature valid AND issued by the registered root AND epoch strictly
    /// greater than the last (monotone — no rollback or replay). `last_epoch = None` accepts
    /// the bootstrap certificate.
    pub fn verify_against(&self, registered_root_pk: &[u8], last_epoch: Option<u64>) -> bool {
        if self.root_pk != registered_root_pk {
            return false;
        }
        if let Some(prev) = last_epoch {
            if self.epoch <= prev {
                return false;
            }
        }
        self.verify_sig()
    }
}

// SLH-DSA operations allocate large fixed arrays — run tests on a generous stack.
#[cfg(test)]
fn on_big_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new().stack_size(32 * 1024 * 1024).spawn(f).unwrap().join().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_verify_rotation_chain() {
        on_big_stack(|| {
            let root = RootSecret::from_seed(&[9u8; 32]);
            let root_pk = root.public_bytes().to_vec();

            let op0 = HkPub(vec![1u8; 60]);
            let op1 = HkPub(vec![2u8; 60]);

            // Bootstrap (epoch 0), then rotate to a fresh tree (epoch 1).
            let c0 = RotationCert::issue(&root, op0, 0, 1);
            let c1 = RotationCert::issue(&root, op1.clone(), 1, 100);

            assert!(c0.verify_against(&root_pk, None)); // bootstrap accepted
            assert!(c1.verify_against(&root_pk, Some(0))); // strictly newer epoch
            assert_eq!(c1.new_op_pk, op1);

            // Monotonicity: an older or equal epoch is a replay → rejected.
            assert!(!c0.verify_against(&root_pk, Some(1)));
            assert!(!c1.verify_against(&root_pk, Some(1)));
        });
    }

    #[test]
    fn forged_and_wrong_root_rejected() {
        on_big_stack(|| {
            let root = RootSecret::from_seed(&[3u8; 32]);
            let root_pk = root.public_bytes().to_vec();

            let mut cert = RotationCert::issue(&root, HkPub(vec![7u8; 60]), 5, 10);
            assert!(cert.verify_against(&root_pk, Some(4)));

            // Tampered signature fails.
            let mid = cert.root_sig.len() / 2;
            cert.root_sig[mid] ^= 1;
            assert!(!cert.verify_sig());

            // A valid cert must not verify against a different registered root, but does
            // against its true root.
            let good = RotationCert::issue(&root, HkPub(vec![7u8; 60]), 6, 11);
            let other_root = RootSecret::from_seed(&[4u8; 32]).public_bytes().to_vec();
            assert!(!good.verify_against(&other_root, Some(5)));
            assert!(good.verify_against(&root_pk, Some(5)));
        });
    }

    #[test]
    fn validator_set_applies_and_rejects_rotation() {
        on_big_stack(|| {
            use crate::context::{HkValidator, HkValidatorSet};

            let root = RootSecret::from_seed(&[11u8; 32]);
            let root_pk = root.public_bytes().to_vec();

            // Two validators; A carries `root`'s identity, B a stranger's.
            let a = HkValidator::new(root_pk.clone(), HkPub(vec![1u8; 60]), 1);
            let b = HkValidator::new(vec![9u8; 48], HkPub(vec![2u8; 60]), 1);
            let addr_a = a.address;
            let set = HkValidatorSet::new(vec![a, b]);

            // A rotates to a fresh operational key at epoch 1.
            let new_op = HkPub(vec![7u8; 60]);
            let cert = RotationCert::issue(&root, new_op.clone(), 1, 5);
            let set2 = set.apply_rotation(&cert).expect("apply rotation");
            let a2 = set2.get_by_address(&addr_a).unwrap();
            assert_eq!(a2.public_key, new_op); // operational key swapped
            assert_eq!(a2.epoch, 1);
            assert_eq!(a2.address, addr_a); // identity (address) unchanged

            // Replaying the same cert (epoch no longer newer) is rejected.
            assert!(set2.apply_rotation(&cert).is_err());
            // A cert whose root is not in the set is rejected.
            let stranger = RootSecret::from_seed(&[99u8; 32]);
            let bad = RotationCert::issue(&stranger, HkPub(vec![3u8; 60]), 1, 5);
            assert!(set.apply_rotation(&bad).is_err());
        });
    }
}
