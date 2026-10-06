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
//!
//! L-2 (R17, reported 2026-10-06): two signing domains, chosen by the COMMIT HEIGHT of the
//! block that carries the certificate ([`RotationRules`]). v1 (`hk/v1/rotation-cert`, every
//! certificate testnet-1 has committed to date) binds no chain id, and its signed
//! `valid_from_height` was never read by any verifier — issuers wrote 0 or `tip + 1` and
//! the rotation always activated at commit + 1. v2 (`hk/v2/rotation-cert`) signs the chain
//! id exactly as `setchange` does, and a verifier enforces `valid_from_height` as a
//! freshness window: a certificate committed at height `h` activates at `h + 1` and is
//! valid only if `valid_from_height ≤ h + 1` (it cannot name a future height) and
//! `h + 1 ≤ valid_from_height + ROTATION_FRESHNESS_HORIZON` (an old certificate that never
//! landed cannot be carried in late). The staged activation docs/MAINNET-KEY-MANAGEMENT.md
//! once described (old tree signs until `valid_from_height`, new tree from there) is NOT
//! implemented — activation is commit + 1, as it has always been — and the window is the
//! simplest sound meaning the signed field can carry without new snapshot state. Before a
//! chain's v2 height the v1 rule applies byte for byte; from it ONLY v2 is accepted: a
//! verifier that still accepted v1 would let an un-upgraded seat keep rotating, but every
//! upgraded seat's v2 certificate would be refused by that un-upgraded verifier, which then
//! verifies the rotated seat's votes against a stale key and islands — so the height is
//! named only once the roll call shows every seat on the release (`genesis.rs`).

use serde::{Deserialize, Serialize};

use hk_crypto::slhdsa_adapter::{root_verify, RootSecret, ROOT_PK_LEN, ROOT_SIG_LEN};

use crate::hashsig_scheme::HkPub;

/// The v1 domain (v0.9.2 → v0.19.4): `tag ‖ 0x00 ‖ ⟨root_pk⟩ ‖ ⟨op_pk⟩ ‖ epoch ‖
/// valid_from_height`, no chain id. Every certificate committed before a chain's v2 height
/// is verified under it, byte for byte as before L-2.
pub const DOM_ROTATION_V1: &str = "hk/v1/rotation-cert";
/// L-2 (R17): the chain-bound domain — `tag ‖ 0x00 ‖ ⟨chain_id⟩ ‖ ⟨root_pk⟩ ‖ ⟨op_pk⟩ ‖
/// epoch ‖ valid_from_height`, mirroring `hk/v1/set-change`. staging-1 and testnet-1 roots
/// are disjoint (the ceremony rule: fresh keys per chain), so no cross-chain replay was
/// ever possible against the public chains; the binding closes the class for every chain
/// that may share a root in future (rehearsals, a mainnet ceremony that re-uses a seat).
pub const DOM_ROTATION_V2: &str = "hk/v2/rotation-cert";

/// L-2: how far behind its `valid_from_height` a v2 certificate may still commit (blocks).
/// Issuers write `tip + 1` (`RotationCert::issue_for` callers in hk-node: the commit-path
/// trigger, the R1.b tick and `issue-rotation <HOME> <EPOCH> <VALID_FROM> <CHAIN_ID>`), and
/// a certificate normally commits within the issuer's next few proposer slots; the R9
/// re-issue clock is 600 s. The revival path is a human (issue offline on the exhausted
/// seat's host, submit through any live peer — across a night, sometimes a weekend), so the
/// window is sized for people, not for the chain: 100,000 blocks ≈ 1.5 days at testnet-1's
/// 1.3 s cadence. Outside it the certificate is refused and must be re-issued at the tip.
/// The window is NOT the replay defence — epochs are monotone and the operational key for
/// an epoch is derived from the master seed (`op_seed`), so a replayed certificate could
/// only install the key the seat would install itself; it bounds how long a lost
/// certificate stays carriable, which is the one meaning `valid_from_height` can be given
/// without a staged activation.
pub const ROTATION_FRESHNESS_HORIZON: u64 = 100_000;

/// L-2: which domain a certificate is signed under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationDomain {
    V1,
    V2,
}

/// L-2: what a verifier brings to a certificate — the chain's rotation rule at one height.
/// Built by hk-node at every site that judges a certificate: `hk_submitRotation` (height =
/// tip + 1, the earliest height the certificate can commit at), propose (the proposal
/// height) and commit / replay (the commit height). The same rule at every site, so a
/// certificate the RPC accepts is one commit will apply.
#[derive(Clone, Copy, Debug)]
pub struct RotationRules<'a> {
    /// The commit height of the block carrying the certificate; the rotation activates at
    /// `height + 1` (HK-R6: the set history entry is `(height + 1, set)`).
    pub height: u64,
    /// `hk_chainInfo.chain_id` — signed into the v2 domain.
    pub chain_id: &'a str,
    /// The first height at which only v2 is accepted (`hk-node genesis::rotation_v2_from_for`):
    /// `u64::MAX` = never (testnet-1 until a later patch names it), `0` = from genesis
    /// (devnets, tests).
    pub v2_from: u64,
}

impl<'a> RotationRules<'a> {
    pub fn new(height: u64, chain_id: &'a str, v2_from: u64) -> Self {
        Self { height, chain_id, v2_from }
    }

    /// The domain a certificate committed at `self.height` must be signed under.
    pub fn domain(&self) -> RotationDomain {
        if self.height >= self.v2_from {
            RotationDomain::V2
        } else {
            RotationDomain::V1
        }
    }

    /// The height the certificate activates at.
    fn activation(&self) -> u64 {
        self.height.saturating_add(1)
    }
}

/// A root-signed certificate delegating consensus authority to a fresh operational key.
///
/// `root_pk` is the validator's permanent SLH-DSA identity (48 bytes); `new_op_pk` is the
/// fresh HSS operational public key; `epoch` is a strictly increasing rotation counter;
/// `valid_from_height` is the height the issuer named (v2: the freshness anchor — see the
/// module doc; activation itself is always commit + 1); `root_sig` is the SLH-DSA signature
/// (~16 KB) over the domain-separated body. The certificate carries no domain tag: the
/// commit height decides which domain it must verify under ([`RotationRules::domain`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationCert {
    pub root_pk: Vec<u8>,
    pub new_op_pk: HkPub,
    pub epoch: u64,
    pub valid_from_height: u64,
    pub root_sig: Vec<u8>,
}

fn put_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u64).to_le_bytes());
    buf.extend_from_slice(b);
}

impl RotationCert {
    /// The exact bytes the root signs: domain tag ‖ 0x00 ‖ (v2 only: length-prefixed
    /// chain id) ‖ length-prefixed root_pk ‖ length-prefixed operational pubkey ‖ epoch ‖
    /// valid_from_height. `chain_id` is ignored under v1 (the v1 preimage is pinned by
    /// `v1_preimage_is_byte_identical_to_v0_19_4`).
    pub fn signing_bytes(
        domain: RotationDomain,
        chain_id: &str,
        root_pk: &[u8],
        new_op_pk: &HkPub,
        epoch: u64,
        valid_from_height: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(DOM_ROTATION_V2.len() + 1 + chain_id.len() + root_pk.len() + new_op_pk.0.len() + 48);
        match domain {
            RotationDomain::V1 => {
                buf.extend_from_slice(DOM_ROTATION_V1.as_bytes());
                buf.push(0x00);
            }
            RotationDomain::V2 => {
                buf.extend_from_slice(DOM_ROTATION_V2.as_bytes());
                buf.push(0x00);
                put_bytes(&mut buf, chain_id.as_bytes());
            }
        }
        put_bytes(&mut buf, root_pk);
        put_bytes(&mut buf, &new_op_pk.0);
        buf.extend_from_slice(&epoch.to_le_bytes());
        buf.extend_from_slice(&valid_from_height.to_le_bytes());
        buf
    }

    /// Issue (sign) a rotation certificate with the validator's root secret under `domain`.
    pub fn issue(
        root: &RootSecret,
        domain: RotationDomain,
        chain_id: &str,
        new_op_pk: HkPub,
        epoch: u64,
        valid_from_height: u64,
    ) -> Self {
        let root_pk = root.public_bytes().to_vec();
        let msg = Self::signing_bytes(domain, chain_id, &root_pk, &new_op_pk, epoch, valid_from_height);
        let root_sig = root.sign(&msg);
        Self { root_pk, new_op_pk, epoch, valid_from_height, root_sig }
    }

    /// L-2: issue under the domain the chain will demand where this certificate commits.
    /// The issuer names `valid_from_height = tip + 1`; the certificate commits at some
    /// `h ≥ valid_from_height` (its own next proposal at the earliest), so v2 is chosen
    /// exactly when `valid_from_height ≥ v2_from` — then every height it can commit at
    /// demands v2. The one ambiguity is one-sided and self-healing: a v1 certificate issued
    /// within a few blocks BEFORE the chain's v2 height that only commits after it is
    /// refused, and R9 re-issues it (as v2) 600 s later.
    pub fn issue_for(
        root: &RootSecret,
        chain_id: &str,
        v2_from: u64,
        new_op_pk: HkPub,
        epoch: u64,
        valid_from_height: u64,
    ) -> Self {
        let domain = if valid_from_height >= v2_from { RotationDomain::V2 } else { RotationDomain::V1 };
        Self::issue(root, domain, chain_id, new_op_pk, epoch, valid_from_height)
    }

    /// Check only that the root signature is well-formed and authentic under `domain` (not
    /// epoch, identity or window — see [`verify_against`](Self::verify_against)).
    pub fn verify_sig(&self, domain: RotationDomain, chain_id: &str) -> bool {
        if self.root_pk.len() != ROOT_PK_LEN || self.root_sig.len() != ROOT_SIG_LEN {
            return false;
        }
        let msg = Self::signing_bytes(domain, chain_id, &self.root_pk, &self.new_op_pk, self.epoch, self.valid_from_height);
        root_verify(&self.root_pk, &msg, &self.root_sig)
    }

    /// L-2: the free (no signature) part of the v2 rule — the freshness window on
    /// `valid_from_height` against the activation height `rules.height + 1`. `Ok` under v1
    /// (the field was never read there and still is not). `hk_submitRotation` runs this in
    /// front of the verify; [`verify_against`](Self::verify_against) runs it again.
    pub fn check_window(&self, rules: &RotationRules<'_>) -> Result<(), String> {
        if rules.domain() == RotationDomain::V1 {
            return Ok(());
        }
        let activation = rules.activation();
        if self.valid_from_height > activation {
            // R17 review (2026-10-06): at the RPC the activation is THIS node's tip + 2, so
            // a certificate minted per the recipe (`valid_from = tip + 1` read on any live
            // peer) is refused by a node that lags the issuer's peer by ≥ 2 blocks although
            // commit would accept it later. Say so — "issue it at the tip" on the lagging
            // node reproduces the refusal.
            return Err(format!(
                "rotation cert: valid_from_height {} is past its activation height {} (a certificate cannot name a future height; submit it to a node whose tip is at least the one it was issued against, or re-issue it at this node's tip)",
                self.valid_from_height, activation
            ));
        }
        if self.valid_from_height.saturating_add(ROTATION_FRESHNESS_HORIZON) < activation {
            return Err(format!(
                "rotation cert: stale — valid_from_height {} is more than {ROTATION_FRESHNESS_HORIZON} blocks before its activation height {} (re-issue at the tip)",
                self.valid_from_height, activation
            ));
        }
        Ok(())
    }

    /// Full acceptance check against the validator's registered root identity, the last
    /// accepted epoch and the chain's rule at the commit height: issued by the registered
    /// root AND epoch strictly greater than the last (monotone — no rollback or replay) AND,
    /// under v2, inside the freshness window AND the signature valid under the domain the
    /// height demands. `last_epoch = None` accepts the bootstrap certificate. The `Err` text
    /// is what `hk_submitRotation` answers and what commit logs; the "invalid or stale"
    /// wording of a bad signature is v0.19.4's, byte for byte, with the domain appended
    /// under v2. A certificate that fails v2 but verifies under v1 is named as such, so an
    /// operator at the roll boundary reads "re-issue" instead of "forged".
    pub fn verify_against(
        &self,
        registered_root_pk: &[u8],
        last_epoch: Option<u64>,
        rules: &RotationRules<'_>,
    ) -> Result<(), String> {
        if self.root_pk != registered_root_pk {
            return Err("rotation cert: not issued by the registered root".to_string());
        }
        if let Some(prev) = last_epoch {
            if self.epoch <= prev {
                return Err(format!("rotation cert: stale (cert epoch {}, current {})", self.epoch, prev));
            }
        }
        self.check_window(rules)?;
        let current = last_epoch.unwrap_or(0);
        match rules.domain() {
            RotationDomain::V1 => {
                if self.verify_sig(RotationDomain::V1, "") {
                    Ok(())
                } else {
                    Err(format!("rotation cert: invalid or stale (cert epoch {}, current {current})", self.epoch))
                }
            }
            RotationDomain::V2 => {
                if self.verify_sig(RotationDomain::V2, rules.chain_id) {
                    Ok(())
                } else if self.verify_sig(RotationDomain::V1, "") {
                    Err(format!(
                        "rotation cert: signed under the v1 domain — from height {} this chain accepts only chain-bound v2 certificates (re-issue on a node that knows the height, or `hk-node issue-rotation <HOME> {} <TIP+1> {}`)",
                        rules.v2_from, self.epoch, rules.chain_id
                    ))
                } else {
                    Err(format!(
                        "rotation cert: invalid or stale (cert epoch {}, current {current}; v2 domain, chain {})",
                        self.epoch, rules.chain_id
                    ))
                }
            }
        }
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

    const CHAIN: &str = "hashkinetics-test";
    /// A chain that never activates v2 — the v0.19.4 rule.
    fn v1_rules(height: u64) -> RotationRules<'static> {
        RotationRules::new(height, CHAIN, u64::MAX)
    }
    /// A chain on v2 from genesis — the devnet rule.
    fn v2_rules(height: u64) -> RotationRules<'static> {
        RotationRules::new(height, CHAIN, 0)
    }

    #[test]
    fn v1_preimage_is_byte_identical_to_v0_19_4() {
        // The pre-L-2 `signing_bytes`, written out: a change here is a consensus break for
        // every certificate testnet-1 has committed.
        let root_pk = vec![0xaa; 48];
        let op = HkPub(vec![0xbb; 60]);
        let mut want = Vec::new();
        want.extend_from_slice(b"hk/v1/rotation-cert");
        want.push(0x00);
        want.extend_from_slice(&48u64.to_le_bytes());
        want.extend_from_slice(&root_pk);
        want.extend_from_slice(&60u64.to_le_bytes());
        want.extend_from_slice(&op.0);
        want.extend_from_slice(&7u64.to_le_bytes());
        want.extend_from_slice(&1234u64.to_le_bytes());
        assert_eq!(RotationCert::signing_bytes(RotationDomain::V1, CHAIN, &root_pk, &op, 7, 1234), want);
        // v1 ignores the chain id entirely.
        assert_eq!(
            RotationCert::signing_bytes(RotationDomain::V1, "another", &root_pk, &op, 7, 1234),
            RotationCert::signing_bytes(RotationDomain::V1, "", &root_pk, &op, 7, 1234)
        );
        // v2: the chain id is length-prefixed right after the separator, setchange-style.
        let mut want2 = Vec::new();
        want2.extend_from_slice(b"hk/v2/rotation-cert");
        want2.push(0x00);
        want2.extend_from_slice(&(CHAIN.len() as u64).to_le_bytes());
        want2.extend_from_slice(CHAIN.as_bytes());
        want2.extend_from_slice(&want[b"hk/v1/rotation-cert".len() + 1..]);
        assert_eq!(RotationCert::signing_bytes(RotationDomain::V2, CHAIN, &root_pk, &op, 7, 1234), want2);
        assert_ne!(
            RotationCert::signing_bytes(RotationDomain::V2, CHAIN, &root_pk, &op, 7, 1234),
            RotationCert::signing_bytes(RotationDomain::V2, "hashkinetics-1-deadbeef", &root_pk, &op, 7, 1234)
        );
    }

    #[test]
    fn rules_pick_the_domain_by_commit_height() {
        assert_eq!(v1_rules(u64::MAX - 1).domain(), RotationDomain::V1);
        assert_eq!(v2_rules(0).domain(), RotationDomain::V2);
        let r = RotationRules::new(999, CHAIN, 1_000);
        assert_eq!(r.domain(), RotationDomain::V1);
        let r = RotationRules::new(1_000, CHAIN, 1_000);
        assert_eq!(r.domain(), RotationDomain::V2);
    }

    #[test]
    fn issue_and_verify_rotation_chain_v1() {
        on_big_stack(|| {
            let root = RootSecret::from_seed(&[9u8; 32]);
            let root_pk = root.public_bytes().to_vec();

            let op0 = HkPub(vec![1u8; 60]);
            let op1 = HkPub(vec![2u8; 60]);

            // Bootstrap (epoch 0), then rotate to a fresh tree (epoch 1).
            let c0 = RotationCert::issue(&root, RotationDomain::V1, "", op0, 0, 1);
            let c1 = RotationCert::issue(&root, RotationDomain::V1, "", op1.clone(), 1, 100);

            assert_eq!(c0.verify_against(&root_pk, None, &v1_rules(50)), Ok(())); // bootstrap accepted
            assert_eq!(c1.verify_against(&root_pk, Some(0), &v1_rules(50)), Ok(())); // strictly newer epoch
            assert_eq!(c1.new_op_pk, op1);
            // v1 never reads valid_from_height: a "future" or ancient value is fine pre-activation.
            assert_eq!(c1.verify_against(&root_pk, Some(0), &v1_rules(0)), Ok(()));
            assert_eq!(c1.verify_against(&root_pk, Some(0), &v1_rules(10_000_000)), Ok(()));

            // Monotonicity: an older or equal epoch is a replay → rejected.
            assert!(c0.verify_against(&root_pk, Some(1), &v1_rules(50)).unwrap_err().contains("stale (cert epoch 0, current 1)"));
            assert!(c1.verify_against(&root_pk, Some(1), &v1_rules(50)).is_err());
        });
    }

    #[test]
    fn forged_and_wrong_root_rejected() {
        on_big_stack(|| {
            let root = RootSecret::from_seed(&[3u8; 32]);
            let root_pk = root.public_bytes().to_vec();

            let mut cert = RotationCert::issue(&root, RotationDomain::V1, "", HkPub(vec![7u8; 60]), 5, 10);
            assert_eq!(cert.verify_against(&root_pk, Some(4), &v1_rules(9)), Ok(()));

            // Tampered signature fails.
            let mid = cert.root_sig.len() / 2;
            cert.root_sig[mid] ^= 1;
            assert!(!cert.verify_sig(RotationDomain::V1, ""));
            assert!(cert.verify_against(&root_pk, Some(4), &v1_rules(9)).unwrap_err().contains("invalid or stale (cert epoch 5, current 4)"));

            // A valid cert must not verify against a different registered root, but does
            // against its true root.
            let good = RotationCert::issue(&root, RotationDomain::V1, "", HkPub(vec![7u8; 60]), 6, 11);
            let other_root = RootSecret::from_seed(&[4u8; 32]).public_bytes().to_vec();
            assert!(good.verify_against(&other_root, Some(5), &v1_rules(10)).is_err());
            assert_eq!(good.verify_against(&root_pk, Some(5), &v1_rules(10)), Ok(()));
        });
    }

    #[test]
    fn l2_v2_required_from_the_height_and_v1_only_before_it() {
        on_big_stack(|| {
            let root = RootSecret::from_seed(&[21u8; 32]);
            let root_pk = root.public_bytes().to_vec();
            let op = HkPub(vec![5u8; 60]);
            let v2_from = 1_000u64;
            let rules = |h: u64| RotationRules::new(h, CHAIN, v2_from);

            // The issuer picks the domain by valid_from_height against v2_from.
            let before = RotationCert::issue_for(&root, CHAIN, v2_from, op.clone(), 1, 999);
            let after = RotationCert::issue_for(&root, CHAIN, v2_from, op.clone(), 1, 1_000);
            assert!(before.verify_sig(RotationDomain::V1, ""));
            assert!(!before.verify_sig(RotationDomain::V2, CHAIN));
            assert!(after.verify_sig(RotationDomain::V2, CHAIN));
            assert!(!after.verify_sig(RotationDomain::V1, ""));

            // Before the height: v1 verifies exactly as today; v2 is refused (it is not a v1
            // signature — nothing else about it is looked at).
            assert_eq!(before.verify_against(&root_pk, Some(0), &rules(998)), Ok(()));
            assert_eq!(before.verify_against(&root_pk, Some(0), &rules(999)), Ok(()));
            let e = after.verify_against(&root_pk, Some(0), &rules(999)).unwrap_err();
            assert!(e.contains("invalid or stale (cert epoch 1, current 0)"), "{e}");

            // From the height: only v2. The v1 certificate is named as v1 so the operator
            // re-issues instead of suspecting a forgery.
            assert_eq!(after.verify_against(&root_pk, Some(0), &rules(1_000)), Ok(()));
            assert_eq!(after.verify_against(&root_pk, Some(0), &rules(1_500)), Ok(()));
            let e = before.verify_against(&root_pk, Some(0), &rules(1_000)).unwrap_err();
            assert!(e.contains("signed under the v1 domain"), "{e}");
            assert!(e.contains("issue-rotation <HOME> 1 <TIP+1> hashkinetics-test"), "{e}");

            // Monotone epoch still precedes everything under v2.
            let e = after.verify_against(&root_pk, Some(1), &rules(1_000)).unwrap_err();
            assert!(e.contains("stale (cert epoch 1, current 1)"), "{e}");
            // And the registered-root check.
            let other = RootSecret::from_seed(&[22u8; 32]).public_bytes().to_vec();
            assert!(after.verify_against(&other, Some(0), &rules(1_000)).unwrap_err().contains("registered root"));
        });
    }

    #[test]
    fn l2_chain_id_mismatch_refused() {
        on_big_stack(|| {
            let root = RootSecret::from_seed(&[23u8; 32]);
            let root_pk = root.public_bytes().to_vec();
            let cert = RotationCert::issue(&root, RotationDomain::V2, "hashkinetics-1-deadbeef", HkPub(vec![6u8; 60]), 3, 10);
            // Verifies for the chain it was signed for …
            assert_eq!(cert.verify_against(&root_pk, Some(2), &RotationRules::new(10, "hashkinetics-1-deadbeef", 0)), Ok(()));
            // … and for no other: a different chain id is a different preimage.
            let e = cert.verify_against(&root_pk, Some(2), &v2_rules(10)).unwrap_err();
            assert!(e.contains("invalid or stale (cert epoch 3, current 2; v2 domain, chain hashkinetics-test)"), "{e}");
            // A tampered v2 signature reads the same way (not "v1" — it verifies under neither).
            let mut bad = RotationCert::issue(&root, RotationDomain::V2, CHAIN, HkPub(vec![6u8; 60]), 3, 10);
            let mid = bad.root_sig.len() / 2;
            bad.root_sig[mid] ^= 1;
            assert!(bad.verify_against(&root_pk, Some(2), &v2_rules(10)).unwrap_err().contains("invalid or stale"));
        });
    }

    #[test]
    fn l2_valid_from_height_window_under_v2() {
        on_big_stack(|| {
            let root = RootSecret::from_seed(&[24u8; 32]);
            let root_pk = root.public_bytes().to_vec();
            let issue = |valid_from: u64| RotationCert::issue(&root, RotationDomain::V2, CHAIN, HkPub(vec![8u8; 60]), 2, valid_from);

            // The common case: issued at commit H with valid_from = H + 1, committed at H + 1.
            let c = issue(501);
            assert_eq!(c.verify_against(&root_pk, Some(1), &v2_rules(500)), Ok(())); // activation 501 == valid_from
            assert_eq!(c.verify_against(&root_pk, Some(1), &v2_rules(501)), Ok(())); // one block late
            assert_eq!(c.verify_against(&root_pk, Some(1), &v2_rules(500 + ROTATION_FRESHNESS_HORIZON)), Ok(())); // the last fresh height

            // From the future: refused (free check, in front of the signature).
            let e = c.verify_against(&root_pk, Some(1), &v2_rules(499)).unwrap_err();
            assert!(e.contains("valid_from_height 501 is past its activation height 500"), "{e}");
            assert_eq!(c.check_window(&v2_rules(499)).unwrap_err(), e);

            // Stale beyond the horizon: refused.
            let e = c.verify_against(&root_pk, Some(1), &v2_rules(501 + ROTATION_FRESHNESS_HORIZON)).unwrap_err();
            assert!(e.contains("stale — valid_from_height 501 is more than 100000 blocks before its activation height"), "{e}");
            assert_eq!(c.check_window(&v2_rules(501 + ROTATION_FRESHNESS_HORIZON)).unwrap_err(), e);

            // The legacy `issue-rotation` default of 0: fresh only while the chain is young.
            let zero = issue(0);
            assert_eq!(zero.verify_against(&root_pk, Some(1), &v2_rules(0)), Ok(()));
            assert_eq!(zero.verify_against(&root_pk, Some(1), &v2_rules(ROTATION_FRESHNESS_HORIZON - 1)), Ok(()));
            assert!(zero.verify_against(&root_pk, Some(1), &v2_rules(ROTATION_FRESHNESS_HORIZON)).is_err());

            // Under v1 the field is never read — the same certificates (signed v1) pass anywhere.
            let v1 = RotationCert::issue(&root, RotationDomain::V1, "", HkPub(vec![8u8; 60]), 2, 501);
            assert_eq!(v1.check_window(&v1_rules(0)), Ok(()));
            assert_eq!(v1.verify_against(&root_pk, Some(1), &v1_rules(0)), Ok(()));
            assert_eq!(v1.verify_against(&root_pk, Some(1), &v1_rules(10_000_000)), Ok(()));

            // No overflow at the top of the height space.
            assert_eq!(issue(u64::MAX).check_window(&v2_rules(u64::MAX)), Ok(()));
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

            // A rotates to a fresh operational key at epoch 1 (v2 chain, committed at 4).
            let new_op = HkPub(vec![7u8; 60]);
            let cert = RotationCert::issue(&root, RotationDomain::V2, CHAIN, new_op.clone(), 1, 5);
            let set2 = set.apply_rotation(&cert, &v2_rules(4)).expect("apply rotation");
            let a2 = set2.get_by_address(&addr_a).unwrap();
            assert_eq!(a2.public_key, new_op); // operational key swapped
            assert_eq!(a2.epoch, 1);
            assert_eq!(a2.address, addr_a); // identity (address) unchanged

            // Replaying the same cert (epoch no longer newer) is rejected.
            assert!(set2.apply_rotation(&cert, &v2_rules(5)).is_err());
            // A cert whose root is not in the set is rejected.
            let stranger = RootSecret::from_seed(&[99u8; 32]);
            let bad = RotationCert::issue(&stranger, RotationDomain::V2, CHAIN, HkPub(vec![3u8; 60]), 1, 5);
            assert!(set.apply_rotation(&bad, &v2_rules(4)).unwrap_err().contains("no validator with that root identity"));
            // The same v2 cert on a chain that has not activated v2 is refused (it is not v1).
            assert!(set.apply_rotation(&cert, &v1_rules(4)).is_err());
            // And a v1 cert applies there exactly as before.
            let v1 = RotationCert::issue(&root, RotationDomain::V1, "", new_op.clone(), 1, 0);
            assert_eq!(set.apply_rotation(&v1, &v1_rules(4)).unwrap().get_by_address(&addr_a).unwrap().epoch, 1);
        });
    }
}
