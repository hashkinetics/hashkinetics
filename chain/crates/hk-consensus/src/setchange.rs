//! V1 — validator-set changes on a RUNNING chain (docs/V1-VALIDATOR-SET-CHANGES.md).
//!
//! Until v0.14 the validator set was a genesis fact: every external cohort needed a new
//! genesis. A [`SetChangeCert`] admits or removes one seat mid-chain, authorized by a
//! **supermajority of the current seats' stateless SLH-DSA-192s roots** (each approval is
//! a full root signature over the same domain-separated body). No new genesis field, no
//! coordinator key: the seats that hold the chain today vote a seat in or out, offline,
//! with the same keys that certify their own rotations. Mainnet replaces this with bonded
//! self-admission + governance; the certificate shape stays.
//!
//! Safety properties, all checked at submit, at propose AND at commit (every node,
//! deterministically, against the set as it stands at that moment):
//!   * `body.chain_id` must be this chain's id — no cross-network replay.
//!   * every approval's root must be a DISTINCT member of the current set, its signature
//!     valid; approving power must be strictly more than ⅔ of the set's total power.
//!   * the commit height must lie in `[not_before, not_after]` — a stale certificate
//!     (approved months ago, found later) cannot be committed.
//!   * application is idempotent: admitting a root already seated, or removing one not
//!     seated, is a no-op — a replay inside the window changes nothing (and once the set
//!     has grown, a replay whose approvers no longer form a supermajority of the CURRENT
//!     set is refused outright, which is the same outcome: nothing changes).
//!   * a removal may never empty the set or drop the remaining power below the approving
//!     supermajority's ability to keep deciding (the set must keep ≥ 1 seat).
//!
//! Like `RotationCert`, the cert rides a block (`Batch.set_changes`, wire v2) and takes
//! effect for height + 1; HK-R6 per-height set history makes sync across the boundary
//! free. Bincode is positional, so the certificate carries no optional fields.

use serde::{Deserialize, Serialize};

use hk_crypto::slhdsa_adapter::{root_verify, RootSecret, ROOT_PK_LEN, ROOT_SIG_LEN};

use crate::context::{HkValidator, HkValidatorSet};
use crate::hashsig_scheme::HkPub;

const DOM_SET_CHANGE: &str = "hk/v1/set-change";

/// What changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SetChange {
    /// Seat a new validator: its permanent root identity, its genesis operational key
    /// (exactly the `validator.json` that `hk-node keygen` prints) and its voting power.
    Admit { root_pk: Vec<u8>, public_key: HkPub, voting_power: u64 },
    /// Unseat the validator with this root identity.
    Remove { root_pk: Vec<u8> },
    /// G1 (v0.18.0): change a seated validator's voting power in place (root identity,
    /// operational key and epoch untouched). The handover tool: the founding seats lower
    /// their own weight, or raise an external's, by certificate — never by binary.
    SetPower { root_pk: Vec<u8>, voting_power: u64 },
}

/// The signed body — everything an approver commits to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetChangeBody {
    /// The network this change is for (`hk_chainInfo.chain_id`).
    pub chain_id: String,
    pub change: SetChange,
    /// Earliest commit height at which the change may be applied.
    pub not_before: u64,
    /// Latest commit height at which the change may be applied (freshness window).
    pub not_after: u64,
}

/// One seat's approval: its root identity + its SLH-DSA signature over the body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub root_pk: Vec<u8>,
    pub root_sig: Vec<u8>,
}

/// The certificate that rides a block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetChangeCert {
    pub body: SetChangeBody,
    pub approvals: Vec<Approval>,
}

fn put_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u64).to_le_bytes());
    buf.extend_from_slice(b);
}

impl SetChangeBody {
    /// The exact bytes every approver signs: domain tag ‖ 0x00 ‖ chain id ‖ variant tag ‖
    /// the variant's fields (length-prefixed) ‖ not_before ‖ not_after. Binary and
    /// explicit — never a serde form — so the signature domain is independent of codecs.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(DOM_SET_CHANGE.as_bytes());
        buf.push(0x00);
        put_bytes(&mut buf, self.chain_id.as_bytes());
        match &self.change {
            SetChange::Admit { root_pk, public_key, voting_power } => {
                buf.push(0x01);
                put_bytes(&mut buf, root_pk);
                put_bytes(&mut buf, &public_key.0);
                buf.extend_from_slice(&voting_power.to_le_bytes());
            }
            SetChange::Remove { root_pk } => {
                buf.push(0x02);
                put_bytes(&mut buf, root_pk);
            }
            SetChange::SetPower { root_pk, voting_power } => {
                buf.push(0x03);
                put_bytes(&mut buf, root_pk);
                buf.extend_from_slice(&voting_power.to_le_bytes());
            }
        }
        buf.extend_from_slice(&self.not_before.to_le_bytes());
        buf.extend_from_slice(&self.not_after.to_le_bytes());
        buf
    }

    /// The root identity this change is about.
    pub fn subject_root(&self) -> &[u8] {
        match &self.change {
            SetChange::Admit { root_pk, .. } => root_pk,
            SetChange::Remove { root_pk } => root_pk,
            SetChange::SetPower { root_pk, .. } => root_pk,
        }
    }

    /// Structural sanity that needs no set: window ordered, key sizes right, power > 0.
    pub fn check_shape(&self) -> Result<(), String> {
        if self.chain_id.is_empty() {
            return Err("set change: empty chain_id".into());
        }
        if self.not_after < self.not_before {
            return Err("set change: not_after < not_before".into());
        }
        match &self.change {
            SetChange::Admit { root_pk, public_key, voting_power } => {
                if root_pk.len() != ROOT_PK_LEN {
                    return Err(format!("set change: root_pk must be {ROOT_PK_LEN} bytes"));
                }
                if public_key.0.is_empty() {
                    return Err("set change: empty operational public key".into());
                }
                if *voting_power == 0 {
                    return Err("set change: voting_power must be ≥ 1".into());
                }
            }
            SetChange::Remove { root_pk } => {
                if root_pk.len() != ROOT_PK_LEN {
                    return Err(format!("set change: root_pk must be {ROOT_PK_LEN} bytes"));
                }
            }
            SetChange::SetPower { root_pk, voting_power } => {
                if root_pk.len() != ROOT_PK_LEN {
                    return Err(format!("set change: root_pk must be {ROOT_PK_LEN} bytes"));
                }
                if *voting_power == 0 {
                    return Err("set change: voting_power must be ≥ 1 (remove the seat instead)".into());
                }
            }
        }
        Ok(())
    }
}

impl Approval {
    /// Sign the body with a seat's root secret (offline: `hk-node set-change approve`).
    pub fn sign(root: &RootSecret, body: &SetChangeBody) -> Self {
        let root_pk = root.public_bytes().to_vec();
        let root_sig = root.sign(&body.signing_bytes());
        Self { root_pk, root_sig }
    }

    pub fn verify(&self, body: &SetChangeBody) -> bool {
        if self.root_pk.len() != ROOT_PK_LEN || self.root_sig.len() != ROOT_SIG_LEN {
            return false;
        }
        root_verify(&self.root_pk, &body.signing_bytes(), &self.root_sig)
    }
}

impl SetChangeCert {
    /// Full acceptance check against the set as it stands: chain id, shape, every
    /// approval from a distinct CURRENT seat with a valid signature, approving power
    /// strictly greater than ⅔ of total. Height-window and idempotence are checked by
    /// [`apply_set_change`] because they depend on the commit height / current membership.
    pub fn verify_against(&self, set: &HkValidatorSet, chain_id: &str) -> Result<(), String> {
        self.body.check_shape()?;
        if self.body.chain_id != chain_id {
            return Err(format!(
                "set change: for chain {} — this is {chain_id}",
                self.body.chain_id
            ));
        }
        if self.approvals.is_empty() {
            return Err("set change: no approvals".into());
        }
        let total = set.total_voting_power();
        let mut approving: u64 = 0;
        let mut seen: Vec<&[u8]> = Vec::with_capacity(self.approvals.len());
        for a in &self.approvals {
            if seen.iter().any(|s| *s == a.root_pk.as_slice()) {
                return Err("set change: duplicate approval from one root".into());
            }
            let seat = set
                .iter()
                .find(|v| v.root_pk == a.root_pk)
                .ok_or_else(|| "set change: approval from a root that is not seated".to_string())?;
            if !a.verify(&self.body) {
                return Err("set change: invalid approval signature".into());
            }
            seen.push(&a.root_pk);
            approving = approving.saturating_add(seat.voting_power);
        }
        // strictly more than two thirds: 3·approving > 2·total
        if approving.saturating_mul(3) <= total.saturating_mul(2) {
            return Err(format!(
                "set change: approving power {approving} is not > 2/3 of {total}"
            ));
        }
        Ok(())
    }

    /// Would this certificate be committable at `height` (window)?
    pub fn in_window(&self, height: u64) -> bool {
        self.body.not_before <= height && height <= self.body.not_after
    }
}

/// Apply a certificate to a set at commit `height`. `Ok(Some(new_set))` = the set
/// changed; `Ok(None)` = valid but a no-op (already seated / not seated: an in-window
/// replay); `Err` = invalid here (bad approvals, outside the window, would empty the set).
pub fn apply_set_change(
    set: &HkValidatorSet,
    cert: &SetChangeCert,
    height: u64,
    chain_id: &str,
) -> Result<Option<HkValidatorSet>, String> {
    cert.verify_against(set, chain_id)?;
    if !cert.in_window(height) {
        return Err(format!(
            "set change: height {height} outside [{}, {}]",
            cert.body.not_before, cert.body.not_after
        ));
    }
    match &cert.body.change {
        SetChange::Admit { root_pk, public_key, voting_power } => {
            if set.iter().any(|v| &v.root_pk == root_pk) {
                return Ok(None);
            }
            let newcomer = HkValidator::new(root_pk.clone(), public_key.clone(), *voting_power);
            if set.iter().any(|v| v.address == newcomer.address) {
                return Err("set change: operational key collides with a seated address".into());
            }
            let mut vals: Vec<HkValidator> = set.iter().cloned().collect();
            vals.push(newcomer);
            Ok(Some(HkValidatorSet::new(vals)))
        }
        SetChange::Remove { root_pk } => {
            if !set.iter().any(|v| &v.root_pk == root_pk) {
                return Ok(None);
            }
            let vals: Vec<HkValidator> =
                set.iter().filter(|v| &v.root_pk != root_pk).cloned().collect();
            if vals.is_empty() {
                return Err("set change: refusing to remove the last seat".into());
            }
            Ok(Some(HkValidatorSet::new(vals)))
        }
        SetChange::SetPower { root_pk, voting_power } => {
            let seat = set
                .iter()
                .find(|v| &v.root_pk == root_pk)
                .ok_or_else(|| "set change: set-power for a root that is not seated".to_string())?;
            if seat.voting_power == *voting_power {
                return Ok(None);
            }
            let vals: Vec<HkValidator> = set
                .iter()
                .map(|v| {
                    let mut v = v.clone();
                    if &v.root_pk == root_pk {
                        v.voting_power = *voting_power;
                    }
                    v
                })
                .collect();
            Ok(Some(HkValidatorSet::new(vals)))
        }
    }
}

/// G1 (v0.18.0) — the bootstrap-governance re-weight. At the activation height every node
/// sets the voting power of the GENESIS seats (identified by their permanent roots) to
/// `power`, in place: operational keys, epochs and addresses untouched, no certificate,
/// no signatures — the rule is in the binary every node runs, so it is exactly as
/// authoritative as the genesis itself and applies identically on live commits and on
/// replay. `None` = nothing to change (no genesis root seated, or all already at `power`).
pub fn reweight_roots(set: &HkValidatorSet, roots: &[Vec<u8>], power: u64) -> Option<HkValidatorSet> {
    let mut changed = false;
    let vals: Vec<HkValidator> = set
        .iter()
        .map(|v| {
            let mut v = v.clone();
            if roots.iter().any(|r| r == &v.root_pk) && v.voting_power != power {
                v.voting_power = power;
                changed = true;
            }
            v
        })
        .collect();
    changed.then(|| HkValidatorSet::new(vals))
}

/// The smallest approving/voting power that is strictly more than ⅔ of `total`
/// (3·q > 2·total): the quorum line the chain and every set change use.
pub fn quorum_power(total: u64) -> u64 {
    (total.saturating_mul(2) / 3).saturating_add(1)
}

// SLH-DSA operations allocate large fixed arrays — run tests on a generous stack.
#[cfg(test)]
fn on_big_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new().stack_size(32 * 1024 * 1024).spawn(f).unwrap().join().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN: &str = "hashkinetics-1-4e4ea68d";

    fn seat(seed: u8, power: u64) -> (RootSecret, HkValidator) {
        let root = RootSecret::from_seed(&[seed; 32]);
        let v = HkValidator::new(root.public_bytes().to_vec(), HkPub(vec![seed; 60]), power);
        (root, v)
    }

    fn admit_body(root_pk: Vec<u8>, key: u8) -> SetChangeBody {
        SetChangeBody {
            chain_id: CHAIN.into(),
            change: SetChange::Admit { root_pk, public_key: HkPub(vec![key; 60]), voting_power: 1 },
            not_before: 100,
            not_after: 200,
        }
    }

    fn cert(body: &SetChangeBody, approvals: &[&Approval]) -> SetChangeCert {
        SetChangeCert { body: body.clone(), approvals: approvals.iter().map(|a| (*a).clone()).collect() }
    }

    // SLH-DSA-192s signing is slow in debug builds — every root signs each body ONCE and
    // the certificates below are assembled from subsets of those approvals.
    #[test]
    fn supermajority_admits_then_removes_a_seat() {
        on_big_stack(|| {
            let (r1, v1) = seat(1, 1);
            let (r2, v2) = seat(2, 1);
            let (r3, v3) = seat(3, 1);
            let (r4, v4) = seat(4, 1);
            let set = HkValidatorSet::new(vec![v1, v2, v3, v4]);
            let newcomer = RootSecret::from_seed(&[9u8; 32]);
            let new_root = newcomer.public_bytes().to_vec();

            let body = admit_body(new_root.clone(), 9);
            let (a1, a2, a3, a4) = (
                Approval::sign(&r1, &body),
                Approval::sign(&r2, &body),
                Approval::sign(&r3, &body),
                Approval::sign(&r4, &body),
            );
            // 2 of 4 approve: 2·3 = 6 is not > 2·4 = 8 → refused.
            assert!(apply_set_change(&set, &cert(&body, &[&a1, &a2]), 150, CHAIN).is_err());
            // 3 of 4 approve: 9 > 8 → admitted, effective set has 5 seats.
            let three = cert(&body, &[&a1, &a2, &a3]);
            let set5 = apply_set_change(&set, &three, 150, CHAIN).unwrap().expect("changed");
            assert_eq!(set5.len(), 5);
            assert!(set5.iter().any(|v| v.root_pk == new_root));
            // Replay against the grown set: 3 of 5 (9 ≤ 10) is refused outright …
            assert!(apply_set_change(&set5, &three, 160, CHAIN).is_err());
            // … and 4 of 5 (12 > 10) is a no-op — idempotent, never a second seat.
            let four = cert(&body, &[&a1, &a2, &a3, &a4]);
            assert!(apply_set_change(&set5, &four, 160, CHAIN).unwrap().is_none());
            // Outside the window: refused. Wrong chain: refused.
            assert!(apply_set_change(&set, &three, 99, CHAIN).is_err());
            assert!(apply_set_change(&set, &three, 201, CHAIN).is_err());
            assert!(apply_set_change(&set, &three, 150, "hashkinetics-devnet-1").is_err());

            // Remove it again. 3 of the 5 seats: 9 is NOT > 10 → refused.
            let rm = SetChangeBody {
                chain_id: CHAIN.into(),
                change: SetChange::Remove { root_pk: new_root.clone() },
                not_before: 150,
                not_after: 300,
            };
            let (b1, b2, b3, bn) = (
                Approval::sign(&r1, &rm),
                Approval::sign(&r2, &rm),
                Approval::sign(&r3, &rm),
                Approval::sign(&newcomer, &rm),
            );
            assert!(apply_set_change(&set5, &cert(&rm, &[&b1, &b2, &b3]), 160, CHAIN).is_err());
            // 4 of 5 (the newcomer approves its own removal): 12 > 10 → back to 4.
            let set4 = apply_set_change(&set5, &cert(&rm, &[&b1, &b2, &b3, &bn]), 160, CHAIN)
                .unwrap()
                .expect("changed");
            assert_eq!(set4.len(), 4);
            assert!(!set4.iter().any(|v| v.root_pk == new_root));
            // The same 4-approval cert again: one approver (the newcomer) is no longer seated →
            // refused outright (approvals must all come from CURRENT seats).
            assert!(apply_set_change(&set4, &cert(&rm, &[&b1, &b2, &b3, &bn]), 170, CHAIN).is_err());
            // Removing a root that is not seated, approved by 3 of the 4 current seats
            // (9 > 8): valid, but a no-op.
            assert!(apply_set_change(&set4, &cert(&rm, &[&b1, &b2, &b3]), 170, CHAIN).unwrap().is_none());
        });
    }

    #[test]
    fn forged_duplicate_and_stranger_approvals_rejected() {
        on_big_stack(|| {
            let (r1, v1) = seat(1, 1);
            let (r2, v2) = seat(2, 1);
            let (_r3, v3) = seat(3, 1);
            let set = HkValidatorSet::new(vec![v1, v2, v3]);
            let body = admit_body(RootSecret::from_seed(&[8u8; 32]).public_bytes().to_vec(), 8);
            let stranger = RootSecret::from_seed(&[77u8; 32]);
            let (a1, a2, ax) = (Approval::sign(&r1, &body), Approval::sign(&r2, &body), Approval::sign(&stranger, &body));

            // Duplicate approval from one root does not count twice.
            assert!(cert(&body, &[&a1, &a1, &a2]).verify_against(&set, CHAIN).is_err());
            // A stranger's approval is refused even alongside valid ones.
            assert!(cert(&body, &[&a1, &a2, &ax]).verify_against(&set, CHAIN).is_err());
            // Tampered signature bytes fail.
            let mut t = a1.clone();
            let mid = t.root_sig.len() / 2;
            t.root_sig[mid] ^= 1;
            assert!(!t.verify(&body));
            assert!(a1.verify(&body));
            // A signature over a different body (window moved) does not carry over.
            let mut other = body.clone();
            other.not_after += 1;
            assert!(cert(&other, &[&a1, &a2]).verify_against(&set, CHAIN).is_err());
            // 2 of 3 with power 1 each: 6 > 6 is false → not enough.
            assert!(cert(&body, &[&a1, &a2]).verify_against(&set, CHAIN).is_err());
        });
    }

    #[test]
    fn never_removes_the_last_seat_and_rejects_address_collision() {
        on_big_stack(|| {
            let (r1, v1) = seat(1, 1);
            let set = HkValidatorSet::new(vec![v1.clone()]);
            let rm = SetChangeBody {
                chain_id: CHAIN.into(),
                change: SetChange::Remove { root_pk: v1.root_pk.clone() },
                not_before: 0,
                not_after: 10,
            };
            let a = Approval::sign(&r1, &rm);
            assert!(apply_set_change(&set, &cert(&rm, &[&a]), 5, CHAIN).is_err());

            // Admitting a different root with the SAME operational key (same address) is refused.
            let clash = SetChangeBody {
                chain_id: CHAIN.into(),
                change: SetChange::Admit {
                    root_pk: RootSecret::from_seed(&[5u8; 32]).public_bytes().to_vec(),
                    public_key: v1.public_key.clone(),
                    voting_power: 1,
                },
                not_before: 0,
                not_after: 10,
            };
            let c = Approval::sign(&r1, &clash);
            assert!(apply_set_change(&set, &cert(&clash, &[&c]), 5, CHAIN).is_err());
        });
    }

    #[test]
    fn g1_reweight_roots_touches_only_the_named_seats_and_is_idempotent() {
        let (_, f1) = seat(1, 1);
        let (_, f2) = seat(2, 1);
        let (_, ext) = seat(3, 1);
        let set = HkValidatorSet::new(vec![f1.clone(), f2.clone(), ext.clone()]);
        let roots = vec![f1.root_pk.clone(), f2.root_pk.clone()];
        let re = reweight_roots(&set, &roots, 4).expect("changed");
        assert_eq!(re.total_voting_power(), 9);
        for v in re.iter() {
            let want = if roots.contains(&v.root_pk) { 4 } else { 1 };
            assert_eq!(v.voting_power, want);
            // identity untouched: address, key, epoch
            let before = set.iter().find(|b| b.root_pk == v.root_pk).unwrap();
            assert_eq!((v.address, &v.public_key, v.epoch), (before.address, &before.public_key, before.epoch));
        }
        // Founders alone now pass a change: 3·8 = 24 > 2·9 = 18. Before: 3·2 = 6 > 6 is false.
        assert!(8 * 3 > re.total_voting_power() * 2);
        assert!(!(2 * 3 > set.total_voting_power() * 2));
        // Applying again changes nothing; an unknown root changes nothing.
        assert!(reweight_roots(&re, &roots, 4).is_none());
        assert!(reweight_roots(&set, &[vec![9u8; 48]], 4).is_none());
        // The quorum line: strictly more than ⅔.
        assert_eq!(quorum_power(6), 5);
        assert_eq!(quorum_power(18), 13);
        assert_eq!(quorum_power(4), 3);
        assert_eq!(quorum_power(1), 1);
    }

    #[test]
    fn set_power_certificate_changes_one_seat_in_place() {
        on_big_stack(|| {
            let (r1, v1) = seat(1, 4);
            let (r2, v2) = seat(2, 4);
            let (_r3, v3) = seat(3, 1);
            let set = HkValidatorSet::new(vec![v1.clone(), v2.clone(), v3.clone()]);
            // Two founders at 4 each: 3·8 = 24 > 2·9 = 18 — they pass a re-weight alone.
            let body = SetChangeBody {
                chain_id: CHAIN.into(),
                change: SetChange::SetPower { root_pk: v3.root_pk.clone(), voting_power: 3 },
                not_before: 0,
                not_after: 10,
            };
            let a1 = Approval::sign(&r1, &body);
            let a2 = Approval::sign(&r2, &body);
            let new_set = apply_set_change(&set, &cert(&body, &[&a1, &a2]), 5, CHAIN).unwrap().expect("changed");
            assert_eq!(new_set.total_voting_power(), 11);
            let s3 = new_set.iter().find(|v| v.root_pk == v3.root_pk).unwrap();
            assert_eq!((s3.voting_power, s3.address, s3.epoch), (3, v3.address, v3.epoch));
            // Replay inside the window: no-op. Unknown root: error. Zero power: shape error.
            assert!(apply_set_change(&new_set, &cert(&body, &[&a1, &a2]), 6, CHAIN).unwrap().is_none());
            let ghost = SetChangeBody {
                chain_id: CHAIN.into(),
                change: SetChange::SetPower { root_pk: vec![7u8; 48], voting_power: 2 },
                not_before: 0,
                not_after: 10,
            };
            let g1 = Approval::sign(&r1, &ghost);
            let g2 = Approval::sign(&r2, &ghost);
            assert!(apply_set_change(&set, &cert(&ghost, &[&g1, &g2]), 5, CHAIN).is_err());
            let zero = SetChangeBody {
                chain_id: CHAIN.into(),
                change: SetChange::SetPower { root_pk: v3.root_pk.clone(), voting_power: 0 },
                not_before: 0,
                not_after: 10,
            };
            assert!(zero.check_shape().is_err());
            // The signing bytes distinguish SetPower from Admit/Remove on the same root.
            let rm = SetChangeBody { change: SetChange::Remove { root_pk: v3.root_pk.clone() }, ..body.clone() };
            assert_ne!(body.signing_bytes(), rm.signing_bytes());
        });
    }
}
