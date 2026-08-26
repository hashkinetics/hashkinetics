//! hk-primitives — core protocol types for HashKinetics.
//! Plan reference: HASHKINETICS-IMPLEMENTATION-PLAN.md §5, §6, §7.4.
//! Everything is serde-serializable; wire encoding (canonical, deterministic) is TODO(P1)
//! — candidate: SSZ-style or borsh; decision recorded in CLAUDE.md when made.

use serde::{Deserialize, Serialize};

/// Micro-units of an asset (1 token = 10^6 micro). u128 headroom for stables.
pub type Amount = u128;
/// Unix seconds.
pub type Timestamp = u64;

/// 32-byte identifier/hash newtype (SHAKE-256 output truncated to 32B, domain-separated).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct H256(pub [u8; 32]);

impl core::fmt::Debug for H256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0[..8]))
    }
}

pub type AccountId = H256;
pub type MandateId = H256;
pub type AssetId = H256;
pub type ChannelId = H256;
pub type NoteCommitment = H256; // Poseidon2/RPO in-circuit later (plan §3.1); H256 placeholder
pub type Nullifier = H256;

/// Signature scheme tags — the keychain layers of plan §3.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigScheme {
    /// Root identity: SLH-DSA-SHAKE-192s (default per Yadu 2026-08-15; 128s allowed for T0 tier).
    SlhDsa192s,
    SlhDsa128s,
    /// Agent operational keys (stateful; leaf budget = tx-count cap).
    Lms,
    Xmss,
    /// Channel-interior one-shots.
    WotsPlus,
    /// v0 account auth: Lamport-OTS self-ratcheting chain (hk-crypto::lamport).
    /// Real hash-based security, dev-tier ergonomics; replaced by Lms/Xmss adapters.
    LamportRatchetV0,
}

/// A mandate node — consensus-enforced budget (plan §5; carried spec: docs/carried-specs/MANDATETREE-SPEC.md).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MandateNode {
    pub id: MandateId,
    pub parent: Option<MandateId>,
    pub holder_key: Vec<u8>,       // operational pubkey this mandate authorizes
    pub scheme: SigScheme,
    pub asset: AssetId,
    pub rate_per_sec: Amount,      // drip accrual rate
    pub buffer_max: Amount,        // accrual cap ("drip not reset")
    pub per_tx_max: Amount,
    pub expiry: Timestamp,
    pub revoked: bool,
    // Lazy accounting state (plan §5.3 — per-node O(1)):
    pub buffer: Amount,
    pub last_accrual: Timestamp,
    /// Autonomy tier: 0 probation (co-sign above per_tx_max), 1 earned, 2 bonded.
    pub tier: u8,
}

/// Parent-signed delegation certificate binding a child key + policy (plan §5.1).
/// Offline-attenuable (Biscuit-style): child certs can only narrow.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelegationCert {
    pub parent: MandateId,
    pub child_pubkey: Vec<u8>,
    pub child_scheme: SigScheme,
    pub policy: CertPolicy,
    pub parent_sig: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertPolicy {
    pub per_tx_max: Amount,
    pub rate_per_sec: Amount,
    pub buffer_max: Amount,
    pub expiry: Timestamp,
    /// Scope tags (merchant class, chain, purpose) — AP2-mappable (plan §5.4).
    pub scopes: Vec<String>,
    /// Count cap carried by the child's stateful-key leaf budget; recorded for audit.
    pub max_signatures: u64,
}

/// PayWord channel anchor (plan §6 P-chains): tip commitment + pricing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelState {
    pub id: ChannelId,
    pub payer: AccountId,
    pub payee: AccountId,
    pub asset: AssetId,
    pub mandate: MandateId,     // ancestor-chain check ran at open (plan §6)
    pub tip: H256,              // w_0 — PayWord chain head
    pub unit_price: Amount,     // per preimage step
    pub max_steps: u64,
    pub highest_step_settled: u64,
    pub expiry: Timestamp,
}

/// CASP disclosure envelope stub (plan §4.4) — real fields land with the shield (P2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaspEnvelope {
    pub casp_registry_id: H256,
    pub ivms101_blob_enc: Vec<u8>, // encrypted to CASP envelope key
    pub disclosure_commitment: H256,
}

#[derive(Debug, thiserror::Error)]
pub enum PrimitiveError {
    #[error("invalid length for {0}: got {1}")]
    BadLength(&'static str, usize),
}

impl TryFrom<&[u8]> for H256 {
    type Error = PrimitiveError;
    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; 32] = v.try_into().map_err(|_| PrimitiveError::BadLength("H256", v.len()))?;
        Ok(H256(arr))
    }
}
