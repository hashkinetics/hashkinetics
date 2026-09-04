//! In-node SP1 STARK verification (P2.0/WS2) — the real `ProofVerifier` that replaces
//! hk-state's RejectAll default.
//!
//! How the chain checks a shielded tx: the state machine DERIVES the expected public
//! statement from the transaction's fields (anchor, nullifier, out_commitment, fee, and
//! the tx_binding rule H(credit ‖ fee)), then calls us. We require (1) the proof's
//! committed public values to BYTE-MATCH that expectation (the guest commits bincode, so
//! we compare against `bincode(expected)`), and (2) the STARK to verify under the pinned
//! verifying key. Anything else is false — never an error the caller could misread.
//!
//! vk provenance: the join kit's `vks.json` (`HK_VKS_FILE`, default `<HOME>/vks.json`) or,
//! failing that, fetched once at startup from hk-prove (`HK_PROVER_URL`, http or https).
//! Either way the keys are checked against the genesis pins — a node on a pinned genesis
//! needs no prover to verify (K6, v0.15.1).
//!
//! All raw-STARK: `client.verify` on core/compressed SP1 proofs — no pairing wraps (F1).

use std::sync::Arc;

use eyre::{eyre, Result};
use serde_json::{json, Value};
use tracing::info;

use hk_spend_circuit::{MintPublic, SpendPublic};
use hk_state::pool::ProofVerifier;
use sp1_sdk::prelude::*;
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1VerifyingKey};

/// (proof bytes, expected public-value bytes) -> valid? The prover-client type stays
/// inferred inside these closures — we never have to name SDK internals.
type VerifyFn = Box<dyn Fn(&[u8], &[u8]) -> bool + Send + Sync>;

pub struct Sp1PoolVerifier {
    spend: VerifyFn,
    mint: VerifyFn,
}

impl ProofVerifier for Sp1PoolVerifier {
    fn verify_spend(&self, proof: &[u8], expected: &SpendPublic) -> bool {
        match bincode::serialize(expected) {
            Ok(b) => (self.spend)(proof, &b),
            Err(_) => false,
        }
    }
    fn verify_mint(&self, proof: &[u8], expected: &MintPublic) -> bool {
        match bincode::serialize(expected) {
            Ok(b) => (self.mint)(proof, &b),
            Err(_) => false,
        }
    }
}

/// The three verifying keys as the prover's `vks` method returns them and as the join
/// kit ships them (`networks/<net>/vks.json`): hex-encoded bincode of each
/// `SP1VerifyingKey`. 104 bytes each on testnet-1 — small enough to pin and to ship.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VkSet {
    pub spend_vk: String,
    pub mint_vk: String,
    pub agg_vk: String,
}

impl VkSet {
    /// Accepts either the bare object or the prover's `{"result": {…}}` envelope.
    pub fn from_json(v: &Value) -> Result<Self> {
        let obj = v.get("result").unwrap_or(v);
        serde_json::from_value(obj.clone()).map_err(|e| eyre!("vks: {e}"))
    }
}

/// Fetch the vks from a prover (http or https — K6).
pub fn fetch_vks(url: &str) -> Result<VkSet> {
    let resp = http_json(url, &json!({"method": "vks"}))?;
    if resp.get("result").is_none() {
        return Err(eyre!("prover at {url} returned no result: {resp}"));
    }
    VkSet::from_json(&resp)
}

/// Read the vks from the join kit's file (K6, v0.15.1): a node on a pinned genesis then
/// needs NO prover at all — verification is local, the file is checked against the pins.
pub fn read_vks_file(path: &std::path::Path) -> Result<VkSet> {
    let raw = std::fs::read_to_string(path).map_err(|e| eyre!("{}: {e}", path.display()))?;
    let v: Value = serde_json::from_str(&raw).map_err(|e| eyre!("{}: not JSON: {e}", path.display()))?;
    VkSet::from_json(&v)
}

/// Build the node's verifiers from a prover URL (fetch, pin-check, construct).
pub async fn from_prover_url(
    url: &str,
    pins: Option<&crate::genesis::VkPins>,
) -> Result<crate::state::PoolVerifiers> {
    let set = fetch_vks(url)?;
    from_vk_set(&set, pins, &format!("prover {url}")).await
}

/// Build the node's verifiers from the kit's vks file (pin-check, construct).
pub async fn from_vks_file(
    path: &std::path::Path,
    pins: Option<&crate::genesis::VkPins>,
) -> Result<crate::state::PoolVerifiers> {
    let set = read_vks_file(path)?;
    from_vk_set(&set, pins, &format!("file {}", path.display())).await
}

/// VERIFY THE VKS AGAINST THE GENESIS PINS (P2.5 — a mismatched proof system refuses to
/// start), then construct a CPU client whose only job is `verify`.
async fn from_vk_set(
    set: &VkSet,
    pins: Option<&crate::genesis::VkPins>,
    source: &str,
) -> Result<crate::state::PoolVerifiers> {
    let spend_bytes = hex::decode(&set.spend_vk).map_err(|e| eyre!("spend_vk hex: {e}"))?;
    let mint_bytes = hex::decode(&set.mint_vk).map_err(|e| eyre!("mint_vk hex: {e}"))?;
    let agg_bytes = hex::decode(&set.agg_vk).map_err(|e| eyre!("agg_vk hex: {e}"))?;
    if let Some(p) = pins {
        for (name, bytes, want) in [
            ("spend", &spend_bytes, &p.spend),
            ("mint", &mint_bytes, &p.mint),
            ("agg", &agg_bytes, &p.agg),
        ] {
            let got = hex::encode(hk_crypto::hash::shake256_32(
                hk_crypto::hash::DOM_VK_PIN,
                &[bytes],
            ));
            if &got != want {
                return Err(eyre!(
                    "{name} vk PIN MISMATCH (genesis {want}, {source} {got}) — refusing to start: \
                     the proof system a chain accepts is a genesis fact"
                ));
            }
        }
        info!(%source, "verifying keys MATCH the genesis pins");
    } else {
        info!(%source, "genesis carries no vk pins — trust-on-fetch (devnet posture)");
    }
    let spend_vk: SP1VerifyingKey =
        bincode::deserialize(&spend_bytes).map_err(|e| eyre!("spend_vk decode: {e}"))?;
    let mint_vk: SP1VerifyingKey =
        bincode::deserialize(&mint_bytes).map_err(|e| eyre!("mint_vk decode: {e}"))?;
    let agg_vk: SP1VerifyingKey =
        bincode::deserialize(&agg_bytes).map_err(|e| eyre!("agg_vk decode: {e}"))?;
    let spend_vk_hash = spend_vk.hash_u32();
    let mint_vk_hash = mint_vk.hash_u32();
    info!(%source, "spend+mint+agg verifying keys loaded");

    let client = Arc::new(ProverClient::builder().cpu().build().await);

    let c = client.clone();
    let spend: VerifyFn = Box::new(move |proof_bytes, expected_public| {
        let Ok(p) = bincode::deserialize::<SP1ProofWithPublicValues>(proof_bytes) else {
            return false;
        };
        if p.public_values.as_slice() != expected_public {
            return false;
        }
        c.verify(&p, &spend_vk, None).is_ok()
    });
    let c = client.clone();
    let mint: VerifyFn = Box::new(move |proof_bytes, expected_public| {
        let Ok(p) = bincode::deserialize::<SP1ProofWithPublicValues>(proof_bytes) else {
            return false;
        };
        if p.public_values.as_slice() != expected_public {
            return false;
        }
        c.verify(&p, &mint_vk, None).is_ok()
    });
    let c = client.clone();
    let agg: crate::state::AggVerifyFn = Arc::new(move |proof_bytes, expected_digest| {
        let Ok(p) = bincode::deserialize::<SP1ProofWithPublicValues>(proof_bytes) else {
            return false;
        };
        if p.public_values.as_slice() != expected_digest {
            return false;
        }
        c.verify(&p, &agg_vk, None).is_ok()
    });

    Ok(crate::state::PoolVerifiers {
        pool: Arc::new(Sp1PoolVerifier { spend, mint }),
        agg,
        spend_vk_hash,
        mint_vk_hash,
    })
}

/// Blocking JSON POST (startup-only). K6: http AND https — the previous raw-TcpStream
/// client could not reach `https://prover.hashkinetics.org`, so K5 refused to start the
/// stock binary on exactly the instruction the join kit gave (found by the first external
/// operator, 2026-09-05).
fn http_json(base: &str, body: &Value) -> Result<Value> {
    crate::demo::post_json(base, body, 60).map_err(|e| eyre!("prover: {e}"))
}
