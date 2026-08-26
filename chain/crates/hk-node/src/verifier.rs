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
//! vk provenance (devnet): fetched once at startup from hk-prove (`HK_PROVER_URL`).
//! Mainnet pins vk hashes in genesis — noted in the P2 plan (WS2 hardening).
//!
//! All raw-STARK: `client.verify` on core/compressed SP1 proofs — no pairing wraps (F1).

use std::io::{Read, Write};
use std::net::TcpStream;
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

/// Build the node's verifiers: fetch all three vks from hk-prove, VERIFY THEM AGAINST
/// THE GENESIS PINS (P2.5 — a mismatched proof system refuses to start), then construct
/// a CPU client whose only job is `verify`.
pub async fn from_prover_url(
    url: &str,
    pins: Option<&crate::genesis::VkPins>,
) -> Result<crate::state::PoolVerifiers> {
    let resp = http_json(url, &json!({"method": "vks"}))?;
    let r = resp
        .get("result")
        .ok_or_else(|| eyre!("prover at {url} returned no result: {resp}"))?;
    let spend_bytes = vk_bytes(r, "spend_vk")?;
    let mint_bytes = vk_bytes(r, "mint_vk")?;
    let agg_bytes = vk_bytes(r, "agg_vk")?;
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
                    "{name} vk PIN MISMATCH (genesis {want}, prover {got}) — refusing to start: \
                     the proof system a chain accepts is a genesis fact"
                ));
            }
        }
        info!("verifying keys MATCH the genesis pins");
    } else {
        info!("genesis carries no vk pins — trust-on-fetch (devnet posture)");
    }
    let spend_vk: SP1VerifyingKey =
        bincode::deserialize(&spend_bytes).map_err(|e| eyre!("spend_vk decode: {e}"))?;
    let mint_vk: SP1VerifyingKey =
        bincode::deserialize(&mint_bytes).map_err(|e| eyre!("mint_vk decode: {e}"))?;
    let agg_vk: SP1VerifyingKey =
        bincode::deserialize(&agg_bytes).map_err(|e| eyre!("agg_vk decode: {e}"))?;
    let spend_vk_hash = spend_vk.hash_u32();
    let mint_vk_hash = mint_vk.hash_u32();
    info!("fetched spend+mint+agg verifying keys from hk-prove");

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

fn vk_bytes(r: &Value, key: &str) -> Result<Vec<u8>> {
    let hexs = r
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre!("prover response missing {key}"))?;
    hex::decode(hexs).map_err(|e| eyre!("{key} hex: {e}"))
}

/// Minimal blocking JSON POST (startup-only; same wire shape as the demo driver's rpc()).
fn http_json(base: &str, body: &Value) -> Result<Value> {
    let hostport =
        base.trim_start_matches("http://").split('/').next().unwrap_or(base).to_string();
    let body = body.to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let mut s = TcpStream::connect(&hostport).map_err(|e| eyre!("connect {hostport}: {e}"))?;
    s.write_all(req.as_bytes())?;
    let mut resp = String::new();
    s.read_to_string(&mut resp)?;
    let payload = resp.splitn(2, "\r\n\r\n").nth(1).unwrap_or("");
    serde_json::from_str(payload).map_err(|e| eyre!("prover response unparseable: {e}"))
}
