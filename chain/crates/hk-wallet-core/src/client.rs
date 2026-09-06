//! HTTP plumbing (blocking, ureq): the node RPC, the faucet and the prover — the same three
//! calls the desktop wallet makes, parameterised by endpoints instead of env vars.

use std::time::Duration;

use hk_primitives::{Amount, H256};
use serde_json::{json, Value};

use crate::{Endpoints, WalletError};

/// The transparent test unit (32 × 0x09) — the fee asset on testnet-1.
pub const USD: H256 = H256([9u8; 32]);

pub struct Http {
    pub ep: Endpoints,
}

impl Http {
    pub fn new(ep: Endpoints) -> Self {
        Self { ep }
    }

    pub fn rpc(&self, method: &str, params: Value) -> Result<Value, WalletError> {
        self.rpc_within(method, params, 8)
    }

    /// A page of the pool feed can be megabytes — the scanner's calls get a longer budget.
    pub fn rpc_within(&self, method: &str, params: Value, secs: u64) -> Result<Value, WalletError> {
        ureq::post(&self.ep.rpc)
            .timeout(Duration::from_secs(secs))
            .send_json(json!({ "method": method, "params": params }))
            .map_err(|e| WalletError::msg(format!("rpc: {e}")))?
            .into_json::<Value>()
            .map_err(|e| WalletError::msg(format!("rpc parse: {e}")))
    }

    pub fn balance(&self, id: &H256) -> Result<Amount, WalletError> {
        let v = self.rpc("hk_balance", json!({ "id": hex::encode(id.0), "asset": hex::encode(USD.0) }))?;
        Ok(v.get("result")
            .and_then(|r| r.get("amount"))
            .and_then(|a| a.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0))
    }

    /// `Ok(None)` = the account does not exist on-chain yet.
    pub fn nonce(&self, id: &H256) -> Result<Option<u64>, WalletError> {
        let v = self.rpc("hk_getAccount", json!({ "id": hex::encode(id.0) }))?;
        let r = v.get("result").ok_or_else(|| WalletError::msg("rpc: no result"))?;
        if r.get("found").and_then(|f| f.as_bool()).unwrap_or(false) {
            Ok(r.get("nonce").and_then(|n| n.as_u64()))
        } else {
            Ok(None)
        }
    }

    pub fn receipt(&self, txid: &str) -> Option<String> {
        let v = self.rpc("hk_getReceipt", json!({ "txid": txid })).ok()?;
        let r = v.get("result")?;
        if r.get("found")?.as_bool()? {
            r.get("detail")?.as_str().map(str::to_string)
        } else {
            None
        }
    }

    /// `hk_chainInfo` → (chain id, height, fee policy). Fee fields are strings on the wire.
    pub fn chain_info(&self) -> Result<ChainInfo, WalletError> {
        let v = self.rpc("hk_chainInfo", json!({}))?;
        let r = v.get("result").ok_or_else(|| WalletError::msg("rpc: no result"))?;
        let chain_id = r.get("chain_id").and_then(|c| c.as_str()).unwrap_or("?").to_string();
        let height = r.get("height").and_then(|h| h.as_u64()).unwrap_or(0);
        let node_version = r.get("node_version").and_then(|c| c.as_str()).unwrap_or("").to_string();
        let (fee_micro, fee_from) = match r.get("fee") {
            Some(f) => (
                f.get("micro").and_then(|m| m.as_str()).and_then(|s| s.parse::<Amount>().ok()).unwrap_or(0),
                f.get("from_height").and_then(|h| h.as_u64()).unwrap_or(u64::MAX),
            ),
            None => (0, u64::MAX),
        };
        Ok(ChainInfo { chain_id, height, node_version, fee_micro, fee_from })
    }

    /// v0.13.1: an RPC failure is an error, not "height 0" — deriving the epoch-0 stealth
    /// address on a network blip was wrong.
    pub fn height(&self) -> Result<u64, WalletError> {
        Ok(self.chain_info()?.height)
    }

    /// POST to the faucet. Success and refusal both come back as JSON; non-2xx statuses
    /// (cooldown, bad input) carry their explanation in the body.
    pub fn faucet_post(&self, body: Value) -> Result<Value, WalletError> {
        let req = ureq::post(&format!("{}/drip", self.ep.faucet)).timeout(Duration::from_secs(30));
        match req.send_json(body) {
            Ok(resp) => resp.into_json().map_err(|e| WalletError::msg(format!("faucet parse: {e}"))),
            Err(ureq::Error::Status(_, resp)) => resp.into_json().map_err(|e| WalletError::msg(format!("faucet parse: {e}"))),
            Err(e) => Err(WalletError::msg(format!("faucet unreachable: {e}"))),
        }
    }

    /// `prove_mint` / `prove_spend` on the public prover. Core-mode STARKs can take a while —
    /// long timeout; the caller runs off the UI thread. Returns (proof bytes, prove_ms).
    pub fn prove(&self, method: &str, witness: Value) -> Result<(Vec<u8>, u64), WalletError> {
        let prover = &self.ep.prover;
        let health = ureq::post(prover)
            .timeout(Duration::from_secs(10))
            .send_json(json!({ "method": "health", "params": {} }))
            .map_err(|e| WalletError::msg(format!("prover unreachable at {prover}: {e}")))?
            .into_json::<Value>()
            .map_err(|e| WalletError::msg(format!("prover health parse: {e}")))?;
        if health.get("result").is_none() {
            return Err(WalletError::msg(format!("prover at {prover} is not healthy: {health}")));
        }
        let v = ureq::post(prover)
            .timeout(Duration::from_secs(900))
            .send_json(json!({ "method": method, "params": { "witness": witness } }))
            .map_err(|e| WalletError::msg(format!("prover {method}: {e}")))?
            .into_json::<Value>()
            .map_err(|e| WalletError::msg(format!("prover {method} parse: {e}")))?;
        if let Some(e) = v.get("error") {
            return Err(WalletError::msg(format!("prover error: {e}")));
        }
        let r = v.get("result").ok_or_else(|| WalletError::msg(format!("prover: no result: {v}")))?;
        let proof_hex = r.get("proof").and_then(|p| p.as_str()).ok_or_else(|| WalletError::msg("prover: no proof in result"))?;
        Ok((
            hex::decode(proof_hex).map_err(|e| WalletError::msg(e.to_string()))?,
            r.get("prove_ms").and_then(|m| m.as_u64()).unwrap_or(0),
        ))
    }
}

/// What `hk_chainInfo` tells a wallet.
#[derive(Clone, Debug)]
pub struct ChainInfo {
    pub chain_id: String,
    pub height: u64,
    pub node_version: String,
    pub fee_micro: Amount,
    pub fee_from: u64,
}

impl ChainInfo {
    /// The fee charged on a transaction sent NOW (0 before activation).
    pub fn fee_now(&self) -> Amount {
        if self.fee_micro > 0 && self.height + 1 >= self.fee_from { self.fee_micro } else { 0 }
    }
}
