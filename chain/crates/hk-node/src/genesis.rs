//! HashKinetics devnet genesis: the consensus validator set + the chain-state genesis.

use hk_consensus::{HkPub, HkValidator, HkValidatorSet};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Permanent SLH-DSA-192s root identity (48 bytes) — certifies this validator's
    /// operational-key rotations (SCMS). Derived from the same master seed as the keys below.
    #[serde(default)]
    pub root_pk: Vec<u8>,
    /// Hash-based (LMS/HSS) consensus public key bytes — the *genesis operational* key.
    /// Quantum-secure; rotated under the root over the validator's life.
    pub public_key: HkPub,
    pub voting_power: u64,
}

/// P2.5: verifying-key pins — SHAKE-256 hashes of the (bincode) vk bytes, embedded at
/// genesis generation. A node whose fetched vks don't match REFUSES TO START: the proof
/// system a chain accepts is a GENESIS fact, not an operator convenience.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VkPins {
    pub spend: String, // hex SHAKE-256₃₂(DOM_VK_PIN ‖ vk bytes)
    pub mint: String,
    pub agg: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HkGenesis {
    /// Deterministic chain clock epoch: block time = chain_start_time + height.
    /// (Wall clocks are not consensus-safe; a real BFT-time comes later.)
    pub chain_start_time: u64,
    pub validators: Vec<GenesisValidator>,
    /// Chain-state genesis (accounts/allocations) — empty for the bring-up devnet;
    /// the P0 demo seeds org/agents/merchant here.
    #[serde(default)]
    pub chain: Option<hk_state::Genesis>,
    /// P2.5: pinned proof-system vks (None = devnet trust-on-fetch, logged loudly).
    #[serde(default)]
    pub vk_pins: Option<VkPins>,
}

impl HkGenesis {
    pub fn validator_set(&self) -> eyre::Result<HkValidatorSet> {
        let vals: Vec<HkValidator> = self
            .validators
            .iter()
            .map(|v| HkValidator::new(v.root_pk.clone(), v.public_key.clone(), v.voting_power))
            .collect();
        if vals.is_empty() {
            eyre::bail!("genesis has no validators");
        }
        Ok(HkValidatorSet::new(vals))
    }

    pub fn chain_genesis(&self) -> hk_state::Genesis {
        self.chain.clone().unwrap_or(hk_state::Genesis {
            time: self.chain_start_time,
            accounts: vec![],
            alloc: vec![],
            fee: None,
            assets: vec![],
        })
    }

    /// U4.b: the genesis-bound fee policy, if this network pins one.
    pub fn fee(&self) -> Option<hk_state::GenesisFee> {
        self.chain.as_ref().and_then(|c| c.fee.clone())
    }
}
