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

// ---------------------------------------------------------------------------------------
// G1 (v0.18.0) — bootstrap governance: the activation table.
// ---------------------------------------------------------------------------------------

/// One network's bootstrap re-weight: at commit height `height` every node sets the voting
/// power of the GENESIS seats (the roots in this genesis file) to `founding_power`, in place,
/// effective `height + 1`. Externals keep their admitted power (1). With four founding seats
/// at 4 the founders hold strictly more than ⅔ against up to SEVEN external seats
/// (3·16 > 2·(16+7)), so no set of young seats can stall the chain or block a set change,
/// and the founders alone can seat, unseat and — at the published handover — re-weight
/// (`SetChange::SetPower`). The handover is a certificate, not a binary: this table only
/// ever raises the founders once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bootstrap {
    pub height: u64,
    pub founding_power: u64,
}

/// testnet-1's activation. v0.18.0 named 200,000 (chosen at tip ≈101,900: four days of
/// notice); the founder moved it to 110,000 the same evening (v0.18.1, tip ≈105,200, ~4.5 h
/// out) — the co-sign and liveness exposure the rule removes was live that day, and the
/// founding fleet rolls within the hour. v0.18.0 was withdrawn unrolled: a binary that names
/// a different height islands at whichever comes first, exactly like a node still on v0.17.
/// The number may move by patch release BEFORE it is reached; it never moves after.
pub const G1_TESTNET1_HEIGHT: u64 = 110_000;
pub const G1_FOUNDING_POWER: u64 = 4;

/// The re-weight this node applies for `chain_id`, if any. testnet-1 is hard-wired; any
/// OTHER chain (devnets, rehearsals) reads `HK_G1_HEIGHT` / `HK_G1_POWER` from the
/// environment so gates can exercise the activation — never the public network: an
/// operator cannot talk a testnet-1 node onto a different rule.
pub fn bootstrap_for(chain_id: &str) -> Option<Bootstrap> {
    bootstrap_from(chain_id, std::env::var("HK_G1_HEIGHT").ok().as_deref(), std::env::var("HK_G1_POWER").ok().as_deref())
}

/// The pure table behind [`bootstrap_for`]: the chain id decides, the environment only
/// ever speaks for chains that are not testnet-1 (tested without touching the process env).
pub fn bootstrap_from(chain_id: &str, env_height: Option<&str>, env_power: Option<&str>) -> Option<Bootstrap> {
    if chain_id == "hashkinetics-1-4e4ea68d" {
        return Some(Bootstrap { height: G1_TESTNET1_HEIGHT, founding_power: G1_FOUNDING_POWER });
    }
    let height = env_height?.trim().parse::<u64>().ok().filter(|h| *h > 0)?;
    let founding_power =
        env_power.and_then(|s| s.trim().parse::<u64>().ok()).filter(|p| *p > 0).unwrap_or(G1_FOUNDING_POWER);
    Some(Bootstrap { height, founding_power })
}

#[cfg(test)]
mod g1_tests {
    use super::*;

    #[test]
    fn g1_activation_is_hardwired_for_testnet1_and_env_only_elsewhere() {
        assert_eq!(
            bootstrap_from("hashkinetics-1-4e4ea68d", None, None),
            Some(Bootstrap { height: 110_000, founding_power: 4 })
        );
        // The env can never move testnet-1's activation.
        assert_eq!(bootstrap_from("hashkinetics-1-4e4ea68d", Some("5"), Some("9")).unwrap().height, 110_000);
        assert_eq!(bootstrap_from("hashkinetics-1-4e4ea68d", Some("5"), Some("9")).unwrap().founding_power, 4);
        // Any other chain: the env, height required, power defaulting to 4; junk and zero refused.
        assert_eq!(bootstrap_from("hashkinetics-devnet-1", Some("5"), Some("9")), Some(Bootstrap { height: 5, founding_power: 9 }));
        assert_eq!(bootstrap_from("hashkinetics-devnet-1", Some(" 40 "), None).unwrap().founding_power, 4);
        assert_eq!(bootstrap_from("hashkinetics-devnet-1", Some("40"), Some("0")).unwrap().founding_power, 4);
        assert_eq!(bootstrap_from("hashkinetics-devnet-1", Some("0"), Some("9")), None);
        assert_eq!(bootstrap_from("hashkinetics-devnet-1", Some("soon"), None), None);
        assert_eq!(bootstrap_from("hashkinetics-devnet-1", None, Some("9")), None);
        // Without the variables the real reader answers None for a devnet and the table for testnet-1.
        if std::env::var_os("HK_G1_HEIGHT").is_none() {
            assert_eq!(bootstrap_for("hashkinetics-devnet-1"), None);
        }
        assert_eq!(bootstrap_for("hashkinetics-1-4e4ea68d").unwrap().height, 110_000);
        // The arithmetic the number was chosen for: four founders at 4 beat up to seven externals.
        let founders = 4 * G1_FOUNDING_POWER;
        assert!(3 * founders > 2 * (founders + 7));
        assert!(3 * founders <= 2 * (founders + 8));
    }
}
