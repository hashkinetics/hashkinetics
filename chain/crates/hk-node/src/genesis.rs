//! HashKinetics devnet genesis: the consensus validator set + the chain-state genesis.

use hk_consensus::setchange::MAX_VOTING_POWER;
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
    /// `1..=hk_consensus::setchange::MAX_VOTING_POWER` (M-1, 2026-10-06): the node refuses
    /// to start on a genesis outside it (`HkGenesis::validator_set`) — the same bound
    /// `check_shape` puts on every `Admit` / `SetPower` certificate, so no path into the
    /// set is unbounded. testnet-1's genesis seats weigh 1 (G1 re-weights them to 4 by rule).
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
    /// The genesis validator set. M-1 (audit intake, reported 2026-10-06; the genesis half
    /// landed with the R17 review the same day): every seat's power must be inside
    /// `1..=MAX_VOTING_POWER`, or the node refuses to start. The certificate path has the
    /// same bound at `check_shape`; without this one a genesis file (operator-authored)
    /// was the one unbounded way into a set whose saturated total the engine's quorum
    /// test (`is_met`, checked multiplication) panics on. A zero power was never
    /// meaningful either (a seat that can never vote or be counted).
    pub fn validator_set(&self) -> eyre::Result<HkValidatorSet> {
        for (i, v) in self.validators.iter().enumerate() {
            if v.voting_power == 0 || v.voting_power > MAX_VOTING_POWER {
                eyre::bail!(
                    "genesis validator #{i}: voting_power {} outside 1..={} (M-1, 2026-10-06)",
                    v.voting_power,
                    MAX_VOTING_POWER
                );
            }
        }
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

/// P6 (docs/P6-MULTI-ASSET-POOL.md): the height from which testnet-1 nodes open a
/// shielded pool per additional asset. Named 2026-09-08 21:53 UTC at tip 163,659 with the
/// chain at 1.80 s/block (one external seat still on v0.18.2's predecessor): ≈ 13 h out at
/// that rate, ≈ 7 h if every seat runs at the 1 s floor — the founder chose ~12 h of notice
/// (v0.19.0). A node that is not on the release at this height rejects the first
/// second-asset shield and forks. The number may move by patch release BEFORE it is
/// reached; it never moves after (the G1 rule).
pub const P6_TESTNET1_HEIGHT: u64 = 190_000;

/// The multi-pool activation this node applies for `chain_id`: testnet-1 hard-wired;
/// any OTHER chain reads `HK_P6_HEIGHT` (unset ⇒ 0 = active from genesis, so every
/// devnet gate runs multi-asset from block 1; set it to exercise the pre-activation
/// refusal). Never the public network.
pub fn multi_pool_from_for(chain_id: &str) -> u64 {
    multi_pool_from_from(chain_id, std::env::var("HK_P6_HEIGHT").ok().as_deref())
}

pub fn multi_pool_from_from(chain_id: &str, env_height: Option<&str>) -> u64 {
    if chain_id == "hashkinetics-1-4e4ea68d" {
        return P6_TESTNET1_HEIGHT;
    }
    env_height.and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0)
}

/// R17 (H-1, reported 2026-10-06): the height from which testnet-1 nodes bind MandateTree
/// authorization to the asset — a child carries its parent's asset, and every spend sink
/// refuses a leaf whose asset differs from its root's (`hk_state::State::mandate_asset_from`).
/// Before it, a child holder could hang a leaf in ANY asset under an envelope the org
/// funded in one asset and drain the funder in the other. Named 2026-10-06 14:02 UTC at
/// tip 1,855,785 with the chain at 1.307 s/block (measured over the previous 6 h 47 m):
/// 16,715 blocks ≈ 6.07 h out, ≈ 20:06 UTC — the founder chose ~6 h of notice (the rule
/// removes a live drain, and the founding fleet rolls within the hour). This is the SECOND
/// number: the first, 1,844,000 (named 03:51 UTC, built as v0.19.5 at 07:13 UTC), passed at
/// ≈ 09:44 UTC with every seat still on v0.19.4 — the roll never started — so the rule never
/// activated anywhere, v0.19.5 was withdrawn unreleased, and the height was renamed by this
/// patch (v0.19.6) before any node applied it; a v0.19.6 node treats 1,844,000..1,872,500 as
/// pre-activation, byte for byte v0.19.4. A node that is not on the release at this height
/// accepts the first cross-asset mandate and forks. The number may move by patch release
/// BEFORE it is reached; it never moves after a node has applied it (the G1 rule).
pub const R17_TESTNET1_HEIGHT: u64 = 1_872_500;

/// The asset-bound-mandate activation this node applies for `chain_id`: testnet-1
/// hard-wired; any OTHER chain reads `HK_R17_HEIGHT` (unset ⇒ 0 = active from genesis,
/// so every devnet gate runs the asset rule from block 1; set it to exercise the
/// pre-activation acceptance). Never the public network.
pub fn mandate_asset_from_for(chain_id: &str) -> u64 {
    mandate_asset_from_from(chain_id, std::env::var("HK_R17_HEIGHT").ok().as_deref())
}

pub fn mandate_asset_from_from(chain_id: &str, env_height: Option<&str>) -> u64 {
    if chain_id == "hashkinetics-1-4e4ea68d" {
        return R17_TESTNET1_HEIGHT;
    }
    env_height.and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0)
}

/// L-2 (R17, reported 2026-10-06): the height from which testnet-1 nodes accept ONLY
/// chain-bound v2 rotation certificates (`hk/v2/rotation-cert`: the chain id is signed, and
/// `valid_from_height` is enforced as a freshness window — `hk_consensus::rotation`). Before
/// it, v1 certificates are issued and accepted byte for byte as v0.19.4 does.
///
/// NEVER (`u64::MAX`) for now, by design, not by oversight. Seats rotate automatically (R9)
/// every few hours (the gateway reached epoch 159 in ~34 days): a seat that is not on the
/// release cannot verify a v2 certificate, so from this height every un-upgraded node
/// refuses every upgraded seat's rotation, keeps that seat's OLD key, and islands at the
/// first commit certificate the rotated seat signs — and a v1 certificate it issues itself
/// is refused by the network, so it exhausts its tree. Unlike R17 (`R17_TESTNET1_HEIGHT`,
/// whose trigger is a cross-asset mandate someone must submit), the trigger here is the
/// fleet's own rotation cadence, so the height cannot carry notice: it is named by a later
/// patch once the roll call (`hk_getPeers[].version`, and `hk_chainInfo.activations` on each
/// seat) shows every seat on v0.19.6, as a height a few hours out at that time. Set
/// 2026-10-06 ~04:35 UTC at tip ≈ 1,830,000 (v0.19.6). Once named, the G1 rule: the number
/// may move by patch release BEFORE it is reached; it never moves after.
pub const ROTATION_V2_TESTNET1_HEIGHT: u64 = u64::MAX;

/// The rotation-v2 activation this node applies for `chain_id`: testnet-1 hard-wired; any
/// OTHER chain reads `HK_ROTATION_V2_HEIGHT` (unset ⇒ 0 = v2 from genesis, so every devnet
/// gate exercises the chain-bound domain and the freshness window from block 1; set it to
/// exercise the v1 → v2 boundary). Never the public network.
pub fn rotation_v2_from_for(chain_id: &str) -> u64 {
    rotation_v2_from_from(chain_id, std::env::var("HK_ROTATION_V2_HEIGHT").ok().as_deref())
}

pub fn rotation_v2_from_from(chain_id: &str, env_height: Option<&str>) -> u64 {
    if chain_id == "hashkinetics-1-4e4ea68d" {
        return ROTATION_V2_TESTNET1_HEIGHT;
    }
    env_height.and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0)
}

#[cfg(test)]
mod l2_tests {
    use super::*;

    #[test]
    fn rotation_v2_activation_is_hardwired_for_testnet1_and_env_only_elsewhere() {
        assert_eq!(rotation_v2_from_from("hashkinetics-1-4e4ea68d", Some("5")), ROTATION_V2_TESTNET1_HEIGHT);
        // Until the roll call names it: never.
        assert_eq!(rotation_v2_from_from("hashkinetics-1-4e4ea68d", None), u64::MAX);
        assert_eq!(rotation_v2_from_from("hashkinetics-devnet-1", None), 0);
        assert_eq!(rotation_v2_from_from("hashkinetics-devnet-1", Some("40")), 40);
        assert_eq!(rotation_v2_from_from("hashkinetics-devnet-1", Some(" 40 ")), 40);
        assert_eq!(rotation_v2_from_from("hashkinetics-devnet-1", Some("junk")), 0);
        // The real reader: the table for testnet-1 whatever the environment says.
        assert_eq!(rotation_v2_from_for("hashkinetics-1-4e4ea68d"), ROTATION_V2_TESTNET1_HEIGHT);
        if std::env::var_os("HK_ROTATION_V2_HEIGHT").is_none() {
            assert_eq!(rotation_v2_from_for("hashkinetics-devnet-1"), 0);
        }
        // Its own gate, never R17's: the two activations are independent by construction.
        // Compared through the readers, not the consts: `u64::MAX >= x` on the consts is a
        // clippy `absurd_extreme_comparisons` hard error (R17 review, 2026-10-06).
        assert!(
            rotation_v2_from_from("hashkinetics-1-4e4ea68d", None)
                >= mandate_asset_from_from("hashkinetics-1-4e4ea68d", None)
        );
    }
}

#[cfg(test)]
mod m1_tests {
    use super::*;

    fn genesis_with(powers: &[u64]) -> HkGenesis {
        HkGenesis {
            chain_start_time: 0,
            validators: powers
                .iter()
                .enumerate()
                .map(|(i, p)| GenesisValidator { root_pk: vec![], public_key: HkPub(vec![i as u8 + 1; 60]), voting_power: *p })
                .collect(),
            chain: None,
            vk_pins: None,
        }
    }

    #[test]
    fn m1_genesis_refuses_a_power_outside_the_bound() {
        // testnet-1's shape (four seats at 1) and a re-weighted shape (4 + 1s) load.
        assert_eq!(genesis_with(&[1, 1, 1, 1]).validator_set().unwrap().total_voting_power(), 4);
        assert_eq!(genesis_with(&[4, 4, 4, 4, 1, 1, 1]).validator_set().unwrap().total_voting_power(), 19);
        // the bound itself passes; one above it, u64::MAX, u64::MAX / 3 and zero do not —
        // and the refusal names the seat
        assert!(genesis_with(&[MAX_VOTING_POWER, 1]).validator_set().is_ok());
        for bad in [MAX_VOTING_POWER + 1, u64::MAX, u64::MAX / 3, 0] {
            let err = genesis_with(&[1, bad]).validator_set().unwrap_err().to_string();
            assert!(err.contains("genesis validator #1") && err.contains("M-1"), "{bad}: {err}");
        }
        // an empty genesis is still its own refusal
        assert!(genesis_with(&[]).validator_set().unwrap_err().to_string().contains("no validators"));
    }
}

#[cfg(test)]
mod r17_tests {
    use super::*;

    #[test]
    fn r17_activation_is_hardwired_for_testnet1_and_env_only_elsewhere() {
        assert_eq!(mandate_asset_from_from("hashkinetics-1-4e4ea68d", Some("5")), R17_TESTNET1_HEIGHT);
        assert_eq!(mandate_asset_from_from("hashkinetics-1-4e4ea68d", None), 1_872_500);
        assert_eq!(mandate_asset_from_from("hashkinetics-devnet-1", None), 0);
        assert_eq!(mandate_asset_from_from("hashkinetics-devnet-1", Some("40")), 40);
        assert_eq!(mandate_asset_from_from("hashkinetics-devnet-1", Some(" 40 ")), 40);
        assert_eq!(mandate_asset_from_from("hashkinetics-devnet-1", Some("junk")), 0);
        // The real reader: the table for testnet-1 whatever the environment says.
        assert_eq!(mandate_asset_from_for("hashkinetics-1-4e4ea68d"), R17_TESTNET1_HEIGHT);
        if std::env::var_os("HK_R17_HEIGHT").is_none() {
            assert_eq!(mandate_asset_from_for("hashkinetics-devnet-1"), 0);
        }
        // Named after P6 on the same chain: the activations are ordered as they shipped
        // (through the readers — a comparison of two consts is clippy's
        // `assertions_on_constants`).
        assert!(
            mandate_asset_from_from("hashkinetics-1-4e4ea68d", None)
                > multi_pool_from_from("hashkinetics-1-4e4ea68d", None)
        );
    }
}

#[cfg(test)]
mod p6_tests {
    use super::*;

    #[test]
    fn p6_activation_is_hardwired_for_testnet1_and_env_only_elsewhere() {
        assert_eq!(multi_pool_from_from("hashkinetics-1-4e4ea68d", Some("5")), P6_TESTNET1_HEIGHT);
        assert_eq!(multi_pool_from_from("hashkinetics-devnet-1", None), 0);
        assert_eq!(multi_pool_from_from("hashkinetics-devnet-1", Some("40")), 40);
        assert_eq!(multi_pool_from_from("hashkinetics-devnet-1", Some("junk")), 0);
    }
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
