//! Node configuration — mirrors the engine example's Config but loads with plain
//! `toml` (no `config` crate). Every section falls back to defaults, so the
//! generated config.toml only needs to pin what actually differs per node.

use std::path::Path;

use serde::{Deserialize, Serialize};

pub use malachitebft_app_channel::app::config::{
    ConsensusConfig, LoggingConfig, MetricsConfig, RuntimeConfig, ValueSyncConfig,
};
use malachitebft_app_channel::app::node::NodeConfig;

// NOTE: no serde defaults here — the testnet generator writes a COMPLETE config.toml
// (template mirrors the engine example's known-good file), so we never depend on
// unverified Default impls in the engine's config types.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub moniker: String,
    pub logging: LoggingConfig,
    pub consensus: ConsensusConfig,
    pub value_sync: ValueSyncConfig,
    pub metrics: MetricsConfig,
    pub runtime: RuntimeConfig,
    /// HashKinetics RPC (0.7) — our own section, not part of the engine config.
    #[serde(default)]
    pub hk_rpc: HkRpcConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HkRpcConfig {
    pub enabled: bool,
    pub listen_addr: String,
    /// C2.3: peer RPC base addresses ("http://host:port") to push admitted txs to —
    /// single-hop tx gossip. `#[serde(default)]` keeps pre-C2 configs loading
    /// (empty = v0 submit-to-your-home-node behavior).
    #[serde(default)]
    pub gossip_peers: Vec<String>,
    /// HR-1 (mr-hrydarie, reported 2026-11-04; v0.19.11): the P2.3 aggregation door. `false` —
    /// the default, and what a config.toml written before v0.19.11 (no key) means — refuses
    /// `hk_submitBundle` on this node: there is no aggregator role yet, and the only legitimate
    /// caller in the tree is the devnet's `demo-agg`, so a networked seat keeps it closed.
    /// `true` opens it: a loopback devnet only (main.rs `testnet` writes true, `config-gen`
    /// false). HK_RPC_ACCEPT_BUNDLES=1 opens it for one process without a config edit (rpc.rs
    /// `bundles_open`). `#[serde(default)]` keeps every older config loading, closed.
    #[serde(default)]
    pub accept_bundles: bool,
}

impl Default for HkRpcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: "127.0.0.1:26000".to_string(),
            gossip_peers: Vec::new(),
            accept_bundles: false,
        }
    }
}

impl NodeConfig for Config {
    fn moniker(&self) -> &str {
        &self.moniker
    }

    fn consensus(&self) -> &ConsensusConfig {
        &self.consensus
    }

    fn consensus_mut(&mut self) -> &mut ConsensusConfig {
        &mut self.consensus
    }

    fn value_sync(&self) -> &ValueSyncConfig {
        &self.value_sync
    }

    fn value_sync_mut(&mut self) -> &mut ValueSyncConfig {
        &mut self.value_sync
    }
}

/// v0.19.13: the part of the request-response frame (`consensus.p2p.rpc_max_size`) that the
/// value-sync response budget leaves free: room for what a response carries beside its values.
pub const SYNC_RESPONSE_HEADROOM_BYTES: u64 = 1024 * 1024;

/// v0.19.13: the value-sync response budget in effect: the configured
/// `value_sync.max_response_size`, and never more than the request-response frame less
/// `SYNC_RESPONSE_HEADROOM_BYTES`. With the fleet's 32 MiB frame the budget is 31 MiB, the size
/// of the largest value this node votes for (`state::MAX_SYNC_SERVABLE_VALUE_BYTES`).
pub fn effective_sync_response_bytes(configured: u64, rpc_max_size: u64) -> u64 {
    configured.min(rpc_max_size.saturating_sub(SYNC_RESPONSE_HEADROOM_BYTES))
}

/// v0.19.13: hold a loaded configuration's value-sync response budget to the frame
/// (`effective_sync_response_bytes`). Every reader of the configuration comes through
/// `load_config`, so no config.toml needs an edit. Returns the configured number when it was
/// lowered.
fn bound_sync_response(config: &mut Config) -> Option<u64> {
    let configured = config.value_sync.max_response_size.0;
    let effective =
        effective_sync_response_bytes(configured, config.consensus.p2p.rpc_max_size.0);
    config.value_sync.max_response_size.0 = effective;
    (effective != configured).then_some(configured)
}

pub fn load_config(path: impl AsRef<Path>) -> eyre::Result<Config> {
    let raw = std::fs::read_to_string(path.as_ref())?;
    let mut config: Config = toml::from_str(&raw)?;
    // v0.19.13: the value-sync response budget fits the request-response frame.
    if let Some(configured) = bound_sync_response(&mut config) {
        tracing::info!(
            configured_bytes = configured,
            effective_bytes = config.value_sync.max_response_size.0,
            "value_sync.max_response_size is held to the request-response frame"
        );
    }
    Ok(config)
}

/// v0.19.13: the value-sync response budget in effect.
#[cfg(test)]
mod v0_19_13_sync_budget_tests {
    use super::{bound_sync_response, effective_sync_response_bytes, Config};

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn v0_19_13_the_sync_response_budget_fits_the_request_response_frame() {
        // a budget above the frame is held to the frame less the headroom
        assert_eq!(effective_sync_response_bytes(64 * MIB, 32 * MIB), 31 * MIB);
        assert_eq!(effective_sync_response_bytes(32 * MIB, 32 * MIB), 31 * MIB);
        // a budget at or under the bound is kept as configured
        assert_eq!(effective_sync_response_bytes(31 * MIB, 32 * MIB), 31 * MIB);
        assert_eq!(effective_sync_response_bytes(10 * MIB, 32 * MIB), 10 * MIB);
        // a frame smaller than the headroom leaves nothing, and nothing wraps
        assert_eq!(effective_sync_response_bytes(64 * MIB, MIB / 2), 0);
        assert_eq!(effective_sync_response_bytes(u64::MAX, u64::MAX), u64::MAX - MIB);
    }

    #[test]
    fn v0_19_13_the_budget_beside_the_fleet_frame_is_the_largest_value_this_node_votes_for() {
        assert_eq!(
            effective_sync_response_bytes(64 * MIB, 32 * MIB),
            crate::state::MAX_SYNC_SERVABLE_VALUE_BYTES as u64
        );
    }

    /// A config.toml as the generator writes it, with the two numbers given.
    fn config_with(max_response_size: &str, rpc_max_size: &str) -> Config {
        let text = crate::config_template("hk-0", "/ip4/127.0.0.1/tcp/27000", "", false, "127.0.0.1:29000", "127.0.0.1:26000", "", false);
        let text = text
            .lines()
            .map(|l| {
                if l.starts_with("max_response_size = ") {
                    format!("max_response_size = \"{max_response_size}\"")
                } else if l.starts_with("rpc_max_size = ") {
                    format!("rpc_max_size = \"{rpc_max_size}\"")
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        toml::from_str(&text).expect("the generated config.toml loads")
    }

    #[test]
    fn v0_19_13_a_loaded_config_carries_the_bounded_budget() {
        // a config.toml written by a release before v0.19.13: 64 MiB beside a 32 MiB frame
        let mut older = config_with("64 MiB", "32 MiB");
        assert_eq!(bound_sync_response(&mut older), Some(64 * MIB));
        assert_eq!(older.value_sync.max_response_size.0, 31 * MIB);
        // bounding it again changes nothing
        assert_eq!(bound_sync_response(&mut older), None);
        assert_eq!(older.value_sync.max_response_size.0, 31 * MIB);
        // a config.toml the generator writes today is inside the bound as written
        let text = crate::config_template("hk-0", "/ip4/127.0.0.1/tcp/27000", "", false, "127.0.0.1:29000", "127.0.0.1:26000", "", false);
        let mut current: Config = toml::from_str(&text).expect("the generated config.toml loads");
        assert_eq!(current.consensus.p2p.rpc_max_size.0, 32 * MIB);
        assert_eq!(bound_sync_response(&mut current), None);
        assert_eq!(current.value_sync.max_response_size.0, 31 * MIB);
        // an operator's smaller budget is kept
        let mut small = config_with("8 MiB", "32 MiB");
        assert_eq!(bound_sync_response(&mut small), None);
        assert_eq!(small.value_sync.max_response_size.0, 8 * MIB);
    }

    /// The file a seat already has on disk: `load_config` itself hands back the bounded budget.
    #[test]
    fn v0_19_13_load_config_bounds_the_budget_of_a_file_written_by_an_older_release() {
        let text = crate::config_template("hk-0", "/ip4/127.0.0.1/tcp/27000", "", false, "127.0.0.1:29000", "127.0.0.1:26000", "", false)
            .replace("max_response_size = \"31 MiB\"", "max_response_size = \"64 MiB\"");
        assert!(text.contains("max_response_size = \"64 MiB\""), "the template line changed");
        let path = std::env::temp_dir().join(format!("hk-v0-19-13-config-{}.toml", std::process::id()));
        std::fs::write(&path, &text).expect("the temp file is written");
        let loaded = super::load_config(&path);
        let _ = std::fs::remove_file(&path);
        let loaded = loaded.expect("the config.toml of an older release loads");
        assert_eq!(loaded.value_sync.max_response_size.0, 31 * MIB);
        assert_eq!(loaded.consensus.p2p.rpc_max_size.0, 32 * MIB);
    }
}

/// HR-1 (mr-hrydarie, reported 2026-11-04; v0.19.11): the bundle door's switch defaults closed.
#[cfg(test)]
mod hr1_tests {
    use super::HkRpcConfig;

    /// Kill: flip the default, or drop `#[serde(default)]` from `accept_bundles` — the first
    /// opens every seat's door, the second stops every pre-v0.19.11 config.toml from loading.
    #[test]
    fn hr1_accept_bundles_defaults_to_false_and_an_older_config_still_loads() {
        assert!(!HkRpcConfig::default().accept_bundles);
        // a [hk_rpc] section written before v0.19.11: no key → closed, everything else intact
        let older: HkRpcConfig = toml::from_str(
            "enabled = true\nlisten_addr = \"127.0.0.1:26000\"\ngossip_peers = [\"http://127.0.0.1:26001\"]\n",
        )
        .expect("an older section loads");
        assert!(!older.accept_bundles);
        assert!(older.enabled);
        assert_eq!(older.gossip_peers, vec!["http://127.0.0.1:26001".to_string()]);
        // the pre-C2 shape (no gossip_peers either) still loads too
        let oldest: HkRpcConfig = toml::from_str("enabled = false\nlisten_addr = \"127.0.0.1:26000\"\n").expect("the pre-C2 section loads");
        assert!(!oldest.accept_bundles && oldest.gossip_peers.is_empty());
        // the operator's explicit choice is read
        let open: HkRpcConfig = toml::from_str("enabled = true\nlisten_addr = \"127.0.0.1:26000\"\naccept_bundles = true\n").expect("loads");
        assert!(open.accept_bundles);
        let closed: HkRpcConfig = toml::from_str("enabled = true\nlisten_addr = \"127.0.0.1:26000\"\naccept_bundles = false\n").expect("loads");
        assert!(!closed.accept_bundles);
    }
}
