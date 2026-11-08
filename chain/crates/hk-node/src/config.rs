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

pub fn load_config(path: impl AsRef<Path>) -> eyre::Result<Config> {
    let raw = std::fs::read_to_string(path.as_ref())?;
    toml::from_str(&raw).map_err(Into::into)
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
