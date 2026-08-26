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
}

impl Default for HkRpcConfig {
    fn default() -> Self {
        Self { enabled: false, listen_addr: "127.0.0.1:26000".to_string() }
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
