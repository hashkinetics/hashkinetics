//! Node trait implementation — mirrors the engine example's node.rs with HkContext.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::task::JoinHandle;
use tracing::{error, info, Instrument};

use malachitebft_app_channel::app::events::{RxEvent, TxEvent};
use malachitebft_app_channel::app::node::{EngineHandle, Node, NodeHandle};
use malachitebft_app_channel::app::types::Keypair;

use hk_consensus::{HkAddress, HkContext, HkHeight, HkPriv, HkPub, HkSigningProvider};

use crate::codec::HkCodec;
use crate::config::{load_config, Config};
use crate::genesis::HkGenesis;
use crate::state::HkApp;

#[derive(Clone)]
pub struct App {
    pub home_dir: PathBuf,
    pub start_height: Option<HkHeight>,
    /// Filled by `get_signing_provider` when the engine builds the consensus signer; read
    /// back in `start` to hand HkApp a handle to the SAME signer for live key rotation.
    /// Shared across clones (Arc), so the clone the engine uses writes what `start` reads.
    rotation_slot: Arc<Mutex<Option<HkPriv>>>,
}

impl App {
    pub fn new(home_dir: PathBuf, start_height: Option<HkHeight>) -> Self {
        Self { home_dir, start_height, rotation_slot: Arc::new(Mutex::new(None)) }
    }

    fn config_path(&self) -> PathBuf {
        self.home_dir.join("config.toml")
    }

    fn genesis_path(&self) -> PathBuf {
        self.home_dir.join("genesis.json")
    }

    fn key_path(&self) -> PathBuf {
        self.home_dir.join("priv_validator_key.json")
    }
}

pub struct Handle {
    pub app: JoinHandle<()>,
    pub engine: EngineHandle,
    pub tx_event: TxEvent<HkContext>,
}

#[async_trait]
impl NodeHandle<HkContext> for Handle {
    fn subscribe(&self) -> RxEvent<HkContext> {
        self.tx_event.subscribe()
    }

    async fn kill(&self, _reason: Option<String>) -> eyre::Result<()> {
        self.engine.actor.kill_and_wait(None).await?;
        self.app.abort();
        self.engine.handle.abort();
        Ok(())
    }
}

#[async_trait]
impl Node for App {
    type Context = HkContext;
    type Config = Config;
    type Genesis = HkGenesis;
    /// The key file is the validator's 32-byte master seed. Both keys derive from it:
    /// consensus = LMS/HSS (HkPriv), network identity = libp2p Ed25519.
    type PrivateKeyFile = [u8; 32];
    type SigningProvider = HkSigningProvider;
    type NodeHandle = Handle;

    fn get_home_dir(&self) -> PathBuf {
        self.home_dir.to_owned()
    }

    fn load_config(&self) -> eyre::Result<Self::Config> {
        load_config(self.config_path())
    }

    fn get_address(&self, pk: &HkPub) -> HkAddress {
        HkAddress::from_public_key(pk)
    }

    fn get_public_key(&self, pk: &HkPriv) -> HkPub {
        pk.public()
    }

    /// Network/transport identity: libp2p Ed25519 from the same master seed
    /// (peer auth, NOT ledger security — the consensus votes are hash-based).
    fn get_keypair(&self, pk: HkPriv) -> Keypair {
        Keypair::ed25519_from_bytes(pk.seed).unwrap()
    }

    fn load_private_key(&self, file: Self::PrivateKeyFile) -> HkPriv {
        HkPriv::from_seed(file)
    }

    fn load_private_key_file(&self) -> eyre::Result<Self::PrivateKeyFile> {
        let raw = std::fs::read_to_string(self.key_path())?;
        serde_json::from_str(&raw).map_err(Into::into)
    }

    fn get_signing_provider(&self, private_key: HkPriv) -> Self::SigningProvider {
        // Prefer the operational signer `start` pre-built and stashed — a shared handle so
        // the engine's provider and HkApp advance the SAME tree (single writer + live
        // rotation). Fall back to building one if ever called first (keeps the trait total).
        // Either way the signer owns the durable state file (reserve-then-sign).
        let sk = self.rotation_slot.lock().unwrap().clone().unwrap_or_else(|| {
            private_key.into_persistent(self.home_dir.join("consensus_state.bin"))
        });
        HkSigningProvider::new(sk)
    }

    fn load_genesis(&self) -> eyre::Result<Self::Genesis> {
        let raw = std::fs::read_to_string(self.genesis_path())?;
        serde_json::from_str(&raw).map_err(Into::into)
    }

    async fn start(&self) -> eyre::Result<Handle> {
        let config = self.load_config()?;
        let span = tracing::error_span!("node", moniker = %config.moniker);
        let _enter = span.enter();

        let private_key_file = self.load_private_key_file()?;
        let private_key = self.load_private_key(private_key_file);
        let public_key = self.get_public_key(&private_key);
        let address = self.get_address(&public_key);
        // Build the ONE operational signer now (persistent) and stash a shared clone: the
        // engine's provider (via get_signing_provider) and HkApp then advance the SAME tree
        // — single writer, plus a handle HkApp uses to rotate the live key. HkApp signs no
        // consensus messages itself; it only swaps the tree when a RotationCert commits.
        let op_handle =
            private_key.into_persistent(self.home_dir.join("consensus_state.bin"));
        *self.rotation_slot.lock().unwrap() = Some(op_handle.clone());
        // HK-R6: shared validator-set history. HkApp maintains it (genesis seed,
        // snapshot reseed, append per committed rotation); the engine reads it via
        // `HkContext::validator_set_at` so commit certificates are verified against
        // the set AS OF their height — sync/replay now crosses rotation boundaries.
        let set_history: hk_consensus::SetHistory = Default::default();
        let ctx = HkContext::with_history(set_history.clone());

        let genesis = self.load_genesis()?;

        // Genesis-gate: our genesis digest IS our network identity. Hash the EXACT
        // genesis bytes (SHA-256 == the published `sha256sum genesis.json` fingerprint)
        // and hand it to the network layer BEFORE the engine spawns, so identify
        // advertises it and any peer on a different genesis (an "island" chain) is
        // refused at connect time. Also bound into chain_id + surfaced by hk_chainInfo.
        let genesis_digest: [u8; 32] = {
            use sha2::{Digest, Sha256};
            let bytes = std::fs::read(self.genesis_path())?;
            let mut d = [0u8; 32];
            d.copy_from_slice(Sha256::digest(&bytes).as_slice());
            d
        };
        malachitebft_network::hk_set_genesis_digest(genesis_digest);
        // N1 (v0.15.2): advertise our version to peers too (identify agent tag), and
        // remember our own libp2p id so `hk_getPeers` can name it.
        malachitebft_network::hk_set_node_version(crate::NODE_VERSION);
        let self_peer_id = self.get_keypair(op_handle.clone()).public().to_peer_id().to_string();
        info!(
            genesis_digest = %hex::encode(genesis_digest),
            peer_id = %self_peer_id,
            version = crate::NODE_VERSION,
            "genesis fingerprint pinned — network identity (island peers refused)"
        );

        let initial_validator_set = genesis.validator_set()?;

        info!(%address, validators = initial_validator_set.len(), "Starting HashKinetics node");

        let (mut channels, engine_handle) = malachitebft_app_channel::start_engine(
            ctx.clone(),
            self.clone(),
            config.clone(),
            HkCodec, // WAL codec
            HkCodec, // network codec
            self.start_height,
            initial_validator_set,
        )
        .await?;

        let tx_event = channels.events.clone();

        // WS2: wire the real SP1 STARK verifier if a prover URL is configured. Without it
        // the chain keeps hk-state's RejectAll default — shielded txs are refused, never
        // trusted. (vks are fetched from hk-prove once; mainnet pins them in genesis.)
        // K6 (v0.15.1): the verifying keys come from a FILE first — `HK_VKS_FILE`, else
        // `<HOME>/vks.json` (the join kit ships it) — and only then from a prover URL.
        // A node on a pinned genesis therefore needs no prover to verify; the file is
        // checked against the pins exactly like a fetched set.
        #[cfg(feature = "sp1-verify")]
        let pool_verifier: Option<crate::state::PoolVerifiers> = {
            let explicit = std::env::var("HK_VKS_FILE").ok().filter(|p| !p.is_empty()).map(std::path::PathBuf::from);
            let default_file = self.home_dir.join("vks.json");
            let vks_file = explicit.or_else(|| default_file.exists().then_some(default_file));
            let prover_url = std::env::var("HK_PROVER_URL").ok().filter(|u| !u.is_empty());
            match (vks_file, prover_url) {
                (Some(path), _) => {
                    match crate::verifier::from_vks_file(&path, genesis.vk_pins.as_ref()).await {
                        Ok(v) => {
                            info!(path = %path.display(), "SP1 pool verifier wired from the vks file (no prover needed to verify; in-node STARK verification live, incl. aggregates)");
                            Some(v)
                        }
                        Err(e) => {
                            error!(%e, path = %path.display(), "SP1 verifier init FAILED from the vks file — shielded txs will be rejected");
                            None
                        }
                    }
                }
                (None, Some(url)) => {
                    match crate::verifier::from_prover_url(&url, genesis.vk_pins.as_ref()).await {
                        Ok(v) => {
                            info!(%url, "SP1 pool verifier wired (in-node STARK verification live, incl. aggregates)");
                            Some(v)
                        }
                        Err(e) => {
                            error!(%e, %url, "SP1 verifier init FAILED — shielded txs will be rejected");
                            None
                        }
                    }
                }
                (None, None) => {
                    info!("neither a vks file nor HK_PROVER_URL — shielded txs will be rejected (RejectAll default)");
                    None
                }
            }
        };
        #[cfg(not(feature = "sp1-verify"))]
        let pool_verifier: Option<crate::state::PoolVerifiers> = None;

        // K5 (2026-09-04, from the first external operator's wedge at height 479): on a
        // network that PINS its proof system (genesis.vk_pins), running without the
        // verifier is not a mode — it is a guaranteed app_hash divergence at the first
        // shielded block (the node refuses a valid proof, computes a different state and
        // wedges; CHANGELOG 0.10.9 tells the story from our own fleet). Refuse to start
        // instead: loudly, with the fix in the message. Devnets built without pins are
        // unaffected; `HK_ALLOW_UNVERIFIED=1` overrides for deliberate experiments.
        let allow_unverified = std::env::var("HK_ALLOW_UNVERIFIED").map(|v| v == "1").unwrap_or(false);
        if pool_verifier.is_none() && genesis.vk_pins.is_some() && !allow_unverified {
            eyre::bail!(
                "this network pins its proof system (genesis.vk_pins) but no STARK verifier is wired: \
                 put the kit's verifying keys next to the genesis (copy networks/<net>/vks.json to \
                 <HOME>/vks.json, or set HK_VKS_FILE=<path>) — no prover needed — or set \
                 HK_PROVER_URL=https://prover.hashkinetics.org (reachable at startup). Starting \
                 without a verifier wedges the node at the first shielded block (app_hash \
                 divergence). HK_ALLOW_UNVERIFIED=1 overrides for experiments."
            );
        }

        // `op_handle` (built above, shared with the engine's provider) lets HkApp rotate the
        // live operational key when a RotationCert commits.
        let mut state = HkApp::new(
            address,
            &genesis,
            private_key_file,
            op_handle,
            self.home_dir.clone(),
            set_history,
            pool_verifier,
        )?;
        // Genesis-gate: bind identity to genesis — sets the digest + derives chain_id
        // from it, so hk_chainInfo distinguishes the canonical chain from any island.
        state.set_genesis_digest(genesis_digest);

        // P3.0/WS-B: durable node. Restore Σ + history + mempool from the home dir,
        // then attach the store so every commit persists. The engine's start height
        // comes from the rehydrated decided log via `start_height()` — a restarted
        // node RESUMES (replay-or-sync), it never silently restarts from genesis.
        // HK_NO_PERSIST=1 keeps the old in-memory behavior (throwaway runs).
        if std::env::var("HK_NO_PERSIST").is_err() {
            let store = Arc::new(crate::store::NodeStore::open(&self.home_dir)?);
            state.restore_from_store(&store)?;
            state.attach_store(store);
        } else {
            info!("HK_NO_PERSIST set — running in-memory (no block log, no snapshots)");
        }
        // R2/WS-F: if the restored chain says our validator entry rotated to epoch E,
        // swap the live signer to that epoch's tree BEFORE consensus starts (the engine
        // holds a clone of the same handle; per-epoch state files resume their counters).
        state.adopt_epoch_signer();

        // 0.7: spawn the RPC server sharing the chain/mempool/receipts handles.
        if config.hk_rpc.enabled {
            let mut handles = state.handles();
            handles.self_peer_id = self_peer_id.clone();
            // C2.3: single-hop tx gossip — locally admitted txs push to peer RPCs.
            if !config.hk_rpc.gossip_peers.is_empty() {
                handles.gossip =
                    Some(crate::gossip::spawn(config.hk_rpc.gossip_peers.clone()));
            }
            match config.hk_rpc.listen_addr.parse() {
                Ok(addr) => {
                    tokio::spawn(async move {
                        if let Err(e) = crate::rpc::serve(addr, handles).await {
                            error!(%e, "RPC server exited");
                        }
                    });
                }
                Err(e) => error!(%e, addr = %config.hk_rpc.listen_addr, "bad hk_rpc.listen_addr — RPC disabled"),
            }
        }

        // R1.b: tick-based rotation-threshold check — the commit-path R1 check
        // is blind when this node isn't committing (parked / wedged / minority),
        // which is exactly when a validator historically burned its tree to zero.
        state.spawn_rotation_tick(config.hk_rpc.gossip_peers.clone());

        let span = tracing::error_span!("node", moniker = %config.moniker);
        let app_handle = tokio::spawn(
            async move {
                if let Err(e) = crate::app::run(&mut state, &mut channels).await {
                    error!(%e, "Application error");
                }
            }
            .instrument(span),
        );

        Ok(Handle { app: app_handle, engine: engine_handle, tx_event })
    }

    async fn run(self) -> eyre::Result<()> {
        let handles = self.start().await?;
        handles.app.await.map_err(Into::into)
    }
}
