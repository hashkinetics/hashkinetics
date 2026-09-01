//! hk-node — the HashKinetics node binary.
//!
//! Commands:
//!   hk-node testnet <N> <HOME>   generate an N-validator local devnet under HOME
//!                                (seeded with the P0 demo genesis + RPC enabled)
//!   hk-node start <NODE_HOME>    run one node
//!   hk-node demo  <RPC_URL>      drive the P0 storyline over a live node's RPC
//!
//! Consensus votes are hash-based (LMS/HSS over SHAKE-256) — quantum-secure, not
//! Ed25519. The operational key's monotone state is persisted (reserve-then-sign) so a
//! restart never reuses a leaf; exhaustion rotates under the stateless SLH-DSA root.
//! See docs/MAINNET-KEY-MANAGEMENT.md. Ed25519 remains ONLY as libp2p transport identity.

mod account;
mod app;
mod batch;
mod faucet;
mod bench_agg;
mod codec;
mod config;
mod demo;
mod demo_agg;
mod demo_disclose;
mod demo_economy;
mod demo_mandates;
mod demo_shielded;
mod genesis;
mod gossip;
mod mempool;
mod node;
mod rpc;
mod state;
mod store;
mod storm;
mod streaming;
mod wallet_cli;
#[cfg(feature = "sp1-verify")]
mod verifier;

use std::path::PathBuf;

use hk_consensus::{op_seed, HkPriv, RootSecret, RotationCert};

use crate::genesis::{GenesisValidator, HkGenesis};
use crate::node::App;

const CONSENSUS_BASE_PORT: usize = 27000;
const METRICS_BASE_PORT: usize = 29000;
const RPC_BASE_PORT: usize = 26000;
const CHAIN_START_TIME: u64 = 1_000;

fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // LMS/HSS keygen + signing use large stack frames — run everything on a 64 MiB
    // stack (Windows main-thread default is ~1 MiB, which overflows on keygen).
    let args: Vec<String> = std::env::args().collect();
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || real_main(args))
        .unwrap()
        .join()
        .unwrap()
}

fn real_main(args: Vec<String>) -> eyre::Result<()> {
    match args.get(1).map(String::as_str) {
        Some("testnet") => {
            let n: usize = args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(4);
            let home = PathBuf::from(args.get(3).cloned().unwrap_or_else(|| "devnet".into()));
            cmd_testnet(n, &home)
        }
        Some("start") => {
            let home = PathBuf::from(
                args.get(2).cloned().ok_or_else(|| eyre::eyre!("usage: hk-node start <NODE_HOME>"))?,
            );
            // Consensus vote signing (hash-based) runs on tokio worker threads — give
            // them a 32 MiB stack too.
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(32 * 1024 * 1024)
                .build()?;
            rt.block_on(run_node(home))
        }
        Some("demo") => {
            let url = args.get(2).cloned().unwrap_or_else(|| "http://127.0.0.1:26000".into());
            demo::run(&url)
        }
        Some("demo-shielded") => {
            let url = args.get(2).cloned().unwrap_or_else(|| "http://127.0.0.1:26000".into());
            let prover = args.get(3).cloned().unwrap_or_else(|| "http://127.0.0.1:9911".into());
            demo_shielded::run(&url, &prover)
        }
        Some("demo-disclose") => {
            let url = args.get(2).cloned().unwrap_or_else(|| "http://127.0.0.1:26000".into());
            let prover = args.get(3).cloned().unwrap_or_else(|| "http://127.0.0.1:9911".into());
            demo_disclose::run(&url, &prover)
        }
        Some("demo-agg") => {
            let url = args.get(2).cloned().unwrap_or_else(|| "http://127.0.0.1:26000".into());
            let prover = args.get(3).cloned().unwrap_or_else(|| "http://127.0.0.1:9911".into());
            demo_agg::run(&url, &prover)
        }
        Some("demo-mandates") => {
            let url = args.get(2).cloned().unwrap_or_else(|| "http://127.0.0.1:26000".into());
            let prover = args.get(3).cloned().unwrap_or_else(|| "http://127.0.0.1:9911".into());
            demo_mandates::run(&url, &prover)
        }
        Some("demo-economy") => {
            // THE client demo: the whole machine economy in one command (~5 min).
            let url = args.get(2).cloned().unwrap_or_else(|| "http://127.0.0.1:26000".into());
            let prover = args.get(3).cloned().unwrap_or_else(|| "http://127.0.0.1:9911".into());
            demo_economy::run(&url, &prover)
        }
        Some("wallet") => {
            // P3.0b: wallet v1 — a real user wallet over RPC + hk-prove.
            wallet_cli::run(&args[2..])
        }
        Some("keygen") => {
            // P3.0c operator-side: generate key material + the public validator.json.
            let home = PathBuf::from(
                args.get(2).cloned().ok_or_else(|| eyre::eyre!("usage: hk-node keygen <HOME> [MONIKER]"))?,
            );
            let moniker = args.get(3).cloned().unwrap_or_else(|| "validator".into());
            cmd_keygen(&home, &moniker)
        }
        Some("genesis-build") => {
            // P3.0c coordinator-side: validators.json (array) → genesis.json.
            let vals = args.get(2).cloned().ok_or_else(|| {
                eyre::eyre!("usage: hk-node genesis-build <VALIDATORS.json> <OUT-genesis.json>  (env: HK_PROVER_URL to pin, HK_CHAIN_START_TIME)")
            })?;
            let out = args.get(3).cloned().unwrap_or_else(|| "genesis.json".into());
            cmd_genesis_build(&vals, &out)
        }
        Some("config-gen") => {
            // P3.0c operator-side: WAN-ready config.toml.
            cmd_config_gen(&args[2..])
        }
        Some("issue-rotation") => {
            // R2: mint a root-signed RotationCert OFFLINE (the stateless SLH-DSA root
            // never exhausts — this works even when the operational tree is at zero).
            // Submit the output to ANY live peer: it rides that peer's next proposal.
            let home = PathBuf::from(args.get(2).cloned().ok_or_else(|| {
                eyre::eyre!("usage: hk-node issue-rotation <HOME> [EPOCH] [VALID_FROM_HEIGHT]")
            })?);
            let epoch = args.get(3).and_then(|s| s.parse().ok());
            let valid_from = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
            cmd_issue_rotation(&home, epoch, valid_from)
        }
        Some("agg-bench") => {
            // C1p2.a: the aggregation scaling curve — T_agg(N) = a + b·N (prover only).
            let url = args.get(2).cloned().unwrap_or_else(|| "http://127.0.0.1:9911".into());
            let mut ns = vec![4usize, 10, 50, 100, 256];
            if let Some(p) = args.iter().position(|a| a == "--n") {
                if let Some(csv) = args.get(p + 1) {
                    ns = csv.split(',').filter_map(|s| s.trim().parse().ok()).collect();
                }
            }
            bench_agg::run(&url, ns)
        }
        Some("storm") => {
            // P3.1/C1: transparent load harness → the capacity sheet.
            let url = args.get(2).cloned().unwrap_or_else(|| "http://127.0.0.1:26000".into());
            let rate = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
            let dur = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(60);
            let nodes = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(4);
            storm::run(&url, rate, dur, nodes)
        }
        // ---- U1/U2: self-custodied accounts + the faucet ----------------------
        Some("account-new") => {
            let dir = PathBuf::from(args.get(2).cloned().ok_or_else(|| eyre::eyre!("usage: hk-node account-new <DIR>"))?);
            account::cmd_new(&dir)
        }
        Some("account-info") => {
            let dir = PathBuf::from(args.get(2).cloned().ok_or_else(|| eyre::eyre!("usage: hk-node account-info <DIR>"))?);
            account::cmd_info(&dir)
        }
        Some("account-balance") => {
            let rpc = args.get(2).cloned().ok_or_else(|| eyre::eyre!("usage: hk-node account-balance <RPC> <ID-hex|DIR>"))?;
            let who = args.get(3).cloned().ok_or_else(|| eyre::eyre!("usage: hk-node account-balance <RPC> <ID-hex|DIR>"))?;
            account::cmd_balance(&rpc, &who)
        }
        Some("account-send") => {
            let usage = "usage: hk-node account-send <DIR> <RPC> <TO-hex> <AMOUNT-micro> [ASSET-hex]";
            let dir = PathBuf::from(args.get(2).cloned().ok_or_else(|| eyre::eyre!(usage))?);
            let rpc = args.get(3).cloned().ok_or_else(|| eyre::eyre!(usage))?;
            let to = args.get(4).cloned().ok_or_else(|| eyre::eyre!(usage))?;
            let amount: u128 = args.get(5).and_then(|s| s.parse().ok()).ok_or_else(|| eyre::eyre!(usage))?;
            account::cmd_send(&dir, &rpc, &to, amount, args.get(6).map(|s| s.as_str()))
        }
        Some("account-create") => {
            let usage = "usage: hk-node account-create <DIR> <RPC> <AUTH-COMMIT-hex> <AMOUNT-micro> [ASSET-hex]";
            let dir = PathBuf::from(args.get(2).cloned().ok_or_else(|| eyre::eyre!(usage))?);
            let rpc = args.get(3).cloned().ok_or_else(|| eyre::eyre!(usage))?;
            let auth = args.get(4).cloned().ok_or_else(|| eyre::eyre!(usage))?;
            let amount: u128 = args.get(5).and_then(|s| s.parse().ok()).ok_or_else(|| eyre::eyre!(usage))?;
            account::cmd_create(&dir, &rpc, &auth, amount, args.get(6).map(|s| s.as_str()))
        }
        Some("account-adopt-demo") => {
            let usage = "usage: hk-node account-adopt-demo <DIR> <NAME> [RPC]";
            let dir = PathBuf::from(args.get(2).cloned().ok_or_else(|| eyre::eyre!(usage))?);
            let name = args.get(3).cloned().ok_or_else(|| eyre::eyre!(usage))?;
            let rpc = args.get(4).cloned().unwrap_or_else(|| "http://127.0.0.1:26000".into());
            account::cmd_adopt_demo(&dir, &name, &rpc)
        }
        Some("faucet-serve") => {
            let usage = "usage: hk-node faucet-serve <WALLET-DIR> <RPC> [--listen 127.0.0.1:9922] [--drip MICRO] [--asset HEX] [--cooldown-secs N] [--daily-cap N]";
            let dir = PathBuf::from(args.get(2).cloned().ok_or_else(|| eyre::eyre!(usage))?);
            let rpc = args.get(3).cloned().ok_or_else(|| eyre::eyre!(usage))?;
            let mut listen = "127.0.0.1:9922".to_string();
            let mut drip: u128 = 100_000; // $0.10 default — staging supply is tiny
            let mut asset: Option<String> = None;
            let mut cooldown: u64 = 86_400;
            let mut daily_cap: u32 = 200;
            let rest: Vec<String> = args[4..].to_vec();
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--listen" => { listen = rest.get(i + 1).cloned().ok_or_else(|| eyre::eyre!(usage))?; i += 2 }
                    "--drip" => { drip = rest.get(i + 1).and_then(|s| s.parse().ok()).ok_or_else(|| eyre::eyre!(usage))?; i += 2 }
                    "--asset" => { asset = rest.get(i + 1).cloned(); i += 2 }
                    "--cooldown-secs" => { cooldown = rest.get(i + 1).and_then(|s| s.parse().ok()).ok_or_else(|| eyre::eyre!(usage))?; i += 2 }
                    "--daily-cap" => { daily_cap = rest.get(i + 1).and_then(|s| s.parse().ok()).ok_or_else(|| eyre::eyre!(usage))?; i += 2 }
                    _ => return Err(eyre::eyre!(usage)),
                }
            }
            let asset = match asset {
                Some(a) => account::parse_h256(&a)?,
                None => demo::usd(),
            };
            faucet::serve(faucet::FaucetCfg {
                wallet_dir: dir,
                node_rpc: rpc,
                listen,
                drip,
                asset,
                cooldown: std::time::Duration::from_secs(cooldown),
                daily_cap,
            })
        }
        Some("verify-disclosure") => {
            // OFFLINE: reads one JSON file, touches no network, needs no node.
            let path = args
                .get(2)
                .cloned()
                .ok_or_else(|| eyre::eyre!("usage: hk-node verify-disclosure <package.json>"))?;
            let raw = std::fs::read_to_string(&path)?;
            let pkg: hk_wallet::DisclosurePackage = serde_json::from_str(&raw)?;
            match hk_wallet::verify_disclosure(&pkg) {
                Ok(d) => {
                    println!("✓ DISCLOSURE VERIFIED (offline) — chain {}", pkg.chain_id);
                    println!("  amount     : {} micro-units", d.value);
                    println!("  memo       : {:?}", String::from_utf8_lossy(&d.memo));
                    println!("  recipient  : tag {}…", hex::encode(&d.owner_tag[..8]));
                    println!("  commitment : {}…  (tree index {})", hex::encode(&d.commitment[..8]), d.leaf_index);
                    println!("  anchor     : {}   ← cross-check this root on-chain", hex::encode(d.anchor));
                    Ok(())
                }
                Err(e) => {
                    eprintln!("✗ package REJECTED: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("HashKinetics node v0.10 (hash-based consensus + shielded pool + disclosure + durable store)");
            eprintln!("usage: hk-node testnet <N> <HOME> | start <NODE_HOME> | wallet <CMD …> | keygen <HOME> [MONIKER] | issue-rotation <HOME> [EPOCH] [VALID_FROM] | genesis-build <VALIDATORS.json> <OUT.json> | config-gen <HOME> --listen … --peers … | storm <RPC> [RATE] [DURATION_S] | demo <RPC> | demo-economy <RPC> <PROVER> | demo-shielded <RPC> <PROVER> | demo-disclose <RPC> <PROVER> | demo-agg <RPC> <PROVER> | demo-mandates <RPC> <PROVER> | verify-disclosure <package.json>");
            eprintln!("join a testnet: docs/VALIDATOR-ONBOARDING.md (keygen → send validator.json → receive genesis → config-gen → start)");
            eprintln!("accounts (U1): account-new DIR · account-info DIR · account-balance RPC ID|DIR · account-send DIR RPC TO MICRO [ASSET] · account-create DIR RPC AUTH_COMMIT MICRO [ASSET] · faucet-serve DIR RPC [--drip …]");
            eprintln!("wallet: init DIR ACCOUNT [RPC] · status DIR [RPC] · address DIR [RPC] · scan DIR [RPC] · transfer DIR TO USD [RPC] · shield DIR USD [RPC] [PROVER] · unshield DIR USD [RPC] [PROVER] · pay DIR HKADDR USD [MEMO] [RPC] [PROVER] · disclose DIR COMMITMENT OUT.json [RPC]");
            Ok(())
        }
    }
}

async fn run_node(home: PathBuf) -> eyre::Result<()> {
    use malachitebft_app_channel::app::node::Node;
    let app = App::new(home, None);
    app.run().await
}

/// P2.5: pin the proof-system vks into genesis when a prover is reachable at
/// generation time. Nodes then REFUSE any other proof system — which also makes
/// fetching vk BYTES from a hosted prover trustless for external validators.
fn fetch_vk_pins() -> Option<crate::genesis::VkPins> {
    match std::env::var("HK_PROVER_URL") {
        Ok(url) if !url.is_empty() => {
            let v = demo::rpc(&url, "vks", serde_json::json!({}));
            let pin = |k: &str| -> Option<String> {
                let hexs = v.get("result")?.get(k)?.as_str()?;
                let bytes = hex::decode(hexs).ok()?;
                Some(hex::encode(hk_crypto::hash::shake256_32(
                    hk_crypto::hash::DOM_VK_PIN,
                    &[&bytes],
                )))
            };
            match (pin("spend_vk"), pin("mint_vk"), pin("agg_vk")) {
                (Some(spend), Some(mint), Some(agg)) => {
                    println!("pinning proof-system vks into genesis (fetched from {url})");
                    Some(crate::genesis::VkPins { spend, mint, agg })
                }
                _ => {
                    eprintln!("WARN: could not fetch vks from {url} — genesis is UNPINNED");
                    None
                }
            }
        }
        _ => None,
    }
}

fn cmd_testnet(n: usize, home: &PathBuf) -> eyre::Result<()> {
    // Each validator gets a 32-byte master seed; the consensus (LMS/HSS) public key is
    // derived from it. Keygen is done once per validator here (a second or two each).
    let seeds: Vec<[u8; 32]> = (0..n).map(|_| rand::random::<[u8; 32]>()).collect();
    println!("generating {n} hash-based validator keys (LMS/HSS keygen — a moment each)...");

    let vk_pins = fetch_vk_pins();

    let genesis = HkGenesis {
        chain_start_time: CHAIN_START_TIME,
        validators: seeds
            .iter()
            .map(|seed| GenesisValidator {
                root_pk: RootSecret::from_seed(seed).public_bytes().to_vec(),
                public_key: HkPriv::from_seed(*seed).public(),
                voting_power: 1,
            })
            .collect(),
        // Seed the P0 storyline accounts (org funded $50, agents, merchant).
        chain: Some(demo::genesis(CHAIN_START_TIME)),
        vk_pins,
    };
    let genesis_json = serde_json::to_string_pretty(&genesis)?;

    for (i, seed) in seeds.iter().enumerate() {
        let dir = home.join(format!("node{i}"));
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("genesis.json"), &genesis_json)?;
        std::fs::write(dir.join("priv_validator_key.json"), serde_json::to_string_pretty(seed)?)?;

        let peers: Vec<String> = (0..n)
            .filter(|j| *j != i)
            .map(|j| format!("\"/ip4/127.0.0.1/tcp/{}\"", CONSENSUS_BASE_PORT + j))
            .collect();

        // C2.3: every other node's RPC — a tx submitted to ANY devnet node reaches
        // every proposer's mempool one hop later.
        let gossip_peers: Vec<String> = (0..n)
            .filter(|j| *j != i)
            .map(|j| format!("\"http://127.0.0.1:{}\"", RPC_BASE_PORT + j))
            .collect();
        let config = config_template(
            &format!("hk-{i}"),
            &format!("/ip4/127.0.0.1/tcp/{}", CONSENSUS_BASE_PORT + i),
            &peers.join(", "),
            false,
            &format!("127.0.0.1:{}", METRICS_BASE_PORT + i),
            &format!("127.0.0.1:{}", RPC_BASE_PORT + i),
            &gossip_peers.join(", "),
        );
        std::fs::write(dir.join("config.toml"), config)?;
        println!("wrote {}  (rpc :{}) ", dir.display(), RPC_BASE_PORT + i);
    }

    println!("\nDevnet ready: {n} validators under {}", home.display());
    println!("Start each in its own terminal:  hk-node start {}\\node<i>", home.display());
    println!("Then run the demo against node0:  hk-node demo http://127.0.0.1:{RPC_BASE_PORT}");
    Ok(())
}

fn config_template(
    moniker: &str,
    listen_addr: &str,
    peers: &str,
    metrics_enabled: bool,
    metrics_addr: &str,
    rpc_addr: &str,
    gossip_peers: &str,
) -> String {
    format!(
        r#"moniker = "{moniker}"

[logging]
log_level = "info"
log_format = "plaintext"

[consensus]
enabled = true
# With the HSS bottom tree at H5 + aux cache, LMS sign/verify are ~ms, so blocks decide
# at round 0 in ~1.4 s — the phase timeouts are upper bounds the happy path rarely hits.
# `timeout_propose` only bites when a proposer is ABSENT (round change), so 2 s detects a
# dead proposer a second faster than the old 3 s without risking premature round changes
# (proposals arrive ~300 ms after round start). Don't go much lower on this devnet.
timeout_propose = "2s"
timeout_propose_delta = "500ms"
timeout_prevote = "2s"
timeout_prevote_delta = "500ms"
timeout_precommit = "2s"
timeout_precommit_delta = "500ms"
timeout_commit = "0s"
timeout_rebroadcast = "5s"
value_payload = "proposal-and-parts"

[consensus.vote_sync]
mode = "request-response"

[consensus.p2p]
listen_addr = "{listen_addr}"
persistent_peers = [{peers}]
transport = "tcp"
discovery = {{ enabled = false }}
# P2.5: the wire codec is BINCODE — proofs ride raw (a 2.7 MB core STARK costs ~2.7 MB;
# under the old JSON codec it cost ~11 MB and hit MessageTooLarge at the 8 MiB default).
# 32 MiB kept as headroom for blocks carrying several core-mode proofs at once.
pubsub_max_size = "32 MiB"
rpc_max_size = "32 MiB"

[consensus.p2p.protocol]
type = "gossipsub"
mesh_n = 6
mesh_n_high = 12
mesh_n_low = 4
mesh_outbound_min = 2

[value_sync]
enabled = true
status_update_interval = "10s"
request_timeout = "10s"
max_request_size = "1 MiB"
# Sync responses carry whole decided values (batched) — proof blocks are MB-scale raw.
max_response_size = "64 MiB"
parallel_requests = 5
scoring_strategy = "ema"
inactive_threshold = "60s"
# R5: 5×20 = 100 heights in flight (queue capacity derives from this product).
# The patched sync engine refills the window on every response, so throughput is
# RTT/apply-bound, not status-tick-bound (was ~46 blk/min, burst-then-idle).
batch_size = 20

[metrics]
enabled = {metrics_enabled}
listen_addr = "{metrics_addr}"

[runtime]
flavor = "single_threaded"

[hk_rpc]
enabled = true
listen_addr = "{rpc_addr}"
# C2.3: peer RPC endpoints to push admitted txs to (single-hop tx gossip).
# Empty = v0 behavior (submit to your home node; only it can propose your tx).
gossip_peers = [{gossip_peers}]
"#
    )
}

// ---------------------------------------------------------------------------
// P3.0c — the testnet kit: keygen → genesis ceremony → per-node WAN config.
// The localhost `testnet` generator stays for devnets; these three commands are
// the JOIN FLOW for external validators (docs/VALIDATOR-ONBOARDING.md).
// ---------------------------------------------------------------------------

/// Operator-side: generate this validator's key material in HOME.
/// `priv_validator_key.json` is SECRET; `validator.json` is the public blob the
/// operator sends to the genesis coordinator (exactly the shape genesis embeds).
fn cmd_keygen(home: &PathBuf, moniker: &str) -> eyre::Result<()> {
    std::fs::create_dir_all(home)?;
    let key_path = home.join("priv_validator_key.json");
    if key_path.exists() {
        eyre::bail!("{} already exists — refusing to overwrite a validator key", key_path.display());
    }
    println!("generating hash-based validator key (LMS/HSS keygen — a moment)...");
    let seed: [u8; 32] = rand::random();
    std::fs::write(&key_path, serde_json::to_string_pretty(&seed)?)?;
    let gv = GenesisValidator {
        root_pk: RootSecret::from_seed(&seed).public_bytes().to_vec(),
        public_key: HkPriv::from_seed(seed).public(),
        voting_power: 1,
    };
    let vj = home.join("validator.json");
    std::fs::write(&vj, serde_json::to_string_pretty(&gv)?)?;
    println!("✓ key material written:");
    println!("    {}  (SECRET — never leaves this machine; back it up)", key_path.display());
    println!("    {}  (PUBLIC — send THIS to the genesis coordinator)", vj.display());
    println!("  moniker           : {moniker}");
    println!("  root identity     : SLH-DSA-192s {}…", hex::encode(&gv.root_pk[..8.min(gv.root_pk.len())]));
    println!("  consensus address : {}", hk_consensus::HkAddress::from_public_key(&gv.public_key));
    println!("\nAlso send the coordinator your PUBLIC consensus multiaddr, e.g.:");
    println!("    /ip4/<YOUR-PUBLIC-IP>/tcp/27000");
    Ok(())
}

/// R2 (staging incident #1): mint a root-signed RotationCert OFFLINE. The stateless
/// SLH-DSA root signs regardless of the operational tree's leaf budget — this is the
/// revival path for a validator whose HSS tree exhausted (it can no longer sign votes,
/// so it can never PROPOSE its own cert; any live peer carries it instead).
///
/// Flow: run this on the validator's machine (needs priv_validator_key.json) →
/// submit the printed JSON to any peer's RPC (`hk_submitRotation`) → the cert rides
/// that peer's next proposal → on commit every node swaps this validator's key in the
/// set → restart the exhausted node: `adopt_epoch_signer` builds the fresh epoch tree
/// (never-signed ⇒ starts at leaf 0) and it rejoins consensus.
fn cmd_issue_rotation(home: &PathBuf, epoch: Option<u64>, valid_from: u64) -> eyre::Result<()> {
    let key_path = home.join("priv_validator_key.json");
    let raw = std::fs::read_to_string(&key_path)
        .map_err(|e| eyre::eyre!("{}: {e} (run on the VALIDATOR's machine)", key_path.display()))?;
    let seed: [u8; 32] = serde_json::from_str(&raw)?;
    let root = RootSecret::from_seed(&seed);
    let epoch = epoch.unwrap_or(1);
    if epoch == 0 {
        eyre::bail!("epoch must be ≥ 1 (0 is the genesis key; certs are strictly monotone)");
    }
    println!("deriving epoch-{epoch} operational tree (LMS/HSS keygen — a moment)...");
    let new_op_pk = HkPriv::from_seed(op_seed(&seed, epoch)).public();
    println!("signing the rotation cert with the SLH-DSA root (stateless — never exhausts)...");
    let cert = RotationCert::issue(&root, new_op_pk, epoch, valid_from);
    let out = home.join(format!("rotation_e{epoch}.json"));
    std::fs::write(&out, serde_json::to_string(&serde_json::json!({ "cert": cert }))?)?;
    println!("✓ rotation cert written: {}", out.display());
    println!("  root identity : SLH-DSA-192s {}…", hex::encode(&cert.root_pk[..8]));
    println!("  new epoch     : {epoch}   (must be strictly greater than the on-chain epoch)");
    println!("\nsubmit it through ANY live peer (the cert rides that peer's next proposal):");
    println!(
        "  printf '{{\"method\":\"hk_submitRotation\",\"params\":%s}}' \"$(cat {})\" | \\",
        out.display()
    );
    println!("    curl -s -X POST <PEER_RPC> -d @-");
    println!("\nthen restart THIS validator's node — it adopts the fresh epoch-{epoch} tree on boot.");
    Ok(())
}

/// Coordinator-side: assemble genesis from the collected validator.json blobs
/// (a JSON array). Set HK_PROVER_URL to pin the proof system (public testnets
/// must ALWAYS pin); HK_CHAIN_START_TIME overrides the deterministic clock epoch.
fn cmd_genesis_build(validators_path: &str, out_path: &str) -> eyre::Result<()> {
    let raw = std::fs::read_to_string(validators_path)?;
    let validators: Vec<GenesisValidator> = serde_json::from_str(&raw)?;
    if validators.is_empty() {
        eyre::bail!("no validators in {validators_path}");
    }
    let start_time = std::env::var("HK_CHAIN_START_TIME")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(CHAIN_START_TIME);
    let vk_pins = fetch_vk_pins();
    if vk_pins.is_none() {
        eprintln!("WARN: building an UNPINNED genesis — set HK_PROVER_URL; a public testnet must always pin");
    }
    let genesis = HkGenesis {
        chain_start_time: start_time,
        validators,
        chain: Some(demo::genesis(start_time)),
        vk_pins,
    };
    std::fs::write(out_path, serde_json::to_string_pretty(&genesis)?)?;
    println!(
        "✓ genesis written to {out_path} — {} validators · chain_start_time {start_time} · vk pins: {}",
        genesis.validators.len(),
        if genesis.vk_pins.is_some() { "YES" } else { "NO (devnet only!)" }
    );
    println!("  Distribute this EXACT file to every operator — byte-identical, or app hashes fork at height 1.");
    Ok(())
}

/// Operator-side: write a WAN-ready config.toml into HOME.
fn cmd_config_gen(rest: &[String]) -> eyre::Result<()> {
    let usage = "usage: hk-node config-gen <HOME> --listen /ip4/0.0.0.0/tcp/27000 --peers /ip4/A.B.C.D/tcp/27000,/ip4/… [--moniker NAME] [--rpc 127.0.0.1:26000] [--metrics 127.0.0.1:29000] [--gossip-peers http://A.B.C.D:26000,…]";
    let home = PathBuf::from(rest.first().ok_or_else(|| eyre::eyre!("{usage}"))?);
    let (mut listen, mut peers, mut metrics) = (None::<String>, None::<String>, None::<String>);
    let mut moniker = "hk-validator".to_string();
    let mut rpc_addr = "127.0.0.1:26000".to_string();
    let mut gossip = String::new();
    let mut i = 1;
    while i < rest.len() {
        match rest[i].as_str() {
            "--listen" => { listen = rest.get(i + 1).cloned(); i += 2 }
            "--peers" => { peers = rest.get(i + 1).cloned(); i += 2 }
            "--moniker" => { moniker = rest.get(i + 1).cloned().ok_or_else(|| eyre::eyre!("{usage}"))?; i += 2 }
            "--rpc" => { rpc_addr = rest.get(i + 1).cloned().ok_or_else(|| eyre::eyre!("{usage}"))?; i += 2 }
            "--metrics" => { metrics = rest.get(i + 1).cloned(); i += 2 }
            "--gossip-peers" => { gossip = rest.get(i + 1).cloned().unwrap_or_default(); i += 2 }
            other => eyre::bail!("unknown flag {other}\n{usage}"),
        }
    }
    let listen = listen.ok_or_else(|| eyre::eyre!("--listen is required\n{usage}"))?;
    let quoted: Vec<String> = peers
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!("\"{}\"", s.trim()))
        .collect();
    let gossip_quoted: Vec<String> = gossip
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!("\"{}\"", s.trim()))
        .collect();
    std::fs::create_dir_all(&home)?;
    let cfg = config_template(
        &moniker,
        &listen,
        &quoted.join(", "),
        metrics.is_some(),
        metrics.as_deref().unwrap_or("127.0.0.1:29000"),
        &rpc_addr,
        &gossip_quoted.join(", "),
    );
    std::fs::write(home.join("config.toml"), cfg)?;
    println!(
        "✓ config.toml written to {} — listen {listen} · {} peer(s) · rpc {rpc_addr}{}",
        home.display(),
        quoted.len(),
        if metrics.is_some() { " · metrics ON" } else { "" }
    );
    println!("  Place the coordinator's genesis.json beside it, then:  hk-node start {}", home.display());
    println!("  (RPC binds {rpc_addr} — keep it loopback unless fronted by a proxy: it has NO auth.)");
    Ok(())
}
