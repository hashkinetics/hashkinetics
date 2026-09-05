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

/// The release label this binary reports (`hk-node --version`, the usage banner).
/// Bump with every node release; the crate version is workspace-wide and not it.
pub const NODE_VERSION: &str = "v0.15.2";

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

use hk_consensus::{op_seed, Approval, HkPriv, RootSecret, RotationCert, SetChange, SetChangeBody, SetChangeCert};

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
        Some("--version") | Some("version") => {
            println!("hk-node {NODE_VERSION}");
            Ok(())
        }
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
            // U4.b: fee policy + allocations are genesis facts (see cmd_genesis_build).
            let vals = args.get(2).cloned().ok_or_else(|| {
                eyre::eyre!("usage: hk-node genesis-build <VALIDATORS.json> <OUT-genesis.json> [--fee-micro N] [--fee-from H] [--fee-asset HEX] [--alloc AUTH0:MICRO ...] [--asset SYMBOL:DECIMALS:ISSUER-AUTH0:FLAGS[:ID-hex] ...] [--demo-accounts [ORG-USD]]  (env: HK_PROVER_URL to pin, HK_CHAIN_START_TIME)")
            })?;
            let out = args.get(3).cloned().unwrap_or_else(|| "genesis.json".into());
            cmd_genesis_build(&vals, &out, &args[4.min(args.len())..])
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
        Some("set-change") => {
            // V1: validator-set changes on a running chain — propose (build the body) →
            // approve (each seat signs with its root, on its own machine) → assemble
            // (collect approvals, verify, print the cert) → hk_submitSetChange on any peer.
            cmd_set_change(&args[2..])
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
        // ---- X1: issued assets (docs/X1-ISSUED-ASSETS.md) ----------------------------
        Some("asset-id") => {
            // Offline: the id an issuer account gets for a symbol.
            let usage = "usage: hk-node asset-id <ISSUER-hex|DIR> <SYMBOL>";
            let who = args.get(2).cloned().ok_or_else(|| eyre::eyre!(usage))?;
            let sym = args.get(3).cloned().ok_or_else(|| eyre::eyre!(usage))?;
            account::cmd_asset_id(&who, &sym)
        }
        Some("asset") => account::cmd_asset(&args[2..]),
        // ---- K6 (v0.15.1): the join kit ships the verifying keys ----------------------
        Some("vks-fetch") => {
            // Coordinator/operator-side: pull the three vks from a prover (http or https),
            // optionally check them against a genesis' pins, write `vks.json` — the file a
            // node reads via HK_VKS_FILE / <HOME>/vks.json so it never needs the prover.
            let usage = "usage: hk-node vks-fetch <PROVER_URL> [-o vks.json] [--genesis genesis.json]";
            let url = args.get(2).cloned().ok_or_else(|| eyre::eyre!(usage))?;
            let mut out = PathBuf::from("vks.json");
            let mut gen: Option<PathBuf> = None;
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "-o" => { out = PathBuf::from(args.get(i + 1).ok_or_else(|| eyre::eyre!(usage))?); i += 2 }
                    "--genesis" => { gen = Some(PathBuf::from(args.get(i + 1).ok_or_else(|| eyre::eyre!(usage))?)); i += 2 }
                    _ => return Err(eyre::eyre!(usage)),
                }
            }
            cmd_vks_fetch(&url, &out, gen.as_deref())
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
            eprintln!("HashKinetics node {NODE_VERSION} (hash-based consensus + shielded pool + disclosure + durable store)");
            eprintln!("usage: hk-node testnet <N> <HOME> | start <NODE_HOME> | wallet <CMD …> | keygen <HOME> [MONIKER] | issue-rotation <HOME> [EPOCH] [VALID_FROM] | set-change propose|approve|assemble … | genesis-build <VALIDATORS.json> <OUT.json> | config-gen <HOME> --listen … --peers … | storm <RPC> [RATE] [DURATION_S] | demo <RPC> | demo-economy <RPC> <PROVER> | demo-shielded <RPC> <PROVER> | demo-disclose <RPC> <PROVER> | demo-agg <RPC> <PROVER> | demo-mandates <RPC> <PROVER> | verify-disclosure <package.json>");
            eprintln!("join a testnet: docs/VALIDATOR-ONBOARDING.md (keygen → send validator.json → receive genesis → config-gen → start)");
            eprintln!("accounts (U1): account-new DIR · account-info DIR · account-balance RPC ID|DIR · account-send DIR RPC TO MICRO [ASSET] · account-create DIR RPC AUTH_COMMIT MICRO [ASSET] · faucet-serve DIR RPC [--drip …]");
            eprintln!("verifying keys (K6): vks-fetch PROVER_URL [-o vks.json] [--genesis genesis.json]  — a node reads HK_VKS_FILE or <HOME>/vks.json and needs no prover to verify");
            eprintln!("issued assets (X1): asset-id ISSUER|DIR SYMBOL · asset register DIR RPC SYMBOL DECIMALS FLAGS(m/f/p/s|-) · asset mint DIR RPC ASSET TO MICRO · asset burn DIR RPC ASSET MICRO [DEST-hex] · asset freeze|unfreeze DIR RPC ASSET ACCOUNT · asset pause|unpause DIR RPC ASSET · asset info RPC ASSET|SYMBOL@ISSUER · asset list RPC");
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
/// K6: `vks-fetch` — the three verifying keys as a file the join kit ships.
fn cmd_vks_fetch(url: &str, out: &PathBuf, genesis: Option<&std::path::Path>) -> eyre::Result<()> {
    let v = demo::rpc(url, "vks", serde_json::json!({}));
    let r = v.get("result").ok_or_else(|| eyre::eyre!("prover at {url} returned no result: {v}"))?;
    let mut set = serde_json::Map::new();
    let mut pins = Vec::new();
    for key in ["spend_vk", "mint_vk", "agg_vk"] {
        let hexs = r.get(key).and_then(|x| x.as_str()).ok_or_else(|| eyre::eyre!("prover response missing {key}"))?;
        let bytes = hex::decode(hexs).map_err(|e| eyre::eyre!("{key} hex: {e}"))?;
        pins.push((key, hex::encode(hk_crypto::hash::shake256_32(hk_crypto::hash::DOM_VK_PIN, &[&bytes])), bytes.len()));
        set.insert(key.to_string(), serde_json::Value::String(hexs.to_string()));
    }
    if let Some(g) = genesis {
        let raw = std::fs::read_to_string(g).map_err(|e| eyre::eyre!("{}: {e}", g.display()))?;
        let hg: HkGenesis = serde_json::from_str(&raw)?;
        match hg.vk_pins {
            Some(p) => {
                let want = [("spend_vk", p.spend), ("mint_vk", p.mint), ("agg_vk", p.agg)];
                for ((key, got, _), (_, w)) in pins.iter().zip(want.iter()) {
                    if got != w {
                        eyre::bail!("{key} PIN MISMATCH: genesis {w}, prover {got} — not writing; this prover serves a different proof system than the genesis pins");
                    }
                }
                println!("✓ all three vks match the pins in {}", g.display());
            }
            None => println!("(genesis {} carries no vk pins — nothing to check against)", g.display()),
        }
    }
    let text = serde_json::to_string_pretty(&serde_json::Value::Object(set))?;
    std::fs::write(out, format!("{text}\n"))?;
    println!("✓ verifying keys written: {} ({} bytes)", out.display(), text.len() + 1);
    for (key, pin, len) in &pins {
        println!("  {key:8} {len} bytes · pin {pin}");
    }
    println!("\na node reads this file via HK_VKS_FILE=<path> (or as <HOME>/vks.json) and needs no prover to verify");
    Ok(())
}

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
    // H12 (v0.13.2): the highest-value key in the system comes straight from the OS CSPRNG.
    let seeds: Vec<[u8; 32]> = (0..n).map(|_| os_seed()).collect();
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
    let seed: [u8; 32] = os_seed(); // H12: OS CSPRNG, no userspace generator state
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

/// V1 (v0.14): validator-set changes on a running chain. Three verbs, one certificate:
///
///   hk-node set-change propose <HOME> --admit <validator.json> [--power 1] --not-before H --not-after H2
///   hk-node set-change propose <HOME> --remove <root_pk_hex>          --not-before H --not-after H2
///       → prints `set-change.json` (the BODY; chain id read from <HOME>/genesis.json)
///   hk-node set-change approve <HOME> <set-change.json>
///       → on EACH approving seat's machine (needs its priv_validator_key.json): signs the body
///         with the seat's stateless SLH-DSA root → prints `approval-<root8>.json`
///   hk-node set-change assemble <set-change.json> <approval.json>… [-o cert.json]
///       → verifies every approval, prints the certificate; submit it through ANY live peer:
///         printf '{"method":"hk_submitSetChange","params":%s}' "$(cat cert.json)" | curl -s -X POST <RPC> -d @-
///
/// Authority = strictly more than ⅔ of the CURRENT seats' voting power, checked by every
/// node at propose and at commit; the change takes effect one height after it commits.
fn cmd_set_change(args: &[String]) -> eyre::Result<()> {
    let usage = "usage: hk-node set-change propose <HOME> (--admit <validator.json> [--power N] | --remove <root_hex>) --not-before H --not-after H | approve <HOME> <set-change.json> | assemble <set-change.json> <approval.json>... [-o cert.json]";
    match args.first().map(String::as_str) {
        Some("propose") => {
            let home = PathBuf::from(args.get(1).ok_or_else(|| eyre::eyre!("{usage}"))?);
            let mut admit: Option<PathBuf> = None;
            let mut remove: Option<String> = None;
            let mut power: u64 = 1;
            let mut not_before: Option<u64> = None;
            let mut not_after: Option<u64> = None;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--admit" => { admit = args.get(i + 1).map(PathBuf::from); i += 2 }
                    "--remove" => { remove = args.get(i + 1).cloned(); i += 2 }
                    "--power" => { power = args.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(1); i += 2 }
                    "--not-before" => { not_before = args.get(i + 1).and_then(|v| v.parse().ok()); i += 2 }
                    "--not-after" => { not_after = args.get(i + 1).and_then(|v| v.parse().ok()); i += 2 }
                    other => eyre::bail!("unknown flag {other}\n{usage}"),
                }
            }
            let (not_before, not_after) = match (not_before, not_after) {
                (Some(a), Some(b)) if b >= a => (a, b),
                _ => eyre::bail!("--not-before and --not-after (≥ not-before) are required — a certificate must expire\n{usage}"),
            };
            let chain_id = chain_id_of_home(&home)?;
            let change = match (admit, remove) {
                (Some(vj), None) => {
                    let raw = std::fs::read_to_string(&vj)
                        .map_err(|e| eyre::eyre!("{}: {e}", vj.display()))?;
                    let gv: GenesisValidator = serde_json::from_str(&raw)?;
                    if gv.root_pk.len() != 48 {
                        eyre::bail!("{}: root_pk must be 48 bytes (SLH-DSA-192s)", vj.display());
                    }
                    SetChange::Admit { root_pk: gv.root_pk, public_key: gv.public_key, voting_power: power }
                }
                (None, Some(hexroot)) => {
                    let root_pk = hex::decode(hexroot.trim()).map_err(|e| eyre::eyre!("--remove: bad hex: {e}"))?;
                    if root_pk.len() != 48 {
                        eyre::bail!("--remove: root_pk must be 48 bytes (96 hex chars)");
                    }
                    SetChange::Remove { root_pk }
                }
                _ => eyre::bail!("exactly one of --admit / --remove\n{usage}"),
            };
            let body = SetChangeBody { chain_id: chain_id.clone(), change, not_before, not_after };
            body.check_shape().map_err(|e| eyre::eyre!(e))?;
            let out = home.join("set-change.json");
            std::fs::write(&out, serde_json::to_string_pretty(&body)?)?;
            println!("✓ set-change body written: {}", out.display());
            println!("  chain id  : {chain_id}");
            match &body.change {
                SetChange::Admit { root_pk, public_key, voting_power } => {
                    println!("  ADMIT     : root {}… · address {} · power {voting_power}",
                        hex::encode(&root_pk[..8]), hk_consensus::HkAddress::from_public_key(public_key));
                }
                SetChange::Remove { root_pk } => println!("  REMOVE    : root {}…", hex::encode(&root_pk[..8])),
            }
            println!("  window    : commit height {not_before} … {not_after} (effective one height after commit)");
            println!("\nnext: on EACH approving seat's machine:  hk-node set-change approve <HOME> {}", out.display());
            println!("      (approvals from strictly more than 2/3 of the current voting power are required)");
            Ok(())
        }
        Some("approve") => {
            let home = PathBuf::from(args.get(1).ok_or_else(|| eyre::eyre!("{usage}"))?);
            let body_path = PathBuf::from(args.get(2).ok_or_else(|| eyre::eyre!("{usage}"))?);
            let body: SetChangeBody = serde_json::from_str(&std::fs::read_to_string(&body_path)
                .map_err(|e| eyre::eyre!("{}: {e}", body_path.display()))?)?;
            body.check_shape().map_err(|e| eyre::eyre!(e))?;
            // Refuse to sign for a different network than this home's genesis, if it has one.
            if let Ok(cid) = chain_id_of_home(&home) {
                if cid != body.chain_id {
                    eyre::bail!("this home is on {cid}; the body is for {} — refusing to approve", body.chain_id);
                }
            }
            let key_path = home.join("priv_validator_key.json");
            let raw = std::fs::read_to_string(&key_path)
                .map_err(|e| eyre::eyre!("{}: {e} (run on the SEAT's machine)", key_path.display()))?;
            let seed: [u8; 32] = serde_json::from_str(&raw)?;
            let root = RootSecret::from_seed(&seed);
            println!("signing the set-change body with this seat's SLH-DSA root (stateless — never exhausts)...");
            let approval = Approval::sign(&root, &body);
            let tag = hex::encode(&approval.root_pk[..4]);
            let out = home.join(format!("approval-{tag}.json"));
            std::fs::write(&out, serde_json::to_string(&approval)?)?;
            println!("✓ approval written: {}", out.display());
            println!("  seat root : {}…", hex::encode(&approval.root_pk[..8]));
            println!("\nsend it to the coordinator; assemble with:  hk-node set-change assemble {} <approvals…>", body_path.display());
            Ok(())
        }
        Some("assemble") => {
            let body_path = PathBuf::from(args.get(1).ok_or_else(|| eyre::eyre!("{usage}"))?);
            let body: SetChangeBody = serde_json::from_str(&std::fs::read_to_string(&body_path)
                .map_err(|e| eyre::eyre!("{}: {e}", body_path.display()))?)?;
            let mut out_path = PathBuf::from("set-change-cert.json");
            let mut approvals: Vec<Approval> = Vec::new();
            let mut i = 2;
            while i < args.len() {
                if args[i] == "-o" {
                    out_path = PathBuf::from(args.get(i + 1).ok_or_else(|| eyre::eyre!("-o needs a path"))?);
                    i += 2;
                    continue;
                }
                let a: Approval = serde_json::from_str(&std::fs::read_to_string(&args[i])
                    .map_err(|e| eyre::eyre!("{}: {e}", args[i]))?)?;
                if !a.verify(&body) {
                    eyre::bail!("{}: approval signature does NOT verify over this body", args[i]);
                }
                if approvals.iter().any(|x| x.root_pk == a.root_pk) {
                    println!("  (duplicate approval from root {}… skipped)", hex::encode(&a.root_pk[..8]));
                } else {
                    println!("  ✓ approval from root {}…", hex::encode(&a.root_pk[..8]));
                    approvals.push(a);
                }
                i += 1;
            }
            if approvals.is_empty() {
                eyre::bail!("no approvals given\n{usage}");
            }
            let cert = SetChangeCert { body, approvals };
            std::fs::write(&out_path, serde_json::to_string(&serde_json::json!({ "cert": cert }))?)?;
            println!("✓ certificate written: {} ({} approvals)", out_path.display(), cert.approvals.len());
            println!("  the chain checks the supermajority against the CURRENT set at propose and at commit.");
            println!("\nsubmit it through ANY live peer (it rides that peer's next proposal inside its window):");
            println!("  printf '{{\"method\":\"hk_submitSetChange\",\"params\":%s}}' \"$(cat {})\" | curl -s -X POST <PEER_RPC> -d @-", out_path.display());
            println!("  then:  curl -s -X POST <PEER_RPC> -d '{{\"method\":\"hk_getValidators\"}}'   # seats + pending_set_changes");
            Ok(())
        }
        _ => eyre::bail!("{usage}"),
    }
}

/// The chain id a node home is on: SHA-256 of its genesis.json, first 4 bytes — exactly
/// what `hk_chainInfo.chain_id` reports.
fn chain_id_of_home(home: &PathBuf) -> eyre::Result<String> {
    use sha2::{Digest, Sha256};
    let gpath = home.join("genesis.json");
    let bytes = std::fs::read(&gpath).map_err(|e| eyre::eyre!("{}: {e}", gpath.display()))?;
    let d = Sha256::digest(&bytes);
    Ok(format!("hashkinetics-1-{}", hex::encode(&d[..4])))
}

/// Coordinator-side: assemble genesis from the collected validator.json blobs
/// (a JSON array). Set HK_PROVER_URL to pin the proof system (public testnets
/// must ALWAYS pin); HK_CHAIN_START_TIME overrides the deterministic clock epoch.
/// Coordinator-side genesis. U4.b (v0.13.0): the fee policy and the allocations are
/// GENESIS facts — pinned in the bytes whose digest is the chain id — so a network
/// launches with fees from block 1 and a funded faucet treasury, no coordinated
/// activation roll, no operator environment to agree on.
///
///   --fee-micro N        envelope fee in micro-units (default 100; 0 = no fee)
///   --fee-from H         first height charged (default 1)
///   --alloc AUTH0:MICRO  fund a self-custodied account at genesis. AUTH0 is the
///                        account's auth commitment at nonce 0 (`hk-node account-info`
///                        prints it as "genesis auth"); the id is DERIVED from it
///                        (squat-proof, exactly like `Tx::AccountCreate`). Repeatable.
///   --demo-accounts [$]  include the five PUBLIC-seed demo accounts (org funded, default
///                        $50) so the showreel/demos run against this network. They are
///                        public by design — never fund them beyond demo money.
fn cmd_genesis_build(validators_path: &str, out_path: &str, rest: &[String]) -> eyre::Result<()> {
    let raw = std::fs::read_to_string(validators_path)?;
    let validators: Vec<GenesisValidator> = serde_json::from_str(&raw)?;
    if validators.is_empty() {
        eyre::bail!("no validators in {validators_path}");
    }
    let start_time = std::env::var("HK_CHAIN_START_TIME")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(CHAIN_START_TIME);

    let (mut fee_micro, mut fee_from) = (100u128, 1u64);
    let mut fee_asset: Option<hk_primitives::H256> = None;
    let mut allocs: Vec<(hk_primitives::H256, hk_primitives::Amount)> = Vec::new();
    // X1: (symbol, decimals, issuer auth0, policy, explicit id) — the issuer is a
    // genesis account named by its nonce-0 auth commitment, like --alloc.
    let mut assets: Vec<(String, u8, hk_primitives::H256, hk_state::assets::AssetPolicy, Option<hk_primitives::H256>)> = Vec::new();
    let mut demo_org_usd: Option<u128> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--fee-micro" => {
                fee_micro = rest.get(i + 1).and_then(|s| s.parse().ok()).ok_or_else(|| eyre::eyre!("--fee-micro N"))?;
                i += 2;
            }
            "--fee-from" => {
                fee_from = rest.get(i + 1).and_then(|s| s.parse().ok()).ok_or_else(|| eyre::eyre!("--fee-from H"))?;
                i += 2;
            }
            "--fee-asset" => {
                let hexs = rest.get(i + 1).ok_or_else(|| eyre::eyre!("--fee-asset HEX"))?;
                fee_asset = Some(account::parse_h256(hexs)?);
                i += 2;
            }
            "--asset" => {
                let spec = rest.get(i + 1).ok_or_else(|| eyre::eyre!("--asset SYMBOL:DECIMALS:ISSUER-AUTH0:FLAGS[:ID-hex]"))?;
                let parts: Vec<&str> = spec.split(':').collect();
                if parts.len() < 4 || parts.len() > 5 {
                    eyre::bail!("--asset wants SYMBOL:DECIMALS:ISSUER-AUTH0:FLAGS[:ID-hex], got '{spec}'");
                }
                if !hk_state::assets::valid_symbol(parts[0]) {
                    eyre::bail!("--asset: bad symbol '{}' (1-16 of [A-Za-z0-9._-], letter first)", parts[0]);
                }
                let decimals: u8 = parts[1].parse().map_err(|_| eyre::eyre!("--asset: bad decimals '{}'", parts[1]))?;
                let issuer_auth = account::parse_h256(parts[2])?;
                let policy = hk_state::assets::AssetPolicy::from_flags(parts[3]).map_err(|e| eyre::eyre!("--asset: {e}"))?;
                let id = match parts.get(4) {
                    Some(h) => Some(account::parse_h256(h)?),
                    None => None,
                };
                assets.push((parts[0].to_string(), decimals, issuer_auth, policy, id));
                i += 2;
            }
            "--alloc" => {
                let spec = rest.get(i + 1).ok_or_else(|| eyre::eyre!("--alloc AUTH0:MICRO"))?;
                let (auth_hex, amt) = spec
                    .split_once(':')
                    .ok_or_else(|| eyre::eyre!("--alloc wants AUTH0-hex:AMOUNT-micro, got '{spec}'"))?;
                let auth = account::parse_h256(auth_hex)?;
                let amount: u128 = amt.parse().map_err(|_| eyre::eyre!("bad amount '{amt}'"))?;
                allocs.push((auth, amount));
                i += 2;
            }
            "--demo-accounts" => {
                let usd = rest.get(i + 1).filter(|s| !s.starts_with("--")).and_then(|s| s.parse::<u128>().ok());
                demo_org_usd = Some(usd.unwrap_or(50));
                i += if usd.is_some() { 2 } else { 1 };
            }
            other => eyre::bail!("unknown flag {other}"),
        }
    }
    if fee_from == 0 {
        eyre::bail!("--fee-from must be ≥ 1 (heights start at 1)");
    }

    let mut chain = hk_state::Genesis { time: start_time, accounts: vec![], alloc: vec![], fee: None, assets: vec![] };
    if let Some(org_usd) = demo_org_usd {
        chain.accounts = demo::genesis_accounts();
        chain.alloc = vec![(demo::account_id("org"), demo::usd(), org_usd * 1_000_000)];
    }
    for (auth0, amount) in &allocs {
        let id = account::derived_id(auth0);
        if chain.accounts.iter().any(|a| a.id == id) {
            eyre::bail!("duplicate allocation for {}", hex::encode(id.0));
        }
        chain.accounts.push(hk_state::GenesisAccount { id, auth_commit: *auth0 });
        chain.alloc.push((id, demo::usd(), *amount));
    }
    chain.fee = Some(hk_state::GenesisFee { micro: fee_micro, from_height: fee_from, asset: fee_asset });
    for (symbol, decimals, issuer_auth, policy, explicit_id) in &assets {
        let issuer = account::derived_id(issuer_auth);
        if !chain.accounts.iter().any(|a| a.id == issuer) {
            // An issuer that holds no allocation still needs an account to sign from.
            chain.accounts.push(hk_state::GenesisAccount { id: issuer, auth_commit: *issuer_auth });
        }
        // No explicit id → the runtime rule, so `hk-node asset-id` agrees with genesis.
        let id = explicit_id.unwrap_or_else(|| hk_state::assets::derive_asset_id(&issuer, symbol));
        if chain.assets.iter().any(|a| a.id == id) {
            eyre::bail!("duplicate genesis asset {}", hex::encode(id.0));
        }
        chain.assets.push(hk_state::GenesisAsset { id, symbol: symbol.clone(), decimals: *decimals, issuer, policy: *policy });
    }
    // The state machine's own genesis validation (symbols, duplicates, fee-asset policy)
    // runs here so a bad file never leaves the coordinator's machine.
    hk_state::State::from_genesis(&chain).map_err(|e| eyre::eyre!("genesis refused by the state machine: {e}"))?;

    let vk_pins = fetch_vk_pins();
    if vk_pins.is_none() {
        eprintln!("WARN: building an UNPINNED genesis — set HK_PROVER_URL; a public testnet must always pin");
    }
    let genesis = HkGenesis { chain_start_time: start_time, validators, chain: Some(chain), vk_pins };
    let bytes = serde_json::to_string_pretty(&genesis)?;
    std::fs::write(out_path, &bytes)?;
    let digest = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes.as_bytes()))
    };
    println!(
        "✓ genesis written to {out_path} — {} validators · chain_start_time {start_time} · vk pins: {}",
        genesis.validators.len(),
        if genesis.vk_pins.is_some() { "YES" } else { "NO (devnet only!)" }
    );
    println!("  fee policy       : {fee_micro} micro per envelope from height {fee_from} (genesis-bound){}",
        match fee_asset { Some(a) => format!(" in asset {}", hex::encode(a.0)), None => String::new() });
    for a in &genesis.chain.as_ref().expect("set above").assets {
        println!("  asset            : {} {} · decimals {} · issuer {} · policy {}", hex::encode(a.id.0), a.symbol, a.decimals, hex::encode(a.issuer.0), a.policy.flags());
    }
    let c = genesis.chain.as_ref().expect("set above");
    for (id, _asset, amount) in &c.alloc {
        println!("  allocation       : {} ← {amount} micro", hex::encode(id.0));
    }
    if demo_org_usd.is_some() {
        println!("  demo accounts    : org/agent-a/agent-b/agent-c/merchant (PUBLIC seeds — demo money only)");
    }
    println!("  genesis digest   : {digest}");
    println!("  chain id         : hashkinetics-1-{}", &digest[..8]);
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

/// H12 (v0.13.2): 32 bytes straight from the operating system's CSPRNG (the same
/// source `account-new` has always used); validator master seeds never come from a
/// userspace generator.
fn os_seed() -> [u8; 32] {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}
