//! hk-facilitator — RAG-as-a-merchant (0.8).
//!
//! A paid search service metered by PayWord micropayments settled on the
//! HashKinetics chain. This binary runs the whole economic loop end to end against
//! a live devnet node, proving the flagship agentic use case:
//!
//!   1. org delegates a mandate to a searcher agent (on-chain).
//!   2. the searcher opens a PayWord channel to the merchant (on-chain, escrow drawn
//!      through the mandate — the org's budget, the agent's authority).
//!   3. for each query the agent reveals ONE 32-byte preimage ($0.05, 33 bytes on the
//!      wire); the merchant verifies it in one hash and returns real search results.
//!   4. the merchant settles all N queries on-chain with a single transaction.
//!
//! The keyword index (index.rs) is a dependency-free stand-in; agentic/turbovec is the
//! drop-in vector-search upgrade. Networked HTTP facilitator = documented follow-on;
//! this demo runs agent + merchant in one process but every payment and settlement is
//! real on-chain state.
//!
//!   hk-facilitator demo http://127.0.0.1:26000 [docs_dir]

mod index;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use hk_crypto::hash::{shake256_32, DOM_ACCOUNT_ID};
use hk_crypto::lamport;
use hk_crypto::payword::{PaywordChain, PaywordVerifier};
use hk_primitives::{Amount, H256};
use hk_state::tx::{signing_digest, SignedTx, Tx};
use hk_state::State;

use crate::index::Index;

const M: Amount = 1_000_000;
const BIG_EXPIRY: u64 = 10_000_000;
const UNIT_PRICE: Amount = 50_000; // $0.05 / query
const MAX_STEPS: u32 = 20;

fn usd() -> H256 {
    H256([9u8; 32])
}
fn account_id(name: &str) -> H256 {
    H256(shake256_32(DOM_ACCOUNT_ID, &[name.as_bytes()]))
}
fn commit_at(seed: &[u8], nonce: u64) -> H256 {
    let (_, pk) = lamport::keygen(seed, nonce);
    H256(lamport::pk_commit(&pk))
}

fn sign_at(seed: &[u8], id: H256, nonce: u64, payload: Tx) -> SignedTx {
    let (sk, pk) = lamport::keygen(seed, nonce);
    let next_auth = commit_at(seed, nonce + 1);
    let digest = signing_digest(&payload, &id, nonce, &next_auth).expect("digest");
    let sig = lamport::sign(&sk, &digest);
    SignedTx { sender: id, nonce, payload, next_auth, lamport_pk: pk, sig }
}

// ---- blocking JSON-RPC ----

fn rpc(base: &str, method: &str, params: Value) -> Value {
    let hostport = base.trim_start_matches("http://").split('/').next().unwrap_or(base).to_string();
    let body = json!({ "method": method, "params": params }).to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    match TcpStream::connect(&hostport) {
        Ok(mut s) => {
            let _ = s.write_all(req.as_bytes());
            let mut resp = String::new();
            let _ = s.read_to_string(&mut resp);
            let payload = resp.splitn(2, "\r\n\r\n").nth(1).unwrap_or("");
            serde_json::from_str(payload).unwrap_or_else(|_| json!({"error":"unparseable"}))
        }
        Err(e) => json!({ "error": format!("connect {hostport}: {e}") }),
    }
}

fn get_nonce(base: &str, id: &H256) -> u64 {
    rpc(base, "hk_getAccount", json!({ "id": hex::encode(id.0) }))
        .get("result")
        .and_then(|r| if r.get("found")?.as_bool()? { r.get("nonce")?.as_u64() } else { None })
        .unwrap_or(0)
}
fn balance(base: &str, id: &H256) -> Amount {
    rpc(base, "hk_balance", json!({ "id": hex::encode(id.0), "asset": hex::encode(usd().0) }))
        .get("result")
        .and_then(|r| r.get("amount")?.as_str()?.parse().ok())
        .unwrap_or(0)
}
fn chain_height(base: &str) -> u64 {
    rpc(base, "hk_chainInfo", json!({}))
        .get("result")
        .and_then(|r| r.get("height")?.as_u64())
        .unwrap_or(0)
}
fn submit(base: &str, tx: &SignedTx) -> String {
    rpc(base, "hk_submitTx", json!({ "tx": serde_json::to_value(tx).unwrap() }))
        .get("result")
        .and_then(|r| r.get("txid")?.as_str().map(str::to_string))
        .unwrap_or_else(|| "submit-failed".into())
}
fn receipt(base: &str, txid: &str) -> Option<String> {
    let v = rpc(base, "hk_getReceipt", json!({ "txid": txid }));
    let r = v.get("result")?;
    if r.get("found")?.as_bool()? { r.get("detail")?.as_str().map(str::to_string) } else { None }
}

fn wait<F: FnMut() -> bool>(label: &str, mut f: F) -> bool {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        sleep(Duration::from_millis(400));
    }
    println!("   ⚠ timed out waiting for: {label}");
    false
}

/// Send a tx from `seed`/`id` at its current on-chain nonce; wait for the ratchet.
fn send_wait(base: &str, seed: &[u8], id: &H256, payload: Tx, label: &str) -> bool {
    let n = get_nonce(base, id);
    let txid = submit(base, &sign_at(seed, *id, n, payload));
    if wait(label, || get_nonce(base, id) == n + 1) {
        true
    } else {
        if let Some(r) = receipt(base, &txid) {
            println!("   rejected: {r}");
        }
        false
    }
}

fn dollars(a: Amount) -> String {
    let cents = (a % M) / 10_000;
    format!("${}.{:02}", a / M, cents)
}

fn main() -> eyre::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("demo") => {
            let base = args.get(2).cloned().unwrap_or_else(|| "http://127.0.0.1:26000".into());
            let docs = PathBuf::from(args.get(3).cloned().unwrap_or_else(|| "..".into()));
            run_demo(&base, &docs)
        }
        _ => {
            eprintln!("hk-facilitator — RAG-as-a-merchant (0.8)");
            eprintln!("usage: hk-facilitator demo <RPC_URL> [docs_dir]");
            Ok(())
        }
    }
}

fn run_demo(base: &str, docs: &PathBuf) -> eyre::Result<()> {
    println!("\n=== HashKinetics paid search — RAG-as-a-merchant, live on {base} ===");
    println!("Indexing corpus at {} ...", docs.display());
    let idx = Index::build(docs);
    println!("  indexed {} documents.\n", idx.doc_count());
    if idx.doc_count() == 0 {
        eyre::bail!("no .md documents found under {} — pass a docs_dir", docs.display());
    }
    if !wait("node live", || chain_height(base) >= 1) {
        eyre::bail!("node not reachable at {base}");
    }

    let org = account_id("org");
    let searcher = account_id("agent-a");
    let merchant = account_id("merchant");
    let msearch = H256([0xD0; 32]);
    let usd = usd();

    // 1) org delegates a $1 search budget to the searcher agent.
    println!("[1] org delegates a $1 search mandate to the searcher agent...");
    if !send_wait(base, b"org", &org, Tx::MandateCreate {
        id: msearch,
        parent: None,
        holder: searcher,
        asset: usd,
        rate_per_sec: 0,
        buffer_max: M,
        per_tx_max: M,
        initial_buffer: M,
        expiry: BIG_EXPIRY,
        tier: 1,
    }, "search mandate created") {
        eyre::bail!("mandate creation failed (already exists? use a -Fresh devnet)");
    }
    println!("    ✓ mandate live.\n");

    // 2) searcher opens a PayWord channel to the merchant ($1 escrow = 20 queries).
    println!("[2] searcher opens a PayWord channel to the merchant ($0.05/query)...");
    let pw = PaywordChain::mint(b"search-demo-seed", b"search-session", MAX_STEPS);
    let tip = H256(pw.tip());
    let s_nonce = get_nonce(base, &searcher);
    let ch_id = State::derive_channel_id(&searcher, &merchant, &tip, s_nonce);
    let merchant_before = balance(base, &merchant);
    let txid = submit(base, &sign_at(b"agent-a", searcher, s_nonce, Tx::ChannelOpen {
        id: ch_id,
        mandate: msearch,
        payee: merchant,
        asset: usd,
        tip,
        unit_price: UNIT_PRICE,
        max_steps: MAX_STEPS,
        expiry: BIG_EXPIRY,
    }));
    if !wait("channel funded", || get_nonce(base, &searcher) == s_nonce + 1) {
        if let Some(r) = receipt(base, &txid) {
            println!("   rejected: {r}");
        }
        eyre::bail!("channel open failed");
    }
    println!("    ✓ channel open, $1 escrowed under the mandate.\n");

    // 3) paid queries — one preimage per query, verified in one hash by the merchant.
    let queries = [
        "mandate spend cap hierarchy",
        "payword channel micropayment",
        "post quantum hash based signature",
        "shielded pool one-time disclosure",
        "malachite consensus validator",
    ];
    println!("[3] the agent runs {} paid searches (merchant verifies each preimage):", queries.len());
    let mut verifier = PaywordVerifier::new(pw.tip(), MAX_STEPS);
    for (i, q) in queries.iter().enumerate() {
        let step = (i + 1) as u32;
        let word = pw.pay(step).expect("preimage");
        // Merchant side: verify the payment before serving.
        match verifier.accept(step, word) {
            Ok(_) => {
                let hits = idx.search(q, 1);
                let top = hits
                    .first()
                    .map(|h| {
                        let short = shorten(&h.path);
                        format!("{short}  —  \"{}\"", truncate(&h.snippet, 90))
                    })
                    .unwrap_or_else(|| "(no match)".into());
                println!("    ${:.2}  q{}: {:<34} → {}", UNIT_PRICE as f64 / M as f64, step, q, top);
            }
            Err(_) => {
                println!("    ⛔ q{step}: payment rejected — no service");
            }
        }
    }
    println!();

    // 4) merchant settles all queries in ONE on-chain transaction.
    println!("[4] merchant settles {} queries with ONE 32-byte preimage on-chain...", queries.len());
    let (last_word, last_step) = verifier.settlement_claim();
    if send_wait(base, b"merchant", &merchant, Tx::ChannelSettle {
        id: ch_id,
        word: H256(last_word),
        step: last_step,
    }, "settlement") {
        let earned = balance(base, &merchant).saturating_sub(merchant_before);
        println!("    ✓ merchant earned {} for {} searches (settled in one tx).", dollars(earned), last_step);
    }

    println!("\n=== that's RAG-as-a-merchant ===");
    println!("An agent paid, per query, for real retrieval — 33 bytes and one hash per payment,");
    println!("its budget enforced by the same consensus-level mandate tree. Swap the keyword");
    println!("index for agentic/turbovec and this is a production paid-inference endpoint.\n");
    Ok(())
}

fn shorten(path: &str) -> String {
    let p = path.replace('\\', "/");
    p.rsplit('/').take(2).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("/")
}
fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n).collect();
        out.push('…');
        out
    }
}
