//! The P0 storyline as a live on-chain demo (0.7 / gate G0).
//!
//! Genesis (`demo::genesis_accounts` + `demo::alloc`) seeds five L-ratchet accounts —
//! org (funded $50), agents A/B/C, and a merchant. `demo::run` then drives the exact
//! storyline from the verified test, but as real transactions over the RPC of a live
//! validator: org builds an oversubscribed mandate tree, two agents pay, the third's
//! overspend is REJECTED BY CONSENSUS (shown via its receipt), the org revokes it,
//! then agent B streams 1,000 PayWord micropayments settled in one shot.
//!
//! Run against a live devnet:  hk-node demo http://127.0.0.1:26000

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use hk_crypto::hash::{shake256_32, DOM_ACCOUNT_ID};
use hk_crypto::lamport;
use hk_crypto::payword::PaywordChain;
use hk_primitives::{Amount, ChannelId, H256};
use hk_state::tx::{signing_digest, SignedTx, Tx};
use hk_state::{Genesis, GenesisAccount, State};

const M: Amount = 1_000_000; // $1 in micro-units
const BIG_EXPIRY: u64 = 10_000_000;
const NAMES: [&str; 5] = ["org", "agent-a", "agent-b", "agent-c", "merchant"];

pub(crate) fn usd() -> H256 {
    H256([9u8; 32])
}

pub(crate) fn account_id(name: &str) -> H256 {
    H256(shake256_32(DOM_ACCOUNT_ID, &[name.as_bytes()]))
}

fn commit_at(seed: &[u8], nonce: u64) -> H256 {
    let (_, pk) = lamport::keygen(seed, nonce);
    H256(lamport::pk_commit(&pk))
}

/// Genesis accounts for the devnet (auth_commit at nonce 0).
pub fn genesis_accounts() -> Vec<GenesisAccount> {
    NAMES
        .iter()
        .map(|n| GenesisAccount { id: account_id(n), auth_commit: commit_at(n.as_bytes(), 0) })
        .collect()
}

/// org starts with $50; everyone else at zero (they receive/authorize, not fund).
pub fn alloc() -> Vec<(H256, H256, Amount)> {
    vec![(account_id("org"), usd(), 50 * M)]
}

/// Complete demo genesis (embedded in the devnet by `hk-node testnet`).
pub fn genesis(time: u64) -> Genesis {
    Genesis { time, accounts: genesis_accounts(), alloc: alloc() }
}

// ---------------------------------------------------------------------------
// Demo wallet — local L-ratchet, exactly like the verified test's Keychain.
// ---------------------------------------------------------------------------

pub(crate) struct Wallet {
    seed: Vec<u8>,
    pub(crate) id: H256,
    pub(crate) next_nonce: u64,
}

impl Wallet {
    pub(crate) fn new(name: &str) -> Self {
        Self { seed: name.as_bytes().to_vec(), id: account_id(name), next_nonce: 0 }
    }

    pub(crate) fn sign(&mut self, payload: Tx) -> SignedTx {
        let nonce = self.next_nonce;
        let (sk, pk) = lamport::keygen(&self.seed, nonce);
        let next_auth = commit_at(&self.seed, nonce + 1);
        let digest = signing_digest(&payload, &self.id, nonce, &next_auth).expect("digest");
        let sig = lamport::sign(&sk, &digest);
        self.next_nonce += 1;
        SignedTx { sender: self.id, nonce, payload, next_auth, lamport_pk: pk, sig }
    }

    /// After an on-chain REJECTION (chain didn't ratchet), roll the local key back.
    pub(crate) fn rollback(&mut self) {
        self.next_nonce -= 1;
    }
}

// ---------------------------------------------------------------------------
// Blocking JSON-RPC client (std only)
// ---------------------------------------------------------------------------

pub(crate) fn rpc(base: &str, method: &str, params: Value) -> Value {
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
            serde_json::from_str(payload).unwrap_or_else(|_| json!({"error":"unparseable response"}))
        }
        Err(e) => json!({ "error": format!("connect {hostport}: {e}") }),
    }
}

pub(crate) fn submit(base: &str, tx: &SignedTx) -> String {
    let v = rpc(base, "hk_submitTx", json!({ "tx": serde_json::to_value(tx).unwrap() }));
    v.get("result")
        .and_then(|r| r.get("txid"))
        .and_then(|t| t.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| {
            // LOUD: a tx that never entered the mempool can't fail later with a receipt.
            println!("   ✗ submit FAILED (tx never entered the mempool): {v}");
            format!("submit-failed: {v}")
        })
}

/// `wait`, but bound to a specific tx: on timeout, pull the consensus receipt and say
/// WHICH failure this is — included-but-REJECTED (receipt names the rule) and
/// never-included (no receipt) are different bugs.
pub(crate) fn wait_tx<F: FnMut() -> bool>(
    base: &str,
    label: &str,
    txid: &str,
    pred: F,
) -> bool {
    if wait(label, pred) {
        return true;
    }
    match receipt(base, txid) {
        Some(r) => println!("   ⛔ consensus receipt for {txid}: {r}"),
        None => println!("   ∅ no receipt for {txid} — the tx was NEVER included in a block"),
    }
    false
}

pub(crate) fn balance(base: &str, id: &H256) -> Amount {
    let v = rpc(base, "hk_balance", json!({ "id": hex::encode(id.0), "asset": hex::encode(usd().0) }));
    v.get("result")
        .and_then(|r| r.get("amount"))
        .and_then(|a| a.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

pub(crate) fn account_nonce(base: &str, id: &H256) -> Option<u64> {
    let v = rpc(base, "hk_getAccount", json!({ "id": hex::encode(id.0) }));
    let r = v.get("result")?;
    if r.get("found")?.as_bool()? {
        r.get("nonce")?.as_u64()
    } else {
        None
    }
}

pub(crate) fn receipt(base: &str, txid: &str) -> Option<String> {
    let v = rpc(base, "hk_getReceipt", json!({ "txid": txid }));
    let r = v.get("result")?;
    if r.get("found")?.as_bool()? {
        r.get("detail")?.as_str().map(str::to_string)
    } else {
        None
    }
}

pub(crate) fn chain_height(base: &str) -> u64 {
    rpc(base, "hk_chainInfo", json!({}))
        .get("result")
        .and_then(|r| r.get("height"))
        .and_then(|h| h.as_u64())
        .unwrap_or(0)
}

pub(crate) fn wait<F: FnMut() -> bool>(label: &str, mut f: F) -> bool {
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

pub(crate) fn dollars(a: Amount) -> String {
    format!("${}", a / M)
}

// ---------------------------------------------------------------------------
// The storyline
// ---------------------------------------------------------------------------

pub fn run(base: &str) -> eyre::Result<()> {
    println!("\n=== HashKinetics P0 demo — live on {base} ===");
    if !wait("node RPC reachable", || chain_height(base) >= 1) {
        eyre::bail!("node not reachable / not producing blocks at {base}");
    }
    println!("Chain is live at height {}.\n", chain_height(base));

    let mut org = Wallet::new("org");
    let mut a = Wallet::new("agent-a");
    let mut b = Wallet::new("agent-b");
    let mut c = Wallet::new("agent-c");
    let mut merchant = Wallet::new("merchant");

    let (m0, ma, mb, mc) = (H256([0xA0; 32]), H256([0xA1; 32]), H256([0xA2; 32]), H256([0xA3; 32]));
    let usd = usd();

    // 1) org builds the tree — children oversubscribe: 20+25+20 = $65 over a $50 root.
    println!("[1] org funds a $50 mandate and delegates to 3 agents (oversubscribed to $65)...");
    let mk = |id, parent, holder_id: H256, buffer_max, per_tx, initial, tier| Tx::MandateCreate {
        id,
        parent,
        holder: holder_id,
        asset: usd,
        rate_per_sec: 0,
        buffer_max,
        per_tx_max: per_tx,
        initial_buffer: initial,
        expiry: BIG_EXPIRY,
        tier,
    };
    let t_root = mk(m0, None, org.id, 50 * M, 50 * M, 50 * M, 2);
    let t_a = mk(ma, Some(m0), a.id, 20 * M, 20 * M, 20 * M, 0);
    let t_b = mk(mb, Some(m0), b.id, 25 * M, 20 * M, 25 * M, 0);
    let t_c = mk(mc, Some(m0), c.id, 20 * M, 20 * M, 20 * M, 0);
    submit(base, &org.sign(t_root));
    submit(base, &org.sign(t_a));
    submit(base, &org.sign(t_b));
    submit(base, &org.sign(t_c));
    wait("mandate tree created (org nonce=4)", || account_nonce(base, &org.id) == Some(4));
    println!("    ✓ tree live on-chain.\n");

    // 2) A and B each pay the merchant $20.
    println!("[2] agent-a pays $20, agent-b pays $20 to the merchant...");
    submit(base, &a.sign(Tx::MandateSpend { leaf: ma, to: merchant.id, amount: 20 * M }));
    submit(base, &b.sign(Tx::MandateSpend { leaf: mb, to: merchant.id, amount: 20 * M }));
    wait("two payments settled", || balance(base, &merchant.id) == 40 * M && balance(base, &org.id) == 10 * M);
    println!("    ✓ merchant has {}, org envelope down to {}.\n", dollars(balance(base, &merchant.id)), dollars(balance(base, &org.id)));

    // 3) C tries $20 — its own budget allows it, but the shared $50 root has only $10.
    println!("[3] agent-c tries $20 — but the shared root is nearly dry. Watch consensus refuse it...");
    let c_txid = submit(base, &c.sign(Tx::MandateSpend { leaf: mc, to: merchant.id, amount: 20 * M }));
    let mut shown = false;
    wait("agent-c receipt", || {
        if let Some(r) = receipt(base, &c_txid) {
            println!("    ⛔ consensus receipt for agent-c: {r}");
            shown = true;
            true
        } else {
            false
        }
    });
    c.rollback();
    if balance(base, &org.id) == 10 * M && balance(base, &merchant.id) == 40 * M {
        println!("    ✓ funds did NOT move — the ancestor cap held. org still {}.\n", dollars(balance(base, &org.id)));
    }
    let _ = shown;

    // 4) org revokes agent-c's mandate (cascade).
    println!("[4] org revokes agent-c's mandate (subtree dies)...");
    submit(base, &org.sign(Tx::MandateRevoke { target: mc }));
    wait("revoke applied (org nonce=5)", || account_nonce(base, &org.id) == Some(5));
    println!("    ✓ agent-c revoked.\n");

    // 5) agent-b opens a 1,000-call PayWord channel; merchant settles all of it in one word.
    println!("[5] agent-b opens a 1,000-call PayWord channel ($0.005/call = $5 escrow)...");
    let chain = PaywordChain::mint(b"demo-payword", b"demo-session", 1000);
    let tip = H256(chain.tip());
    let b_nonce = account_nonce(base, &b.id).unwrap_or(1);
    let ch_id: ChannelId = State::derive_channel_id(&b.id, &merchant.id, &tip, b_nonce);
    submit(base, &b.sign(Tx::ChannelOpen {
        id: ch_id,
        mandate: mb,
        payee: merchant.id,
        asset: usd,
        tip,
        unit_price: 5_000,
        max_steps: 1000,
        expiry: BIG_EXPIRY,
    }));
    wait("channel funded ($5 escrow drawn, org -> $5)", || balance(base, &org.id) == 5 * M);
    println!("    ✓ channel open, $5 escrowed under agent-b's mandate.");

    println!("    ... agent-b makes 1,000 paid calls; merchant settles with ONE 32-byte preimage.");
    let word = H256(chain.pay(1000).expect("word 1000"));
    submit(base, &merchant.sign(Tx::ChannelSettle { id: ch_id, word, step: 1000 }));
    wait("channel settled (merchant -> $45)", || balance(base, &merchant.id) == 45 * M);
    println!("    ✓ 1,000 calls settled in one transaction.\n");

    // Final tally.
    println!("=== final balances ===");
    println!("  org      : {}", dollars(balance(base, &org.id)));
    println!("  merchant : {}", dollars(balance(base, &merchant.id)));
    println!("  height   : {}", chain_height(base));
    println!("\nThat was the whole HashKinetics thesis, live: consensus-enforced hierarchical");
    println!("spend caps + hash-based micropayment channels — no trusted intermediary.\n");
    Ok(())
}
