//! U1/U2 — self-custodied runtime accounts, CLI-side.
//!
//! The counterpart of `Tx::AccountCreate`: anyone generates a keychain locally
//! (`account-new`), hands the FAUCET (or any sponsor) their auth commitment, and is
//! on-chain seconds later — no genesis ceremony, no permission. The account file is
//! a local JSON `{ seed, id, next_nonce }`; the L-ratchet discipline is the same
//! reserve-then-sign the consensus signer uses: the nonce is PERSISTED BEFORE the
//! transaction is submitted, and rolled back (and persisted again) only on a
//! definitive on-chain refusal — a crash can never re-sign a spent index.

use std::fs;
use std::path::{Path, PathBuf};

use hk_crypto::hash::{shake256_32, DOM_ACCOUNT_ID};
use hk_primitives::{Amount, H256};
use hk_state::tx::Tx;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::demo::{self, Wallet};

/// The derived, squat-proof account id: `H(DOM_ACCOUNT_ID ‖ auth_commit)`.
pub(crate) fn derived_id(auth_commit: &H256) -> H256 {
    H256(shake256_32(DOM_ACCOUNT_ID, &[&auth_commit.0]))
}

pub(crate) fn parse_h256(s: &str) -> eyre::Result<H256> {
    let raw = hex::decode(s.trim()).map_err(|e| eyre::eyre!("bad hex: {e}"))?;
    let arr: [u8; 32] =
        raw.try_into().map_err(|_| eyre::eyre!("expected 32 bytes (64 hex chars)"))?;
    Ok(H256(arr))
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AccountFile {
    /// 32 bytes of OS entropy, hex. The whole keychain derives from this — guard it.
    pub seed: String,
    /// The derived account id (H(auth_commit at nonce 0)), hex.
    pub id: String,
    /// Next L-ratchet index to sign with. Persisted BEFORE every submit.
    pub next_nonce: u64,
}

impl AccountFile {
    fn path(dir: &Path) -> PathBuf {
        dir.join("account.json")
    }

    pub(crate) fn load(dir: &Path) -> eyre::Result<Self> {
        let p = Self::path(dir);
        let s = fs::read_to_string(&p)
            .map_err(|e| eyre::eyre!("no account at {} ({e}) — run account-new first", p.display()))?;
        Ok(serde_json::from_str(&s)?)
    }

    pub(crate) fn save(&self, dir: &Path) -> eyre::Result<()> {
        fs::create_dir_all(dir)?;
        let tmp = dir.join("account.json.tmp");
        fs::write(&tmp, serde_json::to_string_pretty(self)?)?;
        fs::rename(&tmp, Self::path(dir))?;
        Ok(())
    }

    pub(crate) fn seed_bytes(&self) -> eyre::Result<Vec<u8>> {
        Ok(hex::decode(&self.seed)?)
    }

    pub(crate) fn id_h256(&self) -> eyre::Result<H256> {
        parse_h256(&self.id)
    }
}

/// `account-new <DIR>` — generate a keychain, derive the id, print the onboarding kit.
pub(crate) fn cmd_new(dir: &Path) -> eyre::Result<()> {
    if AccountFile::path(dir).exists() {
        return Err(eyre::eyre!(
            "{} already holds an account — refusing to overwrite key material",
            dir.display()
        ));
    }
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let auth0 = demo::commit_at(&seed, 0);
    let id = derived_id(&auth0);
    let file = AccountFile { seed: hex::encode(seed), id: hex::encode(id.0), next_nonce: 0 };
    file.save(dir)?;
    println!("✓ new account keychain written to {}", dir.display());
    println!();
    println!("  account id   : {}", hex::encode(id.0));
    println!("  auth commit  : {}", hex::encode(auth0.0));
    println!();
    println!("  Next step: paste the AUTH COMMIT into the faucet");
    println!("  (https://www.hashkinetics.org/faucet) — it creates and funds this");
    println!("  account on-chain. Then: hk-node account-balance <RPC> {}", dir.display());
    println!();
    println!("  ⚠ {}/account.json holds your seed. It IS the account. Back it up;", dir.display());
    println!("    never share it; the faucet only ever needs the auth commit.");
    Ok(())
}

/// `account-info <DIR>` — id + current auth commitment (for faucet re-requests).
pub(crate) fn cmd_info(dir: &Path) -> eyre::Result<()> {
    let f = AccountFile::load(dir)?;
    let seed = f.seed_bytes()?;
    println!("account id   : {}", f.id);
    println!("next nonce   : {}", f.next_nonce);
    println!("auth commit  : {}", hex::encode(demo::commit_at(&seed, f.next_nonce).0));
    Ok(())
}

/// `account-balance <RPC> <ID-hex | DIR>` — transparent balance (default asset).
pub(crate) fn cmd_balance(rpc: &str, who: &str) -> eyre::Result<()> {
    let id = match parse_h256(who) {
        Ok(h) => h,
        Err(_) => AccountFile::load(Path::new(who))?.id_h256()?,
    };
    let bal = demo::balance(rpc, &id);
    println!("{} : {} micro (${}.{:06})", hex::encode(id.0), bal, bal / 1_000_000, bal % 1_000_000);
    Ok(())
}

/// Sign + submit one payload from the DIR's account with reserve-then-sign nonce
/// persistence, then poll the consensus receipt. Shared by send/create.
fn sign_submit(dir: &Path, rpc: &str, payload: Tx) -> eyre::Result<()> {
    let mut f = AccountFile::load(dir)?;
    let seed = f.seed_bytes()?;
    let id = f.id_h256()?;

    // Sync with the chain: if the chain's nonce is ahead/behind our file (e.g. a
    // restored backup), trust the CHAIN — signing at a spent index is refused anyway,
    // and signing below it leaks OTS chunks for nothing.
    if let Some(chain_nonce) = demo::account_nonce(rpc, &id) {
        if chain_nonce != f.next_nonce {
            println!(
                "  (nonce sync: file said {}, chain says {} — following the chain)",
                f.next_nonce, chain_nonce
            );
            f.next_nonce = chain_nonce;
        }
    } else {
        return Err(eyre::eyre!(
            "account {} does not exist on-chain yet — fund it via the faucet first",
            f.id
        ));
    }

    let mut w = Wallet::from_seed(seed, id, f.next_nonce);
    let tx = w.sign(payload);
    // RESERVE-THEN-SIGN: persist the advanced nonce BEFORE the network sees the tx.
    f.next_nonce = w.next_nonce;
    f.save(dir)?;

    let txid = demo::submit(rpc, &tx);
    if txid.starts_with("submit-failed") {
        // Never entered the mempool — the chain didn't ratchet. Roll back.
        f.next_nonce -= 1;
        f.save(dir)?;
        return Err(eyre::eyre!("submit failed (nonce rolled back): {txid}"));
    }
    println!("  txid {txid}");
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(700));
        if let Some(r) = demo::receipt(rpc, &txid) {
            println!("  receipt: {r}");
            if r.starts_with("rejected") {
                f.next_nonce -= 1;
                f.save(dir)?;
                return Err(eyre::eyre!("chain refused the tx (nonce rolled back)"));
            }
            return Ok(());
        }
    }
    println!("  (no receipt after ~20s — check the explorer; nonce stays advanced)");
    Ok(())
}

/// `account-send <DIR> <RPC> <TO-hex> <AMOUNT-micro> [ASSET-hex]`
pub(crate) fn cmd_send(
    dir: &Path,
    rpc: &str,
    to: &str,
    amount: Amount,
    asset: Option<&str>,
) -> eyre::Result<()> {
    let to = parse_h256(to)?;
    let asset = match asset {
        Some(a) => parse_h256(a)?,
        None => demo::usd(),
    };
    println!("→ sending {amount} micro to {}", hex::encode(to.0));
    sign_submit(dir, rpc, Tx::Transfer { to, asset, amount })
}

/// `account-create <DIR> <RPC> <AUTH-COMMIT-hex> <AMOUNT-micro> [ASSET-hex]` — sponsor
/// a NEW account from the DIR's funds (this is the faucet's inner move, usable by hand).
pub(crate) fn cmd_create(
    dir: &Path,
    rpc: &str,
    auth_commit: &str,
    amount: Amount,
    asset: Option<&str>,
) -> eyre::Result<()> {
    let auth_commit = parse_h256(auth_commit)?;
    let id = derived_id(&auth_commit);
    let asset = match asset {
        Some(a) => parse_h256(a)?,
        None => demo::usd(),
    };
    println!("→ creating account {} (funded {amount} micro)", hex::encode(id.0));
    sign_submit(dir, rpc, Tx::AccountCreate { id, auth_commit, asset, amount })?;
    println!("  the new account can spend immediately: its ratchet starts at nonce 0");
    Ok(())
}

/// Bootstrap helper for STAGING only: adopt a demo/genesis NAMED account (whose seed
/// is the name itself — public in this repo) into an account file, so it can fund a
/// real faucet treasury. `account-adopt-demo <DIR> <NAME>`.
pub(crate) fn cmd_adopt_demo(dir: &Path, name: &str, rpc: &str) -> eyre::Result<()> {
    if AccountFile::path(dir).exists() {
        return Err(eyre::eyre!("{} already holds an account", dir.display()));
    }
    let id = demo::account_id(name);
    let nonce = demo::account_nonce(rpc, &id)
        .ok_or_else(|| eyre::eyre!("account '{name}' not on this chain"))?;
    let file = AccountFile {
        seed: hex::encode(name.as_bytes()),
        id: hex::encode(id.0),
        next_nonce: nonce,
    };
    file.save(dir)?;
    println!("✓ adopted demo account '{name}' ({}) at nonce {nonce}", hex::encode(id.0));
    println!("  ⚠ demo seeds are PUBLIC — move funds to a fresh account immediately.");
    Ok(())
}

pub(crate) fn health_json(rpc: &str, faucet_id: &H256, drip: Amount) -> serde_json::Value {
    json!({
        "ok": true,
        "faucet_account": hex::encode(faucet_id.0),
        "faucet_balance_micro": demo::balance(rpc, faucet_id),
        "drip_micro": drip,
    })
}
