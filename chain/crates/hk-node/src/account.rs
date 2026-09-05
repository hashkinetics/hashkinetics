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

    /// K1 (v0.16.0): the file may be sealed (`HKE1`); `keys::read_secret` opens it with
    /// `HK_WALLET_PASSPHRASE` / `_FILE` / systemd credential / prompt. Plain files never ask.
    pub(crate) fn load(dir: &Path) -> eyre::Result<Self> {
        let p = Self::path(dir);
        if !p.exists() {
            return Err(eyre::eyre!("no account at {} — run account-new first", p.display()));
        }
        let s = crate::keys::read_secret(&p, crate::keys::Secret::Wallet)?;
        Ok(serde_json::from_str(&s)?)
    }

    /// Atomic (tmp → fsync → rename); a sealed file is written back sealed.
    pub(crate) fn save(&self, dir: &Path) -> eyre::Result<()> {
        fs::create_dir_all(dir)?;
        crate::keys::write_secret(&Self::path(dir), &serde_json::to_string_pretty(self)?, crate::keys::Secret::Wallet)
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
    // U4.b: the nonce-0 commitment is what a genesis allocation binds to
    // (`genesis-build --alloc <this>:<micro>`); the id derives from it.
    println!("genesis auth : {}  (nonce 0 — for genesis-build --alloc)", hex::encode(demo::commit_at(&seed, 0).0));
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
    // U4: surface the chain's fee so the site can say "each drip pays N micro in fees".
    let info = demo::rpc(rpc, "hk_chainInfo", json!({}));
    let fee = info.get("result").and_then(|r| r.get("fee")).cloned().unwrap_or(serde_json::Value::Null);
    json!({
        "ok": true,
        "faucet_account": hex::encode(faucet_id.0),
        "faucet_balance_micro": demo::balance(rpc, faucet_id),
        "drip_micro": drip,
        "fee": fee,
    })
}

// ---- X1: issued assets (docs/X1-ISSUED-ASSETS.md) ----------------------------------

/// `asset-id <ISSUER-hex|DIR> <SYMBOL>` — offline: the id the runtime rule assigns.
pub(crate) fn cmd_asset_id(who: &str, symbol: &str) -> eyre::Result<()> {
    let issuer = match parse_h256(who) {
        Ok(h) => h,
        Err(_) => AccountFile::load(Path::new(who))?.id_h256()?,
    };
    if !hk_state::assets::valid_symbol(symbol) {
        return Err(eyre::eyre!("bad symbol '{symbol}' (1-16 of [A-Za-z0-9._-], letter first)"));
    }
    let id = hk_state::assets::derive_asset_id(&issuer, symbol);
    println!("{}", hex::encode(id.0));
    Ok(())
}

/// `asset <verb> …` — the five issuer/holder verbs, signed with the DIR's account
/// through the same reserve-then-sign path as `account-send`, plus two read-only views.
pub(crate) fn cmd_asset(args: &[String]) -> eyre::Result<()> {
    let usage = "usage: hk-node asset register <DIR> <RPC> <SYMBOL> <DECIMALS> <FLAGS m/f/p/s|-> \
                 | mint <DIR> <RPC> <ASSET-hex> <TO-hex> <MICRO> \
                 | burn <DIR> <RPC> <ASSET-hex> <MICRO> [DESTINATION-hex] \
                 | freeze|unfreeze <DIR> <RPC> <ASSET-hex> <ACCOUNT-hex> \
                 | pause|unpause <DIR> <RPC> <ASSET-hex> \
                 | info <RPC> <ASSET-hex | SYMBOL@ISSUER-hex> \
                 | list <RPC>";
    let arg = |i: usize| args.get(i).cloned().ok_or_else(|| eyre::eyre!(usage));
    match args.first().map(String::as_str) {
        Some("register") => {
            let dir = PathBuf::from(arg(1)?);
            let rpc = arg(2)?;
            let symbol = arg(3)?;
            let decimals: u8 = arg(4)?.parse().map_err(|_| eyre::eyre!("bad decimals"))?;
            let policy = hk_state::assets::AssetPolicy::from_flags(&arg(5)?).map_err(|e| eyre::eyre!(e))?;
            if !hk_state::assets::valid_symbol(&symbol) {
                return Err(eyre::eyre!("bad symbol '{symbol}' (1-16 of [A-Za-z0-9._-], letter first)"));
            }
            let issuer = AccountFile::load(&dir)?.id_h256()?;
            let asset = hk_state::assets::derive_asset_id(&issuer, &symbol);
            println!("→ registering {symbol} (decimals {decimals}, policy {}) as {}", policy.flags(), hex::encode(asset.0));
            println!("  issuer {} — the id is bound to this account and this symbol", hex::encode(issuer.0));
            sign_submit(&dir, &rpc, Tx::AssetRegister { asset, symbol, decimals, policy })
        }
        Some("mint") => {
            let dir = PathBuf::from(arg(1)?);
            let rpc = arg(2)?;
            let asset = parse_h256(&arg(3)?)?;
            let to = parse_h256(&arg(4)?)?;
            let amount: Amount = arg(5)?.parse().map_err(|_| eyre::eyre!("bad amount"))?;
            println!("→ minting {amount} of {} to {}", hex::encode(asset.0), hex::encode(to.0));
            sign_submit(&dir, &rpc, Tx::AssetMint { asset, to, amount })
        }
        Some("burn") => {
            let dir = PathBuf::from(arg(1)?);
            let rpc = arg(2)?;
            let asset = parse_h256(&arg(3)?)?;
            let amount: Amount = arg(4)?.parse().map_err(|_| eyre::eyre!("bad amount"))?;
            let destination = match args.get(5) {
                Some(d) => hex::decode(d.trim()).map_err(|e| eyre::eyre!("bad destination hex: {e}"))?,
                None => Vec::new(),
            };
            if destination.len() > hk_state::assets::MAX_BURN_DESTINATION {
                return Err(eyre::eyre!("destination longer than {} bytes", hk_state::assets::MAX_BURN_DESTINATION));
            }
            println!("→ burning {amount} of {} (destination {} bytes)", hex::encode(asset.0), destination.len());
            sign_submit(&dir, &rpc, Tx::AssetBurn { asset, amount, destination })
        }
        Some(v @ ("freeze" | "unfreeze")) => {
            let dir = PathBuf::from(arg(1)?);
            let rpc = arg(2)?;
            let asset = parse_h256(&arg(3)?)?;
            let account = parse_h256(&arg(4)?)?;
            let frozen = v == "freeze";
            println!("→ {v} {} for asset {}", hex::encode(account.0), hex::encode(asset.0));
            sign_submit(&dir, &rpc, Tx::AssetFreeze { asset, account, frozen })
        }
        Some(v @ ("pause" | "unpause")) => {
            let dir = PathBuf::from(arg(1)?);
            let rpc = arg(2)?;
            let asset = parse_h256(&arg(3)?)?;
            let paused = v == "pause";
            println!("→ {v} asset {}", hex::encode(asset.0));
            sign_submit(&dir, &rpc, Tx::AssetPause { asset, paused })
        }
        Some("info") => {
            let rpc = arg(1)?;
            let what = arg(2)?;
            let params = match what.split_once('@') {
                Some((sym, issuer)) => json!({"issuer": issuer, "symbol": sym}),
                None => json!({"asset": what}),
            };
            let v = demo::rpc(&rpc, "hk_getAsset", params);
            println!("{}", serde_json::to_string_pretty(&v)?);
            Ok(())
        }
        Some("list") => {
            let rpc = arg(1)?;
            let v = demo::rpc(&rpc, "hk_getAssets", json!({}));
            println!("{}", serde_json::to_string_pretty(&v)?);
            Ok(())
        }
        _ => Err(eyre::eyre!(usage)),
    }
}
