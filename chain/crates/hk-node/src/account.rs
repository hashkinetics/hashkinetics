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

/// HR-9 (v0.19.12): the recipient pre-flight every CLI credit runs before it builds the tx.
/// The chain credits ANY 32-byte id — `Transfer`, `AssetMint`, `MandateSpend`, the unshield
/// leg and a channel's payee never check that an account exists — so a credit to an id with
/// no account lands as a balance nobody can spend until an `AccountCreate` carrying the auth
/// commitment the id derives from binds it; a mistyped or random id never gets one. The
/// decision is pure, over `hk_getAccount`'s answer as `demo::rpc` returns it (`rpc` only names
/// the node in the message), and three-way: `found: true` passes; `found: false` is refused
/// unless `allow_new` — the `--allow-new-recipient` flag for the one legitimate case,
/// pre-funding an id whose auth commitment the sender holds; anything else — an `error`
/// (`demo::rpc` folds a transport failure, a timeout and an HTTP error body into one), no
/// `result`, no boolean `found` — means the lookup failed, which is not "no account": it is
/// refused whatever the flag says, and the message does not offer the flag.
pub(crate) fn recipient_preflight(rpc: &str, answer: &serde_json::Value, allow_new: bool) -> Result<(), String> {
    let found = match answer.get("error") {
        Some(_) => None,
        None => answer.get("result").and_then(|r| r.get("found")).and_then(|f| f.as_bool()),
    };
    match found {
        Some(true) => Ok(()),
        Some(false) if allow_new => Ok(()),
        Some(false) => Err("no account exists at this id — the recipient must create their account first \
                            (or pass --allow-new-recipient if you hold the auth_commit its id derives from)"
            .to_string()),
        None => {
            let reason = match answer.get("error") {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(e) => e.to_string(),
                None => format!(
                    "no boolean `found` in the answer {}",
                    answer.to_string().chars().take(200).collect::<String>()
                ),
            };
            Err(format!("could not check the recipient at {rpc}: {reason} — nothing was signed"))
        }
    }
}

/// HR-9 (v0.19.12): the pre-flight over a live node — one `hk_getAccount` for `to`, then the
/// pure decision above. Shared by `account-send`, `asset mint` and `wallet transfer`, each of
/// which runs it before anything is signed.
pub(crate) fn check_recipient(rpc: &str, to: &H256, allow_new: bool) -> eyre::Result<()> {
    let answer = demo::rpc(rpc, "hk_getAccount", json!({ "id": hex::encode(to.0) }));
    recipient_preflight(rpc, &answer, allow_new).map_err(|e| eyre::eyre!("{e}"))
}

/// HR-9 (v0.19.12): `--allow-new-recipient` anywhere in the argument list, removed so the
/// positional parsing around it is untouched (the `--asset` pattern of `wallet`).
pub(crate) fn take_allow_new_recipient(args: &[String]) -> (bool, Vec<String>) {
    let mut allow = false;
    let rest = args
        .iter()
        .filter(|a| {
            if a.as_str() == "--allow-new-recipient" {
                allow = true;
                false
            } else {
                true
            }
        })
        .cloned()
        .collect();
    (allow, rest)
}

/// `account-send <DIR> <RPC> <TO-hex> <AMOUNT-micro> [ASSET-hex] [--allow-new-recipient]`
pub(crate) fn cmd_send(
    dir: &Path,
    rpc: &str,
    to: &str,
    amount: Amount,
    asset: Option<&str>,
    allow_new_recipient: bool,
) -> eyre::Result<()> {
    let to = parse_h256(to)?;
    let asset = match asset {
        Some(a) => parse_h256(a)?,
        None => demo::usd(),
    };
    check_recipient(rpc, &to, allow_new_recipient)?;
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

/// HR-4 (v0.19.12): `hk_getAssets` answers at most 1,000 entries per call with `next`, the
/// following page's `from` (`null` on the last page; absent from a node older than v0.19.12,
/// which answers the whole registry at once). `asset list` follows `next` for at most this
/// many pages, and refuses a registry that does not end within them rather than print part of it.
const ASSET_LIST_MAX_PAGES: usize = 100;
/// A node runs one registry scan at a time and answers the rest "busy — retry": such a page is
/// asked for again, up to this many tries in all, before the answer is reported …
const ASSET_LIST_BUSY_TRIES: usize = 3;
/// … with this pause between two tries.
const ASSET_LIST_BUSY_PAUSE: std::time::Duration = std::time::Duration::from_millis(300);

/// Whether an RPC answer is a "busy — retry" refusal: the node's one registry-scan slot is
/// taken (`busy: an asset registry scan is already in flight …`, HTTP 400) or its connection
/// table is full (`rpc busy — try again`, HTTP 503). `demo::rpc` hands both bodies back.
fn answer_is_busy(answer: &serde_json::Value) -> bool {
    answer
        .get("error")
        .and_then(|e| e.as_str())
        .is_some_and(|s| s.starts_with("busy") || s.starts_with("rpc busy"))
}

/// HR-4 (v0.19.12): the whole registry from `hk_getAssets`' pages, as one answer. `fetch(from)`
/// is one call (the RPC in `asset list`, canned pages in the tests). A page answered "busy" is
/// asked for again (up to `ASSET_LIST_BUSY_TRIES` tries, `pause` apart) before the answer is
/// reported; any other answer without a `result` is reported at once; `next` is followed until
/// it is null or absent and must move forward; a registry that does not end within
/// `ASSET_LIST_MAX_PAGES` pages is refused. The answer is the last page's, with `assets[]`
/// holding every page's entries (an id already read is skipped: an asset registered between two
/// pages shifts the later indices by one), `from` 0 and `next` null — for a registry that fits
/// one page, exactly what the node answered.
pub(crate) fn read_asset_pages(
    mut fetch: impl FnMut(u64) -> serde_json::Value,
    pause: std::time::Duration,
) -> Result<serde_json::Value, String> {
    let mut assets: Vec<serde_json::Value> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut from: u64 = 0;
    for _ in 0..ASSET_LIST_MAX_PAGES {
        let mut answer = fetch(from);
        let mut tries = 1;
        while answer_is_busy(&answer) && tries < ASSET_LIST_BUSY_TRIES {
            std::thread::sleep(pause);
            answer = fetch(from);
            tries += 1;
        }
        let Some(page) = answer.get("result").and_then(|r| r.as_object()) else {
            let reason = match answer.get("error") {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(e) => e.to_string(),
                None => format!("no result in {}", answer.to_string().chars().take(200).collect::<String>()),
            };
            return Err(format!("hk_getAssets (the page from {from}): {reason}"));
        };
        for a in page.get("assets").and_then(|l| l.as_array()).into_iter().flatten() {
            let fresh = match a.get("asset").and_then(|x| x.as_str()) {
                Some(id) => seen.insert(id.to_string()),
                None => true,
            };
            if fresh {
                assets.push(a.clone());
            }
        }
        match page.get("next") {
            None | Some(serde_json::Value::Null) => {
                let mut whole = page.clone();
                if let Some(f) = whole.get_mut("from") {
                    *f = json!(0);
                }
                whole.insert("assets".to_string(), serde_json::Value::Array(assets));
                return Ok(json!({ "result": serde_json::Value::Object(whole) }));
            }
            Some(next) => match next.as_u64() {
                Some(n) if n > from => from = n,
                _ => {
                    return Err(format!(
                        "hk_getAssets: the page from {from} answered next = {next} — refusing to read it as a following page"
                    ))
                }
            },
        }
    }
    Err(format!(
        "hk_getAssets: the registry did not end within {ASSET_LIST_MAX_PAGES} pages — refusing a partial list"
    ))
}

/// `asset <verb> …` — the five issuer/holder verbs, signed with the DIR's account
/// through the same reserve-then-sign path as `account-send`, plus two read-only views.
pub(crate) fn cmd_asset(args: &[String]) -> eyre::Result<()> {
    // HR-9 (v0.19.12): `--allow-new-recipient` (mint's pre-flight override) may sit anywhere.
    let (allow_new_recipient, args) = take_allow_new_recipient(args);
    let args = &args[..];
    let usage = "usage: hk-node asset register <DIR> <RPC> <SYMBOL> <DECIMALS> <FLAGS m/f/p/s|-> \
                 | mint <DIR> <RPC> <ASSET-hex> <TO-hex> <MICRO> [--allow-new-recipient] \
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
            check_recipient(&rpc, &to, allow_new_recipient)?;
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
            // HR-4 (v0.19.12): every page of the registry, not only the first.
            let v = read_asset_pages(|from| demo::rpc(&rpc, "hk_getAssets", json!({ "from": from })), ASSET_LIST_BUSY_PAUSE)
                .map_err(|e| eyre::eyre!("{e}"))?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            Ok(())
        }
        _ => Err(eyre::eyre!(usage)),
    }
}

#[cfg(test)]
mod hr9_tests {
    use super::{recipient_preflight, take_allow_new_recipient};
    use serde_json::json;

    const RPC: &str = "http://127.0.0.1:26000";

    /// HR-9 (v0.19.12): the pre-flight refuses a recipient with no account unless the caller
    /// overrides, and the override is a flag that can sit anywhere. KILL: make
    /// `recipient_preflight` return `Ok` for `found: false` without the flag (the pre-v0.19.12
    /// behaviour — no check at all) and the first assertion fails; make
    /// `take_allow_new_recipient` leave the flag in the list and the positional check fails.
    #[test]
    fn hr9_recipient_preflight_refuses_absent_accounts_unless_overridden() {
        // `hk_getAccount`'s two answers (rpc.rs `get_account`)
        let absent = json!({"result": {"found": false, "nonce": null, "auth_commit": null, "balances": []}});
        let present = |nonce: u64| json!({"result": {"found": true, "nonce": nonce, "auth_commit": "00", "balances": []}});
        let e = recipient_preflight(RPC, &absent, false).unwrap_err();
        assert!(e.starts_with("no account exists at this id"), "{e}");
        assert!(e.contains("--allow-new-recipient"), "{e}");
        assert_eq!(recipient_preflight(RPC, &absent, true), Ok(()));
        assert_eq!(recipient_preflight(RPC, &present(0), false), Ok(()));
        assert_eq!(recipient_preflight(RPC, &present(42), true), Ok(()));
        let args: Vec<String> = ["mint", "DIR", "--allow-new-recipient", "RPC", "ASSET", "TO", "5"].iter().map(|s| s.to_string()).collect();
        let (allow, rest) = take_allow_new_recipient(&args);
        assert!(allow);
        assert_eq!(rest, ["mint", "DIR", "RPC", "ASSET", "TO", "5"]);
        let (allow, rest) = take_allow_new_recipient(&rest);
        assert!(!allow);
        assert_eq!(rest.len(), 6);
    }

    /// HR-9 (v0.19.12): a lookup that failed is not "no account". An `error` answer (a
    /// transport failure, a timeout or an HTTP error body — `demo::rpc` folds them into one),
    /// an answer with no `result` and one with no boolean `found` are each refused as "could
    /// not check the recipient", with or without the flag, and the message never offers the
    /// flag. KILL: read a failed lookup as `found: false` again (what `demo::account_nonce`
    /// does) and the flag passes it and the message offers the flag; let an `error` fall
    /// through to a `result` beside it and that answer passes.
    #[test]
    fn hr9_recipient_preflight_fails_closed_when_the_lookup_fails() {
        for answer in [
            json!({"error": "http://127.0.0.1:26000: Connection Failed: Connect error: connection refused"}),
            json!({"error": "http://127.0.0.1:26000: HTTP 502: <html>bad gateway</html>"}),
            json!({"error": "rpc busy — try again"}),
            json!({"error": {"code": 1}}),
            json!({"error": "unknown method", "result": {"found": true, "nonce": 3}}),
            json!({"result": null}),
            json!({}),
            json!({"result": {"nonce": 3}}),
            json!({"result": {"found": "false"}}),
        ] {
            for allow_new in [false, true] {
                let e = recipient_preflight(RPC, &answer, allow_new).unwrap_err();
                assert!(e.starts_with("could not check the recipient at http://127.0.0.1:26000: "), "{answer} -> {e}");
                assert!(e.ends_with(" — nothing was signed"), "{answer} -> {e}");
                assert!(!e.contains("--allow-new-recipient"), "{answer} -> {e}");
            }
        }
        // the node's own reason is carried through
        let e = recipient_preflight(RPC, &json!({"error": "rpc busy — try again"}), true).unwrap_err();
        assert_eq!(e, "could not check the recipient at http://127.0.0.1:26000: rpc busy — try again — nothing was signed");
    }
}

#[cfg(test)]
mod hr4_tests {
    use super::{read_asset_pages, ASSET_LIST_BUSY_TRIES, ASSET_LIST_MAX_PAGES};
    use serde_json::{json, Value};
    use std::time::Duration;

    const BUSY: &str = "busy: an asset registry scan is already in flight — retry in a moment";

    /// One `hk_getAssets` page as rpc.rs `get_assets` answers it.
    fn page(from: u64, ids: &[&str], next: Value) -> Value {
        let assets: Vec<Value> = ids.iter().map(|id| json!({"asset": id, "symbol": id.to_uppercase()})).collect();
        json!({"result": {"count": 5, "total": 5, "from": from, "limit": 2, "next": next, "fee_asset": "09", "assets": assets}})
    }

    /// HR-4 (v0.19.12): `asset list` reads every page — `next` followed until null, a page
    /// answered "busy" asked for again, an entry a later page repeats listed once — and prints
    /// one answer; a registry that fits one page comes back exactly as the node answered it.
    /// KILL: read only the first page (the pre-fix behaviour) and two entries come back instead
    /// of five; drop the busy retry and the second page's "busy" is reported as the answer;
    /// drop the repeat check and `b` is listed twice.
    #[test]
    fn hr4_asset_list_reads_every_page_and_retries_busy() {
        let mut calls = Vec::new();
        let mut busy_left = 2;
        let v = read_asset_pages(
            |from| {
                calls.push(from);
                match from {
                    0 => page(0, &["a", "b"], json!(2)),
                    2 if busy_left > 0 => {
                        busy_left -= 1;
                        json!({ "error": BUSY })
                    }
                    2 => page(2, &["b", "c", "d"], json!(4)),
                    4 => page(4, &["e"], Value::Null),
                    _ => panic!("unexpected page from {from}"),
                }
            },
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(calls, [0, 2, 2, 2, 4]);
        let r = &v["result"];
        let ids: Vec<&str> = r["assets"].as_array().unwrap().iter().map(|a| a["asset"].as_str().unwrap()).collect();
        assert_eq!(ids, ["a", "b", "c", "d", "e"]);
        assert_eq!(r["count"], json!(5));
        assert_eq!(r["from"], json!(0));
        assert_eq!(r["next"], Value::Null);
        let one = page(0, &["a"], Value::Null);
        assert_eq!(read_asset_pages(|_| one.clone(), Duration::ZERO).unwrap(), one);
    }

    /// HR-4 (v0.19.12): the reader stops and says why. A page that is busy on every try is
    /// reported after `ASSET_LIST_BUSY_TRIES` calls; any other error answer at once; a `next`
    /// that does not move forward is refused at the page that answered it; a registry with no
    /// end is refused after `ASSET_LIST_MAX_PAGES` pages instead of printed in part. KILL: retry
    /// "busy" without a bound, read a stuck `next` again, or follow `next` without a bound, and
    /// a call-count assertion fails (inside the fetch, before any hang); return the partial
    /// list at the bound and `unwrap_err` fails.
    #[test]
    fn hr4_asset_list_is_bounded_and_reports_failures() {
        let mut n = 0;
        let e = read_asset_pages(
            |_| {
                n += 1;
                assert!(n < 10, "the busy retry has no bound");
                json!({ "error": BUSY })
            },
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(n, ASSET_LIST_BUSY_TRIES);
        assert_eq!(e, format!("hk_getAssets (the page from 0): {BUSY}"));

        let mut n = 0;
        let e = read_asset_pages(
            |_| {
                n += 1;
                json!({ "error": "http://127.0.0.1:26000: Connection Failed" })
            },
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(n, 1);
        assert_eq!(e, "hk_getAssets (the page from 0): http://127.0.0.1:26000: Connection Failed");

        let mut n = 0;
        let e = read_asset_pages(
            |from| {
                n += 1;
                assert!(n < 10, "a stuck next is read again");
                page(from, &["a"], json!(from))
            },
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(n, 1);
        assert!(e.contains("the page from 0 answered next = 0"), "{e}");

        let mut n = 0;
        let e = read_asset_pages(
            |from| {
                n += 1;
                assert!(n <= 1_000, "the page loop has no bound");
                page(from, &[], json!(from + 1))
            },
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(n, ASSET_LIST_MAX_PAGES);
        assert!(e.contains("did not end within 100 pages"), "{e}");
    }
}
