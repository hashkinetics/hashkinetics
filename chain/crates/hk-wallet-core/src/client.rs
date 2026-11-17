//! HTTP plumbing (blocking, ureq): the node RPC, the faucet and the prover — the same three
//! calls the desktop wallet makes, parameterised by endpoints instead of env vars.
//!
//! P6.2 (2026-09-13): the client knows about ISSUED ASSETS — the registry (`hk_getAssets`:
//! symbol, decimals, pool-eligibility), an account's balances by asset (`hk_getAccount`),
//! and a balance in any one asset (`hk_balance`). The native test unit is [`USD`]; it is
//! never in the registry, so the wallet synthesises its entry.

use std::time::Duration;

use hk_primitives::{Amount, H256};
use serde_json::{json, Value};

use crate::{Endpoints, WalletError};

/// The transparent test unit (32 × 0x09) — the fee asset on testnet-1.
pub const USD: H256 = H256([9u8; 32]);

/// HR-4 (v0.19.12): `hk_getAssets` answers at most 1,000 entries per call with `next`, the
/// following page's `from` (`null` on the last page; absent from a node older than v0.19.12,
/// which answers the whole registry at once). The wallet follows `next` for at most this many
/// pages, and refuses a registry that does not end within them rather than show part of it.
const ASSET_PAGES_MAX: usize = 100;
/// A node runs one registry scan at a time and answers the rest "busy — retry": such a page is
/// asked for again, up to this many tries in all, before the answer is reported …
const ASSET_BUSY_TRIES: u32 = 3;
/// … with this pause between two tries.
const ASSET_BUSY_PAUSE: Duration = Duration::from_millis(300);

/// One entry of the chain's issued-asset registry, as a wallet needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetMeta {
    pub id: H256,
    pub symbol: String,
    pub decimals: u8,
    pub pool_eligible: bool,
    pub paused: bool,
}

pub struct Http {
    pub ep: Endpoints,
}

impl Http {
    pub fn new(ep: Endpoints) -> Self {
        Self { ep }
    }

    pub fn rpc(&self, method: &str, params: Value) -> Result<Value, WalletError> {
        self.rpc_within(method, params, 8)
    }

    /// A page of the pool feed can be megabytes — the scanner's calls get a longer budget.
    pub fn rpc_within(&self, method: &str, params: Value, secs: u64) -> Result<Value, WalletError> {
        ureq::post(&self.ep.rpc)
            .timeout(Duration::from_secs(secs))
            .send_json(json!({ "method": method, "params": params }))
            .map_err(|e| WalletError::msg(format!("rpc: {e}")))?
            .into_json::<Value>()
            .map_err(|e| WalletError::msg(format!("rpc parse: {e}")))
    }

    /// The native (fee) balance.
    pub fn balance(&self, id: &H256) -> Result<Amount, WalletError> {
        self.balance_of(id, &USD)
    }

    /// P6.2: the balance in ANY asset (the chain answers 0 for an asset never held).
    pub fn balance_of(&self, id: &H256, asset: &H256) -> Result<Amount, WalletError> {
        let v = self.rpc("hk_balance", json!({ "id": hex::encode(id.0), "asset": hex::encode(asset.0) }))?;
        Ok(v.get("result")
            .and_then(|r| r.get("amount"))
            .and_then(|a| a.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0))
    }

    /// `Ok(None)` = the account does not exist on-chain yet.
    pub fn nonce(&self, id: &H256) -> Result<Option<u64>, WalletError> {
        let v = self.rpc("hk_getAccount", json!({ "id": hex::encode(id.0) }))?;
        let r = v.get("result").ok_or_else(|| WalletError::msg("rpc: no result"))?;
        if r.get("found").and_then(|f| f.as_bool()).unwrap_or(false) {
            Ok(r.get("nonce").and_then(|n| n.as_u64()))
        } else {
            Ok(None)
        }
    }

    /// P6.2: every transparent balance this account holds — `(asset, symbol, amount)` from
    /// `hk_getAccount.balances[]` (X1). Empty when the account is not on-chain.
    pub fn account_balances(&self, id: &H256) -> Result<Vec<(H256, Option<String>, Amount)>, WalletError> {
        let v = self.rpc("hk_getAccount", json!({ "id": hex::encode(id.0) }))?;
        let r = v.get("result").ok_or_else(|| WalletError::msg("rpc: no result"))?;
        if !r.get("found").and_then(|f| f.as_bool()).unwrap_or(false) {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        if let Some(arr) = r.get("balances").and_then(|b| b.as_array()) {
            for b in arr {
                let asset = match b.get("asset").and_then(|a| a.as_str()).and_then(|s| hex::decode(s).ok()) {
                    Some(raw) if raw.len() == 32 => H256(raw.try_into().unwrap()),
                    _ => continue,
                };
                let symbol = b.get("symbol").and_then(|s| s.as_str()).map(str::to_string);
                let amount: Amount = b.get("amount").and_then(|a| a.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
                out.push((asset, symbol, amount));
            }
        }
        Ok(out)
    }

    /// One RPC call whose refusal comes back as its JSON body — the node answers `{"error": …}`
    /// with HTTP 400, and a full connection table with 503 — instead of a bare status code
    /// (`rpc` keeps that behaviour for its callers), so a caller can tell "busy — retry" from a
    /// failure. A transport failure, or an error body that is not JSON, is still an `Err`.
    fn rpc_answer(&self, method: &str, params: Value) -> Result<Value, WalletError> {
        match ureq::post(&self.ep.rpc)
            .timeout(Duration::from_secs(8))
            .send_json(json!({ "method": method, "params": params }))
        {
            Ok(resp) => resp.into_json::<Value>().map_err(|e| WalletError::msg(format!("rpc parse: {e}"))),
            Err(ureq::Error::Status(code, resp)) => {
                resp.into_json::<Value>().map_err(|_| WalletError::msg(format!("rpc: HTTP {code}")))
            }
            Err(e) => Err(WalletError::msg(format!("rpc: {e}"))),
        }
    }

    /// P6.2: the issued-asset registry (`hk_getAssets`). The native unit is NOT in it.
    /// HR-4 (v0.19.12): every page of it, not only the first (`read_asset_pages`).
    pub fn assets(&self) -> Result<Vec<AssetMeta>, WalletError> {
        read_asset_pages(|from| self.rpc_answer("hk_getAssets", json!({ "from": from })), ASSET_BUSY_PAUSE)
    }

    pub fn receipt(&self, txid: &str) -> Option<String> {
        let v = self.rpc("hk_getReceipt", json!({ "txid": txid })).ok()?;
        let r = v.get("result")?;
        if r.get("found")?.as_bool()? {
            r.get("detail")?.as_str().map(str::to_string)
        } else {
            None
        }
    }

    /// `hk_chainInfo` → (chain id, height, fee policy). Fee fields are strings on the wire.
    pub fn chain_info(&self) -> Result<ChainInfo, WalletError> {
        let v = self.rpc("hk_chainInfo", json!({}))?;
        let r = v.get("result").ok_or_else(|| WalletError::msg("rpc: no result"))?;
        let chain_id = r.get("chain_id").and_then(|c| c.as_str()).unwrap_or("?").to_string();
        let height = r.get("height").and_then(|h| h.as_u64()).unwrap_or(0);
        let node_version = r.get("node_version").and_then(|c| c.as_str()).unwrap_or("").to_string();
        let (fee_micro, fee_from) = match r.get("fee") {
            Some(f) => (
                f.get("micro").and_then(|m| m.as_str()).and_then(|s| s.parse::<Amount>().ok()).unwrap_or(0),
                f.get("from_height").and_then(|h| h.as_u64()).unwrap_or(u64::MAX),
            ),
            None => (0, u64::MAX),
        };
        Ok(ChainInfo { chain_id, height, node_version, fee_micro, fee_from })
    }

    /// v0.13.1: an RPC failure is an error, not "height 0" — deriving the epoch-0 stealth
    /// address on a network blip was wrong.
    pub fn height(&self) -> Result<u64, WalletError> {
        Ok(self.chain_info()?.height)
    }

    /// POST to the faucet. Success and refusal both come back as JSON; non-2xx statuses
    /// (cooldown, bad input) carry their explanation in the body.
    pub fn faucet_post(&self, body: Value) -> Result<Value, WalletError> {
        let req = ureq::post(&format!("{}/drip", self.ep.faucet)).timeout(Duration::from_secs(30));
        match req.send_json(body) {
            Ok(resp) => resp.into_json().map_err(|e| WalletError::msg(format!("faucet parse: {e}"))),
            Err(ureq::Error::Status(_, resp)) => resp.into_json().map_err(|e| WalletError::msg(format!("faucet parse: {e}"))),
            Err(e) => Err(WalletError::msg(format!("faucet unreachable: {e}"))),
        }
    }

    /// `prove_mint` / `prove_spend` on the configured prover, which receives the whole witness and is
    /// trusted with the value of the spend until circuit v4 (M-1; see `PROVER_DEFAULT`). Core-mode
    /// STARKs can take a while —
    /// long timeout; the caller runs off the UI thread. Returns (proof bytes, prove_ms).
    pub fn prove(&self, method: &str, witness: Value) -> Result<(Vec<u8>, u64), WalletError> {
        let prover = &self.ep.prover;
        let health = ureq::post(prover)
            .timeout(Duration::from_secs(10))
            .send_json(json!({ "method": "health", "params": {} }))
            .map_err(|e| WalletError::msg(format!("prover unreachable at {prover}: {e}")))?
            .into_json::<Value>()
            .map_err(|e| WalletError::msg(format!("prover health parse: {e}")))?;
        if health.get("result").is_none() {
            return Err(WalletError::msg(format!("prover at {prover} is not healthy: {health}")));
        }
        let v = ureq::post(prover)
            .timeout(Duration::from_secs(900))
            .send_json(json!({ "method": method, "params": { "witness": witness } }))
            .map_err(|e| WalletError::msg(format!("prover {method}: {e}")))?
            .into_json::<Value>()
            .map_err(|e| WalletError::msg(format!("prover {method} parse: {e}")))?;
        if let Some(e) = v.get("error") {
            return Err(WalletError::msg(format!("prover error: {e}")));
        }
        let r = v.get("result").ok_or_else(|| WalletError::msg(format!("prover: no result: {v}")))?;
        let proof_hex = r.get("proof").and_then(|p| p.as_str()).ok_or_else(|| WalletError::msg("prover: no proof in result"))?;
        Ok((
            hex::decode(proof_hex).map_err(|e| WalletError::msg(e.to_string()))?,
            r.get("prove_ms").and_then(|m| m.as_u64()).unwrap_or(0),
        ))
    }
}

/// Whether an RPC answer is a "busy — retry" refusal: the node's one registry-scan slot is
/// taken (`busy: an asset registry scan is already in flight …`) or its connection table is
/// full (`rpc busy — try again`).
fn answer_is_busy(v: &Value) -> bool {
    v.get("error")
        .and_then(|e| e.as_str())
        .is_some_and(|s| s.starts_with("busy") || s.starts_with("rpc busy"))
}

/// HR-4 (v0.19.12): the whole registry from `hk_getAssets`' pages, sorted by symbol.
/// `fetch(from)` is one call (the RPC in [`Http::assets`], canned pages in the tests). A page
/// answered "busy" is asked for again (up to `ASSET_BUSY_TRIES` tries, `pause` apart) before
/// the answer is reported; any other answer without a `result` is reported at once, and a
/// transport failure is never retried; `next` is followed until it is null or absent and must
/// move forward; a registry that does not end within `ASSET_PAGES_MAX` pages is refused. An id
/// already read is skipped: an asset registered between two pages shifts the later indices by
/// one, so a page can repeat the previous page's last entry.
fn read_asset_pages(
    mut fetch: impl FnMut(u64) -> Result<Value, WalletError>,
    pause: Duration,
) -> Result<Vec<AssetMeta>, WalletError> {
    let mut out: Vec<AssetMeta> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut from: u64 = 0;
    for _ in 0..ASSET_PAGES_MAX {
        let mut v = fetch(from)?;
        let mut tries = 1;
        while answer_is_busy(&v) && tries < ASSET_BUSY_TRIES {
            std::thread::sleep(pause);
            v = fetch(from)?;
            tries += 1;
        }
        let r = v.get("result").ok_or_else(|| WalletError::msg(format!("hk_getAssets: {v}")))?;
        if let Some(arr) = r.get("assets").and_then(|a| a.as_array()) {
            for a in arr {
                let id = match a.get("asset").and_then(|x| x.as_str()).and_then(|s| hex::decode(s).ok()) {
                    Some(raw) if raw.len() == 32 => H256(raw.try_into().unwrap()),
                    _ => continue,
                };
                if !seen.insert(id) {
                    continue;
                }
                out.push(AssetMeta {
                    id,
                    symbol: a.get("symbol").and_then(|s| s.as_str()).unwrap_or("?").to_string(),
                    decimals: a.get("decimals").and_then(|d| d.as_u64()).unwrap_or(6).min(18) as u8,
                    pool_eligible: a.get("policy").and_then(|p| p.get("pool_eligible")).and_then(|b| b.as_bool()).unwrap_or(false),
                    paused: a.get("paused").and_then(|b| b.as_bool()).unwrap_or(false),
                });
            }
        }
        match r.get("next") {
            None | Some(Value::Null) => {
                out.sort_by(|a, b| a.symbol.cmp(&b.symbol));
                return Ok(out);
            }
            Some(next) => match next.as_u64() {
                Some(n) if n > from => from = n,
                _ => {
                    return Err(WalletError::msg(format!(
                        "hk_getAssets: the page from {from} answered next = {next} — refusing to read it as a following page"
                    )))
                }
            },
        }
    }
    Err(WalletError::msg(format!(
        "hk_getAssets: the registry did not end within {ASSET_PAGES_MAX} pages — refusing a partial asset list"
    )))
}

/// What `hk_chainInfo` tells a wallet.
#[derive(Clone, Debug)]
pub struct ChainInfo {
    pub chain_id: String,
    pub height: u64,
    pub node_version: String,
    pub fee_micro: Amount,
    pub fee_from: u64,
}

impl ChainInfo {
    /// The fee charged on a transaction sent NOW (0 before activation).
    pub fn fee_now(&self) -> Amount {
        if self.fee_micro > 0 && self.height + 1 >= self.fee_from { self.fee_micro } else { 0 }
    }
}

#[cfg(test)]
mod hr4_tests {
    use super::{read_asset_pages, WalletError, ASSET_BUSY_TRIES, ASSET_PAGES_MAX};
    use serde_json::{json, Value};
    use std::time::Duration;

    const BUSY: &str = "busy: an asset registry scan is already in flight — retry in a moment";

    /// One `hk_getAssets` page as the node answers it (hk-node rpc.rs `get_assets`); asset `b`
    /// is 32 bytes of `b`, symbol `S<b>`.
    fn page(from: u64, ids: &[u8], next: Value) -> Result<Value, WalletError> {
        let assets: Vec<Value> = ids
            .iter()
            .map(|b| json!({"asset": hex::encode([*b; 32]), "symbol": format!("S{b:02}"), "decimals": 6, "policy": {"pool_eligible": true}, "paused": false}))
            .collect();
        Ok(json!({"result": {"count": 5, "total": 5, "from": from, "limit": 2, "next": next, "fee_asset": hex::encode([9u8; 32]), "assets": assets}}))
    }

    /// HR-4 (v0.19.12): the wallet reads every page — `next` followed until null, a page
    /// answered "busy" asked for again, an entry a later page repeats listed once — sorted by
    /// symbol. KILL: read only the first page (the pre-fix behaviour) and two assets come back
    /// instead of five; drop the busy retry and the second page's "busy" fails the call; drop
    /// the repeat check and `S04` is listed twice.
    #[test]
    fn hr4_assets_reads_every_page_and_retries_busy() {
        let mut calls = Vec::new();
        let mut busy_left = 2;
        let list = read_asset_pages(
            |from| {
                calls.push(from);
                match from {
                    0 => page(0, &[5, 4], json!(2)),
                    2 if busy_left > 0 => {
                        busy_left -= 1;
                        Ok(json!({ "error": BUSY }))
                    }
                    2 => page(2, &[4, 3, 2], json!(5)),
                    5 => page(5, &[1], Value::Null),
                    _ => panic!("unexpected page from {from}"),
                }
            },
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(calls, [0, 2, 2, 2, 5]);
        let symbols: Vec<&str> = list.iter().map(|a| a.symbol.as_str()).collect();
        assert_eq!(symbols, ["S01", "S02", "S03", "S04", "S05"]);
        assert!(list.iter().all(|a| a.decimals == 6 && a.pool_eligible && !a.paused));
    }

    /// HR-4 (v0.19.12): the reader stops and says why. A page that is busy on every try is
    /// reported after `ASSET_BUSY_TRIES` calls; any other error answer, and a transport
    /// failure, at once; a `next` that does not move forward is refused at the page that
    /// answered it; a registry with no end is refused after `ASSET_PAGES_MAX` pages instead of
    /// shown in part; a node older than v0.19.12 (no `next`) is read in one call. KILL: retry
    /// "busy" without a bound, read a stuck `next` again, or follow `next` without a bound, and
    /// a call-count assertion fails (inside the fetch, before any hang); return the partial
    /// list at the bound and `unwrap_err` fails; require `next` and the old node's answer fails.
    #[test]
    fn hr4_assets_is_bounded_and_reports_failures() {
        let mut n = 0;
        let e = read_asset_pages(
            |_| {
                n += 1;
                assert!(n < 10, "the busy retry has no bound");
                Ok(json!({ "error": BUSY }))
            },
            Duration::ZERO,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(n, ASSET_BUSY_TRIES);
        assert!(e.starts_with("hk_getAssets: ") && e.contains(BUSY), "{e}");

        let mut n = 0;
        let e = read_asset_pages(
            |_| {
                n += 1;
                Ok(json!({ "error": "unknown method" }))
            },
            Duration::ZERO,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(n, 1);
        assert!(e.contains("unknown method"), "{e}");

        let mut n = 0;
        let e = read_asset_pages(
            |_| {
                n += 1;
                Err(WalletError::msg("rpc: connection refused"))
            },
            Duration::ZERO,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(n, 1);
        assert_eq!(e, "rpc: connection refused");

        let mut n = 0;
        let e = read_asset_pages(
            |from| {
                n += 1;
                assert!(n < 10, "a stuck next is read again");
                page(from, &[1], json!(from))
            },
            Duration::ZERO,
        )
        .unwrap_err()
        .to_string();
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
        .unwrap_err()
        .to_string();
        assert_eq!(n, ASSET_PAGES_MAX);
        assert!(e.contains("did not end within 100 pages"), "{e}");

        let mut n = 0;
        let list = read_asset_pages(
            |_| {
                n += 1;
                Ok(json!({"result": {"count": 1, "fee_asset": hex::encode([9u8; 32]), "assets": [{"asset": hex::encode([7u8; 32]), "symbol": "OLD", "decimals": 2}]}}))
            },
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(n, 1);
        assert_eq!(list.len(), 1);
        assert_eq!((list[0].symbol.as_str(), list[0].decimals, list[0].pool_eligible), ("OLD", 2, false));
    }
}
