//! X1 — issued assets (docs/X1-ISSUED-ASSETS.md): the asset registry and the
//! issuer-controlled policy behind `AssetRegister / Mint / Burn / Freeze / Pause`.
//!
//! An asset is registered by the account that becomes its issuer; its id is
//! `H(DOM_ASSET_ID ‖ issuer ‖ symbol)` (squat-proof, like account ids). Genesis may
//! register assets under any id (genesis is the trust root). Everything here is
//! plain deterministic data — no clocks, no randomness, BTree iteration only — and
//! every rule is a typed error the state machine turns into a receipt string.

use hk_crypto::hash::shake256_32;
use hk_primitives::{AccountId, Amount, AssetId, H256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Domain separator for asset ids (kept here, not in hk-crypto, so the crate that
/// defines the rule owns the constant).
pub const DOM_ASSET_ID: &str = "hk/v1/asset-id";
/// Symbol length bound (bytes). ASCII `[A-Za-z0-9._-]`, first byte a letter.
pub const MAX_SYMBOL_LEN: usize = 16;
/// Display decimals bound (informational — the state machine moves base units).
pub const MAX_DECIMALS: u8 = 18;
/// `AssetBurn.destination` bound — an opaque redemption target for the issuer's
/// return path (X3 defines formats); bounded so a burn cannot carry a payload.
pub const MAX_BURN_DESTINATION: usize = 64;

/// Fixed at registration (X1 has no policy changes — docs §5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetPolicy {
    /// The issuer may `AssetMint`.
    pub mintable: bool,
    /// The issuer may `AssetFreeze` individual accounts.
    pub freezable: bool,
    /// The issuer may `AssetPause` the whole asset.
    pub pausable: bool,
    /// The asset may enter the shielded pool (`MintToPool`). Issuer freeze can never
    /// reach a note, so an issuer that needs reachability leaves this false (X5).
    pub pool_eligible: bool,
}

impl AssetPolicy {
    /// One byte, bit per flag — the commitment layout (docs §3) and CLI `FLAGS`.
    pub fn bits(&self) -> u8 {
        (self.mintable as u8)
            | ((self.freezable as u8) << 1)
            | ((self.pausable as u8) << 2)
            | ((self.pool_eligible as u8) << 3)
    }

    /// Parse the CLI/genesis-build spelling: any subset of `m` (mintable),
    /// `f` (freezable), `p` (pausable), `s` (shieldable = pool_eligible); `-` = none.
    pub fn from_flags(s: &str) -> Result<Self, String> {
        let mut p = AssetPolicy::default();
        for c in s.chars() {
            match c {
                'm' => p.mintable = true,
                'f' => p.freezable = true,
                'p' => p.pausable = true,
                's' => p.pool_eligible = true,
                '-' => {}
                other => return Err(format!("unknown policy flag '{other}' (use m/f/p/s or -)")),
            }
        }
        Ok(p)
    }

    pub fn flags(&self) -> String {
        let mut s = String::new();
        if self.mintable { s.push('m') }
        if self.freezable { s.push('f') }
        if self.pausable { s.push('p') }
        if self.pool_eligible { s.push('s') }
        if s.is_empty() { s.push('-') }
        s
    }
}

/// One registry entry. Serialized whole into the state snapshot (v3); its
/// commitment bytes are produced by [`AssetInfo::commit_into`] — never by serde.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetInfo {
    pub symbol: String,
    pub decimals: u8,
    pub issuer: AccountId,
    pub policy: AssetPolicy,
    /// Everything ever minted (genesis allocations of a genesis-registered asset included).
    pub supply: Amount,
    /// `AssetBurn` total. Protocol-fee burns of the fee asset are counted in
    /// `State::fees_burned`, not here (docs §2, conservation I5').
    pub burned: Amount,
    pub paused: bool,
    pub frozen: BTreeSet<AccountId>,
    /// Height of registration (0 = genesis). Informational; in the commitment
    /// because it is state every node derives identically.
    pub registered_at: u64,
}

impl AssetInfo {
    /// Fixed byte layout for the state commitment (docs §3): id-independent part —
    /// the caller writes the id first.
    pub fn commit_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.issuer.0);
        buf.push(self.symbol.len() as u8);
        buf.extend_from_slice(self.symbol.as_bytes());
        buf.push(self.decimals);
        buf.push(self.policy.bits());
        buf.push(self.paused as u8);
        buf.extend_from_slice(&self.supply.to_le_bytes());
        buf.extend_from_slice(&self.burned.to_le_bytes());
        buf.extend_from_slice(&self.registered_at.to_le_bytes());
        buf.extend_from_slice(&(self.frozen.len() as u64).to_le_bytes());
        for a in &self.frozen {
            buf.extend_from_slice(&a.0);
        }
    }
}

/// `H(DOM_ASSET_ID ‖ issuer ‖ symbol)` — the only id a runtime registration may claim.
pub fn derive_asset_id(issuer: &AccountId, symbol: &str) -> AssetId {
    H256(shake256_32(DOM_ASSET_ID, &[&issuer.0, symbol.as_bytes()]))
}

/// Symbol rule: 1..=16 bytes of `[A-Za-z0-9._-]`, first byte a letter.
pub fn valid_symbol(symbol: &str) -> bool {
    let b = symbol.as_bytes();
    if b.is_empty() || b.len() > MAX_SYMBOL_LEN || !b[0].is_ascii_alphabetic() {
        return false;
    }
    b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_rule() {
        for ok in ["USDC", "USDC.t", "hkn", "A", "Long_Symbol-16ch", "X.Y-Z_1"] {
            assert!(valid_symbol(ok), "{ok}");
        }
        for bad in ["", "1USDC", ".t", "USD C", "usdc€", "SeventeenCharsLong", "a/b"] {
            assert!(!valid_symbol(bad), "{bad}");
        }
    }

    #[test]
    fn policy_bits_roundtrip() {
        for bits in 0u8..16 {
            let p = AssetPolicy {
                mintable: bits & 1 != 0,
                freezable: bits & 2 != 0,
                pausable: bits & 4 != 0,
                pool_eligible: bits & 8 != 0,
            };
            assert_eq!(p.bits(), bits);
            assert_eq!(AssetPolicy::from_flags(&p.flags()).unwrap(), p);
        }
        assert!(AssetPolicy::from_flags("mfx").is_err());
    }

    #[test]
    fn ids_are_issuer_and_symbol_bound() {
        let a = H256([1; 32]);
        let b = H256([2; 32]);
        assert_ne!(derive_asset_id(&a, "USDC"), derive_asset_id(&b, "USDC"));
        assert_ne!(derive_asset_id(&a, "USDC"), derive_asset_id(&a, "USDT"));
        assert_eq!(derive_asset_id(&a, "USDC"), derive_asset_id(&a, "USDC"));
    }
}
