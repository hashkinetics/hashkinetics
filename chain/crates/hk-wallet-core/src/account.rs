//! The transparent account: the L-ratchet key file (`account.json`, byte-compatible with the
//! CLI's and the desktop wallet's: seed / id / next_nonce), id derivation, signing, amounts.

use hk_crypto::hash::{shake256_32, DOM_ACCOUNT_ID};
use hk_crypto::lamport;
use hk_primitives::{Amount, H256};
use hk_state::tx::{signing_digest, SignedTx, Tx};
use serde::{Deserialize, Serialize};

use crate::WalletError;

/// Identical shape to the CLI's / desktop wallet's `account.json`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AccountFile {
    pub seed: String,
    pub id: String,
    pub next_nonce: u64,
}

impl AccountFile {
    /// A fresh keychain: 32 random bytes; the id is derived from the ratchet-0 auth commit.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        Self::from_seed(&seed)
    }

    pub fn from_seed(seed: &[u8]) -> Self {
        let id = derived_id(&commit_at(seed, 0));
        Self { seed: hex::encode(seed), id: hex::encode(id.0), next_nonce: 0 }
    }

    pub fn seed_bytes(&self) -> Result<Vec<u8>, WalletError> {
        hex::decode(&self.seed).map_err(|e| WalletError::msg(format!("account.json seed: {e}")))
    }

    pub fn id_h256(&self) -> Result<H256, WalletError> {
        parse_h256(&self.id)
    }
}

pub fn commit_at(seed: &[u8], nonce: u64) -> H256 {
    let (_, pk) = lamport::keygen(seed, nonce);
    H256(lamport::pk_commit(&pk))
}

pub fn derived_id(auth_commit: &H256) -> H256 {
    H256(shake256_32(DOM_ACCOUNT_ID, &[&auth_commit.0]))
}

pub fn parse_h256(s: &str) -> Result<H256, WalletError> {
    let raw = hex::decode(s.trim().trim_start_matches("0x")).map_err(|e| WalletError::msg(format!("bad hex: {e}")))?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| WalletError::msg("expected 64 hex characters"))?;
    Ok(H256(arr))
}

pub fn sign_tx(seed: &[u8], id: H256, nonce: u64, payload: Tx) -> SignedTx {
    let (sk, pk) = lamport::keygen(seed, nonce);
    let next_auth = commit_at(seed, nonce + 1);
    let digest = signing_digest(&payload, &id, nonce, &next_auth).expect("digest");
    let sig = lamport::sign(&sk, &digest);
    SignedTx { sender: id, nonce, payload, next_auth, lamport_pk: pk, sig }
}

/// "0.25" / "1" / ".5" → micro-units, max 6 decimals, integer math only.
pub fn parse_amount(s: &str) -> Option<Amount> {
    let s = s.trim().trim_start_matches('$');
    let (int, frac) = match s.split_once('.') {
        Some((a, b)) => (a, b),
        None => (s, ""),
    };
    if int.is_empty() && frac.is_empty() {
        return None;
    }
    if !int.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) || frac.len() > 6 {
        return None;
    }
    let int: Amount = if int.is_empty() { 0 } else { int.parse().ok()? };
    let mut f = frac.to_string();
    while f.len() < 6 {
        f.push('0');
    }
    let frac: Amount = if f.is_empty() { 0 } else { f.parse().ok()? };
    int.checked_mul(1_000_000)?.checked_add(frac)
}

pub fn fmt_amount(micro: Amount) -> String {
    format!("{}.{:06}", micro / 1_000_000, micro % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wa1_account_file_shape_and_id_are_the_desktop_wallets() {
        // The id is H(DOM_ACCOUNT_ID ‖ auth commit at ratchet 0) — the rule consensus checks.
        let a = AccountFile::from_seed(&[7u8; 32]);
        assert_eq!(a.next_nonce, 0);
        assert_eq!(a.seed, hex::encode([7u8; 32]));
        assert_eq!(a.id, hex::encode(derived_id(&commit_at(&[7u8; 32], 0)).0));
        // Round-trips through the exact JSON field names the CLI reads.
        let json = serde_json::to_string(&a).unwrap();
        assert!(json.contains("\"seed\"") && json.contains("\"id\"") && json.contains("\"next_nonce\""));
        let back: AccountFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
        // Two fresh keychains never collide.
        assert_ne!(AccountFile::generate().id, AccountFile::generate().id);
    }

    #[test]
    fn wa1_amounts_parse_and_print_like_the_desktop_wallet() {
        assert_eq!(parse_amount("0.25"), Some(250_000));
        assert_eq!(parse_amount("1"), Some(1_000_000));
        assert_eq!(parse_amount(".5"), Some(500_000));
        assert_eq!(parse_amount("$2.000001"), Some(2_000_001));
        assert_eq!(parse_amount("1.1234567"), None);
        assert_eq!(parse_amount("abc"), None);
        assert_eq!(parse_amount(""), None);
        assert_eq!(fmt_amount(250_000), "0.250000");
        assert_eq!(fmt_amount(1_000_001), "1.000001");
    }

    #[test]
    fn wa1_signature_binds_the_next_auth_commit() {
        let seed = [3u8; 32];
        let a = AccountFile::from_seed(&seed);
        let id = a.id_h256().unwrap();
        let tx = sign_tx(&seed, id, 0, Tx::Transfer { to: H256([1u8; 32]), asset: crate::client::USD, amount: 5 });
        assert_eq!(tx.sender, id);
        assert_eq!(tx.nonce, 0);
        assert_eq!(tx.next_auth, commit_at(&seed, 1));
    }
}
