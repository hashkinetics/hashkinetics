//! Transaction types + signing digest. P2.5: byte fields are FORMAT-AWARE — hex in
//! JSON (RPC, receipts, genesis: human-readable), raw bytes in bincode (the consensus
//! wire). The SIGNING digest + txid hash the canonical serde_json form (deterministic
//! for our types — no maps, fixed field order), so signature domains never depend on
//! the wire codec.

use hk_primitives::{AccountId, Amount, AssetId, ChannelId, H256, MandateId, Timestamp};
use hk_crypto::hash::{shake256_32, DOM_TX_MSG};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Tx {
    /// Move own balance.
    Transfer { to: AccountId, asset: AssetId, amount: Amount },
    /// Create a mandate node. Root (parent=None): sender becomes holder + funding
    /// account. Child: sender must be the PARENT's holder; `holder` is the child agent.
    MandateCreate {
        id: MandateId,
        parent: Option<MandateId>,
        holder: AccountId,
        asset: AssetId,
        rate_per_sec: Amount,
        buffer_max: Amount,
        per_tx_max: Amount,
        initial_buffer: Amount,
        expiry: Timestamp,
        tier: u8,
    },
    /// Spend under a mandate leaf (sender must be leaf holder). Funds move from the
    /// ROOT's funding account — the org pays, the agent authorizes: that's the product.
    MandateSpend { leaf: MandateId, to: AccountId, amount: Amount },
    /// Revoke a node (sender must hold the node's parent; for roots, the root itself).
    /// Cascade is implicit: every descendant spend walks through the revoked ancestor.
    MandateRevoke { target: MandateId },
    /// Open a PayWord channel under a mandate leaf (sender = leaf holder).
    /// Escrow = unit_price × max_steps, drawn via the mandate at open (plan §6:
    /// "ancestor walk runs ONCE at channel funding"). `id` must equal the derived id.
    ChannelOpen {
        id: ChannelId,
        mandate: MandateId,
        payee: AccountId,
        asset: AssetId,
        tip: H256,
        unit_price: Amount,
        max_steps: u32,
        expiry: Timestamp,
    },
    /// Settle a channel up to `step` with revealed PayWord `word`. Proof-carrying:
    /// ANY sender may submit (payee, or their watchtower).
    ChannelSettle { id: ChannelId, word: H256, step: u32 },
    /// After expiry, payer reclaims unspent escrow.
    ChannelRefund { id: ChannelId },
    /// SHIELD (P2.0): move `value` of `asset` from the sender's transparent balance into
    /// the pool as hidden note `commitment`. `proof` (mint statement) attests the
    /// commitment opens to exactly `value` — the inflation guard; owner/rho/rcm stay
    /// private. v1: single-asset pool — the FIRST mint pins the pool's asset.
    MintToPool {
        asset: AssetId,
        value: Amount,
        commitment: H256,
        #[serde(with = "serde_bytes_vec")]
        proof: Vec<u8>,
        /// Stealth payload for the note's recipient (KEM ct ‖ sealed note plaintext).
        /// ADVISORY: consensus stores/gossips it; scanners read it; a lying blob only
        /// hurts its sender (P2.1).
        #[serde(with = "serde_bytes_vec", default)]
        stealth_ct: Vec<u8>,
    },
    /// SHIELDED SPEND (P2.0). Proof-carrying: ANY account may relay — authority comes from
    /// the STARK, not the envelope. Publics: a recent `anchor`, the burned `nullifier`,
    /// the new `out_commitment`, and a transparent `fee` paid to `credit` (the unshield
    /// channel; fee = 0 ⇒ fully shielded transfer). The proof's tx_binding must equal
    /// H(credit ‖ fee), so a relayer cannot redirect the transparent effects.
    ShieldedSpend {
        anchor: H256,
        nullifier: H256,
        /// Output 1 — the payment.
        out_commitment: H256,
        /// Output 2 — the change (v3: two-output circuit, in = out1 + out2 + fee).
        out2_commitment: H256,
        fee: Amount,
        credit: Option<AccountId>,
        /// P2.4 (public skeleton): bind this unshield to a MandateTree leaf. The
        /// ENVELOPE SENDER must be the leaf's holder; the mandate authorizes the PUBLIC
        /// `fee` amount through the whole ancestor chain (org caps enforced in
        /// consensus) — while balances and counterparties stay hidden.
        #[serde(default)]
        mandate: Option<MandateId>,
        #[serde(with = "serde_bytes_vec")]
        proof: Vec<u8>,
        /// Stealth payloads for the two outputs' recipients (advisory, like MintToPool's).
        #[serde(with = "serde_bytes_vec", default)]
        stealth_ct: Vec<u8>,
        #[serde(with = "serde_bytes_vec", default)]
        stealth_ct2: Vec<u8>,
    },
}

/// Account-signed transaction envelope — the L-ratchet (hk-crypto::lamport docs):
/// `lamport_pk` opens the account's current `auth_commit`; the signature covers the
/// payload AND `next_auth` (commitment to the next key). Success ratchets the account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedTx {
    pub sender: AccountId,
    pub nonce: u64,
    pub payload: Tx,
    pub next_auth: H256,
    #[serde(with = "serde_bytes_vec")]
    pub lamport_pk: Vec<u8>,
    #[serde(with = "serde_bytes_vec")]
    pub sig: Vec<u8>,
}

/// Byte fields, format-aware (P2.5, the binary codec): hex strings for human-readable
/// formats (JSON — RPC, receipts, genesis) and RAW BYTES for binary formats (bincode —
/// the consensus wire), so a 2.7 MB proof costs 2.7 MB on the wire instead of ~11 MB.
/// The SIGNING digest and txid still hash the JSON form — signature domains unchanged.
mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(v))
        } else {
            s.serialize_bytes(v)
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            hex::decode(&s).map_err(serde::de::Error::custom)
        } else {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = Vec<u8>;
                fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                    f.write_str("bytes")
                }
                fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                    Ok(v.to_vec())
                }
                fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                    Ok(v)
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
                    let mut out = Vec::new();
                    while let Some(b) = seq.next_element::<u8>()? {
                        out.push(b);
                    }
                    Ok(out)
                }
            }
            d.deserialize_byte_buf(V)
        }
    }
}

/// The 32-byte digest the account key signs. Single source of truth — the state
/// machine and every client MUST use this exact function.
pub fn signing_digest(payload: &Tx, sender: &AccountId, nonce: u64, next_auth: &H256) -> Option<[u8; 32]> {
    let payload_bytes = serde_json::to_vec(payload).ok()?;
    Some(shake256_32(
        DOM_TX_MSG,
        &[&payload_bytes, &sender.0, &nonce.to_le_bytes(), &next_auth.0],
    ))
}
