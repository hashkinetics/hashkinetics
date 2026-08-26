//! Block batch framing (0.7). The bytes inside an `HkValue` are a `Batch`:
//! the parent state commitment + the ordered transactions. Because `HkValueId` is
//! SHAKE-256 over these bytes, **the parent app_hash is bound into the value id** —
//! so a validator whose state diverged computes a different commitment and REJECTS
//! the block at commit time (consensus-fatal divergence, plan §7.3 / honesty item
//! closed from 0.6). Empty blocks still carry the parent hash, so the chain of
//! commitments is unbroken even with no transactions.

use hk_consensus::RotationCert;
use hk_state::tx::SignedTx;
use hk_crypto::hash::shake256_32;
use serde::{Deserialize, Serialize};

pub const DOM_TXID: &str = "hk/v1/txid";
pub const MAX_TXS_PER_BLOCK: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Batch {
    /// State commitment the proposer built on (must equal each committer's own
    /// `state_commitment()` before the block is applied).
    pub parent_app_hash: [u8; 32],
    pub txs: Vec<SignedTx>,
    /// Root-signed operational-key rotations to apply on commit (SCMS). Usually empty;
    /// `#[serde(default)]` keeps older/empty batches decodable.
    #[serde(default)]
    pub rotations: Vec<RotationCert>,
    /// P2.3: ONE aggregate STARK covering every PROOF-LESS pool tx in `txs` (in order).
    /// Empty ⇒ no aggregation (per-proof fallback). Validators verify this ONCE per
    /// block against the chain-derived expected publics.
    #[serde(with = "hex_bytes", default)]
    pub agg_proof: Vec<u8>,
}

/// Format-aware bytes (P2.5): hex for JSON, raw for the bincode wire.
mod hex_bytes {
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
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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

impl Batch {
    /// P2.5: the wire codec is BINCODE — with the format-aware byte fields, proofs and
    /// ciphertexts travel as raw bytes (a 1.24 MB aggregate costs 1.24 MB, not ~5 MB of
    /// nested hex). Deterministic: fixed-field structs, no maps. The tx SIGNING digest
    /// and txid still hash the JSON form — signature domains are untouched.
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Batch is bincode-safe")
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            // Genesis / degenerate empty value — treat as no batch.
            return None;
        }
        bincode::deserialize(bytes).ok()
    }
}

/// Stable id of a transaction (for mempool dedup + receipt lookup).
pub fn txid(tx: &SignedTx) -> [u8; 32] {
    let bytes = serde_json::to_vec(tx).expect("SignedTx is JSON-safe");
    shake256_32(DOM_TXID, &[&bytes])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fat_tx(proof_len: usize) -> SignedTx {
        SignedTx {
            sender: Default::default(),
            nonce: 7,
            payload: hk_state::tx::Tx::MintToPool {
                asset: Default::default(),
                value: 5_000_000,
                commitment: Default::default(),
                proof: (0..proof_len).map(|i| (i % 251) as u8).collect(),
                stealth_ct: vec![0x5c; 1088 + 200],
            },
            next_auth: Default::default(),
            lamport_pk: vec![0xAB; 64],
            sig: vec![0xCD; 512],
        }
    }

    /// P2.5: the wire is bincode with RAW byte fields — the trip must be exact (txid,
    /// a JSON-domain hash, must survive it) and cost ~1× the payload, where the old
    /// JSON codec cost ~4× via nested hex/number-arrays (measured: MessageTooLarge).
    #[test]
    fn batch_bincode_roundtrip_and_size() {
        let proof_len = 64 * 1024;
        let batch = Batch {
            parent_app_hash: [0x11; 32],
            txs: vec![fat_tx(proof_len), fat_tx(proof_len / 2)],
            rotations: vec![],
            agg_proof: vec![0xE0; 32 * 1024],
        };
        let bytes = batch.encode();
        let back = Batch::decode(&bytes).expect("bincode batch decodes");
        assert_eq!(back.parent_app_hash, batch.parent_app_hash);
        assert_eq!(back.txs.len(), 2);
        assert_eq!(txid(&back.txs[0]), txid(&batch.txs[0]));
        assert_eq!(txid(&back.txs[1]), txid(&batch.txs[1]));
        assert_eq!(back.agg_proof, batch.agg_proof);

        let payload = proof_len + proof_len / 2 + 2 * (1088 + 200) + 32 * 1024;
        assert!(
            bytes.len() < payload + payload / 8 + 4096,
            "wire should be ~1× payload: {} vs {payload}",
            bytes.len()
        );
        let json = serde_json::to_vec(&batch).unwrap();
        assert!(
            json.len() > bytes.len() * 2,
            "JSON ({}) should dwarf the binary wire ({})",
            json.len(),
            bytes.len()
        );
    }

    /// Garbage and legacy-JSON bytes are cleanly refused (one wire format, no fallback).
    #[test]
    fn batch_decode_rejects_garbage_and_empty() {
        assert!(Batch::decode(&[]).is_none());
        assert!(Batch::decode(br#"{"parent_app_hash":[0,1],"txs":[]}"#).is_none());
    }
}
