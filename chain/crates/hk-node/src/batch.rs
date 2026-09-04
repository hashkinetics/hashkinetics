//! Block batch framing (0.7). The bytes inside an `HkValue` are a `Batch`:
//! the parent state commitment + the ordered transactions. Because `HkValueId` is
//! SHAKE-256 over these bytes, **the parent app_hash is bound into the value id** —
//! so a validator whose state diverged computes a different commitment and REJECTS
//! the block at commit time (consensus-fatal divergence, plan §7.3 / honesty item
//! closed from 0.6). Empty blocks still carry the parent hash, so the chain of
//! commitments is unbroken even with no transactions.

use hk_consensus::{RotationCert, SetChangeCert};
use hk_state::tx::SignedTx;
use hk_crypto::hash::shake256_32;
use serde::{Deserialize, Serialize};

pub const DOM_TXID: &str = "hk/v1/txid";
/// C2.4: 256 → 1024. Proposer-side cap (consensus never rejects a fuller block —
/// wire limits do). Budget at 1024 transparent txs: ~24.5 KB each on the bincode
/// wire ≈ 25 MB/block, inside the 32 MiB pubsub cap with headroom; shielded blocks
/// ride ONE 1.24 MB aggregate + ~2.7 KB/tx, far smaller. Devnet-measured before
/// any public-testnet bump: see docs/CAPACITY-SHEET.md.
pub const MAX_TXS_PER_BLOCK: usize = 1024;

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
    /// V1 (v0.14): validator-set changes to apply on commit (seat admitted / removed by a
    /// supermajority of the current seats' roots). Usually empty. A batch that carries one
    /// is encoded in the **v2 wire framing** (magic prefix); an empty list encodes exactly
    /// the v1 bytes, so every block before the first admission stays byte-identical and
    /// a pre-v0.14 node keeps decoding until the first set change commits — the same
    /// "≥ vX before the first X commits" discipline as `AccountCreate` (v0.11.0).
    #[serde(default)]
    pub set_changes: Vec<SetChangeCert>,
}

/// v2 wire magic — 8 bytes so a v1 batch (which starts with a 32-byte SHAKE parent hash)
/// collides with it with probability 2⁻⁶⁴ per block, never in practice.
const BATCH_V2_MAGIC: &[u8; 8] = b"HK-BLK-2";

/// The v1 (v0.9.11 … v0.13.x) wire layout: `Batch` without `set_changes`. Owned form for
/// decoding old blocks, borrowed form for encoding new blocks that carry no set change.
#[derive(Deserialize)]
struct BatchV1 {
    parent_app_hash: [u8; 32],
    txs: Vec<SignedTx>,
    #[serde(default)]
    rotations: Vec<RotationCert>,
    #[serde(with = "hex_bytes", default)]
    agg_proof: Vec<u8>,
}

#[derive(Serialize)]
struct BatchV1Ref<'a> {
    parent_app_hash: &'a [u8; 32],
    txs: &'a Vec<SignedTx>,
    rotations: &'a Vec<RotationCert>,
    #[serde(with = "hex_bytes_ref")]
    agg_proof: &'a Vec<u8>,
}

/// Serialize-only twin of `hex_bytes` for the borrowed v1 encoder.
mod hex_bytes_ref {
    use serde::Serializer;
    pub fn serialize<S: Serializer>(v: &&Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(v))
        } else {
            s.serialize_bytes(v)
        }
    }
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
        if self.set_changes.is_empty() {
            // Byte-identical to the v1 wire: no magic, no trailing field.
            let v1 = BatchV1Ref {
                parent_app_hash: &self.parent_app_hash,
                txs: &self.txs,
                rotations: &self.rotations,
                agg_proof: &self.agg_proof,
            };
            return bincode::serialize(&v1).expect("Batch v1 is bincode-safe");
        }
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(BATCH_V2_MAGIC);
        out.extend_from_slice(&bincode::serialize(self).expect("Batch v2 is bincode-safe"));
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            // Genesis / degenerate empty value — treat as no batch.
            return None;
        }
        if let Some(rest) = bytes.strip_prefix(BATCH_V2_MAGIC) {
            return bincode::deserialize::<Batch>(rest).ok();
        }
        let v1: BatchV1 = bincode::deserialize(bytes).ok()?;
        Some(Batch {
            parent_app_hash: v1.parent_app_hash,
            txs: v1.txs,
            rotations: v1.rotations,
            agg_proof: v1.agg_proof,
            set_changes: Vec::new(),
        })
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
            set_changes: vec![],
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

    /// V1: a batch without set changes is BYTE-IDENTICAL to the v1 wire (every block
    /// before the first admission keeps its bytes, and a pre-v0.14 node keeps decoding);
    /// a batch with one carries the v2 magic and round-trips with the certificate intact.
    #[test]
    fn batch_v1_bytes_unchanged_and_v2_roundtrips() {
        use hk_consensus::{Approval, SetChange, SetChangeBody, SetChangeCert};
        let plain = Batch {
            parent_app_hash: [0x22; 32],
            txs: vec![fat_tx(1024)],
            rotations: vec![],
            agg_proof: vec![1, 2, 3],
            set_changes: vec![],
        };
        let bytes = plain.encode();
        // Exactly what the old struct produced: parent hash first, no magic.
        assert_eq!(&bytes[..32], &[0x22; 32]);
        assert!(!bytes.starts_with(BATCH_V2_MAGIC));
        let old_layout = BatchV1Ref {
            parent_app_hash: &plain.parent_app_hash,
            txs: &plain.txs,
            rotations: &plain.rotations,
            agg_proof: &plain.agg_proof,
        };
        assert_eq!(bytes, bincode::serialize(&old_layout).unwrap());
        let back = Batch::decode(&bytes).unwrap();
        assert!(back.set_changes.is_empty());
        assert_eq!(txid(&back.txs[0]), txid(&plain.txs[0]));

        let cert = SetChangeCert {
            body: SetChangeBody {
                chain_id: "hashkinetics-devnet-1".into(),
                change: SetChange::Admit {
                    root_pk: vec![7u8; 48],
                    public_key: hk_consensus::HkPub(vec![9u8; 60]),
                    voting_power: 1,
                },
                not_before: 10,
                not_after: 20,
            },
            approvals: vec![Approval { root_pk: vec![1u8; 48], root_sig: vec![0u8; 16224] }],
        };
        let with = Batch { set_changes: vec![cert.clone()], ..plain.clone() };
        let bytes2 = with.encode();
        assert!(bytes2.starts_with(BATCH_V2_MAGIC));
        let back2 = Batch::decode(&bytes2).unwrap();
        assert_eq!(back2.set_changes, vec![cert]);
        assert_eq!(back2.parent_app_hash, plain.parent_app_hash);
        assert_eq!(txid(&back2.txs[0]), txid(&plain.txs[0]));
        assert_eq!(back2.agg_proof, plain.agg_proof);
    }
}
