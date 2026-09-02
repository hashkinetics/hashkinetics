//! NodeStore — P3.0/WS-B persistence: block log + node snapshots + mempool WAL.
//!
//! Design (docs/P3-BUILD-PLAN.md WS-B):
//! - **Block log**: one bincode file per committed height under `<home>/blocks/`
//!   (`b{height:012}.bin`), written atomically AFTER the block fully applied. Each
//!   entry carries the raw batch bytes + the commit certificate (the sync codec's
//!   DTO) + this node's aggregate verdict, so replay reproduces the exact same
//!   receipts WITHOUT needing a prover connection.
//! - **Snapshot**: every [`SNAPSHOT_EVERY`] blocks, the full node image
//!   (`snapshot.bin`): Σ (via `hk_state::StateSnapshot`), the pool-note index,
//!   receipts, mempool, validator set + rotation epochs, and the app_hash the image
//!   must recompute to. Restore REFUSES to run on a commitment mismatch — the same
//!   posture as the vk pins.
//! - **Mempool WAL** (`mempool.wal`): length-prefixed bincode frames appended on RPC
//!   admission, truncated at every snapshot. A torn tail (crash mid-append) is
//!   tolerated: frames stop at the first undecodable entry.
//!
//! Restart = load snapshot (if any) → replay newer block files through the SAME
//! commit path → identical C(Σ) by construction (proven at the state layer by
//! `snapshot_roundtrip_identical_commitment_and_keeps_running`; proven at the
//! process layer by the crash-kill devnet demo).
//!
//! Durability notes (honest): block/snapshot writes are atomic (tmp+fsync+rename,
//! same discipline as the signer state); WAL appends are NOT fsynced per-tx —
//! a machine crash may lose mempool admissions since the last snapshot (clients
//! re-submit; consensus-critical data never lives only in the WAL).

use std::io::Write;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr as _};
use serde::{Deserialize, Serialize};

use hk_consensus::{HkAddress, HkPub};
use hk_primitives::H256;
use hk_state::tx::SignedTx;
use hk_state::StateSnapshot;

use crate::codec::RawCommitCertificate;

/// Snapshot cadence in blocks. Replay-after-crash is bounded by this many blocks
/// (plus the WAL); small enough that restart is instant on devnet, big enough that
/// the per-block cost is the cheap block-log append, not the full image.
pub const SNAPSHOT_EVERY: u64 = 16;

/// One committed block, exactly as this node accepted it.
#[derive(Serialize, Deserialize)]
pub struct StoredBlock {
    pub height: u64,
    /// Raw batch bytes (the decided `HkValue`'s `txs`; the value id is their hash).
    pub value_bytes: Vec<u8>,
    /// Commit certificate — same DTO the sync codec uses on the wire.
    pub certificate: RawCommitCertificate,
    /// This node's live verdict on the batch's aggregate STARK (true = verified,
    /// coverage installed). Replay reuses the verdict instead of re-proving: the
    /// certificate pins the batch, the parent-hash chain pins the outcome, and an
    /// invalid-aggregate block must reject its proof-less txs on replay too.
    pub agg_valid: bool,
}

/// Validator entry, address preserved verbatim (it is derived from the GENESIS
/// operational key and never recomputed across rotations — recomputing it from a
/// rotated key would corrupt the set).
#[derive(Serialize, Deserialize)]
pub struct ValidatorDto {
    pub address: HkAddress,
    pub root_pk: Vec<u8>,
    pub public_key: HkPub,
    pub epoch: u64,
    pub voting_power: u64,
}

/// The full persistent node image at a height.
#[derive(Serialize, Deserialize)]
pub struct NodeSnapshot {
    /// C(Σ) at `height`. Restore recomputes and MUST match — refuse-on-mismatch.
    pub app_hash: [u8; 32],
    pub height: u64,
    pub state: StateSnapshot,
    /// Node-level indexes (derivable by replaying from genesis; snapshotted so a
    /// restart doesn't break wallets mid-scan).
    pub pool_notes: Vec<(H256, Vec<u8>)>,
    pub receipts: Vec<([u8; 32], String)>,
    pub mempool: Vec<SignedTx>,
    pub validators: Vec<ValidatorDto>,
    pub current_epoch: u64,
    pub highest_issued_epoch: u64,
}

/// U4/v0.12: pre-fee `StateSnapshot` layout (no `fees_burned`) — read-only mirror
/// so a node upgrading in place restores its existing `snapshot.bin` instead of
/// replaying from genesis. New snapshots are written as `snapshot2.bin` (bincode is
/// positional — appending a field silently breaks old bytes, so the FILENAME is the
/// version tag).
#[derive(Deserialize)]
struct LegacyStateSnapshot {
    pub height: u64,
    pub time: hk_primitives::Timestamp,
    pub accounts: std::collections::BTreeMap<hk_primitives::AccountId, hk_state::Account>,
    pub balances:
        std::collections::BTreeMap<(hk_primitives::AccountId, hk_primitives::AssetId), hk_primitives::Amount>,
    pub mandates: hk_mandate::MandateTree,
    pub root_funding: std::collections::BTreeMap<hk_primitives::MandateId, hk_primitives::AccountId>,
    pub channels: std::collections::BTreeMap<hk_primitives::ChannelId, hk_state::Channel>,
    pub pool: hk_state::pool::PoolState,
}

#[derive(Deserialize)]
struct LegacyNodeSnapshot {
    pub app_hash: [u8; 32],
    pub height: u64,
    pub state: LegacyStateSnapshot,
    pub pool_notes: Vec<(H256, Vec<u8>)>,
    pub receipts: Vec<([u8; 32], String)>,
    pub mempool: Vec<SignedTx>,
    pub validators: Vec<ValidatorDto>,
    pub current_epoch: u64,
    pub highest_issued_epoch: u64,
}

impl From<LegacyNodeSnapshot> for NodeSnapshot {
    fn from(l: LegacyNodeSnapshot) -> Self {
        NodeSnapshot {
            app_hash: l.app_hash,
            height: l.height,
            state: StateSnapshot {
                height: l.state.height,
                time: l.state.time,
                accounts: l.state.accounts,
                balances: l.state.balances,
                mandates: l.state.mandates,
                root_funding: l.state.root_funding,
                channels: l.state.channels,
                pool: l.state.pool,
                fees_burned: 0, // pre-fee history by definition
            },
            pool_notes: l.pool_notes,
            receipts: l.receipts,
            mempool: l.mempool,
            validators: l.validators,
            current_epoch: l.current_epoch,
            highest_issued_epoch: l.highest_issued_epoch,
        }
    }
}

pub struct NodeStore {
    blocks_dir: PathBuf,
    snapshot_path: PathBuf,
    legacy_snapshot_path: PathBuf,
    wal_path: PathBuf,
}

impl NodeStore {
    pub fn open(home: &Path) -> Result<Self> {
        let blocks_dir = home.join("blocks");
        std::fs::create_dir_all(&blocks_dir)
            .wrap_err_with(|| format!("creating block dir {}", blocks_dir.display()))?;
        Ok(Self {
            blocks_dir,
            snapshot_path: home.join("snapshot2.bin"),
            legacy_snapshot_path: home.join("snapshot.bin"),
            wal_path: home.join("mempool.wal"),
        })
    }

    fn block_path(&self, height: u64) -> PathBuf {
        self.blocks_dir.join(format!("b{height:012}.bin"))
    }

    // ---- block log ----

    pub fn save_block(&self, block: &StoredBlock) -> Result<()> {
        let bytes = bincode::serialize(block)?;
        write_atomic(&self.block_path(block.height), &bytes)
            .wrap_err_with(|| format!("writing block {}", block.height))
    }

    pub fn load_block(&self, height: u64) -> Result<Option<StoredBlock>> {
        let path = self.block_path(height);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)?;
        let block: StoredBlock = bincode::deserialize(&bytes)
            .wrap_err_with(|| format!("corrupt block file {}", path.display()))?;
        Ok(Some(block))
    }

    /// All stored heights, ascending.
    pub fn block_heights(&self) -> Result<Vec<u64>> {
        let mut hs = Vec::new();
        for entry in std::fs::read_dir(&self.blocks_dir)? {
            let name = entry?.file_name();
            let name = name.to_string_lossy();
            if let Some(num) = name.strip_prefix('b').and_then(|s| s.strip_suffix(".bin")) {
                if let Ok(h) = num.parse::<u64>() {
                    hs.push(h);
                }
            }
        }
        hs.sort_unstable();
        Ok(hs)
    }

    // ---- snapshot ----

    pub fn save_snapshot(&self, snap: &NodeSnapshot) -> Result<()> {
        let bytes = bincode::serialize(snap)?;
        write_atomic(&self.snapshot_path, &bytes).wrap_err("writing snapshot")
    }

    pub fn load_snapshot(&self) -> Result<Option<NodeSnapshot>> {
        // Both formats may coexist on a node that has run v0.11 and v0.12 binaries
        // (e.g. a rolled-back voter: a stale snapshot2.bin from the newer binary next
        // to a FRESHER snapshot.bin written by the older one afterwards). Never let
        // the file format decide — load whatever is present and resume from the
        // HIGHEST height. (Lesson from the aborted v0.12.1 roll, 2026-09-02.)
        let v2: Option<NodeSnapshot> = if self.snapshot_path.exists() {
            let bytes = std::fs::read(&self.snapshot_path)?;
            Some(bincode::deserialize(&bytes).wrap_err("corrupt snapshot2.bin")?)
        } else {
            None
        };
        let legacy: Option<NodeSnapshot> = if self.legacy_snapshot_path.exists() {
            let bytes = std::fs::read(&self.legacy_snapshot_path)?;
            let snap: LegacyNodeSnapshot =
                bincode::deserialize(&bytes).wrap_err("corrupt snapshot.bin (legacy)")?;
            Some(snap.into())
        } else {
            None
        };
        Ok(match (v2, legacy) {
            (Some(a), Some(b)) => Some(if b.height > a.height { b } else { a }),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        })
    }

    // ---- mempool WAL ----

    /// Append one admitted tx: u32-LE length + bincode frame.
    pub fn wal_append(&self, tx: &SignedTx) -> Result<()> {
        let frame = bincode::serialize(tx)?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.wal_path)?;
        f.write_all(&(frame.len() as u32).to_le_bytes())?;
        f.write_all(&frame)?;
        Ok(())
    }

    /// Load every intact frame; a torn tail (crash mid-append) ends the stream.
    pub fn wal_load(&self) -> Vec<SignedTx> {
        let Ok(bytes) = std::fs::read(&self.wal_path) else { return Vec::new() };
        let mut txs = Vec::new();
        let mut off = 0usize;
        while off + 4 <= bytes.len() {
            let len = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            if off + len > bytes.len() {
                break; // torn tail
            }
            match bincode::deserialize::<SignedTx>(&bytes[off..off + len]) {
                Ok(tx) => txs.push(tx),
                Err(_) => break,
            }
            off += len;
        }
        txs
    }

    /// Rewrite the WAL to exactly the given txs (called at snapshot time, after
    /// included txs were pruned — the snapshot carries them; the WAL restarts).
    pub fn wal_reset<'a>(&self, txs: impl IntoIterator<Item = &'a SignedTx>) -> Result<()> {
        let mut buf = Vec::new();
        for tx in txs {
            let frame = bincode::serialize(tx)?;
            buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            buf.extend_from_slice(&frame);
        }
        write_atomic(&self.wal_path, &buf).wrap_err("resetting mempool WAL")
    }
}

/// Atomic write: tmp + fsync + rename (same discipline as the signer state file —
/// a crash leaves the old or the new file, never a torn one).
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use hk_state::tx::Tx;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "hk-store-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn dummy_tx(nonce: u64) -> SignedTx {
        SignedTx {
            sender: H256([7; 32]),
            nonce,
            payload: Tx::Transfer { to: H256([8; 32]), asset: H256([9; 32]), amount: 5 },
            next_auth: H256([1; 32]),
            lamport_pk: vec![2; 64],
            sig: vec![3; 64],
        }
    }

    fn dummy_cert(height: u64) -> RawCommitCertificate {
        use hk_consensus::{HkHeight, HkValueId};
        use malachitebft_app_channel::app::types::core::Round;
        RawCommitCertificate {
            height: HkHeight::new(height),
            round: Round::ZERO,
            value_id: HkValueId::new([0xAB; 32]),
            commit_signatures: vec![crate::codec::RawCommitSignature {
                address: hk_consensus::HkAddress::new([1; 20]),
                signature: vec![0xCD; 40],
            }],
        }
    }

    #[test]
    fn block_roundtrip_and_height_listing() {
        let home = tmpdir("blocks");
        let store = NodeStore::open(&home).unwrap();
        for h in [3u64, 1, 2] {
            store
                .save_block(&StoredBlock {
                    height: h,
                    value_bytes: vec![h as u8; 10],
                    certificate: dummy_cert(h),
                    agg_valid: h == 2,
                })
                .unwrap();
        }
        assert_eq!(store.block_heights().unwrap(), vec![1, 2, 3], "ascending order");
        let b2 = store.load_block(2).unwrap().expect("stored");
        assert_eq!(b2.height, 2);
        assert_eq!(b2.value_bytes, vec![2u8; 10]);
        assert!(b2.agg_valid);
        assert!(store.load_block(99).unwrap().is_none());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn snapshot_roundtrip() {
        let home = tmpdir("snap");
        let store = NodeStore::open(&home).unwrap();
        assert!(store.load_snapshot().unwrap().is_none(), "fresh home has no snapshot");
        let st = hk_state::State::default();
        let snap = NodeSnapshot {
            app_hash: st.state_commitment().0,
            height: 0,
            state: st.to_snapshot(),
            pool_notes: vec![(H256([5; 32]), vec![1, 2, 3])],
            receipts: vec![([6; 32], "ok: 1 event(s)".into())],
            mempool: vec![dummy_tx(4)],
            validators: Vec::new(),
            current_epoch: 2,
            highest_issued_epoch: 3,
        };
        store.save_snapshot(&snap).unwrap();
        let got = store.load_snapshot().unwrap().expect("snapshot loads");
        assert_eq!(got.app_hash, snap.app_hash);
        assert_eq!(got.height, 0);
        assert_eq!(got.pool_notes.len(), 1);
        assert_eq!(got.receipts[0].1, "ok: 1 event(s)");
        assert_eq!(got.mempool[0].nonce, 4);
        assert_eq!(got.current_epoch, 2);
        // The restored Σ recomputes to the recorded commitment (the restore guard).
        let restored = hk_state::State::from_snapshot(got.state);
        assert_eq!(restored.state_commitment().0, got.app_hash);
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn wal_appends_survive_and_torn_tail_is_tolerated() {
        let home = tmpdir("wal");
        let store = NodeStore::open(&home).unwrap();
        store.wal_append(&dummy_tx(0)).unwrap();
        store.wal_append(&dummy_tx(1)).unwrap();
        assert_eq!(store.wal_load().len(), 2);

        // Simulate a crash mid-append: garbage length prefix + partial frame.
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(home.join("mempool.wal"))
                .unwrap();
            f.write_all(&(1000u32).to_le_bytes()).unwrap();
            f.write_all(&[0xEE; 7]).unwrap();
        }
        let txs = store.wal_load();
        assert_eq!(txs.len(), 2, "torn tail ignored, intact frames kept");
        assert_eq!(txs[1].nonce, 1);

        // Reset rewrites cleanly.
        let mut q = VecDeque::new();
        q.push_back(dummy_tx(9));
        store.wal_reset(&q).unwrap();
        let txs = store.wal_load();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].nonce, 9);
        std::fs::remove_dir_all(&home).ok();
    }
}
