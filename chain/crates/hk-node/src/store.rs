//! NodeStore — P3.0/WS-B persistence: block log + node snapshots + mempool WAL.
//!
//! Design (docs/P3-BUILD-PLAN.md WS-B):
//! - **Block log**: one bincode file per committed height under `<home>/blocks/`
//!   (`b{height:012}.bin`), written atomically AFTER the block fully applied. Each
//!   entry carries the raw batch bytes + the commit certificate (the sync codec's
//!   DTO) + this node's aggregate verdict, so replay reproduces the exact same
//!   receipts WITHOUT needing a prover connection.
//! - **Snapshot**: every [`SNAPSHOT_EVERY`] blocks, the full node image
//!   (`snapshot3.bin`; `snapshot2.bin`/`snapshot.bin` are read for in-place upgrades —
//!   the file name is the format version): Σ (via `hk_state::StateSnapshot`), the pool-note index,
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
//! same discipline as the signer state); WAL appends are fsynced per admission
//! since H6 (v0.13.2, `HK_WAL_FSYNC=0` to trade that for throughput on benches).
//!
//! **C2.8 (v0.16.0) — segmented block log + retention.** One file per height forever
//! meant ~30k new files a day on testnet-1 (75k after three days). The hot tail keeps
//! the per-height atomic write (crash-safe, simple); once a run of [`SEGMENT_SPAN`]
//! heights lies entirely at-or-below the latest snapshot it is **compacted** into one
//! segment file `blocks/seg{id:09}.hkb`:
//!
//! ```text
//! "HKS1" | frame* | index[SPAN] u64 LE offsets (0 = absent) | u64 LE index_offset | "HKS1"
//! frame  = u32 LE len | bincode(StoredBlock)
//! ```
//!
//! A lookup is three small reads (trailer → index slot → frame); a listing is one
//! 8 KB index per segment instead of one directory entry per height. Compaction is
//! crash-safe: the segment is written tmp+fsync+rename FIRST, the per-height files
//! are deleted AFTER, and a reader always prefers the per-height file while both
//! exist (identical bytes). A crash between the two steps leaves duplicates that the
//! next compaction pass simply finishes deleting. Existing nodes migrate in the
//! background at startup (the `hk-compact` thread), oldest segment first.
//!
//! **Retention** (`HK_RETAIN_BLOCKS=N`, default 0 = keep everything): whole segments
//! whose every height is older than `tip - N` are deleted at snapshot time. A pruned
//! node serves value-sync only from its first kept height (`hk_chainInfo.history.disk_from`
//! moves up) — voters and the public gateway keep everything; the knob exists for
//! disk-constrained observers, and the honest cost is documented where it is set.

use std::io::{Read, Seek, SeekFrom, Write};
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

/// C2.8: heights per block-log segment. 1,024 × ~2–50 KB ≈ a few MB per file;
/// segment id = height / SPAN.
pub const SEGMENT_SPAN: u64 = 1024;
const SEGMENT_MAGIC: &[u8; 4] = b"HKS1";
const SEGMENT_TRAILER: usize = 8 + 4;
const SEGMENT_INDEX_BYTES: usize = (SEGMENT_SPAN as usize) * 8;

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

/// S2 (v0.16.0): the node-local search index on disk — a restart resumes indexing
/// above `through_height` instead of re-reading the whole block log. Never part of
/// C(Σ); derivable by anyone from the blocks.
#[derive(Serialize, Deserialize, Default)]
pub struct PersistedIndex {
    pub through_height: u64,
    /// txid → (height, index-in-block)
    pub tx: Vec<([u8; 32], u64, u32)>,
    /// account → its transactions (as sender or counterparty), commit order; the kind
    /// is the same name `hk_getTx` reports.
    pub acct: Vec<(hk_primitives::AccountId, Vec<([u8; 32], u64, String)>)>,
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

/// X1/v0.15: pre-registry `StateSnapshot` layout (v2: has `fees_burned`, no `assets`) —
/// read-only mirror for `snapshot2.bin`. The registry restores EMPTY from a v2 file;
/// on a network whose genesis registers assets the recomputed commitment then
/// differs from the recorded one and restore refuses (resync from genesis) — never
/// a silent divergence. New snapshots are written as `snapshot3.bin`.
#[derive(Deserialize)]
struct V2StateSnapshot {
    pub height: u64,
    pub time: hk_primitives::Timestamp,
    pub accounts: std::collections::BTreeMap<hk_primitives::AccountId, hk_state::Account>,
    pub balances:
        std::collections::BTreeMap<(hk_primitives::AccountId, hk_primitives::AssetId), hk_primitives::Amount>,
    pub mandates: hk_mandate::MandateTree,
    pub root_funding: std::collections::BTreeMap<hk_primitives::MandateId, hk_primitives::AccountId>,
    pub channels: std::collections::BTreeMap<hk_primitives::ChannelId, hk_state::Channel>,
    pub pool: hk_state::pool::PoolState,
    pub fees_burned: hk_primitives::Amount,
}

#[derive(Deserialize)]
struct V2NodeSnapshot {
    pub app_hash: [u8; 32],
    pub height: u64,
    pub state: V2StateSnapshot,
    pub pool_notes: Vec<(H256, Vec<u8>)>,
    pub receipts: Vec<([u8; 32], String)>,
    pub mempool: Vec<SignedTx>,
    pub validators: Vec<ValidatorDto>,
    pub current_epoch: u64,
    pub highest_issued_epoch: u64,
}

impl From<V2NodeSnapshot> for NodeSnapshot {
    fn from(l: V2NodeSnapshot) -> Self {
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
                fees_burned: l.state.fees_burned,
                assets: std::collections::BTreeMap::new(), // pre-registry history by definition
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
                assets: std::collections::BTreeMap::new(),
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
    v2_snapshot_path: PathBuf,
    legacy_snapshot_path: PathBuf,
    wal_path: PathBuf,
    /// R10 v2: lowest height of the gap-free block-file suffix reaching the tip
    /// (0 = unknown / nothing yet). Set by restore, advanced past any failed write;
    /// the explorer's `hk_getBlocks` reads it instead of listing 100k+ files per call.
    disk_min: std::sync::atomic::AtomicU64,
    /// C2.8: one compaction at a time (the startup migration thread and the
    /// snapshot-time pass may both want the same segment).
    compact_lock: std::sync::Mutex<()>,
    /// S2: the persisted search index (`index3.bin`).
    index_path: PathBuf,
}

impl NodeStore {
    pub fn open(home: &Path) -> Result<Self> {
        let blocks_dir = home.join("blocks");
        std::fs::create_dir_all(&blocks_dir)
            .wrap_err_with(|| format!("creating block dir {}", blocks_dir.display()))?;
        Ok(Self {
            blocks_dir,
            snapshot_path: home.join("snapshot3.bin"),
            v2_snapshot_path: home.join("snapshot2.bin"),
            legacy_snapshot_path: home.join("snapshot.bin"),
            wal_path: home.join("mempool.wal"),
            disk_min: std::sync::atomic::AtomicU64::new(0),
            compact_lock: std::sync::Mutex::new(()),
            index_path: home.join("index3.bin"),
        })
    }

    pub fn set_disk_min(&self, h: u64) {
        self.disk_min.store(h, std::sync::atomic::Ordering::Relaxed);
    }

    /// 0 = unknown (persistence just opened, or nothing servable yet).
    pub fn disk_min(&self) -> u64 {
        self.disk_min.load(std::sync::atomic::Ordering::Relaxed)
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

    /// A block by height: the per-height file if it still exists (the hot tail, or a
    /// compaction that has not finished deleting), else its segment, else `None`.
    pub fn load_block(&self, height: u64) -> Result<Option<StoredBlock>> {
        let path = self.block_path(height);
        match std::fs::read(&path) {
            Ok(bytes) => {
                let block: StoredBlock = bincode::deserialize(&bytes)
                    .wrap_err_with(|| format!("corrupt block file {}", path.display()))?;
                return Ok(Some(block));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).wrap_err_with(|| format!("reading {}", path.display())),
        }
        self.load_from_segment(height)
    }

    /// All stored heights, ascending — per-height files plus every segment's index.
    pub fn block_heights(&self) -> Result<Vec<u64>> {
        let mut hs = Vec::new();
        let mut segments = Vec::new();
        for entry in std::fs::read_dir(&self.blocks_dir)? {
            let name = entry?.file_name();
            let name = name.to_string_lossy();
            if let Some(num) = name.strip_prefix('b').and_then(|s| s.strip_suffix(".bin")) {
                if let Ok(h) = num.parse::<u64>() {
                    hs.push(h);
                }
            } else if let Some(num) = name.strip_prefix("seg").and_then(|s| s.strip_suffix(".hkb")) {
                if let Ok(id) = num.parse::<u64>() {
                    segments.push(id);
                }
            }
        }
        for id in segments {
            match self.segment_heights(id) {
                Ok(list) => hs.extend(list),
                Err(e) => tracing::warn!(%e, segment = id, "unreadable block-log segment (skipped)"),
            }
        }
        hs.sort_unstable();
        hs.dedup();
        Ok(hs)
    }

    // ---- C2.8: segments ----

    fn segment_path(&self, id: u64) -> PathBuf {
        self.blocks_dir.join(format!("seg{id:09}.hkb"))
    }

    /// Read `(index_offset, file)` of a segment, validating both magics.
    fn open_segment(&self, id: u64) -> Result<Option<(std::fs::File, u64)>> {
        let path = self.segment_path(id);
        let mut f = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).wrap_err_with(|| format!("opening {}", path.display())),
        };
        let len = f.metadata()?.len();
        if len < (4 + SEGMENT_INDEX_BYTES + SEGMENT_TRAILER) as u64 {
            return Err(eyre::eyre!("segment {} is truncated ({len} bytes)", path.display()));
        }
        let mut head = [0u8; 4];
        f.read_exact(&mut head)?;
        let mut trailer = [0u8; SEGMENT_TRAILER];
        f.seek(SeekFrom::End(-(SEGMENT_TRAILER as i64)))?;
        f.read_exact(&mut trailer)?;
        if &head != SEGMENT_MAGIC || &trailer[8..12] != SEGMENT_MAGIC {
            return Err(eyre::eyre!("segment {} has a bad magic", path.display()));
        }
        let index_offset = u64::from_le_bytes(trailer[..8].try_into().unwrap());
        if index_offset + SEGMENT_INDEX_BYTES as u64 + SEGMENT_TRAILER as u64 != len {
            return Err(eyre::eyre!("segment {} index offset does not match its length", path.display()));
        }
        Ok(Some((f, index_offset)))
    }

    fn load_from_segment(&self, height: u64) -> Result<Option<StoredBlock>> {
        let id = height / SEGMENT_SPAN;
        let Some((mut f, index_offset)) = self.open_segment(id)? else { return Ok(None) };
        let slot = (height % SEGMENT_SPAN) * 8;
        f.seek(SeekFrom::Start(index_offset + slot))?;
        let mut off = [0u8; 8];
        f.read_exact(&mut off)?;
        let off = u64::from_le_bytes(off);
        if off == 0 {
            return Ok(None);
        }
        f.seek(SeekFrom::Start(off))?;
        let mut len = [0u8; 4];
        f.read_exact(&mut len)?;
        let len = u32::from_le_bytes(len) as usize;
        let mut bytes = vec![0u8; len];
        f.read_exact(&mut bytes)?;
        let block: StoredBlock = bincode::deserialize(&bytes)
            .wrap_err_with(|| format!("corrupt frame for height {height} in segment {id}"))?;
        if block.height != height {
            return Err(eyre::eyre!("segment {id} slot for {height} holds height {}", block.height));
        }
        Ok(Some(block))
    }

    /// Heights present in one segment (from its index; one 8 KB read).
    fn segment_heights(&self, id: u64) -> Result<Vec<u64>> {
        let Some((mut f, index_offset)) = self.open_segment(id)? else { return Ok(Vec::new()) };
        f.seek(SeekFrom::Start(index_offset))?;
        let mut index = vec![0u8; SEGMENT_INDEX_BYTES];
        f.read_exact(&mut index)?;
        let base = id * SEGMENT_SPAN;
        Ok(index
            .chunks_exact(8)
            .enumerate()
            .filter(|(_, c)| u64::from_le_bytes((*c).try_into().unwrap()) != 0)
            .map(|(i, _)| base + i as u64)
            .collect())
    }

    /// Pack the per-height files of segment `id` into one file, then delete them.
    /// Idempotent: an existing segment is trusted and only the leftovers are removed.
    /// Returns the number of per-height files retired.
    pub fn compact_segment(&self, id: u64) -> Result<usize> {
        let _guard = self.compact_lock.lock().unwrap_or_else(|e| e.into_inner());
        let base = id * SEGMENT_SPAN;
        let seg_path = self.segment_path(id);
        if !seg_path.exists() {
            let mut body: Vec<u8> = Vec::new();
            body.extend_from_slice(SEGMENT_MAGIC);
            let mut index = vec![0u64; SEGMENT_SPAN as usize];
            let mut present = 0usize;
            for i in 0..SEGMENT_SPAN {
                let h = base + i;
                let bytes = match std::fs::read(self.block_path(h)) {
                    Ok(b) => b,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e).wrap_err_with(|| format!("reading block {h} for compaction")),
                };
                // Refuse to pack a corrupt file: replay would have refused it too.
                let _: StoredBlock = bincode::deserialize(&bytes)
                    .wrap_err_with(|| format!("corrupt block file for height {h} — not compacting segment {id}"))?;
                index[i as usize] = body.len() as u64;
                body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                body.extend_from_slice(&bytes);
                present += 1;
            }
            if present == 0 {
                return Ok(0);
            }
            let index_offset = body.len() as u64;
            for off in &index {
                body.extend_from_slice(&off.to_le_bytes());
            }
            body.extend_from_slice(&index_offset.to_le_bytes());
            body.extend_from_slice(SEGMENT_MAGIC);
            write_atomic(&seg_path, &body).wrap_err_with(|| format!("writing segment {id}"))?;
            // Read back through the real path before deleting anything.
            let check = base + (index.iter().position(|o| *o != 0).unwrap_or(0) as u64);
            if self.load_from_segment(check)?.is_none() {
                return Err(eyre::eyre!("segment {id} verification read failed — per-height files kept"));
            }
        }
        let mut retired = 0usize;
        for i in 0..SEGMENT_SPAN {
            match std::fs::remove_file(self.block_path(base + i)) {
                Ok(()) => retired += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).wrap_err_with(|| format!("removing block file {}", base + i)),
            }
        }
        Ok(retired)
    }

    /// Segment ids whose whole span lies at-or-below `through` and that still have
    /// per-height files (candidates for compaction), ascending.
    pub fn compactable_segments(&self, through: u64) -> Result<Vec<u64>> {
        let mut ids = std::collections::BTreeSet::new();
        for entry in std::fs::read_dir(&self.blocks_dir)? {
            let name = entry?.file_name();
            let name = name.to_string_lossy();
            if let Some(num) = name.strip_prefix('b').and_then(|s| s.strip_suffix(".bin")) {
                if let Ok(h) = num.parse::<u64>() {
                    let id = h / SEGMENT_SPAN;
                    if (id + 1) * SEGMENT_SPAN - 1 <= through {
                        ids.insert(id);
                    }
                }
            }
        }
        Ok(ids.into_iter().collect())
    }

    /// Compact the oldest compactable segment (≤ `through`) on a detached thread; a
    /// no-op if a compaction is already running. Called at snapshot time so the
    /// commit path never waits on a multi-MB rewrite.
    pub fn compact_one_background(self: &std::sync::Arc<Self>, through: u64) {
        if self.compact_lock.try_lock().is_err() {
            return;
        }
        let store = self.clone();
        let _ = std::thread::Builder::new().name("hk-compact".into()).spawn(move || {
            match store.compactable_segments(through) {
                Ok(ids) => {
                    if let Some(&id) = ids.first() {
                        match store.compact_segment(id) {
                            Ok(n) => tracing::info!(segment = id, files = n, "block log: segment compacted"),
                            Err(e) => tracing::warn!(%e, segment = id, "block log: compaction failed (files kept)"),
                        }
                    }
                }
                Err(e) => tracing::warn!(%e, "block log: could not list segments"),
            }
        });
    }

    /// Retention (`HK_RETAIN_BLOCKS`): delete whole segments whose every height is
    /// older than `tip - retain`. Never touches per-height files or the segment that
    /// holds `tip - retain` itself. Returns the first height still on disk after
    /// pruning (`None` = nothing pruned).
    pub fn prune_below(&self, tip: u64, retain: u64) -> Result<Option<u64>> {
        if retain == 0 || tip <= retain {
            return Ok(None);
        }
        let keep_from = tip - retain;
        let keep_seg = keep_from / SEGMENT_SPAN;
        let mut pruned = false;
        for entry in std::fs::read_dir(&self.blocks_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(num) = name.strip_prefix("seg").and_then(|s| s.strip_suffix(".hkb")) {
                if let Ok(id) = num.parse::<u64>() {
                    if id < keep_seg {
                        std::fs::remove_file(entry.path())
                            .wrap_err_with(|| format!("pruning segment {id}"))?;
                        pruned = true;
                    }
                }
            }
        }
        Ok(pruned.then_some(keep_seg * SEGMENT_SPAN))
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
        let mut candidates: Vec<NodeSnapshot> = Vec::new();
        if self.snapshot_path.exists() {
            let bytes = std::fs::read(&self.snapshot_path)?;
            candidates.push(bincode::deserialize(&bytes).wrap_err("corrupt snapshot3.bin")?);
        }
        if self.v2_snapshot_path.exists() {
            let bytes = std::fs::read(&self.v2_snapshot_path)?;
            let snap: V2NodeSnapshot = bincode::deserialize(&bytes).wrap_err("corrupt snapshot2.bin")?;
            candidates.push(snap.into());
        }
        if self.legacy_snapshot_path.exists() {
            let bytes = std::fs::read(&self.legacy_snapshot_path)?;
            let snap: LegacyNodeSnapshot =
                bincode::deserialize(&bytes).wrap_err("corrupt snapshot.bin (legacy)")?;
            candidates.push(snap.into());
        }
        // Highest height wins regardless of format (a rolled-back voter may have a
        // fresher older-format file next to a stale newer one).
        Ok(candidates.into_iter().max_by_key(|s| s.height))
    }

    // ---- S2: persisted search index ----

    /// Persist the node-local search index (atomic; `index3.bin`).
    pub fn save_index(&self, ix: &PersistedIndex) -> Result<()> {
        let bytes = bincode::serialize(ix)?;
        write_atomic(&self.index_path, &bytes).wrap_err("writing search index")
    }

    /// The persisted search index, if any. A corrupt file is treated as absent (the
    /// index is derivable: the background pass rebuilds it from the block log).
    pub fn load_index(&self) -> Option<PersistedIndex> {
        let bytes = std::fs::read(&self.index_path).ok()?;
        match bincode::deserialize::<PersistedIndex>(&bytes) {
            Ok(ix) => Some(ix),
            Err(e) => {
                tracing::warn!(%e, "index3.bin unreadable — the search index will be rebuilt from the block log");
                None
            }
        }
    }

    // ---- S3: snapshot rotation knob ----

    /// Keep the previous snapshot as `snapshot3.prev.bin` (`HK_KEEP_PREV_SNAPSHOT=1`):
    /// an operator's escape hatch if the newest image ever fails its commitment check.
    pub fn rotate_snapshot_if_configured(&self) {
        if std::env::var("HK_KEEP_PREV_SNAPSHOT").map(|v| v == "1").unwrap_or(false) && self.snapshot_path.exists() {
            let prev = self.snapshot_path.with_file_name("snapshot3.prev.bin");
            if let Err(e) = std::fs::copy(&self.snapshot_path, &prev) {
                tracing::warn!(%e, "could not keep the previous snapshot");
            }
        }
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
        // H6 (v0.13.2): an admission the client was told "accepted" survives a power
        // cut. One fdatasync per admission by default; `HK_WAL_FSYNC=0` trades that
        // for throughput on benches (the storm harness) — never on a public node.
        if wal_fsync_enabled() {
            f.sync_data()?;
        }
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

    fn stored(h: u64) -> StoredBlock {
        StoredBlock { height: h, value_bytes: vec![(h % 251) as u8; 40 + (h % 7) as usize], certificate: dummy_cert(h), agg_valid: h % 3 == 0 }
    }

    #[test]
    fn c28_segment_compaction_roundtrip_and_idempotence() {
        let home = tmpdir("seg");
        let store = NodeStore::open(&home).unwrap();
        // segment 1 complete (1024..2047) with one hole, plus a hot tail in segment 2
        for h in (1024..2048).chain(2048..2060) {
            if h == 1500 { continue; }
            store.save_block(&stored(h)).unwrap();
        }
        assert_eq!(store.compactable_segments(3100).unwrap(), vec![1, 2], "both spans lie at-or-below 3100");
        assert_eq!(store.compactable_segments(2100).unwrap(), vec![1], "segment 2's span ends at 3071 — not yet");
        let retired = store.compact_segment(1).unwrap();
        assert_eq!(retired, 1023, "every per-height file of segment 1 retired");
        assert!(store.segment_path(1).exists());
        assert!(!store.block_path(1024).exists());
        // reads come from the segment now, holes stay holes, the tail is untouched
        let b = store.load_block(1024).unwrap().expect("first height");
        assert_eq!(b.height, 1024);
        let b = store.load_block(2047).unwrap().expect("last height");
        assert_eq!(b.value_bytes, stored(2047).value_bytes);
        assert!(b.agg_valid == (2047 % 3 == 0));
        assert!(store.load_block(1500).unwrap().is_none(), "the hole");
        assert!(store.load_block(2059).unwrap().is_some(), "hot tail per-height file");
        let hs = store.block_heights().unwrap();
        assert_eq!(hs.len(), 1023 + 12);
        assert_eq!(hs[0], 1024);
        assert!(!hs.contains(&1500));
        // idempotent: a second pass finds the segment and nothing to retire
        assert_eq!(store.compact_segment(1).unwrap(), 0);
        // a crash between write and delete: a per-height file reappears, the next pass retires it
        store.save_block(&stored(1030)).unwrap();
        assert_eq!(store.compact_segment(1).unwrap(), 1);
        assert!(store.load_block(1030).unwrap().is_some());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn c28_retention_prunes_whole_old_segments_only() {
        let home = tmpdir("prune");
        let store = NodeStore::open(&home).unwrap();
        for h in 0..3072 { store.save_block(&stored(h)).unwrap(); }
        for id in 0..3 { store.compact_segment(id).unwrap(); }
        assert_eq!(store.prune_below(3071, 0).unwrap(), None, "retain=0 keeps everything");
        // tip 3071, retain 1500 → keep_from 1571 → keep segment 1 and up; segment 0 goes
        assert_eq!(store.prune_below(3071, 1500).unwrap(), Some(1024));
        assert!(store.load_block(5).unwrap().is_none());
        assert!(store.load_block(1024).unwrap().is_some());
        assert_eq!(store.block_heights().unwrap().first().copied(), Some(1024));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn s2_index_roundtrip() {
        let home = tmpdir("index");
        let store = NodeStore::open(&home).unwrap();
        assert!(store.load_index().is_none());
        let ix = PersistedIndex { through_height: 42, tx: vec![([1; 32], 7, 0)], acct: vec![(H256([2; 32]), vec![([1; 32], 7, "transfer".into())])] };
        store.save_index(&ix).unwrap();
        let got = store.load_index().expect("index loads");
        assert_eq!(got.through_height, 42);
        assert_eq!(got.tx.len(), 1);
        assert_eq!(got.acct[0].1[0].2, "transfer");
        std::fs::write(home.join("index3.bin"), b"garbage").unwrap();
        assert!(store.load_index().is_none(), "corrupt index is treated as absent");
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

/// H6: WAL durability policy (read once). Default ON.
fn wal_fsync_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("HK_WAL_FSYNC").map(|v| v != "0").unwrap_or(true))
}
