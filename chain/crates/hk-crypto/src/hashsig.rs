//! hashsig — the hash-based signature primitive for HashKinetics consensus votes
//! and agent operational keys (0.9). Backed by the vendored `hbs-lms` crate
//! (RFC 8554 LMS/HSS) over **SHAKE-256**, consistent with the two-hash doctrine
//! (SHAKE outside circuits). Feature-gated behind `lms`.
//!
//! This is the SCMS operational-signing primitive: a STATEFUL hash signature whose
//! private key advances every time it signs (leaf index = one-time use). `hbs-lms`
//! exposes exactly the right shape — signing takes the key bytes plus a callback
//! that hands back the NEW key bytes, so state advancement is explicit and
//! persistable. HashKinetics' consensus rule (leaf index = nonce, equivocation =
//! slashable fraud proof) is designed to turn the classic stateful-HBS hazard into a
//! detectable, punishable event (a reused leaf is visible on-chain today; the slashing
//! path is specified, not built).
//!
//! Parameter set here: LM-OTS W2 + LMS H5 (32 signatures/tree) over SHAKE-256 — a
//! small tree suitable for KATs and short-lived session keys. Consensus validators
//! use a taller HSS multi-tree (see docs/HASHSIG-CONSENSUS-SWAP.md).
//!
//! ⚠ Reserve-then-sign: production signers MUST persist the advanced key bytes BEFORE
//! releasing the signature. `sign` does exactly that once a state file is attached
//! (`attach_persistence`); an unattached signer (tests, short-lived session keys) only
//! advances in memory.
//!
//! Durability model (R16, 2026-09-22): "persisted" means the bytes AND the directory
//! entry are fsynced (`crate::fsutil::write_atomic`, shared with every other counter file
//! since R17). What that guarantees: after any crash, power loss
//! or reset the file holds a position ≥ every signature ever released. What it cannot
//! guarantee: storage that acknowledges fsync without honouring it, or a state file
//! restored from an older snapshot/backup — those are operational failures, and a
//! reused leaf is visible on-chain (the slashing path is specified, not built); a floor
//! from the node's own evidence and a reservation window are the follow-ups.
//! `attach_persistence_with_floor` lets the node add its own evidence of spent leaves.
//!
//! What a present state file may do (HR-7, v0.19.12): it resumes the tree only when it is
//! this key's. A file that cannot be read, is truncated, damaged or another key's never
//! resumes the tree (a short file used to fall through to leaf 0), and it does
//! not stop the node either: the tree is retired as used up, the damaged bytes are kept
//! beside the file when they can be read (an unreadable file leaves nothing to copy), the
//! file is rewritten with the record a used-up tree leaves, and the node moves on through
//! key rotation.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use hbs_lms::{
    keygen, verify as hss_verify, HssParameter, HssSigningSession, LmotsAlgorithm, LmsAlgorithm,
    Seed, Shake256_256, MAX_HSS_SIGNATURE_LENGTH,
};

use crate::fsutil::write_atomic;
use crate::hash::shake256_n;

type H = Shake256_256;

const DOM_HASHSIG_SEED: &str = "hk/v1/hashsig-seed";

/// Consensus-grade capacity: two-level HSS (W2/H10 over W2/H5) over SHAKE-256 =
/// 2^15 = 32,768 signatures per validator key (≈ 3 h at 3 sigs/s; validators rotate to
/// a fresh tree under the SLH-DSA root before exhaustion). The top tree is built at
/// keygen; bottom trees are built lazily (once per 32 signatures). See
/// docs/HASHSIG-CONSENSUS-SWAP.md for the parameter rationale, `generate_consensus`
/// for the parameters themselves, and `CONSENSUS_SIG_LEN` for the signature length
/// they fix.
pub const CONSENSUS_CAPACITY: u64 = 1 << 15;

/// Aux-data cache size (bytes). hbs-lms caches upper Merkle-tree nodes here so signing
/// is O(tree-height) instead of O(2^height) — the difference between ~800 ms/sig and
/// ~tens of ms/sig for our H10 trees. 256 KiB comfortably caches useful levels.
///
/// R15 (2026-09-08, found by testnet-1 seat #1): until v0.18.2 this cache was silently
/// DISCARDED at every signature — hbs-lms compared its HMAC against everything after the
/// stored layers, and this buffer is longer than the finalized cache — so every vote
/// rebuilt the H10 authentication path from ~1,000 LM-OTS key generations (~450 ms).
/// Fixed in the vendored crate (`hss/aux.rs`), and the signer now keeps the expanded key
/// alive between signatures (`HssSigningSession`) instead of rebuilding the bottom tree
/// and re-signing its public key on every call.
pub const AUX_CACHE_SIZE: usize = 256 * 1024;

/// RZ-1 (external report 2026-10-14, fixed 2026-10-22): the shortest byte string that can be a
/// well-formed HSS signature over a 32-byte hash — one tree (level 0), LM-OTS W8 (34 chains),
/// LMS H5: 4 (level) + 4 (leaf) + 4 (LM-OTS type) + 32 (randomizer) + 32·34 (chains) + 4 (LMS
/// type) + 32·5 (path) = 1,296 bytes. `verify` refuses anything shorter before the parser sees
/// it. (The parser is total since the same fix; the floor is the cheap first refusal.)
pub const MIN_SIG_LEN: usize = 4 + 4 + 4 + 32 + 32 * 34 + 4 + 32 * 5;

/// The longest HSS signature the vendored crate can represent (eight levels of the tallest
/// trees, its own bound). `verify` refuses anything longer before the parser sees it.
pub const MAX_SIG_LEN: usize = MAX_HSS_SIGNATURE_LENGTH;

/// The exact length of a signature from a `generate_consensus` key — two levels, LM-OTS W2 (133
/// chains over a 32-byte hash), LMS H10 over H5: 4 (level) + [4 + (4 + 32 + 32·133) + 4 + 32·10
/// + 56] (the top tree's signature over the bottom public key, and that key) + [4 + (4 + 32 +
/// 32·133) + 4 + 32·5] (the bottom signature) = 9,140 bytes. Every consensus key is built by
/// `generate_consensus` (`HkPriv::from_seed` is the only path: genesis, keygen, rotation), so
/// every honest vote, proposal, part, extension and commit signature has exactly this length —
/// the consensus verifier refuses any other length before parsing a byte (RZ-1).
pub const CONSENSUS_SIG_LEN: usize =
    4 + (4 + (4 + 32 + 32 * 133) + 4 + 32 * 10 + 56) + (4 + (4 + 32 + 32 * 133) + 4 + 32 * 5);

/// A stateful hash-based signer. `state` is the LMS/HSS private key bytes (advances on
/// every `sign`); `aux` is the hbs-lms authentication-path cache (empty ⇒ no cache);
/// `capacity` is the total signatures the tree can ever produce; `persist`, when set,
/// is the file the monotone state is durably written to BEFORE each signature is
/// released (reserve-then-sign — no reuse under any failure that preserves the last
/// durable write).
pub struct HashSigner {
    state: Vec<u8>,
    aux: Vec<u8>,
    used: u64,
    capacity: u64,
    persist: Option<PathBuf>,
    /// The expanded HSS key kept between signatures (R15). Always derived from `state`;
    /// dropped whenever `state` is replaced from outside or a persistence write fails.
    session: Option<HssSigningSession<H>>,
    /// HR-7 (v0.19.12): the account of a damaged or foreign state file the last attach
    /// retired, kept until the caller takes it to log (`take_damage_report`; this crate does
    /// not log).
    damage_report: Option<String>,
}

/// Public verifying key bytes (LMS/HSS public key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashSigPublic(pub Vec<u8>);

/// `aux_size == 0` ⇒ no cache (fine for tiny H5 keys). Otherwise keygen fills an
/// `aux_size`-byte cache that signing reuses.
fn gen_with(
    params: &[HssParameter<H>],
    capacity: u64,
    aux_size: usize,
    seed32: &[u8; 32],
) -> (HashSigner, HashSigPublic) {
    let mut seed = Seed::<H>::default();
    let need = seed.as_mut_slice().len();
    let expanded = shake256_n(DOM_HASHSIG_SEED, &[seed32], need);
    seed.as_mut_slice().copy_from_slice(&expanded);

    let mut aux = vec![0u8; aux_size];
    let (sk, vk) = if aux_size > 0 {
        let mut a: &mut [u8] = &mut aux;
        keygen::<H>(params, &seed, Some(&mut a)).expect("hbs-lms keygen (aux)")
    } else {
        keygen::<H>(params, &seed, None).expect("hbs-lms keygen")
    };
    (
        HashSigner {
            state: sk.as_slice().to_vec(),
            aux,
            used: 0,
            capacity,
            persist: None,
            session: None,
            damage_report: None,
        },
        HashSigPublic(vk.as_slice().to_vec()),
    )
}

/// The key state the vendored crate leaves after the LAST leaf of a tree: its `increment`
/// refuses to move past the final leaf and wipes the key instead — counter 0, every
/// parameter slot the end marker `0xff`, an all-zero seed (`ReferenceImplPrivateKey::wipe`,
/// `hss/reference_impl_private_key.rs`). `sign` persists exactly this behind a header of
/// `capacity`, so `encode_blob(capacity, &exhausted_state(n))` is the honest record of a
/// used-up tree — and the record HR-7 (v0.19.12) writes over a damaged or foreign state file,
/// because every release reads it as `used == capacity` and signs nothing from it. Layout: the
/// 8-byte counter, 8 parameter slots (the crate's `MAX_ALLOWED_HSS_LEVELS`, 8 by default), then
/// the seed; `hr7_the_last_leaf_record_is_the_used_up_shape_and_attaches_unchanged` pins it
/// against a tree signed to its end.
fn exhausted_state(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    for b in v.iter_mut().skip(8).take(8) {
        *b = 0xff;
    }
    v
}

/// HR-7 (v0.19.12): keep the bytes of a damaged or foreign state file beside it, as
/// `<file name>.damaged-<unix seconds>`, before the file is rewritten. The copy is created new
/// (owner-only on Unix: the bytes may hold the tree's key), its data fsynced, and it is never
/// read again; its directory entry is made durable by the directory fsync of the rewrite that
/// follows in the same directory. A name already taken gets a `-<n>` suffix, so no earlier
/// copy is overwritten; a copy that cannot be written whole is removed.
fn keep_damaged_copy(path: &Path, bytes: &[u8]) -> std::io::Result<PathBuf> {
    use std::io::Write;
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "the state file path has no file name"))?
        .to_string_lossy()
        .into_owned();
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for n in 0u32..100 {
        let suffix = if n == 0 { String::new() } else { format!("-{n}") };
        let copy = path.with_file_name(format!("{name}.damaged-{secs}{suffix}"));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(&copy) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = std::fs::remove_file(&copy);
            return Err(e);
        }
        return Ok(copy);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "every damaged-copy name for this second is taken",
    ))
}

/// Serialize the monotone signer state as `used(8 LE) ‖ hbs-lms-state`.
fn encode_blob(used: u64, state: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + state.len());
    v.extend_from_slice(&used.to_le_bytes());
    v.extend_from_slice(state);
    v
}

// The state file is written by `crate::fsutil::write_atomic` (imported above): tmp +
// fsync(file) + rename + fsync(directory). The routine and its rationale (R16, external
// report 2026-09-22: the rename alone is not durable on POSIX, and a rolled-back state file
// means a reused leaf) lived here until R17 (reported 2026-10-06) found three sibling copies
// across the tree that had never received the directory fsync; it is now the one shared
// helper in `fsutil`, and the signature that depends on the write is still released only
// after it returns. Two places write the file: `sign`, before each signature is released,
// and `attach_persistence_with_floor`, once, when it retires a damaged or foreign file with
// the record of a used-up tree (HR-7, v0.19.12).

/// The leaf counter hbs-lms keeps inside the compressed private key (first 8 bytes, big
/// endian: `CompressedUsedLeafsIndexes::count`). It is the ground truth of the position;
/// `used` in our blob header mirrors it.
fn state_count(state: &[u8]) -> Option<u64> {
    state.get(..8).map(|b| u64::from_be_bytes(b.try_into().expect("8 bytes")))
}

/// The same compressed private key moved to leaf `count` (the key is seed + parameters +
/// position; nothing else changes). Used to fast-forward past leaves that may have been
/// consumed but whose record is not trusted — skipping leaves is always safe, reusing one
/// never is.
fn state_at(state: &[u8], count: u64) -> Vec<u8> {
    let mut v = state.to_vec();
    if v.len() >= 8 {
        v[..8].copy_from_slice(&count.to_be_bytes());
    }
    v
}

/// Deterministically generate a KAT/session keypair from a 32-byte seed.
/// Single LMS tree, H5 = 32 signatures — for tests and short-lived session keys.
pub fn generate(seed32: &[u8; 32]) -> (HashSigner, HashSigPublic) {
    let params = [HssParameter::<H>::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5)];
    gen_with(&params, 32, 0, seed32)
}

/// Deterministically generate a **consensus** keypair (two-level HSS, ~1M signatures)
/// from a 32-byte seed, WITH the aux cache so per-vote signing is fast. The public key
/// is recoverable from the seed; the advancing private state persists separately.
pub fn generate_consensus(seed32: &[u8; 32]) -> (HashSigner, HashSigPublic) {
    // HSS top H10 / bottom H5 = 2^15 ≈ 32,768 signatures/validator. The BOTTOM tree is
    // the one rebuilt frequently (every 32 sigs), so keeping it small (H5 = 32 leaves)
    // is what makes per-signature signing fast (~ms) instead of rebuilding a 1,024-leaf
    // H10 subtree every time. The top H10 is rebuilt rarely and its path is aux-cached.
    // 32K sigs ≈ many hours of blocks; validators rotate to a fresh tree via the
    // SLH-DSA root before exhaustion (SCMS, plan §3.3).
    let params = [
        HssParameter::<H>::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH10),
        HssParameter::<H>::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
    ];
    gen_with(&params, CONSENSUS_CAPACITY, AUX_CACHE_SIZE, seed32)
}

impl HashSigner {
    /// Signatures remaining before the key is exhausted (the built-in count cap).
    pub fn remaining(&self) -> u64 {
        self.capacity.saturating_sub(self.used)
    }

    /// Current private-key state bytes — persist these (atomically) after every sign
    /// so a restart does not reuse a leaf (directory-fsynced write; see the module header
    /// for what that covers). This IS the monotone signer state.
    pub fn state_bytes(&self) -> &[u8] {
        &self.state
    }

    /// Reload persisted state (e.g. on validator restart). The advancing hbs-lms
    /// private-key bytes encode the leaf position; the public key is unchanged.
    /// ⚠ Never load an OLDER state than the last one persisted — that reuses leaves.
    pub fn load_state(&mut self, bytes: Vec<u8>) {
        self.state = bytes;
        self.session = None;
    }

    /// Signatures already produced by this tree.
    pub fn used(&self) -> u64 {
        self.used
    }

    /// The one-line account of the damaged or foreign state file the last attach retired as
    /// used up (HR-7, v0.19.12), handed out once for the caller to log as an error (this
    /// crate does not log); `None` after any other attach.
    pub fn take_damage_report(&mut self) -> Option<String> {
        self.damage_report.take()
    }

    /// Attach a durable state file and adopt any state already on disk. Call this once,
    /// right after keygen, on the ONE signer that will advance this tree:
    /// - if `path` holds this key's state, resume past the last durable leaf (the whole
    ///   point of surviving a restart); a file at the end of its tree attaches used up;
    /// - if `path` is missing, leave the fresh state in place; the first `sign` creates it;
    /// - anything else present (unreadable, truncated, damaged, another key's) retires the
    ///   tree as used up (HR-7; see `attach_persistence_with_floor`).
    ///
    /// The public key is seed-derived and unchanged; only the leaf position moves.
    pub fn attach_persistence(&mut self, path: PathBuf) -> std::io::Result<()> {
        self.attach_persistence_with_floor(path, 0)
    }

    /// `attach_persistence` with a lower bound on the resume position. `floor` is any
    /// independent evidence of leaves already spent — for a validator, the leaf index of
    /// the last vote it knows it released (votes carry their leaf index on-chain), or a
    /// conservative over-estimate. The signer resumes at the HIGHEST of: the file's `used`,
    /// the position inside the file's key state, `floor`, and its own in-memory position.
    /// Skipping leaves costs capacity; reusing one costs the key — so every disagreement
    /// is resolved upwards (R16, defence in depth behind the durable write).
    ///
    /// HR-7 (v0.19.12): a PRESENT file the signer cannot resume from neither falls through to
    /// leaf 0 (as a 0–7-byte file — an interrupted copy, a disk-full restore, media damage, a
    /// planted file — used to) nor triggers a
    /// refusal that stops the node (a node that cannot start cannot sync the rotation that
    /// revives it, and a refusal inside commit recurs at every restart): the tree is retired
    /// as used up. Present means the directory entry exists — only NotFound is "missing"
    /// (`Path::exists` also answers "missing" for a dangling link and for any metadata error).
    /// Retired: an entry that cannot be inspected, followed to a regular file or read; fewer
    /// bytes than the 8-byte header; a key state whose length is not this key's; a header or a
    /// key-state counter past the capacity; and, while the resume position is below the
    /// capacity, parameter and seed bytes other than this key's (`HssSigningSession::open`
    /// only parses and checks the length, so a damaged body would fail or panic at the first
    /// vote and another key's would sign under that key) or a key state that cannot be opened.
    /// Then, in order: the bytes, when they could be read, are kept beside the file as
    /// `<file name>.damaged-<unix seconds>` (an entry that cannot be inspected, followed or
    /// read leaves nothing to copy, and the report says so); the path is rewritten with the
    /// record a used-up tree leaves (`exhausted_state` behind a header of `capacity`, read as
    /// used up by every release), whether or not a copy was kept; the tree is held used up
    /// (`remaining() == 0`, `sign` answers `None`) whatever those two steps answered;
    /// `take_damage_report` hands the caller one line to log. A file whose
    /// position reaches the capacity (the honest record of a used-up tree) attaches used up
    /// with nothing kept or rewritten. A MISSING file keeps its meaning: the signer starts at
    /// the computed position and the first `sign` creates the file. No outcome is an `Err`.
    pub fn attach_persistence_with_floor(&mut self, path: PathBuf, floor: u64) -> std::io::Result<()> {
        self.damage_report = None;
        let resume = self.used.max(floor);
        let blob = match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                self.retire_damaged(path, None, format!("its directory entry cannot be inspected: {e}"));
                return Ok(());
            }
            Ok(_) => {
                let read = match std::fs::metadata(&path) {
                    Err(e) => Err(format!("it cannot be followed to a file: {e}")),
                    Ok(meta) if !meta.is_file() => Err("it is not a regular file".to_string()),
                    Ok(_) => std::fs::read(&path).map_err(|e| format!("it cannot be read: {e}")),
                };
                match read {
                    Ok(blob) => Some(blob),
                    Err(defect) => {
                        self.retire_damaged(path, None, defect);
                        return Ok(());
                    }
                }
            }
        };
        match blob {
            // No file yet: the computed position over the generated key; the first `sign`
            // creates the file and opens the session.
            None => {
                let state = state_at(&self.state, resume);
                self.adopt(path, resume, state, None);
            }
            Some(blob) => match self.resume_from(&blob, resume) {
                Ok((position, state, session)) => self.adopt(path, position, state, session),
                Err(defect) => self.retire_damaged(path, Some(&blob), defect),
            },
        }
        Ok(())
    }

    /// HR-7 (v0.19.12): judge the bytes of a PRESENT state file against this key, replacing
    /// nothing. `Ok` carries the position to resume at — the highest of `resume`, the header
    /// and the key state's own counter (every disagreement resolved upwards, R16) — with the
    /// key state moved there and the session `sign` will use, opened now behind the same panic
    /// boundary `verify` uses and kept; a position at the capacity is a used-up tree, with
    /// nothing to compare or open. `Err` names the defect of a damaged or foreign file.
    fn resume_from(
        &self,
        blob: &[u8],
        resume: u64,
    ) -> Result<(u64, Vec<u8>, Option<HssSigningSession<H>>), String> {
        if blob.len() < 8 {
            return Err(format!("{} bytes; the header alone is 8", blob.len()));
        }
        let file_used = u64::from_le_bytes(blob[..8].try_into().expect("8 bytes"));
        let state = &blob[8..];
        if state.len() != self.state.len() {
            return Err(format!(
                "{} bytes of key state after the header; this key's state is {} bytes",
                state.len(),
                self.state.len()
            ));
        }
        if file_used > self.capacity {
            return Err(format!("the header claims {file_used} used leaves; the tree has {}", self.capacity));
        }
        let in_state = state_count(state).unwrap_or(0);
        if in_state > self.capacity {
            return Err(format!(
                "the key state's counter claims {in_state} used leaves; the tree has {}",
                self.capacity
            ));
        }
        let resume = resume.max(file_used).max(in_state);
        if resume >= self.capacity {
            return Ok((resume, Vec::new(), None));
        }
        // Compared before anything is replaced: the counter moves, the parameters and the seed
        // never do, so another key's file or a damaged one differs here.
        if state.get(8..) != self.state.get(8..) {
            return Err("its parameter and seed bytes are not this key's (another key's file, or a damaged one)".to_string());
        }
        let next = state_at(state, resume);
        match catch_unwind(AssertUnwindSafe(|| HssSigningSession::<H>::open(&next))) {
            Ok(Ok(session)) => Ok((resume, next, Some(session))),
            Ok(Err(_)) | Err(_) => Err("its key state cannot be opened".to_string()),
        }
    }

    /// Adopt `path` at `position`, `state` being the key state moved there. A position at the
    /// capacity is held exactly as the last leaf's signature leaves a tree — the wiped key,
    /// `used == capacity`, no session — so `sign` answers `None` from the first call.
    fn adopt(&mut self, path: PathBuf, position: u64, state: Vec<u8>, session: Option<HssSigningSession<H>>) {
        if position >= self.capacity {
            self.state = exhausted_state(self.state.len());
            self.used = self.capacity;
            self.session = None;
        } else {
            self.state = state;
            self.used = position;
            self.session = session;
        }
        self.persist = Some(path);
    }

    /// HR-7 (v0.19.12): retire the tree over a damaged or foreign state file; `damaged` holds
    /// the file's bytes when they could be read. In order: keep those bytes beside the file
    /// when there are any (an unreadable file leaves nothing to copy, and the report says so);
    /// rewrite the path with the record a used-up tree leaves, through the durable write `sign`
    /// uses, with or without a copy (the path is never missing, so a crash in between leaves
    /// the damaged file for the next start to handle again); hold the tree used up in memory
    /// whatever either step answered; leave one line for the caller to log.
    fn retire_damaged(&mut self, path: PathBuf, damaged: Option<&[u8]>, defect: String) {
        let used_up = exhausted_state(self.state.len());
        let kept = match damaged {
            Some(bytes) => match keep_damaged_copy(&path, bytes) {
                Ok(copy) => format!("the damaged bytes are kept in {}", copy.display()),
                Err(e) => format!("no copy of the damaged bytes could be kept ({e})"),
            },
            None => "no copy of the damaged bytes could be kept (the file could not be read)".to_string(),
        };
        let rewritten = match write_atomic(&path, &encode_blob(self.capacity, &used_up)) {
            Ok(()) => "the file now records the tree as used up".to_string(),
            Err(e) => format!(
                "the file could not be rewritten as used up ({e}), so do not start an older release on this home"
            ),
        };
        self.damage_report = Some(format!(
            "consensus signer state file {} is damaged or not this key's ({defect}): this tree is retired as used up and \
             will never sign again; the node keeps running, and if this is the validator's current key it moves to a fresh \
             epoch through key rotation (automatic, or `hk-node issue-rotation` submitted through a peer); never restore a \
             signer state file from a backup and never copy one between hosts; {kept}; {rewritten}",
            path.display()
        ));
        self.state = used_up;
        self.used = self.capacity;
        self.session = None;
        self.persist = Some(path);
    }

    /// Sign `msg`, advancing the key state. Returns the signature bytes, or `None`
    /// if the key is exhausted or signing fails.
    ///
    /// R15: the expanded HSS key lives in `self.session` between calls, so a signature costs
    /// one LM-OTS signature plus the bottom tree's authentication path — not a rebuild of the
    /// bottom tree and a fresh top-tree signature over it (that only happens on rollover,
    /// once per 32 signatures, and after a restart).
    ///
    /// Reserve-then-sign discipline, unchanged: the ADVANCED compressed state is written
    /// durably BEFORE the signature is released and before the in-memory key adopts it. If
    /// the durable write fails we release nothing, roll the session back (the next call
    /// rebuilds it from the persisted state) and the same leaf is retried — never reused,
    /// because the signature computed here never leaves this function.
    pub fn sign(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        if self.remaining() == 0 {
            return None;
        }
        if self.session.is_none() {
            self.session = Some(HssSigningSession::<H>::open(&self.state).ok()?);
        }
        let sig = {
            let session = self.session.as_mut()?;
            let res = if self.aux.is_empty() {
                session.sign(msg, None)
            } else {
                // Use the aux cache when present (consensus keys) — O(height) top-tree paths.
                let mut a: &mut [u8] = &mut self.aux;
                session.sign(msg, Some(&mut a))
            };
            match res {
                Ok(sig) => sig,
                Err(_) => {
                    self.session = None;
                    return None;
                }
            }
        };
        let next = self.session.as_ref()?.pending_private_key()?.as_slice().to_vec();
        if let Some(path) = &self.persist {
            if write_atomic(path, &encode_blob(self.used + 1, &next)).is_err() {
                if let Some(session) = self.session.as_mut() {
                    session.rollback();
                }
                return None;
            }
        }
        self.session.as_mut()?.commit();
        self.state = next;
        self.used += 1;
        Some(sig.as_ref().to_vec())
    }

    /// The pre-R15 signing path — a fresh expansion through `hbs_lms::sign` on every call.
    /// Kept as the reference the cached path is tested against (byte-identical signatures,
    /// identical state advance); not used by the node.
    #[cfg(test)]
    fn sign_uncached(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        use hbs_lms::sign as hss_sign;
        if self.remaining() == 0 {
            return None;
        }
        let current = self.state.clone();
        let mut advanced: Option<Vec<u8>> = None;
        let mut update = |new_key: &[u8]| {
            advanced = Some(new_key.to_vec());
            Ok(())
        };
        let sig = if self.aux.is_empty() {
            hss_sign::<H>(msg, &current, &mut update, None).ok()?
        } else {
            let mut a: &mut [u8] = &mut self.aux;
            hss_sign::<H>(msg, &current, &mut update, Some(&mut a)).ok()?
        };
        if let Some(ns) = advanced {
            if let Some(path) = &self.persist {
                if write_atomic(path, &encode_blob(self.used + 1, &ns)).is_err() {
                    return None;
                }
            }
            self.state = ns;
            self.used += 1;
            self.session = None;
        }
        Some(sig.as_ref().to_vec())
    }
}

/// Verify a signature against a public key. Stateless, order-free. Total: a malformed `sig` is
/// `false`, never a panic (RZ-1, external report 2026-10-14 — the vendored parser sliced the
/// caller's bytes unchecked, so an empty, truncated or mis-typed signature unwound through the
/// consensus actor, which ractor then stopped for good while the node stayed up). Three layers:
/// the length window here, the parser made total in the vendored crate, and the panic boundary
/// around the call.
pub fn verify(msg: &[u8], sig: &[u8], public: &HashSigPublic) -> bool {
    if sig.len() < MIN_SIG_LEN || sig.len() > MAX_SIG_LEN {
        return false;
    }
    verify_guarded(msg, sig, &public.0)
}

/// The verify call behind a panic boundary. The parser is total since RZ-1 (every read is
/// bounds-checked, every type lookup is a `?`, the level is bounded), so this boundary should
/// never fire; it is the last line — a panic anywhere below becomes `false` instead of unwinding
/// into the caller's actor or rayon worker. `AssertUnwindSafe` is sound: the closure borrows
/// immutable data only, so nothing is left half-updated if it unwinds. (The default panic hook
/// still prints a caught panic to stderr; that line is the signal that a parser hole survived.)
fn verify_guarded(msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
    guarded(|| hss_verify::<H>(msg, sig, pk).is_ok())
}

/// The panic boundary itself: `f`'s verdict, or `false` if `f` unwinds. Kept as its own
/// function so the test that pins the boundary exercises the code that ships.
fn guarded(f: impl FnOnce() -> bool) -> bool {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(false)
}

// ⚠ Stack note: hbs-lms keygen/sign allocate large fixed arrays on the stack.
// Run LMS operations on a thread with a generous stack (≥ 8 MiB). The consensus
// signing provider (0.9 swap) must build its tokio runtime / signer thread with an
// enlarged stack for the same reason — see docs/HASHSIG-CONSENSUS-SWAP.md.
#[cfg(test)]
fn on_big_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip_and_state_advances() {
        on_big_stack(|| {
            let (mut signer, pk) = generate(&[7u8; 32]);
            assert_eq!(signer.remaining(), 32);

            let m1 = b"hashkinetics prevote height=1";
            let s1 = signer.sign(m1).expect("sign 1");
            assert!(verify(m1, &s1, &pk));
            assert_eq!(signer.remaining(), 31);

            // A second signature uses a DIFFERENT leaf (state advanced) and still verifies.
            let m2 = b"hashkinetics precommit height=1";
            let s2 = signer.sign(m2).expect("sign 2");
            assert!(verify(m2, &s2, &pk));
            assert_ne!(s1, s2);
            assert_eq!(signer.remaining(), 30);
        });
    }

    #[test]
    fn tampered_signature_and_wrong_message_rejected() {
        on_big_stack(|| {
            let (mut signer, pk) = generate(&[9u8; 32]);
            let msg = b"authorize spend";
            let mut sig = signer.sign(msg).unwrap();
            assert!(verify(msg, &sig, &pk));

            // Flip a byte in the middle of the signature.
            let mid = sig.len() / 2;
            sig[mid] ^= 1;
            assert!(!verify(msg, &sig, &pk));

            // Original-shaped but wrong message.
            let (mut s2, pk2) = generate(&[9u8; 32]);
            let good = s2.sign(msg).unwrap();
            assert!(!verify(b"different message", &good, &pk2));
        });
    }

    #[test]
    fn deterministic_keygen() {
        on_big_stack(|| {
            let (_, a) = generate(&[1u8; 32]);
            let (_, b) = generate(&[1u8; 32]);
            let (_, c) = generate(&[2u8; 32]);
            assert_eq!(a, b);
            assert_ne!(a, c);
        });
    }

    #[test]
    fn wrong_key_rejected() {
        on_big_stack(|| {
            let (mut s1, _pk1) = generate(&[3u8; 32]);
            let (_s2, pk2) = generate(&[4u8; 32]);
            let msg = b"cross-key check";
            let sig = s1.sign(msg).unwrap();
            assert!(!verify(msg, &sig, &pk2));
        });
    }

    #[test]
    fn consensus_key_signs_verifies_advances_and_persists() {
        on_big_stack(|| {
            let (mut signer, pk) = generate_consensus(&[42u8; 32]);
            assert_eq!(signer.remaining(), CONSENSUS_CAPACITY);

            // Two consensus messages (a prevote + a precommit).
            let m1 = b"hk consensus prevote h=1 r=0";
            let s1 = signer.sign(m1).expect("consensus sign 1");
            assert!(verify(m1, &s1, &pk));

            // Persist state after signing (the reserve-then-sign discipline),
            // then reconstruct a fresh signer from seed + persisted state.
            let persisted = signer.state_bytes().to_vec();
            let m2 = b"hk consensus precommit h=1 r=0";
            let s2 = signer.sign(m2).expect("consensus sign 2");
            assert!(verify(m2, &s2, &pk));
            assert_ne!(s1, s2);

            // A restarted validator: same seed → same public key; load persisted state.
            let (mut restarted, pk2) = generate_consensus(&[42u8; 32]);
            assert_eq!(pk, pk2); // public key is seed-derived, restart-stable
            restarted.load_state(persisted);
            let s2b = restarted.sign(m2).expect("post-restart sign");
            assert!(verify(m2, &s2b, &pk));
        });
    }

    #[test]
    fn file_persistence_survives_restart_without_leaf_reuse() {
        on_big_stack(|| {
            let path = std::env::temp_dir()
                .join(format!("hk_consensus_state_{}.bin", std::process::id()));
            let _ = std::fs::remove_file(&path);

            // Fresh signer; attach the durable file (absent ⇒ starts at leaf 0).
            let (mut s1, pk) = generate_consensus(&[77u8; 32]);
            s1.attach_persistence(path.clone()).unwrap();
            assert_eq!(s1.used(), 0);

            let a = s1.sign(b"h=1 prevote").expect("sign a");
            let b = s1.sign(b"h=1 precommit").expect("sign b");
            assert!(verify(b"h=1 prevote", &a, &pk));
            assert!(verify(b"h=1 precommit", &b, &pk));
            assert_eq!(s1.used(), 2); // file now records used = 2
            drop(s1);

            // "Restart": a new signer from the SAME seed re-attaches the SAME file and
            // must resume PAST the last durable leaf — never reusing leaves 0 or 1.
            let (mut s2, pk2) = generate_consensus(&[77u8; 32]);
            assert_eq!(pk, pk2); // seed-derived, restart-stable
            s2.attach_persistence(path.clone()).unwrap();
            assert_eq!(s2.used(), 2);

            let c = s2.sign(b"h=2 prevote").expect("post-restart sign");
            assert!(verify(b"h=2 prevote", &c, &pk));
            assert_ne!(a, c);
            assert_ne!(b, c);
            assert_eq!(s2.used(), 3);

            let _ = std::fs::remove_file(&path);
        });
    }

    /// R15: the cached session path must be byte-identical to the pre-R15 fresh-expansion
    /// path for the same seed — signatures AND advancing state — across two bottom-tree
    /// rollovers (H5 = 32 leaves; 70 signatures cross 32 and 64).
    #[test]
    fn r15_cached_signing_matches_uncached_across_rollover() {
        on_big_stack(|| {
            let (mut cached, pk) = generate_consensus(&[15u8; 32]);
            let (mut reference, pk2) = generate_consensus(&[15u8; 32]);
            assert_eq!(pk, pk2);
            for i in 0u32..70 {
                let msg = format!("hk vote h={} r=0", i);
                let a = cached.sign(msg.as_bytes()).expect("cached sign");
                let b = reference.sign_uncached(msg.as_bytes()).expect("uncached sign");
                assert_eq!(a, b, "signature {} differs between cached and uncached", i);
                assert_eq!(cached.state_bytes(), reference.state_bytes(), "state {} differs", i);
                assert_eq!(cached.used(), reference.used());
                assert!(verify(msg.as_bytes(), &a, &pk), "signature {} must verify", i);
            }
            assert_eq!(cached.remaining(), CONSENSUS_CAPACITY - 70);
        });
    }

    /// R15: a failed durable write releases nothing and retries the SAME leaf next time.
    #[test]
    fn r15_persistence_failure_retries_the_same_leaf() {
        on_big_stack(|| {
            let (mut signer, pk) = generate_consensus(&[16u8; 32]);
            let (mut reference, _) = generate_consensus(&[16u8; 32]);
            // One good signature first so the session is warm.
            let m0 = b"h=1 prevote";
            assert_eq!(signer.sign(m0).unwrap(), reference.sign_uncached(m0).unwrap());

            // A persistence path whose parent directory does not exist: write_atomic fails.
            let bad = std::env::temp_dir()
                .join(format!("hk_r15_missing_dir_{}", std::process::id()))
                .join("state.bin");
            signer.persist = Some(bad);
            let m1 = b"h=1 precommit";
            assert!(signer.sign(m1).is_none(), "a failed durable write must release nothing");
            assert_eq!(signer.used(), 1, "the leaf counter must not advance");

            // Persistence restored: the same leaf signs — identical bytes to the reference,
            // which never failed.
            signer.persist = None;
            let again = signer.sign(m1).expect("sign after the failure");
            assert_eq!(again, reference.sign_uncached(m1).unwrap(), "the same leaf must be used");
            assert!(verify(m1, &again, &pk));
            assert_eq!(signer.state_bytes(), reference.state_bytes());
        });
    }

    /// R15: a restart (fresh keygen + persisted state) continues with the session exactly
    /// where the reference path would — no leaf skipped, none reused.
    #[test]
    fn r15_restart_resumes_identically() {
        on_big_stack(|| {
            let path = std::env::temp_dir()
                .join(format!("hk_r15_restart_{}.bin", std::process::id()));
            let _ = std::fs::remove_file(&path);
            let (mut s1, pk) = generate_consensus(&[17u8; 32]);
            let (mut reference, _) = generate_consensus(&[17u8; 32]);
            s1.attach_persistence(path.clone()).unwrap();
            for i in 0..40u32 {
                let msg = format!("h={} vote", i);
                assert_eq!(s1.sign(msg.as_bytes()).unwrap(), reference.sign_uncached(msg.as_bytes()).unwrap());
            }
            drop(s1);
            let (mut s2, pk2) = generate_consensus(&[17u8; 32]);
            assert_eq!(pk, pk2);
            s2.attach_persistence(path.clone()).unwrap();
            assert_eq!(s2.used(), 40);
            for i in 40..45u32 {
                let msg = format!("h={} vote", i);
                let a = s2.sign(msg.as_bytes()).expect("post-restart sign");
                assert_eq!(a, reference.sign_uncached(msg.as_bytes()).unwrap(), "post-restart {} differs", i);
                assert!(verify(msg.as_bytes(), &a, &pk));
            }
            let _ = std::fs::remove_file(&path);
        });
    }

    /// R15 receipt: cached signing must be at least 5x faster than the fresh-expansion path
    /// (the fresh path does a whole bottom-tree build + a top-tree signature per call).
    /// Prints both medians; run with `-- --nocapture` for the numbers.
    #[test]
    fn r15_cached_signing_is_faster() {
        on_big_stack(|| {
            let (mut cached, _) = generate_consensus(&[18u8; 32]);
            let (mut reference, _) = generate_consensus(&[18u8; 32]);
            let n = 12u32;
            let bench = |f: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>| -> u128 {
                let mut samples: Vec<u128> = Vec::new();
                for i in 0..n {
                    let msg = format!("bench {}", i);
                    let t = std::time::Instant::now();
                    f(msg.as_bytes()).expect("sign");
                    samples.push(t.elapsed().as_micros());
                }
                samples.sort();
                samples[samples.len() / 2]
            };
            let warm = cached.sign(b"warm").unwrap();
            assert!(!warm.is_empty());
            let fast = bench(&mut |m| cached.sign(m));
            let slow = bench(&mut |m| reference.sign_uncached(m));
            println!("R15 median per signature: cached {} us, uncached {} us", fast, slow);
            assert!(fast * 5 <= slow, "cached ({} us) should be >= 5x faster than uncached ({} us)", fast, slow);
        });
    }

    /// R16: the position lives in the first 8 bytes of the hbs-lms state (big endian) and
    /// fast-forwarding it is exactly equivalent to having signed that many times — the
    /// assumption `state_at` / `attach_persistence_with_floor` rest on.
    #[test]
    fn r16_fast_forwarded_state_signs_like_the_reference() {
        on_big_stack(|| {
            let (mut reference, pk) = generate_consensus(&[19u8; 32]);
            for i in 0..37u32 {
                reference.sign_uncached(format!("h={} vote", i).as_bytes()).unwrap();
            }
            assert_eq!(state_count(reference.state_bytes()), Some(37));

            let (mut jumped, pk2) = generate_consensus(&[19u8; 32]);
            assert_eq!(pk, pk2);
            let fresh = jumped.state_bytes().to_vec();
            assert_eq!(state_count(&fresh), Some(0));
            jumped.load_state(state_at(&fresh, 37));
            jumped.used = 37;
            assert_eq!(jumped.state_bytes(), reference.state_bytes(), "fast-forward must equal 37 real advances");

            let m = b"h=37 vote";
            let a = jumped.sign(m).unwrap();
            let b = reference.sign_uncached(m).unwrap();
            assert_eq!(a, b, "leaf 37 must sign identically");
            assert!(verify(m, &a, &pk));
        });
    }

    /// R16: a STALE state file (the reporter's scenario — an old file surviving a crash) is
    /// resolved upwards. (a) The file's header and the position inside its key state
    /// disagree → the higher wins. (b) The node's own evidence (`floor`) beats the file.
    /// (c) In every case the resumed signer never re-signs a leaf the reference already spent.
    #[test]
    fn r16_stale_state_file_resumes_upwards_never_reuses() {
        on_big_stack(|| {
            let dir = std::env::temp_dir().join(format!("hk_r16_{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("state.bin");
            let _ = std::fs::remove_file(&path);

            let (mut s1, pk) = generate_consensus(&[20u8; 32]);
            let (mut reference, _) = generate_consensus(&[20u8; 32]);
            s1.attach_persistence(path.clone()).unwrap();
            let mut released: Vec<Vec<u8>> = Vec::new();
            let mut stale_blob: Option<Vec<u8>> = None;
            for i in 0..6u32 {
                let msg = format!("h={} vote", i);
                let a = s1.sign(msg.as_bytes()).expect("sign");
                assert_eq!(a, reference.sign_uncached(msg.as_bytes()).unwrap());
                released.push(a);
                if i == 1 {
                    stale_blob = Some(std::fs::read(&path).unwrap()); // the file as it was after leaf 1
                }
            }
            drop(s1);

            // (a) Simulate the lost rename: the file on disk is the OLD blob (used = 2)...
            // but with the key state inside it pointing at leaf 4, as if headers and state
            // disagreed. The higher position must win.
            let stale = stale_blob.unwrap();
            let mut disagreeing = stale[..8].to_vec();
            disagreeing.extend_from_slice(&state_at(&stale[8..], 4));
            std::fs::write(&path, &disagreeing).unwrap();
            let (mut s2, pk2) = generate_consensus(&[20u8; 32]);
            assert_eq!(pk, pk2);
            s2.attach_persistence(path.clone()).unwrap();
            assert_eq!(s2.used(), 4, "the position inside the key state (4) beats the header (2)");
            assert_eq!(state_count(s2.state_bytes()), Some(4));
            drop(s2);

            // (b) The plain stale blob (used = 2) plus the node's evidence that leaf 5 was
            // released → resume at 6, skipping 2..5. Nothing released is ever re-signed.
            std::fs::write(&path, &stale).unwrap();
            let (mut s3, _) = generate_consensus(&[20u8; 32]);
            s3.attach_persistence_with_floor(path.clone(), 6).unwrap();
            assert_eq!(s3.used(), 6);
            let msg = b"h=6 vote";
            let a = s3.sign(msg).expect("sign after resume");
            assert_eq!(a, reference.sign_uncached(msg).unwrap(), "must continue at leaf 6 exactly");
            assert!(verify(msg, &a, &pk));
            for old in &released {
                assert_ne!(&a, old, "a released signature's leaf was reused");
            }
            // The write that resumed us is durable and self-consistent on disk.
            let now = std::fs::read(&path).unwrap();
            assert_eq!(u64::from_le_bytes(now[..8].try_into().unwrap()), 7);
            assert_eq!(state_count(&now[8..]), Some(7));

            // (c) A floor below the file changes nothing: the file's position (7) wins.
            drop(s3);
            let (mut s4, _) = generate_consensus(&[20u8; 32]);
            s4.attach_persistence_with_floor(path.clone(), 3).unwrap();
            assert_eq!(s4.used(), 7);

            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    /// RZ-1 (external report 2026-10-14): a malformed signature is REJECTED, never a panic. The
    /// vendored parser is exercised directly (no boundary) on every prefix of a real signature,
    /// bogus levels and type codes, the level-overflow blob and pseudo-random blobs, so this
    /// pins the parser's totality; then the same inputs go through `verify` (window + boundary).
    #[test]
    fn rz1_malformed_signatures_are_rejected_not_panics() {
        on_big_stack(|| {
            let (mut signer, pk) = generate(&[21u8; 32]);
            let msg = b"hk/v1/consensus-vote prevote h=7 r=0";
            let good = signer.sign(msg).expect("sign");
            assert!(verify(msg, &good, &pk));
            // One W2/H5 tree over a 32-byte hash.
            let lmots_len = 4 + 32 + 32 * 133;
            let lms_sig_len = 4 + lmots_len + 4 + 32 * 5;
            assert_eq!(good.len(), 4 + lms_sig_len);
            assert!(good.len() >= MIN_SIG_LEN && good.len() <= MAX_SIG_LEN);

            let raw = |sig: &[u8]| hss_verify::<H>(msg, sig, &pk.0).is_ok();
            // The parser itself: every prefix (the reporter's panics were n = 0 and n = 10).
            for n in 0..good.len() {
                assert!(!raw(&good[..n]), "prefix of {n} bytes must be refused by the parser");
            }
            // Bogus level (bytes 0..4), including the values that overflowed the level array.
            for level in [1u32, 7, 8, 1_000, u32::MAX] {
                let mut bad = good.clone();
                bad[..4].copy_from_slice(&level.to_be_bytes());
                assert!(!raw(&bad), "level {level} must be refused by the parser");
                assert!(!verify(msg, &bad, &pk));
            }
            // Full length, bogus LM-OTS type (bytes 8..12) and LMS type (after the LM-OTS part).
            let lms_type_at = 4 + 4 + lmots_len;
            for at in [8, lms_type_at] {
                for code in [0u32, 99, u32::MAX] {
                    let mut bad = good.clone();
                    bad[at..at + 4].copy_from_slice(&code.to_be_bytes());
                    assert!(!raw(&bad), "type code {code} at {at} must be refused by the parser");
                    assert!(!verify(msg, &bad, &pk));
                }
            }
            // A leaf number beyond the H5 tree (bytes 4..8).
            let mut bad = good.clone();
            bad[4..8].copy_from_slice(&32u32.to_be_bytes());
            assert!(!raw(&bad) && !verify(msg, &bad, &pk));
            // The level-overflow blob: level 8 followed by eight well-formed (signature, public
            // key) pairs — the bottom signature stands in for each level's signature and a
            // W2/H5 public key header for each key — then the bottom signature.
            let mut overflow = 8u32.to_be_bytes().to_vec();
            let mut pk56 = vec![0u8; 56];
            pk56[..4].copy_from_slice(&5u32.to_be_bytes()); // LMS H5
            pk56[4..8].copy_from_slice(&2u32.to_be_bytes()); // LM-OTS W2
            for _ in 0..8 {
                overflow.extend_from_slice(&good[4..]);
                overflow.extend_from_slice(&pk56);
            }
            overflow.extend_from_slice(&good[4..]);
            assert!(!raw(&overflow), "a level-8 blob must be refused, not overflow the array");
            assert!(!verify(msg, &overflow, &pk));

            // `verify`: the window refuses these before the parser; the parser would too.
            assert!(!verify(msg, &[], &pk));
            assert!(!verify(msg, &good[..10], &pk));
            assert!(!verify(msg, &good[..good.len() - 1], &pk));
            // One byte appended: inside the window, so the parser's strictness refuses it
            // (trailing bytes used to be ignored, and this used to verify).
            let mut longer = good.clone();
            longer.push(0);
            assert!(!raw(&longer) && !verify(msg, &longer, &pk));
            assert!(!verify(msg, &vec![0u8; MIN_SIG_LEN - 1], &pk));
            assert!(!verify(msg, &vec![0u8; MIN_SIG_LEN], &pk));
            assert!(!verify(msg, &vec![0u8; CONSENSUS_SIG_LEN], &pk));
            assert!(!verify(msg, &vec![0u8; MAX_SIG_LEN], &pk));
            assert!(!verify(msg, &vec![0u8; MAX_SIG_LEN + 1], &pk));
            assert!(!verify(msg, &vec![0xFFu8; MAX_SIG_LEN], &pk));

            // Pseudo-random blobs (xorshift, fixed seed): never a panic, never a false accept.
            let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
            let mut next = move || {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x
            };
            // (a) Random bytes, random length; two of three get a level the bound admits
            //     (0..=2), so the readers below the level see random input too.
            for i in 0..500u32 {
                let len = (next() % 12_000) as usize;
                let mut blob: Vec<u8> = (0..len).map(|_| next() as u8).collect();
                if i % 3 != 0 && blob.len() >= 4 {
                    blob[..4].copy_from_slice(&(i % 3).to_be_bytes());
                }
                assert!(!raw(&blob));
                assert!(!verify(msg, &blob, &pk));
            }
            // (b) Every (LM-OTS, LMS) parameter pair the parser admits, at exactly its own
            //     length, with valid type codes, a leaf inside the tree and random everything
            //     else: the parser accepts the shape, the verifier refuses the content. The
            //     W2/H5 pair matches the key, so that one runs the whole LM-OTS verify on
            //     random data; the other nineteen are refused at the parameter compare.
            for (wt, chains) in [(1u32, 265usize), (2, 133), (3, 67), (4, 34)] {
                for (ht, height) in [(5u32, 5usize), (6, 10), (7, 15), (8, 20), (9, 25)] {
                    let lmots = 4 + 32 + 32 * chains;
                    let len = 4 + 4 + lmots + 4 + 32 * height;
                    for _ in 0..5 {
                        let mut blob: Vec<u8> = (0..len).map(|_| next() as u8).collect();
                        blob[..4].copy_from_slice(&0u32.to_be_bytes());
                        let leaf = (next() % (1u64 << height)) as u32;
                        blob[4..8].copy_from_slice(&leaf.to_be_bytes());
                        blob[8..12].copy_from_slice(&wt.to_be_bytes());
                        let lms_at = 4 + 4 + lmots;
                        blob[lms_at..lms_at + 4].copy_from_slice(&ht.to_be_bytes());
                        assert!(!raw(&blob), "W type {wt} / H type {ht} random content must be refused");
                        assert!(!verify(msg, &blob, &pk));
                    }
                }
            }
            // (c) The real signature's shape with every non-structural field randomised
            //     (randomizer, chains, path), the leaf kept inside the tree: the full verify
            //     path on random data, two hundred times.
            for _ in 0..200 {
                let mut blob = good.clone();
                for i in (12..lms_type_at).chain(lms_type_at + 4..good.len()) {
                    blob[i] = next() as u8;
                }
                blob[4..8].copy_from_slice(&((next() % 32) as u32).to_be_bytes());
                assert!(!raw(&blob));
                assert!(!verify(msg, &blob, &pk));
            }
            assert!(verify(msg, &good, &pk), "the real signature still verifies");
        });
    }

    /// RZ-1: the consensus key's signature length is a protocol constant — the consensus
    /// verifier refuses every other length before parsing, so this must never drift silently.
    #[test]
    fn rz1_consensus_signature_length_is_pinned() {
        on_big_stack(|| {
            let (mut signer, pk) = generate_consensus(&[22u8; 32]);
            let msg = b"hk/v1/consensus-vote precommit h=7 r=0";
            // Across a bottom-tree rollover (H5 = 32 leaves) the length is unchanged.
            for i in 0..34u32 {
                let sig = signer.sign(msg).expect("sign");
                assert_eq!(sig.len(), CONSENSUS_SIG_LEN, "signature {i} length");
                assert!(verify(msg, &sig, &pk));
            }
            assert_eq!(CONSENSUS_SIG_LEN, 9140);
            assert_eq!(MIN_SIG_LEN, 1296);
            assert!(MIN_SIG_LEN < CONSENSUS_SIG_LEN && CONSENSUS_SIG_LEN < MAX_SIG_LEN);
            // The parser, with no boundary, on every prefix of a two-level signature.
            let good = signer.sign(msg).expect("sign");
            for n in (0..good.len()).step_by(7).chain([good.len() - 1]) {
                assert!(hss_verify::<H>(msg, &good[..n], &pk.0).is_err(), "prefix {n}");
            }
        });
    }

    /// RZ-1: the panic boundary that ships (`guarded`, behind `verify_guarded`) maps an
    /// unwinding closure to `false` and passes a verdict through. The parser no longer panics
    /// on any input, so the boundary is exercised with a closure that does. (The default
    /// panic hook prints the simulated panic to stderr; that line is expected here.)
    #[test]
    fn rz1_panic_boundary_maps_a_panic_to_false() {
        assert!(!guarded(|| -> bool { panic!("simulated parser hole") }));
        assert!(guarded(|| true));
        assert!(!guarded(|| false));
    }

    /// A fresh copy of a just-generated signer, for one attach each: the keygen (the H10 top
    /// tree) is the slow part, so the HR-7 cases share one.
    fn twin(s: &HashSigner) -> HashSigner {
        HashSigner {
            state: s.state.clone(),
            aux: s.aux.clone(),
            used: s.used,
            capacity: s.capacity,
            persist: None,
            session: None,
            damage_report: None,
        }
    }

    /// The `<file name>.damaged-…` copies kept beside `path`, sorted.
    fn damaged_copies(path: &std::path::Path) -> Vec<PathBuf> {
        let prefix = format!("{}.damaged-", path.file_name().unwrap().to_string_lossy());
        let mut copies: Vec<PathBuf> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|p| p.file_name().map_or(false, |n| n.to_string_lossy().starts_with(&prefix)))
            .collect();
        copies.sort();
        copies
    }

    /// HR-7 (v0.19.12): `bytes` become the state file of a twin of `pristine` in
    /// `base/<case>/`, and the attach must retire the tree: used up (`remaining() == 0`,
    /// `sign` is `None`), the path rewritten with the used-up record (header = capacity), the
    /// original bytes in exactly one `.damaged-…` copy (every case given here can be read; an
    /// unreadable file leaves nothing to copy, see the mode-000 test), one report naming the
    /// path, the defect, the copy and the remedy — and a second start reads the rewritten file
    /// as an honest used-up record (no report, no second copy, nothing rewritten).
    fn assert_retired(base: &std::path::Path, case: &str, pristine: &HashSigner, bytes: &[u8], defect: &str) {
        let dir = base.join(case.replace(' ', "_"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("consensus_state.bin");
        std::fs::write(&path, bytes).unwrap();
        let mut s = twin(pristine);
        s.attach_persistence(path.clone()).unwrap();
        assert_eq!((s.used(), s.remaining()), (s.capacity, 0), "{case}: attached used up");
        assert!(s.sign(b"h=1 vote").is_none(), "{case}: a retired tree signs nothing");
        let used_up = encode_blob(s.capacity, &exhausted_state(pristine.state.len()));
        assert_eq!(std::fs::read(&path).unwrap(), used_up, "{case}: the path holds the used-up record");
        let copies = damaged_copies(&path);
        assert_eq!(copies.len(), 1, "{case}: exactly one copy");
        assert_eq!(std::fs::read(&copies[0]).unwrap(), bytes, "{case}: the copy holds the damaged bytes");
        let report = s.take_damage_report().unwrap_or_else(|| panic!("{case}: no report"));
        for needle in [path.display().to_string(), defect.to_string(), copies[0].display().to_string()] {
            assert!(report.contains(&needle), "{case}: `{needle}` missing from: {report}");
        }
        for needle in ["retired as used up", "hk-node issue-rotation", "never restore", "the file now records the tree as used up"] {
            assert!(report.contains(needle), "{case}: `{needle}` missing from: {report}");
        }
        assert!(s.take_damage_report().is_none(), "{case}: the report is handed out once");
        let mut again = twin(pristine);
        again.attach_persistence(path.clone()).unwrap();
        assert_eq!(again.remaining(), 0, "{case}: still used up after a restart");
        assert!(again.take_damage_report().is_none(), "{case}: the rewritten file is an honest used-up record");
        assert_eq!(damaged_copies(&path).len(), 1, "{case}: no second copy");
        assert_eq!(std::fs::read(&path).unwrap(), used_up, "{case}: nothing rewritten again");
    }

    /// HR-7 (v0.19.12): every damaged or foreign state file is retired as used up — never
    /// resumed, never signed under another key, never a refusal that stops the node — while
    /// the honest used-up record and a good file keep their meaning. One keygen serves every
    /// case (plus one for the other key).
    /// - Too short to carry a position: the reporter's 3-byte file; 0 and 7 bytes; a header
    ///   alone; a header and a short key state. KILL: let a short file fall through to the
    ///   fresh state (the pre-HR-7 shape) and it attaches at leaf 0; answer it with `Err`
    ///   and `attach_persistence(..).unwrap()` panics.
    /// - The right length but not this key's parameters or seed: one flipped parameter byte,
    ///   one flipped seed byte, a real file another key's signer wrote. KILL: drop the
    ///   parameter + seed comparison and each attaches mid-tree (a flipped parameter fails or
    ///   panics at the first vote; the other key's file signs under the other key).
    /// - A header or a key-state counter past the capacity. KILL: drop either check and the
    ///   file attaches used up but unreported and unrewritten (no copy, the bad file stays).
    /// - The honest used-up record attaches used up with no report, no copy, nothing
    ///   rewritten. KILL: compare parameters and seed at the capacity too (the record's key is
    ///   wiped) and it is reported and copied as damage.
    /// - A missing file starts at leaf 0; this key's own file resumes at its position and
    ///   signs, and the next record is that position + 1. KILL: a check that refuses this
    ///   key's own file (comparing the counter bytes too, say) retires it.
    #[test]
    fn hr7_a_damaged_or_foreign_state_file_is_retired_as_used_up() {
        on_big_stack(|| {
            let base = std::env::temp_dir().join(format!("hk_hr7_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            let (pristine, pk) = generate_consensus(&[23u8; 32]);
            let real = pristine.state.clone();

            // Too short to carry a position.
            assert_retired(&base, "reporter 3 bytes", &pristine, &[1, 2, 3], "3 bytes; the header alone is 8");
            assert_retired(&base, "0 bytes", &pristine, &[], "0 bytes; the header alone is 8");
            assert_retired(&base, "7 bytes", &pristine, &[0xA5; 7], "7 bytes; the header alone is 8");
            assert_retired(&base, "header only", &pristine, &5u64.to_le_bytes(), "0 bytes of key state after the header");
            let mut short = 5u64.to_le_bytes().to_vec();
            short.extend_from_slice(&[9, 9, 9]);
            assert_retired(&base, "short body", &pristine, &short, "3 bytes of key state after the header");

            // The right length, not this key's parameters or seed.
            let foreign_defect = "parameter and seed bytes are not this key's";
            let mut param = state_at(&real, 3);
            param[8] ^= 0x01;
            assert_retired(&base, "flipped parameter byte", &pristine, &encode_blob(3, &param), foreign_defect);
            let mut seed = state_at(&real, 3);
            seed[16 + 5] ^= 0x80;
            assert_retired(&base, "flipped seed byte", &pristine, &encode_blob(3, &seed), foreign_defect);
            let other_dir = base.join("other_key_source");
            std::fs::create_dir_all(&other_dir).unwrap();
            let other_path = other_dir.join("consensus_state.bin");
            let (mut other, other_pk) = generate_consensus(&[24u8; 32]);
            other.attach_persistence(other_path.clone()).unwrap();
            for m in [b"h=1 vote", b"h=2 vote"] {
                let sig = other.sign(m).expect("the other key signs");
                assert!(verify(m, &sig, &other_pk));
            }
            let foreign = std::fs::read(&other_path).unwrap();
            assert_eq!(foreign.len(), 8 + real.len(), "a well-formed file of the same length");
            assert_eq!(u64::from_le_bytes(foreign[..8].try_into().unwrap()), 2);
            assert_retired(&base, "other key file", &pristine, &foreign, foreign_defect);

            // A counter past the capacity.
            assert_retired(
                &base,
                "header past capacity",
                &pristine,
                &encode_blob(CONSENSUS_CAPACITY + 1, &real),
                &format!("the header claims {} used leaves; the tree has {CONSENSUS_CAPACITY}", CONSENSUS_CAPACITY + 1),
            );
            assert_retired(
                &base,
                "key state past capacity",
                &pristine,
                &encode_blob(0, &state_at(&real, CONSENSUS_CAPACITY + 7)),
                &format!("the key state's counter claims {} used leaves", CONSENSUS_CAPACITY + 7),
            );

            // The honest used-up record: used up, nothing reported, kept or rewritten.
            let honest_dir = base.join("honest_used_up");
            std::fs::create_dir_all(&honest_dir).unwrap();
            let honest_path = honest_dir.join("consensus_state.bin");
            let honest = encode_blob(CONSENSUS_CAPACITY, &exhausted_state(real.len()));
            std::fs::write(&honest_path, &honest).unwrap();
            let mut h = twin(&pristine);
            h.attach_persistence(honest_path.clone()).unwrap();
            assert_eq!((h.used(), h.remaining()), (CONSENSUS_CAPACITY, 0));
            assert!(h.sign(b"h=1 vote").is_none());
            assert!(h.take_damage_report().is_none(), "the honest record is not damage");
            assert!(damaged_copies(&honest_path).is_empty());
            assert_eq!(std::fs::read(&honest_path).unwrap(), honest, "the honest record is left as it is");

            // No file yet: leaf 0, and the first sign creates the file …
            let good_dir = base.join("good");
            std::fs::create_dir_all(&good_dir).unwrap();
            let good_path = good_dir.join("consensus_state.bin");
            let mut s = twin(&pristine);
            s.attach_persistence(good_path.clone()).unwrap();
            assert_eq!(s.used(), 0);
            assert!(s.take_damage_report().is_none());
            for i in 0..3u32 {
                let m = format!("h={i} vote");
                let sig = s.sign(m.as_bytes()).expect("sign");
                assert!(verify(m.as_bytes(), &sig, &pk));
            }
            drop(s);
            // … and this key's own file resumes at its position and signs; the next record is
            // that position + 1.
            let mut r = twin(&pristine);
            r.attach_persistence(good_path.clone()).unwrap();
            assert_eq!(r.used(), 3);
            assert!(r.take_damage_report().is_none());
            let sig = r.sign(b"h=3 vote").expect("sign after resume");
            assert!(verify(b"h=3 vote", &sig, &pk));
            let now = std::fs::read(&good_path).unwrap();
            assert_eq!(u64::from_le_bytes(now[..8].try_into().unwrap()), 4);
            assert_eq!(state_count(&now[8..]), Some(4));
            assert!(damaged_copies(&good_path).is_empty());
            let _ = std::fs::remove_dir_all(&base);
        });
    }

    /// HR-7 (v0.19.12): the record a tree's LAST signature persists is exactly
    /// `encode_blob(capacity, &exhausted_state(..))` (the vendored crate wipes the key at its
    /// final leaf), so the record the retire path writes is the one every release already reads
    /// as used up; a signer attached to it holds the tree used up, with no report, no copy and
    /// the file unchanged. The small H5 key reaches its end in 32 signatures, and its key state
    /// has the consensus key's layout (counter, parameter slots, seed).
    /// KILL: change `exhausted_state`'s layout (the counter, the `0xff` parameter slots, the
    /// zero seed) and the record no longer matches; treat the record as damage and a report
    /// and a copy appear.
    #[test]
    fn hr7_the_last_leaf_record_is_the_used_up_shape_and_attaches_unchanged() {
        on_big_stack(|| {
            let dir = std::env::temp_dir().join(format!("hk_hr7_end_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("state.bin");
            let (pristine, pk) = generate(&[26u8; 32]);
            assert_eq!(pristine.state.len(), 8 + 8 + 32, "counter, parameter slots, seed");
            let mut s = twin(&pristine);
            s.attach_persistence(path.clone()).unwrap();
            for i in 0..32u32 {
                let m = format!("h={i} vote");
                let sig = s.sign(m.as_bytes()).unwrap_or_else(|| panic!("leaf {i} signs"));
                assert!(verify(m.as_bytes(), &sig, &pk));
            }
            assert_eq!(s.remaining(), 0);
            assert!(s.sign(b"past the end").is_none());
            let record = std::fs::read(&path).unwrap();
            assert_eq!(record, encode_blob(32, &exhausted_state(pristine.state.len())), "the last leaf's record");
            assert_eq!(s.state_bytes(), &exhausted_state(pristine.state.len())[..], "and the key it leaves in memory");
            let mut again = twin(&pristine);
            again.attach_persistence(path.clone()).unwrap();
            assert_eq!((again.used(), again.remaining()), (32, 0));
            assert!(again.sign(b"after a restart").is_none());
            assert!(again.take_damage_report().is_none(), "the last leaf's record is not damage");
            assert!(damaged_copies(&path).is_empty());
            assert_eq!(std::fs::read(&path).unwrap(), record, "nothing rewritten");
            assert_eq!(again.state_bytes(), s.state_bytes(), "held exactly as the last signature left it");
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    /// HR-7 (v0.19.12): a present directory entry that cannot be read as a file — a directory,
    /// a symbolic link to nothing — is retired as used up. `Path::exists` answers "missing" for
    /// the dangling link, and the old attach started a fresh tree at leaf 0 there, whose first
    /// signature would have replaced the link. No bytes means no copy; the dangling link is
    /// replaced by the used-up record; the directory cannot be, and the report says so.
    /// KILL: decide "missing" with `Path::exists` or `fs::metadata` (both follow the link) and
    /// the dangling link attaches a fresh tree — `remaining()` is the capacity.
    #[test]
    fn hr7_an_unreadable_state_entry_is_retired_as_used_up() {
        on_big_stack(|| {
            let base = std::env::temp_dir().join(format!("hk_hr7_entry_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            let (pristine, _) = generate(&[25u8; 32]);
            let path = base.join("directory").join("consensus_state.bin");
            std::fs::create_dir_all(&path).unwrap();
            let mut s = twin(&pristine);
            s.attach_persistence(path.clone()).unwrap();
            assert_eq!(s.remaining(), 0, "a directory: attached used up");
            assert!(s.sign(b"h=1 vote").is_none());
            let report = s.take_damage_report().expect("a report");
            for needle in ["it is not a regular file", "no copy of the damaged bytes could be kept", "could not be rewritten as used up"] {
                assert!(report.contains(needle), "`{needle}` missing from: {report}");
            }
            assert!(path.is_dir(), "the directory is left in place");
            #[cfg(unix)]
            {
                let dir = base.join("dangling");
                std::fs::create_dir_all(&dir).unwrap();
                let path = dir.join("consensus_state.bin");
                std::os::unix::fs::symlink(dir.join("unmounted").join("consensus_state.bin"), &path).unwrap();
                assert!(!path.exists(), "Path::exists calls a dangling link missing");
                let mut s = twin(&pristine);
                s.attach_persistence(path.clone()).unwrap();
                assert_eq!(s.remaining(), 0, "a dangling link: attached used up, not a fresh tree");
                let report = s.take_damage_report().expect("a report");
                for needle in ["it cannot be followed to a file", "the file now records the tree as used up"] {
                    assert!(report.contains(needle), "`{needle}` missing from: {report}");
                }
                assert!(!std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink(), "the link is replaced");
                assert_eq!(std::fs::read(&path).unwrap(), encode_blob(s.capacity, &exhausted_state(pristine.state.len())));
            }
            let _ = std::fs::remove_dir_all(&base);
        });
    }

    /// HR-7 (v0.19.12): a PRESENT regular file this process cannot read (mode 000: the entry
    /// exists, `fs::read` fails) is retired as used up, never taken for a missing file —
    /// `remaining() == 0`, `sign` is `None`. The file is this key's own record at leaf 1, so
    /// "missing" would show as leaf 0 and "read" as leaf 1. As documented for an unreadable
    /// file, no copy can be kept (the report says so), and the path is still rewritten with the
    /// used-up record (the rename needs only the directory), so a restart reads an honest
    /// used-up record. Skipped with a printed note where a mode-000 file can be read anyway
    /// (running as root).
    /// KILL: answer a read error as "missing" and the file attaches a fresh tree at leaf 0
    /// (`remaining()` is the capacity); answer it with `Err` and `attach_persistence(..).unwrap()`
    /// panics; skip the rewrite when no copy was kept and the mode-000 file stays in place.
    #[cfg(unix)]
    #[test]
    fn hr7_an_unreadable_regular_state_file_is_retired_as_used_up() {
        on_big_stack(|| {
            use std::os::unix::fs::PermissionsExt;
            let base = std::env::temp_dir().join(format!("hk_hr7_mode000_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&base).unwrap();
            let path = base.join("consensus_state.bin");
            let (pristine, _) = generate(&[27u8; 32]);
            // This key's own record at leaf 1.
            let mut writer = twin(&pristine);
            writer.attach_persistence(path.clone()).unwrap();
            writer.sign(b"h=1 vote").expect("sign");
            drop(writer);
            let record = std::fs::read(&path).unwrap();
            assert_eq!(u64::from_le_bytes(record[..8].try_into().unwrap()), 1, "this key's record at leaf 1");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
            if std::fs::read(&path).is_ok() {
                println!(
                    "hr7_an_unreadable_regular_state_file_is_retired_as_used_up: SKIPPED, this process can read a \
                     mode-000 file (running as root), so no unreadable file can be made here"
                );
                let _ = std::fs::remove_dir_all(&base);
                return;
            }
            let mut s = twin(&pristine);
            s.attach_persistence(path.clone()).unwrap();
            assert_eq!((s.used(), s.remaining()), (s.capacity, 0), "attached used up, neither leaf 0 nor leaf 1");
            assert!(s.sign(b"h=2 vote").is_none(), "a retired tree signs nothing");
            let report = s.take_damage_report().expect("a report");
            for needle in [
                "it cannot be read",
                "no copy of the damaged bytes could be kept (the file could not be read)",
                "the file now records the tree as used up",
            ] {
                assert!(report.contains(needle), "`{needle}` missing from: {report}");
            }
            assert!(damaged_copies(&path).is_empty(), "no copy can be kept of bytes that cannot be read");
            assert_eq!(
                std::fs::read(&path).unwrap(),
                encode_blob(s.capacity, &exhausted_state(pristine.state.len())),
                "the unreadable file is replaced by the used-up record"
            );
            let mut again = twin(&pristine);
            again.attach_persistence(path.clone()).unwrap();
            assert_eq!(again.remaining(), 0, "still used up after a restart");
            assert!(again.take_damage_report().is_none(), "the rewritten file is an honest used-up record");
            let _ = std::fs::remove_dir_all(&base);
        });
    }

    /// R16: `write_atomic` fsyncs the parent directory on Unix, so the file is visible and
    /// durable under its final name and no `.tmp` is left behind.
    #[test]
    fn r16_write_atomic_leaves_only_the_final_file() {
        let dir = std::env::temp_dir().join(format!("hk_r16_wa_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.bin");
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert!(!path.with_extension("tmp").exists(), "no temp file may survive a completed write");
        // A bare file name (no parent component) syncs the current directory instead of failing.
        let cwd_file = std::path::PathBuf::from(format!("hk_r16_cwd_{}.bin", std::process::id()));
        write_atomic(&cwd_file, b"x").unwrap();
        let _ = std::fs::remove_file(&cwd_file);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
