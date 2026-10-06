//! fsutil — durable atomic file writes: the ONE routine every state-bearing file goes
//! through (the consensus signer state, the node's key/account files, the block log and
//! snapshots, the wallets' reserve-then-advance counters).
//!
//! `write_atomic` = tmp → write → fsync(file) → rename → **fsync(directory)**. Rename
//! replaces the destination on both Unix and Windows, so a crash leaves either the old or
//! the new file — never a torn one; the two fsyncs are what make the NEW file the one that
//! survives.
//!
//! R16 (external report, 2026-09-22; v0.19.4): the rename alone is NOT durable on POSIX.
//! The new directory entry lives in the directory's metadata, which the kernel may still
//! hold in memory after `rename` returns; a power loss / kernel panic / host reset before
//! the next journal commit can bring the machine back with the OLD file still in place.
//! For a stateful signer that is the one failure that must never happen: the old file
//! carries a lower leaf counter, the signer would resume there, and a leaf would be signed
//! twice (LM-OTS key material leaks; repeated reuse of one leaf — a crash-looping node —
//! makes forgery cheap). So after the rename the parent directory is opened and `fsync`ed,
//! which is what makes the rename durable (same discipline as SQLite and Postgres). The
//! write returns only once BOTH the bytes and the directory entry are on stable storage;
//! whatever depends on the write (a signature, a reservation) is released after that.
//!
//! R17 (L-1, reported 2026-10-06): the R16 fix had landed in `hashsig` only. Three sibling
//! copies of the same tmp+fsync+rename routine — the node's secret files (`hk-node/keys.rs`),
//! the wallets' `account.json` / `shield.json` (`hk-wallet-core/vault.rs`; the shielded WOTS
//! leaf counter is exactly the R16 class, no on-chain nonce overrides it) and the node store
//! (`hk-node/store.rs`, whose comment claimed "the same discipline as the signer state") —
//! still ended at the rename. One helper here, every caller goes through it, so the
//! discipline cannot drift again.
//!
//! What this does NOT do: create the parent directory (a missing parent is an error — the
//! caller decides where files live, and the signer relies on the refusal), defeat storage
//! that acknowledges fsync without honouring it, or protect a file restored from an older
//! backup (operational failures; see the durability notes in `hashsig`).
//!
//! Windows has no directory fsync; NTFS journals directory metadata itself and the
//! validators run on Linux. On non-Unix targets only the file is synced.

use std::io::Write;
use std::path::Path;

/// Durably replace `path` with `bytes`. The temp file is `path.with_extension("tmp")` (so
/// `state.bin` goes through `state.tmp`), no permission change. See the module docs.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_atomic_with(path, &path.with_extension("tmp"), bytes, None)
}

/// [`write_atomic`] with the temp path chosen by the caller and an optional Unix mode.
///
/// - `tmp` must sit on the same filesystem as `path` (rename is not a copy). The wallets
///   use `account.json.tmp` beside `account.json`, where `with_extension` would give
///   `account.tmp`.
/// - `mode` is applied to the temp file after its bytes are synced and before the rename,
///   best-effort: `0o600` for the node's secret files, and a failing chmod (a drvfs mount,
///   an exotic filesystem) must not block a reserve-then-sign write. Ignored off Unix.
pub fn write_atomic_with(path: &Path, tmp: &Path, bytes: &[u8], mode: Option<u32>) -> std::io::Result<()> {
    {
        let mut f = std::fs::File::create(tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    set_mode(tmp, mode);
    std::fs::rename(tmp, path)?;
    sync_parent_dir(path)
}

/// fsync the directory that holds `path` (Unix) — makes a preceding create / rename
/// durable. A bare file name (no parent component) syncs the current directory.
#[cfg(unix)]
pub fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    std::fs::File::open(&dir)?.sync_all()
}

/// No directory fsync off Unix (NTFS journals directory metadata itself).
#[cfg(not(unix))]
pub fn sync_parent_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_mode(tmp: &Path, mode: Option<u32>) {
    use std::os::unix::fs::PermissionsExt;
    if let Some(m) = mode {
        let _ = std::fs::set_permissions(tmp, std::fs::Permissions::from_mode(m));
    }
}

#[cfg(not(unix))]
fn set_mode(_tmp: &Path, _mode: Option<u32>) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("hk_fsutil_{tag}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The contract every counter file relies on: the bytes land under the final name, a
    /// second write replaces them, the parent is left as found and no `.tmp` survives a
    /// completed write.
    #[test]
    fn write_atomic_writes_renames_and_leaves_no_tmp() {
        let dir = scratch("basic");
        let path = dir.join("state.bin");
        write_atomic(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        write_atomic(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert!(!path.with_extension("tmp").exists(), "no temp file may survive a completed write");
        assert!(dir.is_dir(), "the parent directory is untouched");
        let names: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, vec![std::ffi::OsString::from("state.bin")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The wallets' convention (`account.json.tmp` beside `account.json`, where
    /// `with_extension` would give `account.tmp`) and the node's 0600 secret files.
    #[test]
    fn write_atomic_with_honours_tmp_name_and_mode() {
        let dir = scratch("with");
        let path = dir.join("account.json");
        let tmp = dir.join("account.json.tmp");
        write_atomic_with(&path, &tmp, b"{}", Some(0o600)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
        assert!(!tmp.exists());
        assert!(!dir.join("account.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A missing parent is an error, never silently created: the signer relies on this to
    /// refuse a persistence path it cannot write (`hashsig` test `attach_persistence…`).
    #[test]
    fn write_atomic_refuses_a_missing_parent() {
        let dir = scratch("missing");
        let path = dir.join("nope").join("state.bin");
        assert!(write_atomic(&path, b"x").is_err());
        assert!(!path.exists());
        assert!(!dir.join("nope").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A bare file name (no parent component) syncs the current directory instead of
    /// failing (`sync_parent_dir` falls back to `.`).
    #[test]
    fn bare_file_name_syncs_the_current_directory() {
        let name = std::path::PathBuf::from(format!("hk_fsutil_cwd_{}.bin", std::process::id()));
        write_atomic(&name, b"x").unwrap();
        assert_eq!(std::fs::read(&name).unwrap(), b"x");
        sync_parent_dir(&name).unwrap();
        let _ = std::fs::remove_file(&name);
    }
}
