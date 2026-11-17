//! K1/K2 (v0.16.0) — keys at rest, node side.
//!
//! Thin wrappers over `hk_wallet::sealed` that give every secret file the node touches
//! (`priv_validator_key.json`, `account.json`, `wallet.json`) ONE behaviour:
//!
//! - read a plain OR a sealed file transparently (a plain file never asks for anything);
//! - write a sealed file back sealed, under the same key; and once this process holds a key
//!   for a kind of secret (it opened or sealed a file of that kind), seal a missing or plain
//!   target of that kind under that key too — never write it plain (HR-10, v0.19.12). A
//!   process that holds no key writes plain, unless `<PREFIX>_PASSPHRASE` is set;
//! - put plaintext back on disk ONLY through the explicit commands `key-unseal <HOME>` and
//!   `account-unseal <DIR>` (`key-seal` / `account-seal` seal a plain file on purpose).
//!
//! The passphrase is resolved once per process (`<PREFIX>_PASSPHRASE`, `_PASSPHRASE_FILE`,
//! systemd `LoadCredential=`, or a terminal prompt — see `hk_wallet::sealed`), the optional
//! key file from `<PREFIX>_KEYFILE`, and the DERIVED KEY is what gets cached (per salt):
//! the Argon2id work (≈1 s at the default 512 MiB profile) happens at unlock, and the
//! reserve-then-sign re-seal before every submit is an AEAD call in microseconds. Block
//! and index files are untouched by this module.
//!
//! Honest scope: this protects a backup, a disk image, a copied home directory. It does
//! not protect a running node (the seed is in memory while it signs), and the live LMS
//! signer state (`consensus_state.bin`, rewritten on every vote) is NOT sealed in v0.16.0
//! — it is the current operational tree only; a root-signed rotation retires it. The HSM
//! path (docs/MAINNET-KEY-MANAGEMENT.md) is the next step and plugs in here.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use hk_wallet::sealed::{self, Kdf, SealError, SealKey, Sealed};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Secret {
    /// `priv_validator_key.json` — the SLH-DSA root seed; every epoch's op-seed derives from it.
    ValidatorKey,
    /// `account.json` / `wallet.json` — the transparent keychain seed and the shielded master.
    Wallet,
}

impl Secret {
    /// Environment prefix: `HK_KEY_PASSPHRASE[_FILE]` / `HK_WALLET_PASSPHRASE[_FILE]`, `…_KEYFILE`.
    pub(crate) fn prefix(self) -> &'static str {
        match self {
            Secret::ValidatorKey => "HK_KEY",
            Secret::Wallet => "HK_WALLET",
        }
    }

    /// systemd credential name (`LoadCredential=<name>:<path>`), read from `$CREDENTIALS_DIRECTORY`.
    pub(crate) fn credential(self) -> &'static str {
        match self {
            Secret::ValidatorKey => "hk-key-passphrase",
            Secret::Wallet => "hk-wallet-passphrase",
        }
    }

    fn prompt(self) -> &'static str {
        match self {
            Secret::ValidatorKey => "validator key passphrase",
            Secret::Wallet => "wallet passphrase",
        }
    }

    fn slot(self) -> usize {
        match self {
            Secret::ValidatorKey => 0,
            Secret::Wallet => 1,
        }
    }
}

#[derive(Default)]
struct Cache {
    /// The passphrase, once resolved (needed again only when a file carries a salt we
    /// have not derived for yet — e.g. account.json and wallet.json sealed in two runs).
    passphrase: Option<String>,
    /// Derived keys by salt (hex). `primary` is the salt new files are sealed under.
    keys: HashMap<String, SealKey>,
    primary: Option<String>,
}

static CACHE: Mutex<[Option<Cache>; 2]> = Mutex::new([None, None]);

fn with_cache<R>(which: Secret, f: impl FnOnce(&mut Cache) -> R) -> R {
    let mut g = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let c = g[which.slot()].get_or_insert_with(Cache::default);
    f(c)
}

/// The passphrase for `which`, resolved once and cached for the life of the process.
pub(crate) fn passphrase(which: Secret) -> Result<String, SealError> {
    if let Some(p) = with_cache(which, |c| c.passphrase.clone()) {
        return Ok(p);
    }
    let p = sealed::passphrase_from_env(which.prefix(), which.credential(), which.prompt())?;
    with_cache(which, |c| c.passphrase = Some(p.clone()));
    Ok(p)
}

/// The optional second factor: `<PREFIX>_KEYFILE`.
fn keyfile(which: Secret) -> Result<Option<Vec<u8>>, SealError> {
    sealed::keyfile_from_env(which.prefix())
}

fn remember_key(which: Secret, key: SealKey, make_primary: bool) {
    with_cache(which, |c| {
        let salt = key.salt_hex();
        if make_primary || c.primary.is_none() {
            c.primary = Some(salt.clone());
        }
        c.keys.insert(salt, key);
    });
}

fn forget(which: Secret) {
    with_cache(which, |c| *c = Cache::default());
}

/// A key derived (≈1 s at the default profile) for an existing envelope — its salt and
/// parameters, bounded by `Kdf::validate` — from the resolved passphrase (+ key file). It
/// neither reads nor fills the cache: the callers look there first and cache the key
/// (`remember_key`) only after it has opened the envelope.
fn key_for(which: Secret, env: &Sealed) -> Result<SealKey, SealError> {
    // SealKey is not Clone on purpose (one zeroize on drop): a cached key is used in place
    // under the cache lock, and a new one is derived here only when the cache has none.
    let pass = passphrase(which)?;
    let kf = keyfile(which)?;
    SealKey::for_envelope(env, &pass, kf.as_deref())
}

fn open_with_cache(which: Secret, env: &Sealed) -> Result<Vec<u8>, SealError> {
    let hit = with_cache(which, |c| c.keys.get(&env.salt).filter(|k| k.fits(env)).map(|k| k.open(env)));
    if let Some(r) = hit {
        return r;
    }
    let key = key_for(which, env)?;
    let out = key.open(env);
    if out.is_ok() {
        remember_key(which, key, false);
    }
    out
}

/// HR-10 (v0.19.12): a save never adopts a key for an envelope this process has not opened.
/// Until v0.19.12 the key for the envelope being replaced was taken from the file itself —
/// its salt and parameters — and the plaintext was re-sealed under it: an envelope swapped
/// in at the owner's secret path (by whoever can write there) had the owner's real secret
/// re-encrypted under the attacker's salt and, before the floor, the attacker's cheap
/// parameters at the owner's next save, silently. Now the key — cached or freshly derived —
/// must OPEN the envelope on disk (plaintext discarded) before anything is sealed under it;
/// otherwise the save is refused with `SealError::NotOpened` and the file is left as it is.
fn seal_with_cache(which: Secret, existing: Option<&Sealed>, plaintext: &str) -> Result<String, SealError> {
    // Re-seal under the key of the envelope being replaced (same salt); a NEW file goes
    // under the primary key, deriving one with a fresh salt if this process has none yet.
    let want_salt = existing.map(|e| e.salt.clone());
    let done = with_cache(which, |c| {
        let salt = want_salt.clone().or_else(|| c.primary.clone())?;
        let k = c.keys.get(&salt)?;
        if let Some(e) = existing {
            if !k.fits(e) {
                return None;
            }
            // verify-then-adopt: the cached key fits the envelope's labels; it must open
            // its body too (one AEAD call), or this is not the file this process read.
            if k.open(e).is_err() {
                return Some(Err(SealError::NotOpened));
            }
        }
        Some(k.seal_to_json(plaintext))
    });
    if let Some(r) = done {
        return r;
    }
    let key = match existing {
        Some(e) => {
            // An envelope under a salt this process has not derived for (a file sealed in
            // another run): derive for it — bounded by `Kdf::validate` — and adopt the key
            // only if it opens the file. A foreign envelope is never re-sealed under.
            let key = key_for(which, e)?;
            key.open(e).map_err(|_| SealError::NotOpened)?;
            key
        }
        None => SealKey::new(&passphrase(which)?, keyfile(which)?.as_deref(), Kdf::default_profile())?,
    };
    let out = key.seal_to_json(plaintext);
    remember_key(which, key, existing.is_none());
    out
}

/// Is the file at `path` an `HKE1` envelope? (`false` when it does not exist.)
pub(crate) fn is_sealed_file(path: &Path) -> bool {
    std::fs::read_to_string(path).map(|s| sealed::is_sealed(&s)).unwrap_or(false)
}

/// Read a secret file: plain content is returned as-is; a sealed one is opened with the
/// cached key or a fresh derivation. A wrong passphrase forgets the cache (a typo can be
/// retried); a missing key file says which one.
pub(crate) fn read_secret(path: &Path, which: Secret) -> eyre::Result<String> {
    let raw = std::fs::read_to_string(path).map_err(|e| eyre::eyre!("{}: {e}", path.display()))?;
    if !sealed::is_sealed(&raw) {
        return Ok(raw);
    }
    let env = sealed::parse(&raw).map_err(|e| eyre::eyre!("{}: {e}", path.display()))?;
    match open_with_cache(which, &env) {
        Ok(bytes) => String::from_utf8(bytes).map_err(|e| eyre::eyre!("{}: {e}", path.display())),
        Err(SealError::Cipher) => {
            forget(which);
            Err(eyre::eyre!("{}: wrong {} (or the file was tampered with)", path.display(), which.prompt()))
        }
        Err(e) => Err(eyre::eyre!("{}: {e}", path.display())),
    }
}

/// Write a secret file atomically (tmp → fsync → rename, mode 0600 on Unix). A sealed file
/// stays sealed, under its own key. A missing or plain target is sealed under the primary key
/// when this process holds a key for this kind of secret — it opened or sealed a file of that
/// kind — or when `<PREFIX>_PASSPHRASE` is set (a scripted install that exports the passphrase
/// gets sealed files from the start); only a process that holds neither writes it plain.
/// HR-10 (v0.19.12): until v0.19.12 the choice came from the file on disk and that variable
/// alone, so a process that opened a sealed file with a passphrase from `_PASSPHRASE_FILE`,
/// `LoadCredential=` (a service) or the prompt wrote the secret back in PLAIN TEXT
/// once the file was removed or replaced by plain JSON. And a sealed file this process's key
/// does not open is never overwritten — the error names the path; the file on disk is
/// untouched. `unseal_path` (`key-unseal` / `account-unseal`) writes plain on purpose, through
/// `write_atomic`.
pub(crate) fn write_secret(path: &Path, plaintext: &str, which: Secret) -> eyre::Result<()> {
    let existing = std::fs::read_to_string(path).ok().filter(|s| sealed::is_sealed(s));
    let body = match existing {
        Some(raw) => {
            let env = sealed::parse(&raw).map_err(|e| eyre::eyre!("{}: {e}", path.display()))?;
            seal_with_cache(which, Some(&env), plaintext).map_err(|e| eyre::eyre!("{}: {e}", path.display()))?
        }
        None => {
            // `remember_key` makes the first key this process derives the primary, so a
            // primary with its key cached = this process holds a key for this kind of secret.
            let holds_key = with_cache(which, |c| c.primary.as_ref().is_some_and(|salt| c.keys.contains_key(salt)));
            let seal_new = std::env::var(format!("{}_PASSPHRASE", which.prefix())).map(|p| !p.is_empty()).unwrap_or(false);
            if holds_key || seal_new {
                seal_with_cache(which, None, plaintext).map_err(|e| eyre::eyre!("{}: {e}", path.display()))?
            } else {
                plaintext.to_string()
            }
        }
    };
    write_atomic(path, body.as_bytes())
}

/// tmp → fsync → rename → fsync(directory), mode 0600 on Unix. Counters in these files are
/// reserve-then-advance; the bytes must be on disk before the rename makes them the live
/// file (the v0.13.1 wallet rule), AND the directory entry must be on disk before the write
/// is reported done — on POSIX the rename alone sits in cached directory metadata and a
/// power loss can bring the OLD file (a lower counter) back (R16, 2026-09-22). The routine
/// is `hk_crypto::fsutil` since R17 (reported 2026-10-06): this copy had stopped at the
/// rename. The missing parent directory is still created here (first write of a fresh
/// home); the helper itself refuses a missing parent.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> eyre::Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    hk_crypto::fsutil::write_atomic_with(path, &path.with_extension("tmp"), bytes, Some(0o600))?;
    Ok(())
}

/// `key-seal` / `account-seal`: convert one plain secret file into a sealed one. The new
/// passphrase comes from `<PREFIX>_PASSPHRASE`, `<PREFIX>_PASSPHRASE_FILE` (v0.16.1, first
/// line) or a double prompt and must pass
/// `sealed::check_strength`; `<PREFIX>_KEYFILE` adds the second factor. `new_pass` carries
/// the passphrase across several files in one command so they share one key (one salt).
/// The plaintext is replaced only after a full seal → open round trip matches byte for byte.
pub(crate) fn seal_path(path: &Path, which: Secret, new_pass: &mut Option<String>) -> eyre::Result<()> {
    let raw = std::fs::read_to_string(path).map_err(|e| eyre::eyre!("{}: {e}", path.display()))?;
    if sealed::is_sealed(&raw) {
        println!("  = {} is already sealed", path.display());
        return Ok(());
    }
    let _: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| eyre::eyre!("{}: not JSON ({e}) — refusing to seal", path.display()))?;
    if new_pass.is_none() {
        // v0.16.1: a NEW seal also takes `<PREFIX>_PASSPHRASE_FILE` (first line), so a
        // generated passphrase can go file → seal → credential without ever being in an
        // environment variable or a `$(cat …)` on a command line.
        let prefix = which.prefix();
        let from_env = std::env::var(format!("{prefix}_PASSPHRASE"))
            .ok()
            .filter(|p| !p.is_empty())
            .map(|p| (format!("{prefix}_PASSPHRASE"), p))
            .or_else(|| {
                let path = std::env::var(format!("{prefix}_PASSPHRASE_FILE")).ok()?;
                let s = std::fs::read_to_string(&path).ok()?;
                let line = s.lines().next()?.trim().to_string();
                (!line.is_empty()).then(|| (format!("{prefix}_PASSPHRASE_FILE"), line))
            });
        let pass = match from_env {
            Some((source, p)) => {
                sealed::check_strength(&p).map_err(|why| eyre::eyre!("{source} refused: {why} (HK_SEAL_ALLOW_WEAK=1 overrides on devnets only)"))?;
                p
            }
            None => sealed::prompt_new_passphrase(&path.display().to_string()).ok_or_else(|| {
                eyre::eyre!("no passphrase — set {prefix}_PASSPHRASE, {prefix}_PASSPHRASE_FILE=<path>, or run on a terminal")
            })?,
        };
        *new_pass = Some(pass);
    }
    let pass = new_pass.as_deref().expect("set above");
    let kf = keyfile(which)?;
    // One derivation per command: files sealed together share the salt (and the cache).
    let have = with_cache(which, |c| c.primary.clone().and_then(|s| c.keys.contains_key(&s).then_some(s)));
    let body = match have {
        Some(salt) => with_cache(which, |c| c.keys[&salt].seal_to_json(&raw))?,
        None => {
            let key = SealKey::new(pass, kf.as_deref(), Kdf::default_profile())?;
            let body = key.seal_to_json(&raw)?;
            with_cache(which, |c| c.passphrase = Some(pass.to_string()));
            remember_key(which, key, true);
            body
        }
    };
    let check = sealed::parse(&body)?;
    let back = SealKey::for_envelope(&check, pass, kf.as_deref())?.open(&check)?;
    if back != raw.as_bytes() {
        eyre::bail!("seal/open round trip mismatch — nothing changed");
    }
    write_atomic(path, body.as_bytes())?;
    let k = Kdf { m_kib: check.m_kib, t: check.t, p: check.p };
    println!(
        "  ✓ sealed   {}   (argon2id {} MiB × t{} × p{}{})",
        path.display(),
        k.m_kib / 1024,
        k.t,
        k.p,
        check.kf.as_deref().map(|id| format!(", key file {id}")).unwrap_or_default()
    );
    Ok(())
}

/// `key-unseal` / `account-unseal`: put the plaintext back on disk (for a migration to
/// another machine, or an HSM import). Says so loudly.
pub(crate) fn unseal_path(path: &Path, which: Secret) -> eyre::Result<()> {
    if !is_sealed_file(path) {
        println!("  = {} is not sealed", path.display());
        return Ok(());
    }
    let plain = read_secret(path, which)?;
    write_atomic(path, plain.as_bytes())?;
    println!("  ✓ unsealed {}  (plaintext on disk again — re-seal when done)", path.display());
    Ok(())
}

/// `keyfile-new <PATH>`: 32 random bytes, mode 0600, and the fingerprint envelopes will name.
pub(crate) fn keyfile_new(path: &Path) -> eyre::Result<()> {
    if path.exists() {
        eyre::bail!("{} exists — refusing to overwrite a key file", path.display());
    }
    let bytes = sealed::new_keyfile();
    write_atomic(path, &bytes)?;
    println!("✓ key file written: {}  (id {})", path.display(), sealed::keyfile_id(&bytes));
    println!("  use it: HK_KEY_KEYFILE={} hk-node key-seal HOME   ·   HK_WALLET_KEYFILE={} hk-node account-seal DIR", path.display(), path.display());
    println!("  keep it on a different device than the backup of the file it protects; without it the passphrase alone opens nothing.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("hk-keys-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // The tests below share the process-wide cache and environment; they run under one
    // lock so a parallel test never sees another test's passphrase.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn fast_kdf() {
        std::env::set_var("HK_SEAL_M_KIB", "65536");
        std::env::set_var("HK_SEAL_T", "3");
    }

    #[test]
    fn k1_seal_read_write_unseal_cycle() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        fast_kdf();
        std::env::remove_var("HK_WALLET_KEYFILE");
        std::env::remove_var("HK_WALLET_PASSPHRASE");
        forget(Secret::Wallet);
        let d = tmpdir("cycle");
        let p = d.join("account.json");
        std::fs::write(&p, "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":0}").unwrap();
        assert!(!is_sealed_file(&p));
        // plain files never ask for a passphrase
        assert_eq!(read_secret(&p, Secret::Wallet).unwrap(), "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":0}");

        let mut pass = Some("correct horse battery staple".to_string());
        seal_path(&p, Secret::Wallet, &mut pass).unwrap();
        assert!(is_sealed_file(&p));
        // the key is cached from the seal → reads and re-writes stay sealed, no re-derivation
        assert_eq!(read_secret(&p, Secret::Wallet).unwrap(), "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":0}");
        let salt_before = sealed::parse(&std::fs::read_to_string(&p).unwrap()).unwrap().salt;
        let t = std::time::Instant::now();
        write_secret(&p, "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":1}", Secret::Wallet).unwrap();
        assert!(t.elapsed() < std::time::Duration::from_millis(200), "a re-seal must not run the KDF again");
        let env_after = sealed::parse(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(env_after.salt, salt_before, "same key, same salt");
        assert!(is_sealed_file(&p), "a sealed file stays sealed across a save");
        assert_eq!(read_secret(&p, Secret::Wallet).unwrap(), "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":1}");

        // a second file in the same command shares the salt (one derivation)
        let q = d.join("wallet.json");
        std::fs::write(&q, "{\"shield_master_hex\":\"22\"}").unwrap();
        seal_path(&q, Secret::Wallet, &mut pass).unwrap();
        assert_eq!(sealed::parse(&std::fs::read_to_string(&q).unwrap()).unwrap().salt, salt_before);

        // wrong passphrase → clean error, cache dropped
        forget(Secret::Wallet);
        std::env::set_var("HK_WALLET_PASSPHRASE", "wrong wrong wrong wrong");
        let e = read_secret(&p, Secret::Wallet).unwrap_err().to_string();
        assert!(e.contains("wrong wallet passphrase"), "{e}");
        std::env::set_var("HK_WALLET_PASSPHRASE", "correct horse battery staple");
        unseal_path(&p, Secret::Wallet).unwrap();
        assert!(!is_sealed_file(&p));
        assert!(std::fs::read_to_string(&p).unwrap().contains("\"next_nonce\":1"));
        std::env::remove_var("HK_WALLET_PASSPHRASE");
        forget(Secret::Wallet);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn k1_refuses_non_json_and_weak_passphrases() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        fast_kdf();
        std::env::remove_var("HK_SEAL_ALLOW_WEAK");
        forget(Secret::ValidatorKey);
        let d = tmpdir("refuse");
        let p = d.join("x.json");
        std::fs::write(&p, "not json").unwrap();
        let mut pass = Some("correct horse battery staple".to_string());
        assert!(seal_path(&p, Secret::ValidatorKey, &mut pass).is_err());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "not json");
        // a weak passphrase from the environment is refused before anything is written
        std::fs::write(&p, "[1,2,3]").unwrap();
        std::env::set_var("HK_KEY_PASSPHRASE", "hunter2");
        let mut none = None;
        let e = seal_path(&p, Secret::ValidatorKey, &mut none).unwrap_err().to_string();
        assert!(e.contains("refused"), "{e}");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "[1,2,3]");
        std::env::remove_var("HK_KEY_PASSPHRASE");
        forget(Secret::ValidatorKey);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn k2_keyfile_second_factor_through_the_env() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        fast_kdf();
        forget(Secret::ValidatorKey);
        let d = tmpdir("keyfile");
        let kf = d.join("seat.key");
        keyfile_new(&kf).unwrap();
        assert!(keyfile_new(&kf).is_err(), "never overwrite a key file");
        let p = d.join("priv_validator_key.json");
        std::fs::write(&p, "[7,7,7]").unwrap();
        std::env::set_var("HK_KEY_KEYFILE", &kf);
        let mut pass = Some("correct horse battery staple".to_string());
        seal_path(&p, Secret::ValidatorKey, &mut pass).unwrap();
        let env = sealed::parse(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert!(env.kf.is_some());
        // without the key file: named refusal, no KDF, no guess possible
        forget(Secret::ValidatorKey);
        std::env::remove_var("HK_KEY_KEYFILE");
        std::env::set_var("HK_KEY_PASSPHRASE", "correct horse battery staple");
        let e = read_secret(&p, Secret::ValidatorKey).unwrap_err().to_string();
        assert!(e.contains("key file"), "{e}");
        // with it: opens
        std::env::set_var("HK_KEY_KEYFILE", &kf);
        forget(Secret::ValidatorKey);
        assert_eq!(read_secret(&p, Secret::ValidatorKey).unwrap(), "[7,7,7]");
        std::env::remove_var("HK_KEY_KEYFILE");
        std::env::remove_var("HK_KEY_PASSPHRASE");
        forget(Secret::ValidatorKey);
        let _ = std::fs::remove_dir_all(&d);
    }

    // v0.16.1: a new seal reads `<PREFIX>_PASSPHRASE_FILE` too (first line, trimmed) — the
    // fleet pattern `passphrase-new > file` → seal → `install` the same file as the credential.
    #[test]
    fn k2_new_seal_takes_the_passphrase_from_a_file() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        fast_kdf();
        std::env::remove_var("HK_KEY_KEYFILE");
        std::env::remove_var("HK_KEY_PASSPHRASE");
        std::env::remove_var("HK_SEAL_ALLOW_WEAK");
        forget(Secret::ValidatorKey);
        let d = tmpdir("passfile");
        let p = d.join("priv_validator_key.json");
        std::fs::write(&p, "[9,9,9]").unwrap();
        let f = d.join("key-passphrase");
        // a weak first line is refused, file untouched
        std::fs::write(&f, "hunter2\n").unwrap();
        std::env::set_var("HK_KEY_PASSPHRASE_FILE", &f);
        let mut none = None;
        let e = seal_path(&p, Secret::ValidatorKey, &mut none).unwrap_err().to_string();
        assert!(e.contains("HK_KEY_PASSPHRASE_FILE refused"), "{e}");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "[9,9,9]");
        // a generated passphrase with a trailing newline seals, and the same file opens it
        std::fs::write(&f, format!("{}\n", sealed::generate_passphrase(7))).unwrap();
        let mut none = None;
        seal_path(&p, Secret::ValidatorKey, &mut none).unwrap();
        assert!(is_sealed_file(&p));
        forget(Secret::ValidatorKey);
        assert_eq!(read_secret(&p, Secret::ValidatorKey).unwrap(), "[9,9,9]");
        // `HK_KEY_PASSPHRASE` still wins over the file when both are set
        forget(Secret::ValidatorKey);
        std::env::set_var("HK_KEY_PASSPHRASE", "wrong wrong wrong wrong");
        assert!(read_secret(&p, Secret::ValidatorKey).is_err());
        std::env::remove_var("HK_KEY_PASSPHRASE");
        std::env::remove_var("HK_KEY_PASSPHRASE_FILE");
        forget(Secret::ValidatorKey);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// HR-10 (v0.19.12): a save never adopts an envelope this process did not open. The
    /// owner seals and reads `account.json`; an envelope under another key (a different
    /// passphrase, the attacker's salt) is swapped in at the path; the owner's next save is
    /// REFUSED and the file is left byte for byte — the owner's secret is never re-sealed
    /// under parameters taken from the file. A sub-floor envelope is refused before any
    /// derivation; a tampered body under the owner's own salt is refused too. The owner's
    /// OWN envelope under another salt (a file sealed in another run) still re-seals, and the
    /// result opens with the real passphrase and parameters.
    /// KILL: remove either open check from `seal_with_cache` (`k.open(e)`, `key.open(e)`; the
    /// pre-v0.19.12 path) and a save that must be refused succeeds — (c) without the first, (a)
    /// without the second, the owner's secret landing under the swapped file's salt and parameters.
    #[test]
    fn hr10_a_save_never_adopts_an_envelope_this_process_did_not_open() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        fast_kdf();
        std::env::remove_var("HK_WALLET_KEYFILE");
        std::env::remove_var("HK_WALLET_PASSPHRASE");
        forget(Secret::Wallet);
        let d = tmpdir("hr10");
        let p = d.join("account.json");
        let owner = "correct horse battery staple";
        let fast = Kdf { m_kib: 65_536, t: 3, p: 1 };
        std::fs::write(&p, "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":0}").unwrap();
        let mut pass = Some(owner.to_string());
        seal_path(&p, Secret::Wallet, &mut pass).unwrap();
        assert_eq!(read_secret(&p, Secret::Wallet).unwrap(), "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":0}");
        let own_json = std::fs::read_to_string(&p).unwrap();

        // (a) a swapped envelope under another passphrase (and salt): the save is refused,
        //     the file is untouched, and nothing under the owner's secret is on disk
        let attacker = SealKey::new("attacker chosen passphrase 1", None, fast).unwrap();
        let swapped = attacker.seal_to_json("{\"seed\":\"ff\"}").unwrap();
        std::fs::write(&p, &swapped).unwrap();
        let e = write_secret(&p, "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":1}", Secret::Wallet).unwrap_err().to_string();
        assert!(e.contains("not the sealed file this process opened"), "{e}");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), swapped, "the file on disk is left as it was");
        let still_theirs = sealed::parse(&swapped).unwrap();
        assert_eq!(attacker.open(&still_theirs).unwrap(), b"{\"seed\":\"ff\"}");

        // (b) a swapped envelope below the floor: refused before any derivation, untouched
        let mut weak = sealed::parse(&swapped).unwrap();
        weak.m_kib = 8;
        weak.t = 1;
        weak.p = 1;
        let weak_json = serde_json::to_string_pretty(&weak).unwrap();
        std::fs::write(&p, &weak_json).unwrap();
        let e = write_secret(&p, "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":1}", Secret::Wallet).unwrap_err().to_string();
        assert!(e.contains("kdf parameters out of range"), "{e}");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), weak_json);

        // (c) the owner's own salt and labels, a tampered body: the cached key fits the
        //     envelope but does not open it → refused, untouched
        let mut tampered = sealed::parse(&own_json).unwrap();
        let mut ct = hex::decode(&tampered.ct).unwrap();
        ct[0] ^= 0x01;
        tampered.ct = hex::encode(ct);
        let tampered_json = serde_json::to_string_pretty(&tampered).unwrap();
        std::fs::write(&p, &tampered_json).unwrap();
        let e = write_secret(&p, "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":1}", Secret::Wallet).unwrap_err().to_string();
        assert!(e.contains("not the sealed file this process opened"), "{e}");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), tampered_json);
        // and the untampered file still saves under its own key, same salt
        std::fs::write(&p, &own_json).unwrap();
        write_secret(&p, "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":1}", Secret::Wallet).unwrap();
        assert_eq!(sealed::parse(&std::fs::read_to_string(&p).unwrap()).unwrap().salt, sealed::parse(&own_json).unwrap().salt);
        assert_eq!(read_secret(&p, Secret::Wallet).unwrap(), "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":1}");

        // (d) the owner's OWN envelope under another salt (sealed in another run): the save
        //     derives for it, it opens, and the re-seal lands under that salt with the real
        //     parameters — readable with the owner's passphrase
        let other_run = SealKey::new(owner, None, fast).unwrap();
        std::fs::write(&p, other_run.seal_to_json("{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":0}").unwrap()).unwrap();
        write_secret(&p, "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":2}", Secret::Wallet).unwrap();
        let after = sealed::parse(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(after.salt, other_run.salt_hex());
        assert_eq!((after.m_kib, after.t, after.p), (fast.m_kib, fast.t, fast.p));
        assert_eq!(
            SealKey::for_envelope(&after, owner, None).unwrap().open(&after).unwrap(),
            b"{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":2}"
        );
        assert_eq!(read_secret(&p, Secret::Wallet).unwrap(), "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":2}");
        std::env::remove_var("HK_WALLET_PASSPHRASE");
        forget(Secret::Wallet);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// HR-10 (v0.19.12): a process that holds the key for a kind of secret never writes that
    /// secret plain. The owner seals `account.json`; a process that takes the passphrase from
    /// `HK_WALLET_PASSPHRASE_FILE` (a service's `LoadCredential=` shape), not from
    /// `HK_WALLET_PASSPHRASE`, opens it; the file is then replaced by plain JSON, and later
    /// deleted: each save lands SEALED under the key the process holds (the same salt, no new
    /// derivation) and opens with the owner's passphrase. `unseal_path` still writes plain.
    /// KILL: choose sealed-or-plain for a missing or plain target from `<PREFIX>_PASSPHRASE`
    /// alone again (the pre-fix `write_secret`) and both saves put the seed on disk in plain
    /// text (the `is_sealed` assertion fails).
    #[test]
    fn hr10_a_process_that_holds_the_key_never_writes_the_secret_plain() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        fast_kdf();
        std::env::remove_var("HK_WALLET_KEYFILE");
        std::env::remove_var("HK_WALLET_PASSPHRASE");
        forget(Secret::Wallet);
        let d = tmpdir("hr10-plain");
        let p = d.join("account.json");
        let owner = "correct horse battery staple";
        std::fs::write(&p, "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":0}").unwrap();
        let mut pass = Some(owner.to_string());
        seal_path(&p, Secret::Wallet, &mut pass).unwrap();
        let salt = sealed::parse(&std::fs::read_to_string(&p).unwrap()).unwrap().salt;

        // a fresh process: the passphrase from a file, the sealed file opened with it
        forget(Secret::Wallet);
        let f = d.join("wallet-passphrase");
        std::fs::write(&f, format!("{owner}\n")).unwrap();
        std::env::set_var("HK_WALLET_PASSPHRASE_FILE", &f);
        assert_eq!(read_secret(&p, Secret::Wallet).unwrap(), "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":0}");

        let sealed_under_the_held_key = |want: &str| {
            let raw = std::fs::read_to_string(&p).unwrap();
            assert!(sealed::is_sealed(&raw), "the secret must not be on disk in plain text: {raw}");
            let env = sealed::parse(&raw).unwrap();
            assert_eq!(env.salt, salt, "sealed under the key this process holds");
            assert_eq!(SealKey::for_envelope(&env, owner, None).unwrap().open(&env).unwrap(), want.as_bytes());
        };
        // (a) the file replaced by plain JSON: the save seals it
        std::fs::write(&p, "{\"seed\":\"ff\"}").unwrap();
        write_secret(&p, "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":1}", Secret::Wallet).unwrap();
        sealed_under_the_held_key("{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":1}");
        // (b) the file deleted: the save seals it
        std::fs::remove_file(&p).unwrap();
        write_secret(&p, "{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":2}", Secret::Wallet).unwrap();
        sealed_under_the_held_key("{\"seed\":\"00\",\"id\":\"11\",\"next_nonce\":2}");
        // the explicit command is still the way back to plain
        unseal_path(&p, Secret::Wallet).unwrap();
        assert!(!is_sealed_file(&p));
        assert!(std::fs::read_to_string(&p).unwrap().contains("\"next_nonce\":2"));
        std::env::remove_var("HK_WALLET_PASSPHRASE_FILE");
        forget(Secret::Wallet);
        let _ = std::fs::remove_dir_all(&d);
    }
}
