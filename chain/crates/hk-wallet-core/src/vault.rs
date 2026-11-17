//! Keys at rest (K1) as an INSTANCE, not the desktop wallet's process-wide statics: one
//! `Vault` per opened wallet directory. While a passphrase is set every secret file is
//! written sealed (`HKE1`: Argon2id → XChaCha20-Poly1305, the envelope `hk-node account-seal`
//! writes, so phone, PC and CLI share a file); while it is unset, files are written plain.
//! HR-10 (v0.19.12): a save overwrites a sealed file only after a key of this vault has
//! OPENED it — a current key, a retired one (a passphrase this session replaced or rolled
//! back from), or one derived now from the session passphrase for that envelope; anything
//! else is refused and left on disk as it is ([`Vault::encode`]).
//!
//! Mobile differences from the desktop vault:
//! - the KDF profile is chosen by the caller: [`Kdf`] default (512 MiB / t4 — a PC) or the
//!   mobile profile (256 MiB / t3 — 2–4 s on a mid-range phone, fits a 4 GB device with the
//!   app's other allocations). The parameters ride in the envelope, so a file sealed on a
//!   phone opens on a PC and vice-versa;
//! - the optional key-file second factor is 32 bytes the APP hands in (Android Keystore
//!   releases them after a biometric or device-credential check) instead of an env path.
//!   Without the bytes a sealed-with-key-file envelope is refused by name, no KDF is run.
//! - the derived key is cached per salt (the one expensive step per unlock); re-seals are
//!   AEAD-only, exactly like the desktop.

use std::collections::HashMap;
use std::path::Path;

use hk_wallet::sealed::{self, Kdf, SealKey, Sealed};

use crate::WalletError;

/// Argon2id profile for phones: 256 MiB, 3 passes, 4 lanes (above the module floors).
pub fn mobile_profile() -> Kdf {
    Kdf { m_kib: 262_144, t: 3, p: 4 }
}

#[derive(Default)]
pub struct Vault {
    passphrase: Option<String>,
    /// Derived keys by salt; `primary` is the salt new files are sealed under.
    keys: HashMap<String, SealKey>,
    primary: Option<String>,
    /// HR-10 (v0.19.12): keys of passphrases this session replaced (`set_new_passphrase`) or
    /// rolled back from (`restore_passphrase`), by salt. They only OPEN — the proof a save
    /// needs before it overwrites a file sealed under one, and reads until then; nothing is
    /// sealed under a retired key. Dropped by `clear()` and `forget_retired()`.
    retired: HashMap<String, SealKey>,
    /// The app-supplied key-file bytes (Android Keystore), if any.
    keyfile: Option<Vec<u8>>,
    /// Profile for NEW envelopes (default = the desktop's; `mobile_profile()` on phones).
    profile: Option<Kdf>,
}

impl Vault {
    pub fn passphrase(&self) -> Option<&str> {
        self.passphrase.as_deref()
    }

    pub fn is_protected(&self) -> bool {
        self.passphrase.is_some()
    }

    pub fn set_keyfile(&mut self, bytes: Option<Vec<u8>>) {
        self.keyfile = bytes;
    }

    pub fn has_keyfile(&self) -> bool {
        self.keyfile.is_some()
    }

    pub fn set_profile(&mut self, kdf: Option<Kdf>) {
        self.profile = kdf;
    }

    fn profile(&self) -> Kdf {
        self.profile.unwrap_or_else(Kdf::default_profile)
    }

    /// Forget everything (lock / unlock / remove passphrase), retired keys included. The key
    /// file bytes and profile stay.
    pub fn clear(&mut self) {
        let keyfile = self.keyfile.take();
        let profile = self.profile;
        *self = Vault::default();
        self.keyfile = keyfile;
        self.profile = profile;
    }

    /// Put a passphrase back without deriving anything yet (the rollback of a failed
    /// `protect` / `unprotect`); keys are derived per envelope as files are touched. HR-10
    /// (v0.19.12): keys this vault still holds are RETIRED, not dropped — a failed `protect`
    /// may already have re-sealed files under the passphrase being rolled back from, and
    /// those must still open and save (each save re-seals under a key of `p`).
    pub fn restore_passphrase(&mut self, p: &str) {
        self.retire_keys();
        self.passphrase = Some(p.to_string());
    }

    /// Set a NEW passphrase: derives a fresh key (fresh salt, the vault's profile) that
    /// becomes the primary. HR-10 (v0.19.12): the keys of the passphrase being replaced are
    /// RETIRED, not dropped — `Wallet::protect` re-writes every secret file next, and each
    /// envelope on disk must be opened by a key of this vault before it is re-sealed under
    /// the new primary.
    pub fn set_new_passphrase(&mut self, p: &str) -> Result<(), WalletError> {
        sealed::check_strength(p).map_err(WalletError::msg)?;
        let key = SealKey::new(p, self.keyfile.as_deref(), self.profile()).map_err(|e| WalletError::msg(e.to_string()))?;
        self.retire_keys();
        self.passphrase = Some(p.to_string());
        self.primary = Some(key.salt_hex());
        self.keys.insert(key.salt_hex(), key);
        Ok(())
    }

    /// Move every current key to the retired ones and drop the primary.
    fn retire_keys(&mut self) {
        let keys = std::mem::take(&mut self.keys);
        self.retired.extend(keys);
        self.primary = None;
    }

    /// Drop the retired keys once a passphrase change has re-sealed every secret file under
    /// the new primary (the success path of `Wallet::protect`); `clear()` drops them too.
    pub fn forget_retired(&mut self) {
        self.retired.clear();
    }

    /// Does this file exist as an `HKE1` envelope?
    pub fn is_sealed_file(path: &Path) -> bool {
        std::fs::read_to_string(path).map(|s| sealed::is_sealed(&s)).unwrap_or(false)
    }

    /// A sealed file we cannot open right now (no passphrase in memory).
    pub fn is_locked(&self, path: &Path) -> bool {
        Self::is_sealed_file(path) && self.passphrase.is_none()
    }

    /// Does the envelope at `path` name a key file (second factor)?
    pub fn needs_keyfile(path: &Path) -> bool {
        std::fs::read_to_string(path).ok().and_then(|s| sealed::parse(&s).ok()).map(|e| e.kf.is_some()).unwrap_or(false)
    }

    /// Open `env` with a key of this vault: a current or a retired key that fits it (salt,
    /// parameters, key file), else one derived now from the session passphrase (+ key file).
    /// HR-10 (v0.19.12): a derived key is cached — and becomes the primary when there is none,
    /// as in `unlock` — only after it has OPENED the envelope; a retired key only opens, it
    /// never becomes a current one. Until v0.19.12 a derived key was cached before the open: a
    /// read of a file under another passphrase right after a rollback made that file's salt
    /// and parameters the primary, and the next new file was sealed under them.
    /// `did_not_open` maps the error of a key that was tried and did not open the envelope; a
    /// refusal before any key could be tried (locked, an envelope outside the KDF bounds or
    /// malformed, a missing key file) keeps its own message.
    fn open_own(&mut self, env: &Sealed, did_not_open: impl Fn(sealed::SealError) -> WalletError) -> Result<Vec<u8>, WalletError> {
        let current = self.keys.get(&env.salt).filter(|k| k.fits(env));
        if let Some(k) = current.or_else(|| self.retired.get(&env.salt).filter(|k| k.fits(env))) {
            return k.open(env).map_err(&did_not_open);
        }
        let p = self.passphrase.clone().ok_or_else(|| WalletError::msg("locked"))?;
        let key = SealKey::for_envelope(env, &p, self.keyfile.as_deref()).map_err(|e| WalletError::msg(e.to_string()))?;
        let bytes = key.open(env).map_err(&did_not_open)?;
        let salt = key.salt_hex();
        if self.primary.is_none() {
            self.primary = Some(salt.clone());
        }
        self.keys.insert(salt, key);
        Ok(bytes)
    }

    /// Read a secret file: `Ok(Some)` plain or opened; `Ok(None)` = sealed and locked;
    /// `Err` = wrong passphrase / missing key file / malformed / I/O.
    pub fn read(&mut self, path: &Path) -> Result<Option<String>, WalletError> {
        let raw = std::fs::read_to_string(path).map_err(|e| WalletError::msg(e.to_string()))?;
        if !sealed::is_sealed(&raw) {
            return Ok(Some(raw));
        }
        if self.passphrase.is_none() {
            return Ok(None);
        }
        let env = sealed::parse(&raw).map_err(|e| WalletError::msg(e.to_string()))?;
        let bytes = self.open_own(&env, |e| WalletError::msg(e.to_string()))?;
        String::from_utf8(bytes).map(Some).map_err(|e| WalletError::msg(e.to_string()))
    }

    /// Try a passphrase against `path`; on success it becomes the session passphrase and
    /// the derived key is cached (the one expensive step of the session).
    pub fn unlock(&mut self, path: &Path, candidate: &str) -> Result<(), WalletError> {
        let raw = std::fs::read_to_string(path).map_err(|e| WalletError::msg(e.to_string()))?;
        if !sealed::is_sealed(&raw) {
            self.clear();
            return Ok(());
        }
        let env = sealed::parse(&raw).map_err(|e| WalletError::msg(e.to_string()))?;
        let key = SealKey::for_envelope(&env, candidate, self.keyfile.as_deref()).map_err(|e| WalletError::msg(e.to_string()))?;
        key.open(&env).map_err(|e| WalletError::msg(e.to_string()))?;
        self.clear();
        self.passphrase = Some(candidate.to_string());
        self.primary = Some(key.salt_hex());
        self.keys.insert(key.salt_hex(), key);
        Ok(())
    }

    /// The bytes to put on disk for `plaintext` at `path`: sealed under the primary key while
    /// a passphrase is set, plain otherwise.
    ///
    /// HR-10 (v0.19.12): a save overwrites a sealed file only when this vault can show the
    /// file is its own — a key of the vault OPENS the envelope first (plaintext discarded): a
    /// current key, a retired one (a passphrase this session replaced or rolled back from: the
    /// old files of a passphrase change, the files a failed change already re-sealed), or one
    /// derived now from the session passphrase for the envelope's salt and parameters (a file
    /// sealed in an earlier session; cached once it opened, made the primary when there is
    /// none). Anything else — another passphrase, a tampered body, an envelope outside the KDF
    /// bounds — is refused (`SealError::NotOpened`, or the bound that failed) and the caller
    /// writes nothing. Until v0.19.12 the key was derived from the file's own salt and
    /// parameters, so an envelope swapped in at a wallet path had the real secret re-sealed
    /// under the attacker's salt and parameters at the next save. A missing or plain file is
    /// sealed under the primary as before. With no passphrase the plaintext is returned: the
    /// one writer over a sealed file then is `Wallet::unprotect`, which read every file first.
    pub fn encode(&mut self, path: &Path, plaintext: &str) -> Result<String, WalletError> {
        if self.passphrase.is_none() {
            return Ok(plaintext.to_string());
        }
        if let Some(raw) = std::fs::read_to_string(path).ok().filter(|s| sealed::is_sealed(s)) {
            // the proof before the overwrite: a key of this vault opens what is on disk, or
            // nothing is written (a derived key is bounded by `Kdf::validate` first)
            let env = sealed::parse(&raw).map_err(|e| WalletError::msg(e.to_string()))?;
            self.open_own(&env, |_| WalletError::msg(sealed::SealError::NotOpened.to_string()))?;
        }
        let salt = match self.primary.clone() {
            Some(salt) => salt,
            None => {
                // no current key (a new file right after a rollback, or a file only a retired
                // key opened): one derivation, the session passphrase and the vault's profile
                let p = self.passphrase.clone().ok_or_else(|| WalletError::msg("locked"))?;
                let key = SealKey::new(&p, self.keyfile.as_deref(), self.profile()).map_err(|e| WalletError::msg(e.to_string()))?;
                let salt = key.salt_hex();
                self.primary = Some(salt.clone());
                self.keys.insert(salt.clone(), key);
                salt
            }
        };
        self.keys[&salt].seal_to_json(plaintext).map_err(|e| WalletError::msg(e.to_string()))
    }
}

/// Write → fsync → rename → fsync(directory). Both key files are reserve-then-advance
/// counters; a crash right after a reservation must never roll a counter back (a reused
/// one-time key leaks spend authority), so the bytes have to be on disk before the rename
/// makes them the live file — AND the directory entry has to be on disk before the write is
/// reported done: on POSIX the rename alone sits in cached directory metadata, and a power
/// loss before the next journal commit brings the OLD file back (R16, 2026-09-22, found
/// for the consensus signer). `shield.json` is the file that matters here — its WOTS leaf
/// counter has no on-chain nonce to override it, so a rolled-back file IS a reused leaf.
/// The routine is `hk_crypto::fsutil` since R17 (reported 2026-10-06): this copy had
/// stopped at the rename. The caller names the temp file (`account.json.tmp`, beside the
/// live file) and creates the directory; errors stay `WalletError::msg`.
pub fn write_atomic(path: &Path, tmp: &Path, bytes: &[u8]) -> Result<(), WalletError> {
    hk_crypto::fsutil::write_atomic_with(path, tmp, bytes, None).map_err(|e| WalletError::msg(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hk_wallet::sealed::parse;
    use std::path::PathBuf;

    /// The floor profile, set on the vault explicitly (no env knob, no race with other tests).
    fn fast() -> Kdf {
        Kdf { m_kib: 65_536, t: 3, p: 1 }
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hk-vault-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The hex with its first digit changed: a body that no longer authenticates (always a
    /// change, unlike replacing a '0' a short ciphertext may not contain).
    fn tamper(hex: &str) -> String {
        let (first, rest) = hex.split_at(1);
        format!("{}{rest}", if first == "0" { "1" } else { "0" })
    }

    /// A shield file with recognisable counters (the wallet's real `shield.json` shape).
    fn shield_file(master: &str, ots: u32, tag: u64) -> crate::shield::ShieldFile {
        crate::shield::ShieldFile {
            version: 1,
            master_hex: master.repeat(32),
            next_ots_index: ots,
            next_note_tag: tag,
            scan: Default::default(),
            pools: Default::default(),
        }
    }

    /// HR-10 (v0.19.12): `encode` never overwrites a sealed file no key of this vault opens.
    /// (a) a foreign envelope at the path — another passphrase and salt — is refused
    /// (`NotOpened`), and with sub-floor labels refused by the bounds before any derivation;
    /// (b) a tampered body under the owner's own salt is refused; (c) a passphrase change
    /// re-seals the file, opened by the retired key, under the NEW passphrase's fresh primary
    /// salt (the old passphrase no longer opens it); (d) after a rollback the file, opened by a
    /// retired key, is re-sealed under a fresh key of the restored passphrase, and a foreign
    /// file in that state is refused with no key kept.
    /// KILL: re-seal, under the primary and without opening it first, an envelope whose salt
    /// this vault holds no key for, and (a) overwrites the foreign envelope instead of refusing
    /// it.
    #[test]
    fn hr10_encode_never_adopts_an_envelope_this_process_did_not_open() {
        let dir = tmp("hr10");
        let path = dir.join("account.json");
        let owner = "correct horse battery staple";
        let mut v = Vault::default();
        v.set_profile(Some(fast()));
        v.set_new_passphrase(owner).unwrap();
        let primary = v.primary.clone().unwrap();
        // a fresh file: sealed under the primary key
        let first = v.encode(&path, "{\"a\":1}").unwrap();
        std::fs::write(&path, &first).unwrap();
        let env1 = parse(&first).unwrap();
        assert_eq!(env1.salt, primary);
        assert_eq!((env1.m_kib, env1.t, env1.p), (65_536, 3, 1));

        // (a) a swapped foreign envelope — another passphrase, another salt: refused
        //     (`NotOpened`); with sub-floor 8 KiB / t1 / p1 labels refused by the bounds before
        //     any derivation; nothing of it is adopted or kept
        let attacker = SealKey::new("attacker chosen passphrase 1", None, fast()).unwrap();
        let foreign = attacker.seal(b"{\"evil\":true}").unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(&foreign).unwrap()).unwrap();
        let e = v.encode(&path, "{\"a\":2}").unwrap_err().to_string();
        assert!(e.contains("not the sealed file this process opened"), "{e}");
        let mut swapped = foreign.clone();
        swapped.m_kib = 8;
        swapped.t = 1;
        swapped.p = 1;
        std::fs::write(&path, serde_json::to_string_pretty(&swapped).unwrap()).unwrap();
        let e = v.encode(&path, "{\"a\":2}").unwrap_err().to_string();
        assert!(e.contains("kdf parameters out of range"), "{e}");
        assert_eq!(v.keys.len(), 1, "no key is kept for a file it did not open");
        assert_eq!(v.primary.as_deref(), Some(primary.as_str()));

        // (b) the owner's own envelope with a tampered body: the cached key fits its labels
        //     but does not open it → refused, nothing encoded
        let mut tampered = env1.clone();
        tampered.ct = tamper(&tampered.ct);
        std::fs::write(&path, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();
        let e = v.encode(&path, "{\"a\":3}").unwrap_err().to_string();
        assert!(e.contains("not the sealed file this process opened"), "{e}");

        // (c) a passphrase change: the file on disk is under the OLD passphrase; the retired
        //     key opens it and the save seals under the NEW passphrase's fresh primary salt —
        //     never under the old envelope's — and the old passphrase no longer opens it
        std::fs::write(&path, &first).unwrap();
        let second = "second passphrase for this wallet";
        v.set_new_passphrase(second).unwrap();
        let new_primary = v.primary.clone().unwrap();
        assert_ne!(new_primary, primary);
        let out = v.encode(&path, "{\"a\":4}").unwrap();
        let env4 = parse(&out).unwrap();
        assert_eq!(env4.salt, new_primary);
        assert_eq!(SealKey::for_envelope(&env4, second, None).unwrap().open(&env4).unwrap(), b"{\"a\":4}");
        assert!(SealKey::for_envelope(&env4, owner, None).unwrap().open(&env4).is_err());
        std::fs::write(&path, &out).unwrap();
        // the ordinary save that follows reuses the key it just sealed with (verified open)
        let again = parse(&v.encode(&path, "{\"a\":5}").unwrap()).unwrap();
        assert_eq!(again.salt, new_primary);

        // (d) a rollback restored the passphrase: no current key, the keys held are retired;
        //     the file on disk (under a retired key) is opened by it and re-sealed under a
        //     fresh key of the restored passphrase; a foreign file in that state is refused,
        //     and no key is kept for it
        v.restore_passphrase(second);
        assert!(v.primary.is_none() && v.keys.is_empty());
        assert!(v.retired.contains_key(&new_primary));
        let out6 = parse(&v.encode(&path, "{\"a\":6}").unwrap()).unwrap();
        assert_ne!(out6.salt, new_primary);
        assert_eq!(v.primary.as_deref(), Some(out6.salt.as_str()));
        assert_eq!(SealKey::for_envelope(&out6, second, None).unwrap().open(&out6).unwrap(), b"{\"a\":6}");
        v.restore_passphrase(second);
        std::fs::write(&path, attacker.seal_to_json("{\"evil\":true}").unwrap()).unwrap();
        let e = v.encode(&path, "{\"a\":7}").unwrap_err().to_string();
        assert!(e.contains("not the sealed file this process opened"), "{e}");
        assert!(v.keys.is_empty(), "a key that did not open the file is not kept");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// HR-10 (v0.19.12): `read` caches a key only after it has OPENED the file. After a
    /// rollback (`restore_passphrase`: the passphrase back, no key, no primary) a read of a
    /// foreign envelope — another passphrase, another salt, the floor profile — fails and
    /// leaves nothing behind: the next save of a NEW file is sealed under a fresh salt and the
    /// vault's own profile, and the primary is not the foreign salt. The owner's own file still
    /// opens through `read`, and its key is then cached and made the primary, as in `unlock`.
    /// KILL: cache the derived key before the open (the pre-fix `key_for`) and the foreign salt
    /// becomes the primary — the new file is sealed under the foreign salt and the floor
    /// parameters (the `assert_ne!(env.salt, foreign.salt)` fails).
    #[test]
    fn hr10_read_caches_a_key_only_after_it_opens_the_file() {
        let dir = tmp("hr10-read");
        let owner = "correct horse battery staple";
        // the vault's own profile: not the floor profile the foreign envelope carries
        let own = Kdf { m_kib: 65_536, t: 3, p: 2 };
        assert_ne!(own, fast());
        let mut v = Vault::default();
        v.set_profile(Some(own));
        v.restore_passphrase(owner);
        assert!(v.primary.is_none() && v.keys.is_empty());

        // a foreign envelope at a secret path: the read fails, nothing is kept or promoted
        let foreign_key = SealKey::new("attacker chosen passphrase 1", None, fast()).unwrap();
        let foreign_json = foreign_key.seal_to_json("{\"evil\":true}").unwrap();
        let foreign = parse(&foreign_json).unwrap();
        let shield = dir.join("shield.json");
        std::fs::write(&shield, &foreign_json).unwrap();
        assert!(v.read(&shield).is_err(), "the owner's passphrase does not open it");
        assert!(v.primary.is_none(), "a key that did not open the file is not made the primary");
        assert!(v.keys.is_empty(), "a key that did not open the file is not kept");

        // the next save of a NEW file: a fresh salt and the vault's own profile
        let account = dir.join("account.json");
        let out = v.encode(&account, "{\"a\":1}").unwrap();
        let env = parse(&out).unwrap();
        assert_ne!(env.salt, foreign.salt, "not sealed under the foreign salt");
        assert_eq!(Kdf { m_kib: env.m_kib, t: env.t, p: env.p }, own, "the vault's own parameters");
        assert_ne!(v.primary.as_deref(), Some(foreign.salt.as_str()));
        assert_eq!(v.primary.as_deref(), Some(env.salt.as_str()));
        assert_eq!(SealKey::for_envelope(&env, owner, None).unwrap().open(&env).unwrap(), b"{\"a\":1}");

        // the owner's own file in a later session that holds no key: `read` opens it, then
        // caches its key and makes it the primary
        std::fs::write(&account, &out).unwrap();
        let mut later = Vault::default();
        later.set_profile(Some(own));
        later.restore_passphrase(owner);
        assert_eq!(later.read(&account).unwrap().as_deref(), Some("{\"a\":1}"));
        assert_eq!(later.primary.as_deref(), Some(env.salt.as_str()));
        assert!(later.keys.contains_key(&env.salt));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// HR-10 (v0.19.12), through the wallet's own write path (`Wallet::write_secret`, which
    /// `save_account` and `save_shield` call): at `account.json` and at `shield.json` alike, a
    /// sealed file no key of the vault opens is refused — another passphrase (`NotOpened`),
    /// sub-floor labels (the bounds), the owner's own salt with a tampered body (`NotOpened`)
    /// — and the file is left byte for byte; the owner's own file then saves. KILL: re-seal,
    /// under the primary and without opening it, an envelope whose salt the vault holds no key
    /// for, and the foreign envelope is overwritten.
    #[test]
    fn hr10_a_foreign_envelope_at_a_wallet_path_is_refused_byte_for_byte() {
        let dir = tmp("hr10-wallet-refuse");
        let owner = "correct horse battery staple";
        let w = crate::Wallet::new(dir.to_string_lossy().to_string(), None);
        w.vault.lock().unwrap().set_profile(Some(fast()));
        w.create().unwrap();
        assert_eq!(w.protect(owner.to_string()).unwrap(), 1);
        let a = w.load_account().unwrap().unwrap();
        let own_json = std::fs::read_to_string(w.account_path()).unwrap();
        let primary = w.vault.lock().unwrap().primary.clone().unwrap();

        let foreign = SealKey::new("attacker chosen passphrase 1", None, fast()).unwrap().seal_to_json("{\"evil\":true}").unwrap();
        let mut sub_floor = parse(&foreign).unwrap();
        sub_floor.m_kib = 8;
        sub_floor.t = 1;
        sub_floor.p = 1;
        let sub_floor = serde_json::to_string_pretty(&sub_floor).unwrap();
        let mut tampered = parse(&own_json).unwrap();
        tampered.ct = tamper(&tampered.ct);
        let tampered = serde_json::to_string_pretty(&tampered).unwrap();
        for (swapped, why) in [
            (&foreign, "not the sealed file this process opened"),
            (&sub_floor, "kdf parameters out of range"),
            (&tampered, "not the sealed file this process opened"),
        ] {
            for (path, tmp_name) in [(w.account_path(), "account.json.tmp"), (w.shield_path(), "shield.json.tmp")] {
                std::fs::write(&path, swapped).unwrap();
                let e = w.write_secret(&path, tmp_name, "{\"a\":1}").unwrap_err().to_string();
                assert!(e.contains(why), "{}: {e}", path.display());
                assert_eq!(std::fs::read(&path).unwrap(), swapped.as_bytes(), "{} left byte for byte", path.display());
            }
        }
        {
            let v = w.vault.lock().unwrap();
            assert_eq!(v.keys.len(), 1, "no key is kept for a file it did not open");
            assert_eq!(v.primary.as_deref(), Some(primary.as_str()));
        }
        // the owner's own file still saves, under the primary
        std::fs::write(w.account_path(), &own_json).unwrap();
        w.save_account(&a).unwrap();
        assert_eq!(parse(&std::fs::read_to_string(w.account_path()).unwrap()).unwrap().salt, primary);
        assert_eq!(w.load_account().unwrap(), Some(a));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// HR-10 (v0.19.12): a passphrase change re-seals every secret file under the new key.
    /// `account.json` is under the session's key, `shield.json` under another salt of the same
    /// passphrase (sealed in an earlier session). `Wallet::protect` reads both, retires their
    /// keys (`set_new_passphrase`) and re-writes both: each envelope is opened by a retired
    /// key and re-sealed under the new primary, which opens with the new passphrase only.
    /// KILL: let `set_new_passphrase` drop the old keys (`clear()`, the previous tree) and the
    /// change is refused — no key of the vault opens the old envelopes any more.
    #[test]
    fn hr10_a_passphrase_change_reseals_every_file_under_the_new_key() {
        let dir = tmp("hr10-change");
        let (first, second) = ("correct horse battery staple", "second passphrase for this wallet");
        let w = crate::Wallet::new(dir.to_string_lossy().to_string(), None);
        w.vault.lock().unwrap().set_profile(Some(fast()));
        w.create().unwrap();
        w.protect(first.to_string()).unwrap();
        let a = w.load_account().unwrap().unwrap();
        let earlier = SealKey::new(first, None, fast()).unwrap();
        let shield = shield_file("11", 3, 5);
        std::fs::write(w.shield_path(), earlier.seal_to_json(&serde_json::to_string_pretty(&shield).unwrap()).unwrap()).unwrap();
        let old_salts = [parse(&std::fs::read_to_string(w.account_path()).unwrap()).unwrap().salt, earlier.salt_hex()];
        assert_ne!(old_salts[0], old_salts[1]);

        assert_eq!(w.protect(second.to_string()).unwrap(), 2);
        let new_primary = w.vault.lock().unwrap().primary.clone().unwrap();
        assert!(!old_salts.contains(&new_primary));
        let account_env = parse(&std::fs::read_to_string(w.account_path()).unwrap()).unwrap();
        let shield_env = parse(&std::fs::read_to_string(w.shield_path()).unwrap()).unwrap();
        assert_eq!((account_env.salt.as_str(), shield_env.salt.as_str()), (new_primary.as_str(), new_primary.as_str()));
        let k2 = SealKey::for_envelope(&account_env, second, None).unwrap();
        let back: crate::account::AccountFile = serde_json::from_slice(&k2.open(&account_env).unwrap()).unwrap();
        assert_eq!(back, a);
        let s: crate::shield::ShieldFile = serde_json::from_slice(&k2.open(&shield_env).unwrap()).unwrap();
        assert_eq!((s.master_hex.as_str(), s.next_ots_index, s.next_note_tag), (shield.master_hex.as_str(), 3, 5));
        assert!(SealKey::for_envelope(&account_env, first, None).unwrap().open(&account_env).is_err(), "the old passphrase opens neither");
        // the change is complete: the retired keys can go, and both files still save
        w.vault.lock().unwrap().forget_retired();
        w.save_account(&a).unwrap();
        w.save_shield(&s).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    /// HR-10 (v0.19.12): a file sealed in an earlier session under the same passphrase, and
    /// not read in this one, is re-sealed — not refused: a key derived for its envelope from
    /// the session passphrase opens it, is kept, and the save goes under the primary. With no
    /// key held at all (right after `restore_passphrase`), the derived key that opened the
    /// file becomes the primary. KILL: refuse every envelope whose salt has no key held (drop
    /// the derive-and-open step of `open_own`) and both saves are refused.
    #[test]
    fn hr10_a_file_sealed_in_an_earlier_session_is_resealed_not_refused() {
        let dir = tmp("hr10-earlier");
        let owner = "correct horse battery staple";
        let (account, shield) = (dir.join("account.json"), dir.join("shield.json"));
        let earlier = SealKey::new(owner, None, fast()).unwrap();
        std::fs::write(&shield, earlier.seal_to_json("{\"s\":1}").unwrap()).unwrap();
        let now = SealKey::new(owner, None, fast()).unwrap();
        std::fs::write(&account, now.seal_to_json("{\"a\":1}").unwrap()).unwrap();
        // this session unlocks with account.json and never reads shield.json
        let mut v = Vault::default();
        v.set_profile(Some(fast()));
        v.unlock(&account, owner).unwrap();
        assert_eq!(v.primary.as_deref(), Some(now.salt_hex().as_str()));
        assert!(!v.keys.contains_key(&earlier.salt_hex()));
        let out = parse(&v.encode(&shield, "{\"s\":2}").unwrap()).unwrap();
        assert_eq!(out.salt, now.salt_hex(), "re-sealed under the primary");
        assert_eq!(now.open(&out).unwrap(), b"{\"s\":2}");
        assert!(v.keys.contains_key(&earlier.salt_hex()), "the key that opened it is kept");
        // no key held at all (a rollback): the derived key that opened the file is adopted
        let mut fresh = Vault::default();
        fresh.set_profile(Some(fast()));
        fresh.restore_passphrase(owner);
        let out = parse(&fresh.encode(&shield, "{\"s\":3}").unwrap()).unwrap();
        assert_eq!(out.salt, earlier.salt_hex());
        assert_eq!(fresh.primary.as_deref(), Some(earlier.salt_hex().as_str()));
        assert_eq!(earlier.open(&out).unwrap(), b"{\"s\":3}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// HR-10 (v0.19.12): after a failed passphrase change the owner's files still open and
    /// save. `Wallet::protect` to a second passphrase re-seals `account.json`, then fails on
    /// `shield.json` (its temp path is a directory) and rolls back with `restore_passphrase`:
    /// `account.json` is on disk under the NEW passphrase, `shield.json` under the old one.
    /// Both still load and save — re-sealed under a fresh key of the restored passphrase — and
    /// a foreign envelope is still refused, the file left as it was. KILL: drop the held keys
    /// in `restore_passphrase` (`clear()`, the previous tree) and `account.json` no longer
    /// opens or saves under the restored passphrase.
    #[test]
    fn hr10_after_a_failed_protect_the_owner_files_still_save() {
        let dir = tmp("hr10-rollback");
        let (first, second) = ("correct horse battery staple", "second passphrase for this wallet");
        let w = crate::Wallet::new(dir.to_string_lossy().to_string(), None);
        w.vault.lock().unwrap().set_profile(Some(fast()));
        w.create().unwrap();
        w.protect(first.to_string()).unwrap();
        let a = w.load_account().unwrap().unwrap();
        let shield = shield_file("22", 7, 9);
        w.save_shield(&shield).unwrap();
        let blocker = dir.join("shield.json.tmp");
        std::fs::create_dir_all(&blocker).unwrap();
        assert!(w.protect(second.to_string()).is_err(), "the shield.json write fails");
        std::fs::remove_dir_all(&blocker).unwrap();
        // the failed change got as far as account.json, which is under the second passphrase
        let half = parse(&std::fs::read_to_string(w.account_path()).unwrap()).unwrap();
        assert!(SealKey::for_envelope(&half, second, None).unwrap().open(&half).is_ok());
        {
            let v = w.vault.lock().unwrap();
            assert_eq!(v.passphrase(), Some(first), "rolled back to the first passphrase");
            assert!(v.retired.contains_key(&half.salt), "the failed change's key is kept, retired");
        }
        // both files still load, and save under a fresh key of the restored passphrase
        assert_eq!(w.load_account().unwrap(), Some(a.clone()));
        w.save_account(&a).unwrap();
        let s = w.load_shield().unwrap().unwrap();
        assert_eq!((s.master_hex.as_str(), s.next_ots_index, s.next_note_tag), (shield.master_hex.as_str(), 7, 9));
        w.save_shield(&s).unwrap();
        let account_env = parse(&std::fs::read_to_string(w.account_path()).unwrap()).unwrap();
        let shield_env = parse(&std::fs::read_to_string(w.shield_path()).unwrap()).unwrap();
        assert_eq!(account_env.salt, shield_env.salt);
        let k1 = SealKey::for_envelope(&account_env, first, None).unwrap();
        assert!(k1.open(&account_env).is_ok() && k1.open(&shield_env).is_ok(), "both under the restored passphrase");
        // and a foreign envelope is still refused, the file left as it was
        let foreign = SealKey::new("attacker chosen passphrase 1", None, fast()).unwrap().seal_to_json("{\"evil\":true}").unwrap();
        std::fs::write(w.account_path(), &foreign).unwrap();
        let e = w.save_account(&a).unwrap_err().to_string();
        assert!(e.contains("not the sealed file this process opened"), "{e}");
        assert_eq!(std::fs::read(w.account_path()).unwrap(), foreign.as_bytes());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// HR-10 (v0.19.12): a completed passphrase change drops the retired keys
    /// (`forget_retired`, in `Wallet::protect`'s success arm). `account.json` as sealed under
    /// the OLD passphrase is put back at the path after the change, so no re-write touched it:
    /// it no longer opens — not through `load_account`, and not as the proof a save needs — so
    /// the save is refused and the file left byte for byte; the retired map is empty. Only a
    /// retired key could open it (the session passphrase is the new one). KILL: remove the
    /// `forget_retired()` call from `protect`'s success arm and the old envelope opens again
    /// through the retired key (the load succeeds and the save re-seals it).
    #[test]
    fn hr10_a_completed_passphrase_change_drops_the_retired_keys() {
        let dir = tmp("hr10-forget");
        let (first, second) = ("correct horse battery staple", "second passphrase for this wallet");
        let w = crate::Wallet::new(dir.to_string_lossy().to_string(), None);
        w.vault.lock().unwrap().set_profile(Some(fast()));
        w.create().unwrap();
        w.protect(first.to_string()).unwrap();
        let a = w.load_account().unwrap().unwrap();
        let under_first = std::fs::read(w.account_path()).unwrap();
        assert_eq!(w.protect(second.to_string()).unwrap(), 1);
        assert!(w.vault.lock().unwrap().retired.is_empty(), "the change is complete: no retired key is kept");
        // the old envelope, back at the path: no key of the vault opens it any more
        std::fs::write(w.account_path(), &under_first).unwrap();
        assert!(w.load_account().is_err(), "the old envelope no longer opens");
        let e = w.save_account(&a).unwrap_err().to_string();
        assert!(e.contains("not the sealed file this process opened"), "{e}");
        assert_eq!(std::fs::read(w.account_path()).unwrap(), under_first, "left byte for byte");
        let _ = std::fs::remove_dir_all(dir);
    }
}
