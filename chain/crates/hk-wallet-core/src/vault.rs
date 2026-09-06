//! Keys at rest (K1) as an INSTANCE, not the desktop wallet's process-wide statics: one
//! `Vault` per opened wallet directory. While a passphrase is set every secret file is
//! written sealed (`HKE1`: Argon2id → XChaCha20-Poly1305, the envelope `hk-node account-seal`
//! writes, so phone, PC and CLI share a file); while it is unset, files are written plain.
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

    /// Forget everything (lock / remove passphrase). The key file bytes and profile stay.
    pub fn clear(&mut self) {
        let keyfile = self.keyfile.take();
        let profile = self.profile;
        *self = Vault::default();
        self.keyfile = keyfile;
        self.profile = profile;
    }

    /// Put a passphrase back without deriving anything yet (rollback path); keys are
    /// derived per envelope as files are touched.
    pub fn restore_passphrase(&mut self, p: &str) {
        self.clear();
        self.passphrase = Some(p.to_string());
    }

    /// Set a NEW passphrase: derives a fresh key (fresh salt, the vault's profile) that
    /// becomes the primary.
    pub fn set_new_passphrase(&mut self, p: &str) -> Result<(), WalletError> {
        sealed::check_strength(p).map_err(WalletError::msg)?;
        let key = SealKey::new(p, self.keyfile.as_deref(), self.profile()).map_err(|e| WalletError::msg(e.to_string()))?;
        self.clear();
        self.passphrase = Some(p.to_string());
        self.primary = Some(key.salt_hex());
        self.keys.insert(key.salt_hex(), key);
        Ok(())
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

    fn key_for(&mut self, env: &Sealed) -> Result<(), WalletError> {
        let have = self.keys.get(&env.salt).map(|k| k.fits(env)).unwrap_or(false);
        if have {
            return Ok(());
        }
        let p = self.passphrase.clone().ok_or_else(|| WalletError::msg("locked"))?;
        let key = SealKey::for_envelope(env, &p, self.keyfile.as_deref()).map_err(|e| WalletError::msg(e.to_string()))?;
        if self.primary.is_none() {
            self.primary = Some(key.salt_hex());
        }
        self.keys.insert(key.salt_hex(), key);
        Ok(())
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
        self.key_for(&env)?;
        let bytes = self.keys[&env.salt].open(&env).map_err(|e| WalletError::msg(e.to_string()))?;
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

    /// The bytes to put on disk for `plaintext` at `path`: sealed while a passphrase is set
    /// (under the key of the envelope being replaced, else the primary key); plain otherwise.
    pub fn encode(&mut self, path: &Path, plaintext: &str) -> Result<String, WalletError> {
        if self.passphrase.is_none() {
            return Ok(plaintext.to_string());
        }
        let existing = std::fs::read_to_string(path).ok().filter(|s| sealed::is_sealed(s));
        let salt = match existing {
            Some(raw) => {
                let env = sealed::parse(&raw).map_err(|e| WalletError::msg(e.to_string()))?;
                self.key_for(&env)?;
                env.salt
            }
            None => match self.primary.clone() {
                Some(salt) => salt,
                None => {
                    // A new file with no primary key yet (e.g. right after a rollback): one derivation.
                    let p = self.passphrase.clone().ok_or_else(|| WalletError::msg("locked"))?;
                    let key = SealKey::new(&p, self.keyfile.as_deref(), self.profile()).map_err(|e| WalletError::msg(e.to_string()))?;
                    let salt = key.salt_hex();
                    self.primary = Some(salt.clone());
                    self.keys.insert(salt.clone(), key);
                    salt
                }
            },
        };
        self.keys[&salt].seal_to_json(plaintext).map_err(|e| WalletError::msg(e.to_string()))
    }
}

/// Write → fsync → rename. Both key files are reserve-then-advance counters; a crash right
/// after a reservation must never roll a counter back (a reused one-time key leaks spend
/// authority), so the bytes have to be on disk before the rename makes them the live file.
pub fn write_atomic(path: &Path, tmp: &Path, bytes: &[u8]) -> Result<(), WalletError> {
    use std::io::Write;
    let mut f = std::fs::File::create(tmp).map_err(|e| WalletError::msg(e.to_string()))?;
    f.write_all(bytes).map_err(|e| WalletError::msg(e.to_string()))?;
    f.sync_all().map_err(|e| WalletError::msg(e.to_string()))?;
    drop(f);
    std::fs::rename(tmp, path).map_err(|e| WalletError::msg(e.to_string()))
}
