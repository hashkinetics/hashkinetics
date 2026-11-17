//! K1/K2 (v0.16.0) — keys at rest: the `HKE1` sealed-file envelope.
//!
//! Every secret file HashKinetics writes to disk (`account.json`, `wallet.json`,
//! `shield.json`, `priv_validator_key.json`) can be stored **sealed**: the plaintext
//! JSON is encrypted with XChaCha20-Poly1305 under a key derived from a passphrase by
//! Argon2id. The envelope is itself JSON so an operator can see *what* a file is
//! without opening it:
//!
//! ```json
//! { "hke": 1, "kdf": "argon2id", "m_kib": 524288, "t": 4, "p": 4,
//!   "salt": "<16 bytes hex>", "nonce": "<24 bytes hex>", "ct": "<hex>", "kf": "<8 hex, optional>" }
//! ```
//!
//! The additional authenticated data is the constant `hk/v1/sealed`, so a ciphertext
//! cannot be re-labelled as another format. A wrong passphrase fails the tag — there
//! is no partial decrypt. Sealing is optional and per file: a plain file keeps working
//! (the loaders sniff the envelope), so an operator upgrades at their own pace with
//! `hk-node key-seal` / `account-seal`, and back with `key-unseal` / `account-unseal`.
//!
//! **Brute force, honestly.** An attacker with a copy of the file can try passphrases
//! offline for as long as they like; the only two things that slow them down are the
//! cost of ONE guess and the number of guesses your passphrase forces. This module
//! spends on both:
//! - **One guess is expensive and memory-hard.** Default Argon2id 512 MiB, t=4, p=4
//!   (≈1 s on a laptop, the QE-Vault profile brought to a size a validator host can
//!   afford; `HK_SEAL_M_KIB` / `HK_SEAL_T` raise or lower it, never below 64 MiB / t=3 and
//!   never above 2 GiB / t=64). Memory-hardness is the lever against GPUs: a 24 GB card
//!   fits ~48 guesses of 512 MiB at a time, and each is memory-bound, so a card manages tens
//!   of guesses per second, not billions. The parameters ride in the envelope; a file opens
//!   with its own parameters within the floor and the ceiling ([`Kdf::validate`], HR-10,
//!   v0.19.12 — a presented envelope can neither make a guess cheap nor make the opener spend
//!   more than the ceiling before authenticating), and a save never adopts an envelope this
//!   process did not open (the node's and the wallet core's write paths verify-then-adopt).
//! - **The KDF runs once per unlock, not once per save.** [`SealKey`] keeps the derived
//!   key (same salt) so reserve-then-sign re-seals in microseconds with a fresh nonce.
//!   That is what makes a heavy KDF affordable.
//! - **The passphrase is checked, not trusted.** [`check_strength`] refuses fewer than
//!   12 characters unless it is a 4+-word passphrase, refuses the obvious, and the GUI
//!   offers [`generate_passphrase`]: 7 words from a 512-word list = 63 bits, beyond any
//!   offline attack at this KDF cost (2^63 guesses × ≥ 10 ms each = millions of GPU-years).
//! - **Optional key file (second factor).** `<PREFIX>_KEYFILE=<path>` mixes 32 random
//!   bytes into the key (`hk-node keyfile-new PATH`). Without the file, the passphrase
//!   is not enough — brute force becomes impossible rather than slow. The envelope
//!   records the key file's 8-hex fingerprint (`kf`) so a loader can name the file it
//!   needs. Keep it on a different device than the backup.
//!
//! **Where the passphrase comes from** (first hit wins), see [`passphrase_from_env`]:
//! `<PREFIX>_PASSPHRASE` · `<PREFIX>_PASSPHRASE_FILE` (first line) · systemd
//! `$CREDENTIALS_DIRECTORY/<credential>` (`LoadCredential=` — root-only file, never in
//! the unit's environment) · an interactive prompt when stdin is a terminal.
//!
//! **What this protects against:** a leaked backup, a stolen disk image, a copied home
//! directory. It does NOT protect a running node — the seed is in memory while the
//! process signs. An HSM path (SP 800-208 LMS signing inside the module) is the next
//! step and is documented in `docs/MAINNET-KEY-MANAGEMENT.md`; this module is the
//! interface it will plug into (a `Signer` that never sees the seed). Post-quantum note:
//! a 256-bit symmetric key under Argon2id is already quantum-safe (Grover halves it to
//! 128 bits); no lattice KEM is needed for a local file.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hk_crypto::hash::shake256_32;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const AAD: &[u8] = b"hk/v1/sealed";
/// Default KDF profile (see the module docs for why): 512 MiB, 4 passes, 4 lanes.
pub const DEFAULT_M_KIB: u32 = 524_288;
pub const DEFAULT_T: u32 = 4;
pub const DEFAULT_P: u32 = 4;
/// Floors: nothing this module writes goes below the v0.16.0-rc profile — and, since
/// HR-10 (v0.19.12), nothing it OPENS either: an envelope presented with weaker parameters
/// is refused before any key derivation ([`Kdf::validate`]).
pub const MIN_M_KIB: u32 = 65_536;
pub const MIN_T: u32 = 3;
/// Ceilings (HR-10, v0.19.12): the most Argon2 work an envelope can make a process do
/// before it has authenticated anything — 2 GiB of memory, 64 passes, 16 lanes. Every
/// profile this project writes (512 MiB default, 256 MiB mobile, 128 MiB small hosts, the
/// 64 MiB floor the tests use) sits inside. A file sealed above the memory ceiling by an
/// older binary (v0.16.0–v0.19.11 clamped `HK_SEAL_M_KIB` only from below) is refused by
/// name — [`SealError::OverCeiling`] gives the value, the ceiling and the way back: unseal it
/// with that binary, re-seal it with this one. Until v0.19.12 the read side had ceilings (8 GiB,
/// t 64, p 16) and m ≥ 8·p, no floor; a swapped envelope could demand 8 GiB at every open or save.
pub const MAX_M_KIB: u32 = 2_097_152;
pub const MAX_T: u32 = 64;
pub const MAX_P: u32 = 16;
const KEYFILE_LEN: usize = 32;

/// The on-disk envelope.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Sealed {
    pub hke: u32,
    pub kdf: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt: String,
    pub nonce: String,
    pub ct: String,
    /// Fingerprint of the key file this envelope needs (absent = passphrase only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kf: Option<String>,
}

/// Argon2id parameters (kibibytes, passes, lanes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Kdf {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Kdf {
    /// The profile new envelopes are written with: the defaults, unless
    /// `HK_SEAL_M_KIB` / `HK_SEAL_T` say otherwise (clamped to the floors AND the ceilings —
    /// HR-10, v0.19.12 — so an operator cannot write an envelope this module refuses to open).
    /// The two variables' values go through [`Kdf::profile_from`].
    pub fn default_profile() -> Self {
        let m_kib = std::env::var("HK_SEAL_M_KIB").ok();
        let t = std::env::var("HK_SEAL_T").ok();
        Self::profile_from(m_kib.as_deref(), t.as_deref())
    }

    /// The profile for the raw values of `HK_SEAL_M_KIB` and `HK_SEAL_T` (`None` = unset): each
    /// trimmed and parsed as a `u32` — absent or unparsable means the default — then clamped to
    /// the floor and the ceiling; the lanes stay `DEFAULT_P`. No environment is read here, so
    /// the clamps are tested without touching the process-wide environment.
    pub fn profile_from(m_kib: Option<&str>, t: Option<&str>) -> Self {
        let parse = |v: Option<&str>| v.and_then(|s| s.trim().parse::<u32>().ok());
        Kdf {
            m_kib: parse(m_kib).unwrap_or(DEFAULT_M_KIB).clamp(MIN_M_KIB, MAX_M_KIB),
            t: parse(t).unwrap_or(DEFAULT_T).clamp(MIN_T, MAX_T),
            p: DEFAULT_P,
        }
    }

    /// HR-10 (v0.19.12): the one bound every key derivation passes, on both sides —
    /// `MIN_M_KIB ≤ m_kib ≤ MAX_M_KIB`, `MIN_T ≤ t ≤ MAX_T`, `1 ≤ p ≤ MAX_P`, and Argon2's own
    /// `m_kib ≥ 8·p`. [`derive_key`] calls it first, so [`SealKey::new`] (a profile this
    /// process chose) and [`SealKey::for_envelope`] (parameters read from a file) are both
    /// covered: a presented envelope can neither make a guess cheap (below the floor) nor
    /// make this process burn gigabytes before it has authenticated anything (above the
    /// ceiling). The error names the bound that failed. An envelope's memory above the
    /// ceiling is refused earlier, by name, in [`SealKey::for_envelope`]
    /// ([`SealError::OverCeiling`]); a profile this process chose gets the error below.
    pub fn validate(&self) -> Result<(), SealError> {
        let Kdf { m_kib, t, p } = *self;
        let out_of_range = |what: String| SealError::Format(format!("kdf parameters out of range: {what}"));
        if !(MIN_M_KIB..=MAX_M_KIB).contains(&m_kib) {
            return Err(out_of_range(format!(
                "m_kib {m_kib} (allowed {MIN_M_KIB}..={MAX_M_KIB}, i.e. 64 MiB..=2 GiB)"
            )));
        }
        if !(MIN_T..=MAX_T).contains(&t) {
            return Err(out_of_range(format!("t {t} (allowed {MIN_T}..={MAX_T})")));
        }
        if !(1..=MAX_P).contains(&p) {
            return Err(out_of_range(format!("p {p} (allowed 1..={MAX_P})")));
        }
        // Argon2's own rule. It cannot fail while the bounds above hold (m_kib ≥ 65,536 and
        // p ≤ 16 give 8 × p ≤ 128); it stays so the check is complete if a bound changes.
        if m_kib < 8 * p {
            return Err(out_of_range(format!("m_kib {m_kib} below 8 × p = {}", 8 * p)));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum SealError {
    Kdf(String),
    Cipher,
    Format(String),
    NoPassphrase(String),
    /// The envelope was sealed with a key file this process does not have.
    NoKeyfile(String),
    WeakPassphrase(String),
    /// HR-10 (v0.19.12): a save found an envelope at the path that this process's key does
    /// not open — not the file this process read (another run re-sealed it under a different
    /// passphrase, or it was replaced) — and nothing is ever re-sealed under a key derived for
    /// a file that was not opened (the swapped-envelope downgrade path).
    NotOpened,
    /// HR-10 (v0.19.12): an envelope's Argon2id memory (KiB) is above [`MAX_M_KIB`]. This
    /// binary never seals above it; v0.16.0–v0.19.11 did when `HK_SEAL_M_KIB` asked for more,
    /// so the refusal names the value, the ceiling and the way back instead of calling the
    /// file malformed. No key derivation runs.
    OverCeiling(u32),
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealError::Kdf(e) => write!(f, "key derivation failed: {e}"),
            SealError::Cipher => write!(f, "wrong passphrase (or the file was tampered with)"),
            SealError::Format(e) => write!(f, "sealed file is malformed: {e}"),
            SealError::NoPassphrase(hint) => write!(f, "this file is sealed — {hint}"),
            SealError::NoKeyfile(id) => write!(f, "this file is sealed with key file {id} — set the *_KEYFILE path to it"),
            SealError::WeakPassphrase(why) => write!(f, "passphrase refused: {why}"),
            SealError::NotOpened => write!(
                f,
                "the file on disk is not the sealed file this process opened — re-sealed by another run or replaced; refusing to overwrite it"
            ),
            SealError::OverCeiling(m_kib) => write!(
                f,
                "this file asks for {m_kib} KiB ({} MiB) of Argon2id memory, above the {MAX_M_KIB} KiB (2 GiB) ceiling this binary opens (HR-10, v0.19.12): it was sealed by an older binary (v0.16.0–v0.19.11 allowed more) — unseal it with that binary (`hk-node key-unseal <HOME>` or `hk-node account-unseal <DIR>`; in a wallet app, remove the passphrase), then re-seal it with this one (`hk-node key-seal <HOME>` or `hk-node account-seal <DIR>`; in a wallet app, set the passphrase again)",
                (u64::from(*m_kib) + 1023) / 1024
            ),
        }
    }
}

impl std::error::Error for SealError {}

/// Is this file content an `HKE1` envelope?
pub fn is_sealed(content: &str) -> bool {
    let t = content.trim_start();
    t.starts_with('{') && t.contains("\"hke\"")
}

/// Parse an envelope (after [`is_sealed`]).
pub fn parse(content: &str) -> Result<Sealed, SealError> {
    serde_json::from_str(content).map_err(|e| SealError::Format(e.to_string()))
}

/// The one place the KDF runs. HR-10 (v0.19.12): the parameters are bounded first
/// ([`Kdf::validate`]) — whoever chose them, this process or a file.
fn derive_key(passphrase: &str, salt: &[u8], kdf: Kdf) -> Result<[u8; 32], SealError> {
    kdf.validate()?;
    let params = Params::new(kdf.m_kib, kdf.t, kdf.p, Some(32)).map_err(|e| SealError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| SealError::Kdf(e.to_string()))?;
    Ok(key)
}

fn os_random(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut out); // H12 rule: OS CSPRNG, no userspace generator state
    out
}

/// 8-hex fingerprint of a key file (what the envelope's `kf` names).
pub fn keyfile_id(keyfile: &[u8]) -> String {
    hex::encode(&shake256_32("hk/v1/sealed-keyfile-id", &[keyfile])[..4])
}

/// Fresh key-file bytes (`hk-node keyfile-new`).
pub fn new_keyfile() -> Vec<u8> {
    os_random(KEYFILE_LEN)
}

/// Read `<PREFIX>_KEYFILE` if set: the bytes and their fingerprint.
pub fn keyfile_from_env(prefix: &str) -> Result<Option<Vec<u8>>, SealError> {
    match std::env::var(format!("{prefix}_KEYFILE")) {
        Ok(path) if !path.trim().is_empty() => {
            let bytes = std::fs::read(path.trim()).map_err(|e| SealError::Format(format!("{prefix}_KEYFILE: {e}")))?;
            if bytes.len() < 16 {
                return Err(SealError::Format(format!("{prefix}_KEYFILE is too short ({} bytes; need ≥ 16)", bytes.len())));
            }
            Ok(Some(bytes))
        }
        _ => Ok(None),
    }
}

/// A derived sealing key: the expensive part of the KDF, done once, reusable for every
/// re-seal of files that share this salt (fresh nonce each time — the nonce space is
/// 192 bits, so reuse of the key is what XChaCha20-Poly1305 is designed for).
pub struct SealKey {
    key: [u8; 32],
    salt: Vec<u8>,
    kdf: Kdf,
    kf: Option<String>,
}

impl Drop for SealKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl SealKey {
    fn finish(mut key: [u8; 32], salt: Vec<u8>, kdf: Kdf, keyfile: Option<&[u8]>) -> Self {
        let kf = keyfile.map(|kfb| {
            // The key file is a second factor: the final key needs BOTH the passphrase
            // derivation and the file's bytes. Domain-separated SHAKE-256 (the repo's hash).
            let mixed = shake256_32("hk/v1/sealed-keyfile-mix", &[&key, kfb]);
            key.zeroize();
            key = mixed;
            keyfile_id(kfb)
        });
        SealKey { key, salt, kdf, kf }
    }

    /// Derive with a fresh salt under `kdf` (what `seal` commands and "Protect" use).
    pub fn new(passphrase: &str, keyfile: Option<&[u8]>, kdf: Kdf) -> Result<Self, SealError> {
        if passphrase.is_empty() {
            return Err(SealError::Kdf("empty passphrase".into()));
        }
        let salt = os_random(16);
        let key = derive_key(passphrase, &salt, kdf)?;
        Ok(Self::finish(key, salt, kdf, keyfile))
    }

    /// Derive for an existing envelope: its salt and parameters (an unlock).
    ///
    /// HR-10 (v0.19.12): the parameters are bounded on BOTH sides first (`Kdf::validate`,
    /// before the key-file and salt checks, before any derivation), and every cheap shape
    /// check — the salt, the 24-byte nonce, the hex of nonce and ciphertext — runs before
    /// the KDF, so a malformed envelope costs nothing and a presented one costs at most the
    /// ceiling. Until v0.19.12 only the ceilings (8 GiB, t 64, p 16) and m ≥ 8·p were tested here;
    /// the writer's floor was never applied to a file being opened. Memory above the ceiling is
    /// refused first and by name ([`SealError::OverCeiling`]): such a file can be the owner's
    /// own, sealed by an older binary, and the error says how to bring it inside the bounds.
    pub fn for_envelope(sealed: &Sealed, passphrase: &str, keyfile: Option<&[u8]>) -> Result<Self, SealError> {
        if sealed.hke != 1 || sealed.kdf != "argon2id" {
            return Err(SealError::Format(format!("unsupported envelope hke={} kdf={}", sealed.hke, sealed.kdf)));
        }
        let kdf = Kdf { m_kib: sealed.m_kib, t: sealed.t, p: sealed.p };
        if kdf.m_kib > MAX_M_KIB {
            return Err(SealError::OverCeiling(kdf.m_kib));
        }
        kdf.validate()?;
        if let Some(want) = &sealed.kf {
            match keyfile {
                None => return Err(SealError::NoKeyfile(want.clone())),
                Some(kfb) if keyfile_id(kfb) != *want => {
                    return Err(SealError::NoKeyfile(format!("{want} (the key file given is {})", keyfile_id(kfb))))
                }
                _ => {}
            }
        }
        if passphrase.is_empty() {
            return Err(SealError::Kdf("empty passphrase".into()));
        }
        let salt = hex::decode(&sealed.salt).map_err(|e| SealError::Format(e.to_string()))?;
        if salt.len() < 8 {
            return Err(SealError::Format("salt too short".into()));
        }
        decode_body(sealed)?;
        let key = derive_key(passphrase, &salt, kdf)?;
        Ok(Self::finish(key, salt, kdf, keyfile))
    }

    /// Does this key belong to `sealed` (same salt, parameters and key file)?
    pub fn fits(&self, sealed: &Sealed) -> bool {
        hex::encode(&self.salt) == sealed.salt
            && self.kdf == Kdf { m_kib: sealed.m_kib, t: sealed.t, p: sealed.p }
            && self.kf == sealed.kf
    }

    pub fn salt_hex(&self) -> String {
        hex::encode(&self.salt)
    }

    pub fn kdf(&self) -> Kdf {
        self.kdf
    }

    pub fn keyfile_id(&self) -> Option<&str> {
        self.kf.as_deref()
    }

    /// Seal plaintext under this key: fresh 24-byte nonce, same salt.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Sealed, SealError> {
        let nonce = os_random(24);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: AAD })
            .map_err(|_| SealError::Cipher)?;
        Ok(Sealed {
            hke: 1,
            kdf: "argon2id".into(),
            m_kib: self.kdf.m_kib,
            t: self.kdf.t,
            p: self.kdf.p,
            salt: hex::encode(&self.salt),
            nonce: hex::encode(nonce),
            ct: hex::encode(ct),
            kf: self.kf.clone(),
        })
    }

    /// Pretty JSON of [`SealKey::seal`] (the file body).
    pub fn seal_to_json(&self, plaintext: &str) -> Result<String, SealError> {
        let s = self.seal(plaintext.as_bytes())?;
        serde_json::to_string_pretty(&s).map_err(|e| SealError::Format(e.to_string()))
    }

    /// Open an envelope sealed under this key (salt/params/key file must match).
    pub fn open(&self, sealed: &Sealed) -> Result<Vec<u8>, SealError> {
        if !self.fits(sealed) {
            return Err(SealError::Format("this key was derived for a different envelope (salt/params/key file)".into()));
        }
        let (nonce, ct) = decode_body(sealed)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));
        cipher
            .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ct, aad: AAD })
            .map_err(|_| SealError::Cipher)
    }
}

/// The envelope's nonce and ciphertext as bytes — the cheap shape checks (hex, a 24-byte
/// nonce, a ciphertext that at least holds its 16-byte tag). HR-10 (v0.19.12): run by
/// `for_envelope` BEFORE the KDF as well as by `open`, so a malformed file never costs a
/// derivation.
fn decode_body(sealed: &Sealed) -> Result<(Vec<u8>, Vec<u8>), SealError> {
    let nonce = hex::decode(&sealed.nonce).map_err(|e| SealError::Format(e.to_string()))?;
    let ct = hex::decode(&sealed.ct).map_err(|e| SealError::Format(e.to_string()))?;
    if nonce.len() != 24 {
        return Err(SealError::Format("nonce must be 24 bytes".into()));
    }
    if ct.len() < 16 {
        return Err(SealError::Format("ciphertext shorter than its authentication tag".into()));
    }
    Ok((nonce, ct))
}

// ---- one-shot conveniences (derive every time; the CLI's seal/unseal commands, tests) ----

/// Seal plaintext bytes under a passphrase with the default profile (fresh salt + nonce).
pub fn seal(plaintext: &[u8], passphrase: &str) -> Result<Sealed, SealError> {
    SealKey::new(passphrase, None, Kdf::default_profile())?.seal(plaintext)
}

/// Open a sealed envelope with a passphrase (derives the key for that envelope).
pub fn open(sealed: &Sealed, passphrase: &str) -> Result<Vec<u8>, SealError> {
    SealKey::for_envelope(sealed, passphrase, None)?.open(sealed)
}

/// Seal a JSON string into the envelope's own JSON text (pretty, for the file).
pub fn seal_to_json(plaintext: &str, passphrase: &str) -> Result<String, SealError> {
    let s = seal(plaintext.as_bytes(), passphrase)?;
    serde_json::to_string_pretty(&s).map_err(|e| SealError::Format(e.to_string()))
}

/// Read file content that may be sealed: plain content is returned as-is; an
/// envelope is opened with `passphrase()` (called only when needed).
pub fn open_maybe_sealed(
    content: &str,
    passphrase: impl FnOnce() -> Result<String, SealError>,
) -> Result<String, SealError> {
    open_maybe_sealed_keyed(content, |env| SealKey::for_envelope(env, &passphrase()?, None)).map(|(s, _)| s)
}

/// Like [`open_maybe_sealed`] but the caller supplies (and gets back) the derived
/// [`SealKey`], so it can be cached for the re-seals that follow.
pub fn open_maybe_sealed_keyed(
    content: &str,
    key_for: impl FnOnce(&Sealed) -> Result<SealKey, SealError>,
) -> Result<(String, Option<SealKey>), SealError> {
    if !is_sealed(content) {
        return Ok((content.to_string(), None));
    }
    let sealed = parse(content)?;
    let key = key_for(&sealed)?;
    let bytes = key.open(&sealed)?;
    let text = String::from_utf8(bytes).map_err(|e| SealError::Format(e.to_string()))?;
    Ok((text, Some(key)))
}

/// Resolve a passphrase for a given prefix (`HK_KEY` for the validator seed,
/// `HK_WALLET` for account/wallet/shield files): `<PREFIX>_PASSPHRASE`, then
/// `<PREFIX>_PASSPHRASE_FILE`, then the systemd credential `<credential>` under
/// `$CREDENTIALS_DIRECTORY`, then an interactive prompt if stdin is a terminal.
pub fn passphrase_from_env(prefix: &str, credential: &str, prompt: &str) -> Result<String, SealError> {
    if let Ok(p) = std::env::var(format!("{prefix}_PASSPHRASE")) {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    if let Ok(path) = std::env::var(format!("{prefix}_PASSPHRASE_FILE")) {
        if let Some(p) = first_line(&path) {
            return Ok(p);
        }
    }
    if let Ok(dir) = std::env::var("CREDENTIALS_DIRECTORY") {
        if let Some(p) = first_line(&format!("{dir}/{credential}")) {
            return Ok(p);
        }
    }
    if let Some(p) = prompt_tty(prompt) {
        return Ok(p);
    }
    Err(SealError::NoPassphrase(format!(
        "set {prefix}_PASSPHRASE, {prefix}_PASSPHRASE_FILE=<path>, or a systemd LoadCredential={credential}:<path> (no terminal to prompt on)"
    )))
}

fn first_line(path: &str) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    let line = s.lines().next()?.trim().to_string();
    (!line.is_empty()).then_some(line)
}

/// Prompt without echo when stdin is a terminal; `None` otherwise.
fn prompt_tty(prompt: &str) -> Option<String> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return None;
    }
    let p = rpassword::prompt_password(format!("{prompt}: ")).ok()?;
    (!p.is_empty()).then_some(p)
}

/// Prompt twice (new passphrase) on a terminal; `None` if not a terminal or mismatch.
/// Weak passphrases are refused here too (the same rule as the GUI).
pub fn prompt_new_passphrase(what: &str) -> Option<String> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return None;
    }
    eprintln!("(12+ characters, or a 4+-word passphrase — `hk-node passphrase-new` prints a strong one)");
    let a = rpassword::prompt_password(format!("new passphrase for {what}: ")).ok()?;
    if let Err(why) = check_strength(&a) {
        eprintln!("passphrase refused: {why} — nothing sealed");
        return None;
    }
    let b = rpassword::prompt_password("repeat: ").ok()?;
    if a != b {
        eprintln!("passphrases differ — nothing sealed");
        return None;
    }
    Some(a)
}

// ---- passphrase strength ----

const OBVIOUS: &[&str] = &[
    "password", "passphrase", "hashkinetics", "testnet", "validator", "letmein", "welcome", "qwerty",
    "iloveyou", "admin", "changeme", "secret", "default", "abc123", "trustno1", "monkey", "dragon",
];

/// The rule every sealing path applies: ≥ 12 characters, or ≥ 4 words of ≥ 3 letters;
/// not a keyboard walk, a repeat, a digit run, or a known-obvious word with decoration.
/// `HK_SEAL_ALLOW_WEAK=1` bypasses it (devnets, gates) — never set it on a real key.
pub fn check_strength(pass: &str) -> Result<(), String> {
    if std::env::var("HK_SEAL_ALLOW_WEAK").map(|v| v == "1").unwrap_or(false) {
        return Ok(());
    }
    let p = pass.trim();
    let chars: Vec<char> = p.chars().collect();
    let words: Vec<&str> = p.split_whitespace().filter(|w| w.chars().count() >= 3).collect();
    let is_phrase = words.len() >= 4;
    if chars.len() < 12 && !is_phrase {
        return Err(format!("{} characters — use 12 or more, or a passphrase of 4+ words", chars.len()));
    }
    let lower = p.to_lowercase();
    let stripped: String = lower.chars().filter(|c| c.is_alphabetic()).collect();
    if OBVIOUS.iter().any(|o| stripped == *o || (stripped.len() <= o.len() + 4 && stripped.starts_with(o))) {
        return Err("a common word with decoration — pick something an attacker's list does not contain".into());
    }
    if chars.iter().all(|c| c.is_ascii_digit()) {
        return Err("digits only".into());
    }
    let distinct = {
        let mut v = chars.clone();
        v.sort_unstable();
        v.dedup();
        v.len()
    };
    if distinct <= 3 {
        return Err("too few distinct characters".into());
    }
    let walks = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "abcdefghijklmnopqrstuvwxyz"];
    if walks.iter().any(|w| w.contains(&stripped) && stripped.len() >= 6) || walks.iter().any(|w| lower.replace(' ', "").starts_with(&w[..6.min(w.len())])) {
        return Err("a keyboard or alphabet walk".into());
    }
    if !is_phrase && p.len() >= 12 {
        // 12+ chars of one class only (all lower, all upper) needs more length.
        let classes = [chars.iter().any(|c| c.is_lowercase()), chars.iter().any(|c| c.is_uppercase()), chars.iter().any(|c| c.is_ascii_digit()), chars.iter().any(|c| !c.is_alphanumeric())];
        if classes.iter().filter(|b| **b).count() == 1 && chars.len() < 16 {
            return Err("one character class only — use 16+ characters, mix classes, or use a 4+-word passphrase".into());
        }
    }
    Ok(())
}

/// `n` random words from a 512-word list (9 bits each: 7 words = 63 bits), joined by
/// spaces — easy to say, easy to type, hard to guess. Indices come from the OS CSPRNG.
pub fn generate_passphrase(n: usize) -> String {
    let n = n.clamp(4, 12);
    let mut out = Vec::with_capacity(n);
    let mut buf = [0u8; 2];
    for _ in 0..n {
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let i = (u16::from_le_bytes(buf) as usize) % WORDS.len(); // 65536 % 512 == 0: unbiased
        out.push(WORDS[i]);
    }
    out.join(" ")
}

/// The generator's list: 512 short, distinct, ordinary words (9 bits per word).
pub const WORDS: [&str; 512] = [
    "acorn", "alpine", "anchor", "angle", "ankle", "anvil", "apricot", "apron",
    "arch", "arena", "ash", "aspen", "atlas", "attic", "axe", "badge",
    "badger", "bagel", "ballad", "balloon", "bamboo", "banana", "barley", "barn",
    "barrel", "basalt", "basket", "bat", "bay", "beach", "bean", "bear",
    "beaver", "bell", "belt", "bench", "berry", "birch", "biscuit", "bison",
    "blade", "blossom", "bluff", "boat", "bolt", "book", "boot", "bottle",
    "boulder", "box", "bramble", "brass", "breeze", "bridge", "brook", "broom",
    "brush", "bucket", "bud", "buffalo", "bugle", "bunny", "burrow", "butter",
    "cabbage", "cabin", "caboose", "cactus", "camel", "camera", "camp", "canal",
    "candy", "canoe", "canopy", "canvas", "cape", "caramel", "cargo", "carpet",
    "cashew", "castle", "cattle", "cave", "cellar", "chair", "chalk", "chapel",
    "cherry", "chess", "chimney", "citrus", "clam", "clay", "cliff", "clock",
    "cloud", "clover", "coal", "cobalt", "cobra", "cocoa", "coconut", "coffee",
    "coin", "comb", "comet", "condor", "cookie", "copper", "coral", "corn",
    "cottage", "cotton", "cougar", "cowboy", "coyote", "crab", "cradle", "crater",
    "cream", "creek", "crocus", "crow", "crown", "crystal", "cup", "curtain",
    "cushion", "cypress", "dahlia", "daisy", "dawn", "deer", "denim", "desert",
    "dew", "diamond", "dill", "diner", "dingo", "dock", "dolphin", "dome",
    "domino", "donkey", "dove", "dragon", "drift", "drizzle", "duck", "dune",
    "dusk", "earth", "echo", "eclipse", "eel", "elk", "elm", "ember",
    "emerald", "engine", "fable", "fairy", "falcon", "fence", "fennel", "fern",
    "ferret", "fiddle", "field", "fig", "finch", "firefly", "fjord", "flame",
    "flint", "flower", "flute", "foam", "fog", "fossil", "fox", "frog",
    "fudge", "gadget", "galaxy", "garden", "garnet", "gate", "gazelle", "gecko",
    "geyser", "ginger", "giraffe", "glacier", "globe", "glove", "goat", "goblet",
    "gorge", "gourd", "granite", "grape", "gravel", "griffin", "grotto", "grove",
    "guitar", "gull", "gypsum", "hamlet", "hammer", "hamster", "harbor", "harp",
    "harvest", "hatch", "hawk", "hazel", "helmet", "heron", "hickory", "hinge",
    "honey", "hood", "horse", "husk", "ice", "iceberg", "icicle", "iguana",
    "ink", "inlet", "iris", "island", "ivory", "ivy", "jacket", "jaguar",
    "jar", "jasmine", "jelly", "jewel", "jigsaw", "jockey", "jungle", "juniper",
    "kayak", "kelp", "kettle", "key", "kite", "kitten", "knot", "koala",
    "lace", "ladder", "lake", "lamp", "lantern", "lapel", "lark", "lasso",
    "latch", "lava", "leaf", "lemon", "lentil", "leopard", "lily", "lime",
    "linen", "lizard", "llama", "lobster", "locket", "log", "loom", "lotus",
    "lumber", "macaw", "magnet", "mallard", "mammoth", "mango", "mantis", "maple",
    "marble", "marsh", "mask", "mast", "meadow", "melon", "mermaid", "mesa",
    "meteor", "mink", "minnow", "mint", "mirror", "mitten", "mole", "monsoon",
    "moor", "moose", "mosaic", "moss", "mud", "muffin", "mug", "mule",
    "napkin", "narwhal", "nectar", "needle", "net", "newt", "nickel", "noodle",
    "nut", "nutmeg", "oak", "oar", "oatmeal", "ocean", "ocelot", "octopus",
    "onion", "opal", "orange", "orca", "orchard", "oregano", "osprey", "otter",
    "oven", "owl", "oxen", "paddle", "pagoda", "pail", "palm", "panda",
    "panther", "papaya", "paper", "parsley", "pasture", "peach", "peacock", "pearl",
    "pebble", "pecan", "pelican", "penguin", "peony", "pepper", "petal", "pickle",
    "pigeon", "pillow", "piper", "pixel", "planet", "plateau", "plum", "pocket",
    "pond", "pony", "porch", "possum", "prairie", "pretzel", "puffin", "pumpkin",
    "puzzle", "python", "quartz", "quilt", "quince", "quiver", "raccoon", "radar",
    "radish", "raft", "rainbow", "raven", "redwood", "reef", "rhubarb", "ribbon",
    "rice", "river", "robin", "rocket", "rooster", "rose", "rowboat", "ruby",
    "rye", "saffron", "sage", "sail", "salmon", "sandal", "sardine", "satin",
    "scallop", "scooter", "seal", "seaweed", "seed", "sesame", "shadow", "shark",
    "sheep", "ship", "shovel", "shrimp", "silk", "skunk", "sled", "sleigh",
    "sloth", "smoke", "snail", "snow", "sock", "sofa", "sorrel", "sparrow",
    "spinach", "sponge", "spoon", "spruce", "squid", "stable", "star", "steam",
    "stork", "storm", "straw", "stream", "summer", "sunset", "swallow", "swan",
    "syrup", "table", "tadpole", "talon", "tapir", "tavern", "tea", "teapot",
    "temple", "tent", "termite", "thread", "thunder", "thyme", "tiger", "toad",
    "toffee", "tomato", "torch", "tower", "trail", "train", "tree", "trout",
    "truffle", "trumpet", "tugboat", "tundra", "tunnel", "turkey", "turnip", "twig",
    "valley", "vanilla", "velvet", "vine", "violet", "volcano", "vulture", "waffle",
    "wagon", "wallaby", "walrus", "wasp", "water", "wave", "whale", "wheat",
    "wheel", "whisker", "wind", "window", "winter", "wolf", "wood", "wool",
    "wren", "yacht", "yam", "yarn", "yeast", "yogurt", "zinc", "zipper",
];

/// Redacted on purpose: the salt, the parameters and the key-file id — never the key.
impl std::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealKey")
            .field("salt", &self.salt_hex())
            .field("kdf", &self.kdf)
            .field("kf", &self.kf)
            .field("key", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests use the floor profile so the suite stays fast; the defaults are exercised by
    /// `kdf_default_profile_clamps_to_the_floor_and_the_ceiling` and
    /// `hr10_default_and_mobile_profiles_round_trip`.
    fn fast() -> Kdf {
        Kdf { m_kib: MIN_M_KIB, t: MIN_T, p: 1 }
    }

    #[test]
    fn seal_open_roundtrip_and_wrong_passphrase_fails() {
        let k = SealKey::new("correct horse battery staple", None, fast()).unwrap();
        let s = k.seal(b"{\"seed\":\"00\"}").unwrap();
        assert_eq!(s.hke, 1);
        assert_eq!(s.kf, None);
        assert_eq!(open(&s, "correct horse battery staple").unwrap(), b"{\"seed\":\"00\"}");
        assert!(matches!(open(&s, "wrong").unwrap_err(), SealError::Cipher));
        let mut t = s.clone();
        let mut ct = hex::decode(&t.ct).unwrap();
        ct[0] ^= 0x01;
        t.ct = hex::encode(ct);
        assert!(matches!(open(&t, "correct horse battery staple").unwrap_err(), SealError::Cipher), "tampering fails the tag");
        assert!(open(&s, "").is_err());
        // cached key: a re-seal keeps the salt, changes the nonce, opens with a fresh derivation
        let s2 = k.seal(b"{\"seed\":\"00\",\"next_nonce\":7}").unwrap();
        assert_eq!(s2.salt, s.salt);
        assert_ne!(s2.nonce, s.nonce);
        assert_eq!(open(&s2, "correct horse battery staple").unwrap(), b"{\"seed\":\"00\",\"next_nonce\":7}");
        assert!(k.fits(&s2));
    }

    #[test]
    fn keyfile_is_a_second_factor() {
        let kf = new_keyfile();
        let k = SealKey::new("correct horse battery staple", Some(&kf), fast()).unwrap();
        let s = k.seal(b"secret").unwrap();
        assert_eq!(s.kf.as_deref(), Some(keyfile_id(&kf).as_str()));
        // passphrase alone: refused before any KDF work, naming the key file
        assert!(matches!(open(&s, "correct horse battery staple").unwrap_err(), SealError::NoKeyfile(_)));
        // wrong key file: refused by fingerprint
        let other = new_keyfile();
        assert!(matches!(SealKey::for_envelope(&s, "correct horse battery staple", Some(&other)).unwrap_err(), SealError::NoKeyfile(_)));
        // right key file + right passphrase
        let k2 = SealKey::for_envelope(&s, "correct horse battery staple", Some(&kf)).unwrap();
        assert_eq!(k2.open(&s).unwrap(), b"secret");
        // right key file + wrong passphrase
        let k3 = SealKey::for_envelope(&s, "nope", Some(&kf)).unwrap();
        assert!(matches!(k3.open(&s).unwrap_err(), SealError::Cipher));
    }

    #[test]
    fn json_envelope_is_detected_and_opened() {
        let k = SealKey::new("correct horse battery staple", None, fast()).unwrap();
        let j = k.seal_to_json("{\"a\":1}").unwrap();
        assert!(is_sealed(&j));
        assert!(!j.contains("\"kf\""), "no key file → no kf field");
        assert!(!is_sealed("{\"seed\":\"aa\",\"id\":\"bb\",\"next_nonce\":0}"));
        assert_eq!(open_maybe_sealed(&j, || Ok("correct horse battery staple".into())).unwrap(), "{\"a\":1}");
        assert_eq!(open_maybe_sealed("{\"plain\":true}", || panic!("must not ask")).unwrap(), "{\"plain\":true}");
        assert!(open_maybe_sealed(&j, || Ok("nope".into())).is_err());
        let (text, key) = open_maybe_sealed_keyed(&j, |env| SealKey::for_envelope(env, "correct horse battery staple", None)).unwrap();
        assert_eq!(text, "{\"a\":1}");
        assert!(key.unwrap().fits(&parse(&j).unwrap()));
    }

    #[test]
    fn passphrase_sources_in_order() {
        std::env::set_var("HKT_PASSPHRASE", "");
        let f = std::env::temp_dir().join(format!("hk-pass-{}", std::process::id()));
        std::fs::write(&f, "from-file\nsecond line ignored\n").unwrap();
        std::env::set_var("HKT_PASSPHRASE_FILE", &f);
        assert_eq!(passphrase_from_env("HKT", "x", "p").unwrap(), "from-file");
        std::env::set_var("HKT_PASSPHRASE", "from-env");
        assert_eq!(passphrase_from_env("HKT", "x", "p").unwrap(), "from-env");
        std::fs::remove_file(&f).ok();
    }

    #[test]
    fn strength_rule_refuses_the_obvious_and_accepts_phrases() {
        std::env::remove_var("HK_SEAL_ALLOW_WEAK");
        for weak in ["hunter2", "password123", "Password2026!", "qwertyuiop12", "111111111111", "123456789012", "abcdefghijkl", "aaaaaaaaaaaa", "hashkinetics1"] {
            assert!(check_strength(weak).is_err(), "{weak} should be refused");
        }
        for ok in ["correct horse battery staple", "Tr0ub4dor&3-x9!", "purple-otter-lantern-42", "sixteenlowercase", &generate_passphrase(7)] {
            assert!(check_strength(ok).is_ok(), "{ok} should pass");
        }
    }

    #[test]
    fn generator_words_are_distinct_and_random() {
        let mut sorted = WORDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 512, "512 distinct words = 9 bits each");
        assert!(WORDS.iter().all(|w| w.chars().all(|c| c.is_ascii_lowercase()) && w.len() >= 3));
        let a = generate_passphrase(7);
        let b = generate_passphrase(7);
        assert_eq!(a.split(' ').count(), 7);
        assert_ne!(a, b);
        assert!(a.split(' ').all(|w| WORDS.contains(&w)));
    }

    /// HR-10 (v0.19.12): the knobs are clamped on BOTH sides — tested on the pure
    /// `Kdf::profile_from` that `default_profile` feeds, so no test sets the process-wide
    /// environment (a 4 GiB knob set there would turn every parallel test's `default_profile()`
    /// into a 2 GiB derivation, and a failed assert would leave it set). KILL: put `.max(MIN_*)`
    /// back in `profile_from` (no ceiling) and the 4 GiB / t 65 knobs come back unclamped — an
    /// envelope this module would then refuse to open.
    #[test]
    fn kdf_default_profile_clamps_to_the_floor_and_the_ceiling() {
        let k = Kdf::profile_from(Some("1024"), Some("1"));
        assert_eq!((k.m_kib, k.t, k.p), (MIN_M_KIB, MIN_T, DEFAULT_P));
        let k = Kdf::profile_from(Some("4194304"), Some("65")); // 4 GiB
        assert_eq!((k.m_kib, k.t, k.p), (MAX_M_KIB, MAX_T, DEFAULT_P));
        assert!(k.validate().is_ok(), "whatever the knobs say, the profile written is one the module opens");
        let d = Kdf::profile_from(None, None);
        assert_eq!((d.m_kib, d.t, d.p), (DEFAULT_M_KIB, DEFAULT_T, DEFAULT_P));
        assert!(d.validate().is_ok());
        // an unparsable knob means the default; surrounding whitespace is trimmed
        let u = Kdf::profile_from(Some("lots"), Some(" 5 "));
        assert_eq!((u.m_kib, u.t, u.p), (DEFAULT_M_KIB, 5, DEFAULT_P));
    }

    /// An envelope whose body is a fresh seal under `k`, re-labelled with `kdf` — what an
    /// attacker who can place bytes at a secret path presents.
    fn relabelled(k: &SealKey, kdf: Kdf) -> Sealed {
        let mut s = k.seal(b"{\"seed\":\"00\"}").unwrap();
        s.m_kib = kdf.m_kib;
        s.t = kdf.t;
        s.p = kdf.p;
        s
    }

    /// HR-10 (v0.19.12): parameters below the floor or above the ceiling are refused on the
    /// READ side as well as the write side, before any derivation. KILL: drop the floor half
    /// of `Kdf::validate` (the pre-v0.19.12 read path) and the 8 / 1 / 1 and 65,535 / 2 / 4
    /// envelopes derive a key — the owner's passphrase under an attacker's cheap profile.
    #[test]
    fn hr10_kdf_bounds_refuse_sub_floor_and_over_ceiling_parameters() {
        let k = SealKey::new("correct horse battery staple", None, fast()).unwrap();
        let refused = |kdf: Kdf| {
            // the profile itself …
            let e = kdf.validate().unwrap_err().to_string();
            assert!(e.contains("kdf parameters out of range"), "{kdf:?}: {e}");
            // … a NEW key under it …
            assert!(matches!(SealKey::new("correct horse battery staple", None, kdf), Err(SealError::Format(_))), "{kdf:?}");
            // … and an envelope presenting it: refused as malformed, never as a wrong
            // passphrase (which is what a derivation that ran would say)
            let s = relabelled(&k, kdf);
            match open(&s, "correct horse battery staple") {
                Err(SealError::Format(why)) => assert!(why.contains("kdf parameters out of range"), "{kdf:?}: {why}"),
                other => panic!("{kdf:?} must be refused before the KDF, got {other:?}"),
            }
        };
        // below the floor: the reporter's 8 KiB / t1 / p1, one step under each floor, t = 2
        refused(Kdf { m_kib: 8, t: 1, p: 1 });
        refused(Kdf { m_kib: 65_535, t: 2, p: 4 });
        refused(Kdf { m_kib: MIN_M_KIB, t: 2, p: 1 });
        refused(Kdf { m_kib: MIN_M_KIB - 1, t: MIN_T, p: 1 });
        // above the ceiling: memory one KiB over is out of range as a profile and for a new
        // key, and an envelope presenting it gets its own refusal, still before the KDF
        // (`hr10_over_ceiling_memory_is_refused_by_name_with_the_way_back`)
        let over = Kdf { m_kib: MAX_M_KIB + 1, t: MIN_T, p: 1 };
        assert!(over.validate().unwrap_err().to_string().contains("kdf parameters out of range"));
        assert!(matches!(SealKey::new("correct horse battery staple", None, over), Err(SealError::Format(_))));
        match open(&relabelled(&k, over), "correct horse battery staple") {
            Err(SealError::OverCeiling(m)) => assert_eq!(m, MAX_M_KIB + 1),
            other => panic!("{over:?} must be refused by name before the KDF, got {other:?}"),
        }
        refused(Kdf { m_kib: MIN_M_KIB, t: MAX_T + 1, p: 1 });
        refused(Kdf { m_kib: MIN_M_KIB, t: MIN_T, p: MAX_P + 1 });
        refused(Kdf { m_kib: MIN_M_KIB, t: MIN_T, p: 0 });
        // the floor itself and the ceiling itself are inside the bounds
        assert!(Kdf { m_kib: MIN_M_KIB, t: MIN_T, p: 1 }.validate().is_ok());
        assert!(Kdf { m_kib: MAX_M_KIB, t: MAX_T, p: MAX_P }.validate().is_ok());
    }

    /// HR-10 (v0.19.12): the floor-exact profile opens, and the cheap shape checks run before
    /// the KDF — an envelope at the CEILING with a bad nonce is refused in microseconds (a
    /// 2 GiB / t 3 derivation would take seconds and 2 GiB). KILL: move `decode_body` back
    /// behind `derive_key` in `for_envelope` and the timing assertion fails (and the process
    /// allocates 2 GiB to find out).
    #[test]
    fn hr10_floor_exact_opens_and_shape_checks_come_before_the_kdf() {
        let floor = Kdf { m_kib: 65_536, t: 3, p: 1 };
        let k = SealKey::new("correct horse battery staple", None, floor).unwrap();
        let s = k.seal(b"{\"seed\":\"00\"}").unwrap();
        assert_eq!((s.m_kib, s.t, s.p), (65_536, 3, 1));
        assert_eq!(open(&s, "correct horse battery staple").unwrap(), b"{\"seed\":\"00\"}");
        // shape before work: a ceiling-priced envelope with a 23-byte nonce, a non-hex
        // ciphertext, a ciphertext shorter than its tag, a short salt
        let at_ceiling = relabelled(&k, Kdf { m_kib: MAX_M_KIB, t: MIN_T, p: 1 });
        let cases: Vec<(&str, Sealed)> = vec![
            ("nonce must be 24 bytes", { let mut e = at_ceiling.clone(); e.nonce = "00".repeat(23); e }),
            ("Invalid character", { let mut e = at_ceiling.clone(); e.ct = "zz".into(); e }),
            ("shorter than its authentication tag", { let mut e = at_ceiling.clone(); e.ct = "00".repeat(15); e }),
            ("salt too short", { let mut e = at_ceiling.clone(); e.salt = "0011".into(); e }),
        ];
        for (expect, env) in cases {
            let t = std::time::Instant::now();
            match SealKey::for_envelope(&env, "correct horse battery staple", None) {
                Err(SealError::Format(why)) => assert!(why.contains(expect), "expected {expect:?}, got {why:?}"),
                other => panic!("expected a shape refusal ({expect}), got {other:?}"),
            }
            assert!(t.elapsed() < std::time::Duration::from_secs(2), "{expect}: the refusal must come before the KDF");
        }
    }

    /// HR-10 (v0.19.12): the two profiles the project writes — the desktop default (512 MiB /
    /// t 4 / p 4) and the phone's (256 MiB / t 3 / p 4) — pass the bounds and round-trip through
    /// a real derivation. KILL: lower `MAX_M_KIB` below 524,288 (or raise `MIN_T` above 3) and
    /// one of the two is refused.
    #[test]
    fn hr10_default_and_mobile_profiles_round_trip() {
        for kdf in [Kdf { m_kib: DEFAULT_M_KIB, t: DEFAULT_T, p: DEFAULT_P }, Kdf { m_kib: 262_144, t: 3, p: 4 }] {
            assert!(kdf.validate().is_ok(), "{kdf:?}");
            let k = SealKey::new("correct horse battery staple", None, kdf).unwrap();
            let s = k.seal(b"{\"seed\":\"00\"}").unwrap();
            assert_eq!((s.m_kib, s.t, s.p), (kdf.m_kib, kdf.t, kdf.p));
            assert_eq!(open(&s, "correct horse battery staple").unwrap(), b"{\"seed\":\"00\"}", "{kdf:?}");
        }
    }

    /// HR-10 (v0.19.12): an envelope labelled 3 GiB — what v0.16.0–v0.19.11 wrote when
    /// `HK_SEAL_M_KIB` asked for it — is refused by name from the header alone (no key
    /// derivation runs: a 3 GiB / t 3 one would take seconds and 3 GiB), and the message
    /// carries the value, the ceiling and the way back: unseal with the older binary
    /// (`key-unseal` / `account-unseal`), re-seal with this one. KILL: drop the `OverCeiling`
    /// check in `for_envelope` and the envelope comes back as `Format` ("sealed file is
    /// malformed: kdf parameters out of range …"), which names no way back.
    #[test]
    fn hr10_over_ceiling_memory_is_refused_by_name_with_the_way_back() {
        let k = SealKey::new("correct horse battery staple", None, fast()).unwrap();
        let three_gib = Kdf { m_kib: 3 * 1_048_576, t: MIN_T, p: 1 };
        let s = relabelled(&k, three_gib);
        match SealKey::for_envelope(&s, "correct horse battery staple", None) {
            Err(SealError::OverCeiling(m)) => assert_eq!(m, 3_145_728),
            other => panic!("a 3 GiB envelope must be refused by name before the KDF, got {other:?}"),
        }
        let msg = match open(&s, "correct horse battery staple") {
            Err(e @ SealError::OverCeiling(_)) => e.to_string(),
            other => panic!("a 3 GiB envelope must be refused by name before the KDF, got {other:?}"),
        };
        for want in ["3145728 KiB", "2097152 KiB", "older binary", "hk-node key-unseal", "hk-node account-unseal", "re-seal"] {
            assert!(msg.contains(want), "{want:?} missing from: {msg}");
        }
        assert!(!msg.contains("malformed"), "{msg}");
        // the wallet core maps unlock errors by these words; this refusal must pass through as is
        for word in ["key file", "wrong", "aead", "decrypt"] {
            assert!(!msg.contains(word), "{word:?} in: {msg}");
        }
    }
}
