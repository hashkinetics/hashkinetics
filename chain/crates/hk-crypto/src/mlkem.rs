//! mlkem — ML-KEM-768 stealth-address adapter (P2.1/WS4; vendored rustcrypto-kems).
//!
//! Role in the design: CONFIDENTIALITY ONLY. The recipient's stealth address contains an
//! ML-KEM encapsulation key; the sender encapsulates → shared secret → SHAKE-AEAD key
//! (`noteenc`) for the note ciphertext (value ‖ rho ‖ rcm ‖ memo) that rides next to the
//! commitment. The recipient's wallet TRIAL-DECAPSULATES every new ciphertext; the AEAD
//! tag says "mine / not mine". Threat model (plan §3.4): a future lattice break leaks old
//! METADATA — it can never forge a signature or steal a coin (spend authority stays pure
//! hash: the spend-tree in the circuit).
//!
//! Determinism: keygen from the wallet master seed (restores from backup); encapsulation
//! takes caller-supplied 32-byte randomness (FIPS 203 deterministic encaps) — no RNG
//! plumbing inside the crypto layer.

use ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{Decapsulate, Key, KeyExport, Seed, B32};

use crate::hash::{shake256_32, shake256_n, DOM_MLKEM_SEED, DOM_NOTE_KEY};

/// ML-KEM-768 encapsulation-key (public) encoding length.
pub const EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext encoding length.
pub const CT_LEN: usize = 1088;

/// A wallet's note-receiving keypair. The 64-byte FIPS 203 seed IS the private key,
/// derived deterministically from the wallet master seed.
pub struct NoteKem {
    dk: DecapsulationKey,
}

impl NoteKem {
    /// Deterministic keygen: seed = SHAKE-256₆₄(DOM_MLKEM_SEED ‖ master ‖ tag).
    pub fn from_master(master: &[u8], tag: &[u8]) -> Self {
        let bytes = shake256_n(DOM_MLKEM_SEED, &[master, tag], 64);
        Self::from_seed_bytes(&bytes).expect("64-byte seed")
    }

    /// Rebuild from an exported 64-byte seed — the INCOMING VIEWING KEY path (P2.2):
    /// holding one epoch's seed grants discovery+decryption for that epoch's notes and
    /// nothing else (no spend authority, no nullifier key, no other epochs).
    pub fn from_seed_bytes(bytes: &[u8]) -> Option<Self> {
        let seed = Seed::try_from(bytes).ok()?;
        Some(Self { dk: DecapsulationKey::from_seed(seed) })
    }

    /// The public component of the stealth address (1184 bytes) — publish freely.
    pub fn public(&self) -> Vec<u8> {
        self.dk.encapsulation_key().to_bytes().to_vec()
    }

    /// Trial-decapsulation. FIPS 203 implicit rejection means this ALWAYS yields a
    /// 32-byte secret — for a ciphertext not addressed to us it's garbage, and the
    /// note-AEAD tag check (`noteenc::open` → None) delivers the "not mine" verdict.
    /// `None` here only for malformed lengths.
    pub fn decapsulate(&self, ct_bytes: &[u8]) -> Option<[u8; 32]> {
        let ct = Ciphertext::try_from(ct_bytes).ok()?;
        let ss = self.dk.decapsulate(&ct);
        let mut out = [0u8; 32];
        out.copy_from_slice(ss.as_slice());
        Some(out)
    }
}

/// Sender side: encapsulate to a recipient's public component. `coin` = fresh 32-byte
/// randomness from the wallet (unique per note). Returns (kem ciphertext, shared secret).
pub fn encapsulate(recipient_ek: &[u8], coin: &[u8; 32]) -> Option<(Vec<u8>, [u8; 32])> {
    let key = Key::<EncapsulationKey>::try_from(recipient_ek).ok()?;
    let ek = EncapsulationKey::new(&key).ok()?;
    let m = B32::from(*coin);
    let (ct, ss) = ek.encapsulate_deterministic(&m);
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.as_slice());
    Some((ct.to_vec(), out))
}

/// AEAD key for a note ciphertext: KDF(shared secret ‖ context). Context = the note
/// commitment — binds the ciphertext to exactly one tree position.
pub fn note_key(shared: &[u8; 32], context: &[u8; 32]) -> [u8; 32] {
    shake256_32(DOM_NOTE_KEY, &[shared, context])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noteenc;

    #[test]
    fn encaps_decaps_roundtrip() {
        let bob = NoteKem::from_master(b"bob-master-seed", b"note/0");
        let ek = bob.public();
        assert_eq!(ek.len(), EK_LEN);

        let (ct, ss_sender) = encapsulate(&ek, &[0x42; 32]).expect("encaps");
        assert_eq!(ct.len(), CT_LEN);
        let ss_bob = bob.decapsulate(&ct).expect("decaps");
        assert_eq!(ss_sender, ss_bob, "sender and recipient agree on the secret");

        // Determinism: same master ⇒ same keypair (wallet restore).
        let bob2 = NoteKem::from_master(b"bob-master-seed", b"note/0");
        assert_eq!(bob2.decapsulate(&ct).unwrap(), ss_bob);
    }

    #[test]
    fn wrong_recipient_gets_garbage_not_the_secret() {
        let bob = NoteKem::from_master(b"bob", b"n");
        let eve = NoteKem::from_master(b"eve", b"n");
        let (ct, ss) = encapsulate(&bob.public(), &[7; 32]).unwrap();
        // Implicit rejection: eve still gets 32 bytes — but never bob's secret.
        let ss_eve = eve.decapsulate(&ct).unwrap();
        assert_ne!(ss, ss_eve);
    }

    #[test]
    fn full_note_ciphertext_flow_scanner_verdicts() {
        // Sender → Bob: encapsulate, derive AEAD key, seal the note plaintext.
        let bob = NoteKem::from_master(b"bob", b"n");
        let eve = NoteKem::from_master(b"eve", b"n");
        let commitment = [0xCC; 32]; // AEAD nonce/context = the note commitment
        let (kem_ct, ss) = encapsulate(&bob.public(), &[9; 32]).unwrap();
        let sealed = noteenc::seal(&note_key(&ss, &commitment), &commitment, b"value|rho|rcm");

        // Bob's scanner: decap + open → MINE.
        let k_bob = note_key(&bob.decapsulate(&kem_ct).unwrap(), &commitment);
        assert_eq!(noteenc::open(&k_bob, &commitment, &sealed).as_deref(), Some(b"value|rho|rcm".as_slice()));

        // Eve's scanner: decap gives garbage → AEAD says NOT MINE.
        let k_eve = note_key(&eve.decapsulate(&kem_ct).unwrap(), &commitment);
        assert!(noteenc::open(&k_eve, &commitment, &sealed).is_none());
    }
}
