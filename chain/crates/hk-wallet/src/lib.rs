//! hk-wallet — client-side shielded-note logic (P2.1/WS4: stealth addresses + scanning).
//!
//! What a shielded wallet does that the chain never sees: derive its ADDRESS (spend-tree
//! root + nullifier key → owner tag; ML-KEM key → confidentiality), mint notes, build
//! SEALED OUTPUTS for other people's addresses (note + KEM ciphertext + SHAKE-AEAD note
//! ciphertext), SCAN the chain's ciphertexts by trial-decapsulation to discover notes
//! addressed to it, rebuild auth paths, and assemble witnesses for `hk-prove`.
//!
//! Every hash byte comes from `hk-spend-circuit`; KEM/AEAD from `hk-crypto` — one
//! implementation each, shared with the chain and the guests. `build_spend` re-runs the
//! statement natively before any GPU time is spent.
//!
//! v1 scope notes (devnet-grade, hardened later):
//! - randomness (`coin`, `entropy`) is CALLER-supplied; the demo derives it
//!   deterministically, real wallets use a CSPRNG. Reuse ⇒ repeated rho ⇒ linkable.
//! - spend-tree capacity is 2^h per address (wallet-chosen, ≤ 2^SPEND_TREE_DEPTH); the
//!   wallet must NEVER reuse an `ots_index` (persist it reserve-then-sign — leaf reuse
//!   hands the leaf key to anyone who sees both signatures, incl. a delegated prover).

use hk_crypto::hash::shake256_32;
use hk_crypto::mlkem::{self, NoteKem};
use hk_crypto::noteenc;
use hk_spend_circuit::{
    self as circuit, address_tag, commit_note, derive_nk, spend_auth, spend_root,
    tx_binding_for, Hash, MerklePath, MintPublic, MintWitness, Note, SpendPublic, SpendWitness,
};
use hk_state::pool::full_tree_path;

const DOM_WALLET_RHO: &str = "hk/wallet/rho/v2";
const DOM_WALLET_RCM: &str = "hk/wallet/rcm/v2";

// ---------------------------------------------------------------------------
// Keys + addresses
// ---------------------------------------------------------------------------

/// A wallet's key material, all derived from one master seed (restores from backup).
/// `h` = address capacity: 2^h one-time spends (h ≤ SPEND_TREE_DEPTH). Bigger h = a
/// longer-lived address at a one-time keygen cost; addresses are cheap to rotate.
pub struct WalletKeys {
    master: Vec<u8>,
    h: u32,
}

impl WalletKeys {
    /// Default capacity 2^6 = 64 spends (devnet-snappy). Use `with_capacity` for more.
    pub fn new(master: &[u8]) -> Self {
        Self::with_capacity(master, 6)
    }

    pub fn with_capacity(master: &[u8], h: u32) -> Self {
        Self { master: master.to_vec(), h }
    }

    /// Secret nullifier key.
    pub fn nk(&self) -> Hash {
        derive_nk(&self.master)
    }

    /// Spend-tree root (derives the 2^h one-time WOTS keys — the address-creation cost).
    pub fn spend_root(&self) -> Hash {
        spend_root(&self.master, self.h)
    }

    /// The 32-byte owner tag senders put in notes addressed to us.
    pub fn owner_tag(&self) -> Hash {
        address_tag(&self.spend_root(), &self.nk())
    }

    /// ML-KEM receiving keypair for `epoch` (P2.2: keys are per-epoch — handing out one
    /// epoch's seed grants visibility into THAT epoch only, never a forever-key).
    pub fn kem_at(&self, epoch: u64) -> NoteKem {
        NoteKem::from_master(&self.master, &epoch_kem_tag(epoch))
    }

    /// Epoch-0 keypair (back-compat convenience).
    pub fn kem(&self) -> NoteKem {
        self.kem_at(0)
    }

    /// The public stealth address for `epoch`: the owner tag is epoch-STABLE (spend
    /// authority is not epoch-scoped); the KEM component rotates per epoch.
    pub fn address_at(&self, epoch: u64) -> Address {
        Address { tag: self.owner_tag(), kem_pk: self.kem_at(epoch).public() }
    }

    /// Epoch-0 address (back-compat convenience).
    pub fn address(&self) -> Address {
        self.address_at(0)
    }

    /// INCOMING VIEWING KEY for one epoch: grants discovery + decryption of notes paid
    /// to this address IN THAT EPOCH — no spend authority, no nullifier key, no other
    /// epochs. This is the "bounded-time visibility, never forever-keys" primitive.
    pub fn ivk(&self, epoch: u64) -> Ivk {
        let seed = hk_crypto::hash::shake256_n(
            hk_crypto::hash::DOM_MLKEM_SEED,
            &[&self.master, &epoch_kem_tag(epoch)],
            64,
        );
        Ivk { epoch, tag: self.owner_tag(), kem_seed: seed }
    }

    /// A note we mint to OURSELVES (rho/rcm derived from the master + a fresh tag).
    pub fn self_note(&self, value: u64, tag: u64) -> Note {
        Note {
            value,
            owner: self.owner_tag(),
            rho: shake256_32(DOM_WALLET_RHO, &[&self.master, &tag.to_le_bytes()]),
            rcm: shake256_32(DOM_WALLET_RCM, &[&self.master, &tag.to_le_bytes()]),
        }
    }

    /// Authorize a message with spend-tree leaf `ots_index` (ONE-TIME per index — the
    /// wallet must persist its next index reserve-then-sign; in-memory here, v1).
    pub fn authorize(&self, ots_index: u32, msg: &Hash) -> (circuit::WotsSig, MerklePath) {
        spend_auth(&self.master, self.h, ots_index, msg)
    }
}

/// A public stealth address: spend authority (pure hash) + confidentiality (ML-KEM).
#[derive(Clone, Debug)]
pub struct Address {
    pub tag: Hash,
    pub kem_pk: Vec<u8>,
}

/// Epoch length in blocks (devnet-scale; a chain parameter later). Senders should use
/// the recipient's CURRENT epoch address; epochs bound viewing-key scope, not spending.
pub const EPOCH_BLOCKS: u64 = 1_000;

pub fn epoch_of(height: u64) -> u64 {
    height / EPOCH_BLOCKS
}

fn epoch_kem_tag(epoch: u64) -> Vec<u8> {
    format!("note-kem/{epoch}").into_bytes()
}

/// An INCOMING VIEWING KEY: one epoch's KEM seed + the (public) owner tag. Grants
/// discovery + decryption for that epoch's incoming notes and nothing else — no spend
/// authority, no nullifier key, no other epochs. Hand to an auditor; it expires with
/// the epoch's relevance.
#[derive(Clone)]
pub struct Ivk {
    pub epoch: u64,
    pub tag: Hash,
    /// 64-byte FIPS 203 seed for this epoch's decapsulation key.
    pub kem_seed: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Note plaintext codec (what rides inside the AEAD): value ‖ rho ‖ rcm ‖ memo
// ---------------------------------------------------------------------------

pub fn encode_note_pt(value: u64, rho: &Hash, rcm: &Hash, memo: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(72 + memo.len());
    out.extend_from_slice(&value.to_le_bytes());
    out.extend_from_slice(rho);
    out.extend_from_slice(rcm);
    out.extend_from_slice(memo);
    out
}

pub fn decode_note_pt(pt: &[u8]) -> Option<(u64, Hash, Hash, Vec<u8>)> {
    if pt.len() < 72 {
        return None;
    }
    let value = u64::from_le_bytes(pt[0..8].try_into().ok()?);
    let rho: Hash = pt[8..40].try_into().ok()?;
    let rcm: Hash = pt[40..72].try_into().ok()?;
    Some((value, rho, rcm, pt[72..].to_vec()))
}

// ---------------------------------------------------------------------------
// Sender side: sealed outputs
// ---------------------------------------------------------------------------

/// A fully-built output for someone's address: the note (goes into the witness), its
/// commitment (public), the stealth payload for their scanner, and the note key — the
/// SENDER-side disclosure capability for this one payment (keep it if you may ever need
/// to prove the payment; it opens exactly this ciphertext and nothing else).
#[derive(Clone, Debug)]
pub struct SealedOutput {
    pub note: Note,
    pub commitment: Hash,
    /// kem_ct (1088 B) ‖ AEAD(value ‖ rho ‖ rcm ‖ memo) — the on-chain advisory blob.
    pub stealth_ct: Vec<u8>,
    /// AEAD key for this output's ciphertext (one-time disclosure material, P2.2).
    pub note_key: [u8; 32],
}

/// Seal an EXISTING note for `to`'s scanner: KEM ct ‖ AEAD(value ‖ rho ‖ rcm ‖ memo).
/// Returns (stealth_ct, note_key) — the key is the sender's one-time disclosure
/// capability for this payment. (Also used to seal change notes back to ourselves.)
pub fn seal_note(
    note: &Note,
    to: &Address,
    coin: &[u8; 32],
    memo: &[u8],
) -> Option<(Vec<u8>, [u8; 32])> {
    let commitment = commit_note(note);
    let (kem_ct, ss) = mlkem::encapsulate(&to.kem_pk, coin)?;
    let key = mlkem::note_key(&ss, &commitment);
    let sealed =
        noteenc::seal(&key, &commitment, &encode_note_pt(note.value, &note.rho, &note.rcm, memo));
    let mut stealth_ct = kem_ct;
    stealth_ct.extend_from_slice(&sealed);
    Some((stealth_ct, key))
}

/// Build an output addressed to `to`. `coin` = KEM encapsulation randomness,
/// `entropy` = note randomness (rho/rcm) — both fresh per output.
pub fn build_output(
    to: &Address,
    value: u64,
    coin: &[u8; 32],
    entropy: &[u8; 32],
    memo: &[u8],
) -> Option<SealedOutput> {
    let rho = shake256_32(DOM_WALLET_RHO, &[entropy, b"out"]);
    let rcm = shake256_32(DOM_WALLET_RCM, &[entropy, b"out"]);
    let note = Note { value, owner: to.tag, rho, rcm };
    let commitment = commit_note(&note);
    let (stealth_ct, note_key) = seal_note(&note, to, coin, memo)?;
    Some(SealedOutput { note, commitment, stealth_ct, note_key })
}

// ---------------------------------------------------------------------------
// One-time disclosure packages (P2.2/WS5) — the CVA primitive
// ---------------------------------------------------------------------------

/// A self-contained, OFFLINE-verifiable proof of one payment's contents and its
/// inclusion in the pool. Contains the one-time AEAD key for exactly ONE ciphertext —
/// it grants nothing else: no other notes, no future visibility, no spend authority,
/// no nullifier tracking. Built by the payment's sender (from `SealedOutput.note_key`)
/// or its recipient (via decapsulation).
///
/// The verifier trusts `anchor` out-of-band (a block explorer / signed chain receipt);
/// everything else verifies from the package alone.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DisclosurePackage {
    pub version: u8,
    pub chain_id: String,
    pub commitment: Hash,
    pub owner_tag: Hash,
    pub leaf_index: u64,
    /// The pool root this package's path folds to (cross-check on-chain).
    pub anchor: Hash,
    pub siblings: Vec<Hash>,
    #[serde(with = "hex_vec")]
    pub stealth_ct: Vec<u8>,
    pub note_key: [u8; 32],
}

/// What a verified package discloses — and NOTHING more.
#[derive(Clone, Debug)]
pub struct DisclosedPayment {
    pub value: u64,
    pub owner_tag: Hash,
    pub rho: Hash,
    pub rcm: Hash,
    pub memo: Vec<u8>,
    pub commitment: Hash,
    pub leaf_index: u64,
    pub anchor: Hash,
}

/// Recipient-side key recovery for a package (sender-side: keep `SealedOutput.note_key`).
pub fn note_key_as_recipient(
    keys: &WalletKeys,
    epoch: u64,
    commitment: &Hash,
    stealth_ct: &[u8],
) -> Option<[u8; 32]> {
    if stealth_ct.len() < mlkem::CT_LEN {
        return None;
    }
    let ss = keys.kem_at(epoch).decapsulate(&stealth_ct[..mlkem::CT_LEN])?;
    Some(mlkem::note_key(&ss, commitment))
}

/// Assemble a package from the pool's leaf list + the target entry + the note key.
pub fn build_disclosure(
    chain_id: &str,
    leaves: &[Hash],
    leaf_index: u64,
    owner_tag: Hash,
    stealth_ct: Vec<u8>,
    note_key: [u8; 32],
) -> Option<DisclosurePackage> {
    let commitment = *leaves.get(leaf_index as usize)?;
    let (siblings, anchor) = full_tree_path(leaves, leaf_index);
    Some(DisclosurePackage {
        version: 1,
        chain_id: chain_id.to_string(),
        commitment,
        owner_tag,
        leaf_index,
        anchor,
        siblings,
        stealth_ct,
        note_key,
    })
}

/// OFFLINE verification — no chain access, no network, no secrets beyond the package:
/// (1) the AEAD opens under the one-time key (nonce = commitment);
/// (2) the decoded note RE-COMMITS to the stated commitment (SHA-256 binding — value,
///     owner, rho, rcm can't be altered without breaking this);
/// (3) the commitment's path folds to the stated anchor at the stated index.
pub fn verify_disclosure(p: &DisclosurePackage) -> Result<DisclosedPayment, String> {
    if p.version != 1 {
        return Err(format!("unsupported package version {}", p.version));
    }
    if p.stealth_ct.len() < mlkem::CT_LEN + noteenc::TAG_LEN {
        return Err("stealth_ct too short".into());
    }
    let sealed = &p.stealth_ct[mlkem::CT_LEN..];
    let pt = noteenc::open(&p.note_key, &p.commitment, sealed)
        .ok_or("AEAD rejects: wrong key or tampered ciphertext")?;
    let (value, rho, rcm, memo) = decode_note_pt(&pt).ok_or("note plaintext malformed")?;
    let note = Note { value, owner: p.owner_tag, rho, rcm };
    if commit_note(&note) != p.commitment {
        return Err("decoded note does not re-commit to the stated commitment".into());
    }
    if p.siblings.len() != hk_spend_circuit::TREE_DEPTH {
        return Err("bad path length".into());
    }
    let mut cur = p.commitment;
    for (l, sib) in p.siblings.iter().enumerate() {
        let go_right = (p.leaf_index >> l) & 1 == 1;
        cur = if go_right {
            hk_spend_circuit::merkle_node(sib, &cur)
        } else {
            hk_spend_circuit::merkle_node(&cur, sib)
        };
    }
    if cur != p.anchor {
        return Err("inclusion path does not fold to the stated anchor".into());
    }
    Ok(DisclosedPayment {
        value,
        owner_tag: p.owner_tag,
        rho,
        rcm,
        memo,
        commitment: p.commitment,
        leaf_index: p.leaf_index,
        anchor: p.anchor,
    })
}

/// Hex serde for the ciphertext blob (packages are JSON files handed to auditors).
mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Recipient side: the scanner (trial-decapsulation)
// ---------------------------------------------------------------------------

/// A note the scanner discovered for this wallet.
#[derive(Clone, Debug)]
pub struct Discovered {
    pub note: Note,
    pub commitment: Hash,
    /// Position in the pool's commitment tree (needed for the spend witness).
    pub leaf_index: u64,
    pub memo: Vec<u8>,
}

/// Scan with the wallet's epoch-0 keys (back-compat).
pub fn scan(keys: &WalletKeys, entries: &[(u64, Hash, Vec<u8>)]) -> Vec<Discovered> {
    scan_core(&keys.kem(), keys.owner_tag(), entries)
}

/// Scan a specific epoch with full wallet keys.
pub fn scan_at(keys: &WalletKeys, epoch: u64, entries: &[(u64, Hash, Vec<u8>)]) -> Vec<Discovered> {
    scan_core(&keys.kem_at(epoch), keys.owner_tag(), entries)
}

/// Scan with ONLY an incoming viewing key — what an auditor/view-service runs. Sees
/// exactly the notes paid to `ivk.tag` under `ivk.epoch`'s KEM key; cannot spend, cannot
/// compute nullifiers, cannot see other epochs.
pub fn scan_with_ivk(ivk: &Ivk, entries: &[(u64, Hash, Vec<u8>)]) -> Vec<Discovered> {
    match NoteKem::from_seed_bytes(&ivk.kem_seed) {
        Some(kem) => scan_core(&kem, ivk.tag, entries),
        None => Vec::new(),
    }
}

/// Core scanner: `(leaf_index, commitment, stealth_ct)` entries. For each:
/// trial-decapsulate, open the AEAD ("mine / not mine"), decode, and REQUIRE the decoded
/// note to re-commit to the on-chain commitment (a lying ciphertext is discarded).
fn scan_core(kem: &NoteKem, my_tag: Hash, entries: &[(u64, Hash, Vec<u8>)]) -> Vec<Discovered> {
    let mut found = Vec::new();
    for (leaf_index, commitment, stealth_ct) in entries {
        if stealth_ct.len() < mlkem::CT_LEN + noteenc::TAG_LEN {
            continue;
        }
        let (kem_ct, sealed) = stealth_ct.split_at(mlkem::CT_LEN);
        let Some(ss) = kem.decapsulate(kem_ct) else { continue };
        let key = mlkem::note_key(&ss, commitment);
        let Some(pt) = noteenc::open(&key, commitment, sealed) else { continue };
        let Some((value, rho, rcm, memo)) = decode_note_pt(&pt) else { continue };
        let note = Note { value, owner: my_tag, rho, rcm };
        if commit_note(&note) != *commitment {
            continue; // ciphertext lies about the note — not spendable, drop it
        }
        found.push(Discovered { note, commitment: *commitment, leaf_index: *leaf_index, memo });
    }
    found
}

// ---------------------------------------------------------------------------
// Spending
// ---------------------------------------------------------------------------

/// Everything a MintToPool transaction needs.
pub fn build_mint(note: &Note) -> (MintWitness, MintPublic) {
    let w = MintWitness { note: note.clone() };
    let p = circuit::run_mint(&w);
    (w, p)
}

/// A fully-checked spend, ready to prove.
#[derive(Clone, Debug)]
pub struct SpendPlan {
    pub witness: SpendWitness,
    pub public: SpendPublic,
}

/// Assemble and PRE-CHECK a v3 shielded spend (two outputs: pay + change).
/// `leaves` = every pool commitment in insertion order; `leaf_index` = the input note's
/// position; `ots_index` = a NEVER-REUSED spend-tree leaf; `credit` = transparent account
/// the public `fee` pays out to ([0;32] when fee = 0 — fully shielded).
#[allow(clippy::too_many_arguments)]
pub fn build_spend(
    leaves: &[Hash],
    leaf_index: u64,
    in_note: Note,
    keys: &WalletKeys,
    ots_index: u32,
    out_note: Note,
    out2_note: Note,
    fee: u64,
    credit: [u8; 32],
) -> Result<SpendPlan, String> {
    let cm = commit_note(&in_note);
    if leaves.get(leaf_index as usize) != Some(&cm) {
        return Err(format!("leaf {leaf_index} is not this note's commitment"));
    }
    let (siblings, _root) = full_tree_path(leaves, leaf_index);
    let tx_binding = tx_binding_for(&credit, fee);
    let (sig, ots_path) = keys.authorize(ots_index, &tx_binding);
    let witness = SpendWitness {
        in_note,
        path: MerklePath { siblings, index: leaf_index },
        sig,
        ots_path,
        nk: keys.nk(),
        out_note,
        out2_note,
        fee,
        tx_binding,
    };
    let public = circuit::run(&witness).map_err(|e| format!("witness fails the statement: {e:?}"))?;
    Ok(SpendPlan { witness, public })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hk_state::pool::IncrementalTree;

    #[test]
    fn stealth_payment_end_to_end() {
        // Alice mints to herself, pays Bob; BOB'S SCANNER discovers the note and Bob can
        // spend it — the whole P2.1 property in one test.
        let alice = WalletKeys::new(b"alice-master");
        let bob = WalletKeys::new(b"bob-master");
        let eve = WalletKeys::new(b"eve-master");

        // Alice's input note (as if previously minted).
        let a_note = alice.self_note(1_000, 1);
        let a_cm = commit_note(&a_note);
        let mut tree = IncrementalTree::new();
        tree.append(a_cm).unwrap();
        let mut leaves = vec![a_cm];

        // Alice builds a payment: 600 to Bob (sealed), 400 change to herself.
        let to_bob = build_output(&bob.address(), 600, &[1; 32], &[2; 32], b"hi bob").unwrap();
        let change = alice.self_note(400, 2);
        let plan = build_spend(
            &leaves, 0, a_note, &alice, 0, to_bob.note.clone(), change, 0, [0; 32],
        )
        .expect("plan");
        assert_eq!(plan.public.merkle_root, tree.root());
        assert_eq!(plan.public.out_commitment, to_bob.commitment);

        // Chain appends both outputs.
        tree.append(plan.public.out_commitment).unwrap();
        tree.append(plan.public.out2_commitment).unwrap();
        leaves.push(plan.public.out_commitment);
        leaves.push(plan.public.out2_commitment);

        // Bob scans: entry (index 1, bob's commitment, stealth blob).
        let entries = vec![(1u64, to_bob.commitment, to_bob.stealth_ct.clone())];
        let found = scan(&bob, &entries);
        assert_eq!(found.len(), 1, "bob discovers his note");
        assert_eq!(found[0].note.value, 600);
        assert_eq!(found[0].memo, b"hi bob");

        // Eve scans the same entries: nothing.
        assert!(scan(&eve, &entries).is_empty(), "nobody else can see it");

        // Bob SPENDS the discovered note (change 0 dummy) — ownership is real.
        let bob_out = bob.self_note(600, 9);
        let dummy = Note { value: 0, owner: [0; 32], rho: [1; 32], rcm: [2; 32] };
        let bplan = build_spend(
            &leaves, found[0].leaf_index, found[0].note.clone(), &bob, 0, bob_out, dummy, 0, [0; 32],
        )
        .expect("bob's spend proves");
        assert_eq!(bplan.public.merkle_root, tree.root());

        // Alice CANNOT spend Bob's note: her keys fail the owner binding.
        let stolen = build_spend(
            &leaves,
            found[0].leaf_index,
            found[0].note.clone(),
            &alice,
            1,
            alice.self_note(600, 3),
            Note { value: 0, owner: [0; 32], rho: [3; 32], rcm: [4; 32] },
            0,
            [0; 32],
        );
        assert!(stolen.is_err(), "sender/anyone-else cannot spend the received note");
    }

    #[test]
    fn wrong_index_is_refused_before_proving() {
        let w = WalletKeys::new(b"w");
        let n = w.self_note(100, 1);
        let (_, p) = build_mint(&n);
        let leaves = [p.commitment];
        let other = WalletKeys::new(b"other").self_note(100, 1);
        let dummy = Note { value: 0, owner: [0; 32], rho: [0; 32], rcm: [0; 32] };
        assert!(build_spend(&leaves, 0, other, &WalletKeys::new(b"other"), 0,
            w.self_note(100, 2), dummy, 0, [0; 32]).is_err());
    }

    #[test]
    fn scanner_rejects_a_lying_ciphertext() {
        // Ciphertext decrypts fine but claims a different note than the commitment.
        let bob = WalletKeys::new(b"bob");
        let out = build_output(&bob.address(), 500, &[7; 32], &[8; 32], b"").unwrap();
        // Attach bob's valid blob to a DIFFERENT commitment.
        let entries = vec![(0u64, [0xEE; 32], out.stealth_ct)];
        assert!(scan(&bob, &entries).is_empty());
    }

    #[test]
    fn ivk_is_scoped_to_its_epoch() {
        // Bob receives in epoch 0 and epoch 1. An auditor holding IVK(0) sees ONLY the
        // epoch-0 note — no spending, no other epochs. This is bounded-time visibility.
        let bob = WalletKeys::new(b"bob-epochs");
        let e0 = build_output(&bob.address_at(0), 100, &[1; 32], &[2; 32], b"e0").unwrap();
        let e1 = build_output(&bob.address_at(1), 200, &[3; 32], &[4; 32], b"e1").unwrap();
        let entries = vec![
            (0u64, e0.commitment, e0.stealth_ct.clone()),
            (1u64, e1.commitment, e1.stealth_ct.clone()),
        ];
        let auditor_view = scan_with_ivk(&bob.ivk(0), &entries);
        assert_eq!(auditor_view.len(), 1);
        assert_eq!(auditor_view[0].note.value, 100);
        // The wallet itself sees each epoch with the matching key.
        assert_eq!(scan_at(&bob, 1, &entries).len(), 1);
        assert_eq!(scan_at(&bob, 1, &entries)[0].note.value, 200);
        // IVK(1) sees only epoch 1.
        let v1 = scan_with_ivk(&bob.ivk(1), &entries);
        assert_eq!(v1.len(), 1);
        assert_eq!(v1[0].note.value, 200);
    }

    #[test]
    fn disclosure_roundtrip_offline_and_tamper_paths() {
        // A payment to Bob; the SENDER discloses it with the retained note key.
        let bob = WalletKeys::new(b"bob-disclose");
        let out = build_output(&bob.address(), 777, &[5; 32], &[6; 32], b"invoice #42").unwrap();
        let mut tree = IncrementalTree::new();
        let filler = commit_note(&bob.self_note(1, 0));
        tree.append(filler).unwrap();
        tree.append(out.commitment).unwrap();
        let leaves = [filler, out.commitment];

        let pkg = build_disclosure(
            "hk-devnet-test", &leaves, 1, bob.owner_tag(), out.stealth_ct.clone(), out.note_key,
        )
        .unwrap();
        assert_eq!(pkg.anchor, tree.root(), "package anchor == chain root");

        // OFFLINE verification (pure function — no chain, no secrets beyond the package).
        let d = verify_disclosure(&pkg).expect("valid package verifies");
        assert_eq!(d.value, 777);
        assert_eq!(d.memo, b"invoice #42");
        assert_eq!(d.leaf_index, 1);

        // Recipient-side key recovery yields the SAME capability.
        let k = note_key_as_recipient(&bob, 0, &out.commitment, &out.stealth_ct).unwrap();
        assert_eq!(k, out.note_key);

        // Tamper paths all fail:
        let mut bad = pkg.clone();
        bad.note_key[0] ^= 1; // wrong key
        assert!(verify_disclosure(&bad).is_err());
        let mut bad = pkg.clone();
        bad.commitment[0] ^= 1; // claims a different commitment
        assert!(verify_disclosure(&bad).is_err());
        let mut bad = pkg.clone();
        bad.siblings[0][0] ^= 1; // broken inclusion path
        assert!(verify_disclosure(&bad).is_err());
        let mut bad = pkg.clone();
        bad.anchor[0] ^= 1; // lies about the anchor
        assert!(verify_disclosure(&bad).is_err());

        // JSON roundtrip (this is the file handed to an auditor).
        let json = serde_json::to_string(&pkg).unwrap();
        let back: DisclosurePackage = serde_json::from_str(&json).unwrap();
        assert!(verify_disclosure(&back).is_ok());

        // And the capability is ONE-TIME in scope: it opens nothing else.
        let other = build_output(&bob.address(), 999, &[7; 32], &[8; 32], b"other").unwrap();
        assert!(
            hk_crypto::noteenc::open(
                &pkg.note_key,
                &other.commitment,
                &other.stealth_ct[hk_crypto::mlkem::CT_LEN..]
            )
            .is_none(),
            "the disclosed key cannot open any other ciphertext"
        );
    }
}
