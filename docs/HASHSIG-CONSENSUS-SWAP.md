# Making consensus votes hash-based (0.9 design)

Goal: retire the last honesty caveat — "devnet votes are stock Ed25519" — by signing
consensus votes/proposals with the hash-based primitive in `hk-crypto::hashsig`
(LMS/HSS over SHAKE-256, RFC 8554), the SCMS operational-signing scheme.

## What's DONE (0.9, this session)
`hk-crypto::hashsig` (feature `lms`) — real stateful LMS/HSS signing over SHAKE-256,
KAT-tested: sign/verify roundtrip, state advances per signature (leaf = one-time),
tampered/wrong-message/wrong-key rejection, deterministic seed-based keygen. Run:
`cargo test -p hk-crypto --features lms`.

## Why the live swap is a separate, careful step
Malachite abstracts signing via `Context::SigningScheme` + `SigningProvider<Ctx>`.
The trait bounds are the friction:

```
SigningScheme::Signature : Clone + Debug + Eq + Ord + Send + Sync
SigningScheme::PublicKey  : Clone + Debug + Eq + Send + Sync
SigningScheme::PrivateKey : Clone + Send + Sync
SigningProvider::sign_vote(&self, ...)   // &self, async, called concurrently
```

Two things must be handled:
1. **`hbs_lms::Signature` isn't `Clone/Eq/Ord`** (only `Debug`). → wrap sig/pubkey
   bytes in newtypes we control (below).
2. **Stateful key + `&self` signing.** LMS advances state on every sign; the provider
   signs under `&self` concurrently. → interior mutability + durable persistence, and
   crucially a **non-cloning signer handle** so `PrivateKey: Clone` never forks state.

## The swap, concretely

### 1. Newtypes (in `hk-consensus`)
```rust
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HkSig(pub Vec<u8>);          // LMS signature bytes
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HkPub(pub Vec<u8>);          // LMS public key bytes
#[derive(Clone)] pub struct HkPriv(Arc<Mutex<HashSigner>>);  // Clone shares, never forks state

pub struct HkHashScheme;
impl SigningScheme for HkHashScheme {
    type DecodingError = std::io::Error;
    type Signature = HkSig;
    type PublicKey  = HkPub;
    type PrivateKey = HkPriv;
    fn decode_signature(b:&[u8]) -> Result<HkSig,_> { Ok(HkSig(b.to_vec())) }
    fn encode_signature(s:&HkSig) -> Vec<u8> { s.0.clone() }
}
```
`HkPriv` is `Arc<Mutex<HashSigner>>`: `Clone` duplicates the *handle*, not the key
state — so the trait's `Clone` bound is satisfied without ever forking leaves.

### 2. Provider
`HkHashProvider` impls `SigningProvider<HkContext>`: `sign_vote` locks the signer,
persists the advanced state to disk **inside** `HashSigner::sign`'s callback (wire the
callback to a file/HSM, fsync, THEN release the signature), and returns `HkSig`.
`verify_*` calls `hashsig::verify`.

### 3. Context + codec
- `HkContext::SigningScheme = HkHashScheme` (replaces `Ed25519`).
- `HkVote/HkProposal` sign-bytes are unchanged (already SHAKE-256, `hk/v1/...`).
- `codec.rs`: `RawSig` becomes `Vec<u8>` (was `ed25519_consensus::Signature`);
  CommitCertificate/vote/proposal DTOs carry `Vec<u8>` sigs. Straightforward.

### 4. Keys & the network/consensus split (important)
- **Network identity stays Ed25519.** `Node::get_keypair` feeds libp2p peer identity —
  transport auth, NOT ledger security. Leave it Ed25519 (hash-based libp2p identity is
  out of scope and unnecessary).
- **Consensus vote signing becomes LMS.** The validator key file grows to
  `{ ed25519_network_key, hashsig_seed, hashsig_state_path }`. The LMS private state is
  loaded from `hashsig_state_path` (persisted, advancing), seeded deterministically from
  `hashsig_seed` on first run.
- **Capacity:** H5 (32 sigs) is a KAT toy. Validators sign ~2–3 messages/block, so use
  an **HSS multi-tree** (e.g. two H10 layers = 2^20 ≈ 1M sigs, ~300k blocks) or rotate
  keys per epoch via a fresh tree certified by the SLH-DSA root (this is literally the
  SCMS attenuating-cert design — plan §3.2/§3.3). Pick parameters with the size/lifetime
  table in research 03 before mainnet.

### 5. Honesty guard until then
Devnet keeps stock Ed25519 votes and is **never** called quantum-secure. Once this swap
lands and a devnet runs green on LMS votes, the caveat is retired in README/CHANGELOG/
version.md/CLAUDE.md in the same commit.

## Risks / open
- Signature size: LMS H10/W2 ≈ 1.5–2.5 KB/sig → commit certs at 100 validators ≈
  150–250 KB/block. Fine for devnet; measure vs the 3.5 MB block budget (M4 in the
  Quaxion spike plan applies).
- Concurrency: `sign_vote` is async; a single `Mutex<HashSigner>` serializes a
  validator's own signing (correct — a validator must not sign two things at one leaf).
- State-loss = liveness fault (can't sign) not a safety fault; on restart, reload the
  persisted state and continue. Never restore an OLDER state (that reuses leaves) — the
  persisted file is the single source of truth; back it up, never roll it back.
