//! Minimal JSON-RPC-ish HTTP server (0.7) — zero extra deps, tokio only.
//!
//! POST any path with body `{"method":"...","params":{...}}` → `{"result":...}`
//! or `{"error":"..."}`. Agent-first surface; nothing EVM-shaped.
//!
//! Methods:
//!   hk_chainInfo                              -> {chain_id, height, app_hash,
//!                                                 signer: {epoch, remaining, capacity},  (R4)
//!                                                 process: {rss_bytes, uptime_secs,
//!                                                           verifier_init_ms,   (R11, v0.17.0)
//!                                                           disk_free_bytes},   (v0.19.4: free
//!                                                 bytes on the block log's filesystem; null off-Unix)
//!                                                 activations: {mandate_asset_from,   (R17, v0.19.6:
//!                                                               rotation_v2_from,     the heights THIS
//!                                                               payword_cap_from}}    node will switch rules at — null = never; the roll
//!                                                 call reads them off every seat before a height is named;
//!                                                 payword_cap_from = R18, 2026-10-08: the PayWord caps)
//!   hk_submitRotation {cert}                   -> {accepted, epoch, queued}  (R2: peer-carried
//!                                                 revival — cert from `hk-node issue-rotation`;
//!                                                 L-2: judged by the rule at tip + 1 — domain +
//!                                                 valid_from_height window — exactly as commit will)
//!   hk_getAccount   {id}                      -> {found, nonce, auth_commit, balances[]}
//!                                                 (HR-9, v0.19.12: `balances[]` is answered for an
//!                                                 id with NO account too — found false, nonce and
//!                                                 auth_commit null — so a credit to a never-created
//!                                                 id is visible instead of hidden)
//!   hk_getAsset     {asset | issuer+symbol}   -> {found, asset: {symbol, issuer, policy,
//!                                                 supply, burned, circulating, held, conserved,
//!                                                 paused, frozen_count}}            (X1)
//!   hk_getAssets    {from?, limit?<=1000}     -> {count, total, from, limit, next, fee_asset,
//!                                                 assets[]}   (X1; HR-4, v0.19.12: PAGED —
//!                                                 `count` = `total` = the whole registry, `assets[]`
//!                                                 the page, `next` the following page's `from` or
//!                                                 null; the conservation receipts of a page come
//!                                                 from ONE pass over balances and channels, and one
//!                                                 call runs at a time per node — "busy — retry")
//!   hk_balance      {id, asset}               -> {amount}            (u128 as string)
//!   hk_mandateAvailable {leaf, at?}           -> {available}         (string | null)
//!   hk_getMandate   {id}                      -> {found, id, parent, root, holder, funder, asset,
//!                                                 rate_per_sec, buffer_max, per_tx_max, buffer,
//!                                                 last_accrual, expiry, tier, revoked}
//!                                                 (HR-5, v0.19.12: `holder` spends and delegates;
//!                                                 `funder` = the root's funding account, which
//!                                                 pays — the two can differ)
//!   hk_submitTx     {tx}                       -> {accepted, txid}
//!   hk_getReceipt   {txid}                     -> {found, detail}
//!   hk_getPoolInfo  {asset?}                   -> {legacy, version, asset?, root, latest_anchor,
//!                                                  next_index, nullifiers, total_shielded}
//!                                                 (P6: `asset` = that asset's pool; absent = legacy)
//!   hk_getPools                                -> {count, multi_pool_from, pools: [hk_getPoolInfo…]}  (P6)
//!   hk_getPoolLeaves {asset?, from?, limit?<=10000} -> {asset, leaves: [hex; ...], from, count, total, next}  (H3: paged)
//!   hk_getPoolNotes  {asset?, from?, limit?<=10000} -> {asset, notes: [{index, commitment, stealth_ct}], from,
//!                                                 count, total, next}   (H3, v0.16.1: paged — `next`
//!                                                 is the wallet's scan cursor; null = end)
//!   hk_getPoolPath   {asset?, index}           -> {asset, index, commitment, siblings[TREE_DEPTH], root, total}
//!                                                 (H3: one authentication path; spenders no longer
//!                                                 download every commitment)
//!
//! P3.0b explorer surface (store-backed — reads the durable block log, no app locks):
//!   hk_getBlock     {height}                   -> full block: txs (public summaries) +
//!                                                 per-tx receipts + aggregate verdict + cert
//!   hk_getBlocks    {before?, limit?<=50}      -> newest-first block list (v0.19.12: plus
//!                                                 truncated + next_before when the call's byte
//!                                                 budget ended the page)
//!   hk_getValidators                           -> the live validator set + power (+ queued set changes)
//!   hk_getPeers                                -> this node's live p2p peer table (N1, v0.15.2):
//!                                                 {self, count, inbound, outbound, public_addr,
//!                                                  identified, islands_refused, untagged_refused,
//!                                                  broadcast_refused (v0.19.10), peers[{peer_id,
//!                                                  direction, addr (masked /24 · /48), private_addr,
//!                                                  version, genesis, connected_secs, last_connection_secs, reconnects}]}
//!   hk_submitSetChange {cert}                  -> {accepted, queued}  (V1: a seat admitted/removed
//!                                                 by a supermajority of the current seats' roots;
//!                                                 rides this node's next proposal)
//!   hk_getMempool                              -> {count, txids[<=100]}
//!
//! PRIVACY NOTE: these endpoints expose only what consensus already made public —
//! the transparent skeleton. Shielded txs show commitments/nullifiers/fee, NEVER
//! amounts or parties. The explorer built on this is itself a privacy demo.
//!
//! All 32-byte ids are lowercase hex (64 chars).
//!
//! R17 (reported 2026-10-06; L-5 + L-6 — client-side only, no consensus impact, no gate):
//!   * L-5: the pool feed is paged UNDER its lock and only the page leaves the lock
//!     (`with_pool_feed`). v0.16.1 (H3) paged this way; the P6 refactor (v0.19.0) cloned
//!     the ENTIRE feed — stealth ciphertexts included — per call, and the commit path takes
//!     the same lock while holding the chain lock, so one scanner on a big pool stalled
//!     commit on every node it polled. `hk_getPoolPath` now copies the 32-byte leaves only,
//!     and (R17 review, 2026-10-06) at most `POOL_PATH_SLOTS` of those full-leaf copies +
//!     O(n) tree builds run at once — past that, "busy — retry", the feed lock untouched.
//!     Response shapes are unchanged byte for byte.
//!   * L-6: `hk_submitRotation` / `hk_submitSetChange` are unauthenticated (Origin check
//!     only) with no per-IP limit, and ran the ≈1.7 ms SLH-DSA-192s verify (a 16,224-byte
//!     signature) FIRST, under the validator-set mutex, for any blob a stranger posted.
//!     Now every free refusal — shape, membership, epoch / window, queue dedup — comes
//!     first (`rotation_preflight`, `set_change_preflight`), the verify runs on a snapshot
//!     with no lock held, the free checks are re-run under the lock before anything is
//!     queued, and at most `CERT_VERIFY_SLOTS` verifies run at once across both methods:
//!     callers past that get a "busy — retry" error instead of pinning every worker thread.
//!   * L-2 (consensus, gated — `genesis::rotation_v2_from_for`): a rotation certificate is
//!     judged here by `hk_consensus::rotation::RotationRules` at `tip + 1` (the earliest
//!     height it can commit at): before the chain's v2 height the v1 rule, byte for byte;
//!     from it only the chain-bound v2 domain, with `valid_from_height` enforced as a
//!     freshness window (not from the future, not more than `ROTATION_FRESHNESS_HORIZON`
//!     blocks old). The window is a free check and runs in the preflight; the domain is the
//!     signature itself. `hk_chainInfo.activations` publishes the heights.
//!
//! R18 (reported 2026-10-04, confirmed 2026-10-08; client-side here, no gate): `hk_submitTx`
//! and `hk_gossipTxs` refuse, through the mempool door (`Mempool::envelope_verdict` /
//! `try_admit_verified`), a `ChannelOpen` past `hk_state::MAX_CHANNEL_STEPS` and a
//! `ChannelSettle` more than `hk_state::MAX_SETTLE_DELTA` links past its channel's settled
//! step — the settle whose apply was ≈ 4.29e9 SHAKE-256 links under the chain mutex, free to
//! the sender and replayable every block. Reasons: `channel too long (N steps, max M)` /
//! `settle delta too large (D links past the highest settled step, max M per settlement)` —
//! hk-state's receipt wording, byte for byte (mempool.rs `AdmitError::as_str`; docs/RPC.md)
//! — and, since the same-day review, `settle too costly to propose (L links from the tip,
//! max B per block …)` for a settle no block this node builds could carry (mempool.rs).
//! The consensus rule behind them is height-gated (`hk_state::State::payword_cap_from`), and
//! `hk_chainInfo.activations.payword_cap_from` publishes that height exactly as the two R17
//! ones. R18 review (2026-10-08): `hk_submitBundle` was a sibling path into the SAME hash
//! loop that bypassed both mirrors and the proposer's budget — `build_batch` places the
//! bundle's txs ahead of the pool without costing them, and an invalid aggregate only logs
//! (the block still applies, so its `ChannelSettle`s were hashed by every validator) — so
//! an unauthenticated caller could put up to `MAX_TXS_PER_BLOCK` over-cap settles into an
//! UPGRADED proposer's next block, before or after the height. A bundle is now refused
//! unless every tx is a proof-less `MintToPool` / `ShieldedSpend` — what P2.3 defines a
//! bundle as, and exactly what `demo_agg` builds (`bundle_shape_verdict`). Nothing else on
//! this surface changes.
//!
//! HR-1 (mr-hrydarie, reported 2026-11-04, confirmed 2026-11-08; v0.19.11, client-side, no gate,
//! no activation height): `hk_submitBundle` queued a bundle for the proposer after the shape
//! check alone — no envelope or signature, no sender, nonce, anchor or nullifier check, no
//! bound on the aggregate bytes but the 8 MiB body cap — behind nothing but the browser-Origin
//! check, and `build_batch` rides the head bundle whole: a 1,024-tx garbage bundle pre-empted
//! this node's whole block, committed as all-Err receipts, and wrote its aggregate into every
//! node's block log; and because the commit prune pushed EVERY block tx's (sender, nonce) into
//! the mempool's `remove_included`, a refused bundle tx naming a victim's pending slot evicted
//! the victim's honest tx fleet-wide. The one legitimate caller in the tree is the devnet's
//! `demo-agg`; there is no aggregator role. v0.19.11:
//!   * THE SWITCH — the door is closed unless the operator opens it: `hk_rpc.accept_bundles`
//!     (config.rs; false by default, false on every seat `config-gen` writes, true only in the
//!     devnet generator) or HK_RPC_ACCEPT_BUNDLES=1 (`bundles_open`, the mirror of
//!     `browser_ops_allowed`). A closed door answers before reading `params`.
//!   * THE HONEST DOOR — when open, a bundle queues only if every tx in it would apply
//!     (`submit_bundle`): the free refusals first — `bundle_shape_verdict` now also demands
//!     right-length envelopes (`PK_LEN` / `SIG_LEN`) and bounded stealth ciphertexts
//!     (`mempool::MAX_STEALTH_CT_BYTES`), the aggregate is capped at `MAX_BUNDLE_AGG_BYTES`,
//!     and under the queue lock the H4 cap and dedup plus E1 (no (sender, nonce) slot or
//!     nullifier that a queued bundle already carries) — then ONE admission slot per node
//!     (`BUNDLE_ADMIT`, F1), the envelope hashes with no lock held, and under the chain lock a
//!     dry run of every tx through `Mempool::try_admit_verified` on a SCRATCH pool (the live
//!     mempool is never touched: nothing from a bundle is WAL'd, gossiped or indexed), so a
//!     legitimate bundle's sequential nonces pass and a refused tx is named with hk_submitTx's
//!     own reason.
//!   * E3 — `hk_submitTx` / `hk_gossipTxs` refuse a proof-less pool tx at the door
//!     (`refuse_proof_less_pool_tx`): uncovered, it could only ride a block and die at apply.
//!   * E4 — the commit prune is receipt-aware (state.rs `commit_prune_sets` in
//!     `apply_batch_to_chain`, `Mempool::remove_refused`): an applied tx prunes its slot, a
//!     refused tx prunes only its identical pending copy.
//! Not in this release: verifying the aggregate at submit, a per-block byte budget in
//! `build_batch`, any change to the state machine, the batch encoding, consensus or the store.
//!
//! v0.19.12 (HR-4, HR-5, HR-9; client-side, no gate, no consensus change): `hk_getAssets` is
//! paged and computes a page's conservation receipts in ONE pass over balances and channels
//! under the chain lock, one call in flight per node (`get_assets`, `ASSET_SCAN`);
//! `hk_getMandate` is new (a node's holder AND funder — the two can differ for a root);
//! `hk_getAccount` answers `balances[]` for an id with no account (a credit to a never-created
//! id is visible); `hk_getAccountTxs` also lists a `MandateCreate` under the holder it names
//! (HR-5: the node-local index records the holder as a counterparty — blocks indexed by this
//! version). Nothing else on this surface changes for these three; the other changes follow.
//!
//! v0.19.12 (client-side, no gate, no consensus change):
//!   * `hk_submitTx` / `hk_gossipTxs` refuse, by the tx's own bytes and before any hash
//!     (mempool.rs `Mempool::field_bounds`), an `AssetRegister` whose symbol
//!     fails hk-state's symbol rule — `bad asset symbol (N B; 1-16 of [A-Za-z0-9._-], letter
//!     first)` — an `AssetBurn` whose destination is longer than 64 bytes — `burn destination too
//!     long (N B, max 64)` — and a tx larger than `mempool::MAX_TX_BYTES` in the block encoding —
//!     `transaction too large (N B encoded, max 4194304)`; `hk_submitBundle` also refuses a
//!     bundle whose txs exceed one block's transaction budget (`batch::MAX_BATCH_TX_BYTES`).
//!   * The pool holds a byte cap beside its count cap: `hk_submitTx` / `hk_gossipTxs` answer
//!     `mempool full (P B pending + N B, max M B) — retry later` past the pool's bytes
//!     (`mempool::MAX_POOL_BYTES`, `HK_MEMPOOL_BYTES`) and `too many bytes pending for this
//!     sender (P B pending + N B, max M B) — retry later, once some are included` past one
//!     sender's (`mempool::MAX_SENDER_PENDING_BYTES`).
//!   * `hk_getBlock`, `hk_getTx` and `hk_getBlocks` share `BLOCK_READ_SLOTS` permits, taken
//!     before any block is loaded; past them a call answers `busy: 2 block reads already in
//!     flight — retry in a moment`.
//!   * A tx summary (`hk_getBlock` `txs[]`, `hk_getTx` `summary`) shows at most
//!     `SUMMARY_SYMBOL_SHOWN` (64) bytes of an asset symbol and `SUMMARY_DESTINATION_SHOWN`
//!     (128) bytes of a burn destination (hex); when it cuts one it adds `symbol_len` /
//!     `destination_len` (the real length) and `truncated: true` in `fields`. A value inside
//!     the bounds — every value the chain accepts — is shown exactly as before, with no new key.
//!   * `hk_getBlock` reuses each tx's txid for its summary and its receipt; the answer is
//!     otherwise unchanged.
//!   * `hk_getBlocks` stops once a call has loaded `BLOCKS_READ_BUDGET` (64 MiB) of stored
//!     blocks and then adds `truncated: true` and `next_before` (the `before` of the call that
//!     continues); a page inside the budget has the earlier shape.
//!   * `hk_submitTx` / `hk_gossipTxs` answer a refusal decided by the tx's own bytes first
//!     (`admit_one`); for a tx those checks pass, the other refusals keep their wording and
//!     their order, with the two byte caps above and HR-2's duplicate-output refusal added.
//!   * `hk_getAsset` holds the `ASSET_SCAN` slot `hk_getAssets` holds (its conservation scan
//!     runs under the chain lock): past it, `busy: an asset registry scan is already in flight
//!     — retry in a moment`.
//!   * `hk_getAccountTxs` selects its page in one pass over the account's rows
//!     (`get_account_txs`); the answer is unchanged, row for row.
//!   * `hk_getMempool` answers from the txids the pool stored when each tx entered it
//!     (`get_mempool`); the response is unchanged.
//!
//! v0.19.13 (client-side, no gate; the rules are the pool's, mempool.rs):
//!   * `hk_submitTx` / `hk_gossipTxs` do not take back, for 16 blocks, a transaction that a
//!     block refused after the envelope checks: `this transaction was refused in a block — the
//!     same signed bytes are admitted again once the chain is at height H`. Nothing follows for
//!     its sender, whoever sends the bytes: its other transactions are admitted as usual.
//!   * They refuse a transfer or a shield of amount zero by the tx's own bytes (`zero amount`),
//!     and — for the sender's next transaction only, the one at the account's current nonce —
//!     a transaction whose sender cannot pay the envelope fee charged at the next height and a
//!     transfer or a shield whose amount the balance does not cover, in hk-state's receipt
//!     wording.
//!   * A pool tx's proof is verified before the tx enters the pool when the node has a verifier
//!     (`door_proof_check`): after the checks above, against the tx's own public values, with
//!     no lock held, `POOL_PROOF_VERIFY_SLOTS` verification at a time (`busy: … retry later`
//!     beyond, nothing queued). A proof that does not verify is refused (`pool proof rejected
//!     (it does not verify)`); the same bytes sent again get that answer at once, with no
//!     verification and no further effect; and the sender's transactions that carry a pool
//!     proof — only those — wait (`a pool transaction of this sender was refused — … height H`),
//!     longer with each further transaction of that sender whose proof fails. A verification
//!     that gives no answer refuses the tx and counts the wait, and the txid is not remembered.
//!     Without a verifier the pool holds one such tx per sender and 8 MiB of them in all, and
//!     the door answers `… retry later` beyond that.

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

use hk_consensus::rotation::RotationRules;
use hk_consensus::{HkAddress, HkValidatorSet, RotationCert, SetChange, SetChangeCert};
use hk_crypto::lamport::{PK_LEN, SIG_LEN};
use hk_crypto::slhdsa_adapter::{ROOT_PK_LEN, ROOT_SIG_LEN};
use hk_primitives::{AccountId, Amount, AssetId, H256};
use hk_state::tx::{SignedTx, Tx};
use hk_state::PoolKey;

use crate::batch::{txid, Batch, MAX_BATCH_TX_BYTES, MAX_TXS_PER_BLOCK};
use crate::mempool::{stealth_ct_over_cap, tx_encoded_len, Mempool, MAX_STEALTH_CT_BYTES};
use crate::state::SharedHandles;

/// H1 (v0.13.2): a request must arrive within this window, headers and body — a
/// half-open connection used to pin a task and up to 1 MiB of buffer forever.
const RPC_CONN_TIMEOUT: Duration = Duration::from_secs(10);
/// H1: at most this many connections are served concurrently; the rest get a fast
/// 503 instead of queueing behind a slowloris.
const RPC_MAX_CONNS: usize = 256;

/// L-6 (R17, reported 2026-10-06): at most this many SLH-DSA-192s root-signature verifies
/// (≈1.7 ms of CPU each; one per approval for a set change) run at once across
/// `hk_submitRotation` + `hk_submitSetChange`. Both are unauthenticated with no per-IP
/// limit, so without a bound a flood of well-shaped garbage certs could occupy all
/// RPC_MAX_CONNS worker slots in verifies. Legitimate traffic is a handful of certs per
/// epoch — two slots are plenty; the rest answer "busy — retry" (`busy_error`).
const CERT_VERIFY_SLOTS: usize = 2;
static CERT_VERIFY: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(CERT_VERIFY_SLOTS);

/// HR-1 (mr-hrydarie, reported 2026-11-04; v0.19.11), F1: at most ONE bundle admission — the
/// per-tx envelope hashes plus the scratch-pool dry run of `submit_bundle`, up to 1,024 txs —
/// runs at once per node, `try_acquire` like `CERT_VERIFY`; the rest answer "busy — retry".
/// Every free refusal (closed door, parse, shape, lengths, byte caps, queue cap / dedup /
/// overlap) comes BEFORE the slot, so a flood of garbage never touches it. A bundle is a few
/// txs every few blocks on the one devnet that opens the door; one slot is plenty.
static BUNDLE_ADMIT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

/// L-5 residual (R17 review, 2026-10-06): `hk_getPoolPath` still copies 32 B × every leaf
/// of a pool UNDER the feed lock (32 MB at a million notes) and then hashes the whole tree
/// (`full_tree_path`, O(n) SHAKEs) per call — the page-sized copy of L-5 bounds the two
/// scanner methods, not this one, and the commit path takes the feed lock with the chain
/// lock held. Until the per-pool tree is cached (a separate item, MBP §7), at most this
/// many path builds run at once across every pool, `try_acquire` like `CERT_VERIFY`: one
/// unauthenticated scanner can no longer serialize commit behind 256 full-feed copies. A
/// wallet needs one path per spend; two slots are plenty.
const POOL_PATH_SLOTS: usize = 2;
static POOL_PATH: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(POOL_PATH_SLOTS);

/// v0.19.13: at most this many pool-proof verifications of the door (`door_proof_check`,
/// behind `hk_submitTx` and `hk_gossipTxs`) run at once in the process, `try_acquire` like
/// `CERT_VERIFY`: past them a pool tx is answered "busy … retry later" at once and nothing
/// queues. A verification runs with no lock held and only for a tx that passed every check of
/// admission, and once a proof of a sender does not verify, that sender's transactions that
/// carry a pool proof wait before the next one is looked at (`Mempool::note_refused_proof`).
/// One slot: the verification runs on the runtime worker that serves the request; one in
/// flight leaves the node's other tasks the other workers; a second caller is answered busy at
/// once.
const POOL_PROOF_VERIFY_SLOTS: usize = 1;
static POOL_PROOF_VERIFY: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(POOL_PROOF_VERIFY_SLOTS);

/// HR-4 (v0.19.12): `hk_getAssets` is paged — at most this
/// many registry entries per call (`limit`, the default and the cap; `from` is the index of
/// the first — `asset_page`). A page's conservation receipts come from one pass over the
/// registry and every balance and channel (`asset_conservation_all`); the page bounds the
/// entries and the JSON a call returns.
pub(crate) const ASSET_PAGE_MAX: usize = 1_000;

/// HR-4: at most ONE registry scan (`hk_getAssets`: one `asset_conservation_all` pass under the
/// chain lock plus a page of JSON) runs at once per node, `try_acquire` like `POOL_PATH` — the
/// rest answer "busy — retry" and never queue on the lock the commit path needs. The pass is
/// O(assets + balances + channels) for the whole page instead of O(page × (balances +
/// channels)); the slot keeps a flood of callers from stacking even that.
static ASSET_SCAN: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

/// v0.19.12: at most this many block reads — `hk_getBlock`, `hk_getTx`, `hk_getBlocks`
/// together — run at once per node, each holding one permit of `BLOCK_READ` from before its
/// first block is loaded until its summaries are built (`try_acquire` like `POOL_PATH`; past them a
/// call answers "busy — retry", `block_read_busy`, and loads nothing). Every call gives its
/// permit back when it ends (pinned by the tests below), and the busy answer names the
/// limit and asks the client to retry in a moment. The explorer polls one at a time, so
/// two are plenty.
const BLOCK_READ_SLOTS: usize = 2;
static BLOCK_READ: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(BLOCK_READ_SLOTS);

/// v0.19.12: the stored-block bytes (`StoredBlock::value_bytes`) one `hk_getBlocks` call
/// loads before it stops and names where to continue (`truncated`, `next_before`). The check
/// runs before each load, so a call loads at most this plus one block.
const BLOCKS_READ_BUDGET: usize = 64 * 1024 * 1024;

/// v0.19.12: the most bytes of an asset symbol `tx_summary` shows (cut on a character
/// boundary). The chain accepts 16 (`hk_state::assets::MAX_SYMBOL_LEN`), so every registered
/// symbol is shown whole.
const SUMMARY_SYMBOL_SHOWN: usize = 64;

/// v0.19.12: the most bytes of a burn destination `tx_summary` shows (as hex, so up to
/// 256 characters). The chain accepts 64 (`hk_state::assets::MAX_BURN_DESTINATION`), so every
/// accepted burn's destination is shown whole — the bridge attestor compares it in full
/// (attest.rs).
const SUMMARY_DESTINATION_SHOWN: usize = 128;

/// L-6: `hk_submitSetChange` refuses, before verifying, a certificate whose window opens
/// more than this many blocks past the tip. A queued cert sits in RAM until its window
/// opens (propose keeps it while `not_before > height`), so this bounds how long an
/// accepted cert can park: ≈18 days at testnet-1's 1.6 s cadence. A certificate for a
/// later window is assembled closer to it, not parked on a node.
const SET_CHANGE_HORIZON: u64 = 1_000_000;

pub async fn serve(addr: SocketAddr, h: SharedHandles) -> eyre::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, timeout_s = RPC_CONN_TIMEOUT.as_secs(), max_conns = RPC_MAX_CONNS, "RPC listening");
    let slots = Arc::new(tokio::sync::Semaphore::new(RPC_MAX_CONNS));
    loop {
        let (mut sock, _peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(%e, "accept failed");
                continue;
            }
        };
        let h = h.clone();
        let slots = slots.clone();
        tokio::spawn(async move {
            let Ok(_permit) = slots.try_acquire() else {
                let _ = respond(&mut sock, 503, &json!({"error":"rpc busy — try again"})).await;
                return;
            };
            match tokio::time::timeout(RPC_CONN_TIMEOUT, handle_conn(&mut sock, &h)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(%e, "rpc conn error"),
                Err(_) => {
                    let _ = respond(&mut sock, 408, &json!({"error":"request timed out"})).await;
                }
            }
        });
    }
}

/// H2 (v0.13.2): operator methods a web page must never be able to drive. A browser
/// always sends `Origin` on a cross-site POST; CORS only hides the RESPONSE, the
/// request still runs — so these are refused outright when an Origin is present.
/// Read methods and `hk_submitTx` stay browser-callable (the explorer, the site,
/// the wallet). Override for a deliberately browser-driven devnet: HK_RPC_ALLOW_BROWSER_OPS=1.
const OPERATOR_METHODS: &[&str] = &["hk_submitRotation", "hk_submitSetChange", "hk_gossipTxs", "hk_submitBundle"];

fn browser_ops_allowed() -> bool {
    std::env::var("HK_RPC_ALLOW_BROWSER_OPS").map(|v| v == "1").unwrap_or(false)
}

/// HR-1 (mr-hrydarie, reported 2026-11-04; v0.19.11): the P2.3 aggregation door is closed unless
/// the operator opens it — `hk_rpc.accept_bundles = true` in config.toml (`SharedHandles::
/// accept_bundles`, copied in node.rs; false by default and on every seat `config-gen` writes)
/// or HK_RPC_ACCEPT_BUNDLES=1 for one process, the mirror of `browser_ops_allowed`. There is
/// no aggregator role yet; the one legitimate caller in the tree is the devnet's `demo-agg`,
/// and the devnet generator opens the door for it.
fn bundles_open(h: &SharedHandles) -> bool {
    h.accept_bundles || std::env::var("HK_RPC_ACCEPT_BUNDLES").map(|v| v == "1").unwrap_or(false)
}

/// C2.1: the shared admission gate for `hk_submitTx` AND `hk_gossipTxs`.
/// Lock order: chain BEFORE mempool (the commit path's order — no deadlocks).
/// WAL on success only: the WAL replays through this same gate at restart, so
/// what was never admissible is never persisted.
///
/// R17 review (2026-10-06): the two M-2 hashes — `pk_commit` over the 16 KiB key and the
/// 256-SHAKE Lamport verify, ≈ 0.3 ms — are state-free, so they run HERE, before either
/// lock, and only the state-dependent binding runs under the locks
/// (`Mempool::try_admit_verified`). The first cut verified inside `try_admit`, i.e. with
/// the chain lock held: a flood of right-length junk on these two unauthenticated methods
/// held the lock the commit path needs for a verify per request, 256 workers deep (the
/// L-6 shape). Verdicts and their precedence are unchanged (mempool.rs
/// `hoisted_verdict_and_try_admit_agree`).
///
/// R18 (2026-10-08): an over-cap `ChannelOpen` is refused inside `envelope_verdict`, i.e.
/// before the hashes; an over-cap `ChannelSettle` under the locks, one channel lookup,
/// before the account walk (mempool.rs `r18_caps_refuse_the_same_through_both_doors`).
///
/// HR-1 (v0.19.11, E3): a proof-less pool tx is refused first of all — by its payload, before
/// the hashes and outside the mempool's verdict (`refuse_proof_less_pool_tx`): its only
/// legitimate carrier is a bundle, and uncovered it would ride a block and die at apply.
///
/// v0.19.12: the asset field rules (symbol, burn destination) and the per-tx byte cap
/// (`mempool::MAX_TX_BYTES`) ride inside `envelope_verdict` too — refused by the tx's own bytes,
/// before the hashes (mempool.rs `Mempool::field_bounds`). A refusal the verdict reached by
/// the tx's own bytes (`hash_free_refusal`: lengths, the R18 open cap, the stealth cap, the
/// field and size rules) is answered first; then the txid is computed and handed to the
/// pool's checks (`try_admit_verified_with_id`). For any tx the verdict passes (every honest
/// one) those checks run in this order: the count cap, the pool's bytes, the duplicate, the
/// slot, the sender's pending bytes (the two byte caps are new in v0.19.12), the R18 settle
/// checks, then the account walk; the older reasons keep their wording. A frame that fails
/// both a hash-free check and one of the pool checks (full, a byte cap, duplicate, slot
/// taken, an R18 settle cap) hears the hash-free one, the first the verdict reached; a bad
/// signature is still judged at the end of the account walk.
///
/// v0.19.13: a `Transfer` or `MintToPool` of amount zero is one more refusal by the tx's own
/// bytes. The pool's checks (mempool.rs `check_gated`) gain, after the nonce window, the memory
/// of txids a block refused and — for a tx that carries a pool proof — its sender's proof
/// wait; after the signature, at the account's current nonce only, the fee and the amount, as
/// apply orders them; and, last, the quota of pool txs with an unverified proof. Before the tx
/// enters the pool, a pool tx's proof is verified when the node has a verifier
/// (`door_proof_check`): the pool's checks run once with nothing indexed, the proof is verified
/// with no lock held on the door's verification slot (`POOL_PROOF_VERIFY_SLOTS`), and the
/// checks run again with the push. Both doors come through here, so both refuse the same
/// frames for the same reasons.
fn admit_one(h: &SharedHandles, tx: &SignedTx) -> Result<[u8; 32], String> {
    admit_one_with(h, tx, &POOL_PROOF_VERIFY)
}

/// v0.19.13: `admit_one` on the given proof-verification slot — the node's is
/// `POOL_PROOF_VERIFY`; a test brings its own, so no test waits on another's.
fn admit_one_with(h: &SharedHandles, tx: &SignedTx, verify_slots: &tokio::sync::Semaphore) -> Result<[u8; 32], String> {
    refuse_proof_less_pool_tx(tx)?;
    let verdict = Mempool::envelope_verdict(tx);
    if let Some(e) = verdict.hash_free_refusal() {
        return Err(e.as_str());
    }
    let id = txid(tx);
    let proof_checked = match door_proof_check(h, tx, &id, &verdict, verify_slots) {
        Ok(checked) => checked,
        Err(e) => return Err(e.as_str()),
    };
    let admitted = {
        let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut mp = h.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if proof_checked {
            mp.try_admit_proof_checked_with_id(tx.clone(), id, &chain, &verdict)
        } else {
            mp.try_admit_verified_with_id(tx.clone(), id, &chain, &verdict)
        }
    };
    match admitted {
        Ok(id) => {
            if let Some(store) = &h.store {
                if let Err(e) = store.wal_append(tx) {
                    warn!(%e, "mempool WAL append failed");
                }
            }
            Ok(id)
        }
        Err(e) => Err(e.as_str()),
    }
}

/// v0.19.13: the door's check of a pool tx's proof, before the tx enters the pool. `Ok(true)`:
/// the node has a verifier and the proof verifies against the tx's own public values.
/// `Ok(false)`: nothing was verified — the tx carries no proof of its own, or the node has no
/// verifier (the pool then holds the tx to its quota of unverified ones). In order:
///   1. under the locks (chain before mempool): the verifier, then `Mempool::precheck_with_id`
///      — a txid remembered at step 4 is answered `pool proof rejected` at
///      once, and so is, with its own reason, a frame the pool refuses anyway (not the
///      account's key, a bad signature, a zero amount, a value the balance does not cover, the
///      sender's proof wait, a full pool): none of them costs a verification;
///   2. the slot (`POOL_PROOF_VERIFY_SLOTS` in the process), or "busy" at once;
///   3. no lock held: the verification (`mempool::pool_proof_verifies`), behind a panic
///      boundary;
///   4. a proof that does not verify: the txid is remembered, so the same bytes are answered
///      in step 1 from now on, and the sender's transactions that carry a pool proof wait —
///      longer with each new txid of that sender that fails here
///      (`Mempool::note_refused_proof`). A verification that gives no answer refuses the tx
///      and counts the wait, and the txid is not remembered.
/// What apply checks against its state (the anchor, the nullifier) stays at apply.
fn door_proof_check(
    h: &SharedHandles,
    tx: &SignedTx,
    id: &[u8; 32],
    verdict: &crate::mempool::EnvelopeVerdict,
    slots: &tokio::sync::Semaphore,
) -> Result<bool, crate::mempool::AdmitError> {
    if !crate::mempool::carries_pool_proof(tx) {
        return Ok(false);
    }
    let verifier = {
        let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mp = h.mempool.lock().unwrap_or_else(|e| e.into_inner());
        let Some(verifier) = mp.proof_verifier() else {
            return Ok(false);
        };
        mp.precheck_with_id(tx, id, &chain, verdict)?;
        verifier
    };
    let Ok(_permit) = slots.try_acquire() else {
        return Err(crate::mempool::AdmitError::ProofVerifyBusy);
    };
    // `Ok(verdict)`: the verifier's own answer; `Err`: the verification gave no answer
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::mempool::pool_proof_verifies(&*verifier, tx)
    }));
    if matches!(outcome, Ok(true)) {
        return Ok(true);
    }
    let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
    let mut mp = h.mempool.lock().unwrap_or_else(|e| e.into_inner());
    mp.note_refused_proof(tx.sender, *id, outcome.is_ok(), chain.height);
    Err(crate::mempool::AdmitError::PoolProofRejected)
}

async fn handle_conn(sock: &mut tokio::net::TcpStream, h: &SharedHandles) -> eyre::Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];

    // Read until headers complete.
    let header_end = loop {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 1_048_576 {
            return respond(sock, 413, &json!({"error":"headers too large"})).await;
        }
    };

    let headers = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
    let content_len: usize = headers
        .split("\r\n")
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    // H1: the body cap is enforced before reading it, not after.
    if content_len > 8_388_608 {
        return respond(sock, 413, &json!({"error":"body too large"})).await;
    }
    // H2: a browser page is calling (cross-site POSTs always carry Origin).
    let from_browser = headers.split("\r\n").any(|l| l.starts_with("origin:"));

    while buf.len() < header_end + content_len {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 8_388_608 {
            return respond(sock, 413, &json!({"error":"body too large"})).await;
        }
    }

    let body = &buf[header_end..(header_end + content_len).min(buf.len())];
    let req: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return respond(sock, 400, &json!({"error": format!("bad json: {e}")})).await,
    };

    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    if from_browser && OPERATOR_METHODS.contains(&method) && !browser_ops_allowed() {
        warn!(method, "operator RPC method refused: called from a browser origin");
        return respond(sock, 403, &json!({"error": format!("{method} is an operator method and cannot be called from a browser page")})).await;
    }
    let result = dispatch(method, &params, h);
    let status = if result.get("error").is_some() { 400 } else { 200 };
    respond(sock, status, &result).await
}

/// H4/H5 (v0.13.2) bounds on unauthenticated ingress.
const BUNDLE_QUEUE_MAX: usize = 64;
const GOSSIP_MAX_TXS: usize = 1_024;

/// HR-1 (mr-hrydarie, reported 2026-11-04; v0.19.11): the most aggregate bytes `hk_submitBundle`
/// takes. An aggregate STARK is 1,242 KB and constant in N — the P2.3 measurement
/// (docs/MASTER-BUILD-PLAN.md, the metrics table: "Aggregate STARK (any N): 1,242 KB
/// constant"; `demo-agg` prints the size it got) — so 2 MiB is ≈ 1.6× headroom. Until this the
/// only bound was the 8 MiB body cap, and a garbage aggregate rode whole into every node's
/// block log once the proposer picked the bundle (≈ 4 MiB per pre-empted block in the report).
/// Re-pin on an SP1 upgrade that changes the compressed-proof size; the error names the
/// legitimate size so a real aggregator that outgrows it knows what to ask for. `pub(crate)`
/// (v0.19.12): mempool.rs checks at compile time that a block at
/// `batch::MAX_BATCH_TX_BYTES` plus this aggregate fits the proposal frame.
pub(crate) const MAX_BUNDLE_AGG_BYTES: usize = 2 * 1024 * 1024;

/// HR-1: the one shape a `MintToPool` / `ShieldedSpend` has when its truth is a block
/// aggregate's — an EMPTY `proof` (P2.3). `bundle_shape_verdict` requires it of every bundle
/// tx; `admit_one` refuses it (`refuse_proof_less_pool_tx`), because through `hk_submitTx` /
/// `hk_gossipTxs` such a tx can only ride uncovered and die at apply (`pool proof rejected`),
/// a block slot burnt for the price of an envelope.
fn proof_less_pool_tx(tx: &SignedTx) -> bool {
    matches!(&tx.payload, Tx::MintToPool { proof, .. } | Tx::ShieldedSpend { proof, .. } if proof.is_empty())
}

/// HR-1 (E3): the `hk_submitTx` / `hk_gossipTxs` refusal of a proof-less pool tx — at the
/// door, before the envelope hashes, and NOT inside `Mempool::envelope_verdict`: the bundle
/// door's scratch dry run (`submit_bundle`) runs that same verdict on txs that are proof-less
/// by definition. There is a second reason the two must stay apart: a proof-less pool tx in
/// the same block as a bundle enters the aggregate digest (state.rs `apply_batch_to_chain`
/// folds EVERY proof-less pool tx of the block into it), so one such pool tx would refuse the
/// whole honest bundle beside it. The reason tells the caller where such a tx belongs. The one
/// legitimate proof-less sender in the tree, `demo_agg`, submits its spends through
/// `hk_submitBundle` only (its step [5] fallback spend carries a proof); the CLI wallet
/// (`wallet_cli.rs`), the desktop/Android core (`hk-wallet-core` `shield.rs`) and the demos
/// attach the prover's proof to every pool tx they send through `hk_submitTx`.
fn refuse_proof_less_pool_tx(tx: &SignedTx) -> Result<(), String> {
    if proof_less_pool_tx(tx) {
        return Err("a proof-less pool tx can only be covered by a bundle's aggregate — submit it through hk_submitBundle".into());
    }
    Ok(())
}

/// R18 review (2026-10-08): what `hk_submitBundle` may queue — P2.3's definition of a
/// bundle, exactly: proof-less pool txs (`MintToPool` / `ShieldedSpend` with an empty
/// `proof`) whose truth the ONE aggregate STARK carries, and no more of them than a block
/// holds (`build_batch` would never pick a longer bundle, and a queued bundle it never
/// picks sits at the head of the queue until its txs commit some other way). Anything else
/// — a `ChannelSettle` above all — has no business in a bundle: it rode ahead of the pool,
/// uncosted by the proposer's settle-link budget and unseen by the mempool's two caps, so
/// the bundle path was the one door through which an over-cap settle reached an UPGRADED
/// proposer's own block (the module doc). The verdict reads payloads only; the mempool
/// never sees bundle txs, so it is judged here, before the queue.
///
/// HR-1 (mr-hrydarie, reported 2026-11-04; v0.19.11): two more payload-reading, state-free rules
/// per tx, so that the report's frames — keyless, with megabytes of advisory bytes — are
/// refused for free, before the queue lock and the admission slot: the envelope must have the
/// one shape a Lamport signature can verify in (`PK_LEN` / `SIG_LEN`, the rule
/// `Mempool::envelope_verdict` applies to every other tx — a bundle tx is account-signed like
/// any other), and every stealth ciphertext must be inside `MAX_STEALTH_CT_BYTES` (one number
/// for both doors, mempool.rs). Whether each tx would APPLY — sender, nonce, key, anchor,
/// nullifier, signature — is `submit_bundle`'s dry run, after this.
///
/// v0.19.12: and the bundle's txs must fit one block's transaction budget —
/// `batch::MAX_BATCH_TX_BYTES` over `mempool::tx_encoded_len` — because `build_batch` rides a
/// bundle whole or not at all (a size walk per tx, no hash).
pub(crate) fn bundle_shape_verdict(txs: &[SignedTx]) -> Result<(), String> {
    if txs.len() > MAX_TXS_PER_BLOCK {
        return Err(format!("bad txs: a bundle may carry at most {MAX_TXS_PER_BLOCK} txs (one block)"));
    }
    for (i, t) in txs.iter().enumerate() {
        if !proof_less_pool_tx(t) {
            return Err(format!(
                "bad txs: a bundle may carry only proof-less MintToPool / ShieldedSpend txs covered by its aggregate (tx {i} is not one — submit it through hk_submitTx)"
            ));
        }
        if t.lamport_pk.len() != PK_LEN || t.sig.len() != SIG_LEN {
            return Err(format!(
                "bad txs: tx {i} has a malformed envelope ({} B pk, {} B sig) — a bundle tx is account-signed like any other",
                t.lamport_pk.len(),
                t.sig.len()
            ));
        }
        if let Some(n) = stealth_ct_over_cap(t) {
            return Err(format!("bad txs: tx {i} carries a {n}-byte stealth ciphertext (max {MAX_STEALTH_CT_BYTES})"));
        }
    }
    let bytes = txs.iter().map(tx_encoded_len).fold(0usize, usize::saturating_add);
    if bytes > MAX_BATCH_TX_BYTES {
        return Err(format!(
            "bad txs: the bundle's txs take {bytes} B in a block (max {MAX_BATCH_TX_BYTES}, one block's transaction budget)"
        ));
    }
    Ok(())
}

/// HR-1 (E1 + H4): the free checks on the bundle QUEUE, run under its lock before the
/// admission slot and again before the push (the queue may have changed in between): the H4
/// cap and aggregate-bytes dedup (v0.13.2), and no overlap with a queued bundle — a
/// (sender, nonce) slot or a `ShieldedSpend` nullifier that a queued bundle already carries
/// refuses the new one (two bundles claiming one slot cannot both apply; the loser would ride
/// a later block as all-Err receipts). The two sets are rebuilt from the queue each call: at
/// most `BUNDLE_QUEUE_MAX` × `MAX_TXS_PER_BLOCK` entries.
fn bundle_queue_verdict(q: &[(Vec<SignedTx>, Vec<u8>)], txs: &[SignedTx], agg: &[u8]) -> Result<(), String> {
    if q.len() >= BUNDLE_QUEUE_MAX {
        return Err(format!("bundle queue full (max {BUNDLE_QUEUE_MAX}) — retry after the next block"));
    }
    if q.iter().any(|(_, a)| a.as_slice() == agg) {
        return Err("duplicate bundle (same aggregate proof already queued)".into());
    }
    let mut slots: HashSet<(AccountId, u64)> = HashSet::new();
    let mut nullifiers: HashSet<[u8; 32]> = HashSet::new();
    for t in q.iter().flat_map(|(btxs, _)| btxs.iter()) {
        slots.insert((t.sender, t.nonce));
        if let Tx::ShieldedSpend { nullifier, .. } = &t.payload {
            nullifiers.insert(nullifier.0);
        }
    }
    for (i, t) in txs.iter().enumerate() {
        let nullifier_queued =
            matches!(&t.payload, Tx::ShieldedSpend { nullifier, .. } if nullifiers.contains(&nullifier.0));
        if slots.contains(&(t.sender, t.nonce)) || nullifier_queued {
            return Err(format!("bad txs: a queued bundle already carries tx {i}'s (sender, nonce) slot or nullifier"));
        }
    }
    Ok(())
}

/// `hk_submitBundle` (P2.3; R18 review; HR-1, mr-hrydarie, reported 2026-11-04, v0.19.11):
/// queue a bundle — proof-less pool txs + ONE aggregate STARK — for this node's next proposal
/// (`build_batch` rides the head bundle whole, ahead of the pool; every validator verifies the
/// aggregate once at commit). The door is CLOSED unless `open` (`bundles_open`: the operator's
/// `hk_rpc.accept_bundles`, or HK_RPC_ACCEPT_BUNDLES=1) — there is no aggregator role yet — and
/// an open door admits a bundle only if every tx in it would apply, in this order:
///   1. free, no lock: the aggregate cap `MAX_BUNDLE_AGG_BYTES` on the hex string's LENGTH,
///      before it is decoded and before the txs are parsed (S3); the parse, by reference —
///      the body may be 8 MiB (S4); `bundle_shape_verdict` (the R18 shape, the HR-1 envelope
///      lengths and stealth caps); the aggregate cap again on the decoded bytes;
///   2. free, the queue lock only: `bundle_queue_verdict` (cap, dedup, E1 overlap);
///   3. the one admission slot (`BUNDLE_ADMIT`, F1) — or "busy", so a flood of well-shaped
///      bundles costs this node one dry run at a time and the garbage above costs it nothing;
///   4. no lock held: per tx the txid and `Mempool::envelope_verdict` — the key commitment and
///      the Lamport verify over the tx's own bytes, ≈ 0.3 ms each — failing fast on a
///      hash-free refusal. Every hash of the admission happens here (S1);
///   5. the chain lock (R17 order: chain before mempool; the live mempool is NEVER taken):
///      every tx in order through `Mempool::try_admit_verified_with_id` on a SCRATCH pool —
///      account, nonce, anchor, nullifier, the key→account binding along the pending ratchet,
///      the signature at its own position, nothing hashed — so a legitimate bundle's sequential
///      nonces pass (the live pool would answer NonceGap for the 2nd..nth, and nothing from a
///      bundle may be WAL'd, gossiped or indexed into it) and a refusal names the tx with
///      hk_submitTx's reason for the same frame;
///   6. the queue lock again: `push_bundle` — the free queue checks re-run against the queue
///      as it is NOW (it may have changed since step 2), then the push.
/// The dry run judges a bundle against the CHAIN, not the live pool: whole from each sender's
/// current nonce (one outstanding bundle per account; at most `mempool::NONCE_WINDOW` txs per
/// sender). v0.19.13: for each sender's first tx — the one at its current nonce — the dry run
/// asks what hk_submitTx asks: the envelope fee, and a shield's value against the balance; a
/// shield of value zero is refused by its own bytes; behind that first tx no balance is
/// judged. The live pool's txid memories and proof waits are not read: the scratch pool has
/// none. Takes the handles it touches rather than `SharedHandles` so
/// `hr1_tests` drives it without a node; `dispatch` passes `bundles_open(h)`, `&h.chain`,
/// `&h.bundles`, `&BUNDLE_ADMIT`. Not in this release: verifying the aggregate at submit — a
/// queued bundle whose aggregate is invalid still rides one of this node's blocks and its txs
/// are refused there, by every node, as before.
fn submit_bundle(
    params: &Value,
    open: bool,
    chain: &Mutex<hk_state::State>,
    bundles: &Mutex<Vec<(Vec<SignedTx>, Vec<u8>)>>,
    admit: &tokio::sync::Semaphore,
) -> Value {
    if !open {
        return json!({"error": "hk_submitBundle is closed on this node (hk_rpc.accept_bundles = false): there is no aggregator role yet — a devnet opens it with accept_bundles = true or HK_RPC_ACCEPT_BUNDLES=1"});
    }
    let agg_hex = params.get("agg_proof").and_then(|p| p.as_str()).unwrap_or("");
    // HR-1 (S3): the aggregate cap on the hex string, before `hex::decode` allocates and
    // decodes it and before the tx parse — two hex digits per byte, an odd digit rounds up.
    if agg_hex.len() > 2 * MAX_BUNDLE_AGG_BYTES {
        return agg_too_large(agg_hex.len().div_ceil(2));
    }
    // HR-1 (S4): the txs are read from `params` by reference — `serde_json::from_value` needs
    // an owned `Value`, i.e. a clone of a body of up to 8 MiB first.
    let null = Value::Null;
    let txs_val = params.get("txs").unwrap_or(&null);
    let (txs, agg) = match (Vec::<SignedTx>::deserialize(txs_val), hex::decode(agg_hex)) {
        (Ok(txs), Ok(agg)) if !txs.is_empty() && !agg.is_empty() => (txs, agg),
        (Err(e), _) => return json!({"error": format!("bad txs: {e}")}),
        (_, Err(e)) => return json!({"error": format!("bad agg_proof hex: {e}")}),
        _ => return json!({"error": "txs (non-empty) and agg_proof required"}),
    };
    // R18 review + HR-1: shape, envelope lengths, stealth caps — payloads only, no lock.
    if let Err(reason) = bundle_shape_verdict(&txs) {
        warn!(txs = txs.len(), "hk_submitBundle refused: {reason}");
        return json!({"error": reason});
    }
    // unreachable while `hex::decode` is exact (the hex-length check above already bounds the
    // decoded size); kept as the belt if the aggregate ever arrives in another encoding.
    if agg.len() > MAX_BUNDLE_AGG_BYTES {
        return agg_too_large(agg.len());
    }
    // H4 + E1 under the queue lock, dropped before the slot.
    {
        let q = bundles.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(reason) = bundle_queue_verdict(&q, &txs, &agg) {
            return json!({"error": reason});
        }
    }
    // F1: one admission in flight per node; the permit is held until the push.
    let Ok(_permit) = admit.try_acquire() else {
        return json!({"error": "busy: a bundle admission is already in flight — retry in a moment"});
    };
    // The hashes, no lock held: each tx's txid (the dry run and the push reuse it — S1: nothing
    // is hashed under a lock) and its envelope verdict. A bad signature is not judged here: the
    // scratch pool judges it at its own position, after the account and key checks, so the
    // reason a caller reads is the one hk_submitTx would give for the same frame.
    let mut judged: Vec<([u8; 32], crate::mempool::EnvelopeVerdict)> = Vec::with_capacity(txs.len());
    for (i, t) in txs.iter().enumerate() {
        let id = txid(t);
        let v = Mempool::envelope_verdict(t);
        // unreachable after `bundle_shape_verdict` (the lengths and the stealth cap are its
        // rules, a bundle tx is never a `ChannelOpen`, an `AssetRegister` or an `AssetBurn`, and
        // its shape keeps it far under `mempool::MAX_TX_BYTES`); kept so a future shape
        // change cannot hash past a `BadEnvelope`.
        if let Some(e) = v.hash_free_refusal() {
            return json!({"error": format!("bad txs: tx {i} would not apply: {}", e.as_str())});
        }
        judged.push((id, v));
    }
    // The dry run: the chain lock only, nothing hashed; the scratch pool indexes as it goes
    // and dies here.
    {
        let chain = chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut scratch = Mempool::new(txs.len());
        for (i, (t, (id, v))) in txs.iter().zip(&judged).enumerate() {
            if let Err(e) = scratch.try_admit_verified_with_id(t.clone(), *id, &chain, v) {
                return json!({"error": format!("bad txs: tx {i} would not apply: {}", e.as_str())});
            }
        }
    }
    let ids: Vec<String> = judged.iter().map(|(id, _)| hex::encode(id)).collect();
    let mut q = bundles.lock().unwrap_or_else(|e| e.into_inner());
    match push_bundle(&mut q, txs, agg, ids) {
        Ok(ids) => json!({"result": {"accepted": true, "txids": ids}}),
        Err(reason) => json!({"error": reason}),
    }
}

/// HR-1: the one wording of the aggregate cap, whether the hex string's length or the decoded
/// bytes tripped it. It names the legitimate size so a real aggregator that outgrows the cap
/// knows what to ask for.
fn agg_too_large(bytes: usize) -> Value {
    json!({"error": format!("bad agg_proof: {bytes} bytes (max {MAX_BUNDLE_AGG_BYTES} — an aggregate STARK is ~1,242 KB)")})
}

/// HR-1 (E1, review item S2): the push, under the queue lock the caller holds. The free queue
/// checks (`bundle_queue_verdict`: cap, dedup, overlap) re-run against the queue AS IT IS NOW —
/// it may have changed since `submit_bundle` judged it before the admission slot — and then the
/// bundle is pushed. `ids` are the txs' txids (hex), computed once with no lock held, handed
/// back for the response. A refusal leaves the queue untouched.
fn push_bundle(
    q: &mut Vec<(Vec<SignedTx>, Vec<u8>)>,
    txs: Vec<SignedTx>,
    agg: Vec<u8>,
    ids: Vec<String>,
) -> Result<Vec<String>, String> {
    bundle_queue_verdict(q, &txs, &agg)?;
    q.push((txs, agg));
    Ok(ids)
}

fn dispatch(method: &str, params: &Value, h: &SharedHandles) -> Value {
    match method {
        "hk_chainInfo" => {
            let (epoch, remaining) = *h.signer_gauge.lock().unwrap_or_else(|e| e.into_inner());
            let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
            json!({"result": {
                "chain_id": h.chain_id,
                // Genesis-gate: the network's identity fingerprint (== `sha256sum
                // genesis.json`). A joiner confirms this matches before trusting a node.
                "genesis_digest": hex::encode(h.genesis_digest),
                // N1 (v0.15.2): an operator can prove which binary answers, and how many
                // peers it holds (the full table is `hk_getPeers`).
                "node_version": crate::NODE_VERSION,
                "peers": malachitebft_network::hk_peers().len(),
                "height": chain.height,
                "app_hash": hex::encode(chain.state_commitment().0),
                // R4: THIS node's consensus-signer leaf budget (the fuse, visible).
                "signer": {
                    "epoch": epoch,
                    "remaining": remaining,
                    "capacity": hk_crypto::hashsig::CONSENSUS_CAPACITY,
                },
                // U4: the flat envelope fee — policy this node enforces + total burned.
                "fee": {
                    "micro": chain.fee_micro.to_string(),
                    "from_height": chain.fee_from,
                    "burned_micro": chain.fees_burned.to_string(),
                },
                // R10 v2: what this node serves to syncing peers from disk (gap-free
                // suffix floor; null until the first block lands) + its RAM window.
                "history": {
                    "disk_from": h.store.as_ref().map(|s| s.disk_min()).filter(|m| *m > 0),
                    "ram_window": crate::state::decided_window(),
                    "indexed_txs": h.tx_index.lock().unwrap_or_else(|e| e.into_inner()).len(),
                    // C2.8 (v0.16.0): null = archive node (keeps every block); N = this node
                    // prunes whole segments older than tip−N, and `disk_from` moves up.
                    "retain_blocks": Some(crate::state::retain_blocks()).filter(|r| *r > 0),
                },
                // R11 (v0.17.0): what THIS process costs — resident set (Linux + macOS
                // since v0.19.4; null elsewhere), seconds since start, and how long the
                // verify-only STARK client took to come up (null = no verifier wired). The
                // onboarding doc's RAM line is checkable on any node with one call.
                // v0.19.4: free bytes on the filesystem holding the block log (incident #13
                // was a full disk) — null without a store or off-Unix.
                "process": {
                    "rss_bytes": crate::state::rss_bytes(),
                    "uptime_secs": crate::state::uptime_secs(),
                    "verifier_init_ms": crate::state::verifier_init_ms(),
                    "disk_free_bytes": h.store.as_ref().and_then(|s| crate::state::disk_free_bytes(s.blocks_dir())),
                },
                // R17 (v0.19.6) + R18 (2026-10-08): the activation heights THIS binary holds
                // for this chain — null = never (`u64::MAX`). The roll call reads them off
                // every seat: a height is named for testnet-1 only once each seat answers the
                // same number, and a node that answers differently is the one that will island.
                "activations": {
                    "mandate_asset_from": activation_height(chain.mandate_asset_from),
                    "rotation_v2_from": activation_height(h.rotation_v2_from),
                    // R18: the PayWord caps (MAX_SETTLE_DELTA links per settle,
                    // MAX_CHANNEL_STEPS per channel) as a consensus rule; the mempool
                    // mirrors them from the moment this binary runs, gate or no gate.
                    "payword_cap_from": activation_height(chain.payword_cap_from),
                },
            }})
        }
        // R2: accept a root-signed RotationCert on behalf of ANOTHER validator (an
        // exhausted signer can't propose its own revival — peers carry it). Validated
        // against the live set here AND re-validated at propose + commit; the root
        // signature makes this trustless (nothing to spoof, replay is epoch-monotone).
        // L-6 (R17): the body lives in `submit_rotation` — free refusals first, the verify
        // on a snapshot with no lock held, bounded by CERT_VERIFY_SLOTS. L-2: judged by the
        // rule at tip + 1, the earliest height the cert can commit at (chain lock taken for
        // the tip only, released before the validator-set lock — the commit path's order).
        "hk_submitRotation" => match params.get("cert") {
            Some(c) => match serde_json::from_value::<RotationCert>(c.clone()) {
                Ok(cert) => {
                    let tip = h.chain.lock().unwrap_or_else(|e| e.into_inner()).height;
                    let rules = RotationRules::new(tip.saturating_add(1), &h.chain_id, h.rotation_v2_from);
                    submit_rotation(&h.validators, &h.foreign_rotations, &CERT_VERIFY, &rules, cert)
                }
                Err(e) => json!({"error": format!("bad cert: {e}")}),
            },
            None => json!({"error": "params.cert required (output of `hk-node issue-rotation`)"}),
        },
        // HR-9 (v0.19.12): the body is `get_account` — it answers the id's balances whether
        // or not an account exists at it, so a credit to a never-created id is visible.
        "hk_getAccount" => get_account(&h.chain, params),
        // X1: the issued-asset registry. `asset` (hex) OR `issuer` + `symbol` (the id rule).
        // One entry, one conservation scan: the per-asset view stays linear. v0.19.12 (HR-4
        // review): the scan holds the `ASSET_SCAN` slot `hk_getAssets` holds — `get_asset`.
        "hk_getAsset" => get_asset(&h.chain, &ASSET_SCAN, params),
        // HR-4 (v0.19.12): paged, one conservation pass, one scan in flight — `get_assets`.
        "hk_getAssets" => get_assets(&h.chain, &ASSET_SCAN, params),
        "hk_balance" => match (param_h256(params, "id"), param_h256(params, "asset")) {
            (Some(id), Some(asset)) => {
                let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
                // AccountId/AssetId are aliases of H256 — pass the H256 values directly.
                json!({"result": {"amount": chain.balance(&id, &asset).to_string()}})
            }
            _ => json!({"error": "id and asset must be 64-char hex"}),
        },
        "hk_mandateAvailable" => match param_h256(params, "leaf") {
            Some(leaf) => {
                let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
                let at = params.get("at").and_then(|v| v.as_u64()).unwrap_or(chain.time);
                match chain.mandates.available(&leaf, at) {
                    Ok(a) => json!({"result": {"available": a.to_string()}}),
                    Err(e) => json!({"result": {"available": null, "reason": e.to_string()}}),
                }
            }
            None => json!({"error": "leaf must be 64-char hex"}),
        },
        // HR-5 (v0.19.12): one mandate node, holder AND funder — `get_mandate`.
        "hk_getMandate" => get_mandate(&h.chain, params),
        "hk_submitTx" => {
            let tx_val = params.get("tx").cloned().unwrap_or(Value::Null);
            match serde_json::from_value::<SignedTx>(tx_val) {
                Ok(tx) => match admit_one(h, &tx) {
                    Ok(id) => {
                        // C2.3: single-hop push to peers (local admissions only —
                        // gossip-received txs never re-forward, so no loops).
                        if let Some(g) = &h.gossip {
                            g.enqueue(tx);
                        }
                        json!({"result": {"accepted": true, "txid": hex::encode(id)}})
                    }
                    Err(reason) => {
                        json!({"result": {"accepted": false, "reason": reason}})
                    }
                },
                Err(e) => json!({"error": format!("bad tx: {e}")}),
            }
        }
        // C2.3: peer ingress. Same admission gate as hk_submitTx, but NEVER
        // re-forwarded (single-hop by construction). Duplicate/stale refusals here
        // are business as usual — most gossiped txs race their own origin copies.
        "hk_gossipTxs" => {
            let txs: Vec<SignedTx> = params
                .get("txs")
                .cloned()
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default();
            // H5 (v0.13.2): one gossip call carries at most a block's worth; a peer
            // that floods gets refused, not served. Duplicates are already refused by
            // the mempool's admission gate (the seen-set is the mempool itself).
            if txs.len() > GOSSIP_MAX_TXS {
                return json!({"error": format!("too many txs in one gossip call (max {GOSSIP_MAX_TXS})")});
            }
            let (mut admitted, mut dropped) = (0usize, 0usize);
            for tx in txs {
                match admit_one(h, &tx) {
                    Ok(_) => admitted += 1,
                    Err(_) => dropped += 1,
                }
            }
            json!({"result": {"admitted": admitted, "dropped": dropped}})
        }
        "hk_getChannel" => match param_h256(params, "id") {
            Some(id) => {
                let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
                match chain.channels.get(&id) {
                    Some(ch) => json!({"result": {
                        "found": true,
                        "payer": hex::encode(ch.state.payer.0),
                        "payee": hex::encode(ch.state.payee.0),
                        "asset": hex::encode(ch.state.asset.0),
                        "mandate": hex::encode(ch.state.mandate.0),
                        "tip": hex::encode(ch.state.tip.0),
                        "unit_price": ch.state.unit_price.to_string(),
                        "max_steps": ch.state.max_steps,
                        "highest_step_settled": ch.state.highest_step_settled,
                        "escrow_remaining": ch.escrow_remaining.to_string(),
                        "expiry": ch.state.expiry,
                        "refunded": ch.refunded,
                    }}),
                    None => json!({"result": {"found": false}}),
                }
            }
            None => json!({"error": "id must be 64-char hex"}),
        },
        // P2.3: proof-less pool txs + ONE aggregate STARK. The proposer includes the
        // bundle whole; every validator verifies the aggregate once at commit.
        // HR-1 (mr-hrydarie, reported 2026-11-04; v0.19.11): closed unless the operator opened
        // it (`bundles_open`), and an open door admits only a bundle whose every tx would
        // apply — the body is `submit_bundle`: the free refusals (R18 shape, envelope lengths,
        // byte caps, the H4 queue checks, E1 overlap) before one admission slot, the envelope
        // hashes with no lock held, then the scratch-pool dry run under the chain lock.
        "hk_submitBundle" => submit_bundle(params, bundles_open(h), &h.chain, &h.bundles, &BUNDLE_ADMIT),
        "hk_getPoolInfo" => {
            // P6: `asset` (64-hex, optional) selects a per-asset pool; absent = the legacy
            // pool — every pre-P6 wallet keeps working unchanged.
            let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
            match pool_key_param(params, &chain) {
                Err(e) => json!({"error": e}),
                Ok(key) => match chain.pool_ref(key) {
                    None => json!({"error": "no pool for that asset yet"}),
                    Some(p) => json!({"result": pool_json(key, p)}),
                },
            }
        }
        "hk_getPools" => {
            // P6: every pool, the legacy one first.
            let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
            let pools: Vec<Value> = chain.pools_iter().map(|(k, p)| pool_json(k, p)).collect();
            json!({"result": {
                "count": pools.len(),
                "multi_pool_from": if chain.multi_pool_from == u64::MAX { Value::Null } else { json!(chain.multi_pool_from) },
                "pools": pools,
            }})
        }
        // ---- H3 (v0.16.1): the pool feed is PAGED. `from` (leaf index, default 0) and
        // `limit` (default and cap POOL_PAGE_MAX) — the answer carries `total` and `next`
        // (null when the page reached the end). A wallet keeps `next` as its scan cursor and
        // asks only for what it has not seen; a spender asks `hk_getPoolPath` for one
        // authentication path instead of downloading every commitment.
        // L-5 (R17): each arm hands `with_pool_feed` a closure that copies exactly what the
        // answer needs — a page of leaves, a page of notes, or the bare 32-byte leaves — and
        // nothing else leaves the lock. The JSON shapes are the v0.19.0 ones, byte for byte.
        "hk_getPoolLeaves" => {
            // P6: `asset` (optional) selects the per-asset feed; absent = the legacy pool.
            match with_pool_feed(&h.chain, &h.pool_notes, &h.pool_notes_by_asset, params, |feed| {
                page_of(feed, params, |(l, _)| l.0)
            }) {
                Err(e) => json!({"error": e}),
                Ok((page, asset)) => json!({"result": {
                    "asset": asset,
                    "leaves": page.items.iter().map(hex::encode).collect::<Vec<_>>(),
                    "from": page.from,
                    "count": page.to - page.from,
                    "total": page.total,
                    "next": page.next,
                }}),
            }
        }
        "hk_getPoolNotes" => {
            // For scanners: (leaf index, commitment, stealth payload). P6: per pool.
            match with_pool_feed(&h.chain, &h.pool_notes, &h.pool_notes_by_asset, params, |feed| {
                page_of(feed, params, |(l, ct)| (l.0, ct.clone()))
            }) {
                Err(e) => json!({"error": e}),
                Ok((page, asset)) => json!({"result": {
                    "asset": asset,
                    "notes": page.items.iter().enumerate().map(|(i, (l, ct))| json!({
                        "index": page.from + i,
                        "commitment": hex::encode(l),
                        "stealth_ct": hex::encode(ct),
                    })).collect::<Vec<_>>(),
                    "from": page.from,
                    "count": page.to - page.from,
                    "total": page.total,
                    "next": page.next,
                }}),
            }
        }
        "hk_getPoolPath" => {
            // One leaf's authentication path (siblings bottom→top) + the root it folds to,
            // computed from the node's full leaf list. The proof binds the root; the chain
            // accepts it only while that root is a recent anchor — a wrong path can only
            // cost the spender a rejected tx, never a coin. P6: per pool (`asset`).
            // L-5: the tree is still rebuilt per call (O(n) hashing — caching it is a
            // separate item), but only the 32-byte leaves are copied out of the lock, never
            // the ≈1.2 KB stealth ciphertext beside each one; the copy + the build are
            // bounded by POOL_PATH_SLOTS (`pool_path`).
            pool_path(&h.chain, &h.pool_notes, &h.pool_notes_by_asset, &POOL_PATH, params)
        }
        "hk_getReceipt" => match param_h256(params, "txid") {
            Some(id) => {
                let rlog = h.receipts.lock().unwrap_or_else(|e| e.into_inner());
                match rlog.get(&id.0) {
                    Some(detail) => json!({"result": {"found": true, "detail": detail}}),
                    None => json!({"result": {"found": false}}),
                }
            }
            None => json!({"error": "txid must be 64-char hex"}),
        },

        // ---- v0.11.2 search surface (node-local indexes; see state.rs::index_txs) ----
        // A txid resolves to its block + full summary — the receipt ring may evict old
        // entries, but the index + block log answer forever. v0.19.12: the body is
        // `get_tx`, under the shared block-read slot.
        "hk_getTx" => get_tx(h.store.as_deref(), &h.tx_index, &h.receipts, &BLOCK_READ, params),
        // An account's transaction history (sender or counterparty), newest first. v0.19.12:
        // the body is `get_account_txs` — one pass selects the page.
        "hk_getAccountTxs" => get_account_txs(&h.acct_index, params),

        // ---- P3.0b explorer surface ----
        "hk_nullifierSpent" => match param_h256(params, "nullifier") {
            // Wallets use this to tell spent notes from live ones (a nullifier reveals
            // nothing by itself — it is unlinkable to any commitment without nk).
            // P6: `asset` (optional) selects the pool; absent = the legacy pool.
            Some(nf) => {
                let chain = h.chain.lock().unwrap_or_else(|e| e.into_inner());
                match pool_key_param(params, &chain) {
                    Err(e) => json!({"error": e}),
                    Ok(key) => {
                        let spent = chain.pool_ref(key).is_some_and(|p| p.nullifiers.contains(&nf.0));
                        json!({"result": {"spent": spent}})
                    }
                }
            }
            None => json!({"error": "nullifier must be 64-char hex"}),
        },
        "hk_getValidators" => {
            let vs = h.validators.lock().unwrap_or_else(|e| e.into_inner());
            let queued = h.pending_set_changes.lock().unwrap_or_else(|e| e.into_inner());
            let height = h.chain.lock().unwrap_or_else(|e| e.into_inner()).height;
            let total = vs.total_voting_power();
            // G1 (v0.18.0): the arithmetic every operator should be able to read off the
            // node — who is a genesis seat, what the founders and the externals weigh, where
            // the quorum line is, and how much power may be absent before commits stop.
            let founding: u64 = vs.iter().filter(|v| h.genesis_roots.contains(&v.root_pk)).map(|v| v.voting_power).sum();
            let quorum = hk_consensus::quorum_power(total);
            let bootstrap = crate::genesis::bootstrap_for(&h.chain_id).map(|b| json!({
                "height": b.height,
                "founding_power": b.founding_power,
                "active": height >= b.height,
            }));
            json!({"result": {
                "count": vs.len(),
                "total_power": total,
                "founding_power": founding,
                "external_power": total.saturating_sub(founding),
                "quorum_power": quorum,
                "max_absent_power": total.saturating_sub(quorum),
                "founders_alone_decide": founding >= quorum,
                "bootstrap": bootstrap,
                "validators": vs.iter().map(|v| json!({
                    "address": v.address.to_string(),
                    "voting_power": v.voting_power,
                    "epoch": v.epoch,
                    "root_pk": hex::encode(&v.root_pk),
                    "genesis": h.genesis_roots.contains(&v.root_pk),
                })).collect::<Vec<_>>(),
                "pending_set_changes": queued.iter().map(|c| {
                    let change = match &c.body.change {
                        hk_consensus::SetChange::Admit { root_pk, voting_power, .. } =>
                            json!({"admit": hex::encode(root_pk), "voting_power": voting_power}),
                        hk_consensus::SetChange::Remove { root_pk } =>
                            json!({"remove": hex::encode(root_pk)}),
                        hk_consensus::SetChange::SetPower { root_pk, voting_power } =>
                            json!({"set_power": hex::encode(root_pk), "voting_power": voting_power}),
                    };
                    json!({
                        "change": change,
                        "not_before": c.body.not_before,
                        "not_after": c.body.not_after,
                        "approvals": c.approvals.len(),
                    })
                }).collect::<Vec<_>>(),
            }})
        }
        // N1 (v0.15.2): this node's live p2p peer table, straight from the swarm — who is
        // connected, which way, from where (masked), on which genesis and node version.
        // Measured, not configured: an entry exists only while a connection is open. The
        // gateway's table is the network's public roll call (every kit node bootstraps
        // through it); a node that peers only with other operators is not visible here.
        "hk_getPeers" => {
            let peers = malachitebft_network::hk_peers();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let (mut inbound, mut outbound, mut public_addr, mut identified) = (0usize, 0usize, 0usize, 0usize);
            let mut list = Vec::with_capacity(peers.len());
            for p in &peers {
                let (addr, private) = mask_multiaddr(&p.remote_addr);
                if p.direction == "inbound" { inbound += 1 } else { outbound += 1 }
                if !private { public_addr += 1 }
                if p.identified { identified += 1 }
                let genesis = match (p.identified, p.genesis) {
                    (false, _) => "pending",
                    (true, Some(g)) if g == h.genesis_digest => "match",
                    (true, Some(_)) => "mismatch",
                    (true, None) => "untagged",
                };
                list.push(json!({
                    "peer_id": p.peer_id,
                    "direction": p.direction,
                    "addr": addr,
                    "private_addr": private,
                    // null = a ≤ v0.15.1 node (genesis tag only) or identify not yet received
                    "version": p.node_version,
                    "genesis": genesis,
                    "identified": p.identified,
                    "connected_secs": now.saturating_sub(p.connected_at),
                    "connections": p.connections,
                    // v0.19.3: a restart that dialed in before its old socket died keeps the entry
                    // (connected_secs runs on) — these show it: seconds since the LATEST connection
                    // and how many connections arrived beyond the first.
                    "last_connection_secs": now.saturating_sub(p.last_connection_at),
                    "reconnects": p.reconnects,
                }));
            }
            json!({"result": {
                "self": {
                    "peer_id": h.self_peer_id,
                    "version": crate::NODE_VERSION,
                    "genesis_digest": hex::encode(h.genesis_digest),
                },
                "count": peers.len(),
                "inbound": inbound,
                "outbound": outbound,
                "public_addr": public_addr,
                "identified": identified,
                "islands_refused": malachitebft_network::hk_islands_refused(),
                // v0.19.10: the gate fails closed (untagged or foreign-protocol peers dropped),
                // and the broadcast carrier accepts Sync frames only.
                "untagged_refused": malachitebft_network::hk_untagged_refused(),
                "broadcast_refused": malachitebft_network::hk_broadcast_refused(),
                "peers": list,
                "note": "live from this node's swarm; addresses masked to /24 (v4) · /48 (v6) — a peer's real source address, not what it claims to listen on; private_addr = loopback/RFC 1918/CGNAT/ULA (the founding fleet peers over its private network)",
            }})
        }
        // V1: queue a validator-set change certificate. Checked against the live set
        // here (chain id, supermajority of CURRENT seats, window not yet closed) and
        // re-checked at propose + commit by every node; the root signatures make it
        // trustless to carry — anyone may relay a valid certificate.
        // L-6 (R17): the body lives in `submit_set_change` — free refusals first (shape,
        // chain id, window, membership, power, subject, queue dedup), then the per-approval
        // verify on a snapshot with no lock held, bounded by CERT_VERIFY_SLOTS.
        "hk_submitSetChange" => match params.get("cert") {
            Some(c) => match serde_json::from_value::<SetChangeCert>(c.clone()) {
                Ok(cert) => {
                    let tip = h.chain.lock().unwrap_or_else(|e| e.into_inner()).height;
                    submit_set_change(&h.validators, &h.pending_set_changes, &CERT_VERIFY, &h.chain_id, tip, cert)
                }
                Err(e) => json!({"error": format!("bad cert: {e}")}),
            },
            None => json!({"error": "params.cert required (output of `hk-node set-change assemble`)"}),
        },
        // v0.19.12: the body is `get_mempool` — the txids the pool stored.
        "hk_getMempool" => get_mempool(&h.mempool),
        // v0.19.12: the two block reads below and `hk_getTx` share the block-read slot;
        // the bodies are `get_block` / `get_blocks`.
        "hk_getBlock" => get_block(h.store.as_deref(), &h.receipts, h.chain_start_time, &BLOCK_READ, params),
        "hk_getBlocks" => {
            get_blocks(h.store.as_deref(), &h.chain, h.chain_start_time, &BLOCK_READ, params, BLOCKS_READ_BUDGET)
        }

        other => json!({"error": format!("unknown method: {other}")}),
    }
}

/// `hk_getMempool`: the pending count and the first 100 txids in pool order. v0.19.12: the
/// txids are the ones the pool stored when each tx entered it
/// (`Mempool::pending_ids`); the call copies at most 100 of them and writes them as hex.
/// Same response as before.
fn get_mempool(mempool: &Mutex<Mempool>) -> Value {
    let (count, ids): (usize, Vec<[u8; 32]>) = {
        let mp = mempool.lock().unwrap_or_else(|e| e.into_inner());
        (mp.len(), mp.pending_ids().take(100).copied().collect())
    };
    json!({"result": {
        "count": count,
        "txids": ids.iter().map(hex::encode).collect::<Vec<_>>(),
    }})
}

/// v0.19.12: the answer past the `BLOCK_READ_SLOTS` permits — the `POOL_PATH` wording.
fn block_read_busy() -> Value {
    json!({"error": format!("busy: {BLOCK_READ_SLOTS} block reads already in flight — retry in a moment")})
}

/// `hk_getTx` (v0.11.2; v0.19.12): a txid → its block, index, public summary and
/// receipt, from the node-local index and the block log. The block load and decode hold one
/// `BLOCK_READ_SLOTS` permit (`slots`; "busy — retry" past them), taken only when there is a
/// block to load — an unindexed txid, or a node without a store, answers without one. The block
/// is still decoded whole: bincode cannot skip the txs ahead of the one asked for without
/// decoding them. The summary is built from the tx and its own txid; the receipt is looked
/// up by the txid asked for. Takes the handles it touches so the tests drive it without a node.
fn get_tx(
    store: Option<&crate::store::NodeStore>,
    tx_index: &Mutex<std::collections::HashMap<[u8; 32], (u64, u32)>>,
    receipts: &Mutex<crate::state::ReceiptLog>,
    slots: &tokio::sync::Semaphore,
    params: &Value,
) -> Value {
    let Some(id) = param_h256(params, "txid") else {
        return json!({"error": "txid must be 64-char hex"});
    };
    let hit = tx_index.lock().unwrap_or_else(|e| e.into_inner()).get(&id.0).copied();
    let Some((height, idx)) = hit else {
        return json!({"result": {"found": false}});
    };
    let summary = match store {
        Some(store) => {
            let Ok(_permit) = slots.try_acquire() else {
                return block_read_busy();
            };
            store
                .load_block(height)
                .ok()
                .flatten()
                .and_then(|sb| Batch::decode(&sb.value_bytes))
                .and_then(|b| b.txs.get(idx as usize).map(|t| tx_summary(t, &txid(t))))
        }
        None => None,
    };
    let receipt = receipts.lock().unwrap_or_else(|e| e.into_inner()).get(&id.0).cloned();
    json!({"result": {
        "found": true,
        "txid": hex::encode(id.0),
        "height": height,
        "index": idx,
        "summary": summary,
        "receipt": receipt,
    }})
}

/// One row of the node-local account index: (txid, height, kind) — state.rs `index_txs_into`.
type AcctRow = ([u8; 32], u64, &'static str);

/// `hk_getAccountTxs` (v0.11.2; v0.19.12): an account's history — as sender or
/// counterparty, and since v0.19.12 as the holder a `MandateCreate` names (HR-5) — newest
/// first, `limit` rows (default 25, at most 100) of `total`. One pass over the account's rows
/// keeps the page's rows in a heap of at most `limit` keys (`newest_rows`); the page is then
/// ordered and the JSON built. The answer equals a stable newest-first sort of the whole list
/// cut to `limit`, row for row.
/// Takes the handle it touches so the tests drive it
/// without a node.
fn get_account_txs(
    acct_index: &Mutex<std::collections::HashMap<AccountId, Vec<AcctRow>>>,
    params: &Value,
) -> Value {
    let Some(id) = param_h256(params, "id") else {
        return json!({"error": "id must be 64-char hex"});
    };
    let limit = params
        .get("limit")
        .and_then(|l| l.as_u64())
        .unwrap_or(25)
        .min(100) as usize;
    let (total, mut page) = {
        let ai = acct_index.lock().unwrap_or_else(|e| e.into_inner());
        match ai.get(&id) {
            Some(v) => (v.len(), newest_rows(v, limit)),
            None => (0, Vec::new()),
        }
    };
    // Newest first, and among equal heights in index order — the stable sort's order.
    page.sort_unstable_by(|a, b| b.0.cmp(&a.0));
    let txs: Vec<Value> = page
        .into_iter()
        .map(|(_, (t, ht, kind))| json!({"txid": hex::encode(t), "height": ht, "kind": kind}))
        .collect();
    json!({"result": {"id": hex::encode(id.0), "total": total, "txs": txs}})
}

/// The `limit` newest rows of an account's index list, in no particular order, each with its
/// rank key `(height, Reverse(position))`: a higher height ranks first, and among equal heights
/// the row indexed earlier — exactly the order of a stable newest-first sort by height (R10 v2:
/// the background history pass appends OLD heights after live commits, so the list itself is
/// not in height order). One pass from the end of the list, where live commits append in
/// height order — so the page usually fills from the last `limit` rows and every earlier row
/// costs one compare — keeping at most `limit` keys in a heap; nothing else is copied.
fn newest_rows(rows: &[AcctRow], limit: usize) -> Vec<((u64, std::cmp::Reverse<usize>), AcctRow)> {
    use std::cmp::Reverse;
    if limit == 0 {
        return Vec::new();
    }
    let mut heap: std::collections::BinaryHeap<Reverse<(u64, Reverse<usize>)>> =
        std::collections::BinaryHeap::with_capacity(limit.saturating_add(1));
    for (i, row) in rows.iter().enumerate().rev() {
        let key = (row.1, Reverse(i));
        if heap.len() < limit {
            heap.push(Reverse(key));
        } else if heap.peek().is_some_and(|Reverse(min)| key > *min) {
            heap.pop();
            heap.push(Reverse(key));
        }
    }
    heap.into_iter().map(|Reverse(key)| (key, rows[(key.1).0])).collect()
}

/// `hk_getBlock` (P3.0b; v0.19.12): one stored block with its txs' public summaries and
/// receipts. The load, the decode and the answer hold one `BLOCK_READ_SLOTS` permit (`slots`;
/// "busy — retry" past them). Each tx's txid serves both its summary and its receipt
/// lookup; the receipts are looked up in one pass, before any JSON is built.
/// Takes the handles it touches so the tests drive it
/// without a node.
fn get_block(
    store: Option<&crate::store::NodeStore>,
    receipts: &Mutex<crate::state::ReceiptLog>,
    chain_start_time: u64,
    slots: &tokio::sync::Semaphore,
    params: &Value,
) -> Value {
    let Some(store) = store else {
        return json!({"error": "persistence disabled on this node (HK_NO_PERSIST)"});
    };
    let Some(height) = params.get("height").and_then(|v| v.as_u64()) else {
        return json!({"error": "height (number) required"});
    };
    let Ok(_permit) = slots.try_acquire() else {
        return block_read_busy();
    };
    let sb = match store.load_block(height) {
        Ok(Some(sb)) => sb,
        Ok(None) => return json!({"result": {"found": false}}),
        Err(e) => {
            warn!(height, %e, "block load failed");
            return json!({"error": "block load failed (see node log)"});
        }
    };
    let batch = Batch::decode(&sb.value_bytes);
    let block_txs: &[SignedTx] = batch.as_ref().map(|b| b.txs.as_slice()).unwrap_or(&[]);
    // every txid once …
    let ids: Vec<[u8; 32]> = block_txs.iter().map(txid).collect();
    // … each receipt looked up by it …
    let found: Vec<Option<String>> = {
        let rlog = receipts.lock().unwrap_or_else(|e| e.into_inner());
        ids.iter().map(|id| rlog.get(id).cloned()).collect()
    };
    // … and the JSON built from both.
    let txs: Vec<Value> = block_txs
        .iter()
        .zip(ids.iter().zip(found))
        .map(|(stx, (id, receipt))| {
            let mut v = tx_summary(stx, id);
            v["receipt"] = match receipt {
                Some(d) => {
                    let ok = d.starts_with("ok");
                    json!({"found": true, "ok": ok, "detail": d})
                }
                None => json!({"found": false}),
            };
            v
        })
        .collect();
    json!({"result": {
        "found": true,
        "height": sb.height,
        "time": chain_start_time + sb.height,
        "parent_app_hash": batch.as_ref().map(|b| hex::encode(b.parent_app_hash)),
        "tx_count": txs.len(),
        "txs": txs,
        "aggregate": {
            "present": batch.as_ref().map(|b| !b.agg_proof.is_empty()).unwrap_or(false),
            "verified": sb.agg_valid,
        },
        "rotations": batch.as_ref().map(|b| b.rotations.len()).unwrap_or(0),
        // v0.15.2: validator-set change certificates carried by this block
        // (V1) — the explorer surface could not show the block that seated
        // testnet-1's first external validator (72219) until this existed.
        "set_changes": batch.as_ref().map(|b| b.set_changes.iter().map(|c| {
            let (kind, root_pk, power) = match &c.body.change {
                hk_consensus::SetChange::Admit { root_pk, voting_power, .. } =>
                    ("admit", hex::encode(root_pk), Some(*voting_power)),
                hk_consensus::SetChange::Remove { root_pk } =>
                    ("remove", hex::encode(root_pk), None),
                hk_consensus::SetChange::SetPower { root_pk, voting_power } =>
                    ("set_power", hex::encode(root_pk), Some(*voting_power)),
            };
            json!({"change": kind, "root_pk": root_pk, "voting_power": power,
                   "approvals": c.approvals.len(),
                   "not_before": c.body.not_before, "not_after": c.body.not_after})
        }).collect::<Vec<_>>()).unwrap_or_default(),
        "certificate": {
            "round": sb.certificate.round.as_i64(),
            "value_id": hex::encode(sb.certificate.value_id.as_bytes()),
            "signatures": sb.certificate.commit_signatures.len(),
        },
    }})
}

/// `hk_getBlocks` (P3.0b, R10 v2; v0.19.12): newest-first block summaries, walking down
/// from `before − 1` (default: the tip) over the gap-free disk suffix, at most `limit` (≤ 50).
/// The walk holds one `BLOCK_READ_SLOTS` permit (`slots`; "busy — retry" past them) and stops
/// once it has loaded `budget` bytes of stored blocks (`BLOCKS_READ_BUDGET` from `dispatch`;
/// checked before each load, so at most that plus one block). The answer then adds
/// `truncated: true` and `next_before` — the `before` of the call that continues, the same
/// value a caller paging by the lowest height it received computes. A page inside the budget
/// has the pre-v0.19.12 shape exactly. Takes the handles it touches so the tests drive it
/// without a node.
fn get_blocks(
    store: Option<&crate::store::NodeStore>,
    chain: &Mutex<hk_state::State>,
    chain_start_time: u64,
    slots: &tokio::sync::Semaphore,
    params: &Value,
    budget: usize,
) -> Value {
    let Some(store) = store else {
        return json!({"error": "persistence disabled on this node (HK_NO_PERSIST)"});
    };
    let before = params.get("before").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
    let limit = params
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(20)
        .min(50) as usize;
    let Ok(_permit) = slots.try_acquire() else {
        return block_read_busy();
    };
    // R10 v2: walk DOWN from the chain tip over the gap-free disk suffix —
    // no per-call directory listing (that was a 100k-entry scan on every
    // explorer poll). `earliest` is the suffix floor restore measured.
    let latest = chain.lock().unwrap_or_else(|e| e.into_inner()).height;
    let earliest = store.disk_min();
    let (earliest_v, latest_v) = if earliest == 0 || earliest > latest {
        (Value::Null, Value::Null)
    } else {
        (json!(earliest), json!(latest))
    };
    let mut blocks = Vec::with_capacity(limit);
    let mut loaded: usize = 0;
    let mut next_before: Option<u64> = None;
    let mut hgt = before.saturating_sub(1).min(latest);
    let floor = earliest.max(1);
    while blocks.len() < limit && earliest != 0 && hgt >= floor {
        // The byte budget, before the next load.
        if loaded >= budget {
            next_before = Some(hgt.saturating_add(1));
            break;
        }
        if let Ok(Some(sb)) = store.load_block(hgt) {
            loaded = loaded.saturating_add(sb.value_bytes.len());
            let batch = Batch::decode(&sb.value_bytes);
            blocks.push(json!({
                "height": sb.height,
                "time": chain_start_time + sb.height,
                "tx_count": batch.as_ref().map(|b| b.txs.len()).unwrap_or(0),
                "aggregate": batch.as_ref().map(|b| !b.agg_proof.is_empty()).unwrap_or(false),
                "rotations": batch.as_ref().map(|b| b.rotations.len()).unwrap_or(0),
                "set_changes": batch.as_ref().map(|b| b.set_changes.len()).unwrap_or(0),
                "value_id": hex::encode(&sb.certificate.value_id.as_bytes()[..8]),
            }));
        }
        if hgt == 0 {
            break;
        }
        hgt -= 1;
    }
    let mut result = json!({"blocks": blocks, "earliest": earliest_v, "latest": latest_v});
    if let Some(next) = next_before {
        result["truncated"] = json!(true);
        result["next_before"] = json!(next);
    }
    json!({"result": result})
}

/// v0.19.12: `s` cut to at most `max` bytes, on a character boundary.
fn str_prefix(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Public per-tx summary for the explorer: kind + the tx's PUBLIC fields only. What's
/// listed here is already on-chain in the clear (the transparent skeleton); shielded
/// txs surface commitments/nullifiers/fee — NEVER amounts, senders, or recipients.
///
/// v0.19.12: `id` is the tx's txid, passed in by the caller (`get_block` looks the tx's
/// receipt up by the same id). The two variable-length fields shown —
/// `AssetRegister.symbol` and `AssetBurn.destination` — are cut to `SUMMARY_SYMBOL_SHOWN` /
/// `SUMMARY_DESTINATION_SHOWN` bytes, and a cut one is followed by `symbol_len` /
/// `destination_len` (the real length) and `truncated: true`. A value inside its bound —
/// every value the chain accepts — is shown exactly as before, with no new key, so the
/// explorer and the bridge attestor (attest.rs reads `fields.destination`) see no change for
/// an accepted tx. No other field shown here has a variable length (proofs and stealth
/// ciphertexts are not shown).
fn tx_summary(stx: &SignedTx, id: &[u8; 32]) -> Value {
    use hk_state::tx::Tx;
    let (kind, fields) = match &stx.payload {
        Tx::Transfer { to, asset, amount } => ("transfer", json!({
            "to": hex::encode(to.0), "asset": hex::encode(asset.0),
            "amount": amount.to_string(),
        })),
        Tx::MandateCreate { id, parent, holder, .. } => ("mandate_create", json!({
            "id": hex::encode(id.0),
            "parent": parent.map(|p| hex::encode(p.0)),
            "holder": hex::encode(holder.0),
        })),
        Tx::MandateSpend { leaf, to, amount } => ("mandate_spend", json!({
            "leaf": hex::encode(leaf.0), "to": hex::encode(to.0),
            "amount": amount.to_string(),
        })),
        Tx::MandateRevoke { target } => ("mandate_revoke", json!({
            "target": hex::encode(target.0),
        })),
        Tx::ChannelOpen { id, payee, unit_price, max_steps, .. } => ("channel_open", json!({
            "id": hex::encode(id.0), "payee": hex::encode(payee.0),
            "unit_price": unit_price.to_string(), "max_steps": max_steps,
        })),
        Tx::ChannelSettle { id, step, .. } => ("channel_settle", json!({
            "id": hex::encode(id.0), "step": step,
        })),
        Tx::ChannelRefund { id } => ("channel_refund", json!({
            "id": hex::encode(id.0),
        })),
        Tx::MintToPool { value, commitment, proof, .. } => ("shield", json!({
            "value": value.to_string(), "commitment": hex::encode(commitment.0),
            "via_aggregate": proof.is_empty(),
        })),
        Tx::ShieldedSpend { nullifier, fee, credit, mandate, proof, .. } => ("shielded_spend", json!({
            "nullifier": hex::encode(nullifier.0), "fee": fee.to_string(),
            "credit": credit.map(|c| hex::encode(c.0)),
            "mandate": mandate.map(|m| hex::encode(m.0)),
            "via_aggregate": proof.is_empty(),
        })),
        // U1: runtime account creation (the faucet flow) — visible in the explorer.
        Tx::AccountCreate { id, asset, amount, .. } => ("account_create", json!({
            "id": hex::encode(id.0), "asset": hex::encode(asset.0), "amount": amount.to_string(),
        })),
        // X1: issued assets — the five issuer verbs, all public by construction.
        Tx::AssetRegister { asset, symbol, decimals, policy } => {
            let mut f = json!({
                "asset": hex::encode(asset.0), "symbol": str_prefix(symbol, SUMMARY_SYMBOL_SHOWN),
                "decimals": decimals, "policy": policy.flags(),
            });
            if symbol.len() > SUMMARY_SYMBOL_SHOWN {
                f["symbol_len"] = json!(symbol.len());
                f["truncated"] = json!(true);
            }
            ("asset_register", f)
        }
        Tx::AssetMint { asset, to, amount } => ("asset_mint", json!({
            "asset": hex::encode(asset.0), "to": hex::encode(to.0), "amount": amount.to_string(),
        })),
        Tx::AssetBurn { asset, amount, destination } => {
            let shown = &destination[..destination.len().min(SUMMARY_DESTINATION_SHOWN)];
            let mut f = json!({
                "asset": hex::encode(asset.0), "amount": amount.to_string(),
                "destination": hex::encode(shown),
            });
            if destination.len() > SUMMARY_DESTINATION_SHOWN {
                f["destination_len"] = json!(destination.len());
                f["truncated"] = json!(true);
            }
            ("asset_burn", f)
        }
        Tx::AssetFreeze { asset, account, frozen } => ("asset_freeze", json!({
            "asset": hex::encode(asset.0), "account": hex::encode(account.0), "frozen": frozen,
        })),
        Tx::AssetPause { asset, paused } => ("asset_pause", json!({
            "asset": hex::encode(asset.0), "paused": paused,
        })),
    };
    json!({
        "txid": hex::encode(id),
        "sender": hex::encode(stx.sender.0),
        "nonce": stx.nonce,
        "kind": kind,
        "fields": fields,
    })
}

/// X1: one registry entry as the explorer/wallet sees it, with the conservation
/// receipt (`held` must equal `issued` on every honest node — invariant I5'). HR-4
/// (v0.19.12): the `(held, issued)` pair is the caller's — `hk_getAsset` computes one,
/// `hk_getAssets` takes a page's worth from a single `asset_conservation_all` pass.
fn asset_json(id: &H256, info: &hk_state::assets::AssetInfo, chain: &hk_state::State, conserved: (Amount, Amount)) -> Value {
    let (held, issued) = conserved;
    json!({
        "asset": hex::encode(id.0),
        "symbol": info.symbol,
        "decimals": info.decimals,
        "issuer": hex::encode(info.issuer.0),
        "policy": {
            "flags": info.policy.flags(),
            "mintable": info.policy.mintable,
            "freezable": info.policy.freezable,
            "pausable": info.policy.pausable,
            "pool_eligible": info.policy.pool_eligible,
        },
        "supply": info.supply.to_string(),
        "burned": info.burned.to_string(),
        "circulating": issued.to_string(),
        "held": held.to_string(),
        "conserved": held == issued,
        "paused": info.paused,
        "frozen_count": info.frozen.len(),
        "registered_at": info.registered_at,
        // P6: this asset's shielded ledger across every pool that denominates it.
        "shielded": chain.shielded_of(id).to_string(),
    })
}

/// `(from, to, limit, next)` for a page of the asset registry (HR-4, v0.19.12): `from`
/// clamped to `total`, `limit` defaulted and capped at `ASSET_PAGE_MAX` (never zero), `next`
/// the index after this page or `None` once the page reached the end — the H3 paging
/// contract of the pool feed, with the effective `limit` echoed.
fn asset_page(params: &Value, total: usize) -> (usize, usize, usize, Option<usize>) {
    let from = params.get("from").and_then(|v| v.as_u64()).unwrap_or(0).min(total as u64) as usize;
    let limit = params
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|l| usize::try_from(l).unwrap_or(ASSET_PAGE_MAX).clamp(1, ASSET_PAGE_MAX))
        .unwrap_or(ASSET_PAGE_MAX);
    let to = from.saturating_add(limit).min(total);
    let next = (to < total).then_some(to);
    (from, to, limit, next)
}

/// `hk_getAsset` (X1; v0.19.12, HR-4 review): one registry entry with its conservation receipt.
/// The receipt is a scan of every balance and every channel under the chain lock — the lock the
/// commit path needs — so the call holds the one `ASSET_SCAN` slot `hk_getAssets` holds
/// (`try_acquire`; a caller past it is told to retry, in `get_assets`' words, and never queues on
/// the lock). The id is parsed (and, for `issuer` + `symbol`, derived — one SHAKE) before the
/// slot and the lock; a missing id needs neither. Same response as before. Takes the handles it
/// touches so the tests drive it without a node.
fn get_asset(chain: &Mutex<hk_state::State>, slots: &tokio::sync::Semaphore, params: &Value) -> Value {
    let id = match param_h256(params, "asset") {
        Some(a) => Some(a),
        None => match (param_h256(params, "issuer"), params.get("symbol").and_then(|v| v.as_str())) {
            (Some(issuer), Some(sym)) => Some(hk_state::assets::derive_asset_id(&issuer, sym)),
            _ => None,
        },
    };
    let Some(id) = id else {
        return json!({"error": "asset (64-char hex) or issuer (64-char hex) + symbol required"});
    };
    let Ok(_permit) = slots.try_acquire() else {
        return json!({"error": "busy: an asset registry scan is already in flight — retry in a moment"});
    };
    let chain = chain.lock().unwrap_or_else(|e| e.into_inner());
    match chain.assets.get(&id) {
        Some(info) => {
            let conserved = chain.asset_conservation(&id).unwrap_or((0, 0));
            json!({"result": {"found": true, "asset": asset_json(&id, info, &chain, conserved)}})
        }
        None => json!({"result": {"found": false, "asset_id": hex::encode(id.0)}}),
    }
}

/// `hk_getAssets` (HR-4, v0.19.12): one page of the registry. The call holds the one
/// `ASSET_SCAN` slot (`try_acquire` — a caller past it is told to retry and never queues on
/// the chain lock), takes the chain lock once, computes the conservation receipts of the
/// WHOLE registry in one pass (`asset_conservation_all`: a walk of balances and a walk of
/// channels, not one per asset) and renders the page. `count` stays the whole registry's
/// size — the field the gates and the explorer read — alongside `total`; `assets[]` is the
/// page. A registry under the cap answers in one page, shape as before plus the paging
/// fields. Takes the handles it touches so the tests can drive it without a node.
fn get_assets(chain: &Mutex<hk_state::State>, slots: &tokio::sync::Semaphore, params: &Value) -> Value {
    let Ok(_permit) = slots.try_acquire() else {
        return json!({"error": "busy: an asset registry scan is already in flight — retry in a moment"});
    };
    let chain = chain.lock().unwrap_or_else(|e| e.into_inner());
    let total = chain.assets.len();
    let (from, to, limit, next) = asset_page(params, total);
    let conserved = if to > from { chain.asset_conservation_all() } else { BTreeMap::new() };
    let list: Vec<Value> = chain
        .assets
        .iter()
        .skip(from)
        .take(to - from)
        .map(|(id, info)| asset_json(id, info, &chain, conserved.get(id).copied().unwrap_or((0, 0))))
        .collect();
    json!({"result": {
        "count": total,
        "total": total,
        "from": from,
        "limit": limit,
        "next": next,
        "fee_asset": hex::encode(chain.fee_asset.0),
        "assets": list,
    }})
}

/// X1: every non-zero transparent balance `id` holds, by asset, with the asset's symbol
/// (when registered) and whether the issuer froze this account in it.
fn account_balances_json(chain: &hk_state::State, id: &H256) -> Vec<Value> {
    chain
        .balances
        .range((*id, H256([0u8; 32]))..=(*id, H256([0xffu8; 32])))
        .filter(|(_, amt)| **amt > 0)
        .map(|((_, asset), amt)| {
            json!({
                "asset": hex::encode(asset.0),
                "symbol": chain.assets.get(asset).map(|i| i.symbol.clone()),
                "amount": amt.to_string(),
                "frozen": chain.assets.get(asset).map(|i| i.frozen.contains(id)).unwrap_or(false),
            })
        })
        .collect()
}

/// `hk_getAccount`. HR-9 (v0.19.12): the chain credits any 32-byte id — `Transfer`,
/// `AssetMint`, `MandateSpend`, an unshield and a channel's payee never check that an
/// account exists — so a credit to a never-created id sits as a balance nobody can spend until
/// an `AccountCreate` with the auth commitment the id derives from binds it (never, for a
/// mistyped id). This method answers `balances[]` for the id either way, so such a balance is
/// visible (`found`, `nonce` and
/// `auth_commit` keep their meaning: `false` / `null` when no account exists). Takes the
/// chain handle so the tests can drive it without a node.
fn get_account(chain: &Mutex<hk_state::State>, params: &Value) -> Value {
    let Some(id) = param_h256(params, "id") else {
        return json!({"error": "id must be 64-char hex"});
    };
    let chain = chain.lock().unwrap_or_else(|e| e.into_inner());
    // X1: every transparent balance this id holds, by asset (a wallet must show two
    // balances once issued assets exist).
    let balances = account_balances_json(&chain, &id);
    match chain.accounts.get(&id) {
        Some(acc) => json!({"result": {
            "found": true,
            "nonce": acc.nonce,
            "auth_commit": hex::encode(acc.auth_commit.0),
            "balances": balances,
        }}),
        None => json!({"result": {
            "found": false,
            "nonce": Value::Null,
            "auth_commit": Value::Null,
            "balances": balances,
        }}),
    }
}

/// `hk_getMandate` (HR-5, v0.19.12): one mandate node as the chain holds it. `holder` spends
/// from the node, opens channels and creates children under it, and revokes its children (a
/// root's holder also revokes the root); `funder` is `root_funding` of the node's root — the
/// account the spends draw on. For a root the two need not be the same account: a root's
/// holder is whatever its `MandateCreate` named, the sender became the funder, and the funder
/// has no verb over such a root (a funder-side revoke is a planned consensus change) — this
/// view shows both so a funder can see what it signed. Lookups only, under the chain lock.
/// Takes the chain handle so the tests can drive it without a node.
fn get_mandate(chain: &Mutex<hk_state::State>, params: &Value) -> Value {
    let Some(id) = param_h256(params, "id") else {
        return json!({"error": "id must be 64-char hex"});
    };
    let chain = chain.lock().unwrap_or_else(|e| e.into_inner());
    let Some(node) = chain.mandates.get(&id) else {
        return json!({"result": {"found": false}});
    };
    let root = chain.mandates.root_of(&id).unwrap_or(id);
    json!({"result": {
        "found": true,
        "id": hex::encode(id.0),
        "parent": node.parent.map(|p| hex::encode(p.0)),
        "root": hex::encode(root.0),
        "holder": hex::encode(&node.holder_key),
        "funder": chain.root_funding.get(&root).map(|f| hex::encode(f.0)),
        "asset": hex::encode(node.asset.0),
        "rate_per_sec": node.rate_per_sec.to_string(),
        "buffer_max": node.buffer_max.to_string(),
        "per_tx_max": node.per_tx_max.to_string(),
        "buffer": node.buffer.to_string(),
        "last_accrual": node.last_accrual,
        "expiry": node.expiry,
        "tier": node.tier,
        "revoked": node.revoked,
    }})
}

/// P6: the pool an RPC call addresses — `asset` (64-hex) names a per-asset pool, or the
/// legacy pool when it is that pool's pinned asset; absent = the legacy pool.
fn pool_key_param(params: &Value, chain: &hk_state::State) -> Result<hk_state::PoolKey, String> {
    match params.get("asset") {
        None | Some(Value::Null) => Ok(hk_state::PoolKey::Legacy),
        Some(_) => match param_h256(params, "asset") {
            None => Err("asset must be 64-char hex".into()),
            Some(a) => {
                if chain.pool.asset == Some(a) {
                    Ok(hk_state::PoolKey::Legacy)
                } else {
                    Ok(hk_state::PoolKey::Asset(a))
                }
            }
        },
    }
}

/// P6: one pool's public view.
fn pool_json(key: hk_state::PoolKey, p: &hk_state::pool::PoolState) -> Value {
    json!({
        "legacy": matches!(key, hk_state::PoolKey::Legacy),
        "version": p.version,
        "asset": p.asset.map(|a| hex::encode(a.0)),
        "root": hex::encode(p.tree.root()),
        "latest_anchor": p.latest_anchor().map(hex::encode),
        "next_index": p.tree.next_index(),
        "nullifiers": p.nullifiers.len(),
        "total_shielded": p.total_shielded.to_string(),
    })
}

/// One pool's note feed as the node indexes it: (commitment, stealth ciphertext) in leaf
/// order (`SharedHandles::pool_notes` / `pool_notes_by_asset`).
type PoolFeed = Vec<(H256, Vec<u8>)>;

/// L-5 (R17, reported 2026-10-06): run `f` over the leaf feed an RPC call addresses, UNDER
/// that feed's lock, and return what it produced + the asset label (`None` = the legacy
/// pool; the answer's `asset`). `f` decides what gets copied out — a page, or the bare
/// 32-byte leaves — so the lock is held for one bounded copy, never for a clone of the
/// whole feed (what v0.19.0's `pool_feed` did, ciphertexts included: ≈1.2 KB × every note,
/// per call, while the commit path waits on this lock with the chain lock held).
/// An `asset` that is the legacy pool's pinned asset reads the legacy feed; an asset
/// without a pool yet reads an empty feed (a scanner sees `total: 0`).
/// Lock order: chain (released) → the one feed lock; never both at once.
fn with_pool_feed<R>(
    chain: &Mutex<hk_state::State>,
    legacy: &Mutex<PoolFeed>,
    by_asset: &Mutex<BTreeMap<AssetId, PoolFeed>>,
    params: &Value,
    f: impl FnOnce(&[(H256, Vec<u8>)]) -> R,
) -> Result<(R, Option<String>), String> {
    let key = {
        let chain = chain.lock().unwrap_or_else(|e| e.into_inner());
        pool_key_param(params, &chain)?
    };
    match key {
        PoolKey::Legacy => {
            let notes = legacy.lock().unwrap_or_else(|e| e.into_inner());
            Ok((f(notes.as_slice()), None))
        }
        PoolKey::Asset(a) => {
            let by = by_asset.lock().unwrap_or_else(|e| e.into_inner());
            let feed = by.get(&a).map(Vec::as_slice).unwrap_or(&[]);
            Ok((f(feed), Some(hex::encode(a.0))))
        }
    }
}

/// `hk_getPoolPath` (H3 + L-5): one leaf's authentication path (siblings bottom → top) and
/// the root it folds to, from the pool's full leaf list. The 32-byte leaves are copied
/// under the feed lock, the tree is built outside it, and the whole call holds one of
/// `slots` (`POOL_PATH_SLOTS`) — `try_acquire`, so a caller past the bound gets a "busy —
/// retry" error and never queues on the lock the commit path needs. Takes the handles it
/// touches so `r17_tests` can drive it without a node; `dispatch` only routes to it.
fn pool_path(
    chain: &Mutex<hk_state::State>,
    legacy: &Mutex<PoolFeed>,
    by_asset: &Mutex<BTreeMap<AssetId, PoolFeed>>,
    slots: &tokio::sync::Semaphore,
    params: &Value,
) -> Value {
    let Some(index) = params.get("index").and_then(|v| v.as_u64()) else {
        return json!({"error": "index (leaf index, integer) required"});
    };
    let Ok(_permit) = slots.try_acquire() else {
        return json!({"error": format!(
            "busy: {POOL_PATH_SLOTS} pool-path builds already in flight — retry in a moment"
        )});
    };
    match with_pool_feed(chain, legacy, by_asset, params, |feed| feed.iter().map(|(l, _)| l.0).collect::<Vec<[u8; 32]>>()) {
        Err(e) => json!({"error": e}),
        Ok((leaves, asset)) => {
            if (index as usize) >= leaves.len() {
                json!({"error": format!("index {index} out of range (pool has {} commitments)", leaves.len())})
            } else {
                let (siblings, root) = hk_state::pool::full_tree_path(&leaves, index);
                json!({"result": {
                    "asset": asset,
                    "index": index,
                    "commitment": hex::encode(leaves[index as usize]),
                    "siblings": siblings.iter().map(hex::encode).collect::<Vec<_>>(),
                    "root": hex::encode(root),
                    "total": leaves.len(),
                }})
            }
        }
    }
}

/// One page of a pool feed, cut under the lock (L-5): `items` is `feed[from..to]` through
/// the arm's projection, `total` the feed's length, `next` the following page's `from`
/// (`None` once this page reached the end) — the H3 paging contract, unchanged.
#[derive(Debug)]
struct PoolPage<T> {
    from: usize,
    to: usize,
    total: usize,
    next: Option<usize>,
    items: Vec<T>,
}

/// `params`'s page of `feed` (`pool_page` arithmetic), each item through `project` — the
/// only copy a paged pool read makes.
fn page_of<T>(feed: &[(H256, Vec<u8>)], params: &Value, project: impl Fn(&(H256, Vec<u8>)) -> T) -> PoolPage<T> {
    let (from, to, next) = pool_page(params, feed.len());
    PoolPage { from, to, total: feed.len(), next, items: feed[from..to].iter().map(project).collect() }
}

fn param_h256(params: &Value, key: &str) -> Option<H256> {
    let s = params.get(key)?.as_str()?;
    let bytes = hex::decode(s).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(H256(arr))
}

/// H3 (v0.16.1): the largest page the pool feed answers in one call. A page of notes is
/// ~2.4 KB each (ML-KEM ciphertext + sealed note as hex), so this is ≈ 24 MB worst case —
/// bounded on the node whatever the pool grows to; wallets page with `next`.
pub(crate) const POOL_PAGE_MAX: usize = 10_000;

/// `(from, to, next)` for a paged read of `total` items: `from` clamped to `total`,
/// `limit` defaulted and capped at `POOL_PAGE_MAX`, `next` = the index after this page or
/// `None` when the page reached the end.
fn pool_page(params: &Value, total: usize) -> (usize, usize, Option<usize>) {
    let from = params.get("from").and_then(|v| v.as_u64()).unwrap_or(0).min(total as u64) as usize;
    let limit = params
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|l| (l as usize).clamp(1, POOL_PAGE_MAX))
        .unwrap_or(POOL_PAGE_MAX);
    let to = from.saturating_add(limit).min(total);
    let next = (to < total).then_some(to);
    (from, to, next)
}

// ---- L-6 (R17, reported 2026-10-06): the operator submits ------------------------------
//
// Both handlers follow one shape: (1) snapshot the validator set — an `Arc` clone — and
// DROP its lock; (2) every free refusal, under the queue's lock only, via a `*_preflight`
// that also answers "already queued"; (3) one of CERT_VERIFY_SLOTS or `busy_error`;
// (4) the SLH-DSA verify on the snapshot, no lock held; (5) re-lock, re-run the free
// checks (the set or the queue may have moved under the verify), then queue. The bodies
// take the handles they touch rather than `SharedHandles` so `r17_tests` can drive them
// without a node; `dispatch` only parses `params.cert` around them.

/// What a free pre-check says about a submitted certificate.
enum Preflight {
    /// Every free check passed — spend a verify slot on it.
    Verify,
    /// An equivalent certificate is already queued; that copy was verified when it was
    /// queued and already rides the next proposal, so the submitted bytes change nothing
    /// and are not verified (a flood of re-submits costs the node a few compares).
    AlreadyQueued,
}

fn busy_error() -> Value {
    json!({"error": format!(
        "busy: {CERT_VERIFY_SLOTS} root-signature verifications already in flight — retry in a moment"
    )})
}

fn refused(reason: String) -> Value {
    json!({"result": {"accepted": false, "reason": reason}})
}

/// R17: an activation height as `hk_chainInfo` reports it — `null` for never (`u64::MAX`).
fn activation_height(h: u64) -> Option<u64> {
    (h != u64::MAX).then_some(h)
}

/// The free checks of `hk_submitRotation`, in the order they refuse: the cert's root must
/// be a seated validator's; its epoch must be strictly newer than that seat's (epochs are
/// monotone — a replay or rollback is stale); L-2: under the v2 rule its
/// `valid_from_height` must sit inside the freshness window (`RotationCert::check_window`
/// — a u64 compare, nothing signed); the signature must be the one size SLH-DSA-192s
/// produces (anything else cannot verify, so it never reaches the verifier); and no cert
/// for that root at this epoch or newer may already be queued. Nothing here costs more than
/// a 48-byte compare per seat. `apply_rotation` repeats the first three (cheaply) in front
/// of the signature — this is the gate in front of it. The chain-id binding of L-2 is the
/// v2 signature domain itself (the cert carries no chain-id field), so it is the verify.
fn rotation_preflight(
    set: &HkValidatorSet,
    queue: &[RotationCert],
    rules: &RotationRules<'_>,
    cert: &RotationCert,
) -> Result<Preflight, String> {
    let seat = set
        .iter()
        .find(|v| v.root_pk == cert.root_pk)
        .ok_or_else(|| "rotation cert: no validator with that root identity".to_string())?;
    if cert.epoch <= seat.epoch {
        return Err(format!("rotation cert: stale (cert epoch {}, current {})", cert.epoch, seat.epoch));
    }
    cert.check_window(rules)?;
    if cert.root_sig.len() != ROOT_SIG_LEN {
        return Err(format!(
            "rotation cert: root_sig must be {ROOT_SIG_LEN} bytes (SLH-DSA-192s), got {}",
            cert.root_sig.len()
        ));
    }
    if queue.iter().any(|x| x.root_pk == cert.root_pk && x.epoch >= cert.epoch) {
        return Ok(Preflight::AlreadyQueued);
    }
    Ok(Preflight::Verify)
}

fn rotation_accepted(cert: &RotationCert, queued: bool) -> Value {
    json!({"result": {"accepted": true, "epoch": cert.epoch, "queued": queued,
        "note": if queued {
            "cert rides this node's next proposal"
        } else {
            "a cert for that root at this epoch or newer is already queued — it rides this node's next proposal"
        }}})
}

/// `hk_submitRotation` (R2 + L-6 + L-2): queue a foreign validator's root-signed rotation
/// cert for this node's next proposal, judged by `rules` (the chain's rotation rule at
/// tip + 1). Responses: `{accepted: true, epoch, queued, note}` for a verified or
/// already-queued cert (the v0.19.4 shape), `{accepted: false, reason}` for a refused one,
/// `{error}` when every verify slot is busy.
fn submit_rotation(
    validators: &Mutex<HkValidatorSet>,
    queue: &Mutex<Vec<RotationCert>>,
    slots: &tokio::sync::Semaphore,
    rules: &RotationRules<'_>,
    cert: RotationCert,
) -> Value {
    let set = validators.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let gate = {
        let q = queue.lock().unwrap_or_else(|e| e.into_inner());
        rotation_preflight(&set, &q, rules, &cert)
    };
    match gate {
        Err(reason) => return refused(reason),
        Ok(Preflight::AlreadyQueued) => return rotation_accepted(&cert, false),
        Ok(Preflight::Verify) => {}
    }
    let Ok(permit) = slots.try_acquire() else {
        return busy_error();
    };
    // The expensive part — on the snapshot, no lock held. `apply_rotation` is the exact
    // check propose and commit run; its `Err` text is what callers saw before R17.
    if let Err(reason) = set.apply_rotation(&cert, rules) {
        return refused(reason);
    }
    drop(permit);
    let set = validators.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
    match rotation_preflight(&set, &q, rules, &cert) {
        Err(reason) => refused(reason),
        Ok(Preflight::AlreadyQueued) => rotation_accepted(&cert, false),
        Ok(Preflight::Verify) => {
            // A newer cert for the same root retires any older queued copy (R9: never
            // stack beside the entry that wedged us).
            q.retain(|x| !(x.root_pk == cert.root_pk && x.epoch < cert.epoch));
            q.push(cert.clone());
            rotation_accepted(&cert, true)
        }
    }
}

/// The free checks of `hk_submitSetChange`, in the order they refuse: body shape (window
/// ordered, key sizes, power ≥ 1), chain id, window against the tip (closed, or opening
/// past SET_CHANGE_HORIZON), approvals present / well-sized / distinct / from seated roots
/// / strictly more than ⅔ of the current power (exactly as `verify_against` counts, minus
/// the signatures), the subject as commit would judge it against the set as it stands (a
/// change that is already applied would only be queued and dropped at the next propose —
/// refuse it here with the reason instead), and the pending-queue dedup. The reason texts
/// match `verify_against` / `apply_set_change` where the check is the same one.
fn set_change_preflight(
    set: &HkValidatorSet,
    queue: &[SetChangeCert],
    chain_id: &str,
    tip: u64,
    cert: &SetChangeCert,
) -> Result<Preflight, String> {
    let body = &cert.body;
    body.check_shape()?;
    if body.chain_id != chain_id {
        return Err(format!("set change: for chain {} — this is {chain_id}", body.chain_id));
    }
    if body.not_after < tip {
        return Err(format!("window closed: not_after {} < tip {tip}", body.not_after));
    }
    if body.not_before > tip.saturating_add(SET_CHANGE_HORIZON) {
        return Err(format!(
            "window too far ahead: not_before {} > tip {tip} + {SET_CHANGE_HORIZON} — assemble it closer to its window",
            body.not_before
        ));
    }
    if cert.approvals.is_empty() {
        return Err("set change: no approvals".into());
    }
    let total = set.total_voting_power();
    let mut approving: u64 = 0;
    let mut seen: Vec<&[u8]> = Vec::with_capacity(cert.approvals.len());
    for a in &cert.approvals {
        if a.root_pk.len() != ROOT_PK_LEN || a.root_sig.len() != ROOT_SIG_LEN {
            return Err(format!(
                "set change: an approval must be a {ROOT_PK_LEN}-byte root + {ROOT_SIG_LEN}-byte SLH-DSA-192s signature"
            ));
        }
        if seen.iter().any(|s| *s == a.root_pk.as_slice()) {
            return Err("set change: duplicate approval from one root".into());
        }
        let seat = set
            .iter()
            .find(|v| v.root_pk == a.root_pk)
            .ok_or_else(|| "set change: approval from a root that is not seated".to_string())?;
        seen.push(&a.root_pk);
        approving = approving.saturating_add(seat.voting_power);
    }
    if approving.saturating_mul(3) <= total.saturating_mul(2) {
        return Err(format!("set change: approving power {approving} is not > 2/3 of {total}"));
    }
    let seated = |root: &[u8]| set.iter().find(|v| v.root_pk == root);
    match &body.change {
        SetChange::Admit { root_pk, public_key, .. } => {
            if seated(root_pk).is_some() {
                return Err("set change: already applied — that root is seated".into());
            }
            let addr = HkAddress::from_public_key(public_key);
            if set.iter().any(|v| v.address == addr) {
                return Err("set change: operational key collides with a seated address".into());
            }
        }
        SetChange::Remove { root_pk } => {
            if seated(root_pk).is_none() {
                return Err("set change: already applied — that root is not seated".into());
            }
            if set.len() == 1 {
                return Err("set change: refusing to remove the last seat".into());
            }
        }
        SetChange::SetPower { root_pk, voting_power } => match seated(root_pk) {
            None => return Err("set change: set-power for a root that is not seated".into()),
            Some(v) if v.voting_power == *voting_power => {
                return Err(format!("set change: already applied — that seat already weighs {voting_power}"));
            }
            Some(_) => {}
        },
    }
    if queue.iter().any(|x| x.body == *body) {
        return Ok(Preflight::AlreadyQueued);
    }
    Ok(Preflight::Verify)
}

fn set_change_accepted(cert: &SetChangeCert, queued: bool) -> Value {
    json!({"result": {"accepted": true, "queued": queued,
        "approvals": cert.approvals.len(),
        "window": [cert.body.not_before, cert.body.not_after],
        "note": if queued {
            "cert rides this node's next proposal inside its window"
        } else {
            "an identical cert is already queued — it rides this node's next proposal inside its window"
        }}})
}

/// `hk_submitSetChange` (V1 + L-6): queue a validator-set change certificate for this
/// node's next proposal. `tip` is the chain height the window is judged against.
/// Responses: `{accepted: true, queued, approvals, window, note}` for a verified or
/// already-queued cert (the v0.19.4 shape), `{accepted: false, reason}` for a refused
/// one, `{error}` when every verify slot is busy.
fn submit_set_change(
    validators: &Mutex<HkValidatorSet>,
    queue: &Mutex<Vec<SetChangeCert>>,
    slots: &tokio::sync::Semaphore,
    chain_id: &str,
    tip: u64,
    cert: SetChangeCert,
) -> Value {
    let set = validators.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let gate = {
        let q = queue.lock().unwrap_or_else(|e| e.into_inner());
        set_change_preflight(&set, &q, chain_id, tip, &cert)
    };
    match gate {
        Err(reason) => return refused(reason),
        Ok(Preflight::AlreadyQueued) => return set_change_accepted(&cert, false),
        Ok(Preflight::Verify) => {}
    }
    let Ok(permit) = slots.try_acquire() else {
        return busy_error();
    };
    // The expensive part — every approval's root signature, on the snapshot, no lock
    // held. `verify_against` is the exact check propose and commit run.
    if let Err(reason) = cert.verify_against(&set, chain_id) {
        return refused(reason);
    }
    drop(permit);
    let set = validators.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
    match set_change_preflight(&set, &q, chain_id, tip, &cert) {
        Err(reason) => refused(reason),
        Ok(Preflight::AlreadyQueued) => set_change_accepted(&cert, false),
        Ok(Preflight::Verify) => {
            q.push(cert.clone());
            set_change_accepted(&cert, true)
        }
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

async fn respond(sock: &mut tokio::net::TcpStream, status: u16, body: &Value) -> eyre::Result<()> {
    let payload = serde_json::to_vec(body)?;
    let reason = if status == 200 { "OK" } else { "ERR" };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        payload.len()
    );
    sock.write_all(head.as_bytes()).await?;
    sock.write_all(&payload).await?;
    sock.flush().await?;
    Ok(())
}

/// N1 (v0.15.2): mask a multiaddr's host for public display — IPv4 to its /24, IPv6 to
/// its /48 (a v4-mapped v6 address is masked like v4), DNS names kept as they are.
/// Returns `(masked, is_private)`; private = loopback, unspecified, RFC 1918, CGNAT
/// (100.64/10), link-local, or a v6 ULA — i.e. a peer on the same private network.
pub(crate) fn mask_multiaddr(addr: &str) -> (String, bool) {
    let parts: Vec<&str> = addr.split('/').collect();
    let mut out: Vec<String> = Vec::with_capacity(parts.len());
    let mut private = false;
    let mut i = 0;
    while i < parts.len() {
        let p = parts[i];
        if (p == "ip4" || p == "ip6") && i + 1 < parts.len() {
            let (masked, prv) = mask_host(p, parts[i + 1]);
            private |= prv;
            out.push(p.to_string());
            out.push(masked);
            i += 2;
        } else {
            out.push(p.to_string());
            i += 1;
        }
    }
    (out.join("/"), private)
}

fn mask_v4(ip: std::net::Ipv4Addr) -> (String, bool) {
    let o = ip.octets();
    let private = ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_private()
        || ip.is_link_local()
        || (o[0] == 100 && (o[1] & 0xc0) == 64);
    (format!("{}.{}.{}.0", o[0], o[1], o[2]), private)
}

fn mask_host(proto: &str, host: &str) -> (String, bool) {
    if proto == "ip4" {
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            return mask_v4(ip);
        }
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        if let Some(v4) = ip.to_ipv4_mapped() {
            let (m, prv) = mask_v4(v4);
            return (format!("::ffff:{m}"), prv);
        }
        let s = ip.segments();
        let private = ip.is_loopback()
            || ip.is_unspecified()
            || (s[0] & 0xfe00) == 0xfc00
            || (s[0] & 0xffc0) == 0xfe80;
        return (format!("{:x}:{:x}:{:x}::", s[0], s[1], s[2]), private);
    }
    (host.to_string(), false)
}

#[cfg(test)]
mod n1_tests {
    use super::mask_multiaddr;

    #[test]
    fn masks_public_and_private_hosts() {
        assert_eq!(mask_multiaddr("/ip4/203.0.113.77/tcp/27000"), ("/ip4/203.0.113.0/tcp/27000".into(), false));
        assert_eq!(mask_multiaddr("/ip4/10.42.7.9/tcp/27000"), ("/ip4/10.42.7.0/tcp/27000".into(), true));
        assert_eq!(mask_multiaddr("/ip4/127.0.0.1/tcp/27001"), ("/ip4/127.0.0.0/tcp/27001".into(), true));
        assert_eq!(mask_multiaddr("/ip4/100.64.3.4/tcp/1"), ("/ip4/100.64.3.0/tcp/1".into(), true));
        assert_eq!(mask_multiaddr("/ip4/100.128.3.4/tcp/1"), ("/ip4/100.128.3.0/tcp/1".into(), false));
        assert_eq!(
            mask_multiaddr("/ip6/2a02:c207:2355:1558::1/tcp/27000"),
            ("/ip6/2a02:c207:2355::/tcp/27000".into(), false)
        );
        assert_eq!(mask_multiaddr("/ip6/fd00:1::5/tcp/27000"), ("/ip6/fd00:1:0::/tcp/27000".into(), true));
        assert_eq!(mask_multiaddr("/ip6/::1/tcp/27000"), ("/ip6/0:0:0::/tcp/27000".into(), true));
        assert_eq!(
            mask_multiaddr("/ip6/::ffff:203.0.113.9/tcp/27000"),
            ("/ip6/::ffff:203.0.113.0/tcp/27000".into(), false)
        );
        assert_eq!(
            mask_multiaddr("/dns4/seed.hashkinetics.org/tcp/27000"),
            ("/dns4/seed.hashkinetics.org/tcp/27000".into(), false)
        );
        // garbage stays garbage, never panics
        assert_eq!(mask_multiaddr("/ip4/not-an-ip/tcp/1"), ("/ip4/not-an-ip/tcp/1".into(), false));
        assert_eq!(mask_multiaddr(""), ("".into(), false));
    }

    #[test]
    fn peer_agent_tags_parse_both_generations() {
        use malachitebft_network::{hk_peer_genesis_digest, hk_peer_node_version};
        let digest = "4e4ea68d48cba1ad4cc7155c19e7768f1fa2cbc99ba0f2b47c58948ec9e971c7";
        let old = format!("hashkinetics/1/genesis/{digest}");
        let new = format!("hashkinetics/1/genesis/{digest}/hk-node/v0.15.2");
        let want = hex::decode(digest).unwrap();
        assert_eq!(hk_peer_genesis_digest(&old).unwrap().to_vec(), want);
        assert_eq!(hk_peer_genesis_digest(&new).unwrap().to_vec(), want);
        assert_eq!(hk_peer_node_version(&old), None);
        assert_eq!(hk_peer_node_version(&new).as_deref(), Some("v0.15.2"));
        // not a tag / wrong length / junk after the digest / non-ASCII boundaries: never gate, never panic
        assert_eq!(hk_peer_genesis_digest("hashkinetics/1"), None);
        assert_eq!(hk_peer_genesis_digest(&format!("hashkinetics/1/genesis/{}", &digest[..63])), None);
        assert_eq!(hk_peer_genesis_digest(&format!("hashkinetics/1/genesis/{digest}x")), None);
        assert_eq!(hk_peer_genesis_digest("hashkinetics/1/genesis/ééééééééééééééééééééééééééééééééé"), None);
        assert_eq!(hk_peer_node_version(&format!("hashkinetics/1/genesis/{digest}/hk-node/")), None);
        assert_eq!(hk_peer_node_version(&format!("hashkinetics/1/genesis/{digest}/hk-node/v0.15.2 <script>")), None);
    }
}

/// R18 review (2026-10-08): the bundle door admits P2.3's bundle and nothing else.
#[cfg(test)]
mod r18_tests {
    use super::{bundle_shape_verdict, MAX_TXS_PER_BLOCK};
    use hk_crypto::lamport::{PK_LEN, SIG_LEN};
    use hk_primitives::H256;
    use hk_state::tx::{SignedTx, Tx};

    /// Frames with right-length junk keys: the verdict reads payloads and lengths only (the
    /// aggregate is the proof; whether the key is the account's is `submit_bundle`'s dry run).
    /// HR-1 (v0.19.11): an EMPTY key / signature — the pre-HR-1 fixture — is refused by the
    /// length rule now, so the shape semantics are asserted on frames that pass it.
    fn frame(payload: Tx) -> SignedTx {
        SignedTx {
            sender: H256([1; 32]),
            nonce: 0,
            payload,
            next_auth: H256([0; 32]),
            lamport_pk: vec![0xAA; PK_LEN],
            sig: vec![0xBB; SIG_LEN],
        }
    }
    fn spend(proof: Vec<u8>) -> SignedTx {
        frame(Tx::ShieldedSpend {
            anchor: H256([2; 32]),
            nullifier: H256([3; 32]),
            out_commitment: H256([4; 32]),
            out2_commitment: H256([5; 32]),
            fee: 0,
            credit: None,
            mandate: None,
            proof,
            stealth_ct: vec![],
            stealth_ct2: vec![],
        })
    }
    fn mint(proof: Vec<u8>) -> SignedTx {
        frame(Tx::MintToPool { asset: H256([9; 32]), value: 1, commitment: H256([6; 32]), proof, stealth_ct: vec![] })
    }

    #[test]
    fn r18_a_bundle_carries_only_proof_less_pool_txs() {
        // exactly what demo_agg builds: proof-less spends (and mints) under one aggregate
        assert_eq!(bundle_shape_verdict(&[spend(vec![]), spend(vec![]), mint(vec![])]), Ok(()));
        // the reported bypass: a ChannelSettle (over-cap or not) rode the bundle uncosted
        let settle = frame(Tx::ChannelSettle { id: H256([7; 32]), word: H256([8; 32]), step: u32::MAX });
        let err = bundle_shape_verdict(&[spend(vec![]), settle.clone()]).unwrap_err();
        assert!(err.starts_with("bad txs: a bundle may carry only proof-less MintToPool / ShieldedSpend txs"), "{err}");
        assert!(err.contains("tx 1 is not one"), "{err}");
        assert!(bundle_shape_verdict(&[settle]).is_err());
        // an over-cap ChannelOpen, a transfer: the same refusal — nothing but pool txs
        let open = frame(Tx::ChannelOpen {
            id: H256([7; 32]), mandate: H256([1; 32]), payee: H256([2; 32]), asset: H256([9; 32]),
            tip: H256([3; 32]), unit_price: 1, max_steps: u32::MAX, expiry: 1,
        });
        assert!(bundle_shape_verdict(&[open]).is_err());
        assert!(bundle_shape_verdict(&[frame(Tx::Transfer { to: H256([2; 32]), asset: H256([9; 32]), amount: 1 })]).is_err());
        // a pool tx that carries its own proof is the classic per-proof path, not a bundle
        assert!(bundle_shape_verdict(&[spend(vec![1, 2, 3])]).is_err());
        assert!(bundle_shape_verdict(&[mint(vec![1])]).is_err());
        // HR-1 (v0.19.11): a keyless frame — the report's PoC shape, and this fixture before
        // HR-1 — is refused by the length rule, after the proof-less rule, at its position
        let mut keyless = spend(vec![]);
        keyless.lamport_pk = vec![];
        keyless.sig = vec![];
        assert_eq!(
            bundle_shape_verdict(&[spend(vec![]), keyless]).unwrap_err(),
            "bad txs: tx 1 has a malformed envelope (0 B pk, 0 B sig) — a bundle tx is account-signed like any other"
        );
        // longer than a block: never picked by build_batch, so never queued
        let too_long: Vec<SignedTx> = (0..=MAX_TXS_PER_BLOCK).map(|_| spend(vec![])).collect();
        assert_eq!(
            bundle_shape_verdict(&too_long).unwrap_err(),
            format!("bad txs: a bundle may carry at most {MAX_TXS_PER_BLOCK} txs (one block)")
        );
        assert_eq!(bundle_shape_verdict(&too_long[..MAX_TXS_PER_BLOCK]), Ok(()));
    }

    /// v0.19.12: a bundle whose txs exceed one block's transaction budget is refused at
    /// the door — `build_batch` rides a bundle whole or not at all. Spends with the largest
    /// stealth fields the door takes: as many as the budget holds pass, one more is refused (and
    /// the byte budget binds before the count). KILL: drop the byte check from
    /// `bundle_shape_verdict` and the over-budget bundle passes — no block could carry it.
    #[test]
    fn a_bundle_over_one_blocks_transaction_budget_is_refused() {
        use crate::batch::MAX_BATCH_TX_BYTES;
        use crate::mempool::{tx_encoded_len, MAX_STEALTH_CT_BYTES};
        let fat = || {
            let mut t = spend(vec![]);
            if let Tx::ShieldedSpend { stealth_ct, stealth_ct2, .. } = &mut t.payload {
                *stealth_ct = vec![0x5c; MAX_STEALTH_CT_BYTES];
                *stealth_ct2 = vec![0x5c; MAX_STEALTH_CT_BYTES];
            }
            t
        };
        let size = tx_encoded_len(&fat());
        let fit = MAX_BATCH_TX_BYTES / size;
        assert!(fit < MAX_TXS_PER_BLOCK, "{fit} txs of {size} B: the byte budget binds before the count");
        let txs: Vec<SignedTx> = (0..=fit).map(|_| fat()).collect();
        assert_eq!(bundle_shape_verdict(&txs[..fit]), Ok(()));
        assert_eq!(
            bundle_shape_verdict(&txs).unwrap_err(),
            format!(
                "bad txs: the bundle's txs take {} B in a block (max {MAX_BATCH_TX_BYTES}, one block's transaction budget)",
                (fit + 1) * size
            )
        );
    }
}

#[cfg(test)]
mod h3_tests {
    use super::{pool_page, POOL_PAGE_MAX};
    use serde_json::json;

    #[test]
    fn h3_pool_pages_are_bounded_and_chain_to_the_end() {
        // empty pool: nothing, no next
        assert_eq!(pool_page(&json!({}), 0), (0, 0, None));
        // default page covers a small pool in one go
        assert_eq!(pool_page(&json!({}), 7), (0, 7, None));
        // explicit pages chain: 0..3 → next 3, 3..6 → next 6, 6..7 → end
        assert_eq!(pool_page(&json!({"limit": 3}), 7), (0, 3, Some(3)));
        assert_eq!(pool_page(&json!({"from": 3, "limit": 3}), 7), (3, 6, Some(6)));
        assert_eq!(pool_page(&json!({"from": 6, "limit": 3}), 7), (6, 7, None));
        // past the end: empty page, no next (a wallet whose cursor == total asks exactly this)
        assert_eq!(pool_page(&json!({"from": 7}), 7), (7, 7, None));
        assert_eq!(pool_page(&json!({"from": 99}), 7), (7, 7, None));
        // limit is capped, never zero
        assert_eq!(pool_page(&json!({"limit": 0}), 7), (0, 1, Some(1)));
        assert_eq!(pool_page(&json!({"limit": 1_000_000}), 3 * POOL_PAGE_MAX), (0, POOL_PAGE_MAX, Some(POOL_PAGE_MAX)));
    }
}

/// v0.19.12 (HR-4, HR-5, HR-9): the read methods the
/// release paged, added or widened, driven over the handles their bodies take (`SharedHandles`
/// needs a genesis and a signer, as `r17_tests` notes) on the shared fixture: a chain with
/// three registered assets, balances in several of them, a mandate tree with a designated
/// holder, an open channel and a credit to an id that has no account.
#[cfg(test)]
mod v0_19_12_tests {
    use super::*;
    use crate::mempool::test_fixtures::*;
    use hk_state::assets::{derive_asset_id, AssetPolicy};
    use tokio::sync::Semaphore;

    /// A root held by its funder (account 1) …
    const ROOT: H256 = H256([0xA0; 32]);
    /// … its child, held by account 2 …
    const LEAF: H256 = H256([0xA1; 32]);
    /// … and a second root account 1 funds but account 3 holds (a designated holder).
    const ROOT_FOREIGN: H256 = H256([0xA2; 32]);
    /// An id nobody ever created an account for.
    const GHOST: u8 = 99;

    /// Three assets registered by account 1 (`A`, `B`, `C`; 1,800 / 700 / 9 minted) with
    /// balances in accounts 1–3; the mandate tree above in `A`; a channel from account 2 to
    /// account 3 in `A` (escrow 50, drawn from the funder through the whole chain); a 5-unit
    /// transfer from account 3 to the never-created id 99. Returns the chain and `[A, B, C]`.
    fn fixture() -> (hk_state::State, [H256; 3]) {
        let mut chain = mini_chain(3);
        let a = derive_asset_id(&acct(1), "A");
        let b = derive_asset_id(&acct(1), "B");
        let c = derive_asset_id(&acct(1), "C");
        let mut height = 0u64;
        let mut apply = |chain: &mut hk_state::State, tx: SignedTx| {
            height += 1;
            let r = chain.apply_block(height, 10 + height, &[tx]).expect("block applies");
            assert!(r[0].result.is_ok(), "height {height}: {:?}", r[0].result);
        };
        let mut n1 = 0u64;
        let mut sign1 = |payload: Tx| {
            let tx = sign_at(1, n1, payload);
            n1 += 1;
            tx
        };
        for (asset, sym) in [(a, "A"), (b, "B"), (c, "C")] {
            apply(&mut chain, sign1(Tx::AssetRegister { asset, symbol: sym.into(), decimals: 6, policy: AssetPolicy::from_flags("mf").unwrap() }));
        }
        for (asset, to, amount) in [(a, 1, 300), (a, 2, 1_000), (a, 3, 500), (b, 2, 700), (c, 3, 9)] {
            apply(&mut chain, sign1(Tx::AssetMint { asset, to: acct(to), amount }));
        }
        let mk = |id, parent, holder| Tx::MandateCreate {
            id, parent, holder, asset: a, rate_per_sec: 0, buffer_max: 1_000, per_tx_max: 1_000,
            initial_buffer: 1_000, expiry: 1_000_000, tier: 1,
        };
        apply(&mut chain, sign1(mk(ROOT, None, acct(1))));
        apply(&mut chain, sign1(mk(LEAF, Some(ROOT), acct(2))));
        apply(&mut chain, sign1(mk(ROOT_FOREIGN, None, acct(3))));
        // account 2 (the leaf's holder) opens a 5 × 10 channel to account 3: escrow 50 leaves
        // the funder (account 1) and the mandate chain's buffers drop to 950
        let tip = H256([0x77; 32]);
        let ch = hk_state::State::derive_channel_id(&acct(2), &acct(3), &tip, 0);
        apply(&mut chain, sign_at(2, 0, Tx::ChannelOpen { id: ch, mandate: LEAF, payee: acct(3), asset: a, tip, unit_price: 10, max_steps: 5, expiry: 1_000_000 }));
        // account 3 credits an id that has no account
        apply(&mut chain, sign_at(3, 0, Tx::Transfer { to: acct(GHOST), asset: ASSET, amount: 5 }));
        assert_eq!(chain.channels.len(), 1);
        (chain, [a, b, c])
    }

    fn id_of(entry: &Value) -> H256 {
        H256(hex::decode(entry["asset"].as_str().unwrap()).unwrap().try_into().unwrap())
    }

    /// HR-4: the registry page arithmetic — `pool_page`'s contract with the effective limit
    /// echoed. KILL: drop the `.clamp(1, ASSET_PAGE_MAX)` (the 1,000,000 and 0 cases) or the
    /// `.min(total)` on `from` (the 99 case).
    #[test]
    fn hr4_asset_pages_are_bounded_and_chain_to_the_end() {
        assert_eq!(asset_page(&json!({}), 0), (0, 0, ASSET_PAGE_MAX, None));
        assert_eq!(asset_page(&json!({}), 7), (0, 7, ASSET_PAGE_MAX, None));
        assert_eq!(asset_page(&json!({"limit": 3}), 7), (0, 3, 3, Some(3)));
        assert_eq!(asset_page(&json!({"from": 3, "limit": 3}), 7), (3, 6, 3, Some(6)));
        assert_eq!(asset_page(&json!({"from": 6, "limit": 3}), 7), (6, 7, 3, None));
        assert_eq!(asset_page(&json!({"from": 7}), 7), (7, 7, ASSET_PAGE_MAX, None));
        assert_eq!(asset_page(&json!({"from": 99}), 7), (7, 7, ASSET_PAGE_MAX, None));
        assert_eq!(asset_page(&json!({"from": u64::MAX}), 7), (7, 7, ASSET_PAGE_MAX, None));
        assert_eq!(asset_page(&json!({"limit": 0}), 7), (0, 1, 1, Some(1)));
        assert_eq!(asset_page(&json!({"limit": 1_000_000}), 3 * ASSET_PAGE_MAX), (0, ASSET_PAGE_MAX, ASSET_PAGE_MAX, Some(ASSET_PAGE_MAX)));
        assert_eq!(asset_page(&json!({"limit": u64::MAX}), 2), (0, 2, ASSET_PAGE_MAX, None));
    }

    /// HR-4: `hk_getAssets` answers the whole registry's `count` with a page of entries whose
    /// conservation receipts equal the per-asset view's, pages chain to the end, and a caller
    /// past the one scan slot is told to retry. KILL: drop `try_acquire` from `get_assets`
    /// (the busy case), make `asset_json` fall back to `chain.asset_conservation` (every entry
    /// still agrees — the KILL for the one-pass view is hk-state's
    /// `hr4_asset_conservation_all_matches_the_per_asset_view`), or answer `count` as the
    /// page's length (the `{"limit": 2}` case: `count` must stay 3 — `gate-x1.sh` reads it).
    #[test]
    fn hr4_get_assets_pages_the_registry_and_holds_one_scan_slot() {
        let (chain, [a, _, _]) = fixture();
        let chain = Mutex::new(chain);
        let slots = Semaphore::new(1);
        let all = get_assets(&chain, &slots, &json!({}));
        let res = &all["result"];
        assert_eq!(res["count"], json!(3), "{all}");
        assert_eq!(res["total"], json!(3));
        assert_eq!(res["from"], json!(0));
        assert_eq!(res["limit"], json!(ASSET_PAGE_MAX));
        assert_eq!(res["next"], Value::Null);
        let entries = res["assets"].as_array().unwrap();
        assert_eq!(entries.len(), 3);
        {
            let st = chain.lock().unwrap();
            assert_eq!(res["fee_asset"], json!(hex::encode(st.fee_asset.0)));
            assert_eq!(entries.iter().map(id_of).collect::<Vec<_>>(), st.assets.keys().copied().collect::<Vec<_>>(), "registry order");
            for entry in entries {
                let (held, issued) = st.asset_conservation(&id_of(entry)).expect("registered");
                assert_eq!(entry["held"], json!(held.to_string()), "{entry}");
                assert_eq!(entry["circulating"], json!(issued.to_string()), "{entry}");
                assert_eq!(entry["conserved"], json!(true), "{entry}");
            }
            // asset A: balances 250 + 1,000 + 500 plus the channel's 50 of escrow = 1,800 minted
            assert_eq!(st.asset_conservation(&a), Some((1_800, 1_800)));
            assert_eq!(st.balance(&acct(1), &a), 250);
        }
        assert_eq!(slots.available_permits(), 1, "the slot comes back");
        // pages chain: 2 + 1, `count` the whole registry throughout
        let ids = |v: &Value| v["result"]["assets"].as_array().unwrap().iter().map(id_of).collect::<Vec<_>>();
        let p1 = get_assets(&chain, &slots, &json!({"limit": 2}));
        assert_eq!((ids(&p1).len(), p1["result"]["next"].clone(), p1["result"]["count"].clone(), p1["result"]["limit"].clone()), (2, json!(2), json!(3), json!(2)));
        let p2 = get_assets(&chain, &slots, &json!({"from": 2, "limit": 2}));
        assert_eq!((ids(&p2).len(), p2["result"]["next"].clone(), p2["result"]["from"].clone()), (1, Value::Null, json!(2)));
        let mut chained = ids(&p1);
        chained.extend(ids(&p2));
        assert_eq!(chained, ids(&all));
        // past the end: an empty page, the count unchanged, no next
        let p3 = get_assets(&chain, &slots, &json!({"from": 99}));
        assert_eq!((ids(&p3).len(), p3["result"]["count"].clone(), p3["result"]["next"].clone()), (0, json!(3), Value::Null));
        // the slot is held: told to retry — nothing locked, nothing answered
        let held = Semaphore::new(1);
        let permit = held.try_acquire().unwrap();
        let busy = get_assets(&chain, &held, &json!({}));
        assert_eq!(busy["error"], json!("busy: an asset registry scan is already in flight — retry in a moment"), "{busy}");
        drop(permit);
        assert_eq!(get_assets(&chain, &held, &json!({}))["result"]["count"], json!(3));
        assert_eq!(held.available_permits(), 1);
    }

    /// HR-9: `hk_getAccount` on an id with no account answers its balances — the ghost credit
    /// is discoverable — with `found: false`, `nonce: null`, `auth_commit: null`; an existing
    /// account keeps its shape. KILL: answer `{found: false}` alone for a missing account (the
    /// pre-v0.19.12 arm) and the ghost's `balances[]` is gone.
    #[test]
    fn hr9_get_account_shows_a_ghost_balance_without_an_account() {
        let (chain, [a, _, _]) = fixture();
        let chain = Mutex::new(chain);
        let ghost = get_account(&chain, &json!({"id": hex::encode(acct(GHOST).0)}));
        let res = &ghost["result"];
        assert_eq!(res["found"], json!(false), "{ghost}");
        assert_eq!(res["nonce"], Value::Null);
        assert_eq!(res["auth_commit"], Value::Null);
        let bal = res["balances"].as_array().unwrap();
        assert_eq!(bal.len(), 1, "{ghost}");
        assert_eq!(bal[0]["asset"], json!(hex::encode(ASSET.0)));
        assert_eq!(bal[0]["amount"], json!("5"));
        assert_eq!(bal[0]["symbol"], Value::Null, "an unregistered asset has no symbol");
        assert_eq!(bal[0]["frozen"], json!(false));
        // an existing account: the shape as before, every balance by asset
        let two = get_account(&chain, &json!({"id": hex::encode(acct(2).0)}));
        assert_eq!(two["result"]["found"], json!(true));
        assert_eq!(two["result"]["nonce"], json!(1));
        assert_eq!(two["result"]["auth_commit"].as_str().unwrap().len(), 64);
        let bal = two["result"]["balances"].as_array().unwrap();
        assert!(bal.iter().any(|e| e["asset"] == json!(hex::encode(a.0)) && e["amount"] == json!("1000") && e["symbol"] == json!("A")), "{two}");
        assert!(bal.iter().any(|e| e["asset"] == json!(hex::encode(ASSET.0)) && e["amount"] == json!("1000")), "{two}");
        // an id nobody ever credited: found false, no balances; a bad id: the error
        let none = get_account(&chain, &json!({"id": hex::encode([0xEE; 32])}));
        assert_eq!(none["result"]["found"], json!(false));
        assert!(none["result"]["balances"].as_array().unwrap().is_empty());
        assert_eq!(get_account(&chain, &json!({"id": "zz"}))["error"], json!("id must be 64-char hex"));
    }

    /// HR-5: `hk_getMandate` shows a node's holder AND its funder, for a root held by its
    /// funder, a child held by another account, and a root whose designated holder is not its
    /// funder — the shape the funder has no verb over. KILL: answer `funder` from the node's
    /// own `holder_key` instead of `root_funding` and the child's and the foreign root's
    /// `funder` assertions fail.
    #[test]
    fn hr5_get_mandate_shows_holder_and_funder_for_root_child_and_designated_holder() {
        let (chain, [a, _, _]) = fixture();
        let chain = Mutex::new(chain);
        let one = json!(hex::encode(acct(1).0));
        let root = get_mandate(&chain, &json!({"id": hex::encode(ROOT.0)}));
        let r = &root["result"];
        assert_eq!(r["found"], json!(true), "{root}");
        assert_eq!(r["id"], json!(hex::encode(ROOT.0)));
        assert_eq!(r["parent"], Value::Null);
        assert_eq!(r["root"], json!(hex::encode(ROOT.0)));
        assert_eq!(r["holder"], one);
        assert_eq!(r["funder"], one);
        assert_eq!(r["asset"], json!(hex::encode(a.0)));
        assert_eq!((r["rate_per_sec"].clone(), r["buffer_max"].clone(), r["per_tx_max"].clone()), (json!("0"), json!("1000"), json!("1000")));
        assert_eq!(r["buffer"], json!("950"), "the channel's escrow was drawn through the whole chain");
        assert_eq!((r["expiry"].clone(), r["tier"].clone(), r["revoked"].clone()), (json!(1_000_000), json!(1), json!(false)));
        assert!(r["last_accrual"].as_u64().is_some());
        // the child: held by account 2, funded by account 1 through its root
        let leaf = get_mandate(&chain, &json!({"id": hex::encode(LEAF.0)}));
        let l = &leaf["result"];
        assert_eq!(l["holder"], json!(hex::encode(acct(2).0)), "the designated holder");
        assert_eq!(l["funder"], one, "the root's funder pays");
        assert_eq!(l["parent"], json!(hex::encode(ROOT.0)));
        assert_eq!(l["root"], json!(hex::encode(ROOT.0)));
        assert_eq!(l["buffer"], json!("950"));
        // a root whose holder is not its funder: both named, so the funder can see what it signed
        let foreign = get_mandate(&chain, &json!({"id": hex::encode(ROOT_FOREIGN.0)}));
        let f = &foreign["result"];
        assert_eq!(f["holder"], json!(hex::encode(acct(3).0)));
        assert_eq!(f["funder"], one);
        assert_eq!(f["parent"], Value::Null);
        assert_eq!(f["buffer"], json!("1000"));
        // unknown and malformed ids
        assert_eq!(get_mandate(&chain, &json!({"id": hex::encode([0xEE; 32])}))["result"]["found"], json!(false));
        assert_eq!(get_mandate(&chain, &json!({}))["error"], json!("id must be 64-char hex"));
    }

    // ---- v0.19.12: block reads and transaction summaries ----

    /// A block store in a fresh temp dir holding `blocks` (height → txs) as `save_block` writes
    /// them, under a stand-in certificate; the disk floor set to 1, as restore would.
    fn store_with(tag: &str, blocks: &[(u64, Vec<SignedTx>)]) -> (std::path::PathBuf, crate::store::NodeStore) {
        let home = std::env::temp_dir().join(format!(
            "hk-block-reads-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let store = crate::store::NodeStore::open(&home).expect("store opens");
        for (height, txs) in blocks {
            let batch = Batch {
                parent_app_hash: [0x11; 32],
                txs: txs.clone(),
                rotations: vec![],
                agg_proof: vec![],
                set_changes: vec![],
            };
            store
                .save_block(&crate::store::StoredBlock {
                    height: *height,
                    value_bytes: batch.encode(),
                    certificate: crate::codec::RawCommitCertificate {
                        height: hk_consensus::HkHeight::new(*height),
                        round: malachitebft_app_channel::app::types::core::Round::ZERO,
                        value_id: hk_consensus::HkValueId::new([0xAB; 32]),
                        commit_signatures: vec![],
                    },
                    agg_valid: false,
                })
                .expect("block saved");
        }
        store.set_disk_min(1);
        (home, store)
    }

    /// The three block reads share `BLOCK_READ_SLOTS` permits, taken before a block is
    /// loaded: with both held each answers "busy — retry" (a free refusal still answers, and an
    /// unindexed txid needs no permit), and every call gives its permit back. `hk_getBlock`
    /// reports each tx's receipt under the txid it computed; `hk_getTx` gives the same
    /// summary and the bare receipt string. KILL: drop the `try_acquire` from any of the three
    /// (its busy assertion fails), or look a receipt up by another id (the receipt assertions).
    #[test]
    fn block_reads_share_a_slot_and_answer_busy_past_it() {
        let t0 = transfer(1, 0);
        let t1 = transfer(2, 0);
        let (home, store) = store_with("slots", &[(1, vec![t0.clone(), t1.clone()]), (2, vec![])]);
        let receipts = Mutex::new(crate::state::ReceiptLog::new(16));
        receipts.lock().unwrap().restore(vec![
            (txid(&t0), "ok: 1 event(s)".to_string()),
            (txid(&t1), "rejected: bad nonce".to_string()),
        ]);
        let tx_index = Mutex::new(std::collections::HashMap::from([(txid(&t1), (1u64, 1u32))]));
        let mut st = hk_state::State::default();
        st.height = 2;
        let chain = Mutex::new(st);
        let slots = Semaphore::new(BLOCK_READ_SLOTS);
        let busy = json!(format!("busy: {BLOCK_READ_SLOTS} block reads already in flight — retry in a moment"));
        let t1_hex = hex::encode(txid(&t1));
        {
            let _held = (slots.try_acquire().unwrap(), slots.try_acquire().unwrap());
            assert_eq!(get_block(Some(&store), &receipts, 0, &slots, &json!({"height": 1}))["error"], busy);
            assert_eq!(get_tx(Some(&store), &tx_index, &receipts, &slots, &json!({"txid": t1_hex}))["error"], busy);
            assert_eq!(get_blocks(Some(&store), &chain, 0, &slots, &json!({}), BLOCKS_READ_BUDGET)["error"], busy);
            // the free answers need no permit
            assert_eq!(
                get_block(Some(&store), &receipts, 0, &slots, &json!({}))["error"],
                json!("height (number) required")
            );
            assert_eq!(
                get_block(None, &receipts, 0, &slots, &json!({"height": 1}))["error"],
                json!("persistence disabled on this node (HK_NO_PERSIST)")
            );
            let unindexed = json!({"txid": hex::encode([0xEE; 32])});
            assert_eq!(get_tx(Some(&store), &tx_index, &receipts, &slots, &unindexed)["result"]["found"], json!(false));
        }
        assert_eq!(slots.available_permits(), BLOCK_READ_SLOTS);
        // a permit free: the block, every txid once, each receipt under its own txid
        let block = get_block(Some(&store), &receipts, 0, &slots, &json!({"height": 1}));
        let txs = block["result"]["txs"].as_array().unwrap();
        assert_eq!(txs.len(), 2);
        assert_eq!(block["result"]["tx_count"], json!(2));
        assert_eq!(txs[0]["txid"], json!(hex::encode(txid(&t0))));
        assert_eq!(txs[1]["txid"], json!(t1_hex));
        assert_eq!(txs[0]["receipt"], json!({"found": true, "ok": true, "detail": "ok: 1 event(s)"}));
        assert_eq!(txs[1]["receipt"], json!({"found": true, "ok": false, "detail": "rejected: bad nonce"}));
        assert_eq!(get_block(Some(&store), &receipts, 0, &slots, &json!({"height": 9}))["result"]["found"], json!(false));
        // `hk_getTx`: the same summary (without the block's receipt key) and the bare receipt
        let one = get_tx(Some(&store), &tx_index, &receipts, &slots, &json!({"txid": t1_hex}));
        assert_eq!(one["result"]["summary"], tx_summary(&t1, &txid(&t1)));
        assert_eq!(one["result"]["receipt"], json!("rejected: bad nonce"));
        assert_eq!((one["result"]["height"].clone(), one["result"]["index"].clone()), (json!(1), json!(1)));
        // `hk_getBlocks`: newest first
        let page = get_blocks(Some(&store), &chain, 0, &slots, &json!({}), BLOCKS_READ_BUDGET);
        let heights: Vec<u64> =
            page["result"]["blocks"].as_array().unwrap().iter().map(|b| b["height"].as_u64().unwrap()).collect();
        assert_eq!(heights, vec![2, 1]);
        assert_eq!(slots.available_permits(), BLOCK_READ_SLOTS, "every call gave its permit back");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// `hk_getBlocks` stops loading once a call has loaded its byte budget and names where
    /// to continue (`truncated`, `next_before`); the follow-up call walks on from there with no
    /// gap and no repeat; a page inside the budget keeps the pre-v0.19.12 shape (no new key).
    /// KILL: drop the budget check (all three blocks load in the first call), or name the wrong
    /// cursor (the follow-up repeats or skips a height).
    #[test]
    fn get_blocks_stops_at_its_byte_budget_and_names_where_to_continue() {
        let blocks: Vec<(u64, Vec<SignedTx>)> = (1..=3u64).map(|h| (h, vec![transfer(1, h)])).collect();
        let (home, store) = store_with("budget", &blocks);
        let mut st = hk_state::State::default();
        st.height = 3;
        let chain = Mutex::new(st);
        let slots = Semaphore::new(BLOCK_READ_SLOTS);
        let heights = |v: &Value| -> Vec<u64> {
            v["result"]["blocks"].as_array().unwrap().iter().map(|b| b["height"].as_u64().unwrap()).collect()
        };
        let one_block = store.load_block(3).unwrap().unwrap().value_bytes.len();
        // a budget one block wide: the first load reaches it, the walk stops before the second
        let page = get_blocks(Some(&store), &chain, 0, &slots, &json!({"limit": 10}), one_block);
        assert_eq!(heights(&page), vec![3]);
        assert_eq!(page["result"]["truncated"], json!(true));
        assert_eq!(page["result"]["next_before"], json!(3));
        // the caller continues from the cursor and walks the rest
        let rest = get_blocks(Some(&store), &chain, 0, &slots, &json!({"limit": 10, "before": 3}), 10 * one_block);
        assert_eq!(heights(&rest), vec![2, 1]);
        assert!(rest["result"].get("truncated").is_none() && rest["result"].get("next_before").is_none());
        // a page inside the budget: the pre-v0.19.12 shape, key for key
        let full = get_blocks(Some(&store), &chain, 0, &slots, &json!({}), BLOCKS_READ_BUDGET);
        assert_eq!(heights(&full), vec![3, 2, 1]);
        let mut keys: Vec<&str> = full["result"].as_object().unwrap().keys().map(|k| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["blocks", "earliest", "latest"]);
        assert_eq!((full["result"]["earliest"].clone(), full["result"]["latest"].clone()), (json!(1), json!(3)));
        assert_eq!(slots.available_permits(), BLOCK_READ_SLOTS);
        let _ = std::fs::remove_dir_all(&home);
    }

    /// `tx_summary` shows at most `SUMMARY_SYMBOL_SHOWN` bytes of a symbol and
    /// `SUMMARY_DESTINATION_SHOWN` of a destination, names the real length and `truncated: true`
    /// when it cut, cuts a symbol on a character boundary, and leaves every value inside the
    /// bounds — every value the chain accepts — byte for byte as before. KILL: drop either cut
    /// (the long symbol or destination comes back whole), or add the length keys always (the
    /// byte-identical assertions fail).
    #[test]
    fn tx_summary_cuts_long_fields_and_keeps_accepted_ones_byte_identical() {
        let id = [0x42; 32];
        let a = H256([0xA5; 32]);
        let frame = |payload: Tx| SignedTx {
            sender: acct(1),
            nonce: 7,
            payload,
            next_auth: H256([0; 32]),
            lamport_pk: vec![],
            sig: vec![],
        };
        // the summary as v0.19.11 built it
        let before = |stx: &SignedTx, kind: &str, fields: Value| {
            json!({
                "txid": hex::encode(id),
                "sender": hex::encode(stx.sender.0),
                "nonce": stx.nonce,
                "kind": kind,
                "fields": fields,
            })
        };
        let same = |got: Value, want: Value| {
            assert_eq!(serde_json::to_string(&got).unwrap(), serde_json::to_string(&want).unwrap());
        };
        // accepted values: byte for byte as before
        let reg = frame(Tx::AssetRegister {
            asset: a,
            symbol: "USDC.t".into(),
            decimals: 6,
            policy: AssetPolicy::from_flags("mf").unwrap(),
        });
        same(
            tx_summary(&reg, &id),
            before(&reg, "asset_register", json!({"asset": hex::encode(a.0), "symbol": "USDC.t", "decimals": 6, "policy": "mf"})),
        );
        let burn = frame(Tx::AssetBurn { asset: a, amount: 5, destination: vec![0x7e; 64] });
        same(
            tx_summary(&burn, &id),
            before(&burn, "asset_burn", json!({"asset": hex::encode(a.0), "amount": "5", "destination": hex::encode([0x7e; 64])})),
        );
        let pay = frame(Tx::Transfer { to: acct(2), asset: a, amount: 9 });
        same(
            tx_summary(&pay, &id),
            before(&pay, "transfer", json!({"to": hex::encode(acct(2).0), "asset": hex::encode(a.0), "amount": "9"})),
        );
        // at the bounds: whole, no new key
        let at = frame(Tx::AssetRegister {
            asset: a,
            symbol: "S".repeat(SUMMARY_SYMBOL_SHOWN),
            decimals: 0,
            policy: AssetPolicy::default(),
        });
        let f = tx_summary(&at, &id)["fields"].clone();
        assert_eq!(f["symbol"], json!("S".repeat(SUMMARY_SYMBOL_SHOWN)));
        assert!(f.get("symbol_len").is_none() && f.get("truncated").is_none(), "{f}");
        let at = frame(Tx::AssetBurn { asset: a, amount: 1, destination: vec![1; SUMMARY_DESTINATION_SHOWN] });
        let f = tx_summary(&at, &id)["fields"].clone();
        assert_eq!(f["destination"], json!(hex::encode([1u8; SUMMARY_DESTINATION_SHOWN])));
        assert!(f.get("destination_len").is_none() && f.get("truncated").is_none(), "{f}");
        // past them: cut, the real length beside it, `truncated`
        let big = "A".repeat(1024 * 1024);
        let reg = frame(Tx::AssetRegister { asset: a, symbol: big.clone(), decimals: 0, policy: AssetPolicy::default() });
        let f = tx_summary(&reg, &id)["fields"].clone();
        assert_eq!(f["symbol"], json!(&big[..SUMMARY_SYMBOL_SHOWN]));
        assert_eq!(f["symbol_len"], json!(big.len()));
        assert_eq!(f["truncated"], json!(true));
        // a cut never splits a character: a two-byte 'é' straddling the bound is left out whole
        let straddle = format!("{}\u{e9}tail", "B".repeat(SUMMARY_SYMBOL_SHOWN - 1));
        let reg = frame(Tx::AssetRegister { asset: a, symbol: straddle.clone(), decimals: 0, policy: AssetPolicy::default() });
        let f = tx_summary(&reg, &id)["fields"].clone();
        assert_eq!(f["symbol"], json!("B".repeat(SUMMARY_SYMBOL_SHOWN - 1)));
        assert_eq!(f["symbol_len"], json!(straddle.len()));
        let dest = vec![0xC3u8; 1000];
        let f = tx_summary(&frame(Tx::AssetBurn { asset: a, amount: 1, destination: dest.clone() }), &id)["fields"].clone();
        assert_eq!(f["destination"], json!(hex::encode(&dest[..SUMMARY_DESTINATION_SHOWN])));
        assert_eq!(f["destination_len"], json!(1000));
        assert_eq!(f["truncated"], json!(true));
        let over = frame(Tx::AssetBurn { asset: a, amount: 1, destination: vec![1; SUMMARY_DESTINATION_SHOWN + 1] });
        let f = tx_summary(&over, &id)["fields"].clone();
        assert_eq!(f["destination_len"], json!(SUMMARY_DESTINATION_SHOWN + 1));
        assert_eq!(f["truncated"], json!(true));
    }

    /// HR-4 review (v0.19.12): `hk_getAsset` runs its conservation scan under the `ASSET_SCAN`
    /// slot, like `hk_getAssets`: with the slot held it answers "busy — retry" (the missing-id
    /// refusal still answers, needing neither slot nor lock); free, it answers as before — the
    /// entry with its receipt, by id or by issuer + symbol, `found: false` for an unknown id —
    /// and gives the slot back. KILL: drop the `try_acquire` from `get_asset`.
    #[test]
    fn hr4_get_asset_holds_the_scan_slot() {
        let (chain, [a, _, _]) = fixture();
        let chain = Mutex::new(chain);
        let slots = Semaphore::new(1);
        let by_id = json!({"asset": hex::encode(a.0)});
        {
            let _in_flight = slots.try_acquire().unwrap();
            assert_eq!(
                get_asset(&chain, &slots, &by_id)["error"],
                json!("busy: an asset registry scan is already in flight — retry in a moment")
            );
            assert_eq!(
                get_asset(&chain, &slots, &json!({}))["error"],
                json!("asset (64-char hex) or issuer (64-char hex) + symbol required")
            );
        }
        let one = get_asset(&chain, &slots, &by_id);
        assert_eq!(one["result"]["found"], json!(true), "{one}");
        let (held, issued) = chain.lock().unwrap().asset_conservation(&a).expect("registered");
        assert_eq!(one["result"]["asset"]["held"], json!(held.to_string()));
        assert_eq!(one["result"]["asset"]["circulating"], json!(issued.to_string()));
        assert_eq!(one["result"]["asset"]["conserved"], json!(true));
        assert_eq!(one["result"]["asset"]["symbol"], json!("A"));
        // by issuer + symbol: the same entry
        assert_eq!(get_asset(&chain, &slots, &json!({"issuer": hex::encode(acct(1).0), "symbol": "A"})), one);
        let unknown = H256([0xEE; 32]);
        assert_eq!(
            get_asset(&chain, &slots, &json!({"asset": hex::encode(unknown.0)}))["result"],
            json!({"found": false, "asset_id": hex::encode(unknown.0)})
        );
        assert_eq!(slots.available_permits(), 1, "the slot comes back");
    }

    /// `admit_one` answers a refusal the tx's own bytes decide — a shield over the byte cap and
    /// a bad symbol here — while the chain lock is held elsewhere: the answers come, in the
    /// mempool's words, and nothing is indexed. An honest tx is then admitted under `txid`'s
    /// id, and its duplicate is refused with the same reason as before. KILL: take the locks
    /// before `hash_free_refusal` (the call waits on the held lock and the receive times out).
    #[test]
    fn admit_one_answers_a_refusal_by_the_txs_own_bytes_without_the_locks() {
        use crate::mempool::{AdmitError, MAX_TX_BYTES};
        let h = crate::state::SharedHandles::for_tests(mini_chain(1));
        // right-length envelopes (the lengths check passes); the signatures are never reached
        let mut oversize = sign_at(1, 0, transfer_payload(1));
        oversize.payload =
            Tx::MintToPool { asset: ASSET, value: 1, commitment: H256([6; 32]), proof: vec![0; MAX_TX_BYTES], stealth_ct: vec![] };
        let mut bad_symbol = sign_at(1, 0, transfer_payload(1));
        bad_symbol.payload =
            Tx::AssetRegister { asset: H256([3; 32]), symbol: "1BAD".into(), decimals: 6, policy: AssetPolicy::default() };
        let want = vec![
            Err(AdmitError::TxTooLarge { len: tx_encoded_len(&oversize) }.as_str()),
            Err(AdmitError::BadSymbol { len: 4 }.as_str()),
        ];
        let held = h.chain.lock().unwrap();
        let (send, recv) = std::sync::mpsc::channel();
        let worker = {
            let h = h.clone();
            let frames = vec![oversize, bad_symbol];
            std::thread::spawn(move || {
                for t in frames {
                    let _ = send.send(admit_one(&h, &t));
                }
            })
        };
        let wait = std::time::Duration::from_secs(10);
        let got: Vec<Result<[u8; 32], String>> = (0..2)
            .map(|_| recv.recv_timeout(wait).expect("answered without waiting for the chain lock"))
            .collect();
        drop(held);
        worker.join().unwrap();
        assert_eq!(got, want);
        assert_eq!(h.mempool.lock().unwrap().len(), 0);
        // an honest tx through the locked path: the id `txid` gives, then the duplicate's reason
        let good = transfer(1, 0);
        assert_eq!(admit_one(&h, &good), Ok(txid(&good)));
        assert_eq!(admit_one(&h, &good), Err(AdmitError::DuplicateTx.as_str()));
        assert_eq!(h.mempool.lock().unwrap().len(), 1);
    }

    /// v0.19.12: `hk_getAccountTxs` selects its page in one pass (`newest_rows`) and answers
    /// what a stable newest-first sort of the whole list cut to the limit gives, row for row: an
    /// index whose heights are out of insertion order (the background history pass appends old
    /// heights after live commits), ties at every height, every limit up to the cap. KILL: break
    /// the tie order in `newest_rows` (a tie across the page edge picks the later-indexed row), or
    /// rank by position instead of height (the history rows come first).
    #[test]
    fn account_txs_page_matches_the_full_stable_sort() {
        let me = acct(7);
        let mut rows: Vec<AcctRow> = Vec::new();
        let row = |n: usize, height: u64, kind: &'static str| {
            let mut t = [0u8; 32];
            t[..8].copy_from_slice(&(n as u64).to_le_bytes());
            (t, height, kind)
        };
        // live commits at heights 100..140, two rows each, then the history pass's 1..=30 —
        // with a third row at 139 and at 120 appended late, out of order
        for height in 100..140u64 {
            rows.push(row(rows.len(), height, "transfer"));
            rows.push(row(rows.len(), height, "shield"));
        }
        for height in 1..=30u64 {
            rows.push(row(rows.len(), height, "mandate_create"));
        }
        rows.push(row(rows.len(), 139, "asset_burn"));
        rows.push(row(rows.len(), 120, "asset_mint"));
        let index = Mutex::new(std::collections::HashMap::from([(me, rows.clone())]));
        // the reference: the whole list, stable-sorted newest first, then cut
        let reference = |limit: usize| -> Vec<Value> {
            let mut sorted: Vec<&AcctRow> = rows.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(&a.1));
            sorted
                .into_iter()
                .take(limit)
                .map(|(t, ht, kind)| json!({"txid": hex::encode(t), "height": ht, "kind": kind}))
                .collect()
        };
        let id = hex::encode(me.0);
        for limit in [0usize, 1, 2, 3, 4, 25, 80, 81, 82, 100, 112, 1_000] {
            let got = get_account_txs(&index, &json!({"id": id, "limit": limit}));
            assert_eq!(got["result"]["total"], json!(rows.len()), "limit {limit}");
            assert_eq!(got["result"]["txs"], json!(reference(limit.min(100))), "limit {limit}");
        }
        assert_eq!(get_account_txs(&index, &json!({"id": id}))["result"]["txs"], json!(reference(25)), "the default");
        let nobody = hex::encode([0xEE; 32]);
        assert_eq!(
            get_account_txs(&index, &json!({"id": nobody}))["result"],
            json!({"id": nobody, "total": 0, "txs": []})
        );
        assert_eq!(get_account_txs(&index, &json!({}))["error"], json!("id must be 64-char hex"));
    }

    /// v0.19.12: `hk_getMempool` answers from the txids the pool stored, with the
    /// response it always had — the whole pool's `count` and the first 100 txids in pool order,
    /// each the hash of its tx. KILL: answer from anything but the pool's own order or ids (the
    /// comparison with hashing the pool fails), or cut `txids` elsewhere than at 100.
    #[test]
    fn get_mempool_answers_from_the_stored_ids() {
        let mempool = Mutex::new(Mempool::new(1_024));
        // 120 frames from two senders through the restore path (no chain checks)
        let frames: Vec<SignedTx> = (0..120u64)
            .map(|n| SignedTx {
                sender: acct(1 + (n % 2) as u8),
                nonce: n,
                payload: Tx::Transfer { to: acct(9), asset: ASSET, amount: 1 },
                next_auth: H256([0; 32]),
                lamport_pk: vec![],
                sig: vec![],
            })
            .collect();
        assert_eq!(mempool.lock().unwrap().restore_unchecked(frames), (120, 0));
        let got = get_mempool(&mempool);
        // the reference: the txids of the pool's first 100 txs, in pool order
        let want: Vec<String> = mempool.lock().unwrap().iter().take(100).map(|t| hex::encode(txid(t))).collect();
        assert_eq!(got, json!({"result": {"count": 120, "txids": want}}));
        // a small pool: every id, in order
        let small = Mutex::new(Mempool::new(16));
        let one = transfer(1, 0);
        small.lock().unwrap().try_admit(one.clone(), &mini_chain(1)).unwrap();
        assert_eq!(get_mempool(&small), json!({"result": {"count": 1, "txids": [hex::encode(txid(&one))]}}));
        assert_eq!(get_mempool(&Mutex::new(Mempool::new(4))), json!({"result": {"count": 0, "txids": []}}));
    }
}

/// R17 (reported 2026-10-06): L-5 — the pool feed is paged under its lock and a page is a
/// slice of the feed; L-6 — the operator submits refuse for free before the SLH-DSA verify,
/// verify with no lock held, and answer "busy" past the verify slots. `SharedHandles` needs
/// a genesis and a signer (`HkApp::new`), so the handler bodies are driven here over the
/// handles they take; `dispatch`'s `params.cert` plumbing around them is unchanged and is
/// exercised by gate-h3 / gate-v1 / gate-g1 against a live devnet.
#[cfg(test)]
mod r17_tests {
    use super::*;
    use hk_consensus::rotation::RotationDomain;
    use hk_consensus::{Approval, HkPub, HkValidator, RootSecret, SetChangeBody};
    use tokio::sync::Semaphore;

    const CHAIN: &str = "hashkinetics-test";

    /// SLH-DSA operations allocate large fixed arrays — anything that reaches the verifier
    /// runs on the stack the node gives its workers (main.rs: 32 MiB).
    fn on_big_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new().stack_size(32 * 1024 * 1024).spawn(f).unwrap().join().unwrap();
    }

    fn feed_of(tag: u8, n: u8) -> PoolFeed {
        (0..n).map(|i| (H256([tag ^ i; 32]), vec![tag, i, i, i, i])).collect()
    }

    fn accepted(v: &Value) -> Option<bool> {
        v.get("result")?.get("accepted")?.as_bool()
    }
    fn queued(v: &Value) -> Option<bool> {
        v.get("result")?.get("queued")?.as_bool()
    }
    fn reason(v: &Value) -> String {
        v.get("result").and_then(|r| r.get("reason")).and_then(|r| r.as_str()).unwrap_or("").to_string()
    }
    fn error(v: &Value) -> String {
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string()
    }

    #[test]
    fn l5_pool_pages_are_slices_of_the_feed_and_chain_to_the_end() {
        let chain = Mutex::new(hk_state::State::default());
        let legacy_feed = feed_of(0x10, 7);
        let asset = H256([0xaa; 32]);
        let asset_feed = feed_of(0x20, 5);
        let legacy = Mutex::new(legacy_feed.clone());
        let by_asset = Mutex::new(BTreeMap::from([(asset, asset_feed.clone())]));
        let notes = |params: &Value| {
            with_pool_feed(&chain, &legacy, &by_asset, params, |feed| page_of(feed, params, |(l, ct)| (*l, ct.clone())))
        };

        // legacy pool: a page is exactly feed[from..to], with the H3 cursor arithmetic
        let (p, asset_label) = notes(&json!({"limit": 3})).unwrap();
        assert_eq!(asset_label, None);
        assert_eq!((p.from, p.to, p.total, p.next), (0, 3, 7, Some(3)));
        assert_eq!(p.items, legacy_feed[0..3].to_vec());
        let (p, _) = notes(&json!({"from": 3, "limit": 3})).unwrap();
        assert_eq!((p.from, p.to, p.next), (3, 6, Some(6)));
        assert_eq!(p.items, legacy_feed[3..6].to_vec());
        let (p, _) = notes(&json!({"from": 6, "limit": 3})).unwrap();
        assert_eq!((p.from, p.to, p.next), (6, 7, None));
        assert_eq!(p.items, legacy_feed[6..7].to_vec());
        // past the end: an empty page, no next (a wallet whose cursor == total asks this)
        let (p, _) = notes(&json!({"from": 99})).unwrap();
        assert_eq!((p.from, p.to, p.total, p.next), (7, 7, 7, None));
        assert!(p.items.is_empty());
        // pages concatenate to the whole feed
        let (mut cursor, mut all) = (Some(0usize), Vec::new());
        while let Some(from) = cursor {
            let (p, _) = notes(&json!({"from": from, "limit": 2})).unwrap();
            all.extend(p.items);
            cursor = p.next;
        }
        assert_eq!(all, legacy_feed);

        // by-asset arm: its own feed, labelled; an asset without a pool is an empty feed
        let (p, asset_label) = notes(&json!({"asset": hex::encode(asset.0), "from": 2, "limit": 2})).unwrap();
        assert_eq!(asset_label, Some(hex::encode(asset.0)));
        assert_eq!((p.from, p.to, p.total, p.next), (2, 4, 5, Some(4)));
        assert_eq!(p.items, asset_feed[2..4].to_vec());
        let other = H256([0xbb; 32]);
        let (p, asset_label) = notes(&json!({"asset": hex::encode(other.0)})).unwrap();
        assert_eq!(asset_label, Some(hex::encode(other.0)));
        assert_eq!((p.from, p.to, p.total, p.next), (0, 0, 0, None));
        assert_eq!(notes(&json!({"asset": "zz"})).unwrap_err(), "asset must be 64-char hex");

        // the leaves-only copy hk_getPoolPath makes: every commitment, nothing else
        let (leaves, _) = with_pool_feed(&chain, &legacy, &by_asset, &json!({}), |feed| {
            feed.iter().map(|(l, _)| l.0).collect::<Vec<[u8; 32]>>()
        })
        .unwrap();
        assert_eq!(leaves, legacy_feed.iter().map(|(l, _)| l.0).collect::<Vec<_>>());
        // and the leaves page projects the same commitments
        let (p, _) = with_pool_feed(&chain, &legacy, &by_asset, &json!({"from": 1, "limit": 4}), |feed| {
            page_of(feed, &json!({"from": 1, "limit": 4}), |(l, _)| l.0)
        })
        .unwrap();
        assert_eq!(p.items, leaves[1..5].to_vec());
    }

    #[test]
    fn l5_pool_path_is_bounded_by_its_slots_and_folds_to_the_root() {
        // R17 review (2026-10-06): the full-feed leaf copy + O(n) tree build of
        // hk_getPoolPath hold one of POOL_PATH_SLOTS; past the bound the caller is told to
        // retry and the feed lock is never taken.
        let chain = Mutex::new(hk_state::State::default());
        let legacy_feed = feed_of(0x10, 5);
        let legacy = Mutex::new(legacy_feed.clone());
        let by_asset = Mutex::new(BTreeMap::new());
        let no_slots = Semaphore::new(0);
        let r = pool_path(&chain, &legacy, &by_asset, &no_slots, &json!({"index": 0}));
        assert!(error(&r).contains("busy: 2 pool-path builds"), "{r}");
        // a missing index is refused before a slot is needed
        let r = pool_path(&chain, &legacy, &by_asset, &no_slots, &json!({}));
        assert!(error(&r).contains("index (leaf index, integer) required"), "{r}");

        // with slots: the answer is `full_tree_path` over the bare leaves, shape unchanged,
        // and the slot comes back
        let slots = Semaphore::new(POOL_PATH_SLOTS);
        let leaves: Vec<[u8; 32]> = legacy_feed.iter().map(|(l, _)| l.0).collect();
        let (siblings, root) = hk_state::pool::full_tree_path(&leaves, 3);
        let r = pool_path(&chain, &legacy, &by_asset, &slots, &json!({"index": 3}));
        assert_eq!(r["result"]["index"], json!(3), "{r}");
        assert_eq!(r["result"]["commitment"], json!(hex::encode(leaves[3])));
        assert_eq!(r["result"]["root"], json!(hex::encode(root)));
        assert_eq!(r["result"]["total"], json!(5));
        assert_eq!(r["result"]["asset"], Value::Null);
        let got: Vec<String> =
            r["result"]["siblings"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();
        assert_eq!(got, siblings.iter().map(hex::encode).collect::<Vec<_>>());
        assert_eq!(slots.available_permits(), POOL_PATH_SLOTS);
        // out of range: refused, and the slot still comes back
        let r = pool_path(&chain, &legacy, &by_asset, &slots, &json!({"index": 5}));
        assert!(error(&r).contains("out of range (pool has 5 commitments)"), "{r}");
        assert_eq!(slots.available_permits(), POOL_PATH_SLOTS);
        // an asset without a pool is an empty feed: every index is out of range
        let r = pool_path(&chain, &legacy, &by_asset, &slots, &json!({"asset": hex::encode([0xbb; 32]), "index": 0}));
        assert!(error(&r).contains("pool has 0 commitments"), "{r}");
        assert_eq!(slots.available_permits(), POOL_PATH_SLOTS);
    }

    fn one_seat(seed: u8, epoch: u64) -> (RootSecret, HkValidator) {
        let root = RootSecret::from_seed(&[seed; 32]);
        let mut v = HkValidator::new(root.public_bytes().to_vec(), HkPub(vec![seed; 60]), 1);
        v.epoch = epoch;
        (root, v)
    }

    fn garbage_rotation(root_pk: Vec<u8>, epoch: u64, sig_len: usize) -> RotationCert {
        RotationCert { root_pk, new_op_pk: HkPub(vec![7u8; 60]), epoch, valid_from_height: 0, root_sig: vec![0u8; sig_len] }
    }

    /// The v0.19.4 rule: a chain that never activates v2, judged at tip + 1 = 101.
    const V1_RULES: RotationRules<'static> = RotationRules { height: 101, chain_id: CHAIN, v2_from: u64::MAX };
    /// The devnet rule: v2 from genesis, judged at tip + 1.
    fn v2_rules(tip: u64) -> RotationRules<'static> {
        RotationRules::new(tip + 1, CHAIN, 0)
    }

    #[test]
    fn l6_rotation_free_refusals_come_before_the_verify_and_the_slot() {
        let (_, seat) = one_seat(1, 3);
        let root = seat.root_pk.clone();
        let validators = Mutex::new(HkValidatorSet::new([seat]));
        let queue = Mutex::new(Vec::new());
        // zero permits: anything that reaches the verifier answers "busy" — so every
        // refusal below provably happened before the slot (and the verify) was needed
        let no_slots = Semaphore::new(0);

        let r = submit_rotation(&validators, &queue, &no_slots, &V1_RULES, garbage_rotation(vec![9u8; ROOT_PK_LEN], 4, ROOT_SIG_LEN));
        assert_eq!(accepted(&r), Some(false));
        assert!(reason(&r).contains("no validator with that root identity"), "{r}");
        for stale in [0, 2, 3] {
            let r = submit_rotation(&validators, &queue, &no_slots, &V1_RULES, garbage_rotation(root.clone(), stale, ROOT_SIG_LEN));
            assert_eq!(accepted(&r), Some(false));
            assert!(reason(&r).contains("stale (cert epoch"), "{r}");
        }
        let r = submit_rotation(&validators, &queue, &no_slots, &V1_RULES, garbage_rotation(root.clone(), 4, 10));
        assert_eq!(accepted(&r), Some(false));
        assert!(reason(&r).contains("root_sig must be"), "{r}");
        assert!(queue.lock().unwrap().is_empty());

        // a well-shaped cert that passes every free check needs a slot: none → busy, nothing queued
        let r = submit_rotation(&validators, &queue, &no_slots, &V1_RULES, garbage_rotation(root.clone(), 4, ROOT_SIG_LEN));
        assert!(error(&r).contains("busy"), "{r}");
        assert!(queue.lock().unwrap().is_empty());

        // L-2: under v2 the valid_from_height window is a free refusal too — from the
        // future, or older than the horizon, never reaches the verifier. At the RPC the
        // rule sits at tip + 1 (the earliest block the cert can commit in), so the
        // activation it is judged against is tip + 2: naming that height is fine, one
        // past it is "from the future".
        let tip = 500_000u64;
        let mut future = garbage_rotation(root.clone(), 4, ROOT_SIG_LEN);
        future.valid_from_height = tip + 3;
        let r = submit_rotation(&validators, &queue, &no_slots, &v2_rules(tip), future);
        assert_eq!(accepted(&r), Some(false));
        assert!(reason(&r).contains("valid_from_height 500003 is past its activation height 500002"), "{r}");
        let mut edge = garbage_rotation(root.clone(), 4, ROOT_SIG_LEN);
        edge.valid_from_height = tip + 2;
        let r = submit_rotation(&validators, &queue, &no_slots, &v2_rules(tip), edge);
        assert!(error(&r).contains("busy"), "{r}"); // inside the window → the verify's turn
        let mut old = garbage_rotation(root.clone(), 4, ROOT_SIG_LEN);
        old.valid_from_height = tip + 1 - hk_consensus::rotation::ROTATION_FRESHNESS_HORIZON - 1;
        let r = submit_rotation(&validators, &queue, &no_slots, &v2_rules(tip), old);
        assert_eq!(accepted(&r), Some(false));
        assert!(reason(&r).contains("stale — valid_from_height"), "{r}");
        // the same values under the v1 rule are not read at all (v0.19.4 behaviour): busy
        let mut legacy = garbage_rotation(root.clone(), 4, ROOT_SIG_LEN);
        legacy.valid_from_height = tip + 2;
        let r = submit_rotation(&validators, &queue, &no_slots, &V1_RULES, legacy);
        assert!(error(&r).contains("busy"), "{r}");
        // inside the window it is the verify's turn: busy
        let mut fresh = garbage_rotation(root.clone(), 4, ROOT_SIG_LEN);
        fresh.valid_from_height = tip + 1;
        let r = submit_rotation(&validators, &queue, &no_slots, &v2_rules(tip), fresh);
        assert!(error(&r).contains("busy"), "{r}");
        assert!(queue.lock().unwrap().is_empty());

        // dedup precedes the verify: with a cert for this root at epoch 4 already queued, a
        // garbage epoch-4 copy is "already queued" — never verified, never a slot
        queue.lock().unwrap().push(garbage_rotation(root.clone(), 4, ROOT_SIG_LEN));
        let r = submit_rotation(&validators, &queue, &no_slots, &V1_RULES, garbage_rotation(root.clone(), 4, ROOT_SIG_LEN));
        assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(false)));
        assert_eq!(queue.lock().unwrap().len(), 1);
        // but a NEWER epoch is not a duplicate — it needs the slot
        let r = submit_rotation(&validators, &queue, &no_slots, &V1_RULES, garbage_rotation(root, 5, ROOT_SIG_LEN));
        assert!(error(&r).contains("busy"), "{r}");
        assert_eq!(queue.lock().unwrap().len(), 1);
    }

    #[test]
    fn l6_rotation_verify_runs_outside_the_lock_and_returns_its_slot() {
        on_big_stack(|| {
            let (root, seat) = one_seat(1, 3);
            let root_pk = seat.root_pk.clone();
            let validators = Mutex::new(HkValidatorSet::new([seat]));
            let queue = Mutex::new(Vec::new());
            let slots = Semaphore::new(CERT_VERIFY_SLOTS);

            // garbage signature of the right size: the verify runs, fails, the slot comes back
            let r = submit_rotation(&validators, &queue, &slots, &V1_RULES, garbage_rotation(root_pk.clone(), 4, ROOT_SIG_LEN));
            assert_eq!(accepted(&r), Some(false));
            assert!(reason(&r).contains("invalid or stale"), "{r}");
            assert!(queue.lock().unwrap().is_empty());
            assert_eq!(slots.available_permits(), CERT_VERIFY_SLOTS);

            // a real cert: verified and queued once; a re-submit is "already queued"
            let c4 = RotationCert::issue(&root, RotationDomain::V1, "", HkPub(vec![4u8; 60]), 4, 0);
            let r = submit_rotation(&validators, &queue, &slots, &V1_RULES, c4.clone());
            assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(true)));
            assert_eq!(r["result"]["epoch"], json!(4));
            let r = submit_rotation(&validators, &queue, &slots, &V1_RULES, c4.clone());
            assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(false)));
            assert_eq!(queue.lock().unwrap().len(), 1);
            // a newer real cert retires the older queued copy
            let c5 = RotationCert::issue(&root, RotationDomain::V1, "", HkPub(vec![5u8; 60]), 5, 0);
            let r = submit_rotation(&validators, &queue, &slots, &V1_RULES, c5);
            assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(true)));
            {
                let q = queue.lock().unwrap();
                assert_eq!(q.len(), 1);
                assert_eq!(q[0].epoch, 5);
            }
            assert_eq!(slots.available_permits(), CERT_VERIFY_SLOTS);
        });
    }

    #[test]
    fn l2_rotation_rpc_demands_v2_from_the_height_and_names_a_v1_cert() {
        on_big_stack(|| {
            let (root, seat) = one_seat(1, 3);
            let validators = Mutex::new(HkValidatorSet::new([seat]));
            let queue = Mutex::new(Vec::new());
            let slots = Semaphore::new(CERT_VERIFY_SLOTS);
            let tip = 1_000u64;

            // a v1 cert (a ≤ v0.19.4 issuer, or `issue-rotation` without the chain id) on a
            // chain past its v2 height: the verify ran (slot taken and returned), the reason
            // says v1 so the operator re-issues instead of suspecting a forgery
            let v1 = RotationCert::issue(&root, RotationDomain::V1, "", HkPub(vec![4u8; 60]), 4, tip + 1);
            let r = submit_rotation(&validators, &queue, &slots, &v2_rules(tip), v1.clone());
            assert_eq!(accepted(&r), Some(false));
            assert!(reason(&r).contains("signed under the v1 domain"), "{r}");
            assert!(reason(&r).contains("issue-rotation <HOME> 4 <TIP+1> hashkinetics-test"), "{r}");
            assert!(queue.lock().unwrap().is_empty());
            assert_eq!(slots.available_permits(), CERT_VERIFY_SLOTS);

            // a v2 cert for ANOTHER chain: refused (the chain id is in the signed bytes)
            let elsewhere = RotationCert::issue(&root, RotationDomain::V2, "hashkinetics-1-deadbeef", HkPub(vec![4u8; 60]), 4, tip + 1);
            let r = submit_rotation(&validators, &queue, &slots, &v2_rules(tip), elsewhere);
            assert_eq!(accepted(&r), Some(false));
            assert!(reason(&r).contains("v2 domain, chain hashkinetics-test"), "{r}");
            assert!(queue.lock().unwrap().is_empty());

            // the same seat's v2 cert for this chain, issued at the tip: queued
            let v2 = RotationCert::issue_for(&root, CHAIN, 0, HkPub(vec![4u8; 60]), 4, tip + 1);
            let r = submit_rotation(&validators, &queue, &slots, &v2_rules(tip), v2.clone());
            assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(true)));
            assert_eq!(queue.lock().unwrap().len(), 1);
            // and the v1 copy is refused on a chain BEFORE its height only as "not v1" would
            // be — i.e. the v2 cert is refused there, the v1 one is what that chain takes
            let before = RotationRules::new(tip + 1, CHAIN, u64::MAX);
            let queue2 = Mutex::new(Vec::new());
            let r = submit_rotation(&validators, &queue2, &slots, &before, v2);
            assert_eq!(accepted(&r), Some(false));
            assert!(reason(&r).contains("invalid or stale (cert epoch 4, current 3)"), "{r}");
            let r = submit_rotation(&validators, &queue2, &slots, &before, v1);
            assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(true)));
            assert_eq!(slots.available_permits(), CERT_VERIFY_SLOTS);
        });
    }

    fn admit_body(root_pk: Vec<u8>, key: u8, not_before: u64, not_after: u64) -> SetChangeBody {
        SetChangeBody {
            chain_id: CHAIN.into(),
            change: SetChange::Admit { root_pk, public_key: HkPub(vec![key; 60]), voting_power: 1 },
            not_before,
            not_after,
        }
    }

    fn garbage_approvals(seats: &[&HkValidator]) -> Vec<Approval> {
        seats.iter().map(|v| Approval { root_pk: v.root_pk.clone(), root_sig: vec![0u8; ROOT_SIG_LEN] }).collect()
    }

    #[test]
    fn l6_set_change_free_refusals_come_before_the_verify_and_the_slot() {
        let tip = 100u64;
        let (_, s1) = one_seat(1, 0);
        let (_, s2) = one_seat(2, 0);
        let (_, s3) = one_seat(3, 0);
        let validators = Mutex::new(HkValidatorSet::new([s1.clone(), s2.clone(), s3.clone()]));
        let queue = Mutex::new(Vec::new());
        let no_slots = Semaphore::new(0);
        let newcomer = RootSecret::from_seed(&[9u8; 32]).public_bytes().to_vec();
        let all3 = garbage_approvals(&[&s1, &s2, &s3]);
        let submit = |body: SetChangeBody, approvals: Vec<Approval>| {
            submit_set_change(&validators, &queue, &no_slots, CHAIN, tip, SetChangeCert { body, approvals })
        };
        let refuses = |body: SetChangeBody, approvals: Vec<Approval>, needle: &str| {
            let r = submit(body, approvals);
            assert_eq!(accepted(&r), Some(false), "{r}");
            assert!(reason(&r).contains(needle), "wanted {needle:?} in {r}");
        };

        // shape, chain id, window — none of them looks at the set
        refuses(admit_body(newcomer.clone(), 9, 150, 140), all3.clone(), "not_after < not_before");
        let mut wrong = admit_body(newcomer.clone(), 9, 101, 500);
        wrong.chain_id = "hashkinetics-1-deadbeef".into();
        refuses(wrong, all3.clone(), "for chain hashkinetics-1-deadbeef — this is hashkinetics-test");
        refuses(admit_body(newcomer.clone(), 9, 1, 99), all3.clone(), "window closed: not_after 99 < tip 100");
        refuses(
            admit_body(newcomer.clone(), 9, tip + SET_CHANGE_HORIZON + 1, u64::MAX),
            all3.clone(),
            "window too far ahead",
        );
        // approvals: present, well-sized, distinct, seated, > 2/3
        refuses(admit_body(newcomer.clone(), 9, 101, 500), vec![], "no approvals");
        refuses(
            admit_body(newcomer.clone(), 9, 101, 500),
            vec![Approval { root_pk: s1.root_pk.clone(), root_sig: vec![0u8; 5] }],
            "SLH-DSA-192s signature",
        );
        refuses(admit_body(newcomer.clone(), 9, 101, 500), garbage_approvals(&[&s1, &s1, &s2]), "duplicate approval");
        let (_, stranger) = one_seat(8, 0);
        refuses(admit_body(newcomer.clone(), 9, 101, 500), garbage_approvals(&[&s1, &s2, &stranger]), "not seated");
        refuses(admit_body(newcomer.clone(), 9, 101, 500), garbage_approvals(&[&s1, &s2]), "approving power 2 is not > 2/3 of 3");
        // the subject, as commit would judge it
        refuses(admit_body(s1.root_pk.clone(), 1, 101, 500), all3.clone(), "already applied — that root is seated");
        refuses(admit_body(newcomer.clone(), 1, 101, 500), all3.clone(), "operational key collides");
        let mut rm = admit_body(newcomer.clone(), 9, 101, 500);
        rm.change = SetChange::Remove { root_pk: newcomer.clone() };
        refuses(rm, all3.clone(), "already applied — that root is not seated");
        let mut sp = admit_body(newcomer.clone(), 9, 101, 500);
        sp.change = SetChange::SetPower { root_pk: newcomer.clone(), voting_power: 2 };
        refuses(sp, all3.clone(), "set-power for a root that is not seated");
        let mut same = admit_body(newcomer.clone(), 9, 101, 500);
        same.change = SetChange::SetPower { root_pk: s1.root_pk.clone(), voting_power: 1 };
        refuses(same, all3.clone(), "already applied — that seat already weighs 1");
        assert!(queue.lock().unwrap().is_empty());

        // every free check passes → a slot is needed: none → busy, nothing queued
        let good = admit_body(newcomer.clone(), 9, 101, 500);
        let r = submit(good.clone(), all3.clone());
        assert!(error(&r).contains("busy"), "{r}");
        assert!(queue.lock().unwrap().is_empty());

        // dedup precedes the verify: an identical body already queued → "already queued",
        // the garbage approvals are never verified and no slot is taken
        queue.lock().unwrap().push(SetChangeCert { body: good.clone(), approvals: all3.clone() });
        let r = submit(good, all3);
        assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(false)));
        assert_eq!(r["result"]["approvals"], json!(3));
        assert_eq!(r["result"]["window"], json!([101, 500]));
        assert_eq!(queue.lock().unwrap().len(), 1);
    }

    #[test]
    fn l6_set_change_verify_runs_outside_the_lock_and_returns_its_slot() {
        on_big_stack(|| {
            let tip = 10u64;
            let (root1, s1) = one_seat(1, 0);
            let validators = Mutex::new(HkValidatorSet::new([s1.clone()]));
            let queue = Mutex::new(Vec::new());
            let slots = Semaphore::new(CERT_VERIFY_SLOTS);
            let newcomer = RootSecret::from_seed(&[2u8; 32]).public_bytes().to_vec();
            let body = admit_body(newcomer, 2, tip + 1, tip + 400);

            // a garbage signature of the right size: the verify runs, fails, the slot comes back
            let r = submit_set_change(&validators, &queue, &slots, CHAIN, tip, SetChangeCert {
                body: body.clone(),
                approvals: garbage_approvals(&[&s1]),
            });
            assert_eq!(accepted(&r), Some(false));
            assert!(reason(&r).contains("invalid approval signature"), "{r}");
            assert!(queue.lock().unwrap().is_empty());
            assert_eq!(slots.available_permits(), CERT_VERIFY_SLOTS);

            // a real 1-of-1 approval: verified and queued once; a re-submit is "already queued"
            let cert = SetChangeCert { body: body.clone(), approvals: vec![Approval::sign(&root1, &body)] };
            let r = submit_set_change(&validators, &queue, &slots, CHAIN, tip, cert.clone());
            assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(true)));
            assert_eq!(r["result"]["approvals"], json!(1));
            assert_eq!(r["result"]["window"], json!([11, 410]));
            let r = submit_set_change(&validators, &queue, &slots, CHAIN, tip, cert);
            assert_eq!((accepted(&r), queued(&r)), (Some(true), Some(false)));
            assert_eq!(queue.lock().unwrap().len(), 1);
            assert_eq!(slots.available_permits(), CERT_VERIFY_SLOTS);
        });
    }
}

/// HR-1 (mr-hrydarie, reported 2026-11-04, confirmed 2026-11-08): `hk_submitBundle` queued a
/// bundle for the proposer after a shape check only — no envelope, sender, nonce, anchor or
/// nullifier check, no bound on the aggregate bytes but the 8 MiB body cap — and the commit
/// prune evicted a victim's pending tx on a refused bundle tx's (sender, nonce) (that half is
/// mempool.rs `hr1_a_refused_twin_does_not_evict_the_victims_pending_tx` and state.rs
/// `hr1_tests`). `submit_bundle` is driven here over the handles it takes, as `r17_tests`
/// drives the operator submits, and `dispatch` itself over `SharedHandles::for_tests`. The
/// chain and the signers are the shared fixture (`mempool::test_fixtures`): genesis accounts
/// behind real L-ratchet commitments, funded, the genesis pool's first anchor as the recent
/// anchor, `demo::Wallet` (the faucet's and the CLI's signer) signing at any ratchet position.
/// A zero-permit `Semaphore` stands for "an admission is in flight": a refusal that still comes
/// back through it provably happened before the slot.
#[cfg(test)]
mod hr1_tests {
    use super::*;
    use crate::mempool::test_fixtures::*;
    use crate::mempool::AdmitError;
    use tokio::sync::Semaphore;

    type Queue = Mutex<Vec<(Vec<SignedTx>, Vec<u8>)>>;

    /// The report's frame: no key, no signature, an arbitrary sender at nonce 0, empty fields.
    fn keyless_frame(i: usize) -> SignedTx {
        let mut nf = [0u8; 32];
        nf[..8].copy_from_slice(&(i as u64).to_le_bytes());
        SignedTx {
            sender: H256([0xAB; 32]),
            nonce: 0,
            payload: Tx::ShieldedSpend {
                anchor: H256([0; 32]),
                nullifier: H256(nf),
                out_commitment: H256([0; 32]),
                out2_commitment: H256([0; 32]),
                fee: 0,
                credit: None,
                mandate: None,
                proof: vec![],
                stealth_ct: vec![],
                stealth_ct2: vec![],
            },
            next_auth: H256([0; 32]),
            lamport_pk: vec![],
            sig: vec![],
        }
    }
    /// A stand-in aggregate: the door reads its length and its identity only (verifying it at
    /// submit is not in this release).
    fn agg(tag: u8) -> Vec<u8> {
        vec![tag; 64]
    }
    fn params(txs: &[SignedTx], agg: &[u8]) -> Value {
        json!({"txs": serde_json::to_value(txs).unwrap(), "agg_proof": hex::encode(agg)})
    }
    fn submit(open: bool, chain: &Mutex<hk_state::State>, q: &Queue, slots: &Semaphore, txs: &[SignedTx], agg: &[u8]) -> Value {
        submit_bundle(&params(txs, agg), open, chain, q, slots)
    }
    fn error(v: &Value) -> String {
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string()
    }
    fn accepted(v: &Value) -> bool {
        v["result"]["accepted"] == json!(true)
    }
    fn would_not_apply(i: usize, e: AdmitError) -> String {
        format!("bad txs: tx {i} would not apply: {}", e.as_str())
    }
    fn ids(txs: &[SignedTx]) -> Vec<String> {
        txs.iter().map(|t| hex::encode(txid(t))).collect()
    }
    fn agg_too_large_msg(bytes: usize) -> String {
        format!("bad agg_proof: {bytes} bytes (max {MAX_BUNDLE_AGG_BYTES} — an aggregate STARK is ~1,242 KB)")
    }
    const CLOSED: &str = "hk_submitBundle is closed on this node (hk_rpc.accept_bundles = false): there is no aggregator role yet — a devnet opens it with accept_bundles = true or HK_RPC_ACCEPT_BUNDLES=1";
    const E3: &str = "a proof-less pool tx can only be covered by a bundle's aggregate — submit it through hk_submitBundle";

    /// Kill: drop the `open` check from `submit_bundle` (or default `accept_bundles` to true)
    /// and a networked seat queues any stranger's bundle for its next block again.
    #[test]
    fn hr1_the_bundle_door_is_closed_by_default() {
        // the default the door reads from config.toml (handles() sets the same false)
        assert!(!crate::config::HkRpcConfig::default().accept_bundles);
        let chain = Mutex::new(mini_chain(1));
        let q: Queue = Mutex::new(Vec::new());
        let bundle = demo_bundle(&chain.lock().unwrap(), 1, 0x10);
        // zero permits and garbage params alike: the closed door answers before the parse,
        // before every check and before the slot — a closed door costs nothing
        let no_slots = Semaphore::new(0);
        for p in [params(&bundle, &agg(1)), json!({}), json!({"txs": "garbage", "agg_proof": "zz"}), Value::Null] {
            let r = submit_bundle(&p, false, &chain, &q, &no_slots);
            assert_eq!(error(&r), CLOSED, "{r}");
        }
        assert!(q.lock().unwrap().is_empty());
        // the same bundle through the open door, with a slot: queued — the switch is the door
        let r = submit(true, &chain, &q, &Semaphore::new(1), &bundle, &agg(1));
        assert!(accepted(&r), "{r}");
        assert_eq!(q.lock().unwrap().len(), 1);
    }

    /// Kill: drop `bundles_open(h)` from the `hk_submitBundle` arm of `dispatch` (pass `true`)
    /// and (a) fails — a networked seat's door is open; drop the env-var half of
    /// `bundles_open` and (c) fails; dry-run on `h.mempool` instead of a scratch pool and the
    /// live-pool assertion in (b) fails. ONE test drives `dispatch` for this method:
    /// HK_RPC_ACCEPT_BUNDLES is process-global, so a second test setting it would race this one.
    #[test]
    #[allow(non_snake_case)]
    fn hr1_dispatch_hk_submitBundle_follows_the_switch_and_never_touches_the_live_pool() {
        // this test owns HK_RPC_ACCEPT_BUNDLES for the process: a shell that exports it (the
        // devnet convenience) must not turn (a) into a failure unrelated to the code
        std::env::remove_var("HK_RPC_ACCEPT_BUNDLES");
        let mut h = SharedHandles::for_tests(mini_chain(3));
        let bundle = demo_bundle(&h.chain.lock().unwrap(), 1, 0x10);
        let second = demo_bundle(&h.chain.lock().unwrap(), 2, 0x60);
        let third = demo_bundle(&h.chain.lock().unwrap(), 3, 0x70);
        let a = anchor(&h.chain.lock().unwrap());
        // (a) the default handles: closed, before the params are read
        assert!(!h.accept_bundles);
        for p in [params(&bundle, &agg(1)), json!({}), Value::Null] {
            let r = dispatch("hk_submitBundle", &p, &h);
            assert_eq!(error(&r), CLOSED, "{r}");
        }
        assert!(h.bundles.lock().unwrap().is_empty());
        // (b) the operator's switch: a demo-shaped bundle queues; the LIVE mempool saw nothing;
        // the slot came back
        h.accept_bundles = true;
        let r = dispatch("hk_submitBundle", &params(&bundle, &agg(1)), &h);
        assert!(accepted(&r), "{r}");
        assert_eq!(r["result"]["txids"], json!(ids(&bundle)));
        assert_eq!(h.bundles.lock().unwrap().len(), 1);
        assert_eq!(h.mempool.lock().unwrap().len(), 0, "nothing from a bundle enters the live pool");
        assert_eq!(BUNDLE_ADMIT.available_permits(), 1);
        // a refused bundle through dispatch: hk_submitTx's reason, nothing queued, the slot back
        let wrong_key = vec![sign_as(2, 3, 0, spend_payload(a, 0x20))];
        let r = dispatch("hk_submitBundle", &params(&wrong_key, &agg(2)), &h);
        assert_eq!(error(&r), would_not_apply(0, AdmitError::AuthMismatch), "{r}");
        assert_eq!(h.bundles.lock().unwrap().len(), 1);
        assert_eq!(BUNDLE_ADMIT.available_permits(), 1);
        // (c) the env var opens a closed door for one process, and closes it again when unset
        h.accept_bundles = false;
        assert_eq!(error(&dispatch("hk_submitBundle", &params(&second, &agg(3)), &h)), CLOSED);
        std::env::set_var("HK_RPC_ACCEPT_BUNDLES", "1");
        let r = dispatch("hk_submitBundle", &params(&second, &agg(3)), &h);
        std::env::remove_var("HK_RPC_ACCEPT_BUNDLES");
        assert!(accepted(&r), "{r}");
        assert_eq!(h.bundles.lock().unwrap().len(), 2);
        assert_eq!(error(&dispatch("hk_submitBundle", &params(&third, &agg(4)), &h)), CLOSED);
        assert_eq!(h.bundles.lock().unwrap().len(), 2);
        assert_eq!(h.mempool.lock().unwrap().len(), 0);
        assert_eq!(BUNDLE_ADMIT.available_permits(), 1);
        // the queue holds what was submitted, whole — what `build_batch` rides
        let q = h.bundles.lock().unwrap();
        assert_eq!(q[0].0.iter().map(txid).collect::<Vec<_>>(), bundle.iter().map(txid).collect::<Vec<_>>());
        assert_eq!(q[0].1, agg(1));
        assert_eq!(q[1].0.iter().map(txid).collect::<Vec<_>>(), second.iter().map(txid).collect::<Vec<_>>());
        assert_eq!(q[1].1, agg(3));
    }

    /// Kill: judge the 2nd and 3rd spend against the chain's nonce instead of the scratch
    /// pool's ratchet (NonceGap) and the demo-shaped bundle stops queueing. (A dry run on the
    /// LIVE pool is invisible here — this test takes no mempool handle;
    /// `hr1_dispatch_hk_submitBundle_follows_the_switch_and_never_touches_the_live_pool`
    /// catches it.)
    #[test]
    fn hr1_the_switch_opens_the_door_for_a_demo_shaped_bundle() {
        let chain = Mutex::new(mini_chain(2));
        let q: Queue = Mutex::new(Vec::new());
        let slots = Semaphore::new(1);
        let bundle = demo_bundle(&chain.lock().unwrap(), 1, 0x10);
        let r = submit(true, &chain, &q, &slots, &bundle, &agg(1));
        assert!(accepted(&r), "{r}");
        let got: Vec<String> =
            r["result"]["txids"].as_array().unwrap().iter().map(|t| t.as_str().unwrap().to_string()).collect();
        assert_eq!(got, ids(&bundle));
        {
            let q = q.lock().unwrap();
            assert_eq!(q.len(), 1);
            assert_eq!(q[0].0.iter().map(txid).collect::<Vec<_>>(), bundle.iter().map(txid).collect::<Vec<_>>());
            assert_eq!(q[0].1, agg(1));
        }
        // the slot came back
        assert_eq!(slots.available_permits(), 1);
        // the dry run applied nothing: the account's nonce and the pool's nullifiers are as at
        // genesis — and the LIVE mempool is untouchable from here by construction
        // (`submit_bundle` takes no mempool handle; the scratch pool dies with the chain lock;
        // the dispatch test above asserts it on the real handles)
        {
            let c = chain.lock().unwrap();
            assert_eq!(c.accounts[&acct(1)].nonce, 0);
            assert!(c.pool.nullifiers.is_empty());
        }
        // a shield rides a bundle too: a proof-less mint, then two spends, from another account
        let a = anchor(&chain.lock().unwrap());
        let mixed = vec![
            sign_at(2, 0, mint_payload(vec![0x5c; LEGIT_CT + 6])),
            sign_at(2, 1, sealed_spend_payload(a, 0x20, vec![0x5c; LEGIT_CT], vec![0x5c; LEGIT_CT])),
            sign_at(2, 2, sealed_spend_payload(a, 0x21, vec![0x5c; LEGIT_CT], vec![])),
        ];
        let r = submit(true, &chain, &q, &slots, &mixed, &agg(2));
        assert!(accepted(&r), "{r}");
        assert_eq!(q.lock().unwrap().len(), 2);
        assert_eq!(slots.available_permits(), 1);
    }

    /// Kill: drop the length rule from `bundle_shape_verdict` and the report's 1,024 keyless
    /// frames reach the slot (busy here; with a slot, the hashes and the chain lock).
    #[test]
    fn hr1_keyless_frames_are_refused_free_before_the_slot() {
        let chain = Mutex::new(mini_chain(1));
        let q: Queue = Mutex::new(Vec::new());
        // the permit is held by "an admission in flight": anything reaching the slot answers busy
        let no_slots = Semaphore::new(0);
        let frames: Vec<SignedTx> = (0..MAX_TXS_PER_BLOCK).map(keyless_frame).collect();
        let r = submit(true, &chain, &q, &no_slots, &frames, &agg(1));
        assert_eq!(
            error(&r),
            "bad txs: tx 0 has a malformed envelope (0 B pk, 0 B sig) — a bundle tx is account-signed like any other",
            "{r}"
        );
        // the rule reads both fields and names the lengths it saw
        let mut half = keyless_frame(0);
        half.lamport_pk = vec![0xAA; PK_LEN];
        let r = submit(true, &chain, &q, &no_slots, &[half], &agg(1));
        assert_eq!(
            error(&r),
            format!("bad txs: tx 0 has a malformed envelope ({PK_LEN} B pk, 0 B sig) — a bundle tx is account-signed like any other")
        );
        let mut long = keyless_frame(0);
        long.lamport_pk = vec![0xAA; PK_LEN + 1];
        long.sig = vec![0xBB; SIG_LEN];
        let r = submit(true, &chain, &q, &no_slots, &[long], &agg(1));
        assert!(error(&r).contains(&format!("({} B pk, {SIG_LEN} B sig)", PK_LEN + 1)), "{r}");
        // one more than a block: the R18 count rule first, still free
        let too_many: Vec<SignedTx> = (0..=MAX_TXS_PER_BLOCK).map(keyless_frame).collect();
        let r = submit(true, &chain, &q, &no_slots, &too_many, &agg(1));
        assert_eq!(error(&r), format!("bad txs: a bundle may carry at most {MAX_TXS_PER_BLOCK} txs (one block)"));
        // the position is named: a good tx 0 followed by a keyless tx 1
        let good = demo_bundle(&chain.lock().unwrap(), 1, 0x10);
        let r = submit(true, &chain, &q, &no_slots, &[good[0].clone(), keyless_frame(1)], &agg(1));
        assert!(error(&r).starts_with("bad txs: tx 1 has a malformed envelope"), "{r}");
        // and a good bundle with no slot answers busy — every refusal above came before it
        let r = submit(true, &chain, &q, &no_slots, &good, &agg(1));
        assert!(error(&r).starts_with("busy:"), "{r}");
        assert!(q.lock().unwrap().is_empty());
        // the same frames through `bundle_shape_verdict` directly; the R18 semantics intact
        assert!(bundle_shape_verdict(&frames).is_err());
        assert_eq!(bundle_shape_verdict(&good), Ok(()));
    }

    /// Kill: skip the scratch-pool dry run (queue after the shape check, as before v0.19.11)
    /// and every bundle below is queued for the proposer.
    #[test]
    fn hr1_right_length_junk_unknown_sender_and_wrong_key_are_refused() {
        let chain = Mutex::new(mini_chain(2));
        let q: Queue = Mutex::new(Vec::new());
        let slots = Semaphore::new(1);
        let a = anchor(&chain.lock().unwrap());
        // right-length junk keys for an unknown sender: the account walk's first refusal, worded
        // as hk_submitTx words it (the junk signature is judged after the account, not before)
        let mut junk = keyless_frame(0);
        junk.lamport_pk = vec![0xAA; PK_LEN];
        junk.sig = vec![0xBB; SIG_LEN];
        let r = submit(true, &chain, &q, &slots, &[junk], &agg(1));
        assert_eq!(error(&r), would_not_apply(0, AdmitError::UnknownSender), "{r}");
        // a known account signed under the wrong key: a VALID Lamport signature whose key does
        // not open the account's commitment
        let wrong_key = sign_as(1, 2, 0, spend_payload(a, 0x21));
        let r = submit(true, &chain, &q, &slots, &[wrong_key], &agg(1));
        assert_eq!(error(&r), would_not_apply(0, AdmitError::AuthMismatch), "{r}");
        // the account's own key, the signature zeroed: judged last, like at hk_submitTx
        let mut nosig = sign_at(1, 0, spend_payload(a, 0x22));
        nosig.sig = vec![0; SIG_LEN];
        let r = submit(true, &chain, &q, &slots, &[nosig], &agg(1));
        assert_eq!(error(&r), would_not_apply(0, AdmitError::BadSignature), "{r}");
        // an anchor no pool knows
        let stale = sign_at(1, 0, spend_payload(H256([0xAA; 32]), 0x23));
        let r = submit(true, &chain, &q, &slots, &[stale], &agg(1));
        assert_eq!(error(&r), would_not_apply(0, AdmitError::UnknownAnchor), "{r}");
        // a good tx 0 and a wrong-key tx 1 (along the pending ratchet): the position is named
        let good = sign_at(1, 0, spend_payload(a, 0x24));
        let bad_second = sign_as(1, 2, 1, spend_payload(a, 0x25));
        let r = submit(true, &chain, &q, &slots, &[good, bad_second], &agg(1));
        assert_eq!(error(&r), would_not_apply(1, AdmitError::AuthMismatch), "{r}");
        // nothing queued, the slot always came back, the chain untouched
        assert!(q.lock().unwrap().is_empty());
        assert_eq!(slots.available_permits(), 1);
        assert_eq!(chain.lock().unwrap().accounts[&acct(1)].nonce, 0);
    }

    /// Kill: drop the aggregate cap (or the stealth cap from `bundle_shape_verdict`) and the
    /// oversize bundles below reach the slot (`busy` here, with no permit; with a slot they
    /// queue — up to 8 MiB of aggregate per block into every node's log); drop the hex-length
    /// check (S3) alone and the two over-cap strings below are parsed first — the non-hex one
    /// answers `bad txs: …` (its garbage txs are judged first), the odd-length one
    /// `bad agg_proof hex: Odd number of digits` — instead of the size; the decoded-length
    /// check after the decode is the belt neither string reaches.
    #[test]
    fn hr1_the_aggregate_and_stealth_fields_are_bounded() {
        let chain = Mutex::new(mini_chain(1));
        let q: Queue = Mutex::new(Vec::new());
        let no_slots = Semaphore::new(0);
        let mib = 1024 * 1024;
        let bundle = demo_bundle(&chain.lock().unwrap(), 1, 0x10);
        // one byte over: refused by the size, before the slot
        let r = submit(true, &chain, &q, &no_slots, &bundle, &vec![0x11; MAX_BUNDLE_AGG_BYTES + 1]);
        assert_eq!(error(&r), agg_too_large_msg(MAX_BUNDLE_AGG_BYTES + 1), "{r}");
        // S3: the hex string's length is judged before it is decoded and before the txs are
        // parsed — an over-cap string that is not even hex, beside garbage txs, is refused by the
        // size (an odd digit counts as a whole byte)
        let not_hex = "zz".repeat(MAX_BUNDLE_AGG_BYTES + 1);
        let r = submit_bundle(&json!({"txs": "garbage", "agg_proof": not_hex}), true, &chain, &q, &no_slots);
        assert_eq!(error(&r), agg_too_large_msg(MAX_BUNDLE_AGG_BYTES + 1), "{r}");
        let odd = format!("{}f", "00".repeat(MAX_BUNDLE_AGG_BYTES));
        let r = submit_bundle(&params(&bundle, &[]).as_object().map(|o| {
            let mut o = o.clone();
            o.insert("agg_proof".into(), json!(odd));
            Value::Object(o)
        }).unwrap(), true, &chain, &q, &no_slots);
        assert_eq!(error(&r), agg_too_large_msg(MAX_BUNDLE_AGG_BYTES + 1), "{r}");
        // under the hex cap but not hex: the decode names it (the size check did not fire)
        let r = submit_bundle(&json!({"txs": serde_json::to_value(&bundle).unwrap(), "agg_proof": "zz"}), true, &chain, &q, &no_slots);
        assert!(error(&r).starts_with("bad agg_proof hex:"), "{r}");
        // the real thing's size — 1,242 KB — and exactly the cap are not refused by the size
        // check: with no slot they reach the slot (busy)
        for n in [1_242 * 1024, MAX_BUNDLE_AGG_BYTES] {
            let r = submit(true, &chain, &q, &no_slots, &bundle, &vec![0x22; n]);
            assert!(error(&r).starts_with("busy:"), "{n}: {r}");
        }
        // … and with a slot the 1,242 KB one queues
        let r = submit(true, &chain, &q, &Semaphore::new(1), &bundle, &vec![0x22; 1_242 * 1024]);
        assert!(accepted(&r), "{r}");
        // the stealth fields: one byte over on any of them is refused by the shape check, free
        let a = anchor(&chain.lock().unwrap());
        let over = MAX_STEALTH_CT_BYTES + 1;
        let cases = [
            sign_at(1, 0, sealed_spend_payload(a, 0x30, vec![0; over], vec![])),
            sign_at(1, 0, sealed_spend_payload(a, 0x31, vec![], vec![0; over])),
            sign_at(1, 0, mint_payload(vec![0; over])),
        ];
        for tx in cases {
            let r = submit(true, &chain, &q, &no_slots, &[tx], &agg(3));
            assert_eq!(
                error(&r),
                format!("bad txs: tx 0 carries a {over}-byte stealth ciphertext (max {MAX_STEALTH_CT_BYTES})"),
                "{r}"
            );
        }
        // a 1 MiB ciphertext names its size, and the position is named
        let big = sign_at(1, 1, mint_payload(vec![0; mib]));
        let r = submit(true, &chain, &q, &no_slots, &[bundle[0].clone(), big], &agg(3));
        assert_eq!(
            error(&r),
            format!("bad txs: tx 1 carries a {mib}-byte stealth ciphertext (max {MAX_STEALTH_CT_BYTES})")
        );
        // the legitimate size (1,192 B plus a memo) and exactly the cap pass the shape check
        let legit = sign_at(1, 0, sealed_spend_payload(a, 0x32, vec![0; LEGIT_CT + 8], vec![0; MAX_STEALTH_CT_BYTES]));
        assert_eq!(bundle_shape_verdict(&[legit]), Ok(()));
        assert_eq!(q.lock().unwrap().len(), 1);
    }

    /// Kill: drop the overlap check from `bundle_queue_verdict` and two bundles claiming one
    /// (sender, nonce) or one nullifier both reach the slot (`busy` here, with no permit; with a
    /// slot both queue) — the loser rides a later block as all-Err receipts (and, before E4,
    /// evicted the victim's pending tx with them).
    #[test]
    fn hr1_a_second_bundle_overlapping_a_queued_one_is_refused() {
        let chain = Mutex::new(mini_chain(3));
        let q: Queue = Mutex::new(Vec::new());
        let slots = Semaphore::new(1);
        let a = anchor(&chain.lock().unwrap());
        let first = demo_bundle(&chain.lock().unwrap(), 1, 0x10);
        let r = submit(true, &chain, &q, &slots, &first, &agg(1));
        assert!(accepted(&r), "{r}");
        let no_slots = Semaphore::new(0);
        // the same slot (account 1, nonce 0), a fresh nullifier, another aggregate: refused free
        let same_slot = vec![sign_at(1, 0, spend_payload(a, 0x40))];
        let r = submit(true, &chain, &q, &no_slots, &same_slot, &agg(2));
        assert_eq!(error(&r), "bad txs: a queued bundle already carries tx 0's (sender, nonce) slot or nullifier", "{r}");
        // another account, but its tx 1 reuses the first bundle's third nullifier: refused free,
        // the position named
        let same_nf = vec![sign_at(2, 0, spend_payload(a, 0x50)), sign_at(2, 1, spend_payload(a, 0x12))];
        let r = submit(true, &chain, &q, &no_slots, &same_nf, &agg(3));
        assert_eq!(error(&r), "bad txs: a queued bundle already carries tx 1's (sender, nonce) slot or nullifier", "{r}");
        // the same aggregate bytes again: the H4 dedup, still free
        let second = demo_bundle(&chain.lock().unwrap(), 2, 0x60);
        let r = submit(true, &chain, &q, &no_slots, &second, &agg(1));
        assert_eq!(error(&r), "duplicate bundle (same aggregate proof already queued)", "{r}");
        assert_eq!(q.lock().unwrap().len(), 1);
        // a disjoint bundle (account 2, fresh nullifiers, its own aggregate): queued behind the first
        let r = submit(true, &chain, &q, &slots, &second, &agg(4));
        assert!(accepted(&r), "{r}");
        assert_eq!(q.lock().unwrap().len(), 2);
        // the H4 cap, free: with the queue full, a disjoint honest bundle is refused by the cap
        {
            let mut qq = q.lock().unwrap();
            while qq.len() < BUNDLE_QUEUE_MAX {
                let i = qq.len();
                qq.push((vec![keyless_frame(i)], vec![i as u8; 3]));
            }
        }
        let third = demo_bundle(&chain.lock().unwrap(), 3, 0x70);
        let r = submit(true, &chain, &q, &no_slots, &third, &agg(5));
        assert_eq!(error(&r), format!("bundle queue full (max {BUNDLE_QUEUE_MAX}) — retry after the next block"), "{r}");
        assert_eq!(q.lock().unwrap().len(), BUNDLE_QUEUE_MAX);
    }

    /// Kill: delete the `bundle_queue_verdict` re-run from `push_bundle` and the three pushes
    /// below land — a bundle judged free before the slot would ride into a queue that filled,
    /// or took its aggregate, slot or nullifier, while the dry run held the chain lock.
    #[test]
    fn hr1_push_bundle_rechecks_the_queue_before_the_push() {
        let chain = mini_chain(3);
        let a = anchor(&chain);
        let first = demo_bundle(&chain, 1, 0x10);
        let mut q: Vec<(Vec<SignedTx>, Vec<u8>)> = vec![(first.clone(), agg(1))];
        // the queue already carries the slot (account 1, nonce 0) …
        let same_slot = vec![sign_at(1, 0, spend_payload(a, 0x40))];
        assert_eq!(
            push_bundle(&mut q, same_slot.clone(), agg(2), ids(&same_slot)),
            Err("bad txs: a queued bundle already carries tx 0's (sender, nonce) slot or nullifier".to_string())
        );
        // … the nullifier (the first bundle's third, 0x12, reused by tx 1 of another account) …
        let same_nf = vec![sign_at(2, 0, spend_payload(a, 0x50)), sign_at(2, 1, spend_payload(a, 0x12))];
        assert_eq!(
            push_bundle(&mut q, same_nf.clone(), agg(3), ids(&same_nf)),
            Err("bad txs: a queued bundle already carries tx 1's (sender, nonce) slot or nullifier".to_string())
        );
        // … and the aggregate bytes
        let second = demo_bundle(&chain, 2, 0x60);
        assert_eq!(
            push_bundle(&mut q, second.clone(), agg(1), ids(&second)),
            Err("duplicate bundle (same aggregate proof already queued)".to_string())
        );
        assert_eq!(q.len(), 1, "a refusal leaves the queue untouched");
        // the disjoint bundle is pushed, its ids echoed back as given
        assert_eq!(push_bundle(&mut q, second.clone(), agg(4), ids(&second)), Ok(ids(&second)));
        assert_eq!(q.len(), 2);
        assert_eq!(q[1].0.iter().map(txid).collect::<Vec<_>>(), second.iter().map(txid).collect::<Vec<_>>());
        assert_eq!(q[1].1, agg(4));
        // the cap: a queue that filled in the meantime refuses a disjoint honest bundle
        while q.len() < BUNDLE_QUEUE_MAX {
            let i = q.len();
            q.push((vec![keyless_frame(i)], vec![i as u8; 3]));
        }
        let third = demo_bundle(&chain, 3, 0x70);
        assert_eq!(
            push_bundle(&mut q, third.clone(), agg(5), ids(&third)),
            Err(format!("bundle queue full (max {BUNDLE_QUEUE_MAX}) — retry after the next block"))
        );
        assert_eq!(q.len(), BUNDLE_QUEUE_MAX);
    }

    /// Kill: dry-run each tx in a FRESH scratch pool (or in none) and a bundle that collides
    /// with itself queues; `build_batch` would ride it and every tx past the first copy dies.
    #[test]
    fn hr1_intra_bundle_duplicate_slot_or_nullifier_is_refused() {
        let chain = Mutex::new(mini_chain(1));
        let q: Queue = Mutex::new(Vec::new());
        let slots = Semaphore::new(1);
        let a = anchor(&chain.lock().unwrap());
        let s = |nonce: u64, nf: u8| sign_at(1, nonce, spend_payload(a, nf));
        // the same slot twice with two payloads → the scratch pool's DuplicateSlot on tx 1
        let r = submit(true, &chain, &q, &slots, &[s(0, 0x10), s(0, 0x11)], &agg(1));
        assert_eq!(error(&r), would_not_apply(1, AdmitError::DuplicateSlot { pending_nonce: 0 }), "{r}");
        // the same tx twice → DuplicateTx
        let r = submit(true, &chain, &q, &slots, &[s(0, 0x10), s(0, 0x10)], &agg(1));
        assert_eq!(error(&r), would_not_apply(1, AdmitError::DuplicateTx), "{r}");
        // one nullifier spent twice at consecutive nonces → NullifierPending on tx 1
        let r = submit(true, &chain, &q, &slots, &[s(0, 0x10), s(1, 0x10)], &agg(1));
        assert_eq!(error(&r), would_not_apply(1, AdmitError::NullifierPending), "{r}");
        // a nonce gap inside the bundle → NonceGap (a bundle is whole from the chain's nonce up)
        let r = submit(true, &chain, &q, &slots, &[s(0, 0x10), s(2, 0x12)], &agg(1));
        assert_eq!(error(&r), would_not_apply(1, AdmitError::NonceGap { got: 2, missing: 1 }), "{r}");
        // out of nonce order → NonceGap on tx 0
        let r = submit(true, &chain, &q, &slots, &[s(1, 0x11), s(0, 0x10)], &agg(1));
        assert_eq!(error(&r), would_not_apply(0, AdmitError::NonceGap { got: 1, missing: 0 }), "{r}");
        assert!(q.lock().unwrap().is_empty());
        assert_eq!(slots.available_permits(), 1);
        // the honest shape queues
        let r = submit(true, &chain, &q, &slots, &[s(0, 0x10), s(1, 0x11), s(2, 0x12)], &agg(1));
        assert!(accepted(&r), "{r}");
        assert_eq!(q.lock().unwrap().len(), 1);
    }

    /// Kill: drop the `refuse_proof_less_pool_tx` call from `admit_one` and the proof-less
    /// spend and mint below are admitted to the live pool through `hk_submitTx` and
    /// `hk_gossipTxs` (the mempool itself checks no proof — the last lines show it), ride a
    /// block uncovered and die at apply — a block slot for the price of an envelope.
    #[test]
    #[allow(non_snake_case)]
    fn hr1_a_proof_less_pool_tx_is_refused_at_hk_submitTx_and_hk_gossipTxs() {
        let h = SharedHandles::for_tests(mini_chain(2));
        let a = anchor(&h.chain.lock().unwrap());
        let proof_less_spend = sign_at(1, 0, spend_payload(a, 0x10));
        let proof_less_mint = sign_at(2, 0, mint_payload(vec![0x5c; LEGIT_CT]));
        // through the real doors: the E3 reason, and the live pool untouched
        for tx in [&proof_less_spend, &proof_less_mint] {
            let r = dispatch("hk_submitTx", &json!({"tx": tx}), &h);
            assert_eq!(r["result"]["accepted"], json!(false), "{r}");
            assert_eq!(r["result"]["reason"], json!(E3), "{r}");
        }
        let r = dispatch("hk_gossipTxs", &json!({"txs": [proof_less_spend, proof_less_mint]}), &h);
        assert_eq!(r["result"]["dropped"], json!(2), "{r}");
        assert_eq!(r["result"]["admitted"], json!(0), "{r}");
        assert_eq!(h.mempool.lock().unwrap().len(), 0);
        // a pool tx that carries its proof reaches the normal admission: refused for ITS reason
        // (a stale anchor here), never E3 …
        let mut stale = spend_payload(H256([0xAA; 32]), 0x11);
        if let Tx::ShieldedSpend { proof, .. } = &mut stale {
            *proof = vec![1, 2, 3];
        }
        let r = dispatch("hk_submitTx", &json!({"tx": sign_at(1, 0, stale)}), &h);
        assert_eq!(r["result"]["accepted"], json!(false), "{r}");
        assert_eq!(r["result"]["reason"], json!(AdmitError::UnknownAnchor.as_str()), "{r}");
        // … and admitted when it would apply (the mempool checks no proof)
        let mut proven = spend_payload(a, 0x12);
        if let Tx::ShieldedSpend { proof, .. } = &mut proven {
            *proof = vec![1, 2, 3];
        }
        let proven = sign_at(1, 0, proven);
        let r = dispatch("hk_submitTx", &json!({"tx": proven}), &h);
        assert_eq!(r["result"]["accepted"], json!(true), "{r}");
        assert_eq!(r["result"]["txid"], json!(hex::encode(txid(&proven))));
        let shield = sign_at(2, 0, proven_mint_payload(vec![0x5c; LEGIT_CT]));
        assert_eq!(dispatch("hk_submitTx", &json!({"tx": shield}), &h)["result"]["accepted"], json!(true));
        assert_eq!(h.mempool.lock().unwrap().len(), 2);
        // the two gates are complementary — what a bundle must carry is what hk_submitTx
        // refuses — and the mempool judges no proof (the bundle dry run relies on that)
        assert_eq!(refuse_proof_less_pool_tx(&proof_less_spend), Err(E3.to_string()));
        assert_eq!(refuse_proof_less_pool_tx(&proof_less_mint), Err(E3.to_string()));
        assert_eq!(bundle_shape_verdict(&[proof_less_spend.clone(), proof_less_mint]), Ok(()));
        let transfer = sign_at(1, 0, Tx::Transfer { to: acct(2), asset: ASSET, amount: 1 });
        assert_eq!(refuse_proof_less_pool_tx(&transfer), Ok(()));
        let mut mp = Mempool::new(4);
        mp.try_admit(proof_less_spend, &h.chain.lock().unwrap()).expect("the mempool judges no proof");
    }

    /// Kill: drop the `try_acquire` and two concurrent floods of well-formed bundles hash and
    /// dry-run in parallel on every worker; the slot caps it at one per node.
    #[test]
    fn hr1_busy_when_an_admission_is_in_flight() {
        let chain = Mutex::new(mini_chain(2));
        let q: Queue = Mutex::new(Vec::new());
        let slots = Semaphore::new(1);
        let bundle = demo_bundle(&chain.lock().unwrap(), 1, 0x10);
        let a = anchor(&chain.lock().unwrap());
        // the permit is held by an admission in flight: a bundle that passes every free check
        // answers busy, nothing queued
        let in_flight = slots.try_acquire().unwrap();
        let r = submit(true, &chain, &q, &slots, &bundle, &agg(1));
        assert_eq!(error(&r), "busy: a bundle admission is already in flight — retry in a moment", "{r}");
        assert!(q.lock().unwrap().is_empty());
        // the free refusals do not wait for the slot (the keyless and the bounds tests pin the rest)
        let r = submit(true, &chain, &q, &slots, &[keyless_frame(0)], &agg(1));
        assert!(error(&r).starts_with("bad txs: tx 0 has a malformed envelope"), "{r}");
        drop(in_flight);
        // the slot comes back after a refusal in the dry run …
        let wrong_key = sign_as(1, 2, 0, spend_payload(a, 0x20));
        let r = submit(true, &chain, &q, &slots, &[wrong_key], &agg(1));
        assert!(error(&r).contains("would not apply"), "{r}");
        assert_eq!(slots.available_permits(), 1);
        // … and after a success
        let r = submit(true, &chain, &q, &slots, &bundle, &agg(1));
        assert!(accepted(&r), "{r}");
        assert_eq!(slots.available_permits(), 1);
        assert_eq!(q.lock().unwrap().len(), 1);
    }
}

/// v0.19.13: the door (`admit_one`, behind `hk_submitTx` and `hk_gossipTxs`) — a transaction a
/// block refused, a pool tx's proof verified before the tx enters the pool, the memory of
/// failed proofs and the proof wait, the verification slot, the quota without a verifier —
/// and the bundle door's fee check. The pool's own rules are tested in mempool.rs
/// `v0_19_13_tests`. A test that verifies a proof brings its own slot (`admit_one_with`), so
/// no test waits on another's.
///
/// Run: `cargo test --offline -p hk-node v0_19_13 -- --nocapture`
#[cfg(test)]
mod v0_19_13_tests {
    use super::*;
    use crate::mempool::test_fixtures::*;
    use crate::mempool::AdmitError;
    use tokio::sync::Semaphore;

    /// Handles over `mini_chain(n)` whose pool has the stand-in verifier (`EchoVerifier`: a
    /// proof verifies exactly when it is the bincode of the tx's own public values).
    fn handles_with_verifier(n: u8) -> (SharedHandles, Arc<EchoVerifier>) {
        let h = SharedHandles::for_tests(mini_chain(n));
        let verifier = Arc::new(EchoVerifier::default());
        h.mempool.lock().unwrap().set_proof_verifier(verifier.clone());
        (h, verifier)
    }

    /// Both doors refuse, for 16 blocks, a transaction that a block refused, with the one
    /// message that names the height, whoever sends it. Nobody waits: another transaction of
    /// the same sender is admitted at once. At that height the same signed bytes are admitted.
    /// Caught mutant: drop the memory's check from the pool's `check_gated` — both doors take the
    /// refused bytes back at once.
    #[test]
    #[allow(non_snake_case)]
    fn a_transaction_a_block_refused_is_refused_at_hk_submitTx_and_hk_gossipTxs_for_sixteen_blocks() {
        let h = SharedHandles::for_tests(mini_chain(2));
        let t = sign_at(1, 0, transfer_payload(2));
        // the block at height 1 refused `t` after the envelope checks
        {
            let mut chain = h.chain.lock().unwrap();
            chain.height = 1;
            let refused = crate::mempool::RefusedTx { sender: acct(1), nonce: 0, id: txid(&t), pool_proof: false };
            assert_eq!(h.mempool.lock().unwrap().note_block(1, &chain, &[refused], &[]), 0);
        }
        let reason = AdmitError::RefusedRecently { until: 17 }.as_str();
        assert!(reason.ends_with("height 17"), "{reason}");
        let r = dispatch("hk_submitTx", &json!({"tx": t}), &h);
        assert_eq!(r["result"]["accepted"], json!(false), "{r}");
        assert_eq!(r["result"]["reason"], json!(reason), "{r}");
        // the gossip door drops it too; another tx of the same sender, at the same nonce, is
        // admitted beside it: nobody waits
        let r = dispatch("hk_gossipTxs", &json!({"txs": [t, transfer(1, 0)]}), &h);
        assert_eq!(r["result"]["admitted"], json!(1), "{r}");
        assert_eq!(r["result"]["dropped"], json!(1), "{r}");
        assert_eq!(h.mempool.lock().unwrap().remove_included(&[(acct(1), 0)]), 1);
        // one block short of the height: still refused; at it: admitted, the same signed bytes
        h.chain.lock().unwrap().height = 16;
        let r = dispatch("hk_submitTx", &json!({"tx": t}), &h);
        assert_eq!(r["result"]["reason"], json!(reason), "{r}");
        h.chain.lock().unwrap().height = 17;
        let r = dispatch("hk_submitTx", &json!({"tx": t}), &h);
        assert_eq!(r["result"]["accepted"], json!(true), "{r}");
        assert_eq!(r["result"]["txid"], json!(hex::encode(txid(&t))));
    }

    /// With a verifier, the door verifies a pool tx's proof against the tx's own public values
    /// before the tx enters the pool, after its cheap checks. One that verifies is admitted and
    /// is not held to the quota of unverified ones. One that does not is refused, and nothing
    /// enters the pool; the same bytes sent again are answered at once, without the verifier
    /// and with no further effect; the sender's transactions that carry a pool proof wait and
    /// its other transactions do not; and only a new transaction of that sender whose proof
    /// fails lengthens the wait.
    /// Caught mutant: skip `door_proof_check` (the failing proof is admitted), verify before the pool's
    /// checks (the frame under another account's key, or the shield above the balance, is
    /// verified), drop the memory of failed proofs (the repeat is verified again and doubles
    /// the wait), or hold every tx of the sender (its transfer is refused).
    #[test]
    fn with_a_verifier_a_proof_that_does_not_verify_is_refused_once_and_only_its_senders_pool_txs_wait() {
        let (h, verifier) = handles_with_verifier(3);
        let slots = Semaphore::new(POOL_PROOF_VERIFY_SLOTS);
        let pool_len = || h.mempool.lock().unwrap().len();
        let wait_of = |i: u8, height: u64| h.mempool.lock().unwrap().proof_wait_until(&acct(i), height);
        // a shield whose proof speaks of another value (6) than the shield does (5)
        let failing = |sender: u8, nonce: u64, c: u8| {
            let mut payload = echo_mint_payload(6, c);
            if let Tx::MintToPool { value, .. } = &mut payload {
                *value = 5;
            }
            sign_at(sender, nonce, payload)
        };
        // two shields of account 1 whose proofs verify: each verified once and admitted — a
        // verified pool tx is not held to "one unverified pool tx per sender"
        let first = sign_at(1, 0, echo_mint_payload(1, 0x71));
        let second = sign_at(1, 1, echo_mint_payload(2, 0x72));
        assert_eq!(admit_one_with(&h, &first, &slots), Ok(txid(&first)));
        assert_eq!(admit_one_with(&h, &second, &slots), Ok(txid(&second)));
        assert_eq!((verifier.calls(), pool_len()), (2, 2));
        // a spend is verified the same way, against its own anchor, nullifier and outputs
        let a = anchor(&h.chain.lock().unwrap());
        let spend = sign_at(3, 0, echo_spend_payload(a, 0x51));
        assert_eq!(admit_one_with(&h, &spend, &slots), Ok(txid(&spend)));
        assert_eq!((verifier.calls(), pool_len()), (3, 3));
        // a frame the pool refuses anyway is answered without a verification: not the
        // account's key, a duplicate, a shield of more than the balance
        let not_its_key = sign_as(2, 3, 0, echo_mint_payload(1, 0x73));
        assert_eq!(admit_one_with(&h, &not_its_key, &slots), Err(AdmitError::AuthMismatch.as_str()));
        assert_eq!(admit_one_with(&h, &first, &slots), Err(AdmitError::DuplicateTx.as_str()));
        let above = sign_at(2, 0, echo_mint_payload(1_001, 0x77));
        assert_eq!(
            admit_one_with(&h, &above, &slots),
            Err(AdmitError::InsufficientBalance { have: 1_000, need: 1_001 }.as_str())
        );
        assert_eq!(verifier.calls(), 3);
        // a proof that does not verify: refused, nothing enters the pool, the slot comes back,
        // and account 2's proof wait runs to height 2
        let rejected = AdmitError::PoolProofRejected.as_str();
        assert_eq!(rejected, "pool proof rejected (it does not verify)");
        let junk = failing(2, 0, 0x74);
        assert_eq!(admit_one_with(&h, &junk, &slots), Err(rejected.clone()));
        assert_eq!((verifier.calls(), pool_len(), slots.available_permits()), (4, 3, POOL_PROOF_VERIFY_SLOTS));
        assert_eq!(wait_of(2, 0), Some(2));
        // the same bytes again, through either door: the same answer at once — no verification,
        // and the wait as it was
        assert_eq!(admit_one_with(&h, &junk, &slots), Err(rejected.clone()));
        let r = dispatch("hk_gossipTxs", &json!({"txs": [junk]}), &h);
        assert_eq!(r["result"]["dropped"], json!(1), "{r}");
        assert_eq!((verifier.calls(), wait_of(2, 0)), (4, Some(2)));
        // the wait holds account 2's txs that carry a pool proof — also one whose proof would
        // verify — and not its transfer
        let good = sign_at(2, 0, echo_mint_payload(1, 0x75));
        assert_eq!(admit_one_with(&h, &good, &slots), Err(AdmitError::ProofWait { until: 2 }.as_str()));
        let plain = transfer(2, 0);
        assert_eq!(admit_one_with(&h, &plain, &slots), Ok(txid(&plain)));
        assert_eq!((verifier.calls(), pool_len()), (4, 4));
        // at the height the door named the remembered bytes are still answered at once: the
        // wait is over and is not renewed …
        h.chain.lock().unwrap().height = 2;
        assert_eq!(admit_one_with(&h, &junk, &slots), Err(rejected.clone()));
        assert_eq!((verifier.calls(), wait_of(2, 2)), (4, None));
        // … a NEW tx of account 2 whose proof fails is verified, and the wait doubles …
        let another = failing(2, 1, 0x78);
        assert_eq!(admit_one_with(&h, &another, &slots), Err(rejected));
        assert_eq!((verifier.calls(), wait_of(2, 2)), (5, Some(6)));
        // … and after it a pool tx of account 2 whose proof verifies is admitted
        h.chain.lock().unwrap().height = 6;
        let good = sign_at(2, 1, echo_mint_payload(1, 0x75));
        assert_eq!(admit_one_with(&h, &good, &slots), Ok(txid(&good)));
        assert_eq!((verifier.calls(), pool_len()), (6, 5));
    }

    /// At most `POOL_PROOF_VERIFY_SLOTS` (one) verification is in flight: with the slot taken the
    /// door answers "busy" at once — nothing verified, nothing admitted, no one made to wait —
    /// and admits the same tx once the slot is free. A tx that carries no proof needs no slot.
    /// Caught mutant: drop the `try_acquire` from `door_proof_check` — a verification runs beside the
    /// one in flight.
    #[test]
    fn a_verification_beyond_the_slot_in_flight_is_answered_busy() {
        assert_eq!(POOL_PROOF_VERIFY_SLOTS, 1);
        let (h, verifier) = handles_with_verifier(2);
        let slots = Semaphore::new(POOL_PROOF_VERIFY_SLOTS);
        let shield = sign_at(1, 0, echo_mint_payload(1, 0x71));
        // a verification in flight holds the slot
        let in_flight = slots.try_acquire().unwrap();
        let busy = AdmitError::ProofVerifyBusy.as_str();
        assert!(busy.starts_with("busy") && busy.ends_with("retry later"), "{busy}");
        assert_eq!(admit_one_with(&h, &shield, &slots), Err(busy));
        assert_eq!(verifier.calls(), 0);
        assert_eq!(h.mempool.lock().unwrap().len(), 0);
        assert_eq!(h.mempool.lock().unwrap().proof_wait_until(&acct(1), 0), None);
        // a tx that carries no proof needs no slot
        let plain = transfer(2, 0);
        assert_eq!(admit_one_with(&h, &plain, &slots), Ok(txid(&plain)));
        // the slot free again: verified and admitted, and the slot comes back
        drop(in_flight);
        assert_eq!(admit_one_with(&h, &shield, &slots), Ok(txid(&shield)));
        assert_eq!((verifier.calls(), slots.available_permits()), (1, POOL_PROOF_VERIFY_SLOTS));
    }

    /// Without a verifier both doors hold pool txs that carry a proof to the pool's quota: a
    /// sender's second one is answered "retry later"; another sender's first is admitted.
    /// Caught mutant: drop the quota from the pool's `check_gated` — the second one is admitted.
    #[test]
    #[allow(non_snake_case)]
    fn without_a_verifier_a_senders_second_unverified_pool_tx_is_answered_retry_later_at_hk_submitTx_and_hk_gossipTxs() {
        let h = SharedHandles::for_tests(mini_chain(2));
        let shield = |sender: u8, nonce: u64, c: u8| {
            let mut payload = proven_mint_payload(vec![0x5c; LEGIT_CT]);
            if let Tx::MintToPool { commitment, .. } = &mut payload {
                *commitment = H256([c; 32]);
            }
            sign_at(sender, nonce, payload)
        };
        let first = shield(1, 0, 0x61);
        assert_eq!(dispatch("hk_submitTx", &json!({"tx": first}), &h)["result"]["accepted"], json!(true));
        let second = shield(1, 1, 0x62);
        let reason = AdmitError::UncheckedProofPending.as_str();
        assert!(reason.contains("retry later"), "{reason}");
        let r = dispatch("hk_submitTx", &json!({"tx": second}), &h);
        assert_eq!(r["result"]["accepted"], json!(false), "{r}");
        assert_eq!(r["result"]["reason"], json!(reason), "{r}");
        let r = dispatch("hk_gossipTxs", &json!({"txs": [second, shield(2, 0, 0x63)]}), &h);
        assert_eq!(r["result"]["admitted"], json!(1), "{r}");
        assert_eq!(r["result"]["dropped"], json!(1), "{r}");
        assert_eq!(h.mempool.lock().unwrap().len(), 2);
    }

    /// The bundle door's dry run asks the envelope fee of a sender's first tx: a bundle whose
    /// sender cannot pay it is refused with hk_submitTx's reason and nothing is queued; the
    /// same bundle queues once the sender can pay.
    /// Caught mutant: drop `fee_and_amount_cover` from the pool's `check_gated` — the bundle of the
    /// sender that cannot pay queues.
    #[test]
    fn a_bundle_whose_sender_cannot_pay_the_fee_is_refused_at_the_bundle_door() {
        let chain = Mutex::new(mini_chain_with_fee(1, 100));
        chain.lock().unwrap().balances.insert((acct(1), hk_state::FEE_ASSET), 99);
        let queue: Mutex<Vec<(Vec<SignedTx>, Vec<u8>)>> = Mutex::new(Vec::new());
        let slot = Semaphore::new(1);
        let bundle = demo_bundle(&chain.lock().unwrap(), 1, 0x10);
        let params = json!({"txs": serde_json::to_value(&bundle).unwrap(), "agg_proof": hex::encode([0xA6u8; 64])});
        let r = submit_bundle(&params, true, &chain, &queue, &slot);
        let want =
            format!("bad txs: tx 0 would not apply: {}", AdmitError::InsufficientFee { have: 99, need: 100 }.as_str());
        assert_eq!(r["error"], json!(want), "{r}");
        assert!(queue.lock().unwrap().is_empty());
        assert_eq!(slot.available_permits(), 1);
        // with the fee in its balance the same bundle queues
        chain.lock().unwrap().balances.insert((acct(1), hk_state::FEE_ASSET), 100);
        let r = submit_bundle(&params, true, &chain, &queue, &slot);
        assert_eq!(r["result"]["accepted"], json!(true), "{r}");
        assert_eq!(queue.lock().unwrap().len(), 1);
    }
}
