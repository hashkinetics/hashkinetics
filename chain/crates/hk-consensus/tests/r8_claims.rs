//! HK-R8 "abstain-while-behind" evidence — regression tests for VZ-2 (v0.19.10).
//!
//! Until v0.19.10 a future-height VOTE or PROPOSAL recorded an R8 height claim from the frame's
//! address field before any signature check, so two keyless frames naming two public member
//! addresses silenced every seat they reached. The fix (`ops/ROLL-v0.19.10-VZ2-2026-11-03.md` §1):
//! a claim is recorded only after the vote's signature VERIFIES under the named member's current
//! operational key; the trigger is power-weighted (claimants above one third of the set's power);
//! proposals no longer count; failed verifications are budgeted per address per window; claims are
//! pruned as our height advances; and the future-height input buffer is bounded (§1.4, v2): every
//! buffered input is confined to the window `h ..= h + BUFFER_HEIGHT_WINDOW`; a vote must name a
//! current-set member and is buffered only after its signature verifies, with dedup and the
//! per-address round cap applied to verified entries only; a proposal must come from the scheduled
//! proposer, first for its round, within the per-height round cap, and is buffered only after its
//! signature verifies; the host's proposed value follows the proposal rules without verification;
//! non-members, out-of-window frames and taken slots are dropped BEFORE any verification. In the
//! same release a vote or proposal whose round is `Round::Nil` is refused at the top of `on_vote` /
//! `on_proposal`, before any height branch, verification or buffering (found while writing these
//! tests: on the current-height path such a proposal reached `select_proposer`, which asserts a
//! defined round — a panic on the consensus actor from a frame nobody signed).
//!
//! The tests at the end pin the vote keeper's rule: one vote per validator per round and type,
//! the first copy whose signature verified; a vote for another value is kept as evidence.
//!
//! Every input enters through the real core-consensus entry point, the `process!` macro, which runs
//! `handle()` as a coroutine and hands every yielded `Effect` to the recorder below — the same path
//! the engine feeds network votes and proposals into (engine/src/consensus.rs `process_input`). A
//! signature can only be checked through `Effect::VerifySignature`, so the effect log is the proof
//! of whether (and how often) a check was requested.
//!
//! The recorder answers `VerifySignature` by signature MARKER (no LMS runs here):
//!   - all-zero bytes (a frame no key ever signed)              → false, as the real verifier does
//!     (hk-crypto hashsig.rs: `!verify(msg, &vec![0u8; CONSENSUS_SIG_LEN], &pk)`);
//!   - 0xA5-filled (a vote this harness itself "signed": honest) → true, also when its last eight
//!     bytes carry a sequence number (`signed_sig`);
//!   - 0x5A-filled (a key we do not hold, e.g. rotated after our height) → false;
//! and resumes every `SignVote` / `SignProposal` with a NEW honest signature, the 0xA5 marker with
//! the signer's sequence number in its last eight bytes (v0.19.12): a stateful hash-based signer
//! spends another one-time leaf on every signature, so the same vote signed twice has two valid
//! signatures with different bytes. It answers the commit, polka and round certificate checks as
//! the engine's verifier does (signing `ext.rs`). Every signature has the wire length the codec
//! admits (RZ-1: exactly `CONSENSUS_SIG_LEN` = 9,140 bytes).
//!
//! Thread safety: the captured log is process-wide, so every test that builds a `Node` holds the
//! `SERIAL` guard for its whole body (the guard lives in the `Node`); the file is safe under the
//! default thread count. A test never holds two `Node`s at once (that would deadlock on `SERIAL`).
//!
//! Run from WSL, in `chain/`:
//!   CARGO_TARGET_DIR=$HOME/hk-target-chain cargo test --offline -p hk-consensus --test r8_claims -- --nocapture --test-threads=1
//! The opt-out test is `#[ignore]`d and needs its own process with the env set:
//!   HK_ABSTAIN_GAP=0 CARGO_TARGET_DIR=$HOME/hk-target-chain cargo test --offline -p hk-consensus --test r8_claims -- --ignored --nocapture --test-threads=1

use std::sync::{Mutex, MutexGuard, Once};

use bytes::Bytes;
use hk_consensus::{
    HkAddress, HkContext, HkHeight, HkProposal, HkPub, HkSig, HkValidator, HkValidatorSet,
    HkValue, HkVote,
};
use malachitebft_core_consensus::{
    BufferAdmission, ConsensusMsg, Effect, Error, Input, Params, ProposedValue, Resumable,
    Resume, Role, SignedConsensusMsg, State, ThresholdParams, WalEntry, BUFFER_HEIGHT_WINDOW,
    BUFFER_MAX_PROPOSAL_ROUNDS_PER_HEIGHT, BUFFER_MAX_VOTE_ROUNDS_PER_ADDRESS,
    CLAIM_FAILURE_WARNS_PER_WINDOW,
};
use malachitebft_core_types::{
    CertificateError, CommitCertificate, CommitSignature, Context as _, NilOrVal, Round,
    RoundCertificate, RoundCertificateType, SignedMessage, SignedProposal, SignedVote, Threshold,
    ThresholdParam, Timeout, Validity, ValueOrigin, ValuePayload, VoteType, VotingPower,
};
use malachitebft_metrics::Metrics;

/// The consensus signature length the codec admits (hk-node codec.rs `sig`, RZ-1).
const SIG_LEN: usize = hk_crypto::hashsig::CONSENSUS_SIG_LEN;
/// The node under test sits at height 40; the far-future claim is 96 (as in the report).
const H: u64 = 40;
const CLAIM: u64 = 96;
/// The shipped default gap (`HkContext::abstain_threshold`, `HK_ABSTAIN_GAP` unset).
const GAP: u64 = 20;
/// app/src/spawn.rs `queue_capacity` = sync.parallel_requests (5) × sync.batch_size (20).
const QUEUE_CAPACITY: usize = 100;

// The warn-throttle and buffer constants (`CLAIM_FAILURE_WARNS_PER_WINDOW`,
// `BUFFER_MAX_VOTE_ROUNDS_PER_ADDRESS`, `BUFFER_MAX_PROPOSAL_ROUNDS_PER_HEIGHT`,
// `BUFFER_HEIGHT_WINDOW`) are imported from core-consensus, which re-exports them for these tests;
// `preconditions_…` pins them to the design's numbers (ROLL §1.4), so a change on either
// side comes back through this file.

/// Signature markers (the whole 9,140-byte signature is filled with one byte).
const ZERO: u8 = 0x00; // no key ever signed this
const HONEST: u8 = 0xA5; // this harness's own signer: verifies
const ROTATED: u8 = 0x5A; // a key we do not hold (rotated after our height): refused

/// The warn the vote handler logs once per address per warn window (vote.rs).
const FAILED_VERIFY_WARN: &str = "failed signature verification";
/// The once-per-height R8 line (driver.rs).
const R8_LINE: &str = "R8: behind the network";

fn sig(marker: u8) -> HkSig {
    HkSig(vec![marker; SIG_LEN])
}

/// The `n`-th signature of the recorder's signer: the honest marker with `n` in its last eight
/// bytes. It verifies as `sig(HONEST)` does, and signatures with different `n` differ.
fn signed_sig(n: u64) -> HkSig {
    let mut s = vec![HONEST; SIG_LEN];
    s[SIG_LEN - 8..].copy_from_slice(&n.to_be_bytes());
    HkSig(s)
}

fn sig_marker(s: &[u8]) -> &'static str {
    if s.len() != SIG_LEN {
        "bad-length"
    } else if s.iter().all(|b| *b == ZERO) {
        "zero"
    } else if s[..SIG_LEN - 8].iter().all(|b| *b == HONEST) {
        "honest"
    } else if s.iter().all(|b| *b == ROTATED) {
        "rotated"
    } else {
        "other"
    }
}

/// What the recorder answers to `Effect::VerifySignature`: only the harness's own marker verifies.
fn harness_verifies(s: &[u8]) -> bool {
    sig_marker(s) == "honest"
}

// ---------------------------------------------------------------------------------------------
// Serialisation and logging: core-consensus's own lines, captured and echoed.
// ---------------------------------------------------------------------------------------------

/// Held by every `Node` for the test's lifetime: the captured log below is process-wide.
static SERIAL: Mutex<()> = Mutex::new(());

static LOG_BUF: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct TeeWriter;

impl std::io::Write for TeeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOG_BUF.lock().unwrap_or_else(|e| e.into_inner()).extend_from_slice(buf);
        print!("{}", String::from_utf8_lossy(buf));
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn init_tracing() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_env("HK_TEST_LOG").unwrap_or_else(
            |_| tracing_subscriber::EnvFilter::new("informalsystems_malachitebft_core_consensus=info"),
        );
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(|| TeeWriter)
            .without_time()
            .with_ansi(false)
            .try_init();
    });
}

/// Clear the captured log. Call it only while holding `SERIAL` (i.e. after the `Node` is built).
fn clear_captured_log() {
    LOG_BUF.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

fn captured_log() -> String {
    String::from_utf8_lossy(&LOG_BUF.lock().unwrap_or_else(|e| e.into_inner())).into_owned()
}

// ---------------------------------------------------------------------------------------------
// Effect recorder.
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Rec {
    kind: &'static str,
    detail: String,
}

#[derive(Default)]
struct Harness {
    log: Vec<Rec>,
    /// How many signatures the recorder's signer has made. `clear` keeps the count, so every
    /// signature the signer returns differs from every earlier one (`signed_sig`).
    signed: u64,
    /// The commit certificate handed over with each `Effect::Decide`, in order.
    decided: Vec<CommitCertificate<HkContext>>,
}

impl Harness {
    fn count(&self, kind: &str) -> usize {
        self.log.iter().filter(|r| r.kind == kind).count()
    }
    fn kinds(&self) -> Vec<&'static str> {
        self.log.iter().map(|r| r.kind).collect()
    }
    fn first(&self, kind: &str) -> Option<&Rec> {
        self.log.iter().find(|r| r.kind == kind)
    }
    fn details(&self, kind: &str) -> Vec<String> {
        self.log.iter().filter(|r| r.kind == kind).map(|r| r.detail.clone()).collect()
    }
    fn clear(&mut self) {
        self.log.clear();
        self.decided.clear();
    }
}

fn rec(log: &mut Vec<Rec>, kind: &'static str, detail: String) {
    log.push(Rec { kind, detail });
}

fn on_effect(h: &mut Harness, effect: Effect<HkContext>) -> Result<Resume<HkContext>, String> {
    let log = &mut h.log;
    Ok(match effect {
        Effect::ResetTimeouts(r) => {
            rec(log, "ResetTimeouts", String::new());
            r.resume_with(())
        }
        Effect::CancelAllTimeouts(r) => {
            rec(log, "CancelAllTimeouts", String::new());
            r.resume_with(())
        }
        Effect::CancelTimeout(t, r) => {
            rec(log, "CancelTimeout", format!("{t}"));
            r.resume_with(())
        }
        Effect::ScheduleTimeout(t, r) => {
            rec(log, "ScheduleTimeout", format!("{t}"));
            r.resume_with(())
        }
        Effect::StartRound(h, round, proposer, role, r) => {
            rec(log, "StartRound", format!("h={h} r={round} proposer={proposer} role={role:?}"));
            r.resume_with(())
        }
        Effect::PublishConsensusMsg(msg, r) => {
            let d = match &msg {
                SignedConsensusMsg::Vote(v) => format!(
                    "vote {:?} h={} r={} value={:?} addr={}",
                    v.message.typ, v.message.height, v.message.round, v.message.value,
                    v.message.validator_address
                ),
                SignedConsensusMsg::Proposal(p) => {
                    format!("proposal h={} r={}", p.message.height, p.message.round)
                }
            };
            rec(log, "PublishConsensusMsg", d);
            r.resume_with(())
        }
        Effect::PublishLivenessMsg(_, r) => {
            rec(log, "PublishLivenessMsg", String::new());
            r.resume_with(())
        }
        Effect::RepublishVote(_, r) => {
            rec(log, "RepublishVote", String::new());
            r.resume_with(())
        }
        Effect::RepublishRoundCertificate(_, r) => {
            rec(log, "RepublishRoundCertificate", String::new());
            r.resume_with(())
        }
        Effect::GetValue(h, round, _t, r) => {
            rec(log, "GetValue", format!("h={h} r={round}"));
            r.resume_with(())
        }
        Effect::RestreamProposal(h, round, _vr, _a, _id, r) => {
            rec(log, "RestreamProposal", format!("h={h} r={round}"));
            r.resume_with(())
        }
        // v0.19.12: the value of a signature-verified proposal, on its way to the host.
        Effect::VerifiedProposal(p, r) => {
            rec(
                log,
                "VerifiedProposal",
                format!(
                    "h={} r={} pol={} addr={} value={} sig={}",
                    p.message.height,
                    p.message.round,
                    p.message.pol_round,
                    p.message.validator_address,
                    p.message.value.id(),
                    sig_marker(&p.signature.0)
                ),
            );
            r.resume_with(())
        }
        Effect::ValidSyncValue(_, _, r) => {
            rec(log, "ValidSyncValue", String::new());
            r.resume_with(())
        }
        Effect::InvalidSyncValue(_, _, _, r) => {
            rec(log, "InvalidSyncValue", String::new());
            r.resume_with(())
        }
        Effect::Decide(c, _, r) => {
            rec(
                log,
                "Decide",
                format!("h={} r={} signatures={}", c.height, c.round, c.commit_signatures.len()),
            );
            h.decided.push(c);
            r.resume_with(())
        }
        Effect::SignVote(vote, r) => {
            rec(
                log,
                "SignVote",
                format!(
                    "{:?} h={} r={} value={:?} addr={}",
                    vote.typ, vote.height, vote.round, vote.value, vote.validator_address
                ),
            );
            // v0.19.12: every call returns a new valid signature, as a stateful hash-based
            // signer does.
            h.signed += 1;
            r.resume_with(SignedMessage::new(vote, signed_sig(h.signed)))
        }
        Effect::SignProposal(p, r) => {
            rec(log, "SignProposal", format!("h={} r={}", p.height, p.round));
            h.signed += 1;
            r.resume_with(SignedMessage::new(p, signed_sig(h.signed)))
        }
        Effect::VerifySignature(msg, _pk, r) => {
            let marker = sig_marker(&msg.signature.0);
            // v0.19.12: the real provider also refuses a proposal whose value id is not
            // the hash of the bytes it carries (hk-consensus provider.rs, tested there against
            // a real key). The recorder answers as the provider does and marks the reason.
            let (what, id_ok) = match &msg.message {
                ConsensusMsg::Vote(v) => {
                    (format!("vote h={} addr={}", v.height, v.validator_address), true)
                }
                ConsensusMsg::Proposal(p) => (
                    format!("proposal h={} addr={}", p.height, p.validator_address),
                    HkValue::new(p.value.txs.clone()).id() == p.value.id(),
                ),
            };
            let reason = if id_ok { "" } else { " id-mismatch" };
            rec(log, "VerifySignature", format!("{what} sig={marker}{reason}"));
            r.resume_with(harness_verifies(&msg.signature.0) && id_ok)
        }
        // v0.19.12: the certificate checks answer as the engine's verifier does
        // (`certificate_verdict`).
        Effect::VerifyCommitCertificate(c, set, t, r) => {
            let signers: Vec<(HkAddress, bool)> = c
                .commit_signatures
                .iter()
                .map(|s| (s.address, harness_verifies(&s.signature.0)))
                .collect();
            let verdict = certificate_verdict(&signers, &set, t.quorum);
            rec(log, "VerifyCommitCertificate", verdict_detail(&verdict));
            r.resume_with(verdict)
        }
        Effect::VerifyPolkaCertificate(c, set, t, r) => {
            let signers: Vec<(HkAddress, bool)> = c
                .polka_signatures
                .iter()
                .map(|s| (s.address, harness_verifies(&s.signature.0)))
                .collect();
            let verdict = certificate_verdict(&signers, &set, t.quorum);
            rec(log, "VerifyPolkaCertificate", verdict_detail(&verdict));
            r.resume_with(verdict)
        }
        Effect::VerifyRoundCertificate(c, set, t, r) => {
            let prevote_in_precommit_cert = c.round_signatures.iter().find(|s| {
                c.cert_type == RoundCertificateType::Precommit && s.vote_type == VoteType::Prevote
            });
            let verdict = match prevote_in_precommit_cert {
                Some(s) => Err(CertificateError::InvalidVoteType(s.address)),
                None => {
                    let signers: Vec<(HkAddress, bool)> = c
                        .round_signatures
                        .iter()
                        .map(|s| (s.address, harness_verifies(&s.signature.0)))
                        .collect();
                    let threshold = match c.cert_type {
                        RoundCertificateType::Precommit => t.quorum,
                        RoundCertificateType::Skip => t.honest,
                    };
                    certificate_verdict(&signers, &set, threshold)
                }
            };
            rec(log, "VerifyRoundCertificate", verdict_detail(&verdict));
            r.resume_with(verdict)
        }
        Effect::WalAppend(h, e, r) => {
            let kind = match &e {
                WalEntry::ConsensusMsg(SignedConsensusMsg::Vote(_)) => "vote",
                WalEntry::ConsensusMsg(SignedConsensusMsg::Proposal(_)) => "proposal",
                WalEntry::Timeout(_) => "timeout",
                WalEntry::ProposedValue(_) => "value",
            };
            rec(log, "WalAppend", format!("h={h} {kind}"));
            r.resume_with(())
        }
        Effect::ExtendVote(_, _, _, r) => {
            rec(log, "ExtendVote", String::new());
            r.resume_with(None)
        }
        Effect::VerifyVoteExtension(_, _, _, _, _, r) => {
            rec(log, "VerifyVoteExtension", String::new());
            r.resume_with(Ok(()))
        }
    })
}

/// What the recorder answers to a certificate check, as the engine's verifier does (signing
/// `ext.rs`): a validator named twice or a non-member refuses the certificate, and the power of
/// the signatures that verify must reach the threshold. `signers` holds, in the certificate's
/// order, each signature's address and whether it verifies (by marker).
fn certificate_verdict(
    signers: &[(HkAddress, bool)],
    set: &HkValidatorSet,
    threshold: ThresholdParam,
) -> Result<(), CertificateError<HkContext>> {
    let mut seen: Vec<HkAddress> = Vec::new();
    let mut signed: VotingPower = 0;
    for (address, verifies) in signers {
        if seen.contains(address) {
            return Err(CertificateError::DuplicateVote(*address));
        }
        seen.push(*address);
        let Some(validator) = set.get_by_address(address) else {
            return Err(CertificateError::UnknownValidator(*address));
        };
        if *verifies {
            signed += validator.voting_power;
        }
    }
    let total = set.total_voting_power();
    if threshold.is_met(signed, total) {
        Ok(())
    } else {
        Err(CertificateError::NotEnoughVotingPower {
            signed,
            total,
            expected: threshold.min_expected(total),
        })
    }
}

fn verdict_detail(verdict: &Result<(), CertificateError<HkContext>>) -> String {
    match verdict {
        Ok(()) => "ok".to_string(),
        Err(e) => e.to_string(),
    }
}

// ---------------------------------------------------------------------------------------------
// Validator sets and one node = one core-consensus State<HkContext> + its effect log.
// ---------------------------------------------------------------------------------------------

/// Validators built the way hk-consensus's own unit tests build them (context.rs tests): fake
/// 48-byte roots, fake 60-byte operational keys, no LMS key generation. `HkValidatorSet::new`
/// sorts by power descending, then address ascending; the node under test is always index 0.
fn validator(i: u8, power: VotingPower) -> HkValidator {
    HkValidator::new(vec![10 + i; 48], HkPub(vec![1 + i; 60]), power)
}

/// Four equal seats (a 4×1 devnet; total 4, more than one third = 2 seats).
fn equal_set() -> HkValidatorSet {
    HkValidatorSet::new((0..4u8).map(|i| validator(i, 1)))
}

/// The testnet-1 shape: four founders at power 4 and seven externals at power 1 (total 23;
/// more than one third = power 8). After sorting, indices 0..4 are founders, 4..11 externals.
fn testnet_set() -> HkValidatorSet {
    let powers: [VotingPower; 11] = [4, 4, 4, 4, 1, 1, 1, 1, 1, 1, 1];
    HkValidatorSet::new(powers.iter().enumerate().map(|(i, p)| validator(i as u8, *p)))
}

struct Node {
    st: State<HkContext>,
    m: Metrics,
    h: Harness,
    set: HkValidatorSet,
    /// In set order (power desc, address asc). `addrs[0]` is this node unless built otherwise.
    addrs: Vec<HkAddress>,
    /// Serialises the tests (the captured log is process-wide). Declared last: released last.
    _serial: MutexGuard<'static, ()>,
}

impl Node {
    fn build(set: HkValidatorSet, address: HkAddress, height: u64, enabled: bool) -> Self {
        let serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        init_tracing();
        let addrs: Vec<HkAddress> = set.iter().map(|v| v.address).collect();
        let params = Params {
            initial_height: HkHeight::new(height),
            initial_validator_set: set.clone(),
            address,
            threshold_params: ThresholdParams::default(), // app/src/spawn.rs: 2f+1 / f+1
            value_payload: ValuePayload::ProposalAndParts, // hk-node main.rs
            enabled,
        };
        let st = State::new(HkContext::new(), params, QUEUE_CAPACITY);
        Self { st, m: Metrics::new(), h: Harness::default(), set, addrs, _serial: serial }
    }

    /// Four equal seats, this node = index 0, consensus enabled.
    fn at(height: u64) -> Self {
        let set = equal_set();
        let me = set.iter().next().unwrap().address;
        Self::build(set, me, height, true)
    }

    /// The testnet shape, this node = index 0 (a founder), consensus enabled.
    fn testnet_at(height: u64) -> Self {
        let set = testnet_set();
        let me = set.iter().next().unwrap().address;
        Self::build(set, me, height, true)
    }

    /// Feed one input through the real entry point, recording every effect.
    fn feed(&mut self, input: Input<HkContext>) {
        self.try_feed(input).expect("core-consensus returned an error");
    }

    /// The same, returning what core-consensus returned instead of requiring Ok.
    fn try_feed(&mut self, input: Input<HkContext>) -> Result<(), Error<HkContext>> {
        malachitebft_core_consensus::process!(
            input: input,
            state: &mut self.st,
            metrics: &self.m,
            with: effect => on_effect(&mut self.h, effect)
        )
    }

    fn start_height(&mut self, height: u64) {
        let set = self.set.clone();
        self.start_height_with(height, set);
    }

    fn start_height_with(&mut self, height: u64, set: HkValidatorSet) {
        self.feed(Input::StartHeight(HkHeight::new(height), set, false));
    }

    /// The round-0 propose timeout: the driver emits our prevote nil (or, under R8, nothing).
    fn propose_timeout(&mut self) {
        self.feed(Input::TimeoutElapsed(Timeout::propose(Round::new(0))));
    }

    fn tip(&self) -> Option<u64> {
        self.st.corroborated_peer_tip().map(|h| h.as_u64())
    }

    fn claims(&self) -> Vec<(HkAddress, u64)> {
        self.st.peer_height_claims.iter().map(|(a, h)| (*a, h.as_u64())).collect()
    }

    /// Failed claim verifications per address in the current warn window (they throttle the
    /// warning).
    fn failures(&self) -> Vec<(HkAddress, u32)> {
        self.st.claim_failures_in_warn_window.clone()
    }

    fn evidence(&self) -> (Vec<(HkAddress, u64, VotingPower)>, VotingPower, VotingPower) {
        let (c, w, t) = self.st.abstain_evidence();
        (c.into_iter().map(|(a, h, p)| (a, h.as_u64(), p)).collect(), w, t)
    }

    fn verifies(&self) -> usize {
        self.h.count("VerifySignature")
    }

    /// Inputs held in the future-height buffer (all heights).
    fn queued(&self) -> usize {
        self.st.input_queue.size()
    }

    /// Inputs the buffer refused since the node was built.
    fn dropped(&self) -> u64 {
        self.st.buffer_dropped_total
    }

    fn proposer(&self, height: u64, round: u32) -> HkAddress {
        *self.st.get_proposer(HkHeight::new(height), Round::new(round))
    }

    /// A member of the set other than `exclude` and other than this node.
    fn other_member(&self, exclude: HkAddress) -> HkAddress {
        *self.addrs.iter().find(|x| **x != exclude && **x != self.addrs[0]).unwrap()
    }
}

// ---------------------------------------------------------------------------------------------
// Frames.
// ---------------------------------------------------------------------------------------------

fn vote(height: u64, round: u32, typ: VoteType, addr: HkAddress, marker: u8) -> SignedVote<HkContext> {
    let v = match typ {
        VoteType::Prevote => {
            HkVote::new_prevote(HkHeight::new(height), Round::new(round), NilOrVal::Nil, addr)
        }
        VoteType::Precommit => {
            HkVote::new_precommit(HkHeight::new(height), Round::new(round), NilOrVal::Nil, addr)
        }
    };
    SignedMessage::new(v, sig(marker))
}

/// A vote no key ever signed: prevote nil at `height`, round 0, a public address, 9,140 zeros.
fn zero_vote(height: u64, addr: HkAddress) -> SignedVote<HkContext> {
    vote(height, 0, VoteType::Prevote, addr, ZERO)
}

/// An honest vote (the harness's own marker verifies).
fn honest_vote(height: u64, addr: HkAddress) -> SignedVote<HkContext> {
    vote(height, 0, VoteType::Prevote, addr, HONEST)
}

/// A vote signed with a key we do not hold (rotated after our height): refused.
fn rotated_vote(height: u64, addr: HkAddress) -> SignedVote<HkContext> {
    vote(height, 0, VoteType::Prevote, addr, ROTATED)
}

/// A vote whose round is Nil (−1): no honest validator ever emits one, but the wire admits it.
fn nil_round_vote(height: u64, typ: VoteType, addr: HkAddress, marker: u8) -> SignedVote<HkContext> {
    let v = match typ {
        VoteType::Prevote => HkVote::new_prevote(HkHeight::new(height), Round::Nil, NilOrVal::Nil, addr),
        VoteType::Precommit => {
            HkVote::new_precommit(HkHeight::new(height), Round::Nil, NilOrVal::Nil, addr)
        }
    };
    SignedMessage::new(v, sig(marker))
}

/// A proposal with its own tx payload (so two frames can differ) and the given signature marker.
fn proposal(height: u64, round: Round, addr: HkAddress, txs: &[u8], marker: u8) -> SignedProposal<HkContext> {
    SignedMessage::new(
        HkProposal::new(
            HkHeight::new(height),
            round,
            HkValue::new(Bytes::copy_from_slice(txs)),
            Round::Nil,
            addr,
        ),
        sig(marker),
    )
}

/// A proposal no key ever signed.
fn zero_proposal(height: u64, round: Round, addr: HkAddress, txs: &[u8]) -> SignedProposal<HkContext> {
    proposal(height, round, addr, txs, ZERO)
}

/// An honestly signed proposal.
fn honest_proposal(height: u64, round: Round, addr: HkAddress, txs: &[u8]) -> SignedProposal<HkContext> {
    proposal(height, round, addr, txs, HONEST)
}

/// The host's reassembled value for (height, round) attributed to `proposer` — no signature of
/// its own (the parts carried theirs).
fn proposed_value(height: u64, round: Round, proposer: HkAddress, txs: &[u8]) -> Input<HkContext> {
    Input::ProposedValue(
        ProposedValue {
            height: HkHeight::new(height),
            round,
            valid_round: Round::Nil,
            proposer,
            value: HkValue::new(Bytes::copy_from_slice(txs)),
            validity: Validity::Valid,
        },
        ValueOrigin::Consensus,
    )
}

// ---------------------------------------------------------------------------------------------
// Harness self-test and preconditions.
// ---------------------------------------------------------------------------------------------

/// The recorder answers VerifySignature by marker (zero → false, 0xA5 → true, 0x5A → false) and
/// resumes SignVote / SignProposal with 0xA5 signatures of the wire length. Since v0.19.12 every
/// signature it returns is new (the same vote signed twice: two signatures that differ and both
/// verify), and its certificate checks answer as `certificate_verdict` does.
#[test]
fn harness_answers_verify_by_signature_marker_and_signs_with_a5() {
    let set = equal_set();
    let a = set.iter().next().unwrap().address;
    let pk = HkPub(vec![1u8; 60]);
    let mut h = Harness::default();

    let verdict = |s: HkSig, h: &mut Harness| {
        let v = HkVote::new_prevote(HkHeight::new(CLAIM), Round::new(0), NilOrVal::Nil, a);
        let msg = SignedMessage::new(ConsensusMsg::Vote(v), s);
        let eff: Effect<HkContext> = Effect::VerifySignature(msg, pk.clone(), Default::default());
        match on_effect(h, eff) {
            Ok(Resume::SignatureValidity(b)) => b,
            other => panic!("unexpected resume {other:?}"),
        }
    };
    assert!(!verdict(sig(ZERO), &mut h), "an all-zero signature is refused");
    assert!(verdict(sig(HONEST), &mut h), "the harness's own 0xA5 signature verifies");
    assert!(!verdict(sig(ROTATED), &mut h), "a 0x5A signature (a key we do not hold) is refused");
    assert_eq!(h.count("VerifySignature"), 3);
    assert!(h.log[0].detail.ends_with("sig=zero"));
    assert!(h.log[1].detail.ends_with("sig=honest"));
    assert!(h.log[2].detail.ends_with("sig=rotated"));

    let sign_vote = |h: &mut Harness| {
        let v = HkVote::new_prevote(HkHeight::new(H), Round::new(0), NilOrVal::Nil, a);
        let eff: Effect<HkContext> = Effect::SignVote(v, Default::default());
        match on_effect(h, eff) {
            Ok(Resume::SignedVote(sv)) => sv.signature,
            other => panic!("unexpected resume {other:?}"),
        }
    };
    let (s1, s2) = (sign_vote(&mut h), sign_vote(&mut h));
    for s in [&s1, &s2] {
        assert_eq!(s.0.len(), SIG_LEN);
        assert_eq!(sig_marker(&s.0), "honest");
    }
    // A stateful hash-based signer spends another one-time leaf on every signature, so the same
    // vote signed twice has two valid signatures with different bytes.
    assert!(s1 != s2, "the same vote signed twice: two different signatures");
    assert!(s1 != sig(HONEST) && s2 != sig(HONEST), "and neither is the bare marker the tests use");
    assert!(verdict(s1, &mut h) && verdict(s2, &mut h), "both verify");

    let p = HkProposal::new(HkHeight::new(H), Round::new(0), HkValue::new(Bytes::new()), Round::Nil, a);
    let eff: Effect<HkContext> = Effect::SignProposal(p, Default::default());
    match on_effect(&mut h, eff) {
        Ok(Resume::SignedProposal(sp)) => assert_eq!(sig_marker(&sp.signature.0), "honest"),
        other => panic!("unexpected resume {other:?}"),
    }

    // v0.19.12: the certificate checks answer as the engine's verifier does.
    let addrs: Vec<HkAddress> = set.iter().map(|v| v.address).collect();
    let commit = |names: &[HkAddress], h: &mut Harness| {
        let c: CommitCertificate<HkContext> = CommitCertificate {
            height: HkHeight::new(H),
            round: Round::new(0),
            value_id: HkValue::new(Bytes::new()).id(),
            commit_signatures: names.iter().map(|x| CommitSignature::new(*x, sig(HONEST))).collect(),
        };
        let eff: Effect<HkContext> =
            Effect::VerifyCommitCertificate(c, set.clone(), ThresholdParams::default(), Default::default());
        match on_effect(h, eff) {
            Ok(Resume::CertificateValidity(v)) => v,
            other => panic!("unexpected resume {other:?}"),
        }
    };
    assert_eq!(commit(&addrs[..3], &mut h), Ok(()), "three of four, each named once");
    assert_eq!(
        commit(&[addrs[0], addrs[1], addrs[1], addrs[2]], &mut h),
        Err(CertificateError::DuplicateVote(addrs[1])),
        "a validator named twice refuses the certificate"
    );
    assert!(
        matches!(commit(&addrs[..2], &mut h), Err(CertificateError::NotEnoughVotingPower { .. })),
        "two of four is not a quorum"
    );
}

/// R8 is on with the shipped default gap 20, the env override is unset, the signature length is
/// the one the wire codec admits, and the shipped constants are the design's frozen numbers.
#[test]
fn preconditions_gap_on_by_default_and_design_constants() {
    assert!(std::env::var_os("HK_ABSTAIN_GAP").is_none(), "HK_ABSTAIN_GAP must be unset for this run");
    assert_eq!(HkContext::new().abstain_threshold(), Some(GAP));
    assert_eq!(GAP, 20);
    assert_eq!(SIG_LEN, 9_140);
    assert_eq!(
        CLAIM_FAILURE_WARNS_PER_WINDOW, 1,
        "one failed-verification warn per address per window"
    );
    assert_eq!(BUFFER_MAX_VOTE_ROUNDS_PER_ADDRESS, 8, "ROLL §1.4: 8 vote rounds per address per height");
    assert_eq!(BUFFER_MAX_PROPOSAL_ROUNDS_PER_HEIGHT, 2, "ROLL §1.4: 2 proposal rounds per height");
    assert_eq!(BUFFER_HEIGHT_WINDOW, 4, "ROLL §1.4: buffered inputs within h ..= h + 4 only");
    assert!(
        H + BUFFER_HEIGHT_WINDOW < H + GAP,
        "the buffer window and the R8 claim path (≥ h + gap) are disjoint: a claim is never buffered"
    );
    assert!(ThresholdParams::default().honest.is_met(2, 4), "two of four equal seats are above one third");
    assert!(!ThresholdParams::default().honest.is_met(1, 4));
    assert!(ThresholdParams::default().honest.is_met(8, 23), "power 8 is above one third of 23");
    assert!(!ThresholdParams::default().honest.is_met(7, 23), "the seven externals are not");
    {
        let n = Node::at(H);
        assert_eq!(n.set.total_voting_power(), 4);
    }
    {
        let t = Node::testnet_at(H);
        assert_eq!(t.set.total_voting_power(), 23);
        assert_eq!(t.set.iter().filter(|v| v.voting_power == 4).count(), 4);
        assert_eq!(t.set.iter().next().unwrap().voting_power, 4, "the node under test is a founder");
    }
}

// ---------------------------------------------------------------------------------------------
// Forged (keyless) frames: verified, refused, inert.
// ---------------------------------------------------------------------------------------------

/// Two zero-signature future-height votes naming two other members: each costs exactly one
/// VerifySignature (the claim path), both are refused, no claim is recorded, no tip, no abstain,
/// the failure counter reads 2 — and nothing is buffered: 96 is outside the buffer window, so the
/// buffer drops them before any second verification.
#[test]
fn forged_future_votes_cost_one_verify_each_record_no_claim_and_are_not_buffered() {
    let mut n = Node::at(H);
    n.start_height(H);
    assert_eq!(n.st.height(), HkHeight::new(H));
    assert_eq!(n.st.round(), Round::new(0));
    assert!(n.st.is_active_validator());
    n.h.clear();

    let (a, b) = (n.addrs[1], n.addrs[2]);
    n.feed(Input::Vote(zero_vote(CLAIM, a)));
    n.feed(Input::Vote(zero_vote(CLAIM, b)));

    println!("effects: {:?}", n.h.kinds());
    assert_eq!(n.verifies(), 2, "one signature check per frame, before any claim");
    assert_eq!(
        n.h.details("VerifySignature"),
        vec![format!("vote h={CLAIM} addr={a} sig=zero"), format!("vote h={CLAIM} addr={b} sig=zero")]
    );
    assert!(n.claims().is_empty(), "a refused signature records no claim");
    assert_eq!(n.tip(), None);
    assert!(!n.st.should_abstain());
    assert_eq!(n.queued(), 0, "96 > 40 + 4: outside the buffer window, nothing kept");
    assert_eq!(n.dropped(), 2, "both counted as buffer drops");
    assert_eq!(n.st.claim_verify_failures_total, 2);
    assert_eq!(n.failures(), vec![(a, 1), (b, 1)]);
}

/// After the two forged votes the propose timeout still yields our prevote: one SignVote and one
/// PublishConsensusMsg — the node keeps voting (the attack is inert).
#[test]
fn node_keeps_voting_after_forged_future_votes() {
    let mut n = Node::at(H);
    n.start_height(H);
    let sr = n.h.first("StartRound").expect("StartRound").detail.clone();
    assert!(sr.ends_with(&format!("role={:?}", Role::Validator)), "not the proposer at (40, 0): {sr}");
    let (a, b) = (n.addrs[1], n.addrs[2]);
    n.feed(Input::Vote(zero_vote(CLAIM, a)));
    n.feed(Input::Vote(zero_vote(CLAIM, b)));
    n.h.clear();

    n.propose_timeout();
    println!("effects after the propose timeout: {:?}", n.h.kinds());
    assert!(n.st.driver.step_is_prevote());
    assert_eq!(n.h.count("SignVote"), 1, "the node signs its prevote");
    assert!(n.h.first("SignVote").unwrap().detail.starts_with("Prevote h=40 r=0 value=Nil"));
    assert_eq!(n.h.count("PublishConsensusMsg"), 1, "and publishes it");
    assert_eq!(n.st.last_abstain_logged, None, "the R8 branch never ran");
    // Our own vote re-enters at the current height and is verified there (0xA5 → accepted).
    assert_eq!(n.h.details("VerifySignature"), vec![format!("vote h={H} addr={} sig=honest", n.addrs[0])]);
}

/// Control (unchanged path): the same zero-signature frame at the CURRENT height is verified once
/// and refused — no claim, not counted.
#[test]
fn forged_vote_at_current_height_is_verified_once_and_refused() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let a = n.addrs[1];
    n.feed(Input::Vote(zero_vote(H, a)));
    assert_eq!(n.verifies(), 1);
    assert!(n.claims().is_empty());
    assert!(!n.st.driver.votes().has_vote(&zero_vote(H, a)), "refused, not counted");
    assert_eq!(n.st.claim_verify_failures_total, 0, "the current-height path is not a claim path");
}

// ---------------------------------------------------------------------------------------------
// Honest claims: verified, weighted, they fire R8 and silence signing.
// ---------------------------------------------------------------------------------------------

/// Honest (0xA5) votes at 96 from two of four equal seats: two verifies, two claims, tip 96,
/// `should_abstain`, evidence = two claimants with weight 2 of 4; the propose timeout then yields
/// NO SignVote and the R8 notice is logged for height 40.
#[test]
fn honest_votes_from_two_of_four_fire_abstain_with_weighted_evidence() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let (a, b) = (n.addrs[1], n.addrs[2]);
    n.feed(Input::Vote(honest_vote(CLAIM, a)));
    n.feed(Input::Vote(honest_vote(CLAIM, b)));

    assert_eq!(n.verifies(), 2);
    assert!(n.h.details("VerifySignature").iter().all(|d| d.ends_with("sig=honest")));
    assert_eq!(n.claims(), vec![(a, CLAIM), (b, CLAIM)]);
    assert_eq!(n.tip(), Some(CLAIM));
    assert!(n.st.should_abstain(), "96 >= 40 + 20 with 2 of 4 vouching");
    let (claimants, weight, total) = n.evidence();
    assert_eq!(claimants, vec![(a, CLAIM, 1), (b, CLAIM, 1)]);
    assert_eq!((weight, total), (2, 4));
    assert_eq!(n.st.claim_verify_failures_total, 0);
    assert_eq!(n.queued(), 0, "a claim is evidence, never a buffered input (outside the window)");
    assert_eq!(n.dropped(), 2);

    n.h.clear();
    n.propose_timeout();
    println!("effects after the propose timeout: {:?}", n.h.kinds());
    assert!(n.st.driver.step_is_prevote(), "the driver did reach the prevote step");
    assert_eq!(n.h.count("SignVote"), 0, "R8: no SignVote requested");
    assert_eq!(n.h.count("PublishConsensusMsg"), 0, "R8: nothing published");
    assert_eq!(n.st.last_abstain_logged, Some(HkHeight::new(H)), "the R8 branch ran once for 40");
}

/// One honest seat of four is not above one third: claim recorded, tip None, the node votes.
#[test]
fn honest_vote_from_one_of_four_does_not_fire() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let a = n.addrs[1];
    n.feed(Input::Vote(honest_vote(CLAIM, a)));
    assert_eq!(n.verifies(), 1);
    assert_eq!(n.claims(), vec![(a, CLAIM)]);
    assert_eq!(n.tip(), None, "1 of 4 is not more than one third");
    assert!(!n.st.should_abstain());
    n.h.clear();
    n.propose_timeout();
    assert_eq!(n.h.count("SignVote"), 1, "the node keeps voting");
    assert_eq!(n.st.last_abstain_logged, None);
}

/// The proposer path is silenced too: at height 41 this node is round 0's proposer
/// ((41 − 1 + 0) mod 4 = index 0). Without claims it asks the app for a value; with honest claims
/// at 96 it requests nothing and signs nothing.
#[test]
fn honest_claims_silence_the_proposer_path_too() {
    {
        let mut c = Node::at(H);
        c.start_height(H);
        c.h.clear();
        c.start_height(H + 1);
        assert!(c.h.first("StartRound").unwrap().detail.ends_with(&format!("role={:?}", Role::Proposer)));
        assert_eq!(c.h.count("GetValue"), 1, "control: the proposer asks the app for a value");
    }

    let mut v = Node::at(H);
    v.start_height(H);
    let (a, b) = (v.addrs[1], v.addrs[2]);
    v.feed(Input::Vote(honest_vote(CLAIM, a)));
    v.feed(Input::Vote(honest_vote(CLAIM, b)));
    v.h.clear();
    v.start_height(H + 1);
    assert_eq!(v.claims().len(), 2, "claims above 41 survive the height change");
    assert!(v.st.should_abstain(), "96 >= 41 + 20");
    assert_eq!(v.h.count("GetValue"), 0, "R8: no value requested, so no proposal");
    assert_eq!(v.h.count("SignProposal"), 0);
    v.h.clear();
    v.propose_timeout();
    assert_eq!(v.h.count("SignVote"), 0);
    assert_eq!(v.st.last_abstain_logged, Some(HkHeight::new(H + 1)));
}

/// The gap boundary: at height 40 with gap 20, honest claims at 59 are filtered BEFORE any
/// verification (zero VerifySignature, no claim) and cannot fire; at 60 they are verified and fire.
/// Neither height is inside the buffer window, so none of the frames is kept.
#[test]
fn gap_boundary_claims_at_59_are_filtered_claims_at_60_fire() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let (a, b) = (n.addrs[1], n.addrs[2]);

    n.feed(Input::Vote(honest_vote(H + GAP - 1, a)));
    n.feed(Input::Vote(honest_vote(H + GAP - 1, b)));
    assert_eq!(n.verifies(), 0, "59 < 40 + 20: no verification spent on a claim that cannot fire");
    assert!(n.claims().is_empty());
    assert_eq!(n.tip(), None);
    assert!(!n.st.should_abstain());
    assert_eq!(n.queued(), 0, "59 > 40 + 4: outside the buffer window");
    assert_eq!(n.dropped(), 2);

    n.feed(Input::Vote(honest_vote(H + GAP, a)));
    n.feed(Input::Vote(honest_vote(H + GAP, b)));
    assert_eq!(n.verifies(), 2, "60 >= 40 + 20: verified");
    assert_eq!(n.claims(), vec![(a, H + GAP), (b, H + GAP)]);
    assert_eq!(n.tip(), Some(H + GAP));
    assert!(n.st.should_abstain(), "60 >= 40 + 20");
    assert_eq!(n.queued(), 0);
    assert_eq!(n.dropped(), 4);
}

// ---------------------------------------------------------------------------------------------
// The testnet shape (4×4 + 7×1 = 23): power-weighted, more than one third = power 8.
// ---------------------------------------------------------------------------------------------

/// Honest claims at 96 from the given set indices on a testnet-shaped node at 40; returns
/// (verifies, claims recorded, tip, should_abstain).
fn testnet_claims(indices: &[usize]) -> (usize, usize, Option<u64>, bool) {
    let mut n = Node::testnet_at(H);
    n.start_height(H);
    n.h.clear();
    for &i in indices {
        let addr = n.addrs[i];
        n.feed(Input::Vote(honest_vote(CLAIM, addr)));
    }
    println!(
        "testnet claimants {:?}: verifies={} claims={} tip={:?} abstain={}",
        indices,
        n.verifies(),
        n.claims().len(),
        n.tip(),
        n.st.should_abstain()
    );
    (n.verifies(), n.claims().len(), n.tip(), n.st.should_abstain())
}

/// Two externals (power 2 of 23): verified, recorded, but no tip and no abstain. The old rule
/// ("two distinct addresses") would have fired here.
#[test]
fn testnet_two_externals_do_not_fire() {
    assert_eq!(testnet_claims(&[4, 5]), (2, 2, None, false));
}

/// All seven externals (power 7 of 23, exactly f): no tip, no abstain.
#[test]
fn testnet_seven_externals_do_not_fire() {
    assert_eq!(testnet_claims(&[4, 5, 6, 7, 8, 9, 10]), (7, 7, None, false));
}

/// Two other founders (power 8 of 23): tip 96, abstain.
#[test]
fn testnet_two_founders_fire() {
    assert_eq!(testnet_claims(&[1, 2]), (2, 2, Some(CLAIM), true));
}

/// One founder plus four externals (power 8 of 23): tip 96, abstain.
#[test]
fn testnet_one_founder_plus_four_externals_fire() {
    assert_eq!(testnet_claims(&[1, 4, 5, 6, 7]), (5, 5, Some(CLAIM), true));
}

/// One founder plus three externals (power 7 of 23): no tip, no abstain.
#[test]
fn testnet_one_founder_plus_three_externals_do_not_fire() {
    assert_eq!(testnet_claims(&[1, 4, 5, 6]), (4, 4, None, false));
}

/// A key-holding minority's u64::MAX claims (two externals, honest signatures) are recorded but
/// cannot raise the tip: None alone, still None with one founder at 96 (power 6 of 23), and
/// Some(96) — the honest height, not u64::MAX — once a second founder vouches for 96.
#[test]
fn testnet_u64_max_claims_from_key_holding_minority_do_not_raise_tip() {
    let mut n = Node::testnet_at(H);
    n.start_height(H);
    n.h.clear();
    let (x, y, f1, f2) = (n.addrs[4], n.addrs[5], n.addrs[1], n.addrs[2]);

    n.feed(Input::Vote(honest_vote(u64::MAX, x)));
    n.feed(Input::Vote(honest_vote(u64::MAX, y)));
    assert_eq!(n.verifies(), 2);
    assert_eq!(n.claims(), vec![(x, u64::MAX), (y, u64::MAX)], "recorded: the keys are real");
    assert_eq!(n.tip(), None, "power 2 of 23 vouches for nothing");
    assert!(!n.st.should_abstain());

    n.feed(Input::Vote(honest_vote(CLAIM, f1)));
    assert_eq!(n.tip(), None, "power 6 of 23 is still not above one third");
    assert_eq!(n.evidence().1, 6);
    assert!(!n.st.should_abstain());

    n.feed(Input::Vote(honest_vote(CLAIM, f2)));
    assert_eq!(n.tip(), Some(CLAIM), "power 10 of 23 at height 96: the honest height wins");
    assert_eq!(n.evidence().1, 10);
    assert!(n.st.should_abstain());
    assert_eq!(n.queued(), 0, "every frame is outside the window: none buffered, u64::MAX included");
    assert_eq!(n.dropped(), 4);
}

// ---------------------------------------------------------------------------------------------
// Failed claim verifications: counted, and warned about once per address per window.
// ---------------------------------------------------------------------------------------------

/// Six zero-signature votes at increasing heights (all above the buffer window) from one address
/// cost six verifications and record no claim; a second address likewise. The total counts every
/// failure; the warn is logged once per address per window.
#[test]
fn forged_future_votes_are_each_verified_and_warned_once_per_address_per_window() {
    let mut n = Node::at(H);
    n.start_height(H);
    clear_captured_log();
    n.h.clear();
    let (a, b) = (n.addrs[1], n.addrs[2]);
    let frames: u64 = 6;

    for i in 0..frames {
        n.feed(Input::Vote(zero_vote(CLAIM + i, a)));
    }
    assert_eq!(n.verifies(), frames as usize, "every frame is verified");
    assert!(n.h.details("VerifySignature").iter().all(|d| d.ends_with("sig=zero")));
    assert_eq!(n.failures(), vec![(a, frames as u32)]);
    assert_eq!(n.st.claim_verify_failures_total, frames);
    assert_eq!(n.queued(), 0, "96.. is outside the window: nothing buffered, no buffer verify");
    assert_eq!(n.dropped(), frames);
    assert!(n.claims().is_empty());

    for i in 0..frames {
        n.feed(Input::Vote(zero_vote(CLAIM + i, b)));
    }
    assert_eq!(n.verifies(), 2 * frames as usize, "a second address: every frame verified too");
    assert_eq!(n.failures(), vec![(a, frames as u32), (b, frames as u32)]);
    assert_eq!(n.st.claim_verify_failures_total, 2 * frames);
    assert!(n.claims().is_empty());
    assert_eq!(n.tip(), None);
    assert!(!n.st.should_abstain());
    assert_eq!(n.dropped(), 2 * frames);

    let log = captured_log();
    assert_eq!(log.matches(FAILED_VERIFY_WARN).count(), 2, "one warn per address per window");
    assert!(log.contains(&format!("validator={a}")) && log.contains(&format!("validator={b}")));
}

/// The warn window restarts only when OUR height has advanced by `gap` since it last restarted:
/// StartHeight at 41 and at 59 keep the window (the address does not warn again), StartHeight at
/// 60 restarts it (the address warns once more). Every frame before and after the restart is
/// verified, and the total counts each failure.
#[test]
fn failure_warn_window_restarts_only_after_gap_heights_of_progress() {
    let mut n = Node::at(H);
    n.start_height(H);
    clear_captured_log();
    let a = n.addrs[1];
    assert_eq!(n.st.claim_warn_window_from, HkHeight::new(H));

    for i in 0..3u64 {
        n.feed(Input::Vote(zero_vote(CLAIM + i, a)));
    }
    n.h.clear();
    n.feed(Input::Vote(zero_vote(CLAIM + 10, a)));
    assert_eq!(n.verifies(), 1, "the next frame in the window is verified");
    assert_eq!(n.failures(), vec![(a, 4)]);
    assert_eq!(captured_log().matches(FAILED_VERIFY_WARN).count(), 1, "warned once in the window");

    n.start_height(H + 1);
    assert_eq!(n.st.claim_warn_window_from, HkHeight::new(H), "41 < 40 + 20: the same window");
    n.h.clear();
    n.feed(Input::Vote(zero_vote(CLAIM + 20, a)));
    assert_eq!(n.verifies(), 1);
    assert_eq!(n.failures(), vec![(a, 5)]);

    n.start_height(H + GAP - 1);
    assert_eq!(n.st.claim_warn_window_from, HkHeight::new(H), "59 < 40 + 20: the same window");
    n.h.clear();
    n.feed(Input::Vote(zero_vote(CLAIM + 21, a)));
    assert_eq!(n.verifies(), 1);
    assert_eq!(n.failures(), vec![(a, 6)]);
    assert_eq!(captured_log().matches(FAILED_VERIFY_WARN).count(), 1, "still one warn: the same window");

    n.start_height(H + GAP);
    assert_eq!(n.st.claim_warn_window_from, HkHeight::new(H + GAP), "60 >= 40 + 20: restarted");
    assert!(n.failures().is_empty());
    n.h.clear();
    for i in 0..4u64 {
        n.feed(Input::Vote(zero_vote(CLAIM + 30 + i, a)));
    }
    assert_eq!(n.verifies(), 4, "every frame verified in the new window too");
    assert_eq!(n.failures(), vec![(a, 4)]);
    assert_eq!(captured_log().matches(FAILED_VERIFY_WARN).count(), 2, "one warn per window");
    assert_eq!(n.st.claim_verify_failures_total, 10, "the total counts every failure");
    assert!(n.claims().is_empty());
    assert_eq!(n.queued(), 0, "every frame was above the buffer window");
}

/// Recorded honest claims persist through a flood of zero-signature frames for a third member
/// (every frame verified and refused) and through frames re-using the recorded claimants at or
/// below their recorded height (filtered without a verify); forged frames above the recorded
/// height are verified, fail and change nothing.
#[test]
fn recorded_honest_claims_persist_through_forged_floods() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let (a, b, c) = (n.addrs[1], n.addrs[2], n.addrs[3]);
    n.feed(Input::Vote(honest_vote(CLAIM, a)));
    n.feed(Input::Vote(honest_vote(CLAIM, b)));
    assert_eq!(n.claims(), vec![(a, CLAIM), (b, CLAIM)]);
    assert!(n.st.should_abstain());
    n.h.clear();

    // A flood for the third member: every frame verified and refused; the honest claims are
    // untouched.
    for i in 0..30u64 {
        n.feed(Input::Vote(zero_vote(CLAIM + i, c)));
    }
    assert_eq!(n.verifies(), 30);
    assert_eq!(n.claims(), vec![(a, CLAIM), (b, CLAIM)]);
    assert_eq!(n.tip(), Some(CLAIM));
    assert!(n.st.should_abstain());
    n.h.clear();

    // Re-using a recorded claimant at or below its recorded height: no information gain, no verify
    // (and all three heights are above the buffer window, so no buffer verify either).
    n.feed(Input::Vote(vote(CLAIM, 1, VoteType::Prevote, a, ZERO)));
    n.feed(Input::Vote(zero_vote(CLAIM - 6, a)));
    n.feed(Input::Vote(zero_vote(H + GAP, b)));
    assert_eq!(n.verifies(), 0, "filtered before any verification");
    assert_eq!(n.claims(), vec![(a, CLAIM), (b, CLAIM)]);
    n.h.clear();

    // Above the recorded height: verified, refused, the claim stays where it was.
    for i in 1..=5u64 {
        n.feed(Input::Vote(zero_vote(CLAIM + i, a)));
    }
    assert_eq!(n.verifies(), 5);
    assert_eq!(n.claims(), vec![(a, CLAIM), (b, CLAIM)], "a refused forgery never moves a claim");
    assert_eq!(n.tip(), Some(CLAIM));
    assert!(n.st.should_abstain());
    assert_eq!(n.st.claim_verify_failures_total, 30 + 5, "the total counts every failure");
    assert_eq!(n.queued(), 0);
}

/// Two founders (power 8 of 23) each send three zero-signature far-future votes, then their
/// honest votes: all eight are verified, the six forged ones are refused and record no claim,
/// the two honest ones are recorded, the tip is their height and the node abstains (the propose
/// timeout yields no SignVote).
#[test]
fn honest_votes_after_failed_verifications_arm_the_abstain() {
    let mut n = Node::testnet_at(H);
    n.start_height(H);
    n.h.clear();
    let (f1, f2) = (n.addrs[1], n.addrs[2]);

    for i in 0..3u64 {
        n.feed(Input::Vote(zero_vote(CLAIM + i, f1)));
        n.feed(Input::Vote(zero_vote(CLAIM + i, f2)));
    }
    assert_eq!(n.verifies(), 6, "every forged frame is verified");
    assert!(n.h.details("VerifySignature").iter().all(|d| d.ends_with("sig=zero")));
    assert!(n.claims().is_empty(), "a refused signature records no claim");
    assert_eq!(n.failures(), vec![(f1, 3), (f2, 3)]);
    assert!(!n.st.should_abstain());

    n.feed(Input::Vote(honest_vote(CLAIM, f1)));
    n.feed(Input::Vote(honest_vote(CLAIM, f2)));
    assert_eq!(n.verifies(), 6 + 2, "both honest votes are verified");
    assert_eq!(
        n.h.details("VerifySignature")[6..].to_vec(),
        vec![
            format!("vote h={CLAIM} addr={f1} sig=honest"),
            format!("vote h={CLAIM} addr={f2} sig=honest"),
        ]
    );
    assert_eq!(n.claims(), vec![(f1, CLAIM), (f2, CLAIM)]);
    assert_eq!(n.tip(), Some(CLAIM));
    assert!(n.st.should_abstain(), "power 8 of 23 vouches for 96 >= 40 + 20");
    let (claimants, weight, total) = n.evidence();
    assert_eq!(claimants, vec![(f1, CLAIM, 4), (f2, CLAIM, 4)]);
    assert_eq!((weight, total), (8, 23));
    assert_eq!(n.st.claim_verify_failures_total, 6);
    assert_eq!(n.queued(), 0, "every frame is outside the buffer window");

    n.h.clear();
    n.propose_timeout();
    assert_eq!(n.h.count("SignVote"), 0, "R8: no SignVote requested");
    assert_eq!(n.h.count("PublishConsensusMsg"), 0, "R8: nothing published");
    assert_eq!(n.st.last_abstain_logged, Some(HkHeight::new(H)), "the R8 branch ran for 40");
}

/// A seat on the tip (no claims, so it votes) verifies every far-future frame and records no
/// claim from a refused one: zero-signature frames for every other member, three each, claiming
/// heights near u64::MAX, are verified and refused (no claim, no abstain). Five heights later,
/// two founders' honest far-future votes are verified and recorded, and the node abstains.
#[test]
fn a_seat_on_the_tip_verifies_every_frame_and_records_later_honest_claims() {
    let mut n = Node::testnet_at(H);
    n.start_height(H);
    n.h.clear();
    let others: Vec<HkAddress> = n.addrs[1..].to_vec();
    assert_eq!(others.len(), 10);

    for i in 0..3u64 {
        for &x in &others {
            n.feed(Input::Vote(zero_vote(u64::MAX - i, x)));
        }
    }
    assert_eq!(n.verifies(), 30, "every forged frame is verified");
    assert!(n.claims().is_empty(), "no claim, however high the forged height");
    assert_eq!(n.tip(), None);
    assert!(!n.st.should_abstain(), "on the tip: the node votes");
    assert_eq!(n.st.claim_verify_failures_total, 30);
    assert_eq!(n.queued(), 0, "every frame is outside the buffer window");

    n.start_height(H + 5);
    assert_eq!(n.st.claim_warn_window_from, HkHeight::new(H), "45 < 40 + 20");
    assert_eq!(n.failures().len(), 10, "every other member's failures are still counted");
    n.h.clear();
    let (f1, f2) = (n.addrs[1], n.addrs[2]);
    n.feed(Input::Vote(honest_vote(CLAIM, f1)));
    n.feed(Input::Vote(honest_vote(CLAIM, f2)));
    assert_eq!(
        n.h.details("VerifySignature"),
        vec![
            format!("vote h={CLAIM} addr={f1} sig=honest"),
            format!("vote h={CLAIM} addr={f2} sig=honest"),
        ]
    );
    assert_eq!(n.claims(), vec![(f1, CLAIM), (f2, CLAIM)]);
    assert_eq!(n.tip(), Some(CLAIM));
    assert!(n.st.should_abstain(), "power 8 of 23 vouches for 96 >= 45 + 20");
}

// ---------------------------------------------------------------------------------------------
// Who never verifies a CLAIM: observers and frames naming ourselves.
// ---------------------------------------------------------------------------------------------

/// A node with consensus disabled never abstains, so it spends no verification on future claims.
/// (The frames sit above the buffer window too, so the buffer never sees them either.)
#[test]
fn observer_with_consensus_disabled_never_verifies() {
    let set = equal_set();
    let me = set.iter().next().unwrap().address;
    let mut n = Node::build(set, me, H, false);
    n.start_height(H);
    assert!(!n.st.is_active_validator());
    assert!(n.h.first("StartRound").unwrap().detail.ends_with(&format!("role={:?}", Role::None)));
    n.h.clear();
    let (a, b) = (n.addrs[1], n.addrs[2]);
    n.feed(Input::Vote(honest_vote(CLAIM, a)));
    n.feed(Input::Vote(honest_vote(CLAIM, b)));
    assert_eq!(n.verifies(), 0);
    assert!(n.claims().is_empty());
    assert_eq!(n.tip(), None);
    assert!(!n.st.should_abstain());
    assert_eq!(n.queued(), 0, "outside the window: not buffered");
    assert_eq!(n.dropped(), 2);
}

/// A node whose address is not in the set (a full node) never verifies a future claim either.
#[test]
fn observer_outside_the_set_never_verifies() {
    let set = equal_set();
    let stranger = HkAddress::new([0xEE; 20]);
    assert!(set.get_by_address(&stranger).is_none());
    let mut n = Node::build(set, stranger, H, true);
    n.start_height(H);
    assert!(!n.st.is_active_validator());
    n.h.clear();
    let (a, b) = (n.addrs[1], n.addrs[2]);
    n.feed(Input::Vote(honest_vote(CLAIM, a)));
    n.feed(Input::Vote(honest_vote(CLAIM, b)));
    assert_eq!(n.verifies(), 0);
    assert!(n.claims().is_empty());
    assert!(!n.st.should_abstain());
    assert_eq!(n.queued(), 0);
    assert_eq!(n.dropped(), 2);
}

/// A future-height frame naming OUR OWN address can only be a forgery: no claim verify, no claim.
/// (Above the window, so the buffer drops it before any verify as well.)
#[test]
fn frame_naming_our_own_address_never_verifies() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let me = n.addrs[0];
    assert_eq!(n.st.address(), &me);
    n.feed(Input::Vote(honest_vote(CLAIM, me)));
    n.feed(Input::Vote(zero_vote(CLAIM + 1, me)));
    assert_eq!(n.verifies(), 0);
    assert!(n.claims().is_empty());
    assert_eq!(n.st.claim_verify_failures_total, 0);
    assert_eq!(n.queued(), 0);
    assert_eq!(n.dropped(), 2);
}

/// A future vote signed with a key we do not hold (0x5A: rotated after our height): one verify,
/// refused, no claim, charged to the address, no panic. Above the window it is not buffered (a
/// near-window one would be refused at admission instead — the §1.4 residual).
#[test]
fn rotated_key_future_vote_is_refused_without_claim_or_panic() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let a = n.addrs[1];
    n.feed(Input::Vote(rotated_vote(CLAIM, a)));
    assert_eq!(n.h.details("VerifySignature"), vec![format!("vote h={CLAIM} addr={a} sig=rotated")]);
    assert!(n.claims().is_empty());
    assert_eq!(n.failures(), vec![(a, 1)]);
    assert_eq!(n.st.claim_verify_failures_total, 1);
    assert_eq!(n.queued(), 0, "outside the window: not buffered");
    assert_eq!(n.dropped(), 1);
    assert!(!n.st.should_abstain());

    // The same rotated key one height above us: verified once at admission, refused, not kept.
    n.h.clear();
    n.feed(Input::Vote(rotated_vote(H + 1, a)));
    assert_eq!(n.h.details("VerifySignature"), vec![format!("vote h={} addr={a} sig=rotated", H + 1)]);
    assert_eq!(n.queued(), 0);
    assert_eq!(n.dropped(), 2);
    assert_eq!(n.st.claim_verify_failures_total, 1, "the buffer path is not the claim path");
}

/// Opt-out (SEPARATE RUN ONLY): with `HK_ABSTAIN_GAP=0` the whole claim path is skipped — no
/// verify, no claim, no evidence — and the node still signs. Run it on its own:
///   HK_ABSTAIN_GAP=0 CARGO_TARGET_DIR=$HOME/hk-target-chain cargo test --offline -p hk-consensus --test r8_claims -- --ignored --nocapture --test-threads=1
/// (`abstain_threshold` caches its answer per process, so the env must be set before the first call.)
#[test]
#[ignore]
fn opt_out_gap_zero_skips_the_claim_path() {
    assert_eq!(std::env::var("HK_ABSTAIN_GAP").as_deref(), Ok("0"), "run with HK_ABSTAIN_GAP=0");
    assert_eq!(HkContext::new().abstain_threshold(), None);
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let (a, b) = (n.addrs[1], n.addrs[2]);
    n.feed(Input::Vote(honest_vote(CLAIM, a)));
    n.feed(Input::Vote(honest_vote(CLAIM, b)));
    assert_eq!(n.verifies(), 0, "opt-out: zero work on future claims");
    assert!(n.claims().is_empty(), "opt-out: no claims recorded");
    assert_eq!(n.tip(), None);
    assert!(!n.st.should_abstain());
    assert_eq!(n.evidence(), (Vec::new(), 0, 4));
    assert_eq!(n.queued(), 0, "outside the window: not buffered");
    assert_eq!(n.dropped(), 2);
    n.h.clear();
    n.propose_timeout();
    assert_eq!(n.h.count("SignVote"), 1, "the node still votes");
    assert_eq!(n.h.count("PublishConsensusMsg"), 1);
}

// ---------------------------------------------------------------------------------------------
// The vote buffer, v2: members only, verified first, dedup and caps on verified entries.
// ---------------------------------------------------------------------------------------------

/// `buffer_admission` verdicts by input kind: a member's vote in the window → Verify under that
/// member's key; a non-member's or an out-of-window vote → Drop; a proposal from the scheduled
/// proposer → Verify, from anyone else → Drop; a proposed value from the scheduled proposer →
/// Admit (no signature of its own), from anyone else → Drop; other kinds → Admit.
#[test]
fn buffer_admission_verdicts_by_input_kind() {
    let mut n = Node::at(H);
    n.start_height(H);
    let (a, stranger) = (n.addrs[1], HkAddress::new([0xEE; 20]));
    let h1 = HkHeight::new(H + 1);
    let far = HkHeight::new(H + BUFFER_HEIGHT_WINDOW + 1);
    let r1 = Round::new(1);
    let p = n.proposer(H + 1, 1);
    let q = n.other_member(p);

    assert!(matches!(
        n.st.buffer_admission(&h1, &Input::Vote(honest_vote(H + 1, a))),
        BufferAdmission::Verify(v) if v.address == a
    ));
    assert!(matches!(
        n.st.buffer_admission(&h1, &Input::Vote(honest_vote(H + 1, stranger))),
        BufferAdmission::Drop
    ));
    assert!(matches!(
        n.st.buffer_admission(&far, &Input::Vote(honest_vote(far.as_u64(), a))),
        BufferAdmission::Drop
    ));
    assert!(matches!(
        n.st.buffer_admission(&h1, &Input::Proposal(honest_proposal(H + 1, r1, p, b""))),
        BufferAdmission::Verify(v) if v.address == p
    ));
    assert!(matches!(
        n.st.buffer_admission(&h1, &Input::Proposal(honest_proposal(H + 1, r1, q, b""))),
        BufferAdmission::Drop
    ));
    assert!(matches!(
        n.st.buffer_admission(&h1, &proposed_value(H + 1, r1, p, b"")),
        BufferAdmission::Admit
    ));
    assert!(matches!(
        n.st.buffer_admission(&h1, &proposed_value(H + 1, r1, q, b"")),
        BufferAdmission::Drop
    ));
    assert!(matches!(
        n.st.buffer_admission(&h1, &Input::TimeoutElapsed(Timeout::propose(Round::new(0)))),
        BufferAdmission::Admit
    ));
}

/// A 0xA5 vote at h+1 from a member is buffered after exactly one VerifySignature; when the node
/// reaches h+1 it is replayed and verified again at its own height, then counted.
#[test]
fn buffer_admits_honest_member_vote_in_window_after_one_verify() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let a = n.addrs[1];
    let v = honest_vote(H + 1, a);
    n.feed(Input::Vote(v.clone()));
    assert_eq!(n.h.details("VerifySignature"), vec![format!("vote h={} addr={a} sig=honest", H + 1)]);
    assert_eq!(n.queued(), 1, "buffered after the signature verified");
    assert_eq!(n.dropped(), 0);
    assert!(n.claims().is_empty(), "41 < 40 + 20: not a claim");
    assert_eq!(n.st.claim_verify_failures_total, 0);

    n.h.clear();
    n.start_height(H + 1);
    assert_eq!(n.queued(), 0, "taken for height 41");
    assert_eq!(n.h.details("VerifySignature"), vec![format!("vote h={} addr={a} sig=honest", H + 1)]);
    assert!(n.st.driver.votes().has_vote(&v), "replayed, verified at its height, counted");
}

/// A zero-signature vote at h+1 from a member is verified once and NOT buffered; it is not a
/// claim-path failure either.
#[test]
fn buffer_drops_zero_signature_member_vote_in_window_after_one_verify() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let a = n.addrs[1];
    n.feed(Input::Vote(zero_vote(H + 1, a)));
    assert_eq!(n.h.details("VerifySignature"), vec![format!("vote h={} addr={a} sig=zero", H + 1)]);
    assert_eq!(n.queued(), 0, "refused: not buffered");
    assert_eq!(n.dropped(), 1);
    assert!(n.claims().is_empty());
    assert!(n.failures().is_empty(), "the buffer path is not the claim path");
    assert_eq!(n.st.claim_verify_failures_total, 0);
}

/// A vote at h+1 from a non-member costs no verify and is not buffered, whatever its signature.
#[test]
fn buffer_drops_non_member_vote_in_window_without_verify() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let stranger = HkAddress::new([0xEE; 20]);
    assert!(n.set.get_by_address(&stranger).is_none());
    n.feed(Input::Vote(honest_vote(H + 1, stranger)));
    n.feed(Input::Vote(zero_vote(H + 1, stranger)));
    assert_eq!(n.verifies(), 0, "dropped before any verification");
    assert_eq!(n.queued(), 0);
    assert_eq!(n.dropped(), 2);
}

/// A member's vote at h+5 (outside the window) is dropped without a verify; at h+4 (the edge) it
/// is verified and kept.
#[test]
fn buffer_drops_member_vote_outside_window_without_verify() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let a = n.addrs[1];
    n.feed(Input::Vote(honest_vote(H + BUFFER_HEIGHT_WINDOW + 1, a)));
    assert_eq!(n.verifies(), 0, "45 > 40 + 4: dropped before any verification");
    assert_eq!(n.queued(), 0);
    assert_eq!(n.dropped(), 1);

    n.feed(Input::Vote(honest_vote(H + BUFFER_HEIGHT_WINDOW, a)));
    assert_eq!(n.verifies(), 1, "44 = 40 + 4: inside the window, verified");
    assert_eq!(n.queued(), 1);
    assert_eq!(n.dropped(), 1);
    assert!(n.claims().is_empty());
}

/// Forgeries evict nothing: after a zero-signature frame for (h+1, A, prevote, 0) the honest 0xA5
/// vote for the same slot IS buffered; a second 0xA5 vote for that slot is dropped as a duplicate
/// before any verification.
#[test]
fn buffer_slot_survives_forgery_then_admits_honest_vote_and_dedups() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let a = n.addrs[1];

    n.feed(Input::Vote(zero_vote(H + 1, a)));
    assert_eq!(n.verifies(), 1);
    assert_eq!(n.queued(), 0, "the forgery took no slot");
    assert_eq!(n.dropped(), 1);

    n.feed(Input::Vote(honest_vote(H + 1, a)));
    assert_eq!(n.verifies(), 2);
    assert_eq!(n.queued(), 1, "the honest vote for the same slot is buffered");
    assert_eq!(n.dropped(), 1);

    n.feed(Input::Vote(honest_vote(H + 1, a)));
    assert_eq!(n.verifies(), 2, "a taken slot is refused before any verification");
    assert_eq!(n.queued(), 1, "one verified vote per (height, address, type, round)");
    assert_eq!(n.dropped(), 2);
}

/// Ten identical honest votes for one slot: one verify, one entry.
#[test]
fn vote_buffer_keeps_one_entry_per_address_type_round() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let a = n.addrs[1];
    for _ in 0..10 {
        n.feed(Input::Vote(honest_vote(H + 1, a)));
    }
    assert_eq!(n.verifies(), 1, "only the first reaches verification");
    assert_eq!(n.queued(), 1, "identical frames share one entry");
    assert_eq!(n.dropped(), 9);
}

/// Honest prevotes at rounds 0..20 from one member at h+1: BUFFER_MAX_VOTE_ROUNDS_PER_ADDRESS
/// verified and kept, the rest dropped before verification.
#[test]
fn vote_buffer_caps_distinct_rounds_per_address() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let a = n.addrs[1];
    for r in 0..20u32 {
        n.feed(Input::Vote(vote(H + 1, r, VoteType::Prevote, a, HONEST)));
    }
    assert_eq!(n.verifies(), BUFFER_MAX_VOTE_ROUNDS_PER_ADDRESS, "the cap is checked before the verify");
    assert_eq!(n.queued(), BUFFER_MAX_VOTE_ROUNDS_PER_ADDRESS);
    assert_eq!(n.dropped() as usize, 20 - BUFFER_MAX_VOTE_ROUNDS_PER_ADDRESS);
}

/// An honest prevote and an honest precommit at the same round are two entries (two verifies).
#[test]
fn vote_buffer_keeps_prevote_and_precommit_separately() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let a = n.addrs[1];
    n.feed(Input::Vote(vote(H + 1, 0, VoteType::Prevote, a, HONEST)));
    n.feed(Input::Vote(vote(H + 1, 0, VoteType::Precommit, a, HONEST)));
    assert_eq!(n.verifies(), 2);
    assert_eq!(n.queued(), 2);
    assert_eq!(n.dropped(), 0);
}

// ---------------------------------------------------------------------------------------------
// Proposals and proposed values: never a claim, buffered only when they could matter.
// ---------------------------------------------------------------------------------------------

/// A zero-signature future-height proposal from the SCHEDULED proposer at 96 records no claim,
/// costs no verify and is not buffered (outside the window: dropped before any verify). At the
/// window edge, 44 (= 40 + 4): a zero-signature one is verified once and dropped, an honest one is
/// verified once and kept; at 45 an honest one is dropped without a verify.
#[test]
fn forged_future_proposal_records_no_claim_costs_no_verify_and_is_not_buffered() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let p96 = n.proposer(CLAIM, 0);
    assert_ne!(p96, n.addrs[0]);
    n.feed(Input::Proposal(zero_proposal(CLAIM, Round::new(0), p96, b"forged")));
    assert_eq!(n.verifies(), 0, "outside the window: never verified");
    assert!(n.claims().is_empty(), "proposals are no longer height evidence");
    assert_eq!(n.tip(), None);
    assert_eq!(n.queued(), 0, "96 > 40 + 4: not buffered");
    assert_eq!(n.dropped(), 1);

    let edge = H + BUFFER_HEIGHT_WINDOW;
    let p_edge = n.proposer(edge, 0);
    n.feed(Input::Proposal(zero_proposal(edge, Round::new(0), p_edge, b"edge-forged")));
    assert_eq!(n.h.details("VerifySignature"), vec![format!("proposal h={edge} addr={p_edge} sig=zero")]);
    assert_eq!(n.queued(), 0, "verified and refused");
    assert_eq!(n.dropped(), 2);

    n.feed(Input::Proposal(honest_proposal(edge, Round::new(0), p_edge, b"edge-honest")));
    assert_eq!(n.verifies(), 2);
    assert_eq!(n.queued(), 1, "44 = 40 + 4 is inside the window: verified and kept");
    assert_eq!(n.dropped(), 2);

    let p_out = n.proposer(edge + 1, 0);
    n.feed(Input::Proposal(honest_proposal(edge + 1, Round::new(0), p_out, b"out")));
    assert_eq!(n.verifies(), 2, "45 is outside the window: no verify");
    assert_eq!(n.queued(), 1);
    assert_eq!(n.dropped(), 3);
    assert!(n.claims().is_empty());
}

/// A proposal at h+1 from the scheduled proposer: with a 0xA5 signature it is buffered after one
/// verify; with a zero signature it is verified once and dropped. (Round 1, because round 0's
/// scheduled proposer at 41 is this node itself.)
#[test]
fn proposal_in_window_from_scheduled_proposer_buffered_after_one_verify_zero_signature_dropped() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let p1 = n.proposer(H + 1, 1);
    let p2 = n.proposer(H + 1, 2);
    assert_ne!(p1, n.addrs[0]);
    assert_ne!(p2, n.addrs[0]);

    n.feed(Input::Proposal(honest_proposal(H + 1, Round::new(1), p1, b"honest")));
    assert_eq!(n.h.details("VerifySignature"), vec![format!("proposal h={} addr={p1} sig=honest", H + 1)]);
    assert_eq!(n.queued(), 1, "buffered after the signature verified");
    assert_eq!(n.dropped(), 0);

    n.feed(Input::Proposal(zero_proposal(H + 1, Round::new(2), p2, b"forged")));
    assert_eq!(n.verifies(), 2);
    assert!(n.h.details("VerifySignature")[1].ends_with(&format!("addr={p2} sig=zero")));
    assert_eq!(n.queued(), 1, "verified and refused");
    assert_eq!(n.dropped(), 1);
    assert!(n.claims().is_empty());
}

/// A proposal at 42 round 0 from the scheduled proposer IS buffered (queue size 1) after one
/// verify, without a claim.
#[test]
fn proposal_within_window_from_scheduled_proposer_is_buffered() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let p = n.proposer(H + 2, 0);
    n.feed(Input::Proposal(honest_proposal(H + 2, Round::new(0), p, b"v")));
    assert_eq!(n.verifies(), 1);
    assert_eq!(n.queued(), 1);
    assert_eq!(n.dropped(), 0);
    assert!(n.claims().is_empty());
}

/// A proposal at 42 round 0 from a member who is NOT the scheduled proposer — or from an address
/// outside the set — is dropped before any verification, whatever its signature.
#[test]
fn proposal_from_non_scheduled_proposer_is_dropped() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let p = n.proposer(H + 2, 0);
    let q = n.other_member(p);
    n.feed(Input::Proposal(honest_proposal(H + 2, Round::new(0), q, b"member")));
    assert_eq!(n.queued(), 0);
    assert_eq!(n.dropped(), 1);
    n.feed(Input::Proposal(honest_proposal(H + 2, Round::new(0), HkAddress::new([0xAA; 20]), b"nobody")));
    assert_eq!(n.queued(), 0);
    assert_eq!(n.dropped(), 2);
    assert_eq!(n.verifies(), 0, "dropped before any verification");
    assert!(n.claims().is_empty());
}

/// A future-height proposal with `Round::Nil` is dropped at the top of `on_proposal` — before the
/// buffer (whose own Nil check in `proposal_slot_admits` is now a second line) and long before
/// `select_proposer`, which asserts on a Nil round: no panic, no effect, nothing queued.
#[test]
fn proposal_with_round_nil_is_dropped_without_panic() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let p = n.proposer(H + 2, 0);
    n.feed(Input::Proposal(zero_proposal(H + 2, Round::Nil, p, b"nil")));
    assert!(n.h.log.is_empty(), "no effect at all: {:?}", n.h.kinds());
    assert_eq!(n.queued(), 0);
    assert_eq!(n.dropped(), 0, "refused before it reached the buffer");
    assert_eq!(n.verifies(), 0);
    assert!(n.claims().is_empty());
}

/// A second proposal for the same (height, round) — even with a different value — is dropped
/// before any verification.
#[test]
fn proposal_duplicate_height_round_is_dropped() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let p = n.proposer(H + 2, 0);
    n.feed(Input::Proposal(honest_proposal(H + 2, Round::new(0), p, b"one")));
    assert_eq!(n.verifies(), 1);
    n.feed(Input::Proposal(honest_proposal(H + 2, Round::new(0), p, b"two")));
    assert_eq!(n.verifies(), 1, "the taken slot is refused before any verification");
    assert_eq!(n.queued(), 1, "one proposal per (height, round)");
    assert_eq!(n.dropped(), 1);
}

/// At most BUFFER_MAX_PROPOSAL_ROUNDS_PER_HEIGHT proposal rounds are kept per height, each from
/// its own scheduled proposer; the rest are dropped before verification.
#[test]
fn proposal_rounds_per_height_are_capped() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let rounds = 5u32;
    for r in 0..rounds {
        let p = n.proposer(H + 2, r);
        n.feed(Input::Proposal(honest_proposal(H + 2, Round::new(r), p, &r.to_le_bytes())));
    }
    assert_eq!(n.verifies(), BUFFER_MAX_PROPOSAL_ROUNDS_PER_HEIGHT);
    assert_eq!(n.queued(), BUFFER_MAX_PROPOSAL_ROUNDS_PER_HEIGHT);
    assert_eq!(n.dropped() as usize, rounds as usize - BUFFER_MAX_PROPOSAL_ROUNDS_PER_HEIGHT);
    assert!(n.claims().is_empty());
}

/// The host's proposed value at h+1 follows the proposal rules without any verification: from the
/// scheduled proposer it is buffered; from another address, with round Nil, or as a second one for
/// the same round it is dropped; at most BUFFER_MAX_PROPOSAL_ROUNDS_PER_HEIGHT rounds per height.
/// (Round 1 first, because round 0's scheduled proposer at 41 is this node itself.)
#[test]
fn proposed_value_follows_the_proposal_rules_without_verification() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let p1 = n.proposer(H + 1, 1);
    let p2 = n.proposer(H + 1, 2);
    let p3 = n.proposer(H + 1, 3);
    let other = n.other_member(p1);

    n.feed(proposed_value(H + 1, Round::new(1), p1, b"v1"));
    assert_eq!(n.queued(), 1, "from the scheduled proposer: buffered");
    assert_eq!(n.dropped(), 0);

    n.feed(proposed_value(H + 1, Round::new(1), other, b"v1-other"));
    assert_eq!(n.queued(), 1, "from another address: dropped");
    assert_eq!(n.dropped(), 1);

    n.feed(proposed_value(H + 1, Round::Nil, p1, b"nil"));
    assert_eq!(n.queued(), 1, "round Nil: dropped, no panic");
    assert_eq!(n.dropped(), 2);

    n.feed(proposed_value(H + 1, Round::new(1), p1, b"v1-again"));
    assert_eq!(n.queued(), 1, "a second one for the same round: dropped");
    assert_eq!(n.dropped(), 3);

    n.feed(proposed_value(H + 1, Round::new(2), p2, b"v2"));
    assert_eq!(n.queued(), 2, "a second round: buffered");
    n.feed(proposed_value(H + 1, Round::new(3), p3, b"v3"));
    assert_eq!(n.queued(), BUFFER_MAX_PROPOSAL_ROUNDS_PER_HEIGHT, "a third round: capped");
    assert_eq!(n.dropped(), 4);

    assert_eq!(n.verifies(), 0, "a proposed value carries no signature of its own: never verified");
    assert!(n.h.log.is_empty(), "no effect at all: {:?}", n.h.kinds());
    assert!(n.claims().is_empty());
}

// ---------------------------------------------------------------------------------------------
// Round Nil: refused at the top of on_vote / on_proposal, before any height branch.
// ---------------------------------------------------------------------------------------------

/// A CURRENT-height proposal with `Round::Nil` from a current-set member (zero signature, the node
/// live at round 0) is dropped at the door: no panic, no VerifySignature, nothing buffered, nothing
/// stored, no effect at all — from the scheduled proposer of (40, 0) and from another member alike.
/// Until this guard such a frame reached `verify_signed_proposal` → `get_proposer` →
/// `select_proposer`, which asserts a defined round: a consensus-actor panic from a frame nobody
/// signed (the proposer check runs before the signature check).
#[test]
fn current_height_proposal_with_round_nil_is_dropped_without_panic() {
    let mut n = Node::at(H);
    n.start_height(H);
    clear_captured_log();
    assert_eq!(n.st.round(), Round::new(0), "live at round 0");
    n.h.clear();
    let scheduled = n.proposer(H, 0);
    let other = n.other_member(scheduled);
    n.feed(Input::Proposal(zero_proposal(H, Round::Nil, scheduled, b"nil-from-proposer")));
    n.feed(Input::Proposal(zero_proposal(H, Round::Nil, other, b"nil-from-member")));
    assert!(n.h.log.is_empty(), "no effect at all: {:?}", n.h.kinds());
    assert_eq!(n.verifies(), 0);
    assert_eq!(n.queued(), 0, "nothing buffered");
    assert_eq!(n.dropped(), 0, "never reached the buffer");
    assert!(
        n.st.full_proposal_at_round_and_proposer(&HkHeight::new(H), Round::Nil, &scheduled).is_none(),
        "nothing stored"
    );
    assert!(n.st.full_proposal_at_round_and_proposer(&HkHeight::new(H), Round::Nil, &other).is_none());
    assert!(n.st.full_proposal_at_round_and_proposer(&HkHeight::new(H), Round::new(0), &scheduled).is_none());
    assert_eq!(captured_log().matches("Received proposal with round Nil, dropping").count(), 2);
}

/// A CURRENT-height vote with `Round::Nil` from a member is dropped at the door: no panic, no
/// VerifySignature (even with a signature that would verify), not counted, nothing buffered.
#[test]
fn current_height_vote_with_round_nil_is_dropped_without_panic() {
    let mut n = Node::at(H);
    n.start_height(H);
    clear_captured_log();
    n.h.clear();
    let a = n.addrs[1];
    let honest_nil = nil_round_vote(H, VoteType::Prevote, a, HONEST);
    let zero_nil = nil_round_vote(H, VoteType::Precommit, a, ZERO);
    n.feed(Input::Vote(honest_nil.clone()));
    n.feed(Input::Vote(zero_nil.clone()));
    assert!(n.h.log.is_empty(), "no effect at all: {:?}", n.h.kinds());
    assert!(!n.st.driver.votes().has_vote(&honest_nil), "not counted");
    assert!(!n.st.driver.votes().has_vote(&zero_nil), "not counted");
    assert_eq!(n.queued(), 0, "nothing buffered");
    assert_eq!(n.st.claim_verify_failures_total, 0);
    assert_eq!(captured_log().matches("Received vote with round Nil, dropping").count(), 2);
}

/// A FUTURE-height vote with `Round::Nil` from a member (height 96) never reaches the claim path:
/// no VerifySignature (even honestly signed by two members), no claim, nothing buffered, nothing
/// charged — the guard runs before the height branch.
#[test]
fn future_height_vote_with_round_nil_never_reaches_the_claim_path() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let (a, b) = (n.addrs[1], n.addrs[2]);
    n.feed(Input::Vote(nil_round_vote(CLAIM, VoteType::Prevote, a, HONEST)));
    n.feed(Input::Vote(nil_round_vote(CLAIM, VoteType::Prevote, b, HONEST)));
    n.feed(Input::Vote(nil_round_vote(CLAIM, VoteType::Precommit, a, ZERO)));
    n.feed(Input::Vote(nil_round_vote(H + 1, VoteType::Prevote, a, HONEST)));
    assert!(n.h.log.is_empty(), "no effect at all: {:?}", n.h.kinds());
    assert!(n.claims().is_empty(), "no claim");
    assert_eq!(n.tip(), None);
    assert!(!n.st.should_abstain());
    assert_eq!(n.queued(), 0, "nothing buffered, inside or outside the window");
    assert_eq!(n.dropped(), 0, "never reached the buffer");
    assert_eq!(n.st.claim_verify_failures_total, 0);
    assert!(n.failures().is_empty());
}

// ---------------------------------------------------------------------------------------------
// Pruning at StartHeight.
// ---------------------------------------------------------------------------------------------

/// Honest claims at 96 survive StartHeight(41) and StartHeight(77) — R8 lapses at 77 because
/// 96 < 77 + 20, the claims remain — and are gone after StartHeight(96). The votes themselves were
/// never buffered (96 is outside the window), so nothing replays at 96.
#[test]
fn claims_survive_height_changes_until_our_height_reaches_them() {
    let mut n = Node::at(H);
    n.start_height(H);
    let (a, b) = (n.addrs[1], n.addrs[2]);
    n.feed(Input::Vote(honest_vote(CLAIM, a)));
    n.feed(Input::Vote(honest_vote(CLAIM, b)));
    assert_eq!(n.queued(), 0, "claims are evidence, not buffered inputs");

    n.start_height(H + 1);
    assert_eq!(n.claims(), vec![(a, CLAIM), (b, CLAIM)]);
    assert_eq!(n.tip(), Some(CLAIM));
    assert!(n.st.should_abstain(), "96 >= 41 + 20");

    n.start_height(CLAIM - GAP + 1);
    assert_eq!(n.claims(), vec![(a, CLAIM), (b, CLAIM)], "claims above 77 remain");
    assert_eq!(n.tip(), Some(CLAIM));
    assert!(!n.st.should_abstain(), "96 < 77 + 20: R8 lapses by our own progress");

    n.h.clear();
    n.start_height(CLAIM);
    assert!(n.claims().is_empty(), "a claim at or below our height is stale and pruned");
    assert_eq!(n.tip(), None);
    assert!(!n.st.should_abstain());
    assert_eq!(n.queued(), 0);
    assert_eq!(n.verifies(), 0, "nothing was buffered for 96, so nothing replays");
    assert!(!n.st.driver.votes().has_vote(&honest_vote(CLAIM, a)));
}

/// A claimant absent from the validator set passed to StartHeight is pruned; the remaining claim
/// is weighed against the NEW set (1 of 3 is not above one third).
#[test]
fn claimant_absent_from_the_new_set_is_pruned() {
    let mut n = Node::at(H);
    n.start_height(H);
    let (a, b) = (n.addrs[1], n.addrs[2]);
    n.feed(Input::Vote(honest_vote(CLAIM, a)));
    n.feed(Input::Vote(honest_vote(CLAIM, b)));
    assert!(n.st.should_abstain());

    let without_a = HkValidatorSet::new(n.set.iter().filter(|v| v.address != a).cloned());
    assert_eq!(without_a.len(), 3);
    n.start_height_with(H + 1, without_a);
    assert_eq!(n.claims(), vec![(b, CLAIM)], "the departed seat's claim is gone");
    assert_eq!(n.tip(), None, "1 of 3 is not more than one third");
    assert!(!n.st.should_abstain());
}

// ---------------------------------------------------------------------------------------------
// Observability: the R8 line names its evidence.
// ---------------------------------------------------------------------------------------------

/// The once-per-height R8 line names the claimants (address@height×power), the accumulated weight,
/// the total, the corroborated tip and the failed-verification total.
#[test]
fn abstain_log_line_names_the_evidence() {
    let mut n = Node::at(H);
    n.start_height(H);
    clear_captured_log();
    let (a, b) = (n.addrs[1], n.addrs[2]);
    n.feed(Input::Vote(honest_vote(CLAIM, a)));
    n.feed(Input::Vote(honest_vote(CLAIM, b)));
    n.feed(Input::Vote(zero_vote(CLAIM, n.addrs[3])));
    n.propose_timeout();
    assert_eq!(n.st.last_abstain_logged, Some(HkHeight::new(H)));

    let log = captured_log();
    let line = log
        .lines()
        .find(|l| l.contains(R8_LINE))
        .unwrap_or_else(|| panic!("no R8 line in:\n{log}"));
    println!("R8 line: {line}");
    assert!(line.contains(&format!("{a}@{CLAIM}×1")), "names claimant {a}");
    assert!(line.contains(&format!("{b}@{CLAIM}×1")), "names claimant {b}");
    assert!(line.contains("weight=2"), "the accumulated power");
    assert!(line.contains("total=4"), "the set's total power");
    assert!(line.contains(&format!("peer_tip=Some({CLAIM})")));
    assert!(line.contains("failed_claim_verifications_total=1"), "the forgery signal");
    assert_eq!(log.matches(R8_LINE).count(), 1, "once per height");

    // The same height again: no second line (once per height, not once per futile round).
    n.propose_timeout();
    assert_eq!(captured_log().matches(R8_LINE).count(), 1);
}

// ---------------------------------------------------------------------------------------------
// v0.19.12: the value of a signature-verified proposal is handed to the host.
// ---------------------------------------------------------------------------------------------
//
// In `proposal-and-parts` mode a proposal's value is taken from the signed proposal, which
// carries the bytes under a signature the engine checks: `on_proposal` emits
// `Effect::VerifiedProposal` for a current-height proposal that verified and has no value yet;
// the engine hands the proposal's own value to the host, and the host's answer arrives as a
// proposed value. These tests pin when the effect is emitted and when it is not. The host's
// side (the id is recomputed from the bytes) is in hk-node (`state.rs` `admit_signed_value`
// and its tests, `app.rs`).

/// The whole path: an honest proposal for the round in progress
/// verifies, is handed to the host exactly once, and no vote is cast before the value is held;
/// the host's answer (the value built from the proposal's own bytes) completes the proposal and
/// the node prevotes the value. Kill: remove the `perform!` in `on_proposal` and the first
/// count is 0.
#[test]
fn verified_proposal_without_a_value_is_handed_to_the_host_and_then_voted() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let p = n.proposer(H, 0);
    assert_ne!(p, n.addrs[0], "round 0 at height 40 belongs to another seat");
    let signed = honest_proposal(H, Round::new(0), p, b"batch");
    let id = signed.message.value.id();

    n.feed(Input::Proposal(signed));
    assert_eq!(n.verifies(), 1);
    assert_eq!(n.h.count("VerifiedProposal"), 1, "{:?}", n.h.kinds());
    let d = n.h.first("VerifiedProposal").unwrap().detail.clone();
    assert!(d.contains(&format!("h={H} r=0 ")), "{d}");
    assert!(d.contains(&format!("addr={p}")), "{d}");
    assert!(d.contains(&format!("value={id}")), "{d}");
    assert!(d.contains("sig=honest"), "{d}");
    assert_eq!(n.h.count("SignVote"), 0, "no vote before the value is held");
    assert!(
        n.st.full_proposal_at_round_and_proposer(&HkHeight::new(H), Round::new(0), &p).is_none(),
        "the proposal is stored without a value"
    );

    n.feed(proposed_value(H, Round::new(0), p, b"batch"));
    assert!(
        n.st.full_proposal_at_round_and_proposer(&HkHeight::new(H), Round::new(0), &p).is_some(),
        "the host's answer completes the proposal"
    );
    let votes = n.h.details("SignVote");
    assert_eq!(votes.len(), 1, "{votes:?}");
    assert!(votes[0].contains("Prevote") && votes[0].contains("Val("), "a prevote for the value: {}", votes[0]);
    assert_eq!(n.h.count("VerifiedProposal"), 1, "the answer does not ask the host again");
}

/// A proposal no key signed is verified once, refused, and never handed to the host (nor
/// written to the WAL); a proposal from a member the schedule does not name is refused before
/// any verification, whatever its signature.
#[test]
fn forged_or_unscheduled_proposal_is_never_handed_to_the_host() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let p = n.proposer(H, 0);
    let other = n.other_member(p);

    n.feed(Input::Proposal(zero_proposal(H, Round::new(0), p, b"forged")));
    assert_eq!(n.verifies(), 1);
    assert_eq!(n.h.count("VerifiedProposal"), 0, "{:?}", n.h.kinds());
    assert_eq!(n.h.count("WalAppend"), 0);

    n.feed(Input::Proposal(honest_proposal(H, Round::new(0), other, b"not scheduled")));
    assert_eq!(n.verifies(), 1, "the proposer check runs before the signature check");
    assert_eq!(n.h.count("VerifiedProposal"), 0, "{:?}", n.h.kinds());
    assert_eq!(n.h.count("SignVote"), 0);
}

/// When the value is already held (the host returned it at round start, or the node built it
/// itself), the proposal completes at once and the host is not asked.
#[test]
fn proposal_whose_value_is_already_held_is_not_handed_to_the_host() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let p = n.proposer(H, 0);

    n.feed(proposed_value(H, Round::new(0), p, b"batch"));
    assert_eq!(n.h.count("SignVote"), 0, "a value without its proposal is not voted");

    n.feed(Input::Proposal(honest_proposal(H, Round::new(0), p, b"batch")));
    assert_eq!(n.h.count("VerifiedProposal"), 0, "{:?}", n.h.kinds());
    assert_eq!(n.h.count("SignVote"), 1, "the proposal completed with the held value");
}

/// A proposer who signs two values for one round: both are handed to the host (it keeps both,
/// up to its bound), so the node can follow whichever value the network locks on. The same
/// proposal again, while it still has no value, is handed again: the host answers from its store.
#[test]
fn both_values_of_an_equivocating_proposer_are_handed_to_the_host() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let p = n.proposer(H, 0);

    n.feed(Input::Proposal(honest_proposal(H, Round::new(0), p, b"one")));
    n.feed(Input::Proposal(honest_proposal(H, Round::new(0), p, b"two")));
    let d = n.h.details("VerifiedProposal");
    assert_eq!(d.len(), 2, "{d:?}");
    assert_ne!(d[0], d[1], "two different values");

    n.feed(Input::Proposal(honest_proposal(H, Round::new(0), p, b"one")));
    assert_eq!(n.h.count("VerifiedProposal"), 3, "a republished proposal without a value asks again");
    assert_eq!(n.h.count("SignVote"), 0);
}

/// A proposal that arrives ahead of its height is buffered (after one verification, as since
/// v0.19.10) and handed to the host only when that height is the current one.
#[test]
fn buffered_proposal_is_handed_to_the_host_when_its_height_starts() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    // Round 0 at height 41 is this node's own; round 1 belongs to another seat.
    let p = n.proposer(H + 1, 1);
    assert_ne!(p, n.addrs[0]);

    n.feed(Input::Proposal(honest_proposal(H + 1, Round::new(1), p, b"early")));
    assert_eq!(n.queued(), 1, "buffered for its height");
    assert_eq!(n.verifies(), 1);
    assert_eq!(n.h.count("VerifiedProposal"), 0, "not while its height is ahead of ours");

    n.start_height(H + 1);
    let d = n.h.details("VerifiedProposal");
    assert_eq!(d.len(), 1, "{:?}", n.h.kinds());
    assert!(d[0].contains(&format!("h={} r=1 ", H + 1)), "{}", d[0]);
    assert!(d[0].contains(&format!("addr={p}")), "{}", d[0]);
}

/// The effect belongs to `proposal-and-parts` mode only. In `proposal-only` mode the engine
/// keeps the proposal's value itself; in `parts-only` mode proposals are synthesized from the
/// parts.
#[test]
fn other_payload_modes_never_hand_a_proposal_to_the_host() {
    for payload in [ValuePayload::ProposalOnly, ValuePayload::PartsOnly] {
        let mut n = Node::at(H);
        n.st.params.value_payload = payload;
        n.start_height(H);
        n.h.clear();
        let p = n.proposer(H, 0);
        n.feed(Input::Proposal(honest_proposal(H, Round::new(0), p, b"batch")));
        assert_eq!(n.h.count("VerifiedProposal"), 0, "{payload:?}: {:?}", n.h.kinds());
    }
}

// ---------------------------------------------------------------------------------------------
// v0.19.12: the value id, re-proposals, a round already left, and the WAL order.
// ---------------------------------------------------------------------------------------------
//
// (1) A proposal whose value id is not the hash of the bytes it carries is refused where the
// signature is checked; the round's proposal is the copy whose bytes hash to its id.
// (2) Re-proposals: the host is asked only when the value of the earlier round is not held.
// (3) A proposal for a round the node has left is still handed over.
// (4) The value is written to the WAL at the moment it completes its proposal, once; a synced
// value stays out of the WAL. (5) Fed in that order (proposal, value, votes, timeout), which is
// the order a replay reads, the node rebuilds its lock.

/// A proposal with a proof-of-lock round: a re-proposal.
fn proposal_with_pol(
    height: u64,
    round: Round,
    pol_round: Round,
    addr: HkAddress,
    txs: &[u8],
) -> SignedProposal<HkContext> {
    SignedMessage::new(
        HkProposal::new(
            HkHeight::new(height),
            round,
            HkValue::new(Bytes::copy_from_slice(txs)),
            pol_round,
            addr,
        ),
        sig(HONEST),
    )
}

/// A proposal that carries the id of `id_of` over the bytes `txs`. Its signature marker is the
/// honest one, so only the id check can refuse it.
fn mismatched_proposal(
    height: u64,
    round: Round,
    addr: HkAddress,
    id_of: &[u8],
    txs: &[u8],
) -> SignedProposal<HkContext> {
    let mut value = HkValue::new(Bytes::copy_from_slice(txs));
    value.id = HkValue::new(Bytes::copy_from_slice(id_of)).id();
    SignedMessage::new(
        HkProposal::new(HkHeight::new(height), round, value, Round::Nil, addr),
        sig(HONEST),
    )
}

/// A proposed value with a proof-of-lock round and an origin.
fn proposed_value_at(
    height: u64,
    round: Round,
    valid_round: Round,
    proposer: HkAddress,
    txs: &[u8],
    origin: ValueOrigin,
) -> Input<HkContext> {
    Input::ProposedValue(
        ProposedValue {
            height: HkHeight::new(height),
            round,
            valid_round,
            proposer,
            value: HkValue::new(Bytes::copy_from_slice(txs)),
            validity: Validity::Valid,
        },
        origin,
    )
}

/// An honest prevote for the value with these bytes.
fn prevote_for(height: u64, round: u32, txs: &[u8], addr: HkAddress) -> SignedVote<HkContext> {
    let id = HkValue::new(Bytes::copy_from_slice(txs)).id();
    SignedMessage::new(
        HkVote::new_prevote(HkHeight::new(height), Round::new(round), NilOrVal::Val(id), addr),
        sig(HONEST),
    )
}

/// How many VALUE entries the node has written to the WAL.
fn wal_values(n: &Node) -> usize {
    n.h.details("WalAppend").iter().filter(|d| d.ends_with(" value")).count()
}

/// A copy whose id is not the hash of its bytes arrives first and is refused at verification:
/// nothing is written to the WAL, nothing is stored, the host is not asked. The matching copy
/// that follows is then the proposal of its round: it is handed to the host, and the proposal
/// the driver ends up with carries bytes that hash to its id. Kill: drop the id check from the
/// verification and the first copy is not refused.
#[test]
fn proposal_value_id_must_match_its_bytes_and_the_matching_copy_is_kept() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let p = n.proposer(H, 0);

    n.feed(Input::Proposal(mismatched_proposal(H, Round::new(0), p, b"batch", b"other bytes")));
    assert_eq!(n.verifies(), 1);
    let d = n.h.details("VerifySignature");
    assert!(d[0].ends_with("sig=honest id-mismatch"), "{d:?}");
    assert_eq!(n.h.count("WalAppend"), 0, "not written to the WAL");
    assert_eq!(n.h.count("VerifiedProposal"), 0, "not handed to the host");

    n.feed(Input::Proposal(honest_proposal(H, Round::new(0), p, b"batch")));
    assert_eq!(n.h.count("VerifiedProposal"), 1, "the matching copy is stored and handed over");
    n.feed(proposed_value(H, Round::new(0), p, b"batch"));
    assert_eq!(n.h.count("SignVote"), 1, "and voted");
    let full = n
        .st
        .full_proposal_at_round_and_proposer(&HkHeight::new(H), Round::new(0), &p)
        .expect("a full proposal");
    let v = &full.proposal.message.value;
    assert_eq!(v.txs.as_ref(), b"batch");
    assert_eq!(HkValue::new(v.txs.clone()).id(), v.id(), "the driver's proposal carries bytes that hash to its id");
}

/// The same across a height start: a copy for a later height whose id is not the hash of its
/// bytes is verified once, refused and not buffered; the matching copy is the one buffered.
#[test]
fn proposal_value_id_must_match_its_bytes_before_it_is_buffered() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let p = n.proposer(H + 1, 1);

    n.feed(Input::Proposal(mismatched_proposal(H + 1, Round::new(1), p, b"early", b"other bytes")));
    assert_eq!(n.verifies(), 1);
    assert_eq!(n.queued(), 0, "refused at verification: not buffered");
    assert_eq!(n.dropped(), 1);

    n.feed(Input::Proposal(honest_proposal(H + 1, Round::new(1), p, b"early")));
    assert_eq!(n.verifies(), 2);
    assert_eq!(n.queued(), 1, "the matching copy takes the place");
    assert_eq!(n.dropped(), 1);
}

/// A re-proposal (round 1, proof-of-lock round 0) whose value this node never held: the host is
/// asked once, and its answer completes the proposal of round 1.
#[test]
fn re_proposal_without_the_earlier_value_is_handed_to_the_host_and_completes() {
    const HH: u64 = 42; // rounds 0 and 1 of 42 both belong to other seats
    let mut n = Node::at(HH);
    n.start_height(HH);
    n.feed(Input::TimeoutElapsed(Timeout::precommit(Round::new(0))));
    assert_eq!(n.st.round(), Round::new(1), "the node is in round 1");
    n.h.clear();
    let p1 = n.proposer(HH, 1);
    assert_ne!(p1, n.addrs[0]);

    n.feed(Input::Proposal(proposal_with_pol(HH, Round::new(1), Round::new(0), p1, b"locked")));
    let d = n.h.details("VerifiedProposal");
    assert_eq!(d.len(), 1, "{:?}", n.h.kinds());
    assert!(d[0].contains(&format!("h={HH} r=1 pol=0 ")), "{}", d[0]);

    n.feed(proposed_value_at(HH, Round::new(1), Round::new(0), p1, b"locked", ValueOrigin::Consensus));
    assert!(
        n.st.full_proposal_at_round_and_proposer(&HkHeight::new(HH), Round::new(1), &p1).is_some(),
        "the answer completes the re-proposal"
    );
}

/// A re-proposal of a value this node holds from the earlier round completes inside the engine:
/// the host is not asked. (So the host holds that value under the earlier round only, which is
/// why the node's restream looks a value up under every round of the height.)
#[test]
fn re_proposal_of_a_value_held_from_the_earlier_round_is_not_handed_to_the_host() {
    const HH: u64 = 42;
    let mut n = Node::at(HH);
    n.start_height(HH);
    let p0 = n.proposer(HH, 0);
    let p1 = n.proposer(HH, 1);
    n.feed(Input::Proposal(honest_proposal(HH, Round::new(0), p0, b"locked")));
    n.feed(proposed_value(HH, Round::new(0), p0, b"locked"));
    n.feed(Input::TimeoutElapsed(Timeout::precommit(Round::new(0))));
    assert_eq!(n.st.round(), Round::new(1));
    n.h.clear();

    n.feed(Input::Proposal(proposal_with_pol(HH, Round::new(1), Round::new(0), p1, b"locked")));
    assert_eq!(n.h.count("VerifiedProposal"), 0, "{:?}", n.h.kinds());
    assert!(
        n.st.full_proposal_at_round_and_proposer(&HkHeight::new(HH), Round::new(1), &p1).is_some(),
        "completed from the value of round 0"
    );
}

/// A proposal for a round the node has already left is still handed to the host: a decision can
/// still come for that round (a commit quorum for it), and the commit needs the value. Kill:
/// restrict the effect to the round in progress or later and this count is 0.
#[test]
fn proposal_for_a_round_already_left_is_still_handed_to_the_host() {
    const HH: u64 = 42;
    let mut n = Node::at(HH);
    n.start_height(HH);
    n.feed(Input::TimeoutElapsed(Timeout::precommit(Round::new(0))));
    assert_eq!(n.st.round(), Round::new(1));
    n.h.clear();
    let p0 = n.proposer(HH, 0);

    n.feed(Input::Proposal(honest_proposal(HH, Round::new(0), p0, b"late")));
    assert_eq!(n.h.count("VerifiedProposal"), 1, "{:?}", n.h.kinds());
}

/// The value is written to the WAL at the moment it completes its proposal, right after the
/// proposal's own entry, and only once: a second copy of the answer is neither written nor
/// voted again. Kill: write no WAL entry for a value from consensus and the WAL never holds
/// the value.
#[test]
fn the_value_is_written_to_the_wal_when_it_completes_its_proposal_and_only_once() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let p = n.proposer(H, 0);

    n.feed(Input::Proposal(honest_proposal(H, Round::new(0), p, b"batch")));
    assert_eq!(n.h.details("WalAppend"), vec![format!("h={H} proposal")]);

    n.feed(proposed_value(H, Round::new(0), p, b"batch"));
    let wal = n.h.details("WalAppend");
    assert!(wal.len() >= 2, "{wal:?}");
    assert_eq!(wal[1], format!("h={H} value"), "the value follows its proposal: {wal:?}");
    assert_eq!(wal_values(&n), 1);
    assert_eq!(n.h.count("SignVote"), 1);

    n.feed(proposed_value(H, Round::new(0), p, b"batch"));
    assert_eq!(wal_values(&n), 1, "a second copy of the answer is not written again");
    assert_eq!(n.h.count("SignVote"), 1, "and casts no second vote");
}

/// A value that arrives by sync stays out of the WAL, as before: the change of the WAL rule is
/// confined to values from consensus.
#[test]
fn a_synced_value_stays_out_of_the_wal() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let p = n.proposer(H, 0);

    n.feed(proposed_value_at(H, Round::new(0), Round::Nil, p, b"synced", ValueOrigin::Sync));
    assert_eq!(wal_values(&n), 0, "{:?}", n.h.details("WalAppend"));
}

/// The order a replay reads (proposal, its value, the votes, the timeout) rebuilds the lock:
/// the node prevotes and precommits V in round 0, moves to round 1 on the precommit timeout, and
/// prevotes NIL on a different value W there.
#[test]
fn proposal_then_value_in_wal_order_rebuilds_the_lock() {
    const HH: u64 = 42;
    let mut n = Node::at(HH);
    n.start_height(HH);
    n.h.clear();
    let p0 = n.proposer(HH, 0);
    let p1 = n.proposer(HH, 1);
    let others: Vec<HkAddress> = n.addrs[1..].to_vec();

    n.feed(Input::Proposal(honest_proposal(HH, Round::new(0), p0, b"V")));
    n.feed(proposed_value(HH, Round::new(0), p0, b"V"));
    for a in others {
        n.feed(Input::Vote(prevote_for(HH, 0, b"V", a)));
    }
    let votes = n.h.details("SignVote");
    assert_eq!(votes.len(), 2, "{votes:?}");
    assert!(votes[0].contains("Prevote") && votes[0].contains("Val("), "{}", votes[0]);
    assert!(votes[1].contains("Precommit") && votes[1].contains("Val("), "locked on V: {}", votes[1]);

    n.feed(Input::TimeoutElapsed(Timeout::precommit(Round::new(0))));
    assert_eq!(n.st.round(), Round::new(1));
    n.feed(Input::Proposal(honest_proposal(HH, Round::new(1), p1, b"W")));
    n.feed(proposed_value(HH, Round::new(1), p1, b"W"));
    let votes = n.h.details("SignVote");
    assert_eq!(votes.len(), 3, "{votes:?}");
    assert!(
        votes[2].contains("Prevote") && votes[2].contains("r=1") && votes[2].contains("Nil"),
        "a node locked on V prevotes nil on W: {}",
        votes[2]
    );
}

// ---------------------------------------------------------------------------------------------
// The vote keeper: one vote per validator per round and type, the first copy whose signature
// verified. The recorder's signer returns a new signature on every call, and its certificate
// checks answer as the engine's verifier does.
// ---------------------------------------------------------------------------------------------

/// An honest precommit for the value with these bytes.
fn precommit_for(height: u64, round: u32, txs: &[u8], addr: HkAddress) -> SignedVote<HkContext> {
    let id = HkValue::new(Bytes::copy_from_slice(txs)).id();
    SignedMessage::new(
        HkVote::new_precommit(HkHeight::new(height), Round::new(round), NilOrVal::Val(id), addr),
        sig(HONEST),
    )
}

/// The same vote under another valid signature (another one-time leaf); `k` picks which one. It
/// differs from `sig(HONEST)` and from every signature the recorder's signer returns in a test.
fn resigned(v: &SignedVote<HkContext>, k: u64) -> SignedVote<HkContext> {
    SignedMessage::new(v.message.clone(), signed_sig(u64::MAX - k))
}

/// The same vote with a signature that does not verify.
fn failing_copy(v: &SignedVote<HkContext>) -> SignedVote<HkContext> {
    SignedMessage::new(v.message.clone(), sig(ZERO))
}

/// The votes of type `typ` from `addr` that the vote keeper holds for `round`, in stored order.
fn held(n: &Node, round: u32, typ: VoteType, addr: HkAddress) -> Vec<SignedVote<HkContext>> {
    n.st.driver
        .votes()
        .per_round(Round::new(round))
        .map(|r| {
            r.received_votes()
                .iter()
                .filter(|v| v.message.typ == typ && v.message.validator_address == addr)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// A round certificate of `cert_type` for (height, round), built from these votes in this order.
fn round_cert(
    height: u64,
    round: u32,
    cert_type: RoundCertificateType,
    votes: &[SignedVote<HkContext>],
) -> Input<HkContext> {
    Input::RoundCertificate(RoundCertificate::new_from_votes(
        HkHeight::new(height),
        Round::new(round),
        cert_type,
        votes.to_vec(),
    ))
}

/// The addresses a commit certificate names, in order.
fn named(c: &CommitCertificate<HkContext>) -> Vec<HkAddress> {
    c.commit_signatures.iter().map(|s| s.address).collect()
}

/// True when no address appears twice.
fn each_once(addrs: &[HkAddress]) -> bool {
    let mut sorted = addrs.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted.len() == addrs.len()
}

/// How many VOTE entries the node has written to the WAL.
fn wal_votes(n: &Node) -> usize {
    n.h.details("WalAppend").iter().filter(|d| d.ends_with(" vote")).count()
}

/// B1 — a WAL replay inside a height: the WAL for (40, 0), which holds our prevote and precommit
/// for V, is read back in the order it was written, our votes where they were cast (so our
/// precommit, cast at the polka, comes before the others' precommits), and the driver derives
/// and signs both votes again. Two WAL orders: the value before its proposal and the proposal
/// before its value. Each own vote is held once, the copy that reached the keeper first; there
/// is exactly one Decide; the commit and polka certificates name each validator once.
#[test]
fn wal_replay_inside_a_height_decides_once() {
    for value_first in [true, false] {
        let order = if value_first { "value first" } else { "proposal first" };
        let mut n = Node::at(H);
        n.start_height(H);
        n.h.clear();
        let me = n.addrs[0];
        let p = n.proposer(H, 0);
        assert_ne!(p, me, "round 0 at height 40 belongs to another seat");
        let others: Vec<HkAddress> = n.addrs[1..].to_vec();
        // Our two votes as the WAL holds them.
        let own_prevote = prevote_for(H, 0, b"V", me);
        let own_precommit = precommit_for(H, 0, b"V", me);

        let mut wal: Vec<Input<HkContext>> = Vec::new();
        if value_first {
            wal.push(proposed_value(H, Round::new(0), p, b"V"));
            wal.push(Input::Vote(own_prevote.clone()));
            wal.push(Input::Proposal(honest_proposal(H, Round::new(0), p, b"V")));
        } else {
            wal.push(Input::Proposal(honest_proposal(H, Round::new(0), p, b"V")));
            wal.push(proposed_value(H, Round::new(0), p, b"V"));
            wal.push(Input::Vote(own_prevote.clone()));
        }
        wal.extend(others.iter().map(|x| Input::Vote(prevote_for(H, 0, b"V", *x))));
        wal.push(Input::Vote(own_precommit.clone()));
        wal.extend(others.iter().map(|x| Input::Vote(precommit_for(H, 0, b"V", *x))));

        let errors: Vec<String> = wal
            .into_iter()
            .filter_map(|input| n.try_feed(input).err())
            .map(|e| e.to_string())
            .collect();
        assert!(errors.is_empty(), "{order}: {errors:?}");

        let signed = n.h.details("SignVote");
        assert_eq!(signed.len(), 2, "{order}: our prevote and our precommit signed again: {signed:?}");
        assert!(signed[0].starts_with("Prevote") && signed[1].starts_with("Precommit"), "{order}: {signed:?}");

        let prevotes = held(&n, 0, VoteType::Prevote, me);
        let precommits = held(&n, 0, VoteType::Precommit, me);
        assert_eq!(prevotes.len(), 1, "{order}: our prevote is held once");
        assert_eq!(precommits.len(), 1, "{order}: our precommit is held once");
        // The copy kept is the one that reached the keeper first.
        assert_eq!(
            prevotes[0].signature == own_prevote.signature,
            value_first,
            "{order}: the WAL's prevote is first only when it comes before the proposal"
        );
        assert!(
            precommits[0].signature != own_precommit.signature,
            "{order}: our precommit signed again at the polka comes before the WAL's copy and stays"
        );

        assert_eq!(n.h.count("Decide"), 1, "{order}: {:?}", n.h.kinds());
        let c = &n.h.decided[0];
        let names = named(c);
        assert!(each_once(&names), "{order}: the commit certificate names each validator once: {names:?}");
        let mine = c.commit_signatures.iter().find(|s| s.address == me).expect("our precommit in the certificate");
        assert!(mine.signature == precommits[0].signature, "{order}: with the copy held");

        let polka = n.st.polka_certificate_at_round(Round::new(0)).expect("the polka certificate of round 0");
        let polka_names: Vec<HkAddress> = polka.polka_signatures.iter().map(|s| s.address).collect();
        assert!(each_once(&polka_names), "{order}: the polka certificate names each validator once: {polka_names:?}");
    }
}

/// B2 — two valid signatures of one precommit (other bytes) arrive before the quorum is
/// complete. Both are verified first; the second is neither written to the WAL nor stored nor
/// counted; the next precommit completes the quorum, there is exactly one Decide, and its
/// certificate names each validator once with the first copy.
#[test]
fn a_precommit_signed_twice_is_held_once() {
    let mut n = Node::at(H);
    n.start_height(H);
    let p = n.proposer(H, 0);
    let (a, b, c) = (n.addrs[1], n.addrs[2], n.addrs[3]);
    n.feed(Input::Proposal(honest_proposal(H, Round::new(0), p, b"V")));
    n.feed(proposed_value(H, Round::new(0), p, b"V"));
    for x in [a, b, c] {
        n.feed(Input::Vote(prevote_for(H, 0, b"V", x)));
    }
    assert_eq!(held(&n, 0, VoteType::Precommit, n.addrs[0]).len(), 1, "the polka: our precommit for V");
    n.h.clear();

    let first = precommit_for(H, 0, b"V", a);
    let again = resigned(&first, 1);
    assert!(first.signature != again.signature);
    n.feed(Input::Vote(first.clone()));
    n.feed(Input::Vote(again));
    assert_eq!(n.verifies(), 2, "both copies are verified before anything else is asked of them");
    assert_eq!(wal_votes(&n), 1, "the second copy is not written to the WAL");
    let kept = held(&n, 0, VoteType::Precommit, a);
    assert_eq!(kept.len(), 1, "one copy held");
    assert!(kept[0].signature == first.signature, "the first");
    assert!(n.st.driver.votes().evidence().is_empty(), "the same value twice is not equivocation");
    assert_eq!(n.h.count("Decide"), 0, "two of four precommits: no quorum yet");

    n.try_feed(Input::Vote(precommit_for(H, 0, b"V", b)))
        .unwrap_or_else(|e| panic!("the vote is processed without error: {e}"));
    assert_eq!(n.h.count("Decide"), 1, "{:?}", n.h.kinds());
    let cert = &n.h.decided[0];
    let names = named(cert);
    assert!(each_once(&names), "{names:?}");
    assert_eq!(names.len(), 3);
    let from_a = cert.commit_signatures.iter().find(|s| s.address == a).expect("a's precommit");
    assert!(from_a.signature == first.signature, "the certificate carries the copy held");
}

/// B3 — each vote of a round certificate is verified on its own before it is counted. Seven
/// equal seats (quorum 5), a precommit round certificate after the polka: a vote in it that
/// does not verify is not stored or counted; the validator's valid precommit that follows is
/// stored and counted, and the one Decide names each validator once, valid signatures only.
#[test]
fn each_vote_of_a_precommit_certificate_is_verified_before_it_is_counted() {
    let set = HkValidatorSet::new((0..7u8).map(|i| validator(i, 1)));
    let me = set.iter().next().unwrap().address;
    let mut n = Node::build(set, me, H, true);
    n.start_height(H);
    let p = n.proposer(H, 0);
    assert_ne!(p, me);
    let a: Vec<HkAddress> = n.addrs.clone(); // a[0] is this node
    n.feed(Input::Proposal(honest_proposal(H, Round::new(0), p, b"V")));
    n.feed(proposed_value(H, Round::new(0), p, b"V"));
    for x in &a[1..5] {
        n.feed(Input::Vote(prevote_for(H, 0, b"V", *x)));
    }
    assert_eq!(held(&n, 0, VoteType::Precommit, me).len(), 1, "the polka (5 of 7): our precommit for V");
    n.h.clear();

    let honest = precommit_for(H, 0, b"V", a[1]);
    let nil = |x: HkAddress| vote(H, 0, VoteType::Precommit, x, HONEST);
    let cert = round_cert(
        H,
        0,
        RoundCertificateType::Precommit,
        &[
            failing_copy(&honest),
            precommit_for(H, 0, b"V", a[2]),
            precommit_for(H, 0, b"V", a[3]),
            precommit_for(H, 0, b"V", a[4]),
            nil(a[5]),
            nil(a[6]),
        ],
    );
    n.try_feed(cert).unwrap_or_else(|e| panic!("the certificate is processed without error: {e}"));
    assert_eq!(n.h.details("VerifyRoundCertificate"), vec!["ok".to_string()]);
    assert_eq!(n.verifies(), 6, "each vote of the certificate is verified on its own");
    assert_eq!(n.h.details("VerifySignature")[0], format!("vote h={H} addr={} sig=zero", a[1]));
    assert!(held(&n, 0, VoteType::Precommit, a[1]).is_empty(), "the failing copy is not stored");
    let id = HkValue::new(Bytes::copy_from_slice(b"V")).id();
    assert!(
        !n.st.driver.votes().is_threshold_met(&Round::new(0), VoteType::Precommit, Threshold::Value(id)),
        "nor counted: V has 4 of 7"
    );
    assert_eq!(n.h.count("Decide"), 0);

    n.try_feed(Input::Vote(honest.clone()))
        .unwrap_or_else(|e| panic!("the vote is processed without error: {e}"));
    let kept = held(&n, 0, VoteType::Precommit, a[1]);
    assert_eq!(kept.len(), 1);
    assert!(kept[0].signature == honest.signature, "the honest precommit is stored");
    assert_eq!(n.h.count("Decide"), 1, "and counted: it completes V's quorum");
    let cert = &n.h.decided[0];
    let names = named(cert);
    assert!(each_once(&names), "{names:?}");
    assert_eq!(names.len(), 5);
    assert!(
        cert.commit_signatures.iter().all(|s| harness_verifies(&s.signature.0)),
        "valid signatures only"
    );
}

/// B4 — a skip round certificate for round 2 with a vote that does not verify: that vote does
/// not enter the keeper and is not counted, the node moves to round 2, and the validator's valid
/// vote that follows is stored and counted.
#[test]
fn each_vote_of_a_skip_certificate_is_verified_before_it_is_counted() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let (a, b, c) = (n.addrs[1], n.addrs[2], n.addrs[3]);
    let honest = vote(H, 2, VoteType::Prevote, a, HONEST);
    let nil_quorum = |n: &Node| {
        n.st.driver.votes().is_threshold_met(&Round::new(2), VoteType::Prevote, Threshold::Nil)
    };

    let cert = round_cert(
        H,
        2,
        RoundCertificateType::Skip,
        &[
            failing_copy(&honest),
            vote(H, 2, VoteType::Prevote, b, HONEST),
            vote(H, 2, VoteType::Prevote, c, HONEST),
        ],
    );
    n.try_feed(cert).unwrap_or_else(|e| panic!("the certificate is processed without error: {e}"));
    assert_eq!(n.h.details("VerifyRoundCertificate"), vec!["ok".to_string()]);
    assert_eq!(n.verifies(), 3, "each vote of the certificate is verified on its own");
    assert_eq!(n.st.round(), Round::new(2), "the node moves to round 2");
    assert!(held(&n, 2, VoteType::Prevote, a).is_empty(), "the failing copy is not stored");
    assert!(!nil_quorum(&n), "nor counted: two of four prevotes for nil");

    n.feed(Input::Vote(honest.clone()));
    let kept = held(&n, 2, VoteType::Prevote, a);
    assert_eq!(kept.len(), 1);
    assert!(kept[0].signature == honest.signature, "the honest vote is stored");
    assert!(nil_quorum(&n), "and counted: three of four");
}

/// A — the vote keeper's rule: the same precommit with three valid signatures, two received on
/// their own and the third inside a round certificate. One copy is stored, the first; no
/// evidence; the certificate's other votes complete the precommit quorum (any value), whose
/// output fires once, and the round certificate the node builds names each validator once. A
/// precommit for another value from the same validator is still evidence and is not counted.
#[test]
fn one_vote_signed_three_times_is_held_once_and_another_value_is_evidence() {
    let mut n = Node::at(H);
    n.start_height(H);
    n.h.clear();
    let (a, b, c) = (n.addrs[1], n.addrs[2], n.addrs[3]);
    let first = vote(H, 0, VoteType::Precommit, a, HONEST);
    let (second, third) = (resigned(&first, 1), resigned(&first, 2));
    let precommit_timeouts =
        |n: &Node| n.h.details("ScheduleTimeout").iter().filter(|d| d.as_str() == "PrecommitTimeout(0)").count();

    n.feed(Input::Vote(first.clone()));
    n.feed(Input::Vote(second));
    assert_eq!(n.verifies(), 2);
    assert_eq!(wal_votes(&n), 1, "the second copy is not written to the WAL");
    assert_eq!(held(&n, 0, VoteType::Precommit, a).len(), 1);

    let cert = round_cert(
        H,
        0,
        RoundCertificateType::Precommit,
        &[third, vote(H, 0, VoteType::Precommit, b, HONEST), vote(H, 0, VoteType::Precommit, c, HONEST)],
    );
    n.try_feed(cert).unwrap_or_else(|e| panic!("the certificate is processed without error: {e}"));
    let kept = held(&n, 0, VoteType::Precommit, a);
    assert_eq!(kept.len(), 1, "one copy held");
    assert!(kept[0].signature == first.signature, "the first");
    assert!(n.st.driver.votes().evidence().is_empty(), "the same vote again is not equivocation");
    assert_eq!(precommit_timeouts(&n), 1, "the precommit quorum (any value) fired once");
    let built = n.st.driver.round_certificate().expect("the round certificate the node built");
    let names: Vec<HkAddress> = built.certificate.round_signatures.iter().map(|s| s.address).collect();
    assert!(each_once(&names), "{names:?}");
    assert_eq!(names.len(), 3);

    // Another value from the same validator: equivocation, kept as evidence, not counted.
    let id = HkValue::new(Bytes::copy_from_slice(b"V")).id();
    let other = SignedMessage::new(
        HkVote::new_precommit(HkHeight::new(H), Round::new(0), NilOrVal::Val(id), a),
        sig(HONEST),
    );
    n.feed(Input::Vote(other.clone()));
    let evidence = n.st.driver.votes().evidence().get(&a).cloned().unwrap_or_default();
    assert_eq!(evidence.len(), 1, "a different value still gives evidence");
    assert_eq!(evidence[0].0.message, first.message);
    assert_eq!(evidence[0].1.message, other.message);
    let kept = held(&n, 0, VoteType::Precommit, a);
    assert_eq!(kept.len(), 1);
    assert!(kept[0].signature == first.signature, "and does not take the place of the first");
    assert_eq!(precommit_timeouts(&n), 1, "nor does it fire anything again");
}
