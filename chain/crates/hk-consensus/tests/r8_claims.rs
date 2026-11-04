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
//! Every input enters through the real core-consensus entry point, the `process!` macro, which runs
//! `handle()` as a coroutine and hands every yielded `Effect` to the recorder below — the same path
//! the engine feeds network votes and proposals into (engine/src/consensus.rs `process_input`). A
//! signature can only be checked through `Effect::VerifySignature`, so the effect log is the proof
//! of whether (and how often) a check was requested.
//!
//! The recorder answers `VerifySignature` by signature MARKER (no LMS runs here):
//!   - all-zero bytes (a frame no key ever signed)              → false, as the real verifier does
//!     (hk-crypto hashsig.rs: `!verify(msg, &vec![0u8; CONSENSUS_SIG_LEN], &pk)`);
//!   - 0xA5-filled (a vote this harness itself "signed": honest) → true;
//!   - 0x5A-filled (a key we do not hold, e.g. rotated after our height) → false;
//! and resumes `SignVote` / `SignProposal` with 0xA5 signatures. Every signature has the wire
//! length the codec admits (RZ-1: exactly `CONSENSUS_SIG_LEN` = 9,140 bytes).
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
    Resume, Role, SignedConsensusMsg, State, ThresholdParams, BUFFER_HEIGHT_WINDOW,
    BUFFER_MAX_PROPOSAL_ROUNDS_PER_HEIGHT, BUFFER_MAX_VOTE_ROUNDS_PER_ADDRESS,
    CLAIM_VERIFY_BUDGET,
};
use malachitebft_core_types::{
    Context as _, NilOrVal, Round, SignedMessage, SignedProposal, SignedVote, Timeout,
    Validity, ValueOrigin, ValuePayload, VoteType, VotingPower,
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

// The budget and buffer constants (`CLAIM_VERIFY_BUDGET`, `BUFFER_MAX_VOTE_ROUNDS_PER_ADDRESS`,
// `BUFFER_MAX_PROPOSAL_ROUNDS_PER_HEIGHT`, `BUFFER_HEIGHT_WINDOW`) are imported from
// core-consensus, which re-exports them for these tests; `preconditions_…` pins them to the
// design's frozen numbers (ROLL §1.3 / §1.4), so a change on either side comes back through this file.

/// Signature markers (the whole 9,140-byte signature is filled with one byte).
const ZERO: u8 = 0x00; // no key ever signed this
const HONEST: u8 = 0xA5; // this harness's own signer: verifies
const ROTATED: u8 = 0x5A; // a key we do not hold (rotated after our height): refused

/// The warn the vote handler logs once per address per budget window (vote.rs).
const FAILED_VERIFY_WARN: &str = "failed signature verification";
/// The once-per-height R8 line (driver.rs).
const R8_LINE: &str = "R8: behind the network";

fn sig(marker: u8) -> HkSig {
    HkSig(vec![marker; SIG_LEN])
}

fn sig_marker(s: &[u8]) -> &'static str {
    if s.len() != SIG_LEN {
        "bad-length"
    } else if s.iter().all(|b| *b == ZERO) {
        "zero"
    } else if s.iter().all(|b| *b == HONEST) {
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
    }
}

fn rec(log: &mut Vec<Rec>, kind: &'static str, detail: String) {
    log.push(Rec { kind, detail });
}

fn on_effect(log: &mut Vec<Rec>, effect: Effect<HkContext>) -> Result<Resume<HkContext>, String> {
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
        Effect::ValidSyncValue(_, _, r) => {
            rec(log, "ValidSyncValue", String::new());
            r.resume_with(())
        }
        Effect::InvalidSyncValue(_, _, _, r) => {
            rec(log, "InvalidSyncValue", String::new());
            r.resume_with(())
        }
        Effect::Decide(_, _, r) => {
            rec(log, "Decide", String::new());
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
            r.resume_with(SignedMessage::new(vote, sig(HONEST)))
        }
        Effect::SignProposal(p, r) => {
            rec(log, "SignProposal", format!("h={} r={}", p.height, p.round));
            r.resume_with(SignedMessage::new(p, sig(HONEST)))
        }
        Effect::VerifySignature(msg, _pk, r) => {
            let marker = sig_marker(&msg.signature.0);
            let what = match &msg.message {
                ConsensusMsg::Vote(v) => format!("vote h={} addr={}", v.height, v.validator_address),
                ConsensusMsg::Proposal(p) => {
                    format!("proposal h={} addr={}", p.height, p.validator_address)
                }
            };
            rec(log, "VerifySignature", format!("{what} sig={marker}"));
            r.resume_with(harness_verifies(&msg.signature.0))
        }
        Effect::VerifyCommitCertificate(_, _, _, r) => {
            rec(log, "VerifyCommitCertificate", String::new());
            r.resume_with(Ok(()))
        }
        Effect::VerifyPolkaCertificate(_, _, _, r) => {
            rec(log, "VerifyPolkaCertificate", String::new());
            r.resume_with(Ok(()))
        }
        Effect::VerifyRoundCertificate(_, _, _, r) => {
            rec(log, "VerifyRoundCertificate", String::new());
            r.resume_with(Ok(()))
        }
        Effect::WalAppend(h, _e, r) => {
            rec(log, "WalAppend", format!("h={h}"));
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
        let r: Result<(), Error<HkContext>> = malachitebft_core_consensus::process!(
            input: input,
            state: &mut self.st,
            metrics: &self.m,
            with: effect => on_effect(&mut self.h.log, effect)
        );
        r.expect("core-consensus returned an error");
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

    fn failures(&self) -> Vec<(HkAddress, u32)> {
        self.st.claim_verify_failures.clone()
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
/// resumes SignVote / SignProposal with 0xA5 signatures of the wire length.
#[test]
fn harness_answers_verify_by_signature_marker_and_signs_with_a5() {
    let a = equal_set().iter().next().unwrap().address;
    let pk = HkPub(vec![1u8; 60]);
    let mut log = Vec::new();

    let verdict = |marker: u8, log: &mut Vec<Rec>| {
        let v = HkVote::new_prevote(HkHeight::new(CLAIM), Round::new(0), NilOrVal::Nil, a);
        let msg = SignedMessage::new(ConsensusMsg::Vote(v), sig(marker));
        let eff: Effect<HkContext> = Effect::VerifySignature(msg, pk.clone(), Default::default());
        match on_effect(log, eff) {
            Ok(Resume::SignatureValidity(b)) => b,
            other => panic!("unexpected resume {other:?}"),
        }
    };
    assert!(!verdict(ZERO, &mut log), "an all-zero signature is refused");
    assert!(verdict(HONEST, &mut log), "the harness's own 0xA5 signature verifies");
    assert!(!verdict(ROTATED, &mut log), "a 0x5A signature (a key we do not hold) is refused");
    assert_eq!(log.iter().filter(|r| r.kind == "VerifySignature").count(), 3);
    assert!(log[0].detail.ends_with("sig=zero"));
    assert!(log[1].detail.ends_with("sig=honest"));
    assert!(log[2].detail.ends_with("sig=rotated"));

    let v = HkVote::new_prevote(HkHeight::new(H), Round::new(0), NilOrVal::Nil, a);
    let eff: Effect<HkContext> = Effect::SignVote(v, Default::default());
    match on_effect(&mut log, eff) {
        Ok(Resume::SignedVote(sv)) => {
            assert_eq!(sv.signature.0.len(), SIG_LEN);
            assert_eq!(sig_marker(&sv.signature.0), "honest");
        }
        other => panic!("unexpected resume {other:?}"),
    }
    let p = HkProposal::new(HkHeight::new(H), Round::new(0), HkValue::new(Bytes::new()), Round::Nil, a);
    let eff: Effect<HkContext> = Effect::SignProposal(p, Default::default());
    match on_effect(&mut log, eff) {
        Ok(Resume::SignedProposal(sp)) => assert_eq!(sig_marker(&sp.signature.0), "honest"),
        other => panic!("unexpected resume {other:?}"),
    }
}

/// R8 is on with the shipped default gap 20, the env override is unset, the signature length is
/// the one the wire codec admits, and the shipped constants are the design's frozen numbers.
#[test]
fn preconditions_gap_on_by_default_and_design_constants() {
    assert!(std::env::var_os("HK_ABSTAIN_GAP").is_none(), "HK_ABSTAIN_GAP must be unset for this run");
    assert_eq!(HkContext::new().abstain_threshold(), Some(GAP));
    assert_eq!(GAP, 20);
    assert_eq!(SIG_LEN, 9_140);
    assert_eq!(CLAIM_VERIFY_BUDGET, 3, "ROLL §1.3: K = 3 failed verifies per address per window");
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
// The verify budget (CPU bound).
// ---------------------------------------------------------------------------------------------

/// Budget + 3 zero-signature votes at increasing heights (all above the buffer window) from one
/// address cost exactly CLAIM_VERIFY_BUDGET verifications; another address has its own budget; the
/// warn is logged once per address per window.
#[test]
fn verify_budget_caps_failed_verifies_per_address() {
    let mut n = Node::at(H);
    n.start_height(H);
    clear_captured_log();
    n.h.clear();
    let (a, b) = (n.addrs[1], n.addrs[2]);
    let frames = CLAIM_VERIFY_BUDGET as u64 + 3;

    for i in 0..frames {
        n.feed(Input::Vote(zero_vote(CLAIM + i, a)));
    }
    assert_eq!(n.verifies(), CLAIM_VERIFY_BUDGET as usize, "then silence for that address");
    assert_eq!(n.failures(), vec![(a, CLAIM_VERIFY_BUDGET)]);
    assert_eq!(n.st.claim_verify_failures_total, CLAIM_VERIFY_BUDGET as u64);
    assert_eq!(n.queued(), 0, "96.. is outside the window: nothing buffered, no buffer verify");
    assert_eq!(n.dropped(), frames);
    assert!(n.claims().is_empty());

    for i in 0..frames {
        n.feed(Input::Vote(zero_vote(CLAIM + i, b)));
    }
    assert_eq!(n.verifies(), 2 * CLAIM_VERIFY_BUDGET as usize, "a second address, its own budget");
    assert_eq!(n.failures(), vec![(a, CLAIM_VERIFY_BUDGET), (b, CLAIM_VERIFY_BUDGET)]);
    assert_eq!(n.st.claim_verify_failures_total, 2 * CLAIM_VERIFY_BUDGET as u64);
    assert!(n.claims().is_empty());
    assert_eq!(n.tip(), None);
    assert!(!n.st.should_abstain());
    assert_eq!(n.dropped(), 2 * frames);

    let log = captured_log();
    assert_eq!(log.matches(FAILED_VERIFY_WARN).count(), 2, "one warn per address per window");
    assert!(log.contains(&format!("validator={a}")) && log.contains(&format!("validator={b}")));
}

/// The window refills only when OUR height has advanced by `gap` since the last refill:
/// StartHeight at 41 and at 59 do not refill; StartHeight at 60 does (a full budget again).
#[test]
fn verify_budget_refills_only_after_gap_heights_of_progress() {
    let mut n = Node::at(H);
    n.start_height(H);
    let a = n.addrs[1];
    assert_eq!(n.st.claim_budget_refilled_at, HkHeight::new(H));

    for i in 0..CLAIM_VERIFY_BUDGET as u64 {
        n.feed(Input::Vote(zero_vote(CLAIM + i, a)));
    }
    n.h.clear();
    n.feed(Input::Vote(zero_vote(CLAIM + 10, a)));
    assert_eq!(n.verifies(), 0, "the budget is spent");

    n.start_height(H + 1);
    assert_eq!(n.st.claim_budget_refilled_at, HkHeight::new(H), "41 < 40 + 20: no refill");
    n.h.clear();
    n.feed(Input::Vote(zero_vote(CLAIM + 20, a)));
    assert_eq!(n.verifies(), 0);

    n.start_height(H + GAP - 1);
    assert_eq!(n.st.claim_budget_refilled_at, HkHeight::new(H), "59 < 40 + 20: no refill");
    n.h.clear();
    n.feed(Input::Vote(zero_vote(CLAIM + 21, a)));
    assert_eq!(n.verifies(), 0);

    n.start_height(H + GAP);
    assert_eq!(n.st.claim_budget_refilled_at, HkHeight::new(H + GAP), "60 >= 40 + 20: refilled");
    assert!(n.failures().is_empty());
    n.h.clear();
    n.feed(Input::Vote(zero_vote(CLAIM + 30, a)));
    assert_eq!(n.verifies(), 1, "one more verify is allowed");
    for i in 1..=CLAIM_VERIFY_BUDGET as u64 {
        n.feed(Input::Vote(zero_vote(CLAIM + 30 + i, a)));
    }
    assert_eq!(n.verifies(), CLAIM_VERIFY_BUDGET as usize, "and the window is a full budget");
    assert_eq!(n.failures(), vec![(a, CLAIM_VERIFY_BUDGET)]);
    assert!(n.claims().is_empty());
    assert_eq!(n.queued(), 0, "every frame was above the buffer window");
}

/// Recorded honest claims persist through a flood of zero-signature frames for a third member
/// (budgeted) and through frames re-using the recorded claimants at or below their recorded
/// height (filtered without a verify); forged frames above the recorded height fail and change
/// nothing.
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

    // A flood for the third member: budget, then silence; the honest claims are untouched.
    for i in 0..30u64 {
        n.feed(Input::Vote(zero_vote(CLAIM + i, c)));
    }
    assert_eq!(n.verifies(), CLAIM_VERIFY_BUDGET as usize);
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

    // Above the recorded height: verified (budgeted), refused, the claim stays where it was.
    for i in 1..=5u64 {
        n.feed(Input::Vote(zero_vote(CLAIM + i, a)));
    }
    assert_eq!(n.verifies(), CLAIM_VERIFY_BUDGET as usize);
    assert_eq!(n.claims(), vec![(a, CLAIM), (b, CLAIM)], "a refused forgery never moves a claim");
    assert_eq!(n.tip(), Some(CLAIM));
    assert!(n.st.should_abstain());
    assert_eq!(n.st.claim_verify_failures_total, 2 * CLAIM_VERIFY_BUDGET as u64);
    assert_eq!(n.queued(), 0);
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
