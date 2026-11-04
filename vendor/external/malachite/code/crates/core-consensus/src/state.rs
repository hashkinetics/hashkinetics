use tracing::info;

use malachitebft_core_driver::Driver;
use malachitebft_core_types::*;

use crate::full_proposal::{FullProposal, FullProposalKeeper};
use crate::input::Input;
use crate::params::Params;
use crate::prelude::*;
use crate::types::ProposedValue;
use crate::util::bounded_queue::BoundedQueue;

/// The state maintained by consensus for processing a [`Input`].
pub struct State<Ctx>
where
    Ctx: Context,
{
    /// The context for the consensus state machine
    pub ctx: Ctx,

    /// The consensus parameters
    pub params: Params<Ctx>,

    /// Driver for the per-round consensus state machine
    pub driver: Driver<Ctx>,

    /// A queue of inputs that were received before the driver started.
    pub input_queue: BoundedQueue<Ctx::Height, Input<Ctx>>,

    /// A queue specifically for `SyncValueResponse`s inputs that were received at a higher height.
    pub sync_input_queue: BoundedQueue<Ctx::Height, Input<Ctx>>,

    /// The proposals to decide on.
    pub full_proposal_keeper: FullProposalKeeper<Ctx>,

    /// Last prevote broadcasted by this node
    pub last_signed_prevote: Option<SignedVote<Ctx>>,

    /// Last precommit broadcasted by this node
    pub last_signed_precommit: Option<SignedVote<Ctx>>,

    /// HK-R5.2: identity of the last commit certificate that PASSED full signature
    /// verification. During catch-up the sync path verifies a certificate and the
    /// decide path then re-verified the SAME certificate — double hash-based
    /// signature work on every synced block. `decide` skips re-verification when
    /// the identity matches; live decides (no sync verify ran) miss and verify
    /// exactly as before.
    pub last_verified_certificate: Option<(Ctx::Height, Round, ValueId<Ctx>)>,

    /// HK-R8: highest height claimed by each current-set validator through a
    /// future-height VOTE whose signature VERIFIED under that validator's current
    /// operational key (v0.19.10, VZ-2 — until then the claim was recorded from
    /// the address field of an unverified frame, so anyone could populate it with
    /// public addresses). One entry per address, the height only ratchets upward,
    /// entries our own height has passed are pruned at every new height. Feeds
    /// `corroborated_peer_tip()` / `should_abstain()`.
    pub peer_height_claims: Vec<(Ctx::Address, Ctx::Height)>,

    /// HK-R8 (v0.19.10): failed future-claim signature verifications per
    /// address in the current budget window (`CLAIM_VERIFY_BUDGET` per address
    /// per window). Bounds the CPU a flood of forged frames can cost; the window
    /// refills when our height has advanced by `gap` since the last refill
    /// (`reset_and_start_height`), so it never refills on a node that makes no
    /// progress — such a node is protocol-quiescent and burns nothing anyway.
    pub claim_verify_failures: Vec<(Ctx::Address, u32)>,

    /// HK-R8 (v0.19.10): the height at which the verify budget last refilled.
    pub claim_budget_refilled_at: Ctx::Height,

    /// HK-R8 (v0.19.10): failed future-claim verifications since the process
    /// started (a forgery signal for the operator; printed in the R8 line).
    pub claim_verify_failures_total: u64,

    /// v0.19.10: inputs refused by the future-height buffer bound since the
    /// process started (see `buffer_admission`).
    pub buffer_dropped_total: u64,

    /// HK-R8: last height at which we logged the abstain notice (once per
    /// height, not once per futile round — abstaining can last hours).
    pub last_abstain_logged: Option<Ctx::Height>,
}

/// HK-R8 (v0.19.10): failed future-claim signature verifications a single
/// validator address may cost us per budget window (see `State::claim_verify_failures`).
pub const CLAIM_VERIFY_BUDGET: u32 = 3;

/// v0.19.10: the buffer keeps at most this many distinct rounds of VERIFIED
/// votes per (height, validator address) — one prevote and one precommit per
/// round, so at most 2 × this many votes per address per height (honest future
/// votes beyond round 8 are practically nonexistent; a node that far behind
/// decides by certificate). Only current-set members' verified votes are
/// buffered, so with 9,196-byte votes and an 11-seat set that is ≈ 1.6 MB per
/// height over the `BUFFER_HEIGHT_WINDOW` + 1 heights the buffer keeps: ≈ 8 MB.
pub const BUFFER_MAX_VOTE_ROUNDS_PER_ADDRESS: usize = 8;

/// v0.19.10: the buffer keeps at most this many distinct proposal rounds per
/// height (signed proposals and host-reassembled proposed values alike), only
/// from the scheduled proposer of that (height, round) under the current set. A
/// proposal carries the whole value (up to the 32 MiB pubsub cap), so an
/// unbounded future-height buffer was a keyless memory lever on 4 GB seats:
/// (window + 1) heights × 2 rounds × 32 MiB ≈ 320 MiB worst case now, and a
/// signed proposal is buffered only after its signature verifies.
pub const BUFFER_MAX_PROPOSAL_ROUNDS_PER_HEIGHT: usize = 2;

/// v0.19.10: future-height inputs are buffered only this many heights above
/// ours. A node further behind decides by certificate (sync) and never needs
/// them, and the R8 claim path has already run on the vote by then.
pub const BUFFER_HEIGHT_WINDOW: u64 = 4;

/// v0.19.10: what `buffer_admission` says about an input a handler wants to
/// buffer for a later height (or for the current height before the driver
/// started): drop it, admit it as is, or admit it only if its signature
/// verifies under this validator's current key.
#[derive_where::derive_where(Clone, Debug)]
pub enum BufferAdmission<Ctx: Context> {
    Drop,
    Admit,
    Verify(Ctx::Validator),
}

impl<Ctx> State<Ctx>
where
    Ctx: Context,
{
    pub fn new(ctx: Ctx, params: Params<Ctx>, queue_capacity: usize) -> Self {
        let driver = Driver::new(
            ctx.clone(),
            params.initial_height,
            params.initial_validator_set.clone(),
            params.address.clone(),
            params.threshold_params,
        );

        let initial_height = params.initial_height;
        Self {
            ctx,
            driver,
            params,
            input_queue: BoundedQueue::new(queue_capacity),
            sync_input_queue: BoundedQueue::new(queue_capacity),
            full_proposal_keeper: Default::default(),
            last_signed_prevote: None,
            last_signed_precommit: None,
            last_verified_certificate: None,
            peer_height_claims: Vec::new(),
            claim_verify_failures: Vec::new(),
            claim_budget_refilled_at: initial_height,
            claim_verify_failures_total: 0,
            buffer_dropped_total: 0,
            last_abstain_logged: None,
        }
    }

    /// HK-R8: record a validator's height claim. Since v0.19.10 the caller
    /// (`on_vote`) calls this only after the vote's signature VERIFIED under the
    /// named validator's current key; the membership check stays as a guard.
    /// Claims only ratchet upward.
    pub fn note_future_height_claim(&mut self, addr: &Ctx::Address, height: Ctx::Height) {
        use malachitebft_core_types::ValidatorSet as _;
        if self.driver.validator_set().get_by_address(addr).is_none() {
            return;
        }
        match self.peer_height_claims.iter_mut().find(|(a, _)| a == addr) {
            Some((_, h)) => {
                if height > *h {
                    *h = height;
                }
            }
            None => self.peer_height_claims.push((addr.clone(), height)),
        }
    }

    /// HK-R8 (v0.19.10): should `on_vote` spend a signature verification on a
    /// future-height vote that names `addr` and claims `height`? Every check is
    /// free, in this order: the context opts in (`HK_ABSTAIN_GAP=0` skips the
    /// whole claim path); we are an active validator (an observer never
    /// abstains, so its verifications would be attacker-controlled CPU); the
    /// claim is at least `gap` above us (a lower one can never fire R8, our
    /// height only rises); the address is not our own (such a frame can only be
    /// a forgery); the address is a current-set member whose recorded claim is
    /// below `height` (no information gain otherwise); and the address is under
    /// its verify budget for this window.
    pub fn future_claim_wants_verify(&self, addr: &Ctx::Address, height: Ctx::Height) -> bool {
        use malachitebft_core_types::ValidatorSet as _;
        let Some(gap) = self.ctx.abstain_threshold() else {
            return false;
        };
        if !self.is_active_validator() {
            return false;
        }
        if height.as_u64() < self.height().as_u64().saturating_add(gap) {
            return false;
        }
        if addr == self.address() {
            return false;
        }
        if self.driver.validator_set().get_by_address(addr).is_none() {
            return false;
        }
        if let Some((_, recorded)) = self.peer_height_claims.iter().find(|(a, _)| a == addr) {
            if height <= *recorded {
                return false;
            }
        }
        let failures = self
            .claim_verify_failures
            .iter()
            .find(|(a, _)| a == addr)
            .map(|(_, n)| *n)
            .unwrap_or(0);
        failures < CLAIM_VERIFY_BUDGET
    }

    /// HK-R8 (v0.19.10): count a failed future-claim verification against
    /// `addr`. Returns the failures charged to that address in the current
    /// window (1 = the first, which the caller logs).
    pub fn note_future_claim_failure(&mut self, addr: &Ctx::Address) -> u32 {
        self.claim_verify_failures_total = self.claim_verify_failures_total.saturating_add(1);
        match self.claim_verify_failures.iter_mut().find(|(a, _)| a == addr) {
            Some((_, n)) => {
                *n = n.saturating_add(1);
                *n
            }
            None => {
                self.claim_verify_failures.push((addr.clone(), 1));
                1
            }
        }
    }

    /// HK-R8: corroborated network-tip evidence, power-weighted (v0.19.10):
    /// the highest height H such that the current-set validators whose VERIFIED
    /// claim is ≥ H hold MORE THAN ONE THIRD of the set's voting power
    /// (`threshold_params.honest`, the vote keeper's own f+1 primitive).
    ///
    /// Why that is BFT-correct: with faulty power ≤ f (3f < total) any claimant
    /// set above one third contains an honest validator; an honest validator
    /// votes only at its current height, which it reaches only after the
    /// previous height was decided; so H is at most one above a decided height
    /// and our votes at heights ≤ H − gap are worthless by construction. A
    /// Byzantine key-holder's u64::MAX claim cannot raise H above the honest
    /// claim that completes the threshold. (Until v0.19.10 this was "the
    /// second-highest claim among two distinct addresses", which two power-1
    /// seats — or, before signature verification, anyone — could satisfy.)
    /// Soundness assumes `honest = F_PLUS_ONE` beside `quorum = TWO_F_PLUS_ONE`
    /// (the engine's defaults).
    pub fn corroborated_peer_tip(&self) -> Option<Ctx::Height> {
        use malachitebft_core_types::ValidatorSet as _;
        let honest = self.params.threshold_params.honest;
        let set = self.driver.validator_set();
        let total = set.total_voting_power();
        let mut claims: Vec<(Ctx::Height, VotingPower)> = self
            .peer_height_claims
            .iter()
            .filter_map(|(a, h)| set.get_by_address(a).map(|v| (*h, v.voting_power())))
            .collect();
        // Highest claim first: the accumulation meets the threshold at the
        // highest height more than one third of the power vouches for.
        claims.sort_by(|a, b| b.0.cmp(&a.0));
        let mut acc: VotingPower = 0;
        for (h, p) in claims {
            acc = acc.saturating_add(p);
            if honest.is_met(acc, total) {
                return Some(h);
            }
        }
        None
    }

    /// HK-R8 (v0.19.10): the evidence behind an abstain, for the log — every
    /// current-set claimant whose verified claim is at least `gap` above us
    /// (address, claimed height, voting power), their summed power, the set's
    /// total power. Empty when the context opts out.
    pub fn abstain_evidence(&self) -> (Vec<(Ctx::Address, Ctx::Height, VotingPower)>, VotingPower, VotingPower) {
        use malachitebft_core_types::ValidatorSet as _;
        let set = self.driver.validator_set();
        let total = set.total_voting_power();
        let Some(gap) = self.ctx.abstain_threshold() else {
            return (Vec::new(), 0, total);
        };
        let floor = self.height().as_u64().saturating_add(gap);
        let mut weight: VotingPower = 0;
        let claimants: Vec<(Ctx::Address, Ctx::Height, VotingPower)> = self
            .peer_height_claims
            .iter()
            .filter(|(_, h)| h.as_u64() >= floor)
            .filter_map(|(a, h)| set.get_by_address(a).map(|v| (a.clone(), *h, v.voting_power())))
            .collect();
        for (_, _, p) in &claimants {
            weight = weight.saturating_add(*p);
        }
        (claimants, weight, total)
    }

    /// HK-R8: should this validator abstain from signing right now?
    /// True only when the context opts in AND corroborated evidence puts the
    /// network at least `gap` heights ahead. Signing while that is true spends
    /// irreplaceable one-time leaves on votes the network will never count.
    pub fn should_abstain(&self) -> bool {
        let Some(gap) = self.ctx.abstain_threshold() else {
            return false;
        };
        let Some(tip) = self.corroborated_peer_tip() else {
            return false;
        };
        tip.as_u64() >= self.height().as_u64().saturating_add(gap)
    }

    pub fn height(&self) -> Ctx::Height {
        self.driver.height()
    }

    pub fn round(&self) -> Round {
        self.driver.round()
    }

    pub fn address(&self) -> &Ctx::Address {
        self.driver.address()
    }

    pub fn validator_set(&self) -> &Ctx::ValidatorSet {
        self.driver.validator_set()
    }

    pub fn get_proposer(&self, height: Ctx::Height, round: Round) -> &Ctx::Address {
        self.ctx
            .select_proposer(self.validator_set(), height, round)
            .address()
    }

    pub fn set_last_vote(&mut self, vote: SignedVote<Ctx>) {
        match vote.vote_type() {
            VoteType::Prevote => self.last_signed_prevote = Some(vote),
            VoteType::Precommit => self.last_signed_precommit = Some(vote),
        }
    }

    pub fn restore_precommits(
        &mut self,
        height: Ctx::Height,
        round: Round,
        value: &Ctx::Value,
    ) -> Vec<SignedVote<Ctx>> {
        assert_eq!(height, self.driver.height());

        // Get the commits for the height and round.
        if let Some(per_round) = self.driver.votes().per_round(round) {
            per_round
                .received_votes()
                .iter()
                .filter(|vote| {
                    vote.vote_type() == VoteType::Precommit
                        && vote.value() == &NilOrVal::Val(value.id())
                })
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn polka_certificate_at_round(&self, round: Round) -> Option<PolkaCertificate<Ctx>> {
        // Get the polka certificate for the specified round if it exists
        self.driver
            .polka_certificates()
            .iter()
            .find(|c| c.round == round && c.height == self.driver.height())
            .cloned()
    }

    pub fn full_proposal_at_round_and_value(
        &self,
        height: &Ctx::Height,
        round: Round,
        value: &Ctx::Value,
    ) -> Option<&FullProposal<Ctx>> {
        self.full_proposal_keeper
            .full_proposal_at_round_and_value(height, round, &value.id())
    }

    pub fn full_proposal_at_round_and_proposer(
        &self,
        height: &Ctx::Height,
        round: Round,
        address: &Ctx::Address,
    ) -> Option<&FullProposal<Ctx>> {
        self.full_proposal_keeper
            .full_proposal_at_round_and_proposer(height, round, address)
    }

    pub fn proposals_for_value(
        &self,
        proposed_value: &ProposedValue<Ctx>,
    ) -> Vec<SignedProposal<Ctx>> {
        self.full_proposal_keeper
            .proposals_for_value(proposed_value)
    }

    pub fn store_proposal(&mut self, new_proposal: SignedProposal<Ctx>) {
        self.full_proposal_keeper.store_proposal(new_proposal)
    }

    pub fn value_exists(&mut self, new_value: &ProposedValue<Ctx>) -> bool {
        self.full_proposal_keeper.value_exists(new_value)
    }

    pub fn store_value(&mut self, new_value: &ProposedValue<Ctx>) {
        // Values for higher height should have been cached for future processing
        assert_eq!(new_value.height, self.driver.height());

        // Store the value at both round and valid_round
        self.full_proposal_keeper.store_value(new_value);
    }

    pub fn reset_and_start_height(
        &mut self,
        height: Ctx::Height,
        validator_set: Ctx::ValidatorSet,
    ) {
        self.full_proposal_keeper.clear();
        self.last_signed_prevote = None;
        self.last_signed_precommit = None;

        // HK-R8 (v0.19.10, VZ-2): a claim at or below the height we are starting
        // is provably stale, and a claimant that left the set no longer counts —
        // prune both; the verify budget refills once per `gap` heights of OUR
        // progress (never by time, never on a peer disconnect: no PeerId reaches
        // core-consensus).
        {
            use malachitebft_core_types::ValidatorSet as _;
            self.peer_height_claims
                .retain(|(a, h)| *h > height && validator_set.get_by_address(a).is_some());
            if let Some(gap) = self.ctx.abstain_threshold() {
                if height.as_u64() >= self.claim_budget_refilled_at.as_u64().saturating_add(gap) {
                    self.claim_verify_failures.clear();
                    self.claim_budget_refilled_at = height;
                }
            }
        }

        self.driver.move_to_height(height, validator_set);
    }

    /// Return the round and value id of the decided value.
    pub fn decided_value(&self) -> Option<(Round, Ctx::Value)> {
        self.driver.decided_value()
    }

    /// Queue an input for later processing, only keep inputs for the highest height seen so far.
    ///
    /// v0.19.10: bounded per height (see `buffer_admission`). Until then any
    /// peer could append unverified frames to a height without limit — and a
    /// future-height proposal carries the whole value, up to the 32 MiB pubsub
    /// cap, so on a 4 GB seat the buffer was a keyless memory lever. The vote and
    /// proposal handlers call `buffer_admission` first and verify the frame's
    /// signature when it says so; this method re-applies the structural bound as
    /// the last gate and counts what it refuses.
    pub fn buffer_input(&mut self, height: Ctx::Height, input: Input<Ctx>, _metrics: &Metrics) {
        match self.buffer_admission(&height, &input) {
            BufferAdmission::Admit => self.push_buffered(height, input, _metrics),
            BufferAdmission::Drop => self.note_buffer_drop(&height),
            BufferAdmission::Verify(_) => {
                // An input that needs its signature verified first must come through
                // `buffer_verified` after the handler verified it (`buffer_vote`,
                // `buffer_proposal`). Refusing it here keeps the gate honest for any
                // future caller that forgets.
                tracing::warn!(%height, "buffer_input refused an input that needs verification first — use buffer_verified after verifying");
                self.note_buffer_drop(&height);
            }
        }
    }

    /// v0.19.10: queue an input whose signature the caller has just verified under the
    /// validator `buffer_admission` named. The structural bound is re-applied (nothing can
    /// have changed in between: the actor handles one input at a time and the verification
    /// effect completes before the handler resumes), then the input is pushed.
    pub fn buffer_verified(&mut self, height: Ctx::Height, input: Input<Ctx>, _metrics: &Metrics) {
        match self.buffer_admission(&height, &input) {
            BufferAdmission::Drop => self.note_buffer_drop(&height),
            BufferAdmission::Admit | BufferAdmission::Verify(_) => {
                self.push_buffered(height, input, _metrics)
            }
        }
    }

    fn push_buffered(&mut self, height: Ctx::Height, input: Input<Ctx>, _metrics: &Metrics) {
        self.input_queue.push(height, input);

        #[cfg(feature = "metrics")]
        {
            _metrics.queue_heights.set(self.input_queue.len() as i64);
            _metrics.queue_size.set(self.input_queue.size() as i64);
        }
    }

    /// v0.19.10: count an input the buffer refused (a duplicate, out of the
    /// window, from a non-member or a non-scheduled proposer, or one whose
    /// signature did not verify).
    pub fn note_buffer_drop(&mut self, height: &Ctx::Height) {
        self.buffer_dropped_total = self.buffer_dropped_total.saturating_add(1);
        tracing::debug!(
            %height,
            dropped_total = self.buffer_dropped_total,
            "Input buffer bound: dropping an input (duplicate, out of window, unknown signer, \
             unscheduled proposer, or a signature that did not verify)"
        );
    }

    /// v0.19.10: the per-height bound on buffered inputs, and whether the input
    /// must be signature-verified first. Every input kind is confined to the
    /// window `our height ..= our height + BUFFER_HEIGHT_WINDOW` (a node further
    /// behind decides by certificate).
    /// - A VOTE must name a current-set member; it is admitted only after its
    ///   signature verifies under that member's current key (`Verify`), and
    ///   then only if no verified vote with the same (address, type, round) is
    ///   queued at that height and the address holds fewer than
    ///   `BUFFER_MAX_VOTE_ROUNDS_PER_ADDRESS` distinct rounds there. Because only
    ///   verified votes occupy slots, a keyless peer can neither fill the buffer
    ///   nor take the slot of the honest vote a slightly-behind node needs.
    /// - A PROPOSAL must carry a defined round (an honest proposal never has
    ///   round Nil; `select_proposer` asserts), come from the proposer
    ///   `select_proposer` names for (height, round) under the current set, be
    ///   the first for that round at that height, and the height must hold
    ///   fewer than `BUFFER_MAX_PROPOSAL_ROUNDS_PER_HEIGHT` rounds; it is
    ///   admitted only after its signature verifies (`Verify`).
    /// - A PROPOSED VALUE (the host's reassembled value, which carries no
    ///   signature of its own) follows the proposal rules without the
    ///   verification (`Admit`).
    /// - Every other input kind is admitted as before (`Admit`).
    pub fn buffer_admission(&self, height: &Ctx::Height, input: &Input<Ctx>) -> BufferAdmission<Ctx> {
        use malachitebft_core_types::ValidatorSet as _;
        if height.as_u64() > self.height().as_u64().saturating_add(BUFFER_HEIGHT_WINDOW) {
            return BufferAdmission::Drop;
        }
        let existing: &[Input<Ctx>] = self.input_queue.get(height).unwrap_or(&[]);
        let set = self.driver.validator_set();
        match input {
            Input::Vote(vote) => {
                let addr = vote.validator_address();
                let round = vote.round();
                let typ = vote.vote_type();
                let Some(validator) = set.get_by_address(addr) else {
                    return BufferAdmission::Drop;
                };
                let mut rounds: Vec<Round> = Vec::new();
                for queued in existing {
                    if let Input::Vote(other) = queued {
                        if other.validator_address() != addr {
                            continue;
                        }
                        if other.round() == round && other.vote_type() == typ {
                            return BufferAdmission::Drop;
                        }
                        if !rounds.contains(&other.round()) {
                            rounds.push(other.round());
                        }
                    }
                }
                if rounds.contains(&round) || rounds.len() < BUFFER_MAX_VOTE_ROUNDS_PER_ADDRESS {
                    BufferAdmission::Verify(validator.clone())
                } else {
                    BufferAdmission::Drop
                }
            }
            Input::Proposal(proposal) => {
                match self.proposal_slot_admits(
                    existing,
                    *height,
                    proposal.round(),
                    proposal.validator_address(),
                    false,
                ) {
                    Some(validator) => BufferAdmission::Verify(validator),
                    None => BufferAdmission::Drop,
                }
            }
            Input::ProposedValue(value, _) => {
                match self.proposal_slot_admits(existing, *height, value.round, &value.proposer, true) {
                    Some(_) => BufferAdmission::Admit,
                    None => BufferAdmission::Drop,
                }
            }
            _ => BufferAdmission::Admit,
        }
    }

    /// The proposal-side rules shared by signed proposals and proposed values:
    /// a defined round, the scheduled proposer for (height, round) under the
    /// current set, one entry per (height, round) of the same kind, at most
    /// `BUFFER_MAX_PROPOSAL_ROUNDS_PER_HEIGHT` rounds per height. Returns the
    /// scheduled proposer (the key a signed proposal is verified under).
    fn proposal_slot_admits(
        &self,
        existing: &[Input<Ctx>],
        height: Ctx::Height,
        round: Round,
        proposer: &Ctx::Address,
        proposed_values: bool,
    ) -> Option<Ctx::Validator> {
        use malachitebft_core_types::ValidatorSet as _;
        if round.is_nil() || round.as_i64() < 0 {
            return None;
        }
        let set = self.driver.validator_set();
        if set.count() == 0 {
            return None;
        }
        let scheduled = self.ctx.select_proposer(set, height, round);
        if scheduled.address() != proposer {
            return None;
        }
        let mut rounds: Vec<Round> = Vec::new();
        for queued in existing {
            let other_round = match (queued, proposed_values) {
                (Input::Proposal(other), false) => other.round(),
                (Input::ProposedValue(other, _), true) => other.round,
                _ => continue,
            };
            if other_round == round {
                return None;
            }
            if !rounds.contains(&other_round) {
                rounds.push(other_round);
            }
        }
        if rounds.len() < BUFFER_MAX_PROPOSAL_ROUNDS_PER_HEIGHT {
            Some(scheduled.clone())
        } else {
            None
        }
    }

    /// Queue a sync input for later processing, only keep inputs for the highest height seen so far.
    pub fn buffer_sync_input(
        &mut self,
        height: Ctx::Height,
        input: Input<Ctx>,
        _metrics: &Metrics,
    ) {
        self.sync_input_queue.push(height, input);

        #[cfg(feature = "metrics")]
        {
            _metrics
                .sync_queue_heights
                .set(self.sync_input_queue.len() as i64);
            _metrics
                .sync_queue_size
                .set(self.sync_input_queue.size() as i64);
        }
    }

    /// Take all inputs that are pending for the specified height and remove from the input queue.
    pub fn take_pending_inputs(&mut self, _metrics: &Metrics) -> Vec<Input<Ctx>>
    where
        Ctx: Context,
    {
        let mut inputs = self
            .input_queue
            .shift_and_take(&self.height())
            .collect::<Vec<_>>();

        let mut sync_response_inputs = self
            .sync_input_queue
            .shift_and_take(&self.height())
            .collect::<Vec<_>>();

        #[cfg(feature = "metrics")]
        {
            _metrics.queue_heights.set(self.input_queue.len() as i64);
            _metrics.queue_size.set(self.input_queue.size() as i64);
            _metrics
                .sync_queue_heights
                .set(self.sync_input_queue.len() as i64);
            _metrics
                .sync_queue_size
                .set(self.sync_input_queue.size() as i64);
        }

        // We first return the sync-related inputs because if we can successfully apply them, we will move
        // to the next height, and therefore we can skip applying pending inputs for the just-committed height.
        sync_response_inputs.append(&mut inputs);
        sync_response_inputs
    }

    pub fn print_state(&self) {
        if let Some(per_round) = self.driver.votes().per_round(self.driver.round()) {
            info!(
                "Number of validators having voted: {} / {}",
                per_round.addresses_weights().get_inner().len(),
                self.driver.validator_set().count()
            );
            info!(
                "Total voting power of validators: {}",
                self.driver.validator_set().total_voting_power()
            );
            info!(
                "Voting power required: {}",
                self.params
                    .threshold_params
                    .quorum
                    .min_expected(self.driver.validator_set().total_voting_power())
            );
            info!(
                "Total voting power of validators having voted: {}",
                per_round.addresses_weights().sum()
            );
            info!(
                "Total voting power of validators having prevoted nil: {}",
                per_round
                    .votes()
                    .get_weight(VoteType::Prevote, &NilOrVal::Nil)
            );
            info!(
                "Total voting power of validators having precommited nil: {}",
                per_round
                    .votes()
                    .get_weight(VoteType::Precommit, &NilOrVal::Nil)
            );
            info!(
                "Total weight of prevotes: {}",
                per_round.votes().weight_sum(VoteType::Prevote)
            );
            info!(
                "Total weight of precommits: {}",
                per_round.votes().weight_sum(VoteType::Precommit)
            );
        }
    }

    /// Check if this node is an active validator.
    ///
    /// Returns true only if:
    /// - Consensus is enabled in the configuration, AND
    /// - This node is present in the current validator set
    pub fn is_active_validator(&self) -> bool {
        self.params.enabled
            && self
                .validator_set()
                .get_by_address(self.address())
                .is_some()
    }

    pub fn round_certificate(&self) -> Option<&EnterRoundCertificate<Ctx>> {
        self.driver.round_certificate.as_ref()
    }
}
