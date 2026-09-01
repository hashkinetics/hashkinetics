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

    /// HK-R8: highest height claimed by each peer via future-height consensus
    /// messages (votes/proposals buffered above our height). Only claims from
    /// members of the CURRENT validator set are recorded, so gossip spam from
    /// arbitrary peers cannot populate this. Small linear vec: bounded by the
    /// validator-set size. Feeds `should_abstain()`.
    pub peer_height_claims: Vec<(Ctx::Address, Ctx::Height)>,

    /// HK-R8: last height at which we logged the abstain notice (once per
    /// height, not once per futile round — abstaining can last hours).
    pub last_abstain_logged: Option<Ctx::Height>,
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
            last_abstain_logged: None,
        }
    }

    /// HK-R8: record a peer's implicit height claim (it sent a consensus message
    /// for a height above ours). Ignored unless the claimed sender is in the
    /// current validator set. Claims only ratchet upward.
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

    /// HK-R8: corroborated network-tip evidence — the SECOND-highest height
    /// claimed by distinct current-set validators. One faulty validator cannot
    /// fabricate it; a lone ahead-of-quorum node cannot stall the majority.
    pub fn corroborated_peer_tip(&self) -> Option<Ctx::Height> {
        use malachitebft_core_types::ValidatorSet as _;
        let set = self.driver.validator_set();
        let mut heights: Vec<Ctx::Height> = self
            .peer_height_claims
            .iter()
            .filter(|(a, _)| set.get_by_address(a).is_some())
            .map(|(_, h)| *h)
            .collect();
        if heights.len() < 2 {
            return None;
        }
        heights.sort_unstable();
        Some(heights[heights.len() - 2])
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

        self.driver.move_to_height(height, validator_set);
    }

    /// Return the round and value id of the decided value.
    pub fn decided_value(&self) -> Option<(Round, Ctx::Value)> {
        self.driver.decided_value()
    }

    /// Queue an input for later processing, only keep inputs for the highest height seen so far.
    pub fn buffer_input(&mut self, height: Ctx::Height, input: Input<Ctx>, _metrics: &Metrics) {
        self.input_queue.push(height, input);

        #[cfg(feature = "metrics")]
        {
            _metrics.queue_heights.set(self.input_queue.len() as i64);
            _metrics.queue_size.set(self.input_queue.size() as i64);
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
