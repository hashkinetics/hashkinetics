use crate::handle::driver::apply_driver_input;
use crate::handle::signature::verify_signature;
use crate::input::Input;
use crate::prelude::*;
use crate::state::BufferAdmission;
use crate::types::{ConsensusMsg, SignedConsensusMsg, WalEntry};
use crate::util::pretty::PrettyVote;

pub async fn on_vote<Ctx>(
    co: &Co<Ctx>,
    state: &mut State<Ctx>,
    metrics: &Metrics,
    signed_vote: SignedVote<Ctx>,
) -> Result<(), Error<Ctx>>
where
    Ctx: Context,
{
    let consensus_height = state.height();
    let consensus_round = state.round();
    let vote_height = signed_vote.height();
    let vote_round = signed_vote.round();
    let validator_address = signed_vote.validator_address();

    // v0.19.10 (HK): no honest vote carries round Nil (-1) — the driver only ever
    // emits votes for a defined round. Refuse it before any other work: the
    // wire format admits the value, and nothing below is written for it.
    if vote_round.is_nil() {
        warn!(
            consensus.height = %consensus_height,
            vote.height = %vote_height,
            validator = %validator_address,
            "Received vote with round Nil, dropping"
        );

        return Ok(());
    }

    // Discard votes for heights lower than the current height.
    if consensus_height > vote_height {
        debug!(
            consensus.height = %consensus_height,
            consensus.round = %consensus_round,
            vote.height = %vote_height,
            vote.round = %vote_round,
            validator = %validator_address,
            "Received vote for lower height, dropping"
        );

        return Ok(());
    }

    // Queue votes for heights higher than the current height.
    if consensus_height < vote_height {
        debug!(
            consensus.height = %consensus_height,
            consensus.round = %consensus_round,
            vote.height = %vote_height,
            vote.round = %vote_round,
            validator = %validator_address,
            "Received vote for higher height, queuing for later"
        );

        // HK-R8 (v0.19.10, VZ-2): a vote above our height is peer evidence that the
        // network is ahead ONLY if it really comes from the validator it names. Until
        // v0.19.10 the claim was recorded here from the frame's address field before
        // any check, so a peer with no key could silence every seat with two public
        // addresses and a zero signature. Now: a set of free filters first decides
        // whether this frame can matter at all and whether the named address still
        // has verify budget (`State::future_claim_wants_verify`), then the signature
        // is verified under the named member's CURRENT operational key through
        // `verify_signature` — never `verify_signed_vote`, which asserts the current
        // height and would panic the consensus actor on a future-height message —
        // and only a verified vote records a claim. A failed verification is charged
        // to the address (a forgery, or a key rotated after our height: the two are
        // indistinguishable here, so the peer is not penalised). Buffering is a
        // separate decision (`buffer_vote` below): a claim-path vote lies far above
        // the buffer window and is never buffered; a vote within the window is
        // buffered only after its own verification there.
        if state.future_claim_wants_verify(validator_address, vote_height) {
            let validator = state
                .validator_set()
                .get_by_address(validator_address)
                .cloned();
            if let Some(validator) = validator {
                let signed_msg = signed_vote.clone().map(ConsensusMsg::Vote);
                if verify_signature(co, signed_msg, &validator).await? {
                    state.note_future_height_claim(validator_address, vote_height);
                } else {
                    let in_window = state.note_future_claim_failure(validator_address);
                    if in_window == 1 {
                        warn!(
                            consensus.height = %consensus_height,
                            vote.height = %vote_height,
                            validator = %validator_address,
                            failed_claim_verifications_total = state.claim_verify_failures_total,
                            "HK-R8: a future-height vote naming a current validator failed signature \
                             verification — not counted as height evidence (a forgery, or a key \
                             rotated after our height)"
                        );
                    }
                }
            }
        }

        buffer_vote(co, state, metrics, signed_vote).await?;

        return Ok(());
    }

    // Queue messages if driver is not initialized
    // Process messages received for the current height.
    // Drop all others.
    if consensus_round == Round::Nil {
        debug!(
            consensus.height = %consensus_height,
            consensus.round = %consensus_round,
            vote.height = %vote_height,
            vote.round = %vote_round,
            validator = %validator_address,
            "Received vote at round -1, queuing for later"
        );

        buffer_vote(co, state, metrics, signed_vote).await?;

        return Ok(());
    }

    debug_assert_eq!(consensus_height, vote_height);

    if !verify_signed_vote(co, state, &signed_vote).await? {
        return Ok(());
    }

    info!(
        consensus.height = %consensus_height,
        consensus.round = %consensus_round,
        vote.height = %vote_height,
        vote.round = %vote_round,
        vote.msg = %PrettyVote::<Ctx>(&signed_vote.message),
        validator = %validator_address,
        "Received vote",
    );

    // Only process this vote if we have not yet seen it.
    if !state.driver.votes().has_vote(&signed_vote) {
        perform!(
            co,
            Effect::WalAppend(
                signed_vote.height(),
                WalEntry::ConsensusMsg(SignedConsensusMsg::Vote(signed_vote.clone())),
                Default::default()
            )
        );

        apply_driver_input(co, state, metrics, DriverInput::Vote(signed_vote)).await?;
    }

    Ok(())
}

/// v0.19.10 (HK): buffer a vote for a later height (or for the current height before the
/// driver has started) only after its signature verifies under the named member's current
/// key. The buffer's dedup and caps (`State::buffer_admission`) then apply to verified
/// entries only, so a peer with no key can neither fill the buffer nor take the slot of the
/// honest vote a slightly-behind node needs for its next height. Until v0.19.10 every frame
/// was buffered unverified and without limit. A vote from outside the current set, beyond
/// the window, or in a slot already taken is dropped before any verification.
async fn buffer_vote<Ctx>(
    co: &Co<Ctx>,
    state: &mut State<Ctx>,
    metrics: &Metrics,
    signed_vote: SignedVote<Ctx>,
) -> Result<(), Error<Ctx>>
where
    Ctx: Context,
{
    let height = signed_vote.height();
    let input = Input::Vote(signed_vote);
    match state.buffer_admission(&height, &input) {
        BufferAdmission::Drop => state.note_buffer_drop(&height),
        BufferAdmission::Admit => state.buffer_input(height, input, metrics),
        BufferAdmission::Verify(validator) => {
            let Input::Vote(vote) = &input else {
                return Ok(());
            };
            let signed_msg = vote.clone().map(ConsensusMsg::Vote);
            if verify_signature(co, signed_msg, &validator).await? {
                state.buffer_verified(height, input, metrics);
            } else {
                state.note_buffer_drop(&height);
            }
        }
    }

    Ok(())
}

pub async fn verify_signed_vote<Ctx>(
    co: &Co<Ctx>,
    state: &State<Ctx>,
    signed_vote: &SignedVote<Ctx>,
) -> Result<bool, Error<Ctx>>
where
    Ctx: Context,
{
    let consensus_height = state.height();
    let vote_height = signed_vote.height();
    let vote_round = signed_vote.round();
    let validator_address = signed_vote.validator_address();

    assert_eq!(vote_height, consensus_height);

    let validator_set = state.validator_set();

    let Some(validator) = validator_set.get_by_address(validator_address) else {
        warn!(
            consensus.height = %consensus_height,
            vote.height = %vote_height,
            vote.round = %vote_round,
            validator = %validator_address,
            "Received vote from unknown validator"
        );

        return Ok(false);
    };

    let signed_msg = signed_vote.clone().map(ConsensusMsg::Vote);
    if !verify_signature(co, signed_msg, validator).await? {
        warn!(
            consensus.height = %consensus_height,
            vote.height = %vote_height,
            vote.round = %vote_round,
            validator = %validator_address,
            "Received vote with invalid signature: {}", PrettyVote::<Ctx>(&signed_vote.message)
        );

        return Ok(false);
    }

    verify_vote_extension(co, state, signed_vote, validator).await
}

async fn verify_vote_extension<Ctx>(
    co: &Co<Ctx>,
    state: &State<Ctx>,
    vote: &SignedVote<Ctx>,
    validator: &Ctx::Validator,
) -> Result<bool, Error<Ctx>>
where
    Ctx: Context,
{
    let VoteType::Precommit = vote.vote_type() else {
        return Ok(true);
    };

    let NilOrVal::Val(value_id) = vote.value().as_ref() else {
        return Ok(true);
    };

    let Some(extension) = vote.extension() else {
        return Ok(true);
    };

    let result = perform!(
        co,
        Effect::VerifyVoteExtension(
            vote.height(),
            vote.round(),
            value_id.clone(),
            extension.clone(),
            validator.public_key().clone(),
            Default::default()
        ),
        Resume::VoteExtensionValidity(result) => result
    );

    if let Err(e) = result {
        warn!(
            consensus.height = %state.height(),
            vote.height = %vote.height(),
            vote.round = %vote.round(),
            validator = %validator.address(),
            "Received vote with invalid extension: {}, reason: {e}",
            PrettyVote::<Ctx>(&vote.message)
        );

        return Ok(false);
    }

    Ok(true)
}
