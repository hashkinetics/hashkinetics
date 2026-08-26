//! The consensus↔application message loop — mirrors the engine example's app.rs,
//! driving HkApp (which drives the verified hk-state chain).

use eyre::eyre;
use tracing::{error, info};

use malachitebft_app_channel::app::engine::host::Next;
use malachitebft_app_channel::app::streaming::StreamContent;
use malachitebft_app_channel::app::types::core::Round;
use malachitebft_app_channel::app::types::sync::RawDecidedValue;
use malachitebft_app_channel::app::types::LocallyProposedValue;
use malachitebft_app_channel::{AppMsg, Channels, NetworkMsg};

use hk_consensus::HkContext;

use crate::codec::HkCodec;
use crate::state::HkApp;

pub async fn run(state: &mut HkApp, channels: &mut Channels<HkContext>) -> eyre::Result<()> {
    use malachitebft_codec::Codec;

    while let Some(msg) = channels.consensus.recv().await {
        match msg {
            AppMsg::ConsensusReady { reply, .. } => {
                let start_height = state.start_height();
                info!(%start_height, "Consensus is ready");
                if reply.send((start_height, state.validator_set())).is_err() {
                    error!("Failed to send ConsensusReady reply");
                }
            }

            AppMsg::StartedRound { height, round, proposer, role: _, reply_value } => {
                info!(%height, %round, %proposer, "Started round");
                state.current_height = height;
                state.current_round = round;
                state.current_proposer = Some(proposer);

                let undecided = state.undecided_at(height, round);
                if reply_value.send(undecided).is_err() {
                    error!("Failed to send StartedRound reply");
                }
            }

            AppMsg::GetValue { height, round, timeout: _, reply } => {
                info!(%height, %round, "Consensus requests a value to propose");

                let proposal = match state.previously_built(height, round) {
                    Some(p) => {
                        info!(value = %p.value.id(), "Re-using previously built value");
                        p
                    }
                    None => state.propose_value(height, round),
                };

                if reply.send(proposal.clone()).is_err() {
                    error!("Failed to send GetValue reply");
                }

                for stream_message in state.stream_proposal(proposal, Round::Nil) {
                    channels
                        .network
                        .send(NetworkMsg::PublishProposalPart(stream_message))
                        .await?;
                }
            }

            AppMsg::ExtendVote { reply, .. } => {
                if reply.send(None).is_err() {
                    error!("Failed to send ExtendVote reply");
                }
            }

            AppMsg::VerifyVoteExtension { reply, .. } => {
                if reply.send(Ok(())).is_err() {
                    error!("Failed to send VerifyVoteExtension reply");
                }
            }

            AppMsg::ReceivedProposalPart { from, part, reply } => {
                let part_type = match &part.content {
                    StreamContent::Data(p) => p.get_type(),
                    StreamContent::Fin => "end of stream",
                };
                info!(%from, sequence = %part.sequence, part = %part_type, "Received proposal part");

                let proposed_value = state.received_proposal_part(from, part);
                if reply.send(proposed_value).is_err() {
                    error!("Failed to send ReceivedProposalPart reply");
                }
            }

            AppMsg::Decided { certificate, extensions, reply } => {
                info!(
                    height = %certificate.height,
                    round = %certificate.round,
                    value = %certificate.value_id,
                    "Consensus decided — committing to the chain"
                );

                match state.commit(certificate, extensions) {
                    Ok(()) => {
                        if reply
                            .send(Next::Start(state.current_height, state.validator_set()))
                            .is_err()
                        {
                            error!("Failed to send Decided reply");
                        }
                    }
                    Err(e) => {
                        let height = state.current_height;
                        error!(%e, %height, "Commit failed — restarting height");
                        if reply
                            .send(Next::Restart(height, state.validator_set()))
                            .is_err()
                        {
                            error!("Failed to send Decided restart reply");
                        }
                    }
                }
            }

            AppMsg::ProcessSyncedValue { height, round, proposer, value_bytes, reply } => {
                info!(%height, %round, "Processing synced value");

                match HkCodec.decode(value_bytes) {
                    Ok(value) => {
                        let proposed = malachitebft_app_channel::app::types::ProposedValue {
                            height,
                            round,
                            valid_round: Round::Nil,
                            proposer,
                            value,
                            validity: malachitebft_app_channel::app::types::core::Validity::Valid,
                        };
                        state.store_undecided(proposed.clone());
                        if reply.send(Some(proposed)).is_err() {
                            error!("Failed to send ProcessSyncedValue reply");
                        }
                    }
                    Err(e) => {
                        error!(%e, "Failed to decode synced value");
                        if reply.send(None).is_err() {
                            error!("Failed to send ProcessSyncedValue reply");
                        }
                    }
                }
            }

            AppMsg::GetDecidedValue { height, reply } => {
                let raw = state.decided.get(&height.as_u64()).map(|entry| RawDecidedValue {
                    certificate: entry.certificate.clone(),
                    value_bytes: HkCodec.encode(&entry.value).unwrap_or_default(),
                });
                if reply.send(raw).is_err() {
                    error!("Failed to send GetDecidedValue reply");
                }
            }

            AppMsg::GetHistoryMinHeight { reply } => {
                if reply.send(state.earliest_height()).is_err() {
                    error!("Failed to send GetHistoryMinHeight reply");
                }
            }

            AppMsg::RestreamProposal { height, round, valid_round, address: _, value_id } => {
                let proposal_round = if valid_round == Round::Nil { round } else { valid_round };
                info!(%height, %proposal_round, "Restreaming proposal");

                if let Some(p) = state.find_undecided(height, proposal_round, value_id) {
                    let lpv = LocallyProposedValue { height, round, value: p.value };
                    for stream_message in state.stream_proposal(lpv, valid_round) {
                        channels
                            .network
                            .send(NetworkMsg::PublishProposalPart(stream_message))
                            .await?;
                    }
                }
            }
        }
    }

    Err(eyre!("Consensus channel closed unexpectedly"))
}
