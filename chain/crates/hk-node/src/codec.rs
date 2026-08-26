//! HkCodec — BINCODE wire/WAL codec for HkContext (P2.5; the v0 JSON codec's DTO
//! structure is kept verbatim). DTOs decompose engine wrapper types into plain serde
//! fields; hash-based signatures travel as raw bytes. Satisfies: ConsensusCodec
//! (ProposalPart + SignedConsensusMsg + LivenessMsg + StreamMessage), WalCodec
//! (+ ProposedValue), SyncCodec (Status/Request/Response) + HasEncodedLen<Response>.
//!
//! Why bincode: JSON serialized every `Bytes` payload as a number array (~3.7×), so a
//! 2.7 MB core proof cost ~11 MB on the wire (measured: MessageTooLarge at 8 MiB).
//! Bincode is non-human-readable, so the format-aware tx/batch byte fields ride RAW —
//! a 1.24 MB aggregate costs ~1.24 MB. SAFETY: consensus signing uses the manual
//! `to_sign_bytes` layouts and the value id hashes the raw batch bytes — neither
//! touches this codec, so signature domains are unchanged. WAL format changes ⇒ a
//! codec swap needs a --fresh devnet.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

// Hash-based consensus signatures travel as raw bytes (LMS/HSS). `From<Vec<u8>> for
// HkSig` (in hk-consensus) makes the decode-side `.into()` calls just work.
type RawSig = Vec<u8>;

use malachitebft_codec::{Codec, HasEncodedLen};

use malachitebft_app_channel::app::streaming::{StreamContent, StreamId, StreamMessage};
use malachitebft_app_channel::app::types::core::{
    CommitCertificate, CommitSignature, NilOrVal, PolkaCertificate, PolkaSignature, Round,
    RoundCertificate, RoundCertificateType, RoundSignature, SignedProposal, SignedVote, Validity,
    VoteType,
};
use malachitebft_app_channel::app::types::sync::RawDecidedValue;
use malachitebft_app_channel::app::types::{PeerId, ProposedValue};
use malachitebft_core_consensus::{LivenessMsg, SignedConsensusMsg};
use malachitebft_sync::{Request, Response, Status, ValueRequest, ValueResponse};

use hk_consensus::{
    HkAddress, HkContext, HkHeight, HkProposal, HkProposalPart, HkValue, HkValueId, HkVote,
};

#[derive(Copy, Clone, Debug)]
pub struct HkCodec;

type JsonError = bincode::Error; // codec error alias (name kept to minimize churn)

fn enc<T: Serialize>(value: &T) -> Result<Bytes, JsonError> {
    bincode::serialize(value).map(Bytes::from)
}

fn dec<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, JsonError> {
    bincode::deserialize(bytes)
}

// ---------------------------------------------------------------------------
// Plain payloads: Value + ProposalPart (both serde-derive directly)
// ---------------------------------------------------------------------------

impl Codec<HkValue> for HkCodec {
    type Error = JsonError;
    fn decode(&self, bytes: Bytes) -> Result<HkValue, Self::Error> {
        dec(&bytes)
    }
    fn encode(&self, msg: &HkValue) -> Result<Bytes, Self::Error> {
        enc(msg)
    }
}

impl Codec<HkProposalPart> for HkCodec {
    type Error = JsonError;
    fn decode(&self, bytes: Bytes) -> Result<HkProposalPart, Self::Error> {
        dec(&bytes)
    }
    fn encode(&self, msg: &HkProposalPart) -> Result<Bytes, Self::Error> {
        enc(msg)
    }
}

// ---------------------------------------------------------------------------
// Votes & proposals (structured DTOs; extensions never produced in v0)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct RawVote {
    typ: VoteType,
    height: HkHeight,
    round: Round,
    value: NilOrVal<HkValueId>,
    validator_address: HkAddress,
}

impl From<&HkVote> for RawVote {
    fn from(v: &HkVote) -> Self {
        Self {
            typ: v.typ,
            height: v.height,
            round: v.round,
            value: v.value.clone(),
            validator_address: v.validator_address,
        }
    }
}

impl From<RawVote> for HkVote {
    fn from(r: RawVote) -> Self {
        HkVote {
            typ: r.typ,
            height: r.height,
            round: r.round,
            value: r.value,
            validator_address: r.validator_address,
            extension: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct RawProposal {
    height: HkHeight,
    round: Round,
    value: HkValue,
    pol_round: Round,
    validator_address: HkAddress,
}

impl From<&HkProposal> for RawProposal {
    fn from(p: &HkProposal) -> Self {
        Self {
            height: p.height,
            round: p.round,
            value: p.value.clone(),
            pol_round: p.pol_round,
            validator_address: p.validator_address,
        }
    }
}

impl From<RawProposal> for HkProposal {
    fn from(r: RawProposal) -> Self {
        HkProposal {
            height: r.height,
            round: r.round,
            value: r.value,
            pol_round: r.pol_round,
            validator_address: r.validator_address,
        }
    }
}

#[derive(Serialize, Deserialize)]
enum RawSignedConsensusMsg {
    Vote { vote: RawVote, signature: RawSig },
    Proposal { proposal: RawProposal, signature: RawSig },
}

impl Codec<SignedConsensusMsg<HkContext>> for HkCodec {
    type Error = JsonError;

    fn decode(&self, bytes: Bytes) -> Result<SignedConsensusMsg<HkContext>, Self::Error> {
        let raw: RawSignedConsensusMsg = dec(&bytes)?;
        Ok(match raw {
            RawSignedConsensusMsg::Vote { vote, signature } => {
                SignedConsensusMsg::Vote(SignedVote {
                    message: vote.into(),
                    signature: signature.into(),
                })
            }
            RawSignedConsensusMsg::Proposal { proposal, signature } => {
                SignedConsensusMsg::Proposal(SignedProposal {
                    message: proposal.into(),
                    signature: signature.into(),
                })
            }
        })
    }

    fn encode(&self, msg: &SignedConsensusMsg<HkContext>) -> Result<Bytes, Self::Error> {
        let raw = match msg {
            SignedConsensusMsg::Vote(v) => RawSignedConsensusMsg::Vote {
                vote: RawVote::from(&v.message),
                signature: v.signature.0.clone(),
            },
            SignedConsensusMsg::Proposal(p) => RawSignedConsensusMsg::Proposal {
                proposal: RawProposal::from(&p.message),
                signature: p.signature.0.clone(),
            },
        };
        enc(&raw)
    }
}

// ---------------------------------------------------------------------------
// Liveness messages
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct RawPolkaSignature {
    address: HkAddress,
    signature: RawSig,
}

#[derive(Serialize, Deserialize)]
struct RawPolkaCertificate {
    height: HkHeight,
    round: Round,
    value_id: HkValueId,
    polka_signatures: Vec<RawPolkaSignature>,
}

#[derive(Serialize, Deserialize)]
struct RawRoundSignature {
    vote_type: VoteType,
    value_id: NilOrVal<HkValueId>,
    address: HkAddress,
    signature: RawSig,
}

#[derive(Serialize, Deserialize)]
struct RawRoundCertificate {
    height: HkHeight,
    round: Round,
    cert_type: RoundCertificateType,
    round_signatures: Vec<RawRoundSignature>,
}

#[derive(Serialize, Deserialize)]
enum RawLivenessMsg {
    Vote { vote: RawVote, signature: RawSig },
    PolkaCertificate(RawPolkaCertificate),
    SkipRoundCertificate(RawRoundCertificate),
}

impl Codec<LivenessMsg<HkContext>> for HkCodec {
    type Error = JsonError;

    fn decode(&self, bytes: Bytes) -> Result<LivenessMsg<HkContext>, Self::Error> {
        let raw: RawLivenessMsg = dec(&bytes)?;
        Ok(match raw {
            RawLivenessMsg::Vote { vote, signature } => LivenessMsg::Vote(SignedVote {
                message: vote.into(),
                signature: signature.into(),
            }),
            RawLivenessMsg::PolkaCertificate(c) => {
                LivenessMsg::PolkaCertificate(PolkaCertificate {
                    height: c.height,
                    round: c.round,
                    value_id: c.value_id,
                    polka_signatures: c
                        .polka_signatures
                        .into_iter()
                        .map(|s| PolkaSignature {
                            address: s.address,
                            signature: s.signature.into(),
                        })
                        .collect(),
                })
            }
            RawLivenessMsg::SkipRoundCertificate(c) => {
                LivenessMsg::SkipRoundCertificate(RoundCertificate {
                    height: c.height,
                    round: c.round,
                    cert_type: c.cert_type,
                    round_signatures: c
                        .round_signatures
                        .into_iter()
                        .map(|s| RoundSignature {
                            vote_type: s.vote_type,
                            value_id: s.value_id,
                            address: s.address,
                            signature: s.signature.into(),
                        })
                        .collect(),
                })
            }
        })
    }

    fn encode(&self, msg: &LivenessMsg<HkContext>) -> Result<Bytes, Self::Error> {
        let raw = match msg {
            LivenessMsg::Vote(v) => RawLivenessMsg::Vote {
                vote: RawVote::from(&v.message),
                signature: v.signature.0.clone(),
            },
            LivenessMsg::PolkaCertificate(c) => RawLivenessMsg::PolkaCertificate(RawPolkaCertificate {
                height: c.height,
                round: c.round,
                value_id: c.value_id,
                polka_signatures: c
                    .polka_signatures
                    .iter()
                    .map(|s| RawPolkaSignature {
                        address: s.address,
                        signature: s.signature.0.clone(),
                    })
                    .collect(),
            }),
            LivenessMsg::SkipRoundCertificate(c) => {
                RawLivenessMsg::SkipRoundCertificate(RawRoundCertificate {
                    height: c.height,
                    round: c.round,
                    cert_type: c.cert_type.clone(),
                    round_signatures: c
                        .round_signatures
                        .iter()
                        .map(|s| RawRoundSignature {
                            vote_type: s.vote_type,
                            value_id: s.value_id.clone(),
                            address: s.address,
                            signature: s.signature.0.clone(),
                        })
                        .collect(),
                })
            }
        };
        enc(&raw)
    }
}

// ---------------------------------------------------------------------------
// Proposal-part streaming
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct RawStreamMessage {
    stream_id: Bytes,
    sequence: u64,
    content: RawStreamContent,
}

#[derive(Serialize, Deserialize)]
enum RawStreamContent {
    Data(HkProposalPart),
    Fin,
}

impl Codec<StreamMessage<HkProposalPart>> for HkCodec {
    type Error = JsonError;

    fn decode(&self, bytes: Bytes) -> Result<StreamMessage<HkProposalPart>, Self::Error> {
        let raw: RawStreamMessage = dec(&bytes)?;
        Ok(StreamMessage::new(
            StreamId::new(raw.stream_id),
            raw.sequence,
            match raw.content {
                RawStreamContent::Data(p) => StreamContent::Data(p),
                RawStreamContent::Fin => StreamContent::Fin,
            },
        ))
    }

    fn encode(&self, msg: &StreamMessage<HkProposalPart>) -> Result<Bytes, Self::Error> {
        let raw = RawStreamMessage {
            stream_id: msg.stream_id.to_bytes(),
            sequence: msg.sequence,
            content: match &msg.content {
                StreamContent::Data(p) => RawStreamContent::Data(p.clone()),
                StreamContent::Fin => RawStreamContent::Fin,
            },
        };
        enc(&raw)
    }
}

// ---------------------------------------------------------------------------
// WAL: ProposedValue
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct RawProposedValue {
    height: HkHeight,
    round: Round,
    valid_round: Round,
    proposer: HkAddress,
    value: HkValue,
    valid: bool,
}

impl Codec<ProposedValue<HkContext>> for HkCodec {
    type Error = JsonError;

    fn decode(&self, bytes: Bytes) -> Result<ProposedValue<HkContext>, Self::Error> {
        let raw: RawProposedValue = dec(&bytes)?;
        Ok(ProposedValue {
            height: raw.height,
            round: raw.round,
            valid_round: raw.valid_round,
            proposer: raw.proposer,
            value: raw.value,
            validity: if raw.valid { Validity::Valid } else { Validity::Invalid },
        })
    }

    fn encode(&self, msg: &ProposedValue<HkContext>) -> Result<Bytes, Self::Error> {
        enc(&RawProposedValue {
            height: msg.height,
            round: msg.round,
            valid_round: msg.valid_round,
            proposer: msg.proposer,
            value: msg.value.clone(),
            valid: msg.validity == Validity::Valid,
        })
    }
}

// ---------------------------------------------------------------------------
// Sync: Status / Request / Response
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct RawStatus {
    peer_id: PeerId,
    tip_height: HkHeight,
    history_min_height: HkHeight,
}

impl Codec<Status<HkContext>> for HkCodec {
    type Error = JsonError;

    fn decode(&self, bytes: Bytes) -> Result<Status<HkContext>, Self::Error> {
        let raw: RawStatus = dec(&bytes)?;
        Ok(Status {
            peer_id: raw.peer_id,
            tip_height: raw.tip_height,
            history_min_height: raw.history_min_height,
        })
    }

    fn encode(&self, msg: &Status<HkContext>) -> Result<Bytes, Self::Error> {
        enc(&RawStatus {
            peer_id: msg.peer_id,
            tip_height: msg.tip_height,
            history_min_height: msg.history_min_height,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct RawValueRequest {
    start: HkHeight,
    end: HkHeight,
}

impl Codec<Request<HkContext>> for HkCodec {
    type Error = JsonError;

    fn decode(&self, bytes: Bytes) -> Result<Request<HkContext>, Self::Error> {
        let raw: RawValueRequest = dec(&bytes)?;
        Ok(Request::ValueRequest(ValueRequest { range: raw.start..=raw.end }))
    }

    fn encode(&self, msg: &Request<HkContext>) -> Result<Bytes, Self::Error> {
        match msg {
            Request::ValueRequest(r) => enc(&RawValueRequest {
                start: *r.range.start(),
                end: *r.range.end(),
            }),
        }
    }
}

// pub(crate): the block store (P3.0/WS-B) persists commit certificates in exactly the
// DTO the sync codec puts on the wire — one encoding, one truth.
#[derive(Serialize, Deserialize)]
pub(crate) struct RawCommitSignature {
    pub(crate) address: HkAddress,
    pub(crate) signature: RawSig,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct RawCommitCertificate {
    pub(crate) height: HkHeight,
    pub(crate) round: Round,
    pub(crate) value_id: HkValueId,
    pub(crate) commit_signatures: Vec<RawCommitSignature>,
}

impl From<&CommitCertificate<HkContext>> for RawCommitCertificate {
    fn from(c: &CommitCertificate<HkContext>) -> Self {
        Self {
            height: c.height,
            round: c.round,
            value_id: c.value_id,
            commit_signatures: c
                .commit_signatures
                .iter()
                .map(|s| RawCommitSignature {
                    address: s.address,
                    signature: s.signature.0.clone(),
                })
                .collect(),
        }
    }
}

impl From<RawCommitCertificate> for CommitCertificate<HkContext> {
    fn from(c: RawCommitCertificate) -> Self {
        CommitCertificate {
            height: c.height,
            round: c.round,
            value_id: c.value_id,
            commit_signatures: c
                .commit_signatures
                .into_iter()
                .map(|s| CommitSignature {
                    address: s.address,
                    signature: s.signature.into(),
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct RawSyncedValue {
    value_bytes: Bytes,
    certificate: RawCommitCertificate,
}

#[derive(Serialize, Deserialize)]
struct RawValueResponse {
    start_height: HkHeight,
    values: Vec<RawSyncedValue>,
}

impl Codec<Response<HkContext>> for HkCodec {
    type Error = JsonError;

    fn decode(&self, bytes: Bytes) -> Result<Response<HkContext>, Self::Error> {
        let raw: RawValueResponse = dec(&bytes)?;
        Ok(Response::ValueResponse(ValueResponse {
            start_height: raw.start_height,
            values: raw
                .values
                .into_iter()
                .map(|v| RawDecidedValue {
                    value_bytes: v.value_bytes,
                    certificate: v.certificate.into(),
                })
                .collect(),
        }))
    }

    fn encode(&self, msg: &Response<HkContext>) -> Result<Bytes, Self::Error> {
        match msg {
            Response::ValueResponse(r) => enc(&RawValueResponse {
                start_height: r.start_height,
                values: r
                    .values
                    .iter()
                    .map(|v| RawSyncedValue {
                        value_bytes: v.value_bytes.clone(),
                        certificate: RawCommitCertificate::from(&v.certificate),
                    })
                    .collect(),
            }),
        }
    }
}

impl HasEncodedLen<Response<HkContext>> for HkCodec {
    fn encoded_len(&self, msg: &Response<HkContext>) -> Result<usize, JsonError> {
        self.encode(msg).map(|b| b.len())
    }
}
