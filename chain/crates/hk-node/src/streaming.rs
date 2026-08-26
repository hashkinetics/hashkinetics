//! Proposal-part stream reassembly — adapted from the engine example's streaming.rs.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashSet};

use malachitebft_app_channel::app::streaming::{Sequence, StreamId, StreamMessage};
use malachitebft_app_channel::app::types::PeerId;

use hk_consensus::{HkProposalFin, HkProposalInit, HkProposalPart};

struct MinSeq(StreamMessage<HkProposalPart>);

impl PartialEq for MinSeq {
    fn eq(&self, other: &Self) -> bool {
        self.0.sequence == other.0.sequence
    }
}

impl Eq for MinSeq {}

impl Ord for MinSeq {
    fn cmp(&self, other: &Self) -> Ordering {
        other.0.sequence.cmp(&self.0.sequence)
    }
}

impl PartialOrd for MinSeq {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Default)]
struct StreamState {
    buffer: BinaryHeap<MinSeq>,
    init_info: Option<HkProposalInit>,
    seen_sequences: HashSet<Sequence>,
    total_messages: usize,
    fin_received: bool,
}

impl StreamState {
    fn is_done(&self) -> bool {
        self.init_info.is_some() && self.fin_received && self.buffer.len() == self.total_messages
    }

    fn drain(&mut self) -> Vec<HkProposalPart> {
        let mut vec = Vec::with_capacity(self.buffer.len());
        while let Some(MinSeq(msg)) = self.buffer.pop() {
            if let Some(data) = msg.content.into_data() {
                vec.push(data);
            }
        }
        vec
    }

    fn insert(&mut self, msg: StreamMessage<HkProposalPart>) -> Option<ProposalParts> {
        if msg.is_first() {
            self.init_info = msg.content.as_data().and_then(|p| p.as_init()).cloned();
        }

        if msg.is_fin() {
            self.fin_received = true;
            self.total_messages = msg.sequence as usize + 1;
        }

        self.buffer.push(MinSeq(msg));

        if self.is_done() {
            let init_info = self.init_info.take()?;
            Some(ProposalParts {
                height: init_info.height,
                round: init_info.round,
                pol_round: init_info.pol_round,
                proposer: init_info.proposer,
                parts: self.drain(),
            })
        } else {
            None
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProposalParts {
    pub height: hk_consensus::HkHeight,
    pub round: malachitebft_app_channel::app::types::core::Round,
    pub pol_round: malachitebft_app_channel::app::types::core::Round,
    pub proposer: hk_consensus::HkAddress,
    pub parts: Vec<HkProposalPart>,
}

impl ProposalParts {
    pub fn fin(&self) -> Option<&HkProposalFin> {
        self.parts.iter().find_map(|p| p.as_fin())
    }
}

#[derive(Default)]
pub struct PartStreamsMap {
    streams: BTreeMap<(PeerId, StreamId), StreamState>,
}

impl PartStreamsMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        peer_id: PeerId,
        msg: StreamMessage<HkProposalPart>,
    ) -> Option<ProposalParts> {
        let stream_id = msg.stream_id.clone();
        let state = self.streams.entry((peer_id, stream_id.clone())).or_default();

        if !state.seen_sequences.insert(msg.sequence) {
            return None;
        }

        let result = state.insert(msg);

        if state.is_done() {
            self.streams.remove(&(peer_id, stream_id));
        }

        result
    }
}
