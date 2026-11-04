//! Proposal-part stream reassembly — adapted from the engine example's streaming.rs.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashSet};

use bytes::Bytes;
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

/// v0.19.10: the most bytes a reassembled proposal may carry — the pubsub frame cap of the
/// fleet's config template (32 MiB); an honest proposal is one frame, so one tx-batch part.
/// Until v0.19.10 a stream concatenated any number of parts of any size for ANY height and the
/// host kept the result until the chain passed that height: a keyless memory lever.
pub const MAX_PROPOSAL_BYTES: usize = 32 * 1024 * 1024;

/// v0.19.10: at most this many INCOMPLETE part streams are kept, in arrival order; the oldest
/// is evicted first. Honest traffic has one or two in flight (one proposer per round).
pub const MAX_INCOMPLETE_STREAMS: usize = 8;

/// v0.19.10: a reassembled proposal is accepted only for `current height ..= current height +
/// this` (the engine's `BUFFER_HEIGHT_WINDOW`): a node further behind decides by certificate.
pub const PROPOSAL_HEIGHT_WINDOW: u64 = 4;

#[derive(Default)]
struct StreamState {
    buffer: BinaryHeap<MinSeq>,
    init_info: Option<HkProposalInit>,
    seen_sequences: HashSet<Sequence>,
    total_messages: usize,
    fin_received: bool,
    /// v0.19.10: tx-batch bytes received so far (the stream is dropped past `MAX_PROPOSAL_BYTES`).
    bytes: usize,
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

        if let Some(data) = msg.content.as_data().and_then(|p| p.as_tx_batch()) {
            self.bytes = self.bytes.saturating_add(data.len());
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

    /// v0.19.10: the reassembled value, or why the stream is refused. An honest stream is
    /// exactly init / one tx-batch / fin / end-of-stream, within the frame cap, and its Fin
    /// names the hash of the bytes it carries. Anything else is a forgery or corruption from
    /// a relay, never the proposer's value — it is DROPPED, never handed on as "invalid"
    /// (until v0.19.10 a mismatching Fin produced a `Validity::Invalid` value that could stick
    /// to the honest value's id in the engine's keeper and make the node refuse the real
    /// proposal: a keyless poisoning the v0.19.10 review traced to an engine assert).
    pub fn reassembled(&self) -> Result<hk_consensus::HkValue, &'static str> {
        let mut batches = self.parts.iter().filter_map(|p| p.as_tx_batch());
        let Some(data) = batches.next() else {
            return Err("no tx-batch part");
        };
        if batches.next().is_some() {
            return Err("more than one tx-batch part");
        }
        if data.len() > MAX_PROPOSAL_BYTES {
            return Err("over the proposal byte cap");
        }
        let value = hk_consensus::HkValue::new(Bytes::copy_from_slice(data));
        match self.fin() {
            Some(fin) if fin.value_id == value.id => Ok(value),
            Some(_) => Err("Fin value-id mismatch"),
            None => Err("no Fin"),
        }
    }
}

#[derive(Default)]
pub struct PartStreamsMap {
    streams: BTreeMap<(PeerId, StreamId), StreamState>,
    /// v0.19.10: arrival order of the incomplete streams, for eviction.
    order: std::collections::VecDeque<(PeerId, StreamId)>,
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
        let key = (peer_id, stream_id.clone());
        if !self.streams.contains_key(&key) {
            // v0.19.10: a new incomplete stream; evict the oldest past the cap.
            while self.streams.len() >= MAX_INCOMPLETE_STREAMS {
                match self.order.pop_front() {
                    Some(oldest) => {
                        self.streams.remove(&oldest);
                    }
                    None => break,
                }
            }
            self.order.push_back(key.clone());
        }
        let state = self.streams.entry(key.clone()).or_default();

        if !state.seen_sequences.insert(msg.sequence) {
            return None;
        }

        let result = state.insert(msg);

        // v0.19.10: a stream past the byte cap can never be an honest proposal — drop it whole.
        let over_cap = state.bytes > MAX_PROPOSAL_BYTES;

        // `StreamState::insert` returns `Some` exactly once, on completion — and completion
        // takes `init_info` and drains the buffer, so `is_done()` is false right after it (the
        // upstream example's shape: a completed stream's husk stayed in the map for ever — in
        // v0.19.9 an unbounded leak, since v0.19.10 a slot the cap would have to evict). Remove
        // the stream the moment it completes.
        let done = result.is_some();

        if done || over_cap {
            self.streams.remove(&key);
            self.order.retain(|k| k != &key);
        }

        if over_cap {
            return None;
        }

        result
    }

    /// v0.19.10: incomplete streams held right now (read by the tests; a metric later).
    #[allow(dead_code)]
    pub fn incomplete(&self) -> usize {
        self.streams.len()
    }
}

/// v0.19.10 (the VZ-2 review, round 2 — ROLL §1.7c): the host-side gate on proposal-part
/// streams. `ProposalParts::reassembled` accepts exactly init / one tx-batch / Fin naming the
/// hash of the bytes, within the 32 MiB frame cap, and refuses everything else (dropped, never
/// handed on as "invalid"); `PartStreamsMap` keeps at most `MAX_INCOMPLETE_STREAMS` incomplete
/// streams (oldest evicted), ignores duplicate sequences, and drops a stream whole once its
/// tx-batch bytes pass `MAX_PROPOSAL_BYTES`. The height / round / proposer / slot checks live in
/// `state.rs::received_proposal_part` (needs a full node state; not tested here).
///
/// Run: `cargo test --offline -p hk-node stream_gate -- --nocapture`
#[cfg(test)]
mod v0_19_10_stream_gate_tests {
    use std::sync::OnceLock;

    use bytes::Bytes;
    use hk_consensus::{HkAddress, HkHeight, HkValue, HkValueId};
    use malachitebft_app_channel::app::streaming::StreamContent;
    use malachitebft_app_channel::app::types::core::Round;

    use super::*;

    const HEIGHT: u64 = 41;

    fn addr(b: u8) -> HkAddress {
        HkAddress::new([b; 20])
    }

    /// A peer id from a tag byte: a sha2-256 multihash (code 0x12, 32 bytes), which
    /// `PeerId::from_multihash` accepts unconditionally (`random()` needs the `rand` feature).
    fn peer(tag: u8) -> PeerId {
        let mut mh = vec![0x12u8, 0x20];
        mh.extend(std::iter::repeat(tag).take(32));
        PeerId::from_bytes(&mh).expect("a sha2-256 multihash is a valid peer id")
    }

    fn sid(tag: u8) -> StreamId {
        StreamId::new(Bytes::from(vec![tag; 16]))
    }

    fn init(proposer: HkAddress) -> HkProposalPart {
        HkProposalPart::Init(HkProposalInit {
            height: HkHeight::new(HEIGHT),
            round: Round::new(0),
            pol_round: Round::Nil,
            proposer,
        })
    }

    fn batch(txs: &[u8]) -> HkProposalPart {
        HkProposalPart::TxBatch(Bytes::copy_from_slice(txs))
    }

    /// The honest Fin: the id of the value the bytes hash to.
    fn fin_for(txs: &Bytes) -> HkProposalPart {
        HkProposalPart::Fin(HkProposalFin { value_id: HkValue::new(txs.clone()).id })
    }

    fn fin_id(id: HkValueId) -> HkProposalPart {
        HkProposalPart::Fin(HkProposalFin { value_id: id })
    }

    /// Reassembled parts as `PartStreamsMap` would hand them to the host.
    fn parts(parts: Vec<HkProposalPart>) -> ProposalParts {
        ProposalParts {
            height: HkHeight::new(HEIGHT),
            round: Round::new(0),
            pol_round: Round::Nil,
            proposer: addr(1),
            parts,
        }
    }

    fn data(id: &StreamId, seq: Sequence, part: HkProposalPart) -> StreamMessage<HkProposalPart> {
        StreamMessage::new(id.clone(), seq, StreamContent::Data(part))
    }

    fn end(id: &StreamId, seq: Sequence) -> StreamMessage<HkProposalPart> {
        StreamMessage::new(id.clone(), seq, StreamContent::Fin)
    }

    /// An honest stream exactly as `state.rs::stream_proposal` builds it: init / tx-batch / fin /
    /// end-of-stream at sequences 0..=3.
    fn honest_stream(id: &StreamId, txs: &[u8]) -> Vec<StreamMessage<HkProposalPart>> {
        let bytes = Bytes::copy_from_slice(txs);
        vec![
            data(id, 0, init(addr(1))),
            data(id, 1, HkProposalPart::TxBatch(bytes.clone())),
            data(id, 2, fin_for(&bytes)),
            end(id, 3),
        ]
    }

    /// `MAX_PROPOSAL_BYTES + 1` zero bytes, built once (it is 32 MiB); slices of it are free.
    fn big() -> Bytes {
        static BIG: OnceLock<Bytes> = OnceLock::new();
        BIG.get_or_init(|| Bytes::from(vec![0u8; MAX_PROPOSAL_BYTES + 1])).clone()
    }

    // ---- constants ---------------------------------------------------------------------------

    /// The gate's numbers are §1.7c's, and the height window is the engine's buffer window.
    #[test]
    fn stream_gate_constants_match_the_design() {
        assert_eq!(MAX_PROPOSAL_BYTES, 32 * 1024 * 1024, "the pubsub frame cap of the fleet template");
        assert_eq!(MAX_INCOMPLETE_STREAMS, 8);
        assert_eq!(PROPOSAL_HEIGHT_WINDOW, 4);
        assert_eq!(
            PROPOSAL_HEIGHT_WINDOW,
            malachitebft_core_consensus::BUFFER_HEIGHT_WINDOW,
            "the host keeps exactly what the engine's buffer would accept"
        );
    }

    // ---- ProposalParts::reassembled ----------------------------------------------------------

    /// An honest stream — one tx-batch and a Fin naming `HkValue::new(bytes).id` — yields the
    /// value with that id and those bytes.
    #[test]
    fn stream_gate_reassembled_accepts_an_honest_stream() {
        let txs = Bytes::from_static(b"a batch of transactions");
        let p = parts(vec![init(addr(1)), HkProposalPart::TxBatch(txs.clone()), fin_for(&txs)]);
        let value = p.reassembled().expect("an honest stream reassembles");
        assert_eq!(value.id, HkValue::new(txs.clone()).id);
        assert_eq!(value.txs, txs);
        assert_eq!(p.fin().map(|f| f.value_id), Some(value.id));
    }

    /// The honest bytes with a Fin naming another id: refused (never an `Invalid` value).
    #[test]
    fn stream_gate_reassembled_refuses_a_fin_naming_another_id() {
        let txs = Bytes::from_static(b"the honest bytes");
        let p = parts(vec![init(addr(1)), HkProposalPart::TxBatch(txs), fin_id(HkValueId::new([0xEE; 32]))]);
        assert_eq!(p.reassembled().err(), Some("Fin value-id mismatch"));
    }

    /// No Fin part at all: refused.
    #[test]
    fn stream_gate_reassembled_refuses_a_missing_fin() {
        let p = parts(vec![init(addr(1)), batch(b"bytes")]);
        assert_eq!(p.reassembled().err(), Some("no Fin"));
    }

    /// Two tx-batch parts: refused, even if the Fin names the first batch.
    #[test]
    fn stream_gate_reassembled_refuses_two_tx_batch_parts() {
        let txs = Bytes::from_static(b"first");
        let p = parts(vec![
            init(addr(1)),
            HkProposalPart::TxBatch(txs.clone()),
            batch(b"second"),
            fin_for(&txs),
        ]);
        assert_eq!(p.reassembled().err(), Some("more than one tx-batch part"));
    }

    /// No tx-batch part: refused.
    #[test]
    fn stream_gate_reassembled_refuses_a_missing_tx_batch() {
        let p = parts(vec![init(addr(1)), fin_for(&Bytes::new())]);
        assert_eq!(p.reassembled().err(), Some("no tx-batch part"));
    }

    /// Exactly `MAX_PROPOSAL_BYTES` passes; one byte more is refused before the Fin is even
    /// looked at (the Fin here names something else, and the cap error still wins).
    #[test]
    fn stream_gate_reassembled_enforces_the_byte_cap() {
        let over = big();
        let exact = over.slice(..MAX_PROPOSAL_BYTES);
        assert_eq!(exact.len(), MAX_PROPOSAL_BYTES);
        assert_eq!(over.len(), MAX_PROPOSAL_BYTES + 1);

        let ok = parts(vec![init(addr(1)), HkProposalPart::TxBatch(exact.clone()), fin_for(&exact)]);
        let value = ok.reassembled().expect("exactly the cap passes");
        assert_eq!(value.txs.len(), MAX_PROPOSAL_BYTES);

        let too_big = parts(vec![init(addr(1)), HkProposalPart::TxBatch(over), fin_id(HkValueId::new([0xEE; 32]))]);
        assert_eq!(too_big.reassembled().err(), Some("over the proposal byte cap"));
    }

    // ---- PartStreamsMap ----------------------------------------------------------------------

    /// A complete honest stream fed in order yields `Some(parts)` exactly once, on the last part,
    /// with the init's fields, and leaves no incomplete stream behind.
    #[test]
    fn stream_gate_map_reassembles_an_honest_stream_once() {
        let mut map = PartStreamsMap::new();
        let id = sid(1);
        let mut results = Vec::new();
        for msg in honest_stream(&id, b"txs") {
            assert_eq!(map.incomplete(), if msg.sequence == 0 { 0 } else { 1 });
            results.push(map.insert(peer(1), msg));
        }
        assert!(results[..3].iter().all(Option::is_none), "nothing before the end-of-stream");
        let parts = results[3].take().expect("the fourth part completes the stream");
        assert_eq!(parts.height, HkHeight::new(HEIGHT));
        assert_eq!(parts.round, Round::new(0));
        assert_eq!(parts.pol_round, Round::Nil);
        assert_eq!(parts.proposer, addr(1));
        assert_eq!(parts.parts.len(), 3, "init, tx-batch, fin (the end-of-stream marker carries no part)");
        let value = parts.reassembled().expect("honest");
        assert_eq!(value.txs, Bytes::from_static(b"txs"));
        assert_eq!(map.incomplete(), 0, "the completed stream is gone");
    }

    /// Arrival order does not matter: reversed and shuffled streams complete exactly once, on
    /// whichever part arrives last.
    #[test]
    fn stream_gate_map_reassembles_in_any_order() {
        for order in [[3usize, 2, 1, 0], [2, 0, 3, 1], [1, 3, 0, 2]] {
            let mut map = PartStreamsMap::new();
            let id = sid(2);
            let msgs = honest_stream(&id, b"any order");
            let mut somes = 0;
            for (i, &k) in order.iter().enumerate() {
                let r = map.insert(peer(2), msgs[k].clone());
                if i < 3 {
                    assert!(r.is_none(), "order {order:?}: completed early at step {i}");
                } else {
                    let parts = r.expect("the last part completes the stream");
                    assert!(parts.reassembled().is_ok());
                    somes += 1;
                }
            }
            assert_eq!(somes, 1, "order {order:?}");
            assert_eq!(map.incomplete(), 0, "order {order:?}");
        }
    }

    /// A duplicate sequence is ignored (`None`), the stream still completes exactly once.
    #[test]
    fn stream_gate_map_ignores_a_duplicate_sequence() {
        let mut map = PartStreamsMap::new();
        let id = sid(3);
        let msgs = honest_stream(&id, b"dup");
        assert!(map.insert(peer(3), msgs[0].clone()).is_none());
        assert!(map.insert(peer(3), msgs[1].clone()).is_none());
        assert!(map.insert(peer(3), msgs[1].clone()).is_none(), "the duplicate is ignored");
        assert!(map.insert(peer(3), msgs[0].clone()).is_none(), "so is a duplicate init");
        assert_eq!(map.incomplete(), 1);
        assert!(map.insert(peer(3), msgs[2].clone()).is_none());
        let parts = map.insert(peer(3), msgs[3].clone()).expect("completes once");
        assert_eq!(parts.parts.len(), 3, "the duplicates left nothing behind");
        assert!(parts.reassembled().is_ok());
        assert_eq!(map.incomplete(), 0);
    }

    /// Nine incomplete streams from nine peers: eight are kept and the FIRST is the one evicted.
    /// The second-oldest (and the newest) still complete; the first can no longer — its init is
    /// gone, so its remaining parts open a fresh init-less entry that never completes.
    #[test]
    fn stream_gate_map_caps_incomplete_streams_per_peer_evicting_the_oldest() {
        let mut map = PartStreamsMap::new();
        let id = sid(4);
        let streams: Vec<Vec<StreamMessage<HkProposalPart>>> =
            (1..=9u8).map(|p| honest_stream(&id, &[p; 8])).collect();
        for (i, s) in streams.iter().enumerate() {
            assert!(map.insert(peer(i as u8 + 1), s[0].clone()).is_none());
            assert_eq!(map.incomplete(), (i + 1).min(MAX_INCOMPLETE_STREAMS));
        }
        assert_eq!(map.incomplete(), MAX_INCOMPLETE_STREAMS);

        // The second-oldest completes.
        assert!(map.insert(peer(2), streams[1][1].clone()).is_none());
        assert!(map.insert(peer(2), streams[1][2].clone()).is_none());
        let p2 = map.insert(peer(2), streams[1][3].clone()).expect("stream 2 survived the cap");
        assert_eq!(p2.reassembled().unwrap().txs, Bytes::from(vec![2u8; 8]));
        assert_eq!(map.incomplete(), MAX_INCOMPLETE_STREAMS - 1);

        // The newest completes.
        assert!(map.insert(peer(9), streams[8][1].clone()).is_none());
        assert!(map.insert(peer(9), streams[8][2].clone()).is_none());
        assert!(map.insert(peer(9), streams[8][3].clone()).is_some(), "stream 9 survived the cap");
        assert_eq!(map.incomplete(), MAX_INCOMPLETE_STREAMS - 2);

        // The first was evicted: nothing completes it.
        assert!(map.insert(peer(1), streams[0][1].clone()).is_none());
        assert!(map.insert(peer(1), streams[0][2].clone()).is_none());
        assert!(map.insert(peer(1), streams[0][3].clone()).is_none(), "stream 1 was evicted: no init, never done");
        assert_eq!(map.incomplete(), MAX_INCOMPLETE_STREAMS - 1, "its late parts opened one init-less entry");
    }

    /// The same cap with nine stream ids from ONE peer: the key is (peer, stream id).
    #[test]
    fn stream_gate_map_caps_incomplete_streams_per_stream_id_evicting_the_oldest() {
        let mut map = PartStreamsMap::new();
        let streams: Vec<Vec<StreamMessage<HkProposalPart>>> =
            (1..=9u8).map(|t| honest_stream(&sid(t), &[t; 4])).collect();
        for s in &streams {
            assert!(map.insert(peer(7), s[0].clone()).is_none());
        }
        assert_eq!(map.incomplete(), MAX_INCOMPLETE_STREAMS);

        for k in 1..=3 {
            let r = map.insert(peer(7), streams[1][k].clone());
            assert_eq!(r.is_some(), k == 3, "the second-oldest completes on its last part");
        }
        assert_eq!(map.incomplete(), MAX_INCOMPLETE_STREAMS - 1);

        for k in 1..=3 {
            assert!(map.insert(peer(7), streams[0][k].clone()).is_none(), "the oldest was evicted");
        }
        assert_eq!(map.incomplete(), MAX_INCOMPLETE_STREAMS);
    }

    /// A stream whose tx-batch parts exceed `MAX_PROPOSAL_BYTES` in total is dropped whole on the
    /// part that crosses the cap: `None`, gone from `incomplete()`, and a later Fin for it yields
    /// nothing (exactly the cap in one part is still an incomplete, live stream).
    #[test]
    fn stream_gate_map_drops_a_stream_whole_past_the_byte_cap() {
        let mut map = PartStreamsMap::new();
        let id = sid(5);
        let exact = big().slice(..MAX_PROPOSAL_BYTES);

        assert!(map.insert(peer(5), data(&id, 0, init(addr(1)))).is_none());
        assert!(map.insert(peer(5), data(&id, 1, HkProposalPart::TxBatch(exact))).is_none());
        assert_eq!(map.incomplete(), 1, "exactly the cap: still a live stream");

        assert!(map.insert(peer(5), data(&id, 2, batch(b"x"))).is_none(), "one byte over: dropped");
        assert_eq!(map.incomplete(), 0, "dropped whole");

        assert!(map.insert(peer(5), data(&id, 3, fin_for(&Bytes::new()))).is_none());
        assert!(map.insert(peer(5), end(&id, 4)).is_none(), "a later Fin yields nothing");
        assert_eq!(map.incomplete(), 1, "the late parts opened one init-less entry, never done");

        // An unrelated honest stream from the same peer still completes.
        let other = sid(6);
        let mut last = None;
        for msg in honest_stream(&other, b"still fine") {
            last = map.insert(peer(5), msg);
        }
        assert!(last.expect("completes").reassembled().is_ok());
    }
}
