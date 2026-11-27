// Copyright 2020 Sigma Prime Pty Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::{collections::HashMap, convert::Infallible, pin::Pin};

use asynchronous_codec::{Decoder, Encoder, Framed};
use byteorder::{BigEndian, ByteOrder};
use bytes::BytesMut;
use futures::prelude::*;
use libp2p_core::{InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use libp2p_identity::{PeerId, PublicKey};
use libp2p_swarm::StreamProtocol;
use quick_protobuf::{MessageWrite, Writer};

use crate::{
    config::ValidationMode,
    handler::HandlerEvent,
    rpc_proto::proto,
    topic::TopicHash,
    types::{
        ControlAction, Graft, IDontWant, IHave, IWant, LogLimit, MessageId, PeerInfo, PeerKind,
        Prune, RawMessage, Rpc, Subscription, SubscriptionAction,
    },
    ValidationError,
};

pub(crate) const SIGNING_PREFIX: &[u8] = b"libp2p-pubsub:";

// HK v0.19.13: the lengths of a message id and of a topic that are acted on.
//
// An entry of a received frame with a longer topic, and a longer message id in an entry, are
// left out when the frame is turned into events: nothing is counted, stored, requested or
// answered for them. The frame itself is decoded and the rest of it is acted on. The message
// ids of this crate are a peer id and a sequence number (about 72 bytes at most) unless the
// application sets its own, and a topic is a short name.

/// HK v0.19.13: the longest message id that is acted on.
const MAX_MESSAGE_ID_LEN: usize = 128;

/// HK v0.19.13: the longest topic that is acted on.
const MAX_TOPIC_LEN: usize = 256;

/// HK v0.19.13: the topic of an entry when it is short enough to be acted on. An entry with a
/// longer topic is left out and counted in `left_out`.
fn topic_acted_on(topic: Option<String>, left_out: &mut usize) -> Option<TopicHash> {
    let topic = topic.unwrap_or_default();
    if topic.len() > MAX_TOPIC_LEN {
        *left_out += 1;
        return None;
    }
    Some(TopicHash::from_raw(topic))
}

/// HK v0.19.13: the message ids of an entry that are short enough to be acted on. A longer one
/// is left out and counted in `left_out`.
fn message_ids_acted_on(message_ids: Vec<Vec<u8>>, left_out: &mut usize) -> Vec<MessageId> {
    message_ids
        .into_iter()
        .filter(|message_id| {
            let acted_on = message_id.len() <= MAX_MESSAGE_ID_LEN;
            if !acted_on {
                *left_out += 1;
            }
            acted_on
        })
        .map(MessageId::from)
        .collect()
}

pub(crate) const GOSSIPSUB_1_2_0_PROTOCOL: ProtocolId = ProtocolId {
    protocol: StreamProtocol::new("/meshsub/1.2.0"),
    kind: PeerKind::Gossipsubv1_2,
};

pub(crate) const GOSSIPSUB_1_1_0_PROTOCOL: ProtocolId = ProtocolId {
    protocol: StreamProtocol::new("/meshsub/1.1.0"),
    kind: PeerKind::Gossipsubv1_1,
};
pub(crate) const GOSSIPSUB_1_0_0_PROTOCOL: ProtocolId = ProtocolId {
    protocol: StreamProtocol::new("/meshsub/1.0.0"),
    kind: PeerKind::Gossipsub,
};
pub(crate) const FLOODSUB_PROTOCOL: ProtocolId = ProtocolId {
    protocol: StreamProtocol::new("/floodsub/1.0.0"),
    kind: PeerKind::Floodsub,
};

/// Implementation of [`InboundUpgrade`] and [`OutboundUpgrade`] for the Gossipsub protocol.
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    /// The Gossipsub protocol id to listen on.
    pub(crate) protocol_ids: Vec<ProtocolId>,
    /// Determines the level of validation to be done on incoming messages.
    pub(crate) validation_mode: ValidationMode,
    /// The default max transmit size.
    pub(crate) default_max_transmit_size: usize,
    /// The max transmit sizes for a topic.
    pub(crate) max_transmit_sizes: HashMap<TopicHash, usize>,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            validation_mode: ValidationMode::Strict,
            protocol_ids: vec![
                GOSSIPSUB_1_2_0_PROTOCOL,
                GOSSIPSUB_1_1_0_PROTOCOL,
                GOSSIPSUB_1_0_0_PROTOCOL,
            ],
            default_max_transmit_size: 65536,
            max_transmit_sizes: HashMap::new(),
        }
    }
}

impl ProtocolConfig {
    /// Get the max transmit size for a given topic, falling back to the default.
    pub fn max_transmit_size_for_topic(&self, topic: &TopicHash) -> usize {
        self.max_transmit_sizes
            .get(topic)
            .copied()
            .unwrap_or(self.default_max_transmit_size)
    }
}

/// The protocol ID
#[derive(Clone, Debug, PartialEq)]
pub struct ProtocolId {
    /// The RPC message type/name.
    pub protocol: StreamProtocol,
    /// The type of protocol we support
    pub kind: PeerKind,
}

impl AsRef<str> for ProtocolId {
    fn as_ref(&self) -> &str {
        self.protocol.as_ref()
    }
}

impl UpgradeInfo for ProtocolConfig {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.protocol_ids.clone()
    }
}

impl<TSocket> InboundUpgrade<TSocket> for ProtocolConfig
where
    TSocket: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (Framed<TSocket, GossipsubCodec>, PeerKind);
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, socket: TSocket, protocol_id: Self::Info) -> Self::Future {
        Box::pin(future::ok((
            Framed::new(
                socket,
                GossipsubCodec::new(
                    self.default_max_transmit_size,
                    self.validation_mode,
                    self.max_transmit_sizes,
                ),
            ),
            protocol_id.kind,
        )))
    }
}

impl<TSocket> OutboundUpgrade<TSocket> for ProtocolConfig
where
    TSocket: AsyncWrite + AsyncRead + Unpin + Send + 'static,
{
    type Output = (Framed<TSocket, GossipsubCodec>, PeerKind);
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, socket: TSocket, protocol_id: Self::Info) -> Self::Future {
        Box::pin(future::ok((
            Framed::new(
                socket,
                GossipsubCodec::new(
                    self.default_max_transmit_size,
                    self.validation_mode,
                    self.max_transmit_sizes,
                ),
            ),
            protocol_id.kind,
        )))
    }
}

// HK v0.19.13: entry limits of one received frame.
//
// The entries of a frame are counted before the frame is decoded, and a frame above a limit is
// refused before a structure is built for any of its entries. The limits leave room for every
// frame this crate sends: an `RpcOut` becomes a frame with ONE entry of one kind (a published or
// forwarded message, a subscription change, a GRAFT, a PRUNE, an IHAVE, an IWANT or an
// IDONTWANT); an IHAVE or an IWANT lists at most `Config::max_ihave_length` message ids (5,000
// by default), an IDONTWANT lists one, and a PRUNE lists at most `Config::prune_peers` peer
// records (0 by default). `hk_tests::hk_largest_frames_this_crate_sends_are_within_the_limits`
// pins that. A configuration that raises `max_ihave_length` or `prune_peers` above a limit has
// to raise the limit with it.

/// HK v0.19.13: the largest number of entries of one kind in a frame. Subscriptions, published
/// messages and IHAVE, IWANT, GRAFT, PRUNE and IDONTWANT entries are each counted on their own.
const MAX_FRAME_ENTRIES_PER_KIND: usize = 1024;

/// HK v0.19.13: the largest number of message ids in a frame, over all of its IHAVE, IWANT and
/// IDONTWANT entries together.
const MAX_FRAME_MESSAGE_IDS: usize = 16_384;

/// HK v0.19.13: the largest number of peer records in a frame, over all of its PRUNE entries
/// together.
const MAX_FRAME_PRUNE_PEERS: usize = 1024;

/// HK v0.19.13: the entries counted in one frame.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct FrameCounts {
    subscriptions: usize,
    publish: usize,
    ihave: usize,
    iwant: usize,
    graft: usize,
    prune: usize,
    idontwant: usize,
    message_ids: usize,
    prune_peers: usize,
}

impl FrameCounts {
    /// Counts the field `tag` of `message`. Returns false once a count is above its limit.
    fn count(&mut self, message: ScanMessage, tag: u32) -> bool {
        let (counter, limit) = match (message, tag) {
            (ScanMessage::Rpc, 10) => (&mut self.subscriptions, MAX_FRAME_ENTRIES_PER_KIND),
            (ScanMessage::Rpc, 18) => (&mut self.publish, MAX_FRAME_ENTRIES_PER_KIND),
            (ScanMessage::Control, 10) => (&mut self.ihave, MAX_FRAME_ENTRIES_PER_KIND),
            (ScanMessage::Control, 18) => (&mut self.iwant, MAX_FRAME_ENTRIES_PER_KIND),
            (ScanMessage::Control, 26) => (&mut self.graft, MAX_FRAME_ENTRIES_PER_KIND),
            (ScanMessage::Control, 34) => (&mut self.prune, MAX_FRAME_ENTRIES_PER_KIND),
            (ScanMessage::Control, 42) => (&mut self.idontwant, MAX_FRAME_ENTRIES_PER_KIND),
            (ScanMessage::IHave, 18) | (ScanMessage::IWant, 10) | (ScanMessage::IDontWant, 10) => {
                (&mut self.message_ids, MAX_FRAME_MESSAGE_IDS)
            }
            (ScanMessage::Prune, 18) => (&mut self.prune_peers, MAX_FRAME_PRUNE_PEERS),
            _ => return true,
        };
        *counter += 1;
        *counter <= limit
    }
}

/// HK v0.19.13: the messages of a frame, named after their generated readers.
#[derive(Debug, Clone, Copy)]
enum ScanMessage {
    Rpc,
    SubOpts,
    Message,
    Control,
    IHave,
    IWant,
    Graft,
    Prune,
    IDontWant,
    PeerInfo,
}

/// HK v0.19.13: a length-delimited field that the generated reader of a message reads itself.
enum KnownField {
    /// A nested message.
    Nested(ScanMessage),
    /// Bytes or a string.
    Bytes,
}

impl ScanMessage {
    /// The length-delimited fields that the generated reader of this message reads itself, by
    /// tag. The reader skips every other field by its wire type.
    fn known_field(self, tag: u32) -> Option<KnownField> {
        match (self, tag) {
            (Self::Rpc, 10) => Some(KnownField::Nested(Self::SubOpts)),
            (Self::Rpc, 18) => Some(KnownField::Nested(Self::Message)),
            (Self::Rpc, 26) => Some(KnownField::Nested(Self::Control)),
            (Self::SubOpts, 18) => Some(KnownField::Bytes),
            (Self::Message, 10 | 18 | 26 | 34 | 42 | 50) => Some(KnownField::Bytes),
            (Self::Control, 10) => Some(KnownField::Nested(Self::IHave)),
            (Self::Control, 18) => Some(KnownField::Nested(Self::IWant)),
            (Self::Control, 26) => Some(KnownField::Nested(Self::Graft)),
            (Self::Control, 34) => Some(KnownField::Nested(Self::Prune)),
            (Self::Control, 42) => Some(KnownField::Nested(Self::IDontWant)),
            (Self::IHave, 10 | 18) => Some(KnownField::Bytes),
            (Self::IWant | Self::Graft | Self::IDontWant, 10) => Some(KnownField::Bytes),
            (Self::Prune, 10) => Some(KnownField::Bytes),
            (Self::Prune, 18) => Some(KnownField::Nested(Self::PeerInfo)),
            (Self::PeerInfo, 10 | 18) => Some(KnownField::Bytes),
            _ => None,
        }
    }
}

/// HK v0.19.13: a varint as the protobuf reader reads it.
enum Varint {
    /// The value. Bits above the 64th are dropped, as the reader drops them.
    Value(u64),
    /// The bytes ended before the varint did.
    Short,
    /// Ten bytes without an end: the reader refuses it.
    Endless,
}

/// HK v0.19.13: reads the varint at `pos` of `buf` and moves `pos` behind the bytes it read.
fn read_varint(buf: &[u8], pos: &mut usize) -> Varint {
    let mut value = 0u64;
    for index in 0..10u32 {
        let Some(&byte) = buf.get(*pos) else {
            return Varint::Short;
        };
        *pos += 1;
        value |= u64::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Varint::Value(value);
        }
    }
    Varint::Endless
}

/// HK v0.19.13: why the count of a frame stopped before the end of the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanStop {
    /// A count is above its limit.
    OverLimit,
    /// A malformed field.
    PastEnd,
    /// The frame has a field that the protobuf reader refuses when it reaches that field: the
    /// reader decides about the frame.
    LeftToDecoder,
}

/// HK v0.19.13: walks the fields of `message`, whose bytes are exactly `buf`, the way its
/// generated reader walks them, and counts the entries without building any of them.
///
/// `Ok` means that every field of the message, and of the messages inside it, ends inside the
/// message that holds it and that every count is within its limit.
///
fn scan_message(
    buf: &[u8],
    message: ScanMessage,
    counts: &mut FrameCounts,
) -> Result<(), ScanStop> {
    // HK v0.19.13
    //
    let cut_short = match message {
        ScanMessage::Rpc => ScanStop::LeftToDecoder,
        _ => ScanStop::PastEnd,
    };

    let mut pos = 0;
    while pos < buf.len() {
        let tag = match read_varint(buf, &mut pos) {
            // The reader keeps the low 32 bits of a tag.
            Varint::Value(tag) => tag as u32,
            Varint::Short => return Err(cut_short),
            Varint::Endless => return Err(ScanStop::LeftToDecoder),
        };

        if let Some(field) = message.known_field(tag) {
            let len = match read_varint(buf, &mut pos) {
                // The reader keeps the low 32 bits of the length of a field it reads itself.
                Varint::Value(len) => len as u32 as usize,
                Varint::Short => return Err(cut_short),
                Varint::Endless => return Err(ScanStop::LeftToDecoder),
            };
            if len > buf.len() - pos {
                return Err(ScanStop::PastEnd);
            }
            if !counts.count(message, tag) {
                return Err(ScanStop::OverLimit);
            }
            if let KnownField::Nested(nested) = field {
                scan_message(&buf[pos..pos + len], nested, counts)?;
            }
            pos += len;
            continue;
        }

        // The reader skips any other field by its wire type.
        let skip = match tag & 0x7 {
            // A varint.
            0 => match read_varint(buf, &mut pos) {
                Varint::Value(_) => 0,
                Varint::Short => return Err(cut_short),
                Varint::Endless => return Err(ScanStop::LeftToDecoder),
            },
            // 64 bits.
            1 => 8,
            // A length and that many bytes.
            2 => match read_varint(buf, &mut pos) {
                Varint::Value(len) => match usize::try_from(len) {
                    Ok(len) => len,
                    Err(_) => return Err(ScanStop::LeftToDecoder),
                },
                Varint::Short => return Err(cut_short),
                Varint::Endless => return Err(ScanStop::LeftToDecoder),
            },
            // 32 bits.
            5 => 4,
            // Groups and unassigned wire types.
            _ => return Err(ScanStop::LeftToDecoder),
        };
        if skip > buf.len() - pos {
            return Err(ScanStop::LeftToDecoder);
        }
        pos += skip;
    }
    Ok(())
}

/// HK v0.19.13: the length prefix of the first frame in `src`, read the way the inner codec reads
/// it: the number of bytes of the prefix and the number of bytes of the frame behind it. `None`
/// when the prefix is not whole yet or the inner codec refuses it.
fn peek_frame_length(src: &[u8]) -> Option<(usize, usize)> {
    // The most bytes the inner codec reads for a length of the width of `usize`.
    const MAX_PREFIX_BYTES: usize = (usize::BITS as usize).div_ceil(7);

    let mut frame_len = 0usize;
    for (index, &byte) in src.iter().enumerate().take(MAX_PREFIX_BYTES) {
        frame_len |= usize::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            // The inner codec refuses a prefix of several bytes that ends in a zero byte.
            if byte == 0 && index > 0 {
                return None;
            }
            return Some((index + 1, frame_len));
        }
    }
    None
}

// Gossip codec for the framing

pub struct GossipsubCodec {
    /// Determines the level of validation performed on incoming messages.
    validation_mode: ValidationMode,
    /// The codec to handle common encoding/decoding of protobuf messages
    codec: quick_protobuf_codec::Codec<proto::RPC>,
    /// Maximum transmit sizes per topic, with a default if not specified.
    max_transmit_sizes: HashMap<TopicHash, usize>,
    /// HK v0.19.13: the largest frame `codec` accepts. A longer frame is left to `codec`, which
    /// refuses it.
    max_frame_len: usize,
}

impl GossipsubCodec {
    pub fn new(
        max_length: usize,
        validation_mode: ValidationMode,
        max_transmit_sizes: HashMap<TopicHash, usize>,
    ) -> GossipsubCodec {
        let codec = quick_protobuf_codec::Codec::new(max_length);
        GossipsubCodec {
            validation_mode,
            codec,
            max_transmit_sizes,
            max_frame_len: max_length,
        }
    }

    /// Get the max transmit size for a given topic if it exists.
    fn max_transmit_size_for_topic(&self, topic: &TopicHash) -> Option<usize> {
        self.max_transmit_sizes.get(topic).copied()
    }

    /// Verifies a gossipsub message. This returns either a success or failure. All errors
    /// are logged, which prevents error handling in the codec and handler. We simply drop invalid
    /// messages and log warnings, rather than propagating errors through the codec.
    fn verify_signature(message: &proto::Message) -> bool {
        use quick_protobuf::MessageWrite;

        let Some(from) = message.from.as_ref() else {
            tracing::debug!("Signature verification failed: No source id given");
            return false;
        };

        let Ok(source) = PeerId::from_bytes(from) else {
            tracing::debug!("Signature verification failed: Invalid Peer Id");
            return false;
        };

        let Some(signature) = message.signature.as_ref() else {
            tracing::debug!("Signature verification failed: No signature provided");
            return false;
        };

        // If there is a key value in the protobuf, use that key otherwise the key must be
        // obtained from the inlined source peer_id.
        let public_key = match message.key.as_deref().map(PublicKey::try_decode_protobuf) {
            Some(Ok(key)) => key,
            _ => match PublicKey::try_decode_protobuf(&source.to_bytes()[2..]) {
                Ok(v) => v,
                Err(_) => {
                    // HK v0.19.13: logged at debug level; `decode` reports the frame once.
                    tracing::debug!("Signature verification failed: No valid public key supplied");
                    return false;
                }
            },
        };

        // The key must match the peer_id
        if source != public_key.to_peer_id() {
            // HK v0.19.13: logged at debug level; `decode` reports the frame once.
            tracing::debug!(
                "Signature verification failed: Public key doesn't match source peer id"
            );
            return false;
        }

        // Construct the signature bytes
        let mut message_sig = message.clone();
        message_sig.signature = None;
        message_sig.key = None;
        let mut buf = Vec::with_capacity(message_sig.get_size());
        let mut writer = Writer::new(&mut buf);
        message_sig
            .write_message(&mut writer)
            .expect("Encoding to succeed");
        let mut signature_bytes = SIGNING_PREFIX.to_vec();
        signature_bytes.extend_from_slice(&buf);
        public_key.verify(&signature_bytes, signature)
    }
}

impl Encoder for GossipsubCodec {
    type Item<'a> = proto::RPC;
    type Error = quick_protobuf_codec::Error;

    fn encode(&mut self, item: Self::Item<'_>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.codec.encode(item, dst)
    }
}

impl Decoder for GossipsubCodec {
    type Item = HandlerEvent;
    type Error = quick_protobuf_codec::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // HK v0.19.13: once a whole frame is buffered, its entries are counted before it is
        // decoded. A frame above an entry limit, or with a malformed field, is taken off the
        // buffer and refused. Every other frame reaches the decoder untouched.
        if let Some((prefix_len, frame_len)) = peek_frame_length(&src[..]) {
            if frame_len <= self.max_frame_len && src.len() - prefix_len >= frame_len {
                let mut counts = FrameCounts::default();
                let refusal = match scan_message(
                    &src[prefix_len..prefix_len + frame_len],
                    ScanMessage::Rpc,
                    &mut counts,
                ) {
                    Ok(()) | Err(ScanStop::LeftToDecoder) => None,
                    Err(ScanStop::OverLimit) => Some("more entries than a frame may carry"),
                    Err(ScanStop::PastEnd) => Some("a malformed field"),
                };
                if let Some(reason) = refusal {
                    // HK v0.19.13: the line is written at most once per interval and carries the
                    // number of refused frames it was held back for.
                    static REFUSED_FRAME: LogLimit = LogLimit::new();
                    if let Some(held_back) = REFUSED_FRAME.admit() {
                        tracing::warn!(
                            held_back,
                            frame_bytes = frame_len,
                            subscriptions = counts.subscriptions,
                            publish = counts.publish,
                            ihave = counts.ihave,
                            iwant = counts.iwant,
                            graft = counts.graft,
                            prune = counts.prune,
                            idontwant = counts.idontwant,
                            message_ids = counts.message_ids,
                            prune_peers = counts.prune_peers,
                            "Refusing a received frame before decoding it: {reason}"
                        );
                    }
                    let _ = src.split_to(prefix_len + frame_len);
                    return Err(quick_protobuf_codec::Error::from(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        reason,
                    )));
                }
            }
        }

        let Some(rpc) = self.codec.decode(src)? else {
            return Ok(None);
        };
        // Store valid messages.
        let mut messages = Vec::with_capacity(rpc.publish.len());
        // Store any invalid messages.
        let mut invalid_messages = Vec::new();
        // HK v0.19.13: the messages of this frame that failed the signature or the anonymity
        // check. Each is logged at debug level; the frame is reported once, with their number.
        let mut failed_checks = 0usize;

        for message in rpc.publish.into_iter() {
            let topic = TopicHash::from_raw(&message.topic);

            // Check the message size to ensure it doesn't bypass the configured max.
            if self
                .max_transmit_size_for_topic(&topic)
                .is_some_and(|max| message.get_size() > max)
            {
                let message = RawMessage {
                    source: None, // don't bother inform the application
                    data: message.data.unwrap_or_default(),
                    sequence_number: None, // don't inform the application
                    topic: TopicHash::from_raw(message.topic),
                    signature: None, // don't inform the application
                    key: message.key,
                    validated: false,
                };

                invalid_messages.push((message, ValidationError::MessageSizeTooLargeForTopic));
                continue;
            }

            // Keep track of the type of invalid message.
            let mut invalid_kind = None;
            let mut verify_signature = false;
            let mut verify_sequence_no = false;
            let mut verify_source = false;

            match self.validation_mode {
                ValidationMode::Strict => {
                    // Validate everything
                    verify_signature = true;
                    verify_sequence_no = true;
                    verify_source = true;
                }
                ValidationMode::Permissive => {
                    // If the fields exist, validate them
                    if message.signature.is_some() {
                        verify_signature = true;
                    }
                    if message.seqno.is_some() {
                        verify_sequence_no = true;
                    }
                    if message.from.is_some() {
                        verify_source = true;
                    }
                }
                ValidationMode::Anonymous => {
                    // HK v0.19.13: logged at debug level and counted for the one warning of
                    // the frame.
                    if message.signature.is_some() {
                        tracing::debug!(
                            "Signature field was non-empty and anonymous validation mode is set"
                        );
                        invalid_kind = Some(ValidationError::SignaturePresent);
                    } else if message.seqno.is_some() {
                        tracing::debug!(
                            "Sequence number was non-empty and anonymous validation mode is set"
                        );
                        invalid_kind = Some(ValidationError::SequenceNumberPresent);
                    } else if message.from.is_some() {
                        tracing::debug!("Message dropped. Message source was non-empty and anonymous validation mode is set");
                        invalid_kind = Some(ValidationError::MessageSourcePresent);
                    }
                    if invalid_kind.is_some() {
                        failed_checks += 1;
                    }
                }
                ValidationMode::None => {}
            }

            // If the initial validation logic failed, add the message to invalid messages and
            // continue processing the others.
            if let Some(validation_error) = invalid_kind.take() {
                let message = RawMessage {
                    source: None, // don't bother inform the application
                    data: message.data.unwrap_or_default(),
                    sequence_number: None, // don't inform the application
                    topic: TopicHash::from_raw(message.topic),
                    signature: None, // don't inform the application
                    key: message.key,
                    validated: false,
                };
                invalid_messages.push((message, validation_error));
                // proceed to the next message
                continue;
            }

            // verify message signatures if required
            if verify_signature && !GossipsubCodec::verify_signature(&message) {
                // HK v0.19.13: logged at debug level and counted for the one warning of the
                // frame.
                tracing::debug!("Invalid signature for received message");
                failed_checks += 1;
                // Build the invalid message (ignoring further validation of sequence number
                // and source)
                let message = RawMessage {
                    source: None, // don't bother inform the application
                    data: message.data.unwrap_or_default(),
                    sequence_number: None, // don't inform the application
                    topic: TopicHash::from_raw(message.topic),
                    signature: None, // don't inform the application
                    key: message.key,
                    validated: false,
                };
                invalid_messages.push((message, ValidationError::InvalidSignature));
                // proceed to the next message
                continue;
            }

            // ensure the sequence number is a u64
            let sequence_number = if verify_sequence_no {
                if let Some(seq_no) = message.seqno {
                    if seq_no.is_empty() {
                        None
                    } else if seq_no.len() != 8 {
                        tracing::debug!(
                            sequence_number=?seq_no,
                            sequence_length=%seq_no.len(),
                            "Invalid sequence number length for received message"
                        );

                        let message = RawMessage {
                            source: None, // don't bother inform the application
                            data: message.data.unwrap_or_default(),
                            sequence_number: None, // don't inform the application
                            topic: TopicHash::from_raw(message.topic),
                            signature: message.signature, // don't inform the application
                            key: message.key,
                            validated: false,
                        };
                        invalid_messages.push((message, ValidationError::InvalidSequenceNumber));
                        // proceed to the next message
                        continue;
                    } else {
                        // valid sequence number
                        Some(BigEndian::read_u64(&seq_no))
                    }
                } else {
                    // sequence number was not present
                    tracing::debug!("Sequence number not present but expected");
                    let message = RawMessage {
                        source: None, // don't bother inform the application
                        data: message.data.unwrap_or_default(),
                        sequence_number: None, // don't inform the application
                        topic: TopicHash::from_raw(message.topic),
                        signature: message.signature, // don't inform the application
                        key: message.key,
                        validated: false,
                    };
                    invalid_messages.push((message, ValidationError::EmptySequenceNumber));
                    continue;
                }
            } else {
                // Do not verify the sequence number, consider it empty
                None
            };

            // Verify the message source if required
            let source = if verify_source {
                if let Some(bytes) = message.from {
                    if !bytes.is_empty() {
                        match PeerId::from_bytes(&bytes) {
                            Ok(peer_id) => Some(peer_id), // valid peer id
                            Err(_) => {
                                // invalid peer id, add to invalid messages
                                tracing::debug!("Message source has an invalid PeerId");
                                let message = RawMessage {
                                    source: None, // don't bother inform the application
                                    data: message.data.unwrap_or_default(),
                                    sequence_number,
                                    topic: TopicHash::from_raw(message.topic),
                                    signature: message.signature, // don't inform the application
                                    key: message.key,
                                    validated: false,
                                };
                                invalid_messages.push((message, ValidationError::InvalidPeerId));
                                continue;
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // This message has passed all validation, add it to the validated messages.
            messages.push(RawMessage {
                source,
                data: message.data.unwrap_or_default(),
                sequence_number,
                topic: TopicHash::from_raw(message.topic),
                signature: message.signature,
                key: message.key,
                validated: false,
            });
        }

        // HK v0.19.13: the messages of a frame that failed the signature or the anonymity check
        // are reported with their number, at most once per interval.
        if failed_checks > 0 {
            static FAILED_CHECKS: LogLimit = LogLimit::new();
            if let Some(held_back) = FAILED_CHECKS.admit() {
                tracing::warn!(
                    messages = failed_checks,
                    held_back,
                    "Messages of a received frame failed the signature or the anonymity check"
                );
            }
        }

        // HK v0.19.13: the entries with a topic longer than `MAX_TOPIC_LEN` and the message ids
        // longer than `MAX_MESSAGE_ID_LEN` that are left out of this frame.
        let mut left_out = 0usize;

        let mut control_msgs = Vec::new();

        if let Some(rpc_control) = rpc.control {
            // Collect the gossipsub control messages
            // HK v0.19.13: an entry with a topic longer than `MAX_TOPIC_LEN` is left out, and so
            // is a message id longer than `MAX_MESSAGE_ID_LEN`.
            let ihave_msgs: Vec<ControlAction> = rpc_control
                .ihave
                .into_iter()
                .filter_map(|ihave| {
                    let topic_hash = topic_acted_on(ihave.topic_id, &mut left_out)?;
                    Some(ControlAction::IHave(IHave {
                        topic_hash,
                        message_ids: message_ids_acted_on(ihave.message_ids, &mut left_out),
                    }))
                })
                .collect();

            // HK v0.19.13: a message id longer than `MAX_MESSAGE_ID_LEN` is left out.
            let iwant_msgs: Vec<ControlAction> = rpc_control
                .iwant
                .into_iter()
                .map(|iwant| {
                    ControlAction::IWant(IWant {
                        message_ids: message_ids_acted_on(iwant.message_ids, &mut left_out),
                    })
                })
                .collect();

            // HK v0.19.13: an entry with a topic longer than `MAX_TOPIC_LEN` is left out.
            let graft_msgs: Vec<ControlAction> = rpc_control
                .graft
                .into_iter()
                .filter_map(|graft| {
                    let topic_hash = topic_acted_on(graft.topic_id, &mut left_out)?;
                    Some(ControlAction::Graft(Graft { topic_hash }))
                })
                .collect();

            let mut prune_msgs = Vec::new();

            for prune in rpc_control.prune {
                // HK v0.19.13: a PRUNE entry with a topic longer than `MAX_TOPIC_LEN` is left
                // out.
                if prune
                    .topic_id
                    .as_ref()
                    .is_some_and(|topic| topic.len() > MAX_TOPIC_LEN)
                {
                    left_out += 1;
                    continue;
                }

                // filter out invalid peers
                let peers = prune
                    .peers
                    .into_iter()
                    .filter_map(|info| {
                        info.peer_id
                            .as_ref()
                            .and_then(|id| PeerId::from_bytes(id).ok())
                            .map(|peer_id|
                                    //TODO signedPeerRecord, see https://github.com/libp2p/specs/pull/217
                                    PeerInfo {
                                        peer_id: Some(peer_id),
                                    })
                    })
                    .collect::<Vec<PeerInfo>>();

                let topic_hash = TopicHash::from_raw(prune.topic_id.unwrap_or_default());
                prune_msgs.push(ControlAction::Prune(Prune {
                    topic_hash,
                    peers,
                    backoff: prune.backoff,
                }));
            }

            // HK v0.19.13: a message id longer than `MAX_MESSAGE_ID_LEN` is left out.
            let idontwant_msgs: Vec<ControlAction> = rpc_control
                .idontwant
                .into_iter()
                .map(|idontwant| {
                    ControlAction::IDontWant(IDontWant {
                        message_ids: message_ids_acted_on(idontwant.message_ids, &mut left_out),
                    })
                })
                .collect();

            control_msgs.extend(ihave_msgs);
            control_msgs.extend(iwant_msgs);
            control_msgs.extend(graft_msgs);
            control_msgs.extend(prune_msgs);
            control_msgs.extend(idontwant_msgs);
        }

        // HK v0.19.13: an entry with a topic longer than `MAX_TOPIC_LEN` is left out.
        let subscriptions: Vec<Subscription> = rpc
            .subscriptions
            .into_iter()
            .filter_map(|sub| {
                let topic_hash = topic_acted_on(sub.topic_id, &mut left_out)?;
                Some(Subscription {
                    action: if Some(true) == sub.subscribe {
                        SubscriptionAction::Subscribe
                    } else {
                        SubscriptionAction::Unsubscribe
                    },
                    topic_hash,
                })
            })
            .collect();

        // HK v0.19.13: one line per frame, at debug level, with the number left out.
        if left_out > 0 {
            tracing::debug!(
                left_out,
                "Entries or message ids of a received frame were left out for their length"
            );
        }

        Ok(Some(HandlerEvent::Message {
            rpc: Rpc {
                messages,
                subscriptions,
                control_msgs,
            },
            invalid_messages,
        }))
    }
}

#[cfg(test)]
mod tests {
    use libp2p_identity::Keypair;
    use quickcheck::*;

    use super::*;
    use crate::{
        config::Config, Behaviour, ConfigBuilder, IdentTopic as Topic, MessageAuthenticity, Version,
    };

    #[derive(Clone, Debug)]
    struct Message(RawMessage);

    impl Arbitrary for Message {
        fn arbitrary(g: &mut Gen) -> Self {
            let keypair = TestKeypair::arbitrary(g);

            // generate an arbitrary GossipsubMessage using the behaviour signing functionality
            let config = Config::default();
            let mut gs: Behaviour =
                Behaviour::new(MessageAuthenticity::Signed(keypair.0), config).unwrap();
            let mut data_g = quickcheck::Gen::new(10024);
            let data = (0..u8::arbitrary(&mut data_g))
                .map(|_| u8::arbitrary(g))
                .collect::<Vec<_>>();
            let topic_id = TopicId::arbitrary(g).0;
            Message(gs.build_raw_message(topic_id, data).unwrap())
        }
    }

    #[derive(Clone, Debug)]
    struct TopicId(TopicHash);

    impl Arbitrary for TopicId {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut data_g = quickcheck::Gen::new(1024);
            let topic_string: String = (0..u8::arbitrary(&mut data_g))
                .map(|_| char::arbitrary(g))
                .collect::<String>();
            TopicId(Topic::new(topic_string).into())
        }
    }

    #[derive(Clone)]
    struct TestKeypair(Keypair);

    impl Arbitrary for TestKeypair {
        fn arbitrary(_g: &mut Gen) -> Self {
            // Small enough to be inlined.
            TestKeypair(Keypair::generate_ed25519())
        }
    }

    impl std::fmt::Debug for TestKeypair {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TestKeypair")
                .field("public", &self.0.public())
                .finish()
        }
    }

    #[test]
    /// Test that RPC messages can be encoded and decoded successfully.
    fn encode_decode() {
        fn prop(message: Message) {
            let message = message.0;

            let rpc = Rpc {
                messages: vec![message.clone()],
                subscriptions: vec![],
                control_msgs: vec![],
            };

            let mut codec =
                GossipsubCodec::new(u32::MAX as usize, ValidationMode::Strict, HashMap::new());
            let mut buf = BytesMut::new();
            codec.encode(rpc.into_protobuf(), &mut buf).unwrap();
            let decoded_rpc = codec.decode(&mut buf).unwrap().unwrap();
            // mark as validated as its a published message
            match decoded_rpc {
                HandlerEvent::Message { mut rpc, .. } => {
                    rpc.messages[0].validated = true;

                    assert_eq!(vec![message], rpc.messages);
                }
                _ => panic!("Must decode a message"),
            }
        }

        QuickCheck::new().quickcheck(prop as fn(_) -> _)
    }

    #[test]
    fn support_floodsub_with_custom_protocol() {
        let protocol_config = ConfigBuilder::default()
            .protocol_id("/foosub", Version::V1_1)
            .support_floodsub()
            .build()
            .unwrap()
            .protocol_config();

        assert_eq!(protocol_config.protocol_ids[0].protocol, "/foosub");
        assert_eq!(protocol_config.protocol_ids[1].protocol, "/floodsub/1.0.0");
    }
}

// HK v0.19.13: tests of the entry limits of a frame. They need no property-testing crate.
#[cfg(test)]
mod hk_tests {
    use std::time::Duration;

    use futures_timer::Delay;
    use libp2p_identity::Keypair;
    use quick_protobuf::{BytesReader, MessageRead};

    use super::*;
    use crate::{config::Config, types::RpcOut, Behaviour, MessageAuthenticity};

    /// The kinds of entries that are counted on their own, by number: subscriptions, published
    /// messages, and IHAVE, IWANT, GRAFT, PRUNE and IDONTWANT entries.
    const KINDS: usize = 7;
    const GRAFT: usize = 4;

    fn codec(validation_mode: ValidationMode) -> GossipsubCodec {
        GossipsubCodec::new(u32::MAX as usize, validation_mode, HashMap::new())
    }

    /// The frame of `rpc` as it goes on the wire.
    fn frame(rpc: proto::RPC) -> BytesMut {
        let mut buf = BytesMut::new();
        codec(ValidationMode::None).encode(rpc, &mut buf).unwrap();
        buf
    }

    /// A varint of the fewest bytes.
    fn varint(mut value: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        while value >= 0x80 {
            bytes.push((value & 0x7f) as u8 | 0x80);
            value >>= 7;
        }
        bytes.push(value as u8);
        bytes
    }

    /// A frame around hand-written bytes.
    fn raw_frame(body: &[u8]) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&varint(body.len()));
        buf.extend_from_slice(body);
        buf
    }

    /// The bytes of the first frame of `buf` behind its length prefix.
    fn frame_body(buf: &[u8]) -> &[u8] {
        let (prefix_len, frame_len) = peek_frame_length(buf).expect("a whole length prefix");
        &buf[prefix_len..prefix_len + frame_len]
    }

    /// The count of the first frame of `buf`.
    fn scan(buf: &[u8]) -> (Result<(), ScanStop>, FrameCounts) {
        let mut counts = FrameCounts::default();
        let result = scan_message(frame_body(buf), ScanMessage::Rpc, &mut counts);
        (result, counts)
    }

    /// Decodes the first frame of `buf`: its entries, or `None` when the frame is refused.
    fn decode_frame(buf: &mut BytesMut) -> Option<Rpc> {
        match codec(ValidationMode::None).decode(buf) {
            Ok(Some(HandlerEvent::Message { rpc, .. })) => Some(rpc),
            Ok(_) => panic!("a whole frame is decoded or refused"),
            Err(_) => None,
        }
    }

    /// A frame with `n` entries of one kind and nothing else.
    fn frame_of_kind(kind: usize, n: usize) -> proto::RPC {
        let topic = || Some(String::from("t"));
        let mut rpc = proto::RPC::default();
        let mut control = proto::ControlMessage::default();
        match kind {
            0 => {
                rpc.subscriptions = vec![
                    proto::SubOpts {
                        subscribe: Some(true),
                        topic_id: topic(),
                    };
                    n
                ];
            }
            1 => {
                rpc.publish = vec![
                    proto::Message {
                        topic: String::from("t"),
                        ..Default::default()
                    };
                    n
                ];
            }
            2 => {
                control.ihave = vec![
                    proto::ControlIHave {
                        topic_id: topic(),
                        message_ids: Vec::new(),
                    };
                    n
                ];
            }
            3 => {
                control.iwant = vec![
                    proto::ControlIWant {
                        message_ids: Vec::new(),
                    };
                    n
                ];
            }
            GRAFT => {
                control.graft = vec![proto::ControlGraft { topic_id: topic() }; n];
            }
            5 => {
                control.prune = vec![
                    proto::ControlPrune {
                        topic_id: topic(),
                        peers: Vec::new(),
                        backoff: Some(60),
                    };
                    n
                ];
            }
            6 => {
                control.idontwant = vec![
                    proto::ControlIDontWant {
                        message_ids: Vec::new(),
                    };
                    n
                ];
            }
            _ => unreachable!("seven kinds of entries"),
        }
        if kind >= 2 {
            rpc.control = Some(control);
        }
        rpc
    }

    /// The number of entries of one kind in a decoded frame.
    fn entries_of_kind(rpc: &Rpc, kind: usize) -> usize {
        match kind {
            0 => rpc.subscriptions.len(),
            1 => rpc.messages.len(),
            _ => rpc
                .control_msgs
                .iter()
                .filter(|action| {
                    kind == match action {
                        ControlAction::IHave(_) => 2,
                        ControlAction::IWant(_) => 3,
                        ControlAction::Graft(_) => GRAFT,
                        ControlAction::Prune(_) => 5,
                        ControlAction::IDontWant(_) => 6,
                    }
                })
                .count(),
        }
    }

    /// `n` message ids, all different.
    fn ids(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| (i as u32).to_be_bytes().to_vec()).collect()
    }

    /// A frame whose message ids are spread over an IHAVE, an IWANT and an IDONTWANT entry.
    fn frame_of_message_ids(ihave: usize, iwant: usize, idontwant: usize) -> proto::RPC {
        proto::RPC {
            control: Some(proto::ControlMessage {
                ihave: vec![proto::ControlIHave {
                    topic_id: Some(String::from("t")),
                    message_ids: ids(ihave),
                }],
                iwant: vec![proto::ControlIWant {
                    message_ids: ids(iwant),
                }],
                idontwant: vec![proto::ControlIDontWant {
                    message_ids: ids(idontwant),
                }],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// A PRUNE entry with `n` peer records.
    fn prune_with_peers(n: usize) -> proto::ControlPrune {
        proto::ControlPrune {
            topic_id: Some(String::from("t")),
            peers: (0..n)
                .map(|_| proto::PeerInfo {
                    peer_id: Some(PeerId::random().to_bytes()),
                    signed_peer_record: None,
                })
                .collect(),
            backoff: Some(60),
        }
    }

    /// A frame with the given PRUNE entries and nothing else.
    fn frame_of_prunes(prune: Vec<proto::ControlPrune>) -> proto::RPC {
        proto::RPC {
            control: Some(proto::ControlMessage {
                prune,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn hk_frame_at_an_entry_limit_is_decoded() {
        for kind in 0..KINDS {
            let mut buf = frame(frame_of_kind(kind, MAX_FRAME_ENTRIES_PER_KIND));
            assert_eq!(scan(&buf).0, Ok(()), "kind {kind}");
            let rpc = decode_frame(&mut buf).expect("a frame at a limit is decoded");
            assert_eq!(
                entries_of_kind(&rpc, kind),
                MAX_FRAME_ENTRIES_PER_KIND,
                "kind {kind}"
            );
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn hk_frame_above_an_entry_limit_is_refused() {
        for kind in 0..KINDS {
            let mut buf = frame(frame_of_kind(kind, MAX_FRAME_ENTRIES_PER_KIND + 1));
            assert_eq!(scan(&buf).0, Err(ScanStop::OverLimit), "kind {kind}");
            assert!(decode_frame(&mut buf).is_none(), "kind {kind}");
            assert!(buf.is_empty(), "a refused frame is taken off the buffer");
        }
    }

    #[test]
    fn hk_message_ids_of_a_frame_are_counted_together() {
        let part = MAX_FRAME_MESSAGE_IDS / 4;
        let rest = MAX_FRAME_MESSAGE_IDS - 2 * part;

        let mut at_limit = frame(frame_of_message_ids(rest, part, part));
        let (result, counts) = scan(&at_limit);
        assert_eq!(result, Ok(()));
        assert_eq!(counts.message_ids, MAX_FRAME_MESSAGE_IDS);
        let rpc = decode_frame(&mut at_limit).expect("a frame at the limit is decoded");
        let decoded: usize = rpc
            .control_msgs
            .iter()
            .map(|action| match action {
                ControlAction::IHave(IHave { message_ids, .. })
                | ControlAction::IWant(IWant { message_ids })
                | ControlAction::IDontWant(IDontWant { message_ids }) => message_ids.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(decoded, MAX_FRAME_MESSAGE_IDS);

        for (ihave, iwant, idontwant) in [
            (rest + 1, part, part),
            (rest, part + 1, part),
            (rest, part, part + 1),
            (MAX_FRAME_MESSAGE_IDS + 1, 0, 0),
            (0, MAX_FRAME_MESSAGE_IDS + 1, 0),
            (0, 0, MAX_FRAME_MESSAGE_IDS + 1),
        ] {
            let mut above = frame(frame_of_message_ids(ihave, iwant, idontwant));
            assert_eq!(scan(&above).0, Err(ScanStop::OverLimit));
            assert!(decode_frame(&mut above).is_none());
            assert!(above.is_empty());
        }
    }

    #[test]
    fn hk_prune_peer_records_of_a_frame_are_counted_together() {
        let half = MAX_FRAME_PRUNE_PEERS / 2;

        let mut at_limit = frame(frame_of_prunes(vec![
            prune_with_peers(half),
            prune_with_peers(MAX_FRAME_PRUNE_PEERS - half),
        ]));
        let (result, counts) = scan(&at_limit);
        assert_eq!(result, Ok(()));
        assert_eq!(counts.prune_peers, MAX_FRAME_PRUNE_PEERS);
        let rpc = decode_frame(&mut at_limit).expect("a frame at the limit is decoded");
        let decoded: usize = rpc
            .control_msgs
            .iter()
            .map(|action| match action {
                ControlAction::Prune(Prune { peers, .. }) => peers.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(decoded, MAX_FRAME_PRUNE_PEERS);

        for prunes in [
            vec![
                prune_with_peers(half),
                prune_with_peers(MAX_FRAME_PRUNE_PEERS - half + 1),
            ],
            vec![prune_with_peers(MAX_FRAME_PRUNE_PEERS + 1)],
        ] {
            let mut above = frame(frame_of_prunes(prunes));
            assert_eq!(scan(&above).0, Err(ScanStop::OverLimit));
            assert!(decode_frame(&mut above).is_none());
            assert!(above.is_empty());
        }
    }

    #[test]
    fn hk_largest_frames_this_crate_sends_are_within_the_limits() {
        let config = Config::default();
        assert!(config.max_ihave_length() <= MAX_FRAME_MESSAGE_IDS);
        assert!(config.prune_peers() <= MAX_FRAME_PRUNE_PEERS);

        let topic = TopicHash::from_raw("a topic of this node");
        let message_ids = |n: usize| -> Vec<MessageId> {
            (0..n)
                .map(|i| MessageId::new(format!("{i:040}").as_bytes()))
                .collect()
        };
        let timeout = || Delay::new(Duration::from_secs(60));

        // A signed message close to the largest one the default configuration publishes.
        let mut gs: Behaviour = Behaviour::new(
            MessageAuthenticity::Signed(Keypair::generate_ed25519()),
            Config::default(),
        )
        .unwrap();
        let message = gs
            .build_raw_message(topic.clone(), vec![7u8; 60_000])
            .unwrap();

        // More peer records than a PRUNE of this crate carries by default.
        let px_peers = config.prune_peers().max(64);

        let largest = vec![
            RpcOut::Publish {
                message: message.clone(),
                timeout: timeout(),
            },
            RpcOut::Forward {
                message,
                timeout: timeout(),
            },
            RpcOut::Subscribe(topic.clone()),
            RpcOut::Unsubscribe(topic.clone()),
            RpcOut::Graft(Graft {
                topic_hash: topic.clone(),
            }),
            RpcOut::Prune(Prune {
                topic_hash: topic.clone(),
                peers: (0..px_peers)
                    .map(|_| PeerInfo {
                        peer_id: Some(PeerId::random()),
                    })
                    .collect(),
                backoff: Some(config.prune_backoff().as_secs()),
            }),
            RpcOut::IHave(IHave {
                topic_hash: topic.clone(),
                message_ids: message_ids(config.max_ihave_length()),
            }),
            RpcOut::IWant(IWant {
                message_ids: message_ids(config.max_ihave_length()),
            }),
            RpcOut::IDontWant(IDontWant {
                message_ids: message_ids(1),
            }),
        ];

        for rpc_out in largest {
            let mut buf = BytesMut::new();
            codec(ValidationMode::Strict)
                .encode(rpc_out.into_protobuf(), &mut buf)
                .unwrap();

            let (result, counts) = scan(&buf);
            assert_eq!(result, Ok(()), "{counts:?}");
            let entries = counts.subscriptions
                + counts.publish
                + counts.ihave
                + counts.iwant
                + counts.graft
                + counts.prune
                + counts.idontwant;
            assert_eq!(entries, 1, "one entry of one kind in a frame: {counts:?}");
            assert!(counts.message_ids <= config.max_ihave_length());
            assert!(counts.prune_peers <= px_peers);

            match codec(ValidationMode::Strict).decode(&mut buf) {
                Ok(Some(HandlerEvent::Message {
                    rpc,
                    invalid_messages,
                })) => {
                    assert!(invalid_messages.is_empty());
                    assert_eq!(
                        rpc.messages.len() + rpc.subscriptions.len() + rpc.control_msgs.len(),
                        1
                    );
                }
                _ => panic!("a frame this crate sends is decoded"),
            }
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn hk_size_of_a_message_plays_no_part_in_the_count() {
        let size = 4 << 20;
        let mut buf = frame(proto::RPC {
            publish: vec![proto::Message {
                data: Some(vec![7u8; size]),
                topic: String::from("t"),
                ..Default::default()
            }],
            ..Default::default()
        });

        let (result, counts) = scan(&buf);
        assert_eq!(result, Ok(()));
        assert_eq!(
            counts,
            FrameCounts {
                publish: 1,
                ..Default::default()
            }
        );
        let rpc = decode_frame(&mut buf).expect("the frame is decoded");
        assert_eq!(rpc.messages[0].data.len(), size);
    }

    #[test]
    fn hk_frame_is_counted_when_it_is_whole() {
        let whole = frame(frame_of_kind(GRAFT, 3));
        let (first, second) = whole.split_at(whole.len() / 2);
        let mut buf = BytesMut::from(first);
        assert!(matches!(
            codec(ValidationMode::None).decode(&mut buf),
            Ok(None)
        ));
        assert_eq!(&buf[..], first, "an unfinished frame stays in the buffer");
        buf.extend_from_slice(second);
        let rpc = decode_frame(&mut buf).expect("the whole frame is decoded");
        assert_eq!(entries_of_kind(&rpc, GRAFT), 3);
        assert!(buf.is_empty());

        // A frame above a limit is refused once it is whole.
        let above = frame(frame_of_kind(GRAFT, MAX_FRAME_ENTRIES_PER_KIND + 1));
        let (first, second) = above.split_at(above.len() - 1);
        let mut buf = BytesMut::from(first);
        assert!(matches!(
            codec(ValidationMode::None).decode(&mut buf),
            Ok(None)
        ));
        buf.extend_from_slice(second);
        assert!(decode_frame(&mut buf).is_none());
        assert!(buf.is_empty());
    }

    #[test]
    fn hk_refused_frame_leaves_the_frames_behind_it() {
        let mut buf = frame(frame_of_kind(GRAFT, MAX_FRAME_ENTRIES_PER_KIND + 1));
        let behind = frame(frame_of_kind(GRAFT, 2));
        buf.extend_from_slice(&behind);

        assert!(decode_frame(&mut buf).is_none());
        assert_eq!(
            &buf[..],
            &behind[..],
            "only the refused frame is taken off the buffer"
        );
        let rpc = decode_frame(&mut buf).expect("the frame behind is decoded");
        assert_eq!(entries_of_kind(&rpc, GRAFT), 2);
        assert!(buf.is_empty());
    }

    #[test]
    fn hk_malformed_frames_are_refused() {
        let bodies: [&[u8]; 6] = [
            &[0x1a, 0x02, 0x0a, 0x04, 0x12, 0x00, 0x12, 0x00],
            &[0x1a, 0x7f, 0x1a, 0x00],
            &[0x12, 0x02, 0x12, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0x1a, 0x01, 0x8a, 0x00],
            &[0x1a, 0x01, 0x7a, 0x00],
            &[0x1a, 0x01, 0x0a, 0x00],
        ];
        for body in bodies {
            let mut buf = raw_frame(body);
            assert_eq!(scan(&buf).0, Err(ScanStop::PastEnd), "{body:02x?}");
            assert!(decode_frame(&mut buf).is_none(), "{body:02x?}");
            assert!(buf.is_empty(), "a refused frame is taken off the buffer");
        }
    }

    #[test]
    fn hk_frame_the_decoder_refuses_on_its_own_is_left_to_the_decoder() {
        let bodies: [&[u8]; 8] = [
            // A field of a group wire type.
            &[0x0b],
            // A tag of ten bytes without an end.
            &[0x80; 10],
            // A field this crate does not read, of more bytes than the frame has.
            &[0x7a, 0x05],
            // A frame that ends inside a tag.
            &[0x80],
            // A field of a group wire type in a control message.
            &[0x1a, 0x01, 0x0b],
            // A tag of ten bytes without an end in a control message.
            &[
                0x1a, 0x0a, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
            ],
            // A field this crate does not read, of more bytes than its control message has.
            &[0x1a, 0x02, 0x7a, 0x05],
            // A field of 64 bits this crate does not read, in a control message with 1 byte left
            // for it.
            &[0x1a, 0x02, 0x79, 0x00],
        ];
        for body in bodies {
            let mut buf = raw_frame(body);
            assert_eq!(scan(&buf).0, Err(ScanStop::LeftToDecoder), "{body:02x?}");
            assert!(decode_frame(&mut buf).is_none(), "{body:02x?}");
        }
    }

    #[test]
    fn hk_malformed_frames_are_refused_in_every_message() {
        let bodies: &[&[u8]] = &[
            &[0x0a, 0x05, 0x12, 0x00],
            &[0x12, 0x05, 0x22, 0x00],
            &[0x0a, 0x02, 0x12, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0x0a, 0x01, 0x12, 0x00],
            &[0x0a, 0x02, 0x08, 0x80, 0x00],
            &[0x12, 0x01, 0x22, 0x00],
            &[0x1a, 0x02, 0x12, 0x04, 0x0a, 0x00, 0x0a, 0x00],
            &[0x1a, 0x02, 0x1a, 0x04, 0x0a, 0x00, 0x0a, 0x00],
            &[0x1a, 0x02, 0x22, 0x04, 0x0a, 0x00, 0x0a, 0x00],
            &[0x1a, 0x02, 0x2a, 0x04, 0x0a, 0x00, 0x0a, 0x00],
            &[0x1a, 0x04, 0x0a, 0x02, 0x12, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0x1a, 0x04, 0x0a, 0x02, 0x78, 0x80, 0x00],
            &[0x1a, 0x04, 0x12, 0x02, 0x0a, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0x1a, 0x04, 0x1a, 0x02, 0x0a, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0x1a, 0x04, 0x22, 0x02, 0x0a, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0x1a, 0x04, 0x22, 0x02, 0x12, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[
                0x1a, 0x06, 0x22, 0x04, 0x12, 0x02, 0x0a, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            &[0x1a, 0x05, 0x22, 0x03, 0x12, 0x01, 0x0a, 0x00],
            &[0x1a, 0x04, 0x2a, 0x02, 0x0a, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00],
        ];
        for &body in bodies {
            let mut buf = raw_frame(body);
            assert_eq!(scan(&buf).0, Err(ScanStop::PastEnd), "{body:02x?}");
            assert!(decode_frame(&mut buf).is_none(), "{body:02x?}");
            assert!(buf.is_empty(), "a refused frame is taken off the buffer");
        }
    }

    #[test]
    fn hk_entries_are_counted_as_the_decoder_reads_them() {
        // GRAFT entries whose tag is written in two bytes: the decoder reads each of them.
        let grafts = |n: usize| -> BytesMut {
            let entries = [0x9a_u8, 0x00, 0x00].repeat(n);
            let mut body = vec![0x1a_u8];
            body.extend_from_slice(&varint(entries.len()));
            body.extend_from_slice(&entries);
            raw_frame(&body)
        };
        let mut read = grafts(3);
        let rpc = decode_frame(&mut read).expect("the frame is decoded");
        assert_eq!(entries_of_kind(&rpc, GRAFT), 3);
        let mut above = grafts(MAX_FRAME_ENTRIES_PER_KIND + 1);
        assert_eq!(scan(&above).0, Err(ScanStop::OverLimit));
        assert!(decode_frame(&mut above).is_none());

        // The entries of a frame are counted over all of its control fields.
        let control_field = |n: usize| -> Vec<u8> { frame_body(&frame(frame_of_kind(GRAFT, n))).to_vec() };
        let two_controls = |first: usize, second: usize| -> BytesMut {
            let mut body = control_field(first);
            body.extend_from_slice(&control_field(second));
            raw_frame(&body)
        };
        let half = MAX_FRAME_ENTRIES_PER_KIND / 2;

        let mut at_limit = two_controls(half, MAX_FRAME_ENTRIES_PER_KIND - half);
        let (result, counts) = scan(&at_limit);
        assert_eq!(result, Ok(()));
        assert_eq!(counts.graft, MAX_FRAME_ENTRIES_PER_KIND);
        assert!(decode_frame(&mut at_limit).is_some());

        let mut above = two_controls(half, MAX_FRAME_ENTRIES_PER_KIND - half + 1);
        assert_eq!(scan(&above).0, Err(ScanStop::OverLimit));
        assert!(decode_frame(&mut above).is_none());
    }

    /// A small fixed sequence of numbers.
    struct Sequence(u64);

    impl Sequence {
        /// The next number, below `bound`.
        fn below(&mut self, bound: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % bound as u64) as usize
        }

        fn bytes(&mut self, max_len: usize) -> Vec<u8> {
            let len = self.below(max_len + 1);
            (0..len).map(|_| self.below(256) as u8).collect()
        }

        fn text(&mut self, max_len: usize) -> String {
            let len = self.below(max_len + 1);
            (0..len)
                .map(|_| char::from(b'a' + self.below(26) as u8))
                .collect()
        }

        /// `Some` three times out of four.
        fn option<T>(&mut self, value: impl FnOnce(&mut Self) -> T) -> Option<T> {
            if self.below(4) == 0 {
                None
            } else {
                Some(value(self))
            }
        }
    }

    /// A frame with a few entries of every kind, some of their fields left out.
    fn mixed_rpc(seq: &mut Sequence) -> proto::RPC {
        let mut rpc = proto::RPC::default();
        for _ in 0..seq.below(4) {
            rpc.subscriptions.push(proto::SubOpts {
                subscribe: seq.option(|seq| seq.below(2) == 0),
                topic_id: seq.option(|seq| seq.text(12)),
            });
        }
        for _ in 0..seq.below(3) {
            rpc.publish.push(proto::Message {
                from: seq.option(|seq| seq.bytes(40)),
                data: seq.option(|seq| seq.bytes(300)),
                seqno: seq.option(|seq| seq.bytes(8)),
                topic: seq.text(12),
                signature: seq.option(|seq| seq.bytes(64)),
                key: seq.option(|seq| seq.bytes(36)),
            });
        }
        if seq.below(4) > 0 {
            let mut control = proto::ControlMessage::default();
            for _ in 0..seq.below(4) {
                control.ihave.push(proto::ControlIHave {
                    topic_id: seq.option(|seq| seq.text(12)),
                    message_ids: (0..seq.below(6)).map(|_| seq.bytes(40)).collect(),
                });
            }
            for _ in 0..seq.below(4) {
                control.iwant.push(proto::ControlIWant {
                    message_ids: (0..seq.below(6)).map(|_| seq.bytes(40)).collect(),
                });
            }
            for _ in 0..seq.below(4) {
                control.graft.push(proto::ControlGraft {
                    topic_id: seq.option(|seq| seq.text(12)),
                });
            }
            for _ in 0..seq.below(4) {
                control.prune.push(proto::ControlPrune {
                    topic_id: seq.option(|seq| seq.text(12)),
                    peers: (0..seq.below(5))
                        .map(|_| proto::PeerInfo {
                            peer_id: seq.option(|seq| seq.bytes(38)),
                            signed_peer_record: seq.option(|seq| seq.bytes(60)),
                        })
                        .collect(),
                    backoff: seq.option(|seq| seq.below(4000) as u64),
                });
            }
            for _ in 0..seq.below(4) {
                control.idontwant.push(proto::ControlIDontWant {
                    message_ids: (0..seq.below(6)).map(|_| seq.bytes(40)).collect(),
                });
            }
            rpc.control = Some(control);
        }
        rpc
    }

    /// The entries of `rpc`, counted from its structure.
    fn counts_of(rpc: &proto::RPC) -> FrameCounts {
        let mut counts = FrameCounts {
            subscriptions: rpc.subscriptions.len(),
            publish: rpc.publish.len(),
            ..Default::default()
        };
        if let Some(control) = &rpc.control {
            counts.ihave = control.ihave.len();
            counts.iwant = control.iwant.len();
            counts.graft = control.graft.len();
            counts.prune = control.prune.len();
            counts.idontwant = control.idontwant.len();
            counts.message_ids = control
                .ihave
                .iter()
                .map(|entry| entry.message_ids.len())
                .chain(control.iwant.iter().map(|entry| entry.message_ids.len()))
                .chain(
                    control
                        .idontwant
                        .iter()
                        .map(|entry| entry.message_ids.len()),
                )
                .sum();
            counts.prune_peers = control.prune.iter().map(|entry| entry.peers.len()).sum();
        }
        counts
    }

    #[test]
    fn hk_count_of_a_frame_is_what_the_decoder_reads() {
        let mut seq = Sequence(0x9e37_79b9_7f4a_7c15);
        for _ in 0..500 {
            let rpc = mixed_rpc(&mut seq);
            let buf = frame(rpc.clone());

            let (result, counts) = scan(&buf);
            assert_eq!(result, Ok(()), "{rpc:?}");
            assert_eq!(counts, counts_of(&rpc), "{rpc:?}");

            let bytes = frame_body(&buf);
            let mut reader = BytesReader::from_bytes(bytes);
            let read = proto::RPC::from_reader(&mut reader, bytes)
                .expect("the decoder reads the frame");
            assert_eq!(read, rpc);
        }
    }

    #[test]
    fn hk_message_id_longer_than_the_limit_is_left_out() {
        let fits = vec![1u8; MAX_MESSAGE_ID_LEN];
        let long = vec![2u8; MAX_MESSAGE_ID_LEN + 1];
        let ids = || vec![fits.clone(), long.clone(), b"short".to_vec()];
        let mut buf = frame(proto::RPC {
            control: Some(proto::ControlMessage {
                ihave: vec![proto::ControlIHave {
                    topic_id: Some(String::from("t")),
                    message_ids: ids(),
                }],
                iwant: vec![proto::ControlIWant { message_ids: ids() }],
                idontwant: vec![proto::ControlIDontWant { message_ids: ids() }],
                ..Default::default()
            }),
            ..Default::default()
        });

        // The frame is decoded; in each entry the longer message id is left out.
        let rpc = decode_frame(&mut buf).expect("the frame is decoded");
        let kept = vec![MessageId::from(fits.clone()), MessageId::new(b"short")];
        assert_eq!(rpc.control_msgs.len(), 3);
        for action in &rpc.control_msgs {
            let message_ids = match action {
                ControlAction::IHave(IHave { message_ids, .. })
                | ControlAction::IWant(IWant { message_ids })
                | ControlAction::IDontWant(IDontWant { message_ids }) => message_ids,
                _ => panic!("an IHAVE, an IWANT and an IDONTWANT entry"),
            };
            assert_eq!(message_ids, &kept);
        }
    }

    #[test]
    fn hk_entry_with_a_topic_longer_than_the_limit_is_left_out() {
        let fits = "t".repeat(MAX_TOPIC_LEN);
        let long = "t".repeat(MAX_TOPIC_LEN + 1);
        let mut rpc = proto::RPC::default();
        let mut control = proto::ControlMessage::default();
        for topic in [&fits, &long] {
            for subscribe in [true, false] {
                rpc.subscriptions.push(proto::SubOpts {
                    subscribe: Some(subscribe),
                    topic_id: Some(topic.clone()),
                });
            }
            control.ihave.push(proto::ControlIHave {
                topic_id: Some(topic.clone()),
                message_ids: vec![b"id".to_vec()],
            });
            control.graft.push(proto::ControlGraft {
                topic_id: Some(topic.clone()),
            });
            control.prune.push(proto::ControlPrune {
                topic_id: Some(topic.clone()),
                peers: Vec::new(),
                backoff: Some(60),
            });
        }
        rpc.control = Some(control);
        let mut buf = frame(rpc);

        // The frame is decoded; the SUBSCRIBE, UNSUBSCRIBE, IHAVE, GRAFT and PRUNE entries
        // with the longer topic are left out.
        let rpc = decode_frame(&mut buf).expect("the frame is decoded");
        let kept = TopicHash::from_raw(fits);
        assert_eq!(rpc.subscriptions.len(), 2);
        assert!(rpc.subscriptions.iter().all(|sub| sub.topic_hash == kept));
        assert_eq!(rpc.control_msgs.len(), 3);
        for action in &rpc.control_msgs {
            let topic_hash = match action {
                ControlAction::IHave(IHave { topic_hash, .. })
                | ControlAction::Graft(Graft { topic_hash })
                | ControlAction::Prune(Prune { topic_hash, .. }) => topic_hash,
                _ => panic!("an IHAVE, a GRAFT and a PRUNE entry"),
            };
            assert_eq!(topic_hash, &kept);
        }
    }

    /// `value` as a varint of `width` bytes, or of the fewest bytes it needs when that is more.
    fn wide_varint(value: usize, width: usize) -> Vec<u8> {
        let mut bytes = varint(value);
        while bytes.len() < width {
            let last = bytes.len() - 1;
            bytes[last] |= 0x80;
            bytes.push(0x00);
        }
        bytes
    }

    /// Appends a length-delimited field whose tag and length are each written in one to ten
    /// bytes.
    fn wide_field(out: &mut Vec<u8>, tag: usize, payload: &[u8], seq: &mut Sequence) {
        out.extend_from_slice(&wide_varint(tag, 1 + seq.below(10)));
        out.extend_from_slice(&wide_varint(payload.len(), 1 + seq.below(10)));
        out.extend_from_slice(payload);
    }

    /// `control` written with tags and lengths wider than needed.
    fn wide_control(control: &proto::ControlMessage, seq: &mut Sequence) -> Vec<u8> {
        let mut out = Vec::new();
        for ihave in &control.ihave {
            let mut entry = Vec::new();
            if let Some(topic) = &ihave.topic_id {
                wide_field(&mut entry, 10, topic.as_bytes(), seq);
            }
            for id in &ihave.message_ids {
                wide_field(&mut entry, 18, id, seq);
            }
            wide_field(&mut out, 10, &entry, seq);
        }
        for iwant in &control.iwant {
            let mut entry = Vec::new();
            for id in &iwant.message_ids {
                wide_field(&mut entry, 10, id, seq);
            }
            wide_field(&mut out, 18, &entry, seq);
        }
        for graft in &control.graft {
            let mut entry = Vec::new();
            if let Some(topic) = &graft.topic_id {
                wide_field(&mut entry, 10, topic.as_bytes(), seq);
            }
            wide_field(&mut out, 26, &entry, seq);
        }
        for prune in &control.prune {
            let mut entry = Vec::new();
            if let Some(topic) = &prune.topic_id {
                wide_field(&mut entry, 10, topic.as_bytes(), seq);
            }
            for peer in &prune.peers {
                let mut record = Vec::new();
                if let Some(peer_id) = &peer.peer_id {
                    wide_field(&mut record, 10, peer_id, seq);
                }
                if let Some(signed) = &peer.signed_peer_record {
                    wide_field(&mut record, 18, signed, seq);
                }
                wide_field(&mut entry, 18, &record, seq);
            }
            if let Some(backoff) = prune.backoff {
                entry.extend_from_slice(&wide_varint(24, 1 + seq.below(10)));
                entry.extend_from_slice(&varint(backoff as usize));
            }
            wide_field(&mut out, 34, &entry, seq);
        }
        for idontwant in &control.idontwant {
            let mut entry = Vec::new();
            for id in &idontwant.message_ids {
                wide_field(&mut entry, 10, id, seq);
            }
            wide_field(&mut out, 42, &entry, seq);
        }
        out
    }

    /// `rpc` written with tags and lengths wider than needed.
    fn wide_encoding(rpc: &proto::RPC, seq: &mut Sequence) -> Vec<u8> {
        let mut out = Vec::new();
        for sub in &rpc.subscriptions {
            let mut entry = Vec::new();
            if let Some(subscribe) = sub.subscribe {
                entry.extend_from_slice(&wide_varint(8, 1 + seq.below(10)));
                entry.push(u8::from(subscribe));
            }
            if let Some(topic) = &sub.topic_id {
                wide_field(&mut entry, 18, topic.as_bytes(), seq);
            }
            wide_field(&mut out, 10, &entry, seq);
        }
        for message in &rpc.publish {
            let mut entry = Vec::new();
            if let Some(from) = &message.from {
                wide_field(&mut entry, 10, from, seq);
            }
            if let Some(data) = &message.data {
                wide_field(&mut entry, 18, data, seq);
            }
            if let Some(seqno) = &message.seqno {
                wide_field(&mut entry, 26, seqno, seq);
            }
            wide_field(&mut entry, 34, message.topic.as_bytes(), seq);
            if let Some(signature) = &message.signature {
                wide_field(&mut entry, 42, signature, seq);
            }
            if let Some(key) = &message.key {
                wide_field(&mut entry, 50, key, seq);
            }
            wide_field(&mut out, 18, &entry, seq);
        }
        if let Some(control) = &rpc.control {
            let bytes = wide_control(control, seq);
            wide_field(&mut out, 26, &bytes, seq);
        }
        out
    }

    #[test]
    fn hk_decoder_builds_no_more_entries_than_were_counted() {
        let mut seq = Sequence(0x2545_f491_4f6c_dd1d);
        for _ in 0..300 {
            // A frame whose tags and lengths are written wider than needed, up to ten bytes.
            let rpc = mixed_rpc(&mut seq);
            let mut body = wide_encoding(&rpc, &mut seq);
            // And with a second control message: the decoder keeps the last one, the count
            // covers both.
            let second = mixed_rpc(&mut seq).control;
            if let Some(control) = &second {
                let bytes = wide_control(control, &mut seq);
                wide_field(&mut body, 26, &bytes, &mut seq);
            }
            let buf = raw_frame(&body);

            let (result, counts) = scan(&buf);
            assert_eq!(result, Ok(()), "{rpc:?}");

            let mut reader = BytesReader::from_bytes(&body);
            let read = proto::RPC::from_reader(&mut reader, &body)
                .expect("the decoder reads the frame");
            let built = counts_of(&read);
            for (built, counted) in [
                (built.subscriptions, counts.subscriptions),
                (built.publish, counts.publish),
                (built.ihave, counts.ihave),
                (built.iwant, counts.iwant),
                (built.graft, counts.graft),
                (built.prune, counts.prune),
                (built.idontwant, counts.idontwant),
                (built.message_ids, counts.message_ids),
                (built.prune_peers, counts.prune_peers),
            ] {
                assert!(built <= counted, "{rpc:?}");
            }

            // What the decoder reads is what was written.
            let mut written = rpc.clone();
            if second.is_some() {
                written.control = second.clone();
            }
            assert_eq!(read, written);

            // And the count is the sum over both control messages.
            let first = counts_of(&rpc);
            let extra = counts_of(&proto::RPC {
                control: second,
                ..Default::default()
            });
            assert_eq!(
                counts,
                FrameCounts {
                    subscriptions: first.subscriptions,
                    publish: first.publish,
                    ihave: first.ihave + extra.ihave,
                    iwant: first.iwant + extra.iwant,
                    graft: first.graft + extra.graft,
                    prune: first.prune + extra.prune,
                    idontwant: first.idontwant + extra.idontwant,
                    message_ids: first.message_ids + extra.message_ids,
                    prune_peers: first.prune_peers + extra.prune_peers,
                }
            );
        }
    }
}
