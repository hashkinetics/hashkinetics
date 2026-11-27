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

use std::collections::HashMap;

use libp2p_identity::PeerId;
use web_time::Instant;

use crate::{peer_score::RejectReason, types::LogLimit, MessageId, ValidationError};

// HK v0.19.13: at most this many promises are tracked at a time, over all peers. A promise is
// held for `Config::iwant_followup_time` (3 seconds by default), so the requests of a node for
// messages it has not yet received stay far below the bound.
pub(crate) const MAX_GOSSIP_PROMISES: usize = 16_384;

// HK v0.19.13: at most this many promises are tracked at a time for the messages requested from
// one peer, so that no peer takes the room of the others. A message beyond a bound is requested
// all the same; only its promise is not tracked.
pub(crate) const MAX_GOSSIP_PROMISES_PER_PEER: usize = 1_024;

/// Tracks recently sent `IWANT` messages and checks if peers respond to them.
#[derive(Default)]
pub(crate) struct GossipPromises {
    /// Stores for each tracked message id and peer the instant when this promise expires.
    ///
    /// If the peer didn't respond until then we consider the promise as broken and penalize the
    /// peer.
    promises: HashMap<MessageId, HashMap<PeerId, Instant>>,
    /// HK v0.19.13: the number of promises tracked for each peer. It is kept equal to
    /// `promises`.
    per_peer: HashMap<PeerId, usize>,
    /// HK v0.19.13: the number of promises tracked over all peers. It is kept equal to
    /// `promises`.
    tracked: usize,
}

impl GossipPromises {
    /// Returns true if the message id exists in the promises.
    pub(crate) fn contains(&self, message: &MessageId) -> bool {
        self.promises.contains_key(message)
    }

    /// Get the peers we sent IWANT the input message id.
    pub(crate) fn peers_for_message(&self, message_id: &MessageId) -> Vec<PeerId> {
        self.promises
            .get(message_id)
            .map(|peers| peers.keys().copied().collect())
            .unwrap_or_default()
    }

    /// HK v0.19.13: the number of promises tracked, counted from the map. The counts kept beside
    /// the map are checked against it.
    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        let mut per_peer: HashMap<PeerId, usize> = HashMap::new();
        for peers in self.promises.values() {
            assert!(!peers.is_empty(), "a message id is kept only with a promise");
            for peer in peers.keys() {
                *per_peer.entry(*peer).or_insert(0) += 1;
            }
        }
        assert_eq!(per_peer, self.per_peer, "the count per peer equals the map");
        let tracked: usize = per_peer.values().sum();
        assert_eq!(
            tracked, self.tracked,
            "the count over all peers equals the map"
        );
        tracked
    }

    /// HK v0.19.13: the number of promises tracked for `peer`, counted from the map.
    #[cfg(test)]
    pub(crate) fn tracked_for(&self, peer: &PeerId) -> usize {
        self.promises
            .values()
            .filter(|peers| peers.contains_key(peer))
            .count()
    }

    /// Track a promise to deliver a message from a list of [`MessageId`]s we are requesting.
    ///
    /// HK v0.19.13: a promise is tracked only while fewer than `MAX_GOSSIP_PROMISES` are tracked
    /// over all peers and fewer than `MAX_GOSSIP_PROMISES_PER_PEER` for this peer. A message
    /// beyond that is requested all the same; only its promise is not tracked.
    pub(crate) fn add_promise(&mut self, peer: PeerId, messages: &[MessageId], expires: Instant) {
        let mut untracked = 0usize;
        for message_id in messages {
            // If a promise for this message id and peer already exists we don't update the expiry!
            if self
                .promises
                .get(message_id)
                .is_some_and(|peers| peers.contains_key(&peer))
            {
                continue;
            }
            let held = self.per_peer.get(&peer).copied().unwrap_or(0);
            if self.tracked >= MAX_GOSSIP_PROMISES || held >= MAX_GOSSIP_PROMISES_PER_PEER {
                untracked += 1;
                continue;
            }
            self.promises
                .entry(message_id.clone())
                .or_default()
                .insert(peer, expires);
            *self.per_peer.entry(peer).or_insert(0) += 1;
            self.tracked += 1;
        }
        if untracked > 0 {
            // HK v0.19.13: reported at most once per interval.
            static UNTRACKED: LogLimit = LogLimit::new();
            if let Some(held_back) = UNTRACKED.admit() {
                tracing::warn!(
                    peer=%peer,
                    untracked,
                    held_back,
                    "Messages were requested without a tracked promise: a bound of the tracked promises is reached"
                );
            }
        }
    }

    /// HK v0.19.13: takes one promise of `peer` out of the counts.
    fn release(per_peer: &mut HashMap<PeerId, usize>, tracked: &mut usize, peer: &PeerId) {
        if let std::collections::hash_map::Entry::Occupied(mut held) = per_peer.entry(*peer) {
            if *held.get() <= 1 {
                held.remove();
            } else {
                *held.get_mut() -= 1;
            }
        }
        *tracked = tracked.saturating_sub(1);
    }

    /// HK v0.19.13: stops tracking every promise for `message_id` and takes them out of the
    /// counts.
    fn forget(&mut self, message_id: &MessageId) {
        if let Some(peers) = self.promises.remove(message_id) {
            for peer in peers.keys() {
                Self::release(&mut self.per_peer, &mut self.tracked, peer);
            }
        }
    }

    pub(crate) fn message_delivered(&mut self, message_id: &MessageId) {
        // Someone delivered a message, we can stop tracking all promises for it.
        self.forget(message_id);
    }

    pub(crate) fn reject_message(&mut self, message_id: &MessageId, reason: &RejectReason) {
        // A message got rejected, so we can stop tracking promises and let the score penalty apply
        // from invalid message delivery.
        // We do take exception and apply promise penalty regardless in the following cases, where
        // the peer delivered an obviously invalid message.
        match reason {
            RejectReason::ValidationError(ValidationError::InvalidSignature) => (),
            RejectReason::SelfOrigin => (),
            _ => {
                self.forget(message_id);
            }
        };
    }

    /// Returns the number of broken promises for each peer who didn't follow up on an IWANT
    /// request.
    /// This should be called not too often relative to the expire times, since it iterates over
    /// the whole stored data.
    pub(crate) fn get_broken_promises(&mut self) -> HashMap<PeerId, usize> {
        let now = Instant::now();
        let mut result = HashMap::new();
        // HK v0.19.13: the counts follow every promise that is dropped here.
        let Self {
            promises,
            per_peer,
            tracked,
        } = self;
        promises.retain(|msg, peers| {
            peers.retain(|peer_id, expires| {
                if *expires < now {
                    let count = result.entry(*peer_id).or_insert(0);
                    *count += 1;
                    Self::release(per_peer, tracked, peer_id);
                    tracing::debug!(
                        peer=%peer_id,
                        message=%msg,
                        "[Penalty] The peer broke the promise to deliver message in time!"
                    );
                    false
                } else {
                    true
                }
            });
            !peers.is_empty()
        });
        result
    }
}
