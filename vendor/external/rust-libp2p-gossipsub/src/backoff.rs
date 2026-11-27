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

//! Data structure for efficiently storing known back-off's when pruning peers.
use std::{
    collections::{
        hash_map::{Entry, HashMap},
        HashSet,
    },
    time::Duration,
};

use libp2p_identity::PeerId;
use web_time::Instant;

use crate::topic::TopicHash;

// HK v0.19.13: the store holds at most this many (topic, peer) backoffs. A backoff is kept per
// joined topic and peer that was pruned or sent a PRUNE, so a node with a few topics and some
// hundreds of peers stays far below the bound.
pub(crate) const MAX_BACKOFF_ENTRIES: usize = 16_384;

// HK v0.19.13: while backoffs are not recorded because the store is at its bound, that is
// reported at most once per this interval.
const BOUND_REPORT_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Copy, Clone)]
struct HeartbeatIndex(usize);

/// Stores backoffs in an efficient manner.
pub(crate) struct BackoffStorage {
    /// Stores backoffs and the index in backoffs_by_heartbeat per peer per topic.
    backoffs: HashMap<TopicHash, HashMap<PeerId, (Instant, HeartbeatIndex)>>,
    /// Stores peer topic pairs per heartbeat (this is cyclic the current index is
    /// heartbeat_index).
    backoffs_by_heartbeat: Vec<HashSet<(TopicHash, PeerId)>>,
    /// The index in the backoffs_by_heartbeat vector corresponding to the current heartbeat.
    heartbeat_index: HeartbeatIndex,
    /// The heartbeat interval duration from the config.
    heartbeat_interval: Duration,
    /// Backoff slack from the config.
    backoff_slack: u32,
    /// HK v0.19.13: the number of (topic, peer) backoffs held, never above
    /// `MAX_BACKOFF_ENTRIES`.
    entries: usize,
    /// HK v0.19.13: when the bound was last reported.
    last_bound_report: Option<Instant>,
    /// HK v0.19.13: the backoffs not recorded since the last report.
    unrecorded: usize,
}

impl BackoffStorage {
    fn heartbeats(d: &Duration, heartbeat_interval: &Duration) -> usize {
        d.as_nanos().div_ceil(heartbeat_interval.as_nanos()) as usize
    }

    pub(crate) fn new(
        prune_backoff: &Duration,
        heartbeat_interval: Duration,
        backoff_slack: u32,
    ) -> BackoffStorage {
        // We add one additional slot for partial heartbeat
        let max_heartbeats =
            Self::heartbeats(prune_backoff, &heartbeat_interval) + backoff_slack as usize + 1;
        BackoffStorage {
            backoffs: HashMap::new(),
            backoffs_by_heartbeat: vec![HashSet::new(); max_heartbeats],
            heartbeat_index: HeartbeatIndex(0),
            heartbeat_interval,
            backoff_slack,
            entries: 0,
            last_bound_report: None,
            unrecorded: 0,
        }
    }

    /// Updates the backoff for a peer (if there is already a more restrictive backoff then this
    /// call doesn't change anything).
    pub(crate) fn update_backoff(&mut self, topic: &TopicHash, peer: &PeerId, time: Duration) {
        let Some(instant) = Instant::now().checked_add(time) else {
            tracing::warn!("ignoring oversized prune backoff");
            return;
        };

        // HK v0.19.13: the store never holds more than `MAX_BACKOFF_ENTRIES` entries. At the
        // bound a new (topic, peer) pair is not recorded; a pair already held is still updated.
        if self.entries >= MAX_BACKOFF_ENTRIES
            && !self
                .backoffs
                .get(topic)
                .is_some_and(|peers| peers.contains_key(peer))
        {
            self.note_unrecorded();
            return;
        }

        let insert_into_backoffs_by_heartbeat =
            |heartbeat_index: HeartbeatIndex,
             backoffs_by_heartbeat: &mut Vec<HashSet<_>>,
             heartbeat_interval,
             backoff_slack| {
                let pair = (topic.clone(), *peer);
                let index = (heartbeat_index.0
                    + Self::heartbeats(&time, heartbeat_interval)
                    + backoff_slack as usize)
                    % backoffs_by_heartbeat.len();
                backoffs_by_heartbeat[index].insert(pair);
                HeartbeatIndex(index)
            };
        match self.backoffs.entry(topic.clone()).or_default().entry(*peer) {
            Entry::Occupied(mut o) => {
                let (backoff, index) = o.get();
                if backoff < &instant {
                    let pair = (topic.clone(), *peer);
                    if let Some(s) = self.backoffs_by_heartbeat.get_mut(index.0) {
                        s.remove(&pair);
                    }
                    let index = insert_into_backoffs_by_heartbeat(
                        self.heartbeat_index,
                        &mut self.backoffs_by_heartbeat,
                        &self.heartbeat_interval,
                        self.backoff_slack,
                    );
                    o.insert((instant, index));
                }
            }
            Entry::Vacant(v) => {
                let index = insert_into_backoffs_by_heartbeat(
                    self.heartbeat_index,
                    &mut self.backoffs_by_heartbeat,
                    &self.heartbeat_interval,
                    self.backoff_slack,
                );
                v.insert((instant, index));
                self.entries += 1;
            }
        };
    }

    /// HK v0.19.13: the number of (topic, peer) backoffs held, counted from the maps. The count
    /// kept beside the maps is checked against it.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        let held: usize = self.backoffs.values().map(|peers| peers.len()).sum();
        assert_eq!(held, self.entries, "the count of entries equals the map");
        let slotted: usize = self
            .backoffs_by_heartbeat
            .iter()
            .map(|slot| slot.len())
            .sum();
        assert_eq!(slotted, held, "every entry is in one heartbeat slot");
        held
    }

    /// HK v0.19.13: counts a backoff that was not recorded because the store is at its bound,
    /// and reports that at most once per `BOUND_REPORT_INTERVAL`.
    fn note_unrecorded(&mut self) {
        self.unrecorded = self.unrecorded.saturating_add(1);
        let now = Instant::now();
        let report_due = match self.last_bound_report {
            Some(last) => now.duration_since(last) >= BOUND_REPORT_INTERVAL,
            None => true,
        };
        if report_due {
            tracing::warn!(
                limit = MAX_BACKOFF_ENTRIES,
                unrecorded = self.unrecorded,
                "The backoff store is at its entry limit; new backoffs are not recorded until entries expire"
            );
            self.last_bound_report = Some(now);
            self.unrecorded = 0;
        }
    }

    /// Checks if a given peer is backoffed for the given topic. This method respects the
    /// configured BACKOFF_SLACK and may return true even if the backup is already over.
    /// It is guaranteed to return false if the backoff is not over and eventually if enough time
    /// passed true if the backoff is over.
    ///
    /// This method should be used for deciding if we can already send a GRAFT to a previously
    /// backoffed peer.
    pub(crate) fn is_backoff_with_slack(&self, topic: &TopicHash, peer: &PeerId) -> bool {
        self.backoffs
            .get(topic)
            .is_some_and(|m| m.contains_key(peer))
    }

    pub(crate) fn get_backoff_time(&self, topic: &TopicHash, peer: &PeerId) -> Option<Instant> {
        Self::get_backoff_time_from_backoffs(&self.backoffs, topic, peer)
    }

    fn get_backoff_time_from_backoffs(
        backoffs: &HashMap<TopicHash, HashMap<PeerId, (Instant, HeartbeatIndex)>>,
        topic: &TopicHash,
        peer: &PeerId,
    ) -> Option<Instant> {
        backoffs
            .get(topic)
            .and_then(|m| m.get(peer).map(|(i, _)| *i))
    }

    /// Applies a heartbeat. That should be called regularly in intervals of length
    /// `heartbeat_interval`.
    pub(crate) fn heartbeat(&mut self) {
        // Clean up backoffs_by_heartbeat
        if let Some(s) = self.backoffs_by_heartbeat.get_mut(self.heartbeat_index.0) {
            let backoffs = &mut self.backoffs;
            // HK v0.19.13: the count of entries follows every removal.
            let entries = &mut self.entries;
            let slack = self.heartbeat_interval * self.backoff_slack;
            let now = Instant::now();
            s.retain(|(topic, peer)| {
                let keep = match Self::get_backoff_time_from_backoffs(backoffs, topic, peer) {
                    Some(backoff_time) => backoff_time
                        .checked_add(slack)
                        .map(|backoff| backoff > now)
                        .unwrap_or(false),
                    None => false,
                };
                if !keep {
                    // remove from backoffs
                    if let Entry::Occupied(mut m) = backoffs.entry(topic.clone()) {
                        if m.get_mut().remove(peer).is_some() {
                            *entries = entries.saturating_sub(1);
                            if m.get().is_empty() {
                                m.remove();
                            }
                        }
                    }
                }

                keep
            });
        }

        // Increase heartbeat index
        self.heartbeat_index =
            HeartbeatIndex((self.heartbeat_index.0 + 1) % self.backoffs_by_heartbeat.len());
    }
}
