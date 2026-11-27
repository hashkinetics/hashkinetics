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

use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use futures::{stream::Peekable, Stream, StreamExt};

use crate::types::RpcOut;

// HK v0.19.13: at most this many GRAFT, PRUNE, SUBSCRIBE and UNSUBSCRIBE messages wait for one
// peer at a time. A peer that takes its messages has a handful waiting. At the bound a further
// one is not queued, as with a full queue.
pub(crate) const MAX_PENDING_CONTROL: usize = 1_024;

/// HK v0.19.13: the numbers of messages that wait in the priority queue of one peer. A number
/// is raised when a message is queued and lowered when a connection handler takes it.
#[derive(Debug, Default)]
pub(crate) struct PriorityQueueLen {
    /// `Publish` messages.
    publish: AtomicUsize,
    /// GRAFT, PRUNE, SUBSCRIBE and UNSUBSCRIBE messages.
    control: AtomicUsize,
}

/// `RpcOut` sender that is priority aware.
#[derive(Debug)]
pub(crate) struct Sender {
    /// Capacity of the priority channel for `Publish` messages.
    priority_cap: usize,
    len: Arc<PriorityQueueLen>,
    pub(crate) priority_sender: async_channel::Sender<RpcOut>,
    pub(crate) non_priority_sender: async_channel::Sender<RpcOut>,
    priority_receiver: async_channel::Receiver<RpcOut>,
    non_priority_receiver: async_channel::Receiver<RpcOut>,
}

impl Sender {
    /// Create a RpcSender.
    pub(crate) fn new(cap: usize) -> Sender {
        // We intentionally do not bound the channel, as we still need to send control messages
        // such as `GRAFT`, `PRUNE`, `SUBSCRIBE`, and `UNSUBSCRIBE`.
        // That's also why we define `cap` and divide it by two,
        // to ensure there is capacity for both priority and non_priority messages.
        // HK v0.19.13: `send_message` counts the control messages that wait and holds their
        // number at `MAX_PENDING_CONTROL`.
        let (priority_sender, priority_receiver) = async_channel::unbounded();
        let (non_priority_sender, non_priority_receiver) = async_channel::bounded(cap / 2);
        let len = Arc::new(PriorityQueueLen::default());
        Sender {
            priority_cap: cap / 2,
            len,
            priority_sender,
            non_priority_sender,
            priority_receiver,
            non_priority_receiver,
        }
    }

    /// Create a new Receiver to the sender.
    pub(crate) fn new_receiver(&self) -> Receiver {
        Receiver {
            priority_queue_len: self.len.clone(),
            priority: Box::pin(self.priority_receiver.clone().peekable()),
            non_priority: Box::pin(self.non_priority_receiver.clone().peekable()),
        }
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn send_message(&self, rpc: RpcOut) -> Result<(), RpcOut> {
        if let RpcOut::Publish { .. } = rpc {
            // Update number of publish message in queue.
            let len = self.len.publish.load(Ordering::Relaxed);
            if len >= self.priority_cap {
                return Err(rpc);
            }
            // HK v0.19.13: counted with one atomic step, so a message a handler takes at the
            // same moment is not lost from the count.
            self.len.publish.fetch_add(1, Ordering::Relaxed);
        }
        // HK v0.19.13: at most `MAX_PENDING_CONTROL` control messages wait for the peer.
        if matches!(
            rpc,
            RpcOut::Graft(_) | RpcOut::Prune(_) | RpcOut::Subscribe(_) | RpcOut::Unsubscribe(_)
        ) {
            let pending = self.len.control.load(Ordering::Relaxed);
            if pending >= MAX_PENDING_CONTROL {
                return Err(rpc);
            }
            self.len.control.fetch_add(1, Ordering::Relaxed);
        }
        let sender = match rpc {
            RpcOut::Publish { .. }
            | RpcOut::Graft(_)
            | RpcOut::Prune(_)
            | RpcOut::Subscribe(_)
            | RpcOut::Unsubscribe(_) => &self.priority_sender,
            RpcOut::Forward { .. } | RpcOut::IHave(_) | RpcOut::IWant(_) | RpcOut::IDontWant(_) => {
                &self.non_priority_sender
            }
        };
        sender.try_send(rpc).map_err(|err| err.into_inner())
    }

    /// Returns the current size of the priority queue.
    #[cfg(feature = "metrics")]
    pub(crate) fn priority_queue_len(&self) -> usize {
        self.len.publish.load(Ordering::Relaxed)
    }

    /// Returns the current size of the non-priority queue.
    // HK v0.19.13: also read before an IHAVE is answered, so it is built without the metrics
    // feature too.
    pub(crate) fn non_priority_queue_len(&self) -> usize {
        self.non_priority_sender.len()
    }

    /// HK v0.19.13: the number of control messages that wait for the peer.
    #[cfg(test)]
    pub(crate) fn pending_control(&self) -> usize {
        self.len.control.load(Ordering::Relaxed)
    }
}

/// `RpcOut` sender that is priority aware.
#[derive(Debug)]
pub struct Receiver {
    /// HK v0.19.13: the numbers of messages that wait in the priority queue, shared with the
    /// `Sender`.
    pub(crate) priority_queue_len: Arc<PriorityQueueLen>,
    /// The priority queue receiver.
    pub(crate) priority: Pin<Box<Peekable<async_channel::Receiver<RpcOut>>>>,
    /// The non priority queue receiver.
    pub(crate) non_priority: Pin<Box<Peekable<async_channel::Receiver<RpcOut>>>>,
}

impl Receiver {
    // Peek the next message in the queues and return it if its timeout has elapsed.
    // Returns `None` if there aren't any more messages on the stream or none is stale.
    pub(crate) fn poll_stale(&mut self, cx: &mut Context<'_>) -> Poll<Option<RpcOut>> {
        // Peek priority queue.
        let priority = match self.priority.as_mut().poll_peek_mut(cx) {
            Poll::Ready(Some(RpcOut::Publish {
                message: _,
                ref mut timeout,
            })) => {
                if Pin::new(timeout).poll(cx).is_ready() {
                    // Return the message.
                    let dropped = futures::ready!(self.priority.poll_next_unpin(cx))
                        .expect("There should be a message");
                    // HK v0.19.13: the publish count follows the queue. A published message
                    // that is taken out of the queue here, past its timeout, no longer counts
                    // as waiting, like one that a handler takes in `poll_next`.
                    self.priority_queue_len
                        .publish
                        .fetch_sub(1, Ordering::Relaxed);
                    return Poll::Ready(Some(dropped));
                }
                Poll::Ready(None)
            }
            poll => poll,
        };

        let non_priority = match self.non_priority.as_mut().poll_peek_mut(cx) {
            Poll::Ready(Some(RpcOut::Forward {
                message: _,
                ref mut timeout,
            })) => {
                if Pin::new(timeout).poll(cx).is_ready() {
                    // Return the message.
                    let dropped = futures::ready!(self.non_priority.poll_next_unpin(cx))
                        .expect("There should be a message");
                    return Poll::Ready(Some(dropped));
                }
                Poll::Ready(None)
            }
            poll => poll,
        };

        match (priority, non_priority) {
            (Poll::Ready(None), Poll::Ready(None)) => Poll::Ready(None),
            _ => Poll::Pending,
        }
    }

    /// Poll queues and return true if both are empty.
    pub(crate) fn poll_is_empty(&mut self, cx: &mut Context<'_>) -> bool {
        matches!(
            (
                self.priority.as_mut().poll_peek(cx),
                self.non_priority.as_mut().poll_peek(cx),
            ),
            (Poll::Ready(None), Poll::Ready(None))
        )
    }
}

impl Stream for Receiver {
    type Item = RpcOut;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        // The priority queue is first polled.
        if let Poll::Ready(rpc) = Pin::new(&mut self.priority).poll_next(cx) {
            match rpc {
                Some(RpcOut::Publish { .. }) => {
                    self.priority_queue_len
                        .publish
                        .fetch_sub(1, Ordering::Relaxed);
                }
                // HK v0.19.13: a control message that a handler takes no longer waits.
                Some(
                    RpcOut::Graft(_)
                    | RpcOut::Prune(_)
                    | RpcOut::Subscribe(_)
                    | RpcOut::Unsubscribe(_),
                ) => {
                    let _ = self.priority_queue_len.control.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |pending| pending.checked_sub(1),
                    );
                }
                _ => {}
            }
            return Poll::Ready(rpc);
        }
        // Then we poll the non priority.
        Pin::new(&mut self.non_priority).poll_next(cx)
    }
}

// HK v0.19.13: a test of the publish count.
#[cfg(test)]
mod hk_tests {
    use std::time::Duration;

    use futures::FutureExt;
    use futures_timer::Delay;

    use super::*;
    use crate::{types::RawMessage, TopicHash};

    /// The publish count follows the queue: a published message that waits past its timeout and
    /// is taken out of the queue no longer counts, and a further one is queued again.
    #[test]
    fn hk_publish_count_follows_messages_dropped_as_stale() {
        let sender = Sender::new(4);
        let mut receiver = sender.new_receiver();
        let publish = || RpcOut::Publish {
            message: RawMessage {
                source: None,
                data: vec![1, 2, 3],
                sequence_number: None,
                topic: TopicHash::from_raw("test"),
                signature: None,
                key: None,
                validated: true,
            },
            timeout: Delay::new(Duration::from_nanos(1)),
        };
        let waiting = |sender: &Sender| sender.len.publish.load(Ordering::Relaxed);

        // The queue takes as many published messages as its bound, and no more.
        let bound = sender.priority_cap;
        assert!(bound > 1);
        for _ in 0..bound {
            assert!(sender.send_message(publish()).is_ok());
        }
        assert!(sender.send_message(publish()).is_err());
        assert_eq!(waiting(&sender), bound);

        // Their timeouts have passed; the timer takes a moment to say so.
        let mut dropped = 0;
        for _ in 0..2_000 {
            if dropped == bound {
                break;
            }
            match std::future::poll_fn(|cx| receiver.poll_stale(cx)).now_or_never() {
                Some(Some(RpcOut::Publish { .. })) => dropped += 1,
                _ => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        assert_eq!(
            dropped, bound,
            "every message past its timeout is taken out of the queue"
        );

        // The count is back at zero and a published message is queued again.
        assert_eq!(waiting(&sender), 0);
        assert!(sender.send_message(publish()).is_ok());
        assert_eq!(waiting(&sender), 1);
    }
}
