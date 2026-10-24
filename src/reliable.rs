// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Acknowledged delivery on top of `Session`. Each message gets an id. The
//! receiver acknowledges every copy it sees, and the sender sends again any
//! message that is not acknowledged within the retransmit timeout. The receiver
//! hands each message to the caller once, so retransmissions and duplicates do
//! not show up in the output.
//!
//! Ids come from the sender's own counter, separate from the link sequence
//! numbers. Every retransmission is a new link frame, so the link never drops
//! it as a duplicate. Messages can still arrive out of order, because a lost
//! message is sent again after the ones behind it.
//!
//! The window bounds how many messages may be unacknowledged at once. It is
//! capped at 64, so a late retransmission always falls inside the receiver's
//! duplicate window.

use std::collections::BTreeMap;
use std::fmt;

use crate::envelope::{Message, Session};
use crate::link::{LinkError, LinkStats};
use crate::seqwin::{SeqWindow, WINDOW};
use crate::transport::Transport;

/// Settings for a `Channel`. All times are in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Most messages that may be unacknowledged at once. Clamped to 1..=64.
    pub window: usize,
    /// How long an unacknowledged message waits before it is sent again.
    pub retransmit_us: u64,
    /// Heartbeat interval, passed to the underlying `Session`.
    pub heartbeat_us: u64,
    /// Silence after which the peer counts as dead, passed to the `Session`.
    pub timeout_us: u64,
}

/// Errors from `Channel::send`, `poll` and `tick`.
#[derive(Debug)]
pub enum ChannelError<E> {
    /// The underlying link failed.
    Link(LinkError<E>),
    /// The window is full. Poll for acknowledgements, then try again.
    WindowFull,
}

impl<E> From<LinkError<E>> for ChannelError<E> {
    fn from(e: LinkError<E>) -> Self {
        Self::Link(e)
    }
}

impl<E: fmt::Display> fmt::Display for ChannelError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Link(e) => write!(f, "{e}"),
            Self::WindowFull => write!(f, "window is full"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ChannelError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Link(e) => Some(e),
            Self::WindowFull => None,
        }
    }
}

#[derive(Debug)]
struct Pending {
    data: Vec<u8>,
    last_sent_us: u64,
}

/// Delivers each message exactly once, and resends any that are lost.
///
/// ```
/// use tpt_link::Loopback;
/// use tpt_link::reliable::{Channel, Config};
///
/// let config = Config { window: 8, retransmit_us: 10_000, heartbeat_us: 1_000_000, timeout_us: 5_000_000 };
/// let (a, b) = Loopback::pair();
/// let mut tx = Channel::new(a, config);
/// let mut rx = Channel::new(b, config);
///
/// tx.send(b"reading=21.5", 0).unwrap();
/// assert_eq!(rx.poll(0).unwrap(), vec![b"reading=21.5".to_vec()]);
/// tx.poll(0).unwrap(); // collects the acknowledgement
/// assert_eq!(tx.unacked(), 0);
/// ```
#[derive(Debug)]
pub struct Channel<T: Transport> {
    session: Session<T>,
    window: usize,
    retransmit_us: u64,
    next_id: u32,
    unacked: BTreeMap<u32, Pending>,
    received: SeqWindow,
    retransmits: u64,
    duplicates: u64,
}

impl<T: Transport> Channel<T> {
    /// Wraps a transport.
    pub fn new(transport: T, config: Config) -> Self {
        Self {
            session: Session::new(transport, config.heartbeat_us, config.timeout_us),
            window: config.window.clamp(1, WINDOW as usize),
            retransmit_us: config.retransmit_us,
            next_id: 0,
            unacked: BTreeMap::new(),
            received: SeqWindow::default(),
            retransmits: 0,
            duplicates: 0,
        }
    }

    /// Sends `data` and returns its message id. It is kept until acknowledged.
    /// Fails with `WindowFull` when too many messages are unacknowledged.
    pub fn send(&mut self, data: &[u8], now_us: u64) -> Result<u32, ChannelError<T::Error>> {
        if self.unacked.len() >= self.window {
            return Err(ChannelError::WindowFull);
        }
        let id = self.next_id;
        self.session.send_at(
            &Message::Reliable {
                id,
                data: data.to_vec(),
            },
            now_us,
        )?;
        self.next_id = self.next_id.wrapping_add(1);
        self.unacked.insert(
            id,
            Pending {
                data: data.to_vec(),
                last_sent_us: now_us,
            },
        );
        Ok(id)
    }

    /// Returns the messages that arrived for the first time since the last call,
    /// and acknowledges every message that arrived, repeats included. Also
    /// clears the acknowledged messages from the window. Never blocks.
    pub fn poll(&mut self, now_us: u64) -> Result<Vec<Vec<u8>>, ChannelError<T::Error>> {
        let mut delivered = Vec::new();
        for message in self.session.poll_at(now_us)? {
            match message {
                Message::Reliable { id, data } => {
                    // Acknowledge every copy. If an acknowledgement was lost, the
                    // next copy repairs it.
                    self.session.send_at(&Message::Ack { seq: id }, now_us)?;
                    if self.received.accept(id).is_some() {
                        delivered.push(data);
                    } else {
                        self.duplicates += 1;
                    }
                }
                Message::Ack { seq } => {
                    self.unacked.remove(&seq);
                }
                Message::Data(data) => delivered.push(data),
                Message::Heartbeat | Message::Error { .. } => {}
            }
        }
        Ok(delivered)
    }

    /// Sends a heartbeat when one is due, and resends any message whose
    /// acknowledgement is overdue. Call it regularly with the same clock as
    /// `send` and `poll`.
    pub fn tick(&mut self, now_us: u64) -> Result<(), ChannelError<T::Error>> {
        self.session.tick(now_us)?;
        for (&id, pending) in self.unacked.iter_mut() {
            if now_us.saturating_sub(pending.last_sent_us) >= self.retransmit_us {
                self.session.send_at(
                    &Message::Reliable {
                        id,
                        data: pending.data.clone(),
                    },
                    now_us,
                )?;
                pending.last_sent_us = now_us;
                self.retransmits += 1;
            }
        }
        Ok(())
    }

    /// Messages sent but not yet acknowledged.
    pub fn unacked(&self) -> usize {
        self.unacked.len()
    }

    /// Times a message has been sent again.
    pub fn retransmits(&self) -> u64 {
        self.retransmits
    }

    /// Copies of an already delivered message that arrived. Each is acknowledged
    /// but not delivered again.
    pub fn duplicates(&self) -> u64 {
        self.duplicates
    }

    /// Frame-level counters of the underlying link, including frames the link
    /// dropped as repeats.
    pub fn link_stats(&self) -> LinkStats {
        self.session.stats()
    }

    /// True if anything arrived within the timeout before `now_us`.
    pub fn is_alive(&self, now_us: u64) -> bool {
        self.session.is_alive(now_us)
    }

    /// Mutable access to the transport, for example to inject faults in tests.
    pub fn transport_mut(&mut self) -> &mut T {
        self.session.link_mut().transport_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::FaultyTransport;
    use crate::transport::Loopback;

    type Faulty = FaultyTransport<Loopback>;

    fn config(window: usize) -> Config {
        Config {
            window,
            retransmit_us: 10_000,
            heartbeat_us: 1_000_000,
            timeout_us: 10_000_000,
        }
    }

    fn pair(loss_per_million: u32) -> (Channel<Faulty>, Channel<Faulty>) {
        let (a, b) = Loopback::pair();
        let mut a = FaultyTransport::new(a);
        let mut b = FaultyTransport::new(b);
        a.random_loss(loss_per_million, 11);
        b.random_loss(loss_per_million, 12);
        (Channel::new(a, config(8)), Channel::new(b, config(8)))
    }

    #[test]
    fn delivers_everything_exactly_once_over_a_lossy_link() {
        let (mut tx, mut rx) = pair(200_000); // 20 % loss in each direction
        let messages: Vec<Vec<u8>> = (0..50u8).map(|i| vec![i; 3]).collect();

        let mut next = 0;
        let mut now = 0u64;
        let mut got = Vec::new();
        for _ in 0..100_000 {
            while next < messages.len() {
                match tx.send(&messages[next], now) {
                    Ok(_) => next += 1,
                    Err(ChannelError::WindowFull) => break,
                    Err(e) => panic!("{e:?}"),
                }
            }
            tx.tick(now).unwrap();
            rx.tick(now).unwrap();
            got.extend(rx.poll(now).unwrap());
            tx.poll(now).unwrap();
            if next == messages.len() && tx.unacked() == 0 {
                break;
            }
            now += 1_000;
        }

        assert_eq!(tx.unacked(), 0, "some messages were never acknowledged");
        assert!(tx.retransmits() > 0, "loss should have forced a resend");
        got.sort();
        let mut want = messages.clone();
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn window_limits_unacknowledged_messages() {
        let (mut tx, mut rx) = pair(0);
        for i in 0..8u8 {
            tx.send(&[i], 0).unwrap();
        }
        assert!(matches!(
            tx.send(b"ninth", 0),
            Err(ChannelError::WindowFull)
        ));

        assert_eq!(rx.poll(0).unwrap().len(), 8);
        tx.poll(0).unwrap();
        assert_eq!(tx.unacked(), 0);
        assert!(tx.send(b"ninth", 0).is_ok());
    }

    #[test]
    fn lost_message_is_sent_again_after_the_timeout() {
        let (mut tx, mut rx) = pair(0);
        tx.transport_mut().drop_next(1);
        tx.send(b"x", 0).unwrap();
        assert!(rx.poll(0).unwrap().is_empty());

        tx.tick(9_999).unwrap();
        assert_eq!(tx.retransmits(), 0);
        tx.tick(10_000).unwrap();
        assert_eq!(tx.retransmits(), 1);

        assert_eq!(rx.poll(10_000).unwrap(), vec![b"x".to_vec()]);
        tx.poll(10_000).unwrap();
        assert_eq!(tx.unacked(), 0);
    }

    #[test]
    fn repeat_after_a_lost_ack_is_acknowledged_but_delivered_once() {
        let (mut tx, mut rx) = pair(0);
        tx.send(b"d", 0).unwrap();

        // The receiver's acknowledgement is lost, so the sender sends again.
        rx.transport_mut().drop_next(1);
        assert_eq!(rx.poll(0).unwrap(), vec![b"d".to_vec()]);
        tx.tick(10_000).unwrap();
        assert_eq!(tx.retransmits(), 1);

        assert!(rx.poll(10_000).unwrap().is_empty());
        assert_eq!(rx.duplicates(), 1);
        tx.poll(10_000).unwrap();
        assert_eq!(tx.unacked(), 0);
    }

    #[test]
    fn link_drops_a_repeated_frame_before_the_channel_sees_it() {
        let (mut tx, mut rx) = pair(0);
        tx.transport_mut().duplicate_next(1);
        tx.send(b"d", 0).unwrap();

        assert_eq!(rx.poll(0).unwrap(), vec![b"d".to_vec()]);
        assert_eq!(rx.link_stats().duplicates, 1);
        assert_eq!(rx.duplicates(), 0);
    }
}
