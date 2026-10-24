// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! An optional message layer on top of `Link`. The first payload byte is a
//! message type, so a receiver can tell data from a heartbeat, an
//! acknowledgement or an error report. The frame format is unchanged: this is
//! only a convention for what goes in the payload, and a `Link` used without it
//! behaves exactly as before.
//!
//! | type | name      | body                        |
//! | ---- | --------- | --------------------------- |
//! | 0    | Data      | any bytes (the application) |
//! | 1    | Heartbeat | empty                       |
//! | 2    | Ack       | sequence number, u32 LE     |
//! | 3    | Error     | error code, u32 LE          |
//!
//! `Session` wraps a `Link` and uses the layer: it sends heartbeats on a
//! schedule and treats every received message as a sign of life.

use std::fmt;

use crate::link::{Heartbeat, Link, LinkError, LinkStats};
use crate::transport::Transport;

const TYPE_DATA: u8 = 0;
const TYPE_HEARTBEAT: u8 = 1;
const TYPE_ACK: u8 = 2;
const TYPE_ERROR: u8 = 3;

/// One message carried in a frame payload.
///
/// ```
/// use tpt_link::envelope::Message;
///
/// let wire = Message::Ack { seq: 7 }.encode();
/// assert_eq!(Message::decode(&wire).unwrap(), Message::Ack { seq: 7 });
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Application data.
    Data(Vec<u8>),
    /// The sender is alive. Carries nothing else.
    Heartbeat,
    /// The sender received the frame with this sequence number.
    Ack {
        /// Sequence number being acknowledged.
        seq: u32,
    },
    /// The sender reports a problem.
    Error {
        /// Application-defined error code.
        code: u32,
    },
}

/// Why a payload is not a valid message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The payload is empty, so it has no type byte.
    Empty,
    /// The type byte is not one this version knows.
    UnknownType(u8),
    /// The body is the wrong length for its type.
    BadLength {
        /// Type byte of the message.
        kind: u8,
        /// Body length found.
        len: usize,
    },
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty message"),
            Self::UnknownType(t) => write!(f, "unknown message type {t}"),
            Self::BadLength { kind, len } => {
                write!(f, "message type {kind} cannot have a body of {len} bytes")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

impl Message {
    /// The bytes to send as a frame payload.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Data(body) => {
                let mut out = Vec::with_capacity(1 + body.len());
                out.push(TYPE_DATA);
                out.extend_from_slice(body);
                out
            }
            Self::Heartbeat => vec![TYPE_HEARTBEAT],
            Self::Ack { seq } => tagged_u32(TYPE_ACK, *seq),
            Self::Error { code } => tagged_u32(TYPE_ERROR, *code),
        }
    }

    /// Parses a received frame payload.
    pub fn decode(payload: &[u8]) -> Result<Self, EnvelopeError> {
        let (&kind, body) = payload.split_first().ok_or(EnvelopeError::Empty)?;
        let bad_length = || EnvelopeError::BadLength {
            kind,
            len: body.len(),
        };
        let u32_body = || {
            <[u8; 4]>::try_from(body)
                .map(u32::from_le_bytes)
                .map_err(|_| bad_length())
        };
        match kind {
            TYPE_DATA => Ok(Self::Data(body.to_vec())),
            TYPE_HEARTBEAT if body.is_empty() => Ok(Self::Heartbeat),
            TYPE_HEARTBEAT => Err(bad_length()),
            TYPE_ACK => Ok(Self::Ack { seq: u32_body()? }),
            TYPE_ERROR => Ok(Self::Error { code: u32_body()? }),
            other => Err(EnvelopeError::UnknownType(other)),
        }
    }
}

fn tagged_u32(kind: u8, value: u32) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&value.to_le_bytes());
    out
}

/// A `Link` plus the message layer, automatic heartbeats and liveness.
///
/// Time is passed in (principle P4), so behaviour is exact in tests. Call
/// `tick` and `poll_at` regularly with the same clock.
///
/// ```
/// use tpt_link::{Loopback, envelope::{Message, Session}};
///
/// let (a, b) = Loopback::pair();
/// // Heartbeat every 100 ms; the peer is dead after 300 ms of silence.
/// let mut a = Session::new(a, 100_000, 300_000);
/// let mut b = Session::new(b, 100_000, 300_000);
///
/// a.tick(0).unwrap();                          // sends the first heartbeat
/// assert_eq!(b.poll_at(1_000).unwrap(), vec![Message::Heartbeat]);
/// assert!(b.is_alive(2_000));
/// assert!(!b.is_alive(400_000));               // nothing since 1 ms
/// ```
#[derive(Debug)]
pub struct Session<T: Transport> {
    link: Link<T>,
    liveness: Heartbeat,
    interval_us: u64,
    last_sent_us: Option<u64>,
    bad_messages: u64,
}

impl<T: Transport> Session<T> {
    /// Wraps a transport. A heartbeat is sent by `tick` every `interval_us`,
    /// and the peer counts as dead after `timeout_us` without any message.
    pub fn new(transport: T, interval_us: u64, timeout_us: u64) -> Self {
        Self {
            link: Link::new(transport),
            liveness: Heartbeat::new(timeout_us),
            interval_us,
            last_sent_us: None,
            bad_messages: 0,
        }
    }

    /// Sends one message and returns the frame's sequence number. This does
    /// not postpone the next heartbeat; use `send_at` for that.
    pub fn send(&mut self, message: &Message) -> Result<u32, LinkError<T::Error>> {
        self.link.send(&message.encode())
    }

    /// Sends application data.
    pub fn send_data(&mut self, body: &[u8]) -> Result<u32, LinkError<T::Error>> {
        self.send(&Message::Data(body.to_vec()))
    }

    /// Like `send`, and counts as traffic at `now_us`, so the next heartbeat
    /// is postponed by one interval.
    pub fn send_at(&mut self, message: &Message, now_us: u64) -> Result<u32, LinkError<T::Error>> {
        let seq = self.send(message)?;
        self.last_sent_us = Some(now_us);
        Ok(seq)
    }

    /// Sends a heartbeat if nothing has gone out for the interval. The first
    /// call always sends one.
    pub fn tick(&mut self, now_us: u64) -> Result<(), LinkError<T::Error>> {
        let due = self
            .last_sent_us
            .is_none_or(|last| now_us.saturating_sub(last) >= self.interval_us);
        if due {
            self.send_at(&Message::Heartbeat, now_us)?;
        }
        Ok(())
    }

    /// Returns every message that has arrived. Each valid frame, whatever it
    /// carries, counts as a sign of life at `now_us`. Payloads that are not valid
    /// messages are dropped and counted in `bad_messages`. Never blocks.
    pub fn poll_at(&mut self, now_us: u64) -> Result<Vec<Message>, LinkError<T::Error>> {
        let payloads = self.link.poll()?;
        let mut messages = Vec::with_capacity(payloads.len());
        for payload in payloads {
            self.liveness.on_frame(now_us);
            match Message::decode(&payload) {
                Ok(message) => messages.push(message),
                Err(_) => self.bad_messages += 1,
            }
        }
        Ok(messages)
    }

    /// True if a message arrived within the timeout before `now_us`.
    pub fn is_alive(&self, now_us: u64) -> bool {
        self.liveness.is_alive(now_us)
    }

    /// Payloads that were valid frames but not valid messages.
    pub fn bad_messages(&self) -> u64 {
        self.bad_messages
    }

    /// Frame-level counters of the underlying link.
    pub fn stats(&self) -> LinkStats {
        self.link.stats()
    }

    /// Mutable access to the underlying link.
    pub fn link_mut(&mut self) -> &mut Link<T> {
        &mut self.link
    }

    /// Gives back the underlying link.
    pub fn into_link(self) -> Link<T> {
        self.link
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Loopback;

    fn pair() -> (Session<Loopback>, Session<Loopback>) {
        let (a, b) = Loopback::pair();
        (Session::new(a, 100, 300), Session::new(b, 100, 300))
    }

    #[test]
    fn every_message_round_trips() {
        for message in [
            Message::Data(vec![]),
            Message::Data(b"hello".to_vec()),
            Message::Heartbeat,
            Message::Ack { seq: u32::MAX },
            Message::Error { code: 300 },
        ] {
            assert_eq!(Message::decode(&message.encode()).unwrap(), message);
        }
    }

    #[test]
    fn bad_payloads_are_rejected() {
        assert_eq!(Message::decode(&[]), Err(EnvelopeError::Empty));
        assert_eq!(Message::decode(&[9]), Err(EnvelopeError::UnknownType(9)));
        assert_eq!(
            Message::decode(&[TYPE_ACK, 1, 2]),
            Err(EnvelopeError::BadLength {
                kind: TYPE_ACK,
                len: 2
            })
        );
        assert_eq!(
            Message::decode(&[TYPE_HEARTBEAT, 0]),
            Err(EnvelopeError::BadLength {
                kind: TYPE_HEARTBEAT,
                len: 1
            })
        );
    }

    #[test]
    fn heartbeats_follow_the_interval() {
        let (mut a, mut b) = pair();
        a.tick(0).unwrap();
        a.tick(50).unwrap(); // too soon
        a.tick(100).unwrap();
        assert_eq!(b.poll_at(100).unwrap(), vec![Message::Heartbeat; 2]);
    }

    #[test]
    fn data_keeps_the_peer_alive_and_postpones_heartbeats() {
        let (mut a, mut b) = pair();
        a.send_at(&Message::Data(b"x".to_vec()), 0).unwrap();
        a.tick(50).unwrap(); // data went out at 0, so no heartbeat is due
        assert_eq!(b.poll_at(10).unwrap(), vec![Message::Data(b"x".to_vec())]);
        assert!(b.is_alive(310));
        assert!(!b.is_alive(311));
    }

    #[test]
    fn silence_is_detected_and_traffic_revives_the_peer() {
        let (mut a, mut b) = pair();
        assert!(!b.is_alive(0)); // nothing heard yet
        a.tick(0).unwrap();
        b.poll_at(0).unwrap();
        assert!(b.is_alive(300));
        assert!(!b.is_alive(301));
        a.tick(1_000).unwrap();
        b.poll_at(1_000).unwrap();
        assert!(b.is_alive(1_100));
    }

    #[test]
    fn invalid_messages_are_counted_but_still_show_life() {
        let (a, b) = Loopback::pair();
        let mut raw = Link::new(a);
        let mut session = Session::new(b, 100, 300);
        raw.send(&[42]).unwrap(); // unknown type
        assert!(session.poll_at(5).unwrap().is_empty());
        assert_eq!(session.bad_messages(), 1);
        assert!(session.is_alive(5));
    }
}
