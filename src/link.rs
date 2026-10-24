// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! `Link` adds sequence numbers, framing and loss statistics on top of a
//! transport. `Heartbeat` tracks whether the peer is still alive.

use std::fmt;

use crate::frame::{self, FrameError};

use crate::transport::Transport;

/// Counters kept by a `Link`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkStats {
    /// Frames sent.
    pub sent: u64,
    /// Valid frames received.
    pub received: u64,
    /// Frames that failed the CRC check.
    pub crc_errors: u64,
    /// Frames with a version this build does not understand.
    pub bad_version: u64,
    /// Frames that could not be parsed for any other reason.
    pub malformed: u64,
    /// Frames the peer sent that never arrived, found from sequence gaps.
    pub lost: u64,
}

/// Errors from `Link::send` and `Link::poll`.
#[derive(Debug)]
pub enum LinkError<E> {
    /// The transport failed.
    Transport(E),
    /// The payload could not be framed, for example because it is too large.
    Frame(FrameError),
}

impl<E: fmt::Display> fmt::Display for LinkError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Frame(e) => write!(f, "frame: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for LinkError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            Self::Frame(e) => Some(e),
        }
    }
}

/// A framed, sequenced link over a transport.
///
/// Damaged frames are counted and dropped, and they never reach the caller.
/// Gaps in the sequence numbers are counted as lost frames.
///
/// Loss is only detectable after the first frame has been received. The
/// receiver has no expected sequence number until then, so frames lost before
/// that point are not counted.
///
/// ```
/// use tpt_link::{Link, Loopback};
///
/// let (a, b) = Loopback::pair();
/// let mut a = Link::new(a);
/// let mut b = Link::new(b);
/// a.send(b"hello").unwrap();
/// assert_eq!(b.poll().unwrap(), vec![b"hello".to_vec()]);
/// ```
#[derive(Debug)]
pub struct Link<T: Transport> {
    transport: T,
    next_seq: u32,
    expected_seq: Option<u32>,
    pending_error: Option<T::Error>,
    stats: LinkStats,
}

/// How far back a sequence number may step and still count as a reordered or
/// duplicate frame rather than a peer restart.
const REORDER_WINDOW: u32 = 64;

impl<T: Transport> Link<T> {
    /// Wraps a transport.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_seq: 0,
            expected_seq: None,
            pending_error: None,
            stats: LinkStats::default(),
        }
    }

    /// Mutable access to the transport, for example to inject faults in tests.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Sets the sequence number the next `send` will use.
    ///
    /// ```
    /// use tpt_link::{Link, Loopback};
    ///
    /// let (a, _b) = Loopback::pair();
    /// let mut a = Link::new(a);
    /// a.set_next_seq(u32::MAX);
    /// assert_eq!(a.send(b"last").unwrap(), u32::MAX);
    /// assert_eq!(a.send(b"wrapped").unwrap(), 0);
    /// ```
    pub fn set_next_seq(&mut self, seq: u32) {
        self.next_seq = seq;
    }

    /// Frames and sends `payload`, and returns the sequence number it used.
    ///
    /// ```
    /// use tpt_link::{Link, Loopback};
    ///
    /// let (a, _b) = Loopback::pair();
    /// let mut a = Link::new(a);
    /// assert_eq!(a.send(b"first").unwrap(), 0);
    /// assert_eq!(a.send(b"second").unwrap(), 1);
    /// assert_eq!(a.stats().sent, 2);
    /// ```
    pub fn send(&mut self, payload: &[u8]) -> Result<u32, LinkError<T::Error>> {
        let seq = self.next_seq;
        let mut wire = Vec::new();
        frame::encode(seq, payload, &mut wire).map_err(LinkError::Frame)?;
        self.transport.send(&wire).map_err(LinkError::Transport)?;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.stats.sent += 1;
        Ok(seq)
    }

    /// Returns every valid payload that has arrived, in order. Never blocks.
    ///
    /// If the transport fails after some payloads were already received, those
    /// payloads are returned first and the error is reported by the next call.
    /// A datagram holding several frames yields all of them.
    pub fn poll(&mut self) -> Result<Vec<Vec<u8>>, LinkError<T::Error>> {
        if let Some(e) = self.pending_error.take() {
            return Err(LinkError::Transport(e));
        }
        let mut payloads = Vec::new();
        loop {
            let bytes = match self.transport.try_recv() {
                Ok(Some(bytes)) => bytes,
                Ok(None) => break,
                Err(e) if payloads.is_empty() => return Err(LinkError::Transport(e)),
                Err(e) => {
                    self.pending_error = Some(e);
                    break;
                }
            };
            let mut rest = &bytes[..];
            while !rest.is_empty() {
                match frame::decode(rest) {
                    Ok((decoded, used)) => {
                        self.note_sequence(decoded.seq);
                        self.stats.received += 1;
                        payloads.push(decoded.payload.to_vec());
                        rest = &rest[used..];
                    }
                    Err(FrameError::BadCrc { .. }) => {
                        self.stats.crc_errors += 1;
                        break;
                    }
                    Err(FrameError::BadVersion(_)) => {
                        self.stats.bad_version += 1;
                        break;
                    }
                    Err(_) => {
                        self.stats.malformed += 1;
                        break;
                    }
                }
            }
        }
        Ok(payloads)
    }

    /// Counters for this link.
    pub fn stats(&self) -> LinkStats {
        self.stats
    }

    /// Gives back the underlying transport.
    ///
    /// ```
    /// use tpt_link::{Link, Loopback};
    ///
    /// let (a, _b) = Loopback::pair();
    /// let link = Link::new(a);
    /// let _transport: Loopback = link.into_inner();
    /// ```
    pub fn into_inner(self) -> T {
        self.transport
    }

    fn note_sequence(&mut self, seq: u32) {
        if let Some(expected) = self.expected_seq {
            // A forward gap counts as loss. A small backward step (a duplicate
            // or a reordered frame) is ignored and does not move the expected
            // number, so the frames after it are not counted as lost. A large
            // backward jump is taken as a peer restart and resyncs. The
            // threshold is half the sequence space, so wraparound is handled.
            let gap = seq.wrapping_sub(expected);
            if gap == 0 {
                self.expected_seq = Some(seq.wrapping_add(1));
            } else if gap < 0x8000_0000 {
                self.stats.lost += u64::from(gap);
                self.expected_seq = Some(seq.wrapping_add(1));
            } else if expected.wrapping_sub(seq) > REORDER_WINDOW {
                self.expected_seq = Some(seq.wrapping_add(1));
            }
        } else {
            self.expected_seq = Some(seq.wrapping_add(1));
        }
    }
}

/// Tracks whether the peer has been heard from recently.
///
/// The caller feeds it the time of every received frame. `is_alive` is false
/// once nothing has arrived for longer than the timeout.
///
/// ```
/// use tpt_link::Heartbeat;
///
/// let mut hb = Heartbeat::new(100_000);
/// hb.on_frame(0);
/// assert!(hb.is_alive(100_000));
/// assert!(!hb.is_alive(100_001));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heartbeat {
    timeout_us: u64,
    last_seen_us: Option<u64>,
}

impl Heartbeat {
    /// Creates a monitor with the given timeout, in microseconds.
    pub fn new(timeout_us: u64) -> Self {
        Self {
            timeout_us,
            last_seen_us: None,
        }
    }

    /// Records that a frame arrived at `now_us`.
    pub fn on_frame(&mut self, now_us: u64) {
        self.last_seen_us = Some(now_us);
    }

    /// True if a frame arrived within the timeout before `now_us`.
    pub fn is_alive(&self, now_us: u64) -> bool {
        self.last_seen_us
            .is_some_and(|seen| now_us.saturating_sub(seen) <= self.timeout_us)
    }
}
