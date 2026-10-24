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
    /// Valid frames dropped because the same sequence number had already
    /// arrived. They are not delivered again.
    pub duplicates: u64,
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
/// Gaps in the sequence numbers are counted as lost frames. A frame that
/// repeats a sequence number already seen is dropped and counted as a duplicate.
/// A frame that arrives late, after a higher number, is delivered and fills in
/// its earlier gap as long as it is within the last 64 sequence numbers.
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
    /// Highest sequence number received so far.
    highest: Option<u32>,
    /// Bit `n` is set when `highest - n` has arrived. One bit per number in the
    /// window, so the window is `u64::BITS` wide.
    seen: u64,
    pending_error: Option<T::Error>,
    stats: LinkStats,
}

/// How far behind the highest sequence number a frame may arrive and still be
/// checked against the window. Anything further back is a peer restart.
const WINDOW: u32 = u64::BITS;

impl<T: Transport> Link<T> {
    /// Wraps a transport.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_seq: 0,
            highest: None,
            seen: 0,
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
                        if self.note_sequence(decoded.seq) {
                            self.stats.received += 1;
                            payloads.push(decoded.payload.to_vec());
                        } else {
                            self.stats.duplicates += 1;
                        }
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

    /// Records an arriving sequence number. Returns `true` if the frame is new
    /// and should be delivered, and `false` for a duplicate.
    fn note_sequence(&mut self, seq: u32) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(seq);
            self.seen = 1;
            return true;
        };

        // Distances wrap, and the half of the sequence space above zero counts
        // as ahead. This keeps wraparound working.
        let ahead = seq.wrapping_sub(highest);
        if ahead == 0 {
            return false;
        }
        if ahead < 0x8000_0000 {
            // The numbers between the old highest and this one are missing so
            // far. A late arrival may still fill them in.
            self.stats.lost += u64::from(ahead - 1);
            self.seen = if ahead >= WINDOW {
                0
            } else {
                self.seen << ahead
            };
            self.seen |= 1;
            self.highest = Some(seq);
            return true;
        }

        let behind = highest.wrapping_sub(seq);
        if behind >= WINDOW {
            // Too far back to be a late frame, so the peer has restarted.
            self.seen = 1;
            self.highest = Some(seq);
            return true;
        }
        let bit = 1u64 << behind;
        if self.seen & bit != 0 {
            return false;
        }
        // A late frame that fills an earlier gap. It was already counted as
        // lost, and it is not taken back out.
        self.seen |= bit;
        true
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
