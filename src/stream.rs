// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Finds frames in a byte stream. Serial and USB-CDC need this, because they
//! deliver bytes, not datagrams.
//!
//! The frame header holds the length, so the deframer knows where a frame
//! ends and checks its CRC before handing it on. When a frame fails, the
//! deframer drops one byte and scans on, so a damaged frame does not hide the
//! good frame that follows it.
//!
//! A corrupted length field can make the deframer wait for bytes that never
//! come. To prevent this, a deframer built with `with_timeout` gives up on a
//! stalled frame: when no byte has arrived for `timeout_us`, it discards one
//! byte and rescans. The caller supplies the time (principle P4), so the
//! behaviour can be tested exactly.

use crate::frame::{CRC_LEN, HEADER_LEN, MAX_PAYLOAD_LEN, VERSION, crc32};

/// Accumulates bytes and yields whole, CRC-valid frames.
///
/// ```
/// use tpt_link::stream::Deframer;
/// use tpt_link::frame::encode;
///
/// let mut wire = Vec::new();
/// encode(0, b"hi", &mut wire).unwrap();
///
/// let mut d = Deframer::new();
/// // Bytes arrive in pieces, as they do on a serial line.
/// d.push(&wire[..3]);
/// assert_eq!(d.next_frame(), None);
/// d.push(&wire[3..]);
/// assert_eq!(d.next_frame(), Some(wire));
/// ```
///
/// With a timeout, a frame whose length field is corrupted does not stall the
/// stream. The good frame behind it is delivered once the timeout passes.
///
/// ```
/// use tpt_link::stream::Deframer;
/// use tpt_link::frame::encode;
///
/// let mut good = Vec::new();
/// // Sequence 2, not 1: a stale sequence byte equal to VERSION would look like
/// // a frame start, and that costs one extra timeout to get past.
/// encode(2, b"after", &mut good).unwrap();
/// let mut bad = good.clone();
/// bad[5..7].copy_from_slice(&1024u16.to_le_bytes()); // a length within the maximum
///
/// let mut d = Deframer::with_timeout(1_000);
/// d.push_at(&bad[..7], 0);
/// d.push_at(&good, 0);
/// assert_eq!(d.next_frame_at(500), None);  // still within the timeout
/// assert_eq!(d.next_frame_at(1_000), Some(good));
/// assert_eq!(d.timeouts(), 1);
/// ```
#[derive(Debug, Default)]
pub struct Deframer {
    buf: Vec<u8>,
    /// Stall timeout in microseconds. `None` means the deframer never gives up.
    timeout_us: Option<u64>,
    /// Time of the most recent byte received, or of the most recent discard.
    last_activity_us: u64,
    timeouts: u64,
}

impl Deframer {
    /// Creates an empty deframer with no stall timeout.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty deframer that discards a stalled frame after
    /// `timeout_us` without any new bytes. The timeout must be longer than the
    /// longest gap between bytes of a valid frame, or valid frames are lost.
    pub fn with_timeout(timeout_us: u64) -> Self {
        Self {
            timeout_us: Some(timeout_us),
            ..Self::default()
        }
    }

    /// Appends bytes received from the wire.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Appends bytes received at `now_us`. The time is used by `next_frame_at`
    /// to measure stalls.
    pub fn push_at(&mut self, bytes: &[u8], now_us: u64) {
        self.push(bytes);
        self.last_activity_us = now_us;
    }

    /// Like `next_frame`, but applies the stall timeout as of `now_us`. Each
    /// timed-out byte is counted in `timeouts`. Returns `None` when more bytes
    /// are needed.
    pub fn next_frame_at(&mut self, now_us: u64) -> Option<Vec<u8>> {
        loop {
            if let Some(frame) = self.next_frame() {
                return Some(frame);
            }
            // With no frame ready, the buffer is either empty or holds the start
            // of a frame that is still incomplete.
            let timeout_us = self.timeout_us?;
            if self.buf.is_empty() || now_us.saturating_sub(self.last_activity_us) < timeout_us {
                return None;
            }
            self.buf.remove(0);
            self.timeouts += 1;
            self.last_activity_us = now_us;
        }
    }

    /// Number of bytes discarded because a frame stalled past the timeout.
    pub fn timeouts(&self) -> u64 {
        self.timeouts
    }

    /// Returns the next complete, CRC-valid frame, including its header and
    /// CRC so that `frame::decode` can parse it. Returns `None` when more bytes
    /// are needed. This never applies the stall timeout.
    pub fn next_frame(&mut self) -> Option<Vec<u8>> {
        loop {
            if self.buf.first() != Some(&VERSION) {
                // Not at a frame start. Scan forward one byte at a time.
                if self.buf.is_empty() {
                    return None;
                }
                self.buf.remove(0);
                continue;
            }
            if self.buf.len() < HEADER_LEN {
                return None;
            }

            let len = usize::from(u16::from_le_bytes([self.buf[5], self.buf[6]]));
            if len > MAX_PAYLOAD_LEN {
                self.buf.remove(0);
                continue;
            }

            let total = HEADER_LEN + len + CRC_LEN;
            if self.buf.len() < total {
                return None;
            }

            let body_end = total - CRC_LEN;
            let expected = u32::from_le_bytes([
                self.buf[body_end],
                self.buf[body_end + 1],
                self.buf[body_end + 2],
                self.buf[body_end + 3],
            ]);
            if crc32(&self.buf[..body_end]) == expected {
                return Some(self.buf.drain(..total).collect());
            }
            // Bad CRC. This may not be a frame start at all, so move on by one
            // byte rather than skipping the whole claimed length.
            self.buf.remove(0);
        }
    }

    /// Bytes buffered and not yet consumed.
    ///
    /// ```
    /// use tpt_link::stream::Deframer;
    ///
    /// let mut d = Deframer::new();
    /// d.push(&[0x00, 0x00]); // line noise, discarded as soon as a frame is looked for
    /// assert_eq!(d.next_frame(), None);
    /// assert_eq!(d.buffered(), 0);
    /// ```
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{decode, encode};

    fn wire_of(seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        encode(seq, payload, &mut wire).unwrap();
        wire
    }

    #[test]
    fn frame_arriving_one_byte_at_a_time() {
        let wire = wire_of(4, b"piecewise");
        let mut d = Deframer::new();
        for (i, byte) in wire.iter().enumerate() {
            d.push(&[*byte]);
            if i + 1 < wire.len() {
                assert_eq!(d.next_frame(), None, "early frame at byte {i}");
            }
        }
        assert_eq!(d.next_frame(), Some(wire));
    }

    #[test]
    fn two_frames_in_one_read() {
        let a = wire_of(1, b"first");
        let b = wire_of(2, b"second");
        let mut d = Deframer::new();
        d.push(&[a.clone(), b.clone()].concat());
        assert_eq!(d.next_frame(), Some(a));
        assert_eq!(d.next_frame(), Some(b));
        assert_eq!(d.next_frame(), None);
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn line_noise_before_a_frame_is_skipped() {
        let frame = wire_of(7, b"after noise");
        let mut d = Deframer::new();
        d.push(&[0x00, 0xFF, 0x13, 0x77]);
        d.push(&frame);
        assert_eq!(d.next_frame(), Some(frame));
    }

    #[test]
    fn corrupt_frame_does_not_hide_the_next_one() {
        let mut bad = wire_of(1, b"damaged");
        let last = bad.len() - 1;
        bad[last] ^= 0x40;
        let good = wire_of(2, b"intact");

        let mut d = Deframer::new();
        d.push(&[bad, good.clone()].concat());
        assert_eq!(d.next_frame(), Some(good));
    }

    #[test]
    fn version_byte_inside_a_payload_does_not_confuse_it() {
        // The payload contains a byte equal to VERSION, which must not be read
        // as a frame start.
        let frame = wire_of(3, &[VERSION, VERSION, 0, 0, 0, 0, 0]);
        let mut d = Deframer::new();
        d.push(&frame);
        let got = d.next_frame().unwrap();
        assert_eq!(
            decode(&got).unwrap().0.payload,
            &[VERSION, VERSION, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn oversize_length_is_skipped() {
        let mut d = Deframer::new();
        // Version, seq, then a length of 0xFFFF, which is above the maximum.
        d.push(&[VERSION, 0, 0, 0, 0, 0xFF, 0xFF]);
        assert_eq!(d.next_frame(), None);
        let frame = wire_of(9, b"ok");
        d.push(&frame);
        assert_eq!(d.next_frame(), Some(frame));
    }

    /// A frame header whose length claims 1024 bytes, which never arrive.
    fn stalled_header() -> Vec<u8> {
        let mut header = wire_of(5, b"x")[..HEADER_LEN].to_vec();
        header[5..7].copy_from_slice(&1024u16.to_le_bytes());
        header
    }

    #[test]
    fn corrupted_length_stalls_then_recovers() {
        let good = wire_of(6, b"behind the bad length");
        let mut d = Deframer::with_timeout(1_000);
        d.push_at(&stalled_header(), 0);
        d.push_at(&good, 0);
        assert_eq!(d.next_frame_at(999), None);
        assert_eq!(d.timeouts(), 0);
        assert_eq!(d.next_frame_at(1_000), Some(good));
        assert_eq!(d.timeouts(), 1);
    }

    #[test]
    fn stalled_header_with_nothing_behind_it_is_cleared() {
        let mut d = Deframer::with_timeout(1_000);
        d.push_at(&stalled_header(), 0);
        assert_eq!(d.next_frame_at(999), None);
        assert_eq!(d.buffered(), HEADER_LEN);
        assert_eq!(d.next_frame_at(1_000), None);
        assert_eq!(d.timeouts(), 1);
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn slow_but_valid_frame_is_not_timed_out() {
        let frame = wire_of(8, b"slow sender");
        let mut d = Deframer::with_timeout(1_000);
        let mut now = 0;
        let mut chunks = frame.chunks(3).peekable();
        while let Some(chunk) = chunks.next() {
            d.push_at(chunk, now);
            if chunks.peek().is_none() {
                assert_eq!(d.next_frame_at(now), Some(frame.clone()));
            } else {
                // Each gap is shorter than the timeout, so the frame must survive.
                now += 900;
                assert_eq!(d.next_frame_at(now), None);
            }
        }
        assert_eq!(d.timeouts(), 0);
    }

    #[test]
    fn deframer_without_timeout_never_discards_on_time_alone() {
        let mut d = Deframer::new();
        d.push_at(&stalled_header(), 0);
        assert_eq!(d.next_frame_at(u64::MAX), None);
        assert_eq!(d.timeouts(), 0);
        assert_eq!(d.buffered(), HEADER_LEN);
    }
}
