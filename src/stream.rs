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
//! One weakness: a corrupted length field can make the deframer wait for bytes
//! that never come, which stalls the stream until enough data has arrived.
//! Closing that gap needs a timeout, and that is future work.

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
#[derive(Debug, Default)]
pub struct Deframer {
    buf: Vec<u8>,
}

impl Deframer {
    /// Creates an empty deframer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends bytes received from the wire.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Returns the next complete, CRC-valid frame, including its header and
    /// CRC so that `frame::decode` can parse it. Returns `None` when more bytes
    /// are needed.
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
}
