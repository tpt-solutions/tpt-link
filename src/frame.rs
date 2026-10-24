// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Link frame format: version, sequence number, length prefix, payload and CRC.
//!
//! Layout (little-endian):
//!
//! | field    | size    | notes                                   |
//! | -------- | ------- | --------------------------------------- |
//! | version  | 1 byte  | `VERSION`, currently 1                  |
//! | seq      | 4 bytes | per-sender counter, wraps at `u32::MAX` |
//! | length   | 2 bytes | payload length, at most `MAX_PAYLOAD_LEN` |
//! | payload  | n bytes |                                         |
//! | crc      | 4 bytes | CRC-32 (IEEE) over everything above     |
//!
//! The CRC is written in-house so the crate stays dependency-free and `no_std`
//! friendly. Decoding needs only `core`. Encoding needs the `alloc` feature.

use core::fmt;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Current frame format version.
pub const VERSION: u8 = 1;
/// Bytes before the payload: version, seq and length.
pub const HEADER_LEN: usize = 1 + 4 + 2;
/// Bytes after the payload: the CRC.
pub const CRC_LEN: usize = 4;
/// Largest payload a single frame may carry. CAN fragmentation builds on this.
pub const MAX_PAYLOAD_LEN: usize = 1024;

/// CRC-32 (IEEE 802.3, reflected polynomial `0xEDB88320`).
///
/// ```
/// use tpt_link::frame::crc32;
///
/// assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
/// ```
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Why a frame could not be encoded or decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The buffer ends before the frame does.
    Truncated,
    /// The version byte is not one this build understands.
    BadVersion(u8),
    /// The payload is longer than `MAX_PAYLOAD_LEN`.
    TooLarge(usize),
    /// The CRC in the frame does not match the bytes received.
    BadCrc {
        /// CRC carried in the frame.
        expected: u32,
        /// CRC computed over the received bytes.
        actual: u32,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "frame is truncated"),
            Self::BadVersion(v) => write!(f, "unsupported frame version {v}"),
            Self::TooLarge(len) => write!(f, "payload of {len} bytes exceeds {MAX_PAYLOAD_LEN}"),
            Self::BadCrc { expected, actual } => {
                write!(
                    f,
                    "CRC mismatch: frame has {expected:#010x}, computed {actual:#010x}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FrameError {}

/// A decoded frame. The payload borrows from the buffer it was decoded from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Sender's sequence number for this frame.
    pub seq: u32,
    /// Payload bytes.
    pub payload: &'a [u8],
}

/// Appends an encoded frame to `out`. Needs the `alloc` feature.
///
/// ```
/// use tpt_link::frame::{decode, encode};
///
/// let mut wire = Vec::new();
/// encode(7, b"hello", &mut wire).unwrap();
/// let (frame, used) = decode(&wire).unwrap();
/// assert_eq!(frame.seq, 7);
/// assert_eq!(frame.payload, b"hello");
/// assert_eq!(used, wire.len());
/// ```
#[cfg(feature = "alloc")]
pub fn encode(seq: u32, payload: &[u8], out: &mut Vec<u8>) -> Result<(), FrameError> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(FrameError::TooLarge(payload.len()));
    }
    // Checked above, so this always fits in the two-byte length field.
    let len = u16::try_from(payload.len()).map_err(|_| FrameError::TooLarge(payload.len()))?;

    let start = out.len();
    out.push(VERSION);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    let crc = crc32(&out[start..]);
    out.extend_from_slice(&crc.to_le_bytes());
    Ok(())
}

/// Decodes the frame at the start of `buf`. Returns the frame and the number of
/// bytes it occupied, so that back-to-back frames can be decoded in turn.
pub fn decode(buf: &[u8]) -> Result<(Frame<'_>, usize), FrameError> {
    let version = *buf.first().ok_or(FrameError::Truncated)?;
    if buf.len() < HEADER_LEN {
        return Err(FrameError::Truncated);
    }
    if version != VERSION {
        return Err(FrameError::BadVersion(version));
    }

    let seq = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let len = usize::from(u16::from_le_bytes([buf[5], buf[6]]));
    if len > MAX_PAYLOAD_LEN {
        return Err(FrameError::TooLarge(len));
    }

    let body_end = HEADER_LEN + len;
    let total = body_end + CRC_LEN;
    if buf.len() < total {
        return Err(FrameError::Truncated);
    }

    let expected = u32::from_le_bytes([
        buf[body_end],
        buf[body_end + 1],
        buf[body_end + 2],
        buf[body_end + 3],
    ]);
    let actual = crc32(&buf[..body_end]);
    if expected != actual {
        return Err(FrameError::BadCrc { expected, actual });
    }

    Ok((
        Frame {
            seq,
            payload: &buf[HEADER_LEN..body_end],
        },
        total,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn round_trip_including_empty_and_max_payload() {
        for payload in [Vec::new(), b"x".to_vec(), vec![0xA5; MAX_PAYLOAD_LEN]] {
            let mut wire = Vec::new();
            encode(42, &payload, &mut wire).unwrap();
            let (frame, used) = decode(&wire).unwrap();
            assert_eq!(frame.seq, 42);
            assert_eq!(frame.payload, payload.as_slice());
            assert_eq!(used, wire.len());
        }
    }

    #[test]
    fn back_to_back_frames_decode_in_turn() {
        let mut wire = Vec::new();
        encode(1, b"first", &mut wire).unwrap();
        encode(2, b"second", &mut wire).unwrap();

        let (a, used_a) = decode(&wire).unwrap();
        let (b, used_b) = decode(&wire[used_a..]).unwrap();
        assert_eq!((a.seq, a.payload), (1, &b"first"[..]));
        assert_eq!((b.seq, b.payload), (2, &b"second"[..]));
        assert_eq!(used_a + used_b, wire.len());
    }

    #[test]
    fn any_single_bit_flip_is_detected() {
        let mut wire = Vec::new();
        encode(9, b"reflex", &mut wire).unwrap();
        for i in 0..wire.len() {
            for bit in 0..8 {
                let mut bad = wire.clone();
                bad[i] ^= 1 << bit;
                assert!(
                    decode(&bad).is_err(),
                    "flip at byte {i} bit {bit} went undetected"
                );
            }
        }
    }

    #[test]
    fn truncated_buffers_are_rejected() {
        let mut wire = Vec::new();
        encode(3, b"abc", &mut wire).unwrap();
        for cut in 0..wire.len() {
            assert_eq!(
                decode(&wire[..cut]),
                Err(FrameError::Truncated),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn bad_version_is_rejected() {
        let mut wire = Vec::new();
        encode(0, b"", &mut wire).unwrap();
        wire[0] = 2;
        assert_eq!(decode(&wire), Err(FrameError::BadVersion(2)));
    }

    #[test]
    fn oversize_payload_is_rejected_on_encode_and_decode() {
        let too_big = vec![0; MAX_PAYLOAD_LEN + 1];
        assert_eq!(
            encode(0, &too_big, &mut Vec::new()),
            Err(FrameError::TooLarge(too_big.len()))
        );

        let mut wire = vec![VERSION, 0, 0, 0, 0];
        wire.extend_from_slice(&u16::try_from(MAX_PAYLOAD_LEN + 1).unwrap().to_le_bytes());
        assert_eq!(
            decode(&wire),
            Err(FrameError::TooLarge(MAX_PAYLOAD_LEN + 1))
        );
    }
}
