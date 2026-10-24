// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Splits a message into fragments that fit a small MTU, and reassembles them.
//!
//! CAN carries 8 bytes per frame (classic) or 64 (CAN-FD). A link frame can be
//! up to `MAX_PAYLOAD_LEN` bytes, so it is split before it goes on the bus.
//!
//! Fragment layout, 3-byte header then data:
//!
//! | byte | meaning                                        |
//! | ---- | ---------------------------------------------- |
//! | 0    | message id, to tell interleaved messages apart |
//! | 1    | fragment index, from 0                         |
//! | 2    | fragment count minus one                       |
//!
//! The MTU is a parameter, so the same code serves classic CAN (8) and CAN-FD
//! (64). The receiver knows a message is complete once every index has
//! arrived, so no separate end flag is needed.

use std::collections::HashMap;
use std::fmt;

/// Header bytes in every fragment.
pub const HEADER_LEN: usize = 3;
/// Most fragments one message can use. The count is stored as a byte, minus one.
pub const MAX_FRAGMENTS: usize = 256;

/// Why a message could not be fragmented or reassembled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentError {
    /// The MTU leaves no room for data after the header.
    InvalidMtu(usize),
    /// The message needs more than `MAX_FRAGMENTS` fragments at this MTU.
    TooLarge {
        /// Length of the message that was rejected.
        len: usize,
        /// Largest message this MTU can carry.
        max: usize,
    },
    /// A fragment is shorter than the header, or its index is out of range.
    Malformed,
}

impl fmt::Display for FragmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMtu(mtu) => write!(f, "MTU {mtu} leaves no room for data"),
            Self::TooLarge { len, max } => write!(f, "message of {len} bytes exceeds {max}"),
            Self::Malformed => write!(f, "malformed fragment"),
        }
    }
}

impl std::error::Error for FragmentError {}

/// Splits `payload` into fragments of at most `mtu` bytes each, header
/// included. An empty payload becomes one fragment with no data.
///
/// ```
/// use tpt_link::fragment::{split, Reassembler};
///
/// let frames = split(1, b"twelve bytes", 8).unwrap();
/// assert_eq!(frames.len(), 3); // 5 data bytes per classic CAN frame
///
/// let mut rx = Reassembler::new(1_000_000);
/// let mut out = None;
/// for frame in &frames {
///     out = rx.push(0, frame).unwrap().or(out);
/// }
/// assert_eq!(out.as_deref(), Some(&b"twelve bytes"[..]));
/// ```
pub fn split(msg_id: u8, payload: &[u8], mtu: usize) -> Result<Vec<Vec<u8>>, FragmentError> {
    if mtu <= HEADER_LEN {
        return Err(FragmentError::InvalidMtu(mtu));
    }
    let chunk = mtu - HEADER_LEN;
    let count = payload.len().div_ceil(chunk).max(1);
    if count > MAX_FRAGMENTS {
        return Err(FragmentError::TooLarge {
            len: payload.len(),
            max: MAX_FRAGMENTS * chunk,
        });
    }

    let frames = (0..count)
        .map(|i| {
            let start = (i * chunk).min(payload.len());
            let end = (start + chunk).min(payload.len());
            let mut frame = Vec::with_capacity(HEADER_LEN + end - start);
            // `count` is at most 256, so both casts fit a byte.
            frame.push(msg_id);
            frame.push(i as u8);
            frame.push((count - 1) as u8);
            frame.extend_from_slice(&payload[start..end]);
            frame
        })
        .collect();
    Ok(frames)
}

#[derive(Debug)]
struct Partial {
    count: usize,
    parts: Vec<Option<Vec<u8>>>,
    received: usize,
    started_us: u64,
}

impl Partial {
    fn new(count: usize, started_us: u64) -> Self {
        Self {
            count,
            parts: vec![None; count],
            received: 0,
            started_us,
        }
    }
}

/// Rebuilds messages from fragments, in any arrival order.
///
/// Partial messages expire after `timeout_us`, measured from their first
/// fragment. Call `expire` periodically so that lost fragments do not leak
/// memory.
#[derive(Debug)]
pub struct Reassembler {
    timeout_us: u64,
    pending: HashMap<u8, Partial>,
}

impl Reassembler {
    /// Creates an empty reassembler.
    pub fn new(timeout_us: u64) -> Self {
        Self {
            timeout_us,
            pending: HashMap::new(),
        }
    }

    /// Accepts one fragment. Returns the whole message when this fragment
    /// completes it, and `None` otherwise. A repeated fragment is ignored.
    pub fn push(&mut self, now_us: u64, fragment: &[u8]) -> Result<Option<Vec<u8>>, FragmentError> {
        if fragment.len() < HEADER_LEN {
            return Err(FragmentError::Malformed);
        }
        let msg_id = fragment[0];
        let index = usize::from(fragment[1]);
        let count = usize::from(fragment[2]) + 1;
        if index >= count {
            return Err(FragmentError::Malformed);
        }

        let entry = self
            .pending
            .entry(msg_id)
            .or_insert_with(|| Partial::new(count, now_us));
        // The id was reused by a different message, so start again.
        if entry.count != count {
            *entry = Partial::new(count, now_us);
        }
        if entry.parts[index].is_none() {
            entry.parts[index] = Some(fragment[HEADER_LEN..].to_vec());
            entry.received += 1;
        }
        if entry.received < entry.count {
            return Ok(None);
        }

        let done = self
            .pending
            .remove(&msg_id)
            .expect("entry was present above");
        let mut message = Vec::new();
        for part in done.parts.into_iter().flatten() {
            message.extend_from_slice(&part);
        }
        Ok(Some(message))
    }

    /// Drops partial messages older than the timeout. Returns how many were
    /// dropped.
    ///
    /// ```
    /// use tpt_link::fragment::{split, Reassembler};
    ///
    /// let frames = split(2, b"never completed", 8).unwrap();
    /// let mut rx = Reassembler::new(1_000);
    /// rx.push(0, &frames[0]).unwrap();
    /// assert_eq!(rx.pending(), 1);
    /// assert_eq!(rx.expire(1_000), 0); // not yet older than the timeout
    /// assert_eq!(rx.expire(1_001), 1);
    /// assert_eq!(rx.pending(), 0);
    /// ```
    pub fn expire(&mut self, now_us: u64) -> usize {
        let before = self.pending.len();
        let timeout = self.timeout_us;
        self.pending
            .retain(|_, p| now_us.saturating_sub(p.started_us) <= timeout);
        before - self.pending.len()
    }

    /// Number of messages still waiting for fragments.
    ///
    /// ```
    /// use tpt_link::fragment::{split, Reassembler};
    ///
    /// let frames = split(3, b"two fragments", 10).unwrap();
    /// let mut rx = Reassembler::new(1_000);
    /// rx.push(0, &frames[0]).unwrap();
    /// assert_eq!(rx.pending(), 1);
    /// ```
    pub fn pending(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reassemble(frames: &[Vec<u8>]) -> Option<Vec<u8>> {
        let mut rx = Reassembler::new(1_000);
        let mut out = None;
        for frame in frames {
            out = rx.push(0, frame).unwrap().or(out);
        }
        out
    }

    #[test]
    fn round_trip_at_classic_and_fd_mtus() {
        let payload: Vec<u8> = (0..300u16).map(|i| (i % 251) as u8).collect();
        for mtu in [8, 64] {
            let frames = split(7, &payload, mtu).unwrap();
            assert!(frames.iter().all(|f| f.len() <= mtu));
            assert_eq!(reassemble(&frames).as_deref(), Some(payload.as_slice()));
        }
    }

    #[test]
    fn boundary_sizes_round_trip() {
        for len in [0, 1, 4, 5, 6, 10, 11] {
            let payload = vec![0xAB; len];
            let frames = split(0, &payload, 8).unwrap();
            assert_eq!(reassemble(&frames), Some(payload), "len {len}");
        }
    }

    #[test]
    fn out_of_order_and_duplicate_fragments_are_handled() {
        let payload = b"reassemble me in any order".to_vec();
        let frames = split(3, &payload, 8).unwrap();
        let mut rx = Reassembler::new(1_000);

        // Reverse order, with the last fragment repeated.
        let mut out = None;
        for frame in frames.iter().rev().chain(frames.last()) {
            out = rx.push(0, frame).unwrap().or(out);
        }
        assert_eq!(out, Some(payload));
        // The repeat arrived after completion, so it started a partial that
        // can only be cleared by expiry. It does not produce a second message.
        assert_eq!(rx.pending(), 1);
        assert_eq!(rx.expire(u64::MAX), 1);
        assert_eq!(rx.pending(), 0);
    }

    #[test]
    fn interleaved_messages_are_kept_apart() {
        let a = split(1, b"aaaaaaaaaa", 8).unwrap();
        let b = split(2, b"bbbbbbbbbb", 8).unwrap();
        let mut rx = Reassembler::new(1_000);
        let mut done = Vec::new();
        for (fa, fb) in a.iter().zip(&b) {
            done.extend(rx.push(0, fa).unwrap());
            done.extend(rx.push(0, fb).unwrap());
        }
        assert_eq!(done, vec![b"aaaaaaaaaa".to_vec(), b"bbbbbbbbbb".to_vec()]);
    }

    #[test]
    fn incomplete_message_expires() {
        let frames = split(5, b"0123456789", 8).unwrap();
        let mut rx = Reassembler::new(1_000);
        assert_eq!(rx.push(0, &frames[0]).unwrap(), None);
        assert_eq!(rx.pending(), 1);

        assert_eq!(rx.expire(1_000), 0);
        assert_eq!(rx.expire(1_001), 1);
        assert_eq!(rx.pending(), 0);
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(split(0, b"x", 3), Err(FragmentError::InvalidMtu(3)));

        let too_big = vec![0; 5 * MAX_FRAGMENTS + 1];
        assert!(matches!(
            split(0, &too_big, 8),
            Err(FragmentError::TooLarge { .. })
        ));

        let mut rx = Reassembler::new(1_000);
        assert_eq!(rx.push(0, &[1, 2]), Err(FragmentError::Malformed));
        // Index 2 in a message of 2 fragments (count byte 1).
        assert_eq!(rx.push(0, &[1, 2, 1, 0]), Err(FragmentError::Malformed));
    }

    #[test]
    fn largest_classic_message_fits_the_link_maximum() {
        // 256 fragments of 5 data bytes is 1280 bytes, which covers the 1024-byte link maximum.
        let max = 5 * MAX_FRAGMENTS;
        assert!(max >= crate::frame::MAX_PAYLOAD_LEN);
        let payload = vec![0x5A; crate::frame::MAX_PAYLOAD_LEN];
        let frames = split(9, &payload, 8).unwrap();
        assert_eq!(reassemble(&frames), Some(payload));
    }
}
