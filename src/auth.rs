// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Message authentication for frames carried in the open, such as UDP and CAN.
//! Enabled with the `auth` feature.
//!
//! The link CRC catches damage, but anyone who can reach the port or the bus
//! can compute it, so it cannot tell a real frame from a forged one.
//! `Authenticated` wraps a transport and appends a tag to every frame: the first
//! 16 bytes of HMAC-SHA256 over the frame, keyed with a 32-byte shared key.
//! Frames whose tag does not verify are dropped and counted, and never reach
//! the link.
//!
//! What this gives: every frame that reaches the link was made by a holder of
//! the key, and was not altered in transit.
//!
//! What it does not give:
//!
//! - **Confidentiality.** Payloads travel in the clear.
//! - **Replay protection.** A recorded frame still verifies. The link drops it
//!   only while its sequence number is in the duplicate window, the last 64
//!   numbers. A replay from further back is accepted as a peer restart.
//! - **Key management.** The key is shared out of band, and it is not rotated.

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::transport::Transport;

type HmacSha256 = Hmac<Sha256>;

/// Bytes in a shared key.
pub const KEY_LEN: usize = 32;
/// Bytes of tag appended to each frame.
pub const TAG_LEN: usize = 16;

/// A shared secret. `Debug` output hides the bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    /// Wraps 32 bytes of key material. Generate them from a secure random source.
    pub fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(..)")
    }
}

/// Wraps a transport and authenticates every frame.
///
/// ```
/// use tpt_link::Loopback;
/// use tpt_link::auth::{Authenticated, Key, KEY_LEN};
/// use tpt_link::Link;
///
/// let key = Key::new([7; KEY_LEN]);
/// let (a, b) = Loopback::pair();
/// let mut tx = Link::new(Authenticated::new(a, key.clone()));
/// let mut rx = Link::new(Authenticated::new(b, key));
/// tx.send(b"open valve").unwrap();
/// assert_eq!(rx.poll().unwrap(), vec![b"open valve".to_vec()]);
/// ```
#[derive(Debug)]
pub struct Authenticated<T> {
    inner: T,
    key: Key,
    rejected: u64,
}

impl<T> Authenticated<T> {
    /// Wraps `inner`. Both ends must use the same key.
    pub fn new(inner: T, key: Key) -> Self {
        Self {
            inner,
            key,
            rejected: 0,
        }
    }

    /// Frames dropped because their tag did not verify, or because they were too
    /// short to carry one.
    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// Mutable access to the underlying transport, for example to read its
    /// own counters.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Gives back the underlying transport.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

/// Computes the tag for `frame`. The key is always a valid HMAC key length, so
/// creating the MAC cannot fail.
fn mac_for(key: &Key, frame: &[u8]) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts any key length");
    mac.update(frame);
    mac
}

fn tag(key: &Key, frame: &[u8]) -> [u8; TAG_LEN] {
    let full = mac_for(key, frame).finalize().into_bytes();
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&full[..TAG_LEN]);
    out
}

impl<T: Transport> Transport for Authenticated<T> {
    type Error = T::Error;

    fn send(&mut self, frame: &[u8]) -> Result<(), T::Error> {
        let mut wire = Vec::with_capacity(frame.len() + TAG_LEN);
        wire.extend_from_slice(frame);
        wire.extend_from_slice(&tag(&self.key, frame));
        self.inner.send(&wire)
    }

    fn try_recv(&mut self) -> Result<Option<Vec<u8>>, T::Error> {
        loop {
            let Some(wire) = self.inner.try_recv()? else {
                return Ok(None);
            };
            if wire.len() < TAG_LEN {
                self.rejected += 1;
                continue;
            }
            let (frame, sent_tag) = wire.split_at(wire.len() - TAG_LEN);
            // verify_truncated_left compares in constant time, so the check does
            // not reveal how many leading bytes of the tag were right.
            if mac_for(&self.key, frame)
                .verify_truncated_left(sent_tag)
                .is_ok()
            {
                return Ok(Some(frame.to_vec()));
            }
            self.rejected += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::encode;
    use crate::link::Link;
    use crate::transport::Loopback;

    fn key(byte: u8) -> Key {
        Key::new([byte; KEY_LEN])
    }

    #[test]
    fn frames_round_trip_with_the_right_key() {
        let (a, b) = Loopback::pair();
        let mut tx = Link::new(Authenticated::new(a, key(1)));
        let mut rx = Link::new(Authenticated::new(b, key(1)));
        tx.send(b"hello").unwrap();
        assert_eq!(rx.poll().unwrap(), vec![b"hello".to_vec()]);
        assert_eq!(rx.transport_mut().rejected(), 0);
    }

    #[test]
    fn frames_under_the_wrong_key_are_dropped() {
        let (a, b) = Loopback::pair();
        let mut tx = Link::new(Authenticated::new(a, key(1)));
        let mut rx = Link::new(Authenticated::new(b, key(2)));
        tx.send(b"hello").unwrap();
        assert!(rx.poll().unwrap().is_empty());
        assert_eq!(rx.transport_mut().rejected(), 1);
        assert_eq!(rx.stats().received, 0);
    }

    #[test]
    fn an_unsigned_forgery_is_dropped() {
        let (a, b) = Loopback::pair();
        let mut attacker = Link::new(a);
        let mut rx = Link::new(Authenticated::new(b, key(1)));
        attacker.send(b"open valve").unwrap();
        assert!(rx.poll().unwrap().is_empty());
        assert_eq!(rx.transport_mut().rejected(), 1);
    }

    #[test]
    fn a_tampered_frame_is_dropped() {
        // Sign a frame, then change one payload byte before it is sent.
        let mut frame = Vec::new();
        encode(0, b"open valve", &mut frame).unwrap();
        let mut signed = frame.clone();
        signed.extend_from_slice(&tag(&key(1), &frame));
        signed[8] ^= 0x01;

        let (mut raw, b) = Loopback::pair();
        raw.send(&signed).unwrap();
        let mut rx = Authenticated::new(b, key(1));
        assert_eq!(rx.try_recv().unwrap(), None);
        assert_eq!(rx.rejected(), 1);
    }

    #[test]
    fn a_datagram_shorter_than_a_tag_is_dropped() {
        let (mut raw, b) = Loopback::pair();
        raw.send(&[1, 2, 3]).unwrap();
        let mut rx = Authenticated::new(b, key(1));
        assert_eq!(rx.try_recv().unwrap(), None);
        assert_eq!(rx.rejected(), 1);
    }
}
