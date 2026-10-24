// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Message authentication for frames carried in the open, such as UDP and CAN.
//! Enabled with the `auth` feature.
//!
//! The link CRC catches damage, but anyone who can reach the port or the bus
//! can compute it, so it cannot tell a real frame from a forged one.
//! `Authenticated` wraps a transport and tags every frame with the first 16
//! bytes of HMAC-SHA256, keyed with a 32-byte shared key.
//!
//! Replay is stopped by a session nonce, which the receiver chooses:
//!
//! 1. A sender with no session sends a signed *hello*, and queues its frames.
//! 2. The receiver answers with a signed *challenge* holding a fresh random
//!    nonce, and accepts data only under that nonce.
//! 3. Every data tag covers the nonce and the frame. A frame recorded in an
//!    earlier session fails once the receiver has issued a new nonce.
//! 4. Within a session, the sequence window refuses repeats, and refuses
//!    numbers too far back to check, rather than treating them as a restart.
//!
//! What this gives: every frame that reaches the link was made by a holder of
//! the key, for the session the receiver is in, and was not altered. A replay
//! from an earlier session or from far back in this one is refused.
//!
//! What it does not give:
//!
//! - **Confidentiality.** Payloads travel in the clear.
//! - **Automatic recovery from restarts.** After either side restarts, call
//!   `renew` on the sender. Until then its frames are refused, and they are not
//!   resent.
//! - **Hello flooding protection.** A replayed hello makes the receiver issue a
//!   new nonce, which ends the current session. That is denial of service, not
//!   a way to inject frames.
//! - **Key management.** The key is shared out of band and is not rotated.

use std::collections::VecDeque;
use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::frame::{HEADER_LEN, VERSION};
use crate::seqwin::{Arrival, SeqWindow};
use crate::transport::Transport;

type HmacSha256 = Hmac<Sha256>;

/// Bytes in a shared key.
pub const KEY_LEN: usize = 32;
/// Bytes of tag on each message.
pub const TAG_LEN: usize = 16;
/// Bytes in a session nonce.
pub const NONCE_LEN: usize = 16;

/// First byte of a hello. It is not a frame version, so the two never clash.
const TYPE_HELLO: u8 = 0xC0;
/// First byte of a challenge.
const TYPE_CHALLENGE: u8 = 0xC1;
/// Frames held back while the session is being set up. The oldest are dropped
/// beyond this.
const MAX_PENDING: usize = 32;
/// While frames wait for a session, the hello is sent again after this many
/// receive calls with nothing arriving.
const HELLO_RETRY_POLLS: u32 = 8;

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

/// The nonce this side issued to its peer, and what has arrived under it.
#[derive(Debug)]
struct Issued {
    nonce: [u8; NONCE_LEN],
    window: SeqWindow,
    /// True once a frame has been accepted under this nonce. Until then, a
    /// repeated hello gets the same challenge back, so duplicate hellos from
    /// a sender that is still setting up do not replace the nonce.
    in_use: bool,
}

/// Wraps a transport and authenticates every frame.
///
/// ```
/// use tpt_link::Loopback;
/// use tpt_link::auth::{Authenticated, KEY_LEN, Key};
/// use tpt_link::Link;
///
/// let key = Key::new([7; KEY_LEN]);
/// let (a, b) = Loopback::pair();
/// let mut tx = Link::new(Authenticated::new(a, key.clone()));
/// let mut rx = Link::new(Authenticated::new(b, key));
/// tx.send(b"open valve").unwrap();
/// rx.poll().unwrap(); // the hello is answered here
/// tx.poll().unwrap(); // the challenge arrives and the queued frame goes out
/// assert_eq!(rx.poll().unwrap(), vec![b"open valve".to_vec()]);
/// ```
#[derive(Debug)]
pub struct Authenticated<T> {
    inner: T,
    key: Key,
    /// The nonce the peer issued to us. Our frames are sent under it.
    peer_nonce: Option<[u8; NONCE_LEN]>,
    /// The nonce we issued to the peer, if any.
    issued: Option<Issued>,
    pending: VecDeque<Vec<u8>>,
    polls_since_hello: u32,
    rejected: u64,
    replayed: u64,
    dropped_pending: u64,
}

impl<T> Authenticated<T> {
    /// Wraps `inner`. Both ends must use the same key.
    pub fn new(inner: T, key: Key) -> Self {
        Self {
            inner,
            key,
            peer_nonce: None,
            issued: None,
            pending: VecDeque::new(),
            polls_since_hello: 0,
            rejected: 0,
            replayed: 0,
            dropped_pending: 0,
        }
    }

    /// Messages dropped because their tag did not verify, or because they were
    /// too short to carry one.
    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// Data frames that verified but were refused as repeats or as too old to
    /// check. These are replays, or duplicates from a lossy link.
    pub fn replayed(&self) -> u64 {
        self.replayed
    }

    /// Frames dropped from the queue because the session took too long to set up.
    pub fn dropped_pending(&self) -> u64 {
        self.dropped_pending
    }

    /// Mutable access to the underlying transport.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Gives back the underlying transport.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

/// Tag over `parts`, keyed with `key`. The key is always a valid HMAC key
/// length, so this cannot fail.
fn tag_over(key: &Key, parts: &[&[u8]]) -> [u8; TAG_LEN] {
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&full[..TAG_LEN]);
    out
}

/// True if `tag` is the tag of `parts` under `key`. Compared in constant time.
fn verify_over(key: &Key, parts: &[&[u8]], tag: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    mac.verify_truncated_left(tag).is_ok()
}

/// A fresh nonce from the operating system. If that source is unavailable, the
/// session cannot be made safe, so this panics rather than return a weak value.
fn fresh_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).expect("the operating system random source is available");
    nonce
}

/// The bytes of a data message: the frame, then its tag over nonce and frame.
fn data_wire(key: &Key, nonce: &[u8; NONCE_LEN], frame: &[u8]) -> Vec<u8> {
    let mut wire = Vec::with_capacity(frame.len() + TAG_LEN);
    wire.extend_from_slice(frame);
    wire.extend_from_slice(&tag_over(key, &[nonce, frame]));
    wire
}

impl<T: Transport> Authenticated<T> {
    /// Starts a new session with the peer. Call this after either side restarts
    /// or reconnects. Frames sent before the peer answers are held in the queue.
    pub fn renew(&mut self) -> Result<(), T::Error> {
        self.peer_nonce = None;
        self.send_hello()
    }

    fn send_hello(&mut self) -> Result<(), T::Error> {
        let mut wire = vec![TYPE_HELLO];
        wire.extend_from_slice(&tag_over(&self.key, &[&[TYPE_HELLO]]));
        self.inner.send(&wire)
    }

    /// Sends the queued frames, now that the peer's nonce is known.
    fn flush(&mut self) -> Result<(), T::Error> {
        let Some(nonce) = self.peer_nonce else {
            return Ok(());
        };
        while let Some(frame) = self.pending.pop_front() {
            self.inner.send(&data_wire(&self.key, &nonce, &frame))?;
        }
        Ok(())
    }

    /// Answers a hello with a challenge holding a fresh nonce.
    fn answer_hello(&mut self, wire: &[u8]) -> Result<(), T::Error> {
        if wire.len() != 1 + TAG_LEN || !verify_over(&self.key, &[&[TYPE_HELLO]], &wire[1..]) {
            self.rejected += 1;
            return Ok(());
        }
        let nonce = match &self.issued {
            Some(issued) if !issued.in_use => issued.nonce,
            _ => {
                let nonce = fresh_nonce();
                self.issued = Some(Issued {
                    nonce,
                    window: SeqWindow::default(),
                    in_use: false,
                });
                nonce
            }
        };
        let mut out = vec![TYPE_CHALLENGE];
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&tag_over(&self.key, &[&[TYPE_CHALLENGE], &nonce]));
        self.inner.send(&out)
    }

    /// Takes the peer's nonce from a challenge and sends the queued frames.
    fn take_challenge(&mut self, wire: &[u8]) -> Result<(), T::Error> {
        let len = 1 + NONCE_LEN + TAG_LEN;
        let valid = wire.len() == len
            && verify_over(
                &self.key,
                &[&[TYPE_CHALLENGE], &wire[1..1 + NONCE_LEN]],
                &wire[1 + NONCE_LEN..],
            );
        if !valid {
            self.rejected += 1;
            return Ok(());
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&wire[1..1 + NONCE_LEN]);
        self.peer_nonce = Some(nonce);
        self.polls_since_hello = 0;
        self.flush()
    }

    /// Checks a data message. Returns the frame if it is new and authentic.
    fn take_data(&mut self, wire: Vec<u8>) -> Option<Vec<u8>> {
        let Some(issued) = self.issued.as_mut() else {
            // No session has been started with this peer, so nothing can be valid.
            self.rejected += 1;
            return None;
        };
        if wire.len() < TAG_LEN + HEADER_LEN {
            self.rejected += 1;
            return None;
        }
        let (frame, sent_tag) = wire.split_at(wire.len() - TAG_LEN);
        if !verify_over(&self.key, &[&issued.nonce, frame], sent_tag) {
            self.rejected += 1;
            return None;
        }
        if frame.first() != Some(&VERSION) {
            self.rejected += 1;
            return None;
        }
        let seq = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]);
        match issued.window.arrive_strict(seq) {
            Arrival::New { .. } => {
                issued.in_use = true;
                Some(frame.to_vec())
            }
            Arrival::Repeat | Arrival::Stale => {
                self.replayed += 1;
                None
            }
        }
    }
}

impl<T: Transport> Transport for Authenticated<T> {
    type Error = T::Error;

    fn send(&mut self, frame: &[u8]) -> Result<(), T::Error> {
        match self.peer_nonce {
            Some(nonce) => self.inner.send(&data_wire(&self.key, &nonce, frame)),
            None => {
                if self.pending.len() == MAX_PENDING {
                    self.pending.pop_front();
                    self.dropped_pending += 1;
                }
                self.pending.push_back(frame.to_vec());
                self.send_hello()
            }
        }
    }

    fn try_recv(&mut self) -> Result<Option<Vec<u8>>, T::Error> {
        loop {
            let Some(wire) = self.inner.try_recv()? else {
                // Nothing arrived. If frames are still waiting for a session,
                // the hello may have been lost, so send it again now and then.
                if self.peer_nonce.is_none() && !self.pending.is_empty() {
                    self.polls_since_hello += 1;
                    if self.polls_since_hello >= HELLO_RETRY_POLLS {
                        self.polls_since_hello = 0;
                        self.send_hello()?;
                    }
                }
                return Ok(None);
            };
            match wire.first() {
                Some(&TYPE_HELLO) => self.answer_hello(&wire)?,
                Some(&TYPE_CHALLENGE) => self.take_challenge(&wire)?,
                _ => {
                    if let Some(frame) = self.take_data(wire) {
                        return Ok(Some(frame));
                    }
                }
            }
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

    /// A loopback end that keeps a copy of everything it sends, and can inject
    /// bytes as if they came from the peer.
    struct Recorder {
        inner: Loopback,
        log: Vec<Vec<u8>>,
    }

    impl Transport for Recorder {
        type Error = crate::transport::Closed;

        fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
            self.log.push(frame.to_vec());
            self.inner.send(frame)
        }

        fn try_recv(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            self.inner.try_recv()
        }
    }

    fn recorder(end: Loopback) -> Recorder {
        Recorder {
            inner: end,
            log: Vec::new(),
        }
    }

    /// A link frame with the given sequence number.
    fn frame(seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        encode(seq, payload, &mut wire).unwrap();
        wire
    }

    /// Sends one frame and lets both sides process what is in flight.
    fn deliver(
        tx: &mut Authenticated<Recorder>,
        rx: &mut Authenticated<Loopback>,
        frame_bytes: &[u8],
    ) -> Vec<Vec<u8>> {
        tx.send(frame_bytes).unwrap();
        let mut got = Vec::new();
        for _ in 0..4 {
            while let Some(f) = rx.try_recv().unwrap() {
                got.push(f);
            }
            while tx.try_recv().unwrap().is_some() {}
        }
        got
    }

    fn data_wires(log: &[Vec<u8>]) -> Vec<Vec<u8>> {
        log.iter()
            .filter(|w| w.first() == Some(&VERSION))
            .cloned()
            .collect()
    }

    #[test]
    fn frames_flow_once_the_session_is_up() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(b, key(1));
        let f0 = frame(0, b"open valve");
        assert_eq!(deliver(&mut tx, &mut rx, &f0), vec![f0.clone()]);
        assert_eq!(rx.rejected(), 0);
        assert_eq!(rx.replayed(), 0);
    }

    #[test]
    fn a_repeat_within_the_session_is_refused() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(b, key(1));
        let f0 = frame(0, b"open valve");
        deliver(&mut tx, &mut rx, &f0);

        let recorded = data_wires(&tx.inner_mut().log)[0].clone();
        tx.inner_mut().inner.send(&recorded).unwrap();
        assert_eq!(rx.try_recv().unwrap(), None);
        assert_eq!(rx.replayed(), 1);
    }

    #[test]
    fn a_frame_from_an_earlier_session_is_refused() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(b, key(1));
        let f0 = frame(0, b"open valve");
        deliver(&mut tx, &mut rx, &f0);
        let old = data_wires(&tx.inner_mut().log)[0].clone();

        // A new session: the receiver issues a fresh nonce.
        tx.renew().unwrap();
        rx.try_recv().unwrap();
        tx.try_recv().unwrap();

        tx.inner_mut().inner.send(&old).unwrap();
        assert_eq!(rx.try_recv().unwrap(), None);
        assert_eq!(rx.rejected(), 1);
    }

    #[test]
    fn a_frame_far_back_in_the_session_is_refused() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(b, key(1));
        for seq in 0..70 {
            deliver(&mut tx, &mut rx, &frame(seq, b"x"));
        }
        let first = data_wires(&tx.inner_mut().log)[0].clone();
        tx.inner_mut().inner.send(&first).unwrap();
        assert_eq!(rx.try_recv().unwrap(), None);
        assert_eq!(rx.replayed(), 1);
    }

    #[test]
    fn a_forged_hello_gets_no_challenge() {
        let (x, y) = Loopback::pair();
        let mut attacker = Authenticated::new(recorder(x), key(2));
        attacker.renew().unwrap();
        let mut rx = Authenticated::new(y, key(1));
        assert_eq!(rx.try_recv().unwrap(), None);
        assert_eq!(rx.rejected(), 1);
        assert!(rx.issued.is_none());
    }

    #[test]
    fn a_tampered_frame_is_dropped() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(b, key(1));
        deliver(&mut tx, &mut rx, &frame(0, b"open valve"));

        let mut tampered = data_wires(&tx.inner_mut().log)[0].clone();
        tampered[8] ^= 0x01;
        tx.inner_mut().inner.send(&tampered).unwrap();
        assert_eq!(rx.try_recv().unwrap(), None);
        assert_eq!(rx.rejected(), 1);
    }

    #[test]
    fn data_before_any_session_is_refused() {
        let (mut raw, b) = Loopback::pair();
        raw.send(&frame(0, b"unsigned")).unwrap();
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

    #[test]
    fn frames_under_the_wrong_key_never_reach_the_link() {
        let (a, b) = Loopback::pair();
        let mut tx = Link::new(Authenticated::new(a, key(1)));
        let mut rx = Link::new(Authenticated::new(b, key(2)));
        tx.send(b"hello").unwrap();
        for _ in 0..3 {
            assert!(rx.poll().unwrap().is_empty());
            tx.poll().unwrap();
        }
        assert_eq!(rx.stats().received, 0);
    }

    #[test]
    fn queue_keeps_the_newest_frames_when_the_session_is_slow() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(b, key(1));
        for seq in 0..40 {
            tx.send(&frame(seq, b"q")).unwrap();
        }
        assert_eq!(tx.dropped_pending(), 8);

        let mut got = Vec::new();
        for _ in 0..4 {
            while let Some(f) = rx.try_recv().unwrap() {
                got.push(f);
            }
            while tx.try_recv().unwrap().is_some() {}
        }
        assert_eq!(got.len(), MAX_PENDING);
        assert_eq!(got[0], frame(8, b"q"));
    }
}
