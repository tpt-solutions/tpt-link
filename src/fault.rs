// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Fault injection for tests. `FaultyTransport` wraps any transport and damages
//! outgoing frames in the ways a real wire does: loss, corruption, truncation,
//! reordering, duplication, and random loss at a set rate.

use crate::rng::Xorshift64;
use crate::transport::Transport;

/// Wraps a transport and damages outgoing frames on purpose.
///
/// Faults apply on `send`, so the receiving side sees a damaged frame exactly as
/// it would from a noisy wire. Each queued fault applies to the next frame sent
/// that it can reach, and several can apply to the same frame.
///
/// ```
/// use tpt_link::{FaultyTransport, Loopback, Transport};
///
/// let (a, mut b) = Loopback::pair();
/// let mut a = FaultyTransport::new(a);
/// a.drop_next(1);
/// a.send(b"lost").unwrap();
/// a.send(b"kept").unwrap();
/// assert_eq!(b.try_recv().unwrap().as_deref(), Some(&b"kept"[..]));
/// ```
#[derive(Debug)]
pub struct FaultyTransport<T> {
    inner: T,
    drop_remaining: usize,
    corrupt_remaining: usize,
    version_remaining: usize,
    truncate_remaining: usize,
    duplicate_remaining: usize,
    reorder_remaining: usize,
    /// A frame held back so that the next one overtakes it.
    held: Option<Vec<u8>>,
    random_loss: Option<RandomLoss>,
}

/// Loss at a fixed rate, drawn from a seeded generator. The same seed always
/// drops the same frames, so a failing test can be replayed.
#[derive(Debug)]
struct RandomLoss {
    per_million: u32,
    rng: Xorshift64,
}

impl<T> FaultyTransport<T> {
    /// Wraps `inner` with no faults queued.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            drop_remaining: 0,
            corrupt_remaining: 0,
            version_remaining: 0,
            truncate_remaining: 0,
            duplicate_remaining: 0,
            reorder_remaining: 0,
            held: None,
            random_loss: None,
        }
    }

    /// Silently drops the next `count` frames.
    pub fn drop_next(&mut self, count: usize) {
        self.drop_remaining += count;
    }

    /// Corrupts each of the next `count` frames, so the receiver sees a CRC failure.
    ///
    /// ```
    /// use tpt_link::{FaultyTransport, Link, Loopback};
    ///
    /// let (a, b) = Loopback::pair();
    /// let mut a = Link::new(FaultyTransport::new(a));
    /// let mut b = Link::new(b);
    /// a.transport_mut().corrupt_next(1);
    /// a.send(b"damaged").unwrap();
    /// a.send(b"intact").unwrap();
    /// assert_eq!(b.poll().unwrap(), vec![b"intact".to_vec()]);
    /// assert_eq!(b.stats().crc_errors, 1);
    /// ```
    pub fn corrupt_next(&mut self, count: usize) {
        self.corrupt_remaining += count;
    }

    /// Replaces the version byte of each of the next `count` frames, so the
    /// receiver counts them as `bad_version`.
    pub fn corrupt_version_next(&mut self, count: usize) {
        self.version_remaining += count;
    }

    /// Cuts each of the next `count` frames in half, so the receiver sees a
    /// truncated frame.
    pub fn truncate_next(&mut self, count: usize) {
        self.truncate_remaining += count;
    }

    /// Sends each of the next `count` frames twice.
    pub fn duplicate_next(&mut self, count: usize) {
        self.duplicate_remaining += count;
    }

    /// Holds each of the next `count` frames back until the frame after it is
    /// sent, so the two arrive in the opposite order. A held frame with no
    /// successor waits until `release_held` is called.
    ///
    /// ```
    /// use tpt_link::{FaultyTransport, Link, Loopback};
    ///
    /// let (a, b) = Loopback::pair();
    /// let mut a = Link::new(FaultyTransport::new(a));
    /// let mut b = Link::new(b);
    /// a.transport_mut().reorder_next(1);
    /// a.send(b"first").unwrap();
    /// a.send(b"second").unwrap();
    /// assert_eq!(b.poll().unwrap(), vec![b"second".to_vec(), b"first".to_vec()]);
    /// ```
    pub fn reorder_next(&mut self, count: usize) {
        self.reorder_remaining += count;
    }

    /// Drops frames at random, at `per_million` frames in a million, using a
    /// generator seeded with `seed`. The same seed drops the same frames each
    /// run. Pass 0 to turn random loss off.
    pub fn random_loss(&mut self, per_million: u32, seed: u64) {
        self.random_loss = (per_million > 0).then_some(RandomLoss {
            per_million,
            rng: Xorshift64::new(seed),
        });
    }

    /// Whether a frame is currently held back by `reorder_next`.
    pub fn has_held(&self) -> bool {
        self.held.is_some()
    }
}

impl<T: Transport> FaultyTransport<T> {
    /// Sends the frame held back by `reorder_next`, if there is one. Call this
    /// when the stream ends so that the last frame is not lost to the fault.
    pub fn release_held(&mut self) -> Result<(), T::Error> {
        if let Some(frame) = self.held.take() {
            self.inner.send(&frame)?;
        }
        Ok(())
    }
}

impl<T: Transport> Transport for FaultyTransport<T> {
    type Error = T::Error;

    fn send(&mut self, frame: &[u8]) -> Result<(), T::Error> {
        if self.drop_remaining > 0 {
            self.drop_remaining -= 1;
            return Ok(());
        }
        if let Some(loss) = self.random_loss.as_mut() {
            if loss.rng.next_u32() % 1_000_000 < loss.per_million {
                return Ok(());
            }
        }

        let mut wire = frame.to_vec();
        if self.truncate_remaining > 0 {
            self.truncate_remaining -= 1;
            wire.truncate(wire.len() / 2);
        }
        if self.version_remaining > 0 {
            self.version_remaining -= 1;
            if let Some(version) = wire.first_mut() {
                *version = 0xFF;
            }
        }
        if self.corrupt_remaining > 0 {
            self.corrupt_remaining -= 1;
            // Flip the last byte, which is part of the CRC. Flipping an early byte
            // could hit the version field and be reported as a different error.
            if let Some(byte) = wire.last_mut() {
                *byte ^= 0x01;
            }
        }

        let copies = if self.duplicate_remaining > 0 {
            self.duplicate_remaining -= 1;
            2
        } else {
            1
        };

        // Only one frame is held at a time. If one is already held, this frame
        // goes out first and the held one follows it.
        if self.held.is_none() && self.reorder_remaining > 0 {
            self.reorder_remaining -= 1;
            self.held = Some(wire);
            return Ok(());
        }
        for _ in 0..copies {
            self.inner.send(&wire)?;
        }
        self.release_held()
    }

    fn try_recv(&mut self) -> Result<Option<Vec<u8>>, T::Error> {
        self.inner.try_recv()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::Link;
    use crate::transport::Loopback;

    fn pair() -> (Link<FaultyTransport<Loopback>>, Link<Loopback>) {
        let (a, b) = Loopback::pair();
        (Link::new(FaultyTransport::new(a)), Link::new(b))
    }

    #[test]
    fn truncated_frame_is_malformed() {
        let (mut a, mut b) = pair();
        a.transport_mut().truncate_next(1);
        a.send(b"cut in half").unwrap();
        assert!(b.poll().unwrap().is_empty());
        assert_eq!(b.stats().malformed, 1);
    }

    #[test]
    fn wrong_version_is_bad_version() {
        let (mut a, mut b) = pair();
        a.transport_mut().corrupt_version_next(1);
        a.send(b"x").unwrap();
        assert!(b.poll().unwrap().is_empty());
        assert_eq!(b.stats().bad_version, 1);
    }

    #[test]
    fn duplicate_is_sent_twice_and_the_second_copy_is_dropped() {
        let (mut a, mut b) = pair();
        a.transport_mut().duplicate_next(1);
        a.send(b"twice").unwrap();
        a.send(b"once").unwrap();
        assert_eq!(b.poll().unwrap(), vec![b"twice".to_vec(), b"once".to_vec()]);
        assert_eq!(b.stats().duplicates, 1);
    }

    #[test]
    fn reordered_frame_arrives_after_its_successor() {
        let (mut a, mut b) = pair();
        a.transport_mut().reorder_next(1);
        a.send(b"first").unwrap();
        assert!(a.transport_mut().has_held());
        a.send(b"second").unwrap();
        assert_eq!(
            b.poll().unwrap(),
            vec![b"second".to_vec(), b"first".to_vec()]
        );
        assert_eq!(b.stats().lost, 0);
    }

    #[test]
    fn held_frame_without_successor_waits_for_release() {
        let (mut a, mut b) = pair();
        a.transport_mut().reorder_next(1);
        a.send(b"last").unwrap();
        assert!(b.poll().unwrap().is_empty());
        a.transport_mut().release_held().unwrap();
        assert_eq!(b.poll().unwrap(), vec![b"last".to_vec()]);
    }

    #[test]
    fn random_loss_is_repeatable_for_a_seed() {
        let run = |seed| {
            let (mut a, mut b) = pair();
            a.transport_mut().random_loss(200_000, seed); // 20 %
            for i in 0..200u8 {
                a.send(&[i]).unwrap();
            }
            b.poll().unwrap();
            b.stats()
        };
        let first = run(7);
        assert_eq!(first, run(7));
        // Roughly a fifth of 200 frames are lost, so the count is well away from
        // both zero and the full 200.
        assert!(first.lost > 10 && first.lost < 80, "lost {}", first.lost);
        assert_ne!(first, run(8));
    }

    #[test]
    fn zero_rate_turns_random_loss_off() {
        let (mut a, mut b) = pair();
        a.transport_mut().random_loss(1_000_000, 3);
        a.transport_mut().random_loss(0, 3);
        for i in 0..20u8 {
            a.send(&[i]).unwrap();
        }
        assert_eq!(b.poll().unwrap().len(), 20);
    }
}
