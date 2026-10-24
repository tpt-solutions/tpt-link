// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Fault injection for tests. `FaultyTransport` wraps any transport and drops
//! or corrupts the next outgoing frames.

use crate::transport::Transport;

/// Wraps a transport and damages outgoing frames on purpose.
///
/// Faults apply on `send`, so the receiving side sees a lost or corrupted
/// frame exactly as it would from a noisy wire.
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
}

impl<T> FaultyTransport<T> {
    /// Wraps `inner` with no faults queued.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            drop_remaining: 0,
            corrupt_remaining: 0,
        }
    }

    /// Silently drops the next `count` frames.
    pub fn drop_next(&mut self, count: usize) {
        self.drop_remaining += count;
    }

    /// Corrupts each of the next `count` frames, so the receiver sees a CRC failure.
    pub fn corrupt_next(&mut self, count: usize) {
        self.corrupt_remaining += count;
    }
}

impl<T: Transport> Transport for FaultyTransport<T> {
    type Error = T::Error;

    fn send(&mut self, frame: &[u8]) -> Result<(), T::Error> {
        if self.drop_remaining > 0 {
            self.drop_remaining -= 1;
            return Ok(());
        }
        if self.corrupt_remaining > 0 {
            self.corrupt_remaining -= 1;
            // Flip the last byte, which is part of the CRC. Flipping an early byte
            // could hit the version field and be reported as a different error.
            let mut damaged = frame.to_vec();
            if let Some(byte) = damaged.last_mut() {
                *byte ^= 0x01;
            }
            return self.inner.send(&damaged);
        }
        self.inner.send(frame)
    }

    fn try_recv(&mut self) -> Result<Option<Vec<u8>>, T::Error> {
        self.inner.try_recv()
    }
}
