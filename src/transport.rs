// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The `Transport` trait, and the in-memory loopback used by tests.

use std::fmt;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

/// The other end of the transport has gone away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closed;

impl fmt::Display for Closed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transport closed")
    }
}

impl std::error::Error for Closed {}

/// A datagram-style transport. Each `send` carries one whole frame, and each
/// `try_recv` returns one whole frame.
///
/// UDP and CAN map onto this directly. Serial and USB-CDC are byte streams, so
/// they need a deframer (see `stream`) that finds frame boundaries before they
/// can implement this trait.
///
/// A minimal implementation that records what is sent and returns nothing:
///
/// ```
/// use std::convert::Infallible;
/// use tpt_link::Transport;
///
/// #[derive(Default)]
/// struct Sink(Vec<Vec<u8>>);
///
/// impl Transport for Sink {
///     type Error = Infallible;
///     fn send(&mut self, frame: &[u8]) -> Result<(), Infallible> {
///         self.0.push(frame.to_vec());
///         Ok(())
///     }
///     fn try_recv(&mut self) -> Result<Option<Vec<u8>>, Infallible> {
///         Ok(None)
///     }
/// }
///
/// let mut t = Sink::default();
/// t.send(b"out").unwrap();
/// assert_eq!(t.try_recv().unwrap(), None);
/// assert_eq!(t.0, vec![b"out".to_vec()]);
/// ```
pub trait Transport {
    /// Error type returned by this transport.
    type Error: std::error::Error;

    /// Sends one frame.
    fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error>;

    /// Returns the next waiting frame, or `None` if nothing has arrived. Never
    /// blocks.
    fn try_recv(&mut self) -> Result<Option<Vec<u8>>, Self::Error>;
}

/// One end of an in-memory, lossless channel.
///
/// ```
/// use tpt_link::{Loopback, Transport};
///
/// let (mut a, mut b) = Loopback::pair();
/// a.send(b"ping").unwrap();
/// assert_eq!(b.try_recv().unwrap().as_deref(), Some(&b"ping"[..]));
/// assert_eq!(b.try_recv().unwrap(), None);
/// ```
#[derive(Debug)]
pub struct Loopback {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl Loopback {
    /// Creates two connected ends. Frames sent on one arrive at the other.
    pub fn pair() -> (Self, Self) {
        let (a_tx, b_rx) = mpsc::channel();
        let (b_tx, a_rx) = mpsc::channel();
        (Self { tx: a_tx, rx: a_rx }, Self { tx: b_tx, rx: b_rx })
    }
}

impl Transport for Loopback {
    type Error = Closed;

    fn send(&mut self, frame: &[u8]) -> Result<(), Closed> {
        self.tx.send(frame.to_vec()).map_err(|_| Closed)
    }

    fn try_recv(&mut self) -> Result<Option<Vec<u8>>, Closed> {
        match self.rx.try_recv() {
            Ok(frame) => Ok(Some(frame)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(Closed),
        }
    }
}
