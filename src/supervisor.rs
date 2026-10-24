// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Keeps a `Session` up. The `Supervisor` opens the transport through a function
//! the caller supplies, retries with backoff while the link is down, and treats
//! the link as dead when the peer has been silent for the timeout.
//!
//! It owns no thread and reads no clock. The caller calls `tick` at its own rate
//! with the current time, per principle P4, so its behaviour is exact in tests.
//! This is what `examples/reconnect.rs` does by hand.

use std::fmt;

use crate::envelope::{Message, Session};
use crate::link::LinkError;
use crate::reconnect::{Action, Reconnector};
use crate::transport::Transport;

/// Why `Supervisor::send` did not send.
#[derive(Debug)]
pub enum SendError<E> {
    /// No link is up. The message was not sent, and nothing is queued.
    Down,
    /// The transport failed while sending. The link is now marked down.
    Link(LinkError<E>),
}

impl<E: fmt::Display> fmt::Display for SendError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Down => write!(f, "link is down"),
            Self::Link(e) => write!(f, "link failed: {e}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for SendError<E> {}

/// Drives one `Session` over a transport that can be reopened.
///
/// `connect` is called with the attempt number within the current outage,
/// starting at 1. It returns the new transport, or an error that the
/// supervisor ignores: the reconnector schedules the next attempt. Log the
/// error inside `connect` if it matters.
///
/// ```
/// use tpt_link::envelope::{Message, Session};
/// use tpt_link::supervisor::Supervisor;
/// use tpt_link::Loopback;
///
/// let (ours, theirs) = Loopback::pair();
/// // Hands out the one transport. A real connect function opens a socket or port.
/// let mut spare = Some(ours);
/// let mut link = Supervisor::new(
///     move |_attempt| spare.take().ok_or(()),
///     100_000,   // first retry after 100 ms
///     1_000_000, // retries never wait longer than 1 s
///     100_000,   // heartbeat every 100 ms
///     300_000,   // peer dead after 300 ms of silence
/// );
///
/// link.tick(0).unwrap();
/// assert!(link.is_up());
/// link.send(&Message::Data(b"hi".to_vec()), 0).unwrap();
///
/// let mut peer = Session::new(theirs, 100_000, 300_000);
/// assert!(peer.poll_at(1).unwrap().contains(&Message::Data(b"hi".to_vec())));
/// ```
pub struct Supervisor<T: Transport, C> {
    connect: C,
    reconnector: Reconnector,
    interval_us: u64,
    timeout_us: u64,
    session: Option<Session<T>>,
    connected_at_us: u64,
    attempts: u32,
}

impl<T, E, C> Supervisor<T, C>
where
    T: Transport,
    C: FnMut(u32) -> Result<T, E>,
{
    /// Creates a supervisor. The link starts down, and the first attempt is
    /// made on the first `tick`. `initial_us` and `max_us` shape the backoff
    /// between attempts. `interval_us` and `timeout_us` are passed to the
    /// `Session` once a link is up.
    pub fn new(
        connect: C,
        initial_us: u64,
        max_us: u64,
        interval_us: u64,
        timeout_us: u64,
    ) -> Self {
        Self {
            connect,
            reconnector: Reconnector::new(initial_us, max_us),
            interval_us,
            timeout_us,
            session: None,
            connected_at_us: 0,
            attempts: 0,
        }
    }

    /// Gives up after this many attempts in one outage. Call `restart` to
    /// begin again.
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.reconnector = self.reconnector.with_max_attempts(attempts);
        self
    }

    /// Whether a link is up.
    pub fn is_up(&self) -> bool {
        self.session.is_some()
    }

    /// Whether the attempt limit was reached. Cleared by `restart` or by a
    /// successful connection.
    pub fn gave_up(&self) -> bool {
        self.reconnector.gave_up()
    }

    /// Starts a fresh outage now after giving up, for example once the
    /// operator has fixed the cable.
    pub fn restart(&mut self, now_us: u64) {
        self.session = None;
        self.reconnector.restart(now_us);
    }

    /// Runs one step. Reconnects if it is time, sends a heartbeat if one is due,
    /// and returns the messages that have arrived.
    ///
    /// If the transport fails, or the peer has been silent past the timeout,
    /// the link is marked down and the next attempt is scheduled. A transport
    /// failure is returned as `Err` so the caller can log it. The caller keeps
    /// ticking either way.
    pub fn tick(&mut self, now_us: u64) -> Result<Vec<Message>, LinkError<T::Error>> {
        if self.session.is_none() && self.reconnector.tick(now_us) == Action::Attempt {
            self.connect_now(now_us);
        }

        let Some(session) = self.session.as_mut() else {
            return Ok(Vec::new());
        };
        // Drain first: a heartbeat that is already waiting counts as a sign of
        // life, so the liveness check must run after it.
        match session.tick(now_us).and_then(|()| session.poll_at(now_us)) {
            Ok(messages) => {
                if !self.is_alive(now_us) {
                    self.drop_link(now_us);
                }
                Ok(messages)
            }
            Err(e) => {
                self.drop_link(now_us);
                Err(e)
            }
        }
    }

    /// Sends one message over the current link, and counts as traffic at
    /// `now_us`. Returns `Down` without sending when no link is up.
    pub fn send(&mut self, message: &Message, now_us: u64) -> Result<u32, SendError<T::Error>> {
        let Some(session) = self.session.as_mut() else {
            return Err(SendError::Down);
        };
        match session.send_at(message, now_us) {
            Ok(seq) => Ok(seq),
            Err(e) => {
                self.drop_link(now_us);
                Err(SendError::Link(e))
            }
        }
    }

    /// Whether the link has heard from the peer recently. A new link is given
    /// one full timeout to hear its first message, so it is not dropped at once.
    fn is_alive(&self, now_us: u64) -> bool {
        let Some(session) = self.session.as_ref() else {
            return false;
        };
        session.is_alive(now_us) || now_us.saturating_sub(self.connected_at_us) < self.timeout_us
    }

    fn connect_now(&mut self, now_us: u64) {
        self.attempts += 1;
        if let Ok(transport) = (self.connect)(self.attempts) {
            self.session = Some(Session::new(transport, self.interval_us, self.timeout_us));
            self.connected_at_us = now_us;
            self.reconnector.on_connected();
            self.attempts = 0;
        }
    }

    fn drop_link(&mut self, now_us: u64) {
        self.session = None;
        self.attempts = 0;
        self.reconnector.on_link_down(now_us);
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use super::*;
    use crate::transport::Loopback;

    /// Shared state for a test: whether connects are refused, how many were
    /// made, and the peer end of every link opened so far.
    #[derive(Clone, Default)]
    struct Fixture {
        refuse: Rc<Cell<bool>>,
        attempts: Rc<Cell<u32>>,
        peers: Rc<RefCell<Vec<Loopback>>>,
    }

    impl Fixture {
        fn supervisor(&self) -> Supervisor<Loopback, impl FnMut(u32) -> Result<Loopback, ()>> {
            let f = self.clone();
            Supervisor::new(
                move |_attempt| {
                    f.attempts.set(f.attempts.get() + 1);
                    if f.refuse.get() {
                        return Err(());
                    }
                    let (ours, theirs) = Loopback::pair();
                    f.peers.borrow_mut().push(theirs);
                    Ok(ours)
                },
                100,
                1_000,
                1_000,
                10_000,
            )
        }
    }

    #[test]
    fn first_attempt_is_immediate() {
        let fx = Fixture::default();
        let mut sup = fx.supervisor();
        sup.tick(0).unwrap();
        assert!(sup.is_up());
        assert_eq!(fx.attempts.get(), 1);
    }

    #[test]
    fn retries_follow_the_backoff_until_connected() {
        let fx = Fixture::default();
        fx.refuse.set(true);
        let mut sup = fx.supervisor();

        sup.tick(0).unwrap(); // attempt 1, refused; next in 100 us
        assert_eq!(fx.attempts.get(), 1);
        sup.tick(50).unwrap(); // still waiting
        assert_eq!(fx.attempts.get(), 1);
        sup.tick(100).unwrap(); // attempt 2, refused; next in 200 us
        assert_eq!(fx.attempts.get(), 2);
        sup.tick(300).unwrap(); // attempt 3, refused; next in 400 us
        assert_eq!(fx.attempts.get(), 3);
        assert!(!sup.is_up());

        fx.refuse.set(false);
        sup.tick(700).unwrap(); // attempt 4 succeeds
        assert!(sup.is_up());
        assert_eq!(fx.attempts.get(), 4);
    }

    #[test]
    fn send_while_down_is_refused() {
        let fx = Fixture::default();
        fx.refuse.set(true);
        let mut sup = fx.supervisor();
        sup.tick(0).unwrap();
        assert!(matches!(
            sup.send(&Message::Data(b"x".to_vec()), 0),
            Err(SendError::Down)
        ));
    }

    #[test]
    fn send_on_a_live_link_reaches_the_peer() {
        let fx = Fixture::default();
        let mut sup = fx.supervisor();
        sup.tick(0).unwrap();
        sup.send(&Message::Data(b"hi".to_vec()), 0).unwrap();

        let theirs = fx.peers.borrow_mut().pop().unwrap();
        let mut peer = Session::new(theirs, 1_000, 10_000);
        let got = peer.poll_at(1).unwrap();
        assert!(got.contains(&Message::Data(b"hi".to_vec())), "{got:?}");
    }

    #[test]
    fn peer_traffic_keeps_the_link_up() {
        let fx = Fixture::default();
        let mut sup = fx.supervisor();
        sup.tick(0).unwrap();

        let theirs = fx.peers.borrow_mut().pop().unwrap();
        let mut peer = Session::new(theirs, 1_000, 10_000);
        peer.send_at(&Message::Heartbeat, 9_000).unwrap();

        sup.tick(15_000).unwrap();
        assert!(sup.is_up());
        assert_eq!(
            fx.attempts.get(),
            1,
            "no reconnect while the peer is talking"
        );
    }

    #[test]
    fn silent_peer_is_declared_dead_and_reconnected() {
        let fx = Fixture::default();
        let mut sup = fx.supervisor();
        sup.tick(0).unwrap();

        sup.tick(9_999).unwrap();
        assert_eq!(fx.attempts.get(), 1, "still within the grace period");

        // Silent for the full timeout: the link is dropped. The next attempt is
        // due at once, and it happens on the following tick.
        sup.tick(10_000).unwrap();
        assert!(!sup.is_up());
        assert_eq!(fx.attempts.get(), 1);

        sup.tick(10_001).unwrap();
        assert!(sup.is_up());
        assert_eq!(fx.attempts.get(), 2);
    }

    #[test]
    fn gives_up_after_the_attempt_limit() {
        let fx = Fixture::default();
        fx.refuse.set(true);
        let mut sup = fx.supervisor().with_max_attempts(2);

        sup.tick(0).unwrap();
        sup.tick(100).unwrap();
        assert!(!sup.gave_up());
        sup.tick(300).unwrap();
        assert!(sup.gave_up());
        assert_eq!(fx.attempts.get(), 2);

        fx.refuse.set(false);
        sup.restart(1_000);
        sup.tick(1_000).unwrap();
        assert!(sup.is_up());
    }
}
