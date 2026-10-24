// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Reconnect policy: exponential backoff, and a small state machine that tells
//! the caller when to try to bring the link back up.
//!
//! The caller drives it. It feeds in the heartbeat result with `on_link_down`
//! and `on_connected`, and calls `tick` on a timer. It never touches the
//! transport itself, so the same policy works for serial, UDP and CAN.

use crate::rng::Xorshift64;

/// Exponential backoff. Each call returns the wait before the next retry: it
/// starts at `initial_us` and doubles up to `max_us`. Optional jitter shortens
/// each wait by a random share, so many devices that lost the same host do not
/// all retry at the same instant.
///
/// ```
/// use tpt_link::reconnect::Backoff;
///
/// let mut b = Backoff::new(100_000, 500_000);
/// let waits: Vec<u64> = (0..5).map(|_| b.next_delay()).collect();
/// assert_eq!(waits, vec![100_000, 200_000, 400_000, 500_000, 500_000]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    initial_us: u64,
    max_us: u64,
    attempts: u32,
    jitter_percent: u8,
    rng: Xorshift64,
}

impl Backoff {
    /// Creates a backoff. `initial_us` is raised to at least 1 so the schedule
    /// never degenerates into a busy retry, and `max_us` is clamped to at
    /// least `initial_us`.
    pub fn new(initial_us: u64, max_us: u64) -> Self {
        let initial_us = initial_us.max(1);
        Self {
            initial_us,
            max_us: max_us.max(initial_us),
            attempts: 0,
            jitter_percent: 0,
            rng: Xorshift64::new(0),
        }
    }

    /// Adds jitter. Each wait is shortened by a random amount of up to
    /// `percent` of itself (values above 100 are treated as 100). The generator
    /// is seeded, so the same seed gives the same waits. Jitter only shortens a
    /// wait, so the schedule never exceeds `max_us`.
    ///
    /// ```
    /// use tpt_link::reconnect::Backoff;
    ///
    /// let mut b = Backoff::new(1_000, 1_000).with_jitter(20, 42);
    /// let wait = b.next_delay();
    /// assert!((800..=1_000).contains(&wait));
    /// ```
    pub fn with_jitter(mut self, percent: u8, seed: u64) -> Self {
        self.jitter_percent = percent.min(100);
        self.rng = Xorshift64::new(seed);
        self
    }

    /// Wait before the next retry, in microseconds. Each call moves the
    /// schedule on by one step.
    pub fn next_delay(&mut self) -> u64 {
        // The shift is capped so it stays below 64. A product that overflows
        // saturates, and the clamp then brings it down to the maximum.
        let shift = self.attempts.min(63);
        let base = self.initial_us.saturating_mul(1 << shift).min(self.max_us);
        self.attempts = self.attempts.saturating_add(1);
        if self.jitter_percent == 0 {
            return base;
        }
        let spread = base / 100 * u64::from(self.jitter_percent);
        let cut = u64::from(self.rng.next_u32()) % (spread + 1);
        (base - cut).max(1)
    }

    /// Starts the schedule again, after a successful connection.
    pub fn reset(&mut self) {
        self.attempts = 0;
    }
}

/// What the caller should do now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Nothing to do.
    Wait,
    /// Try to open the transport now.
    Attempt,
    /// The attempt limit for this outage is used up. The reconnector stops
    /// trying until `restart` is called.
    GiveUp,
}

/// Decides when to retry a link that has gone down.
///
/// ```
/// use tpt_link::reconnect::{Action, Reconnector};
///
/// let mut r = Reconnector::new(100_000, 500_000);
/// r.on_link_down(0);
/// assert_eq!(r.tick(0), Action::Attempt);      // first try is immediate
/// assert_eq!(r.tick(50_000), Action::Wait);    // next try is 100 ms later
/// assert_eq!(r.tick(100_000), Action::Attempt);
/// r.on_connected();
/// assert!(r.is_up());
/// ```
///
/// With an attempt limit, the reconnector gives up after that many tries in
/// one outage.
///
/// ```
/// use tpt_link::reconnect::{Action, Reconnector};
///
/// let mut r = Reconnector::new(100, 500).with_max_attempts(2);
/// r.on_link_down(0);
/// assert_eq!(r.tick(0), Action::Attempt);
/// assert_eq!(r.tick(100), Action::Attempt);
/// assert_eq!(r.tick(300), Action::GiveUp);
/// assert!(r.gave_up());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reconnector {
    backoff: Backoff,
    up: bool,
    next_attempt_us: u64,
    max_attempts: Option<u32>,
    attempts: u32,
    gave_up: bool,
}

impl Reconnector {
    /// Creates a reconnector, starting in the `down` state. The first attempt
    /// happens on the first `tick`. With no attempt limit it retries forever.
    pub fn new(initial_us: u64, max_us: u64) -> Self {
        Self {
            backoff: Backoff::new(initial_us, max_us),
            up: false,
            next_attempt_us: 0,
            max_attempts: None,
            attempts: 0,
            gave_up: false,
        }
    }

    /// Sets how many attempts one outage may use before the reconnector gives
    /// up. The count restarts whenever the link comes back up.
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = Some(attempts);
        self
    }

    /// Replaces the backoff, for example to add jitter.
    pub fn with_backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// Whether the link is currently up.
    pub fn is_up(&self) -> bool {
        self.up
    }

    /// Whether the attempt limit has been reached. Cleared by `restart` or by a
    /// successful connection.
    pub fn gave_up(&self) -> bool {
        self.gave_up
    }

    /// Call when the heartbeat reports the link dead. Attempts resume with the
    /// backoff schedule starting again. Calling it while the link is already
    /// down does nothing, so a caller may report the outage on every tick
    /// without defeating the backoff or the attempt count.
    pub fn on_link_down(&mut self, now_us: u64) {
        if !self.up {
            return;
        }
        self.up = false;
        self.start_outage(now_us);
    }

    /// Call after a successful connection. Backoff and the attempt count are
    /// reset for the next outage.
    pub fn on_connected(&mut self) {
        self.up = true;
        self.gave_up = false;
        self.backoff.reset();
        self.attempts = 0;
    }

    /// Starts a fresh outage now, for a caller that has given up and wants to
    /// try again, for example after the operator has fixed the cable.
    pub fn restart(&mut self, now_us: u64) {
        self.up = false;
        self.start_outage(now_us);
    }

    /// Call on a timer. Returns `Attempt` when it is time to try to connect,
    /// and `GiveUp` once when the attempt limit is reached.
    pub fn tick(&mut self, now_us: u64) -> Action {
        if self.up || self.gave_up || now_us < self.next_attempt_us {
            return Action::Wait;
        }
        if self.max_attempts.is_some_and(|max| self.attempts >= max) {
            self.gave_up = true;
            return Action::GiveUp;
        }
        self.attempts += 1;
        self.next_attempt_us = now_us.saturating_add(self.backoff.next_delay());
        Action::Attempt
    }

    fn start_outage(&mut self, now_us: u64) {
        self.gave_up = false;
        self.backoff.reset();
        self.attempts = 0;
        self.next_attempt_us = now_us;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_then_caps() {
        let mut b = Backoff::new(100, 500);
        let delays: Vec<u64> = (0..6).map(|_| b.next_delay()).collect();
        assert_eq!(delays, vec![100, 200, 400, 500, 500, 500]);
    }

    #[test]
    fn backoff_reset_starts_again() {
        let mut b = Backoff::new(100, 500);
        b.next_delay();
        b.next_delay();
        b.reset();
        assert_eq!(b.next_delay(), 100);
    }

    #[test]
    fn backoff_never_overflows_on_long_outages() {
        let mut b = Backoff::new(1, u64::MAX);
        for _ in 0..200 {
            b.next_delay();
        }
        // Shift capped at 63, so the delay tops out at 2^63 rather than overflowing.
        assert_eq!(b.next_delay(), 1 << 63);
    }

    #[test]
    fn reconnector_retries_on_schedule_and_stops_when_up() {
        let mut r = Reconnector::new(100, 500);
        r.on_link_down(1_000);
        assert_eq!(r.tick(1_000), Action::Attempt);
        assert_eq!(r.tick(1_099), Action::Wait);
        assert_eq!(r.tick(1_100), Action::Attempt);
        assert_eq!(r.tick(1_300), Action::Attempt); // 200 after the last attempt

        r.on_connected();
        assert!(r.is_up());
        assert_eq!(r.tick(u64::MAX), Action::Wait);
    }

    #[test]
    fn repeated_link_down_does_not_reset_the_backoff() {
        let mut r = Reconnector::new(100, 500);
        r.on_link_down(0);
        assert_eq!(r.tick(0), Action::Attempt);
        r.on_link_down(50);
        assert_eq!(r.tick(50), Action::Wait);
        assert_eq!(r.tick(100), Action::Attempt);
    }

    #[test]
    fn zero_initial_delay_is_not_a_busy_retry() {
        let mut b = Backoff::new(0, 0);
        assert_eq!(b.next_delay(), 1);
    }

    #[test]
    fn a_new_outage_starts_the_schedule_again() {
        let mut r = Reconnector::new(100, 500);
        r.on_link_down(0);
        r.tick(0);
        r.tick(100);
        r.on_connected();
        r.on_link_down(10_000);
        assert_eq!(r.tick(10_000), Action::Attempt);
    }

    #[test]
    fn gives_up_after_the_attempt_limit_until_restarted() {
        let mut r = Reconnector::new(100, 500).with_max_attempts(2);
        r.on_link_down(0);
        assert_eq!(r.tick(0), Action::Attempt);
        assert_eq!(r.tick(100), Action::Attempt);
        assert_eq!(r.tick(300), Action::GiveUp);
        assert!(r.gave_up());
        assert_eq!(r.tick(u64::MAX), Action::Wait);

        r.restart(1_000);
        assert!(!r.gave_up());
        assert_eq!(r.tick(1_000), Action::Attempt);
    }

    #[test]
    fn a_connection_resets_the_attempt_count() {
        let mut r = Reconnector::new(100, 500).with_max_attempts(1);
        r.on_link_down(0);
        assert_eq!(r.tick(0), Action::Attempt);
        r.on_connected();
        r.on_link_down(10_000);
        assert_eq!(r.tick(10_000), Action::Attempt);
    }

    #[test]
    fn jitter_only_shortens_waits_and_is_repeatable() {
        let run = |seed| {
            let mut b = Backoff::new(1_000, 1_000).with_jitter(20, seed);
            (0..50).map(|_| b.next_delay()).collect::<Vec<u64>>()
        };
        let waits = run(5);
        assert!(waits.iter().all(|w| (800..=1_000).contains(w)), "{waits:?}");
        assert!(waits.iter().any(|&w| w < 1_000), "jitter never applied");
        assert_eq!(waits, run(5));
        assert_ne!(waits, run(6));
    }
}
