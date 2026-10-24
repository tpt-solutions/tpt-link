// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Reconnect policy: exponential backoff, and a small state machine that tells
//! the caller when to try to bring the link back up.
//!
//! The caller drives it. It feeds in the heartbeat result with `on_link_down`
//! and `on_connected`, and calls `tick` on a timer. It never touches the
//! transport itself, so the same policy works for serial, UDP and CAN.

/// Exponential backoff. Each call returns the wait before the next retry: it
/// starts at `initial_us` and doubles up to `max_us`.
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
        }
    }

    /// Wait before the next retry, in microseconds. Each call moves the
    /// schedule on by one step.
    pub fn next_delay(&mut self) -> u64 {
        // The shift is capped so it stays below 64. A product that overflows
        // saturates, and the clamp then brings it down to the maximum.
        let shift = self.attempts.min(63);
        let delay = self.initial_us.saturating_mul(1 << shift).min(self.max_us);
        self.attempts = self.attempts.saturating_add(1);
        delay
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reconnector {
    backoff: Backoff,
    up: bool,
    next_attempt_us: u64,
}

impl Reconnector {
    /// Creates a reconnector, starting in the `down` state. The first attempt
    /// happens on the first `tick`.
    pub fn new(initial_us: u64, max_us: u64) -> Self {
        Self {
            backoff: Backoff::new(initial_us, max_us),
            up: false,
            next_attempt_us: 0,
        }
    }

    /// Whether the link is currently up.
    pub fn is_up(&self) -> bool {
        self.up
    }

    /// Call when the heartbeat reports the link dead. Attempts resume with the
    /// backoff schedule starting again. Calling it while the link is already
    /// down does nothing, so a caller may report the outage on every tick
    /// without defeating the backoff.
    pub fn on_link_down(&mut self, now_us: u64) {
        if !self.up {
            return;
        }
        self.up = false;
        self.backoff.reset();
        self.next_attempt_us = now_us;
    }

    /// Call after a successful connection. Backoff is reset for the next outage.
    pub fn on_connected(&mut self) {
        self.up = true;
        self.backoff.reset();
    }

    /// Call on a timer. Returns `Attempt` when it is time to try to connect.
    /// After an `Attempt`, the next one is scheduled from the backoff.
    pub fn tick(&mut self, now_us: u64) -> Action {
        if self.up || now_us < self.next_attempt_us {
            return Action::Wait;
        }
        self.next_attempt_us = now_us.saturating_add(self.backoff.next_delay());
        Action::Attempt
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
}
