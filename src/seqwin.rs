// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! A sliding window over sequence numbers. It tells a new number from a repeat,
//! and counts how many numbers were skipped before a new one. `Link` uses it for
//! frames, `Channel` for message ids, and `Authenticated` to refuse replays.

/// How far behind the highest number a late arrival may be and still be
/// checked against the window. One bit per number, so the width is 64.
pub(crate) const WINDOW: u32 = u64::BITS;

/// What happened to a number passed to `SeqWindow::arrive`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arrival {
    /// A number not seen before. `skipped` counts the numbers missing before it.
    New { skipped: u32 },
    /// The same number arrived again.
    Repeat,
    /// The number is further behind than the window, so it cannot be checked
    /// against it. Only returned when restarts are not allowed.
    Stale,
}

/// Remembers the highest number seen and which of the numbers below it arrived.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SeqWindow {
    highest: Option<u32>,
    /// Bit `n` is set when `highest - n` has arrived.
    seen: u64,
}

impl SeqWindow {
    /// Records `seq`. Returns `None` for a repeat, which must not be delivered
    /// again. Otherwise returns `Some(skipped)`, the count of numbers missing
    /// before this one. A late arrival that fills an earlier gap returns
    /// `Some(0)`, because its gap was already counted. A number far behind the
    /// window is taken as a sender restart, so the window starts again.
    pub(crate) fn accept(&mut self, seq: u32) -> Option<u32> {
        match self.arrive(seq, true) {
            Arrival::New { skipped } => Some(skipped),
            Arrival::Repeat | Arrival::Stale => None,
        }
    }

    /// Like `accept`, but a number far behind the window is `Stale` and the
    /// window is not restarted. For use where a replayed number must be refused.
    pub(crate) fn arrive_strict(&mut self, seq: u32) -> Arrival {
        self.arrive(seq, false)
    }

    fn arrive(&mut self, seq: u32, allow_restart: bool) -> Arrival {
        let Some(highest) = self.highest else {
            self.highest = Some(seq);
            self.seen = 1;
            return Arrival::New { skipped: 0 };
        };

        // Distances wrap, and the half of the number space above zero counts as
        // ahead. This keeps wraparound working.
        let ahead = seq.wrapping_sub(highest);
        if ahead == 0 {
            return Arrival::Repeat;
        }
        if ahead < 0x8000_0000 {
            self.seen = if ahead >= WINDOW {
                0
            } else {
                self.seen << ahead
            };
            self.seen |= 1;
            self.highest = Some(seq);
            return Arrival::New { skipped: ahead - 1 };
        }

        let behind = highest.wrapping_sub(seq);
        if behind >= WINDOW {
            if !allow_restart {
                return Arrival::Stale;
            }
            // Too far back to be a late arrival, so the sender has restarted.
            self.seen = 1;
            self.highest = Some(seq);
            return Arrival::New { skipped: 0 };
        }
        let bit = 1u64 << behind;
        if self.seen & bit != 0 {
            return Arrival::Repeat;
        }
        self.seen |= bit;
        Arrival::New { skipped: 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_skips_and_repeats() {
        let mut w = SeqWindow::default();
        assert_eq!(w.accept(0), Some(0));
        assert_eq!(w.accept(3), Some(2));
        assert_eq!(w.accept(3), None);
        assert_eq!(w.accept(1), Some(0));
        assert_eq!(w.accept(1), None);
    }

    #[test]
    fn wraps_around_the_top_of_the_space() {
        let mut w = SeqWindow::default();
        assert_eq!(w.accept(u32::MAX), Some(0));
        assert_eq!(w.accept(0), Some(0));
        assert_eq!(w.accept(1), Some(0));
    }

    #[test]
    fn strict_mode_refuses_numbers_beyond_the_window() {
        let mut w = SeqWindow::default();
        assert_eq!(w.arrive_strict(0), Arrival::New { skipped: 0 });
        assert_eq!(w.arrive_strict(200), Arrival::New { skipped: 199 });
        assert_eq!(w.arrive_strict(0), Arrival::Stale);
        assert_eq!(w.arrive_strict(200), Arrival::Repeat);
    }
}
