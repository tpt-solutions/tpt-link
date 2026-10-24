// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! A sliding window over sequence numbers. It tells a new number from a repeat,
//! and counts how many numbers were skipped before a new one. `Link` uses it for
//! frames and `Channel` uses it for message ids.

/// How far behind the highest number a late arrival may be and still be
/// checked against the window. One bit per number, so the width is 64.
pub(crate) const WINDOW: u32 = u64::BITS;

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
    /// `Some(0)`, because its gap was already counted.
    pub(crate) fn accept(&mut self, seq: u32) -> Option<u32> {
        let Some(highest) = self.highest else {
            self.highest = Some(seq);
            self.seen = 1;
            return Some(0);
        };

        // Distances wrap, and the half of the number space above zero counts as
        // ahead. This keeps wraparound working.
        let ahead = seq.wrapping_sub(highest);
        if ahead == 0 {
            return None;
        }
        if ahead < 0x8000_0000 {
            self.seen = if ahead >= WINDOW {
                0
            } else {
                self.seen << ahead
            };
            self.seen |= 1;
            self.highest = Some(seq);
            return Some(ahead - 1);
        }

        let behind = highest.wrapping_sub(seq);
        if behind >= WINDOW {
            // Too far back to be a late arrival, so the sender has restarted.
            self.seen = 1;
            self.highest = Some(seq);
            return Some(0);
        }
        let bit = 1u64 << behind;
        if self.seen & bit != 0 {
            return None;
        }
        self.seen |= bit;
        Some(0)
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
}
