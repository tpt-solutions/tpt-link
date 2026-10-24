// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! A small seeded generator, used for repeatable test faults and reconnect
//! jitter. It is not suitable for anything that needs unpredictable values.

/// xorshift64. The same seed always gives the same sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    /// Creates a generator. A zero seed is replaced, because an all-zero state
    /// would never change.
    pub(crate) fn new(seed: u64) -> Self {
        let state = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self { state }
    }

    /// The next value, from the high 32 bits, which are the best ones.
    pub(crate) fn next_u32(&mut self) -> u32 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        (self.state >> 32) as u32
    }
}
