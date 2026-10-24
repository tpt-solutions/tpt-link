// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Serial and USB-CDC transport, built on `serial2` (BSD-2-Clause OR
//! Apache-2.0). Enabled with the `serial` feature.
//!
//! The port is a byte stream, so the `Deframer` finds the frame boundaries.
//! Reads use a short timeout (1 ms), so `try_recv` blocks for at most that long
//! when the line is idle. It is not strictly non-blocking.

use std::io::{self, ErrorKind};
use std::time::{Duration, Instant};

use serial2::SerialPort;

use crate::stream::Deframer;
use crate::transport::Transport;

/// Read timeout used by `try_recv`. Windows clamps timeouts to at least 1 ms,
/// so 1 ms is used everywhere to keep the behaviour the same on every platform.
const READ_TIMEOUT: Duration = Duration::from_millis(1);
/// Bytes requested per read call.
const READ_CHUNK: usize = 256;
/// Stall timeout for a partly received frame. A 1024-byte frame at 115200 bps
/// takes about 90 ms, so a gap of 500 ms means the frame is damaged, not slow.
const STALL_TIMEOUT_US: u64 = 500_000;

/// A serial port carrying link frames.
///
/// ```no_run
/// use tpt_link::{serial::SerialTransport, Transport};
///
/// let mut port = SerialTransport::open("COM3", 115_200).unwrap();
/// port.send(b"frame bytes").unwrap();
/// ```
pub struct SerialTransport {
    port: SerialPort,
    deframer: Deframer,
    /// The `Transport` trait has no time argument, so stall timing is measured
    /// from this origin. It is the only clock read in the crate, and it is
    /// needed because the trait cannot take a time.
    origin: Instant,
}

impl SerialTransport {
    /// Opens the port at `path` (for example `COM3` or `/dev/ttyACM0`) at
    /// `baud` bps.
    pub fn open(path: &str, baud: u32) -> io::Result<Self> {
        let mut port = SerialPort::open(path, baud)?;
        port.set_read_timeout(READ_TIMEOUT)?;
        Ok(Self {
            port,
            deframer: Deframer::with_timeout(STALL_TIMEOUT_US),
            origin: Instant::now(),
        })
    }

    /// Number of bytes discarded because a partly received frame stalled.
    pub fn stalls(&self) -> u64 {
        self.deframer.timeouts()
    }

    fn now_us(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_micros()).unwrap_or(u64::MAX)
    }
}

impl Transport for SerialTransport {
    type Error = io::Error;

    /// Writes the whole frame. If the write fails part way (a write timeout, or
    /// the device unplugged), a partial frame is already on the wire. The
    /// peer's deframer discards it and resynchronises on the next frame, so the
    /// caller only needs to send again.
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        self.port.write_all(frame)
    }

    fn try_recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        let now = self.now_us();
        // Frames already buffered come out first, before touching the port.
        if let Some(frame) = self.deframer.next_frame_at(now) {
            return Ok(Some(frame));
        }

        // The read can wait up to READ_TIMEOUT, so the time is taken again
        // afterwards. Otherwise the stall clock would lag by that long.
        let mut buf = [0u8; READ_CHUNK];
        match self.port.read(&mut buf) {
            Ok(0) => {}
            Ok(n) => self.deframer.push_at(&buf[..n], self.now_us()),
            // A signal interrupted the read. Nothing was lost; try again next call.
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
        Ok(self.deframer.next_frame_at(self.now_us()))
    }
}
