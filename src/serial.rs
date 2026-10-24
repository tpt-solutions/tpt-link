// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Serial and USB-CDC transport, built on `serial2` (BSD-2-Clause OR
//! Apache-2.0). Enabled with the `serial` feature.
//!
//! The port is a byte stream, so the `Deframer` finds the frame boundaries.
//! Reads use a short timeout so that `try_recv` never blocks for long.

use std::io::{self, ErrorKind};
use std::time::Duration;

use serial2::SerialPort;

use crate::stream::Deframer;
use crate::transport::Transport;

/// Read timeout used by `try_recv`. Windows clamps timeouts to at least 1 ms,
/// so 1 ms is used everywhere to keep the behaviour the same on every platform.
const READ_TIMEOUT: Duration = Duration::from_millis(1);
/// Bytes requested per read call.
const READ_CHUNK: usize = 256;

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
}

impl SerialTransport {
    /// Opens the port at `path` (for example `COM3` or `/dev/ttyACM0`) at
    /// `baud` bps.
    pub fn open(path: &str, baud: u32) -> io::Result<Self> {
        let mut port = SerialPort::open(path, baud)?;
        port.set_read_timeout(READ_TIMEOUT)?;
        Ok(Self {
            port,
            deframer: Deframer::new(),
        })
    }
}

impl Transport for SerialTransport {
    type Error = io::Error;

    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        self.port.write_all(frame)
    }

    fn try_recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        // Frames already buffered come out first, before touching the port.
        if let Some(frame) = self.deframer.next_frame() {
            return Ok(Some(frame));
        }

        let mut buf = [0u8; READ_CHUNK];
        match self.port.read(&mut buf) {
            Ok(0) => {}
            Ok(n) => self.deframer.push(&buf[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {}
            Err(e) => return Err(e),
        }
        Ok(self.deframer.next_frame())
    }
}
