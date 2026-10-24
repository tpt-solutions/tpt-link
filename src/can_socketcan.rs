// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! SocketCAN bus for Linux, built on the `socketcan` crate (MIT). Enabled with
//! the `can-socketcan` feature. The `CanTransport` in `can` runs on top of it.
//!
//! Test it on Linux with a virtual interface, which needs no hardware:
//!
//! ```sh
//! sudo modprobe vcan
//! sudo ip link add dev vcan0 type vcan
//! sudo ip link set up vcan0
//! ```

use std::io::{self, ErrorKind};

use socketcan::{CanDataFrame, CanFrame, EmbeddedFrame, Id, Socket, StandardId};

use crate::can::CanBus;

/// Most non-data frames `recv_raw` skips before it returns `None` for this call.
const MAX_SKIPPED: usize = 256;

/// A SocketCAN interface, such as `vcan0` or `can0`.
///
/// ```no_run
/// use tpt_link::can::CanTransport;
/// use tpt_link::can_socketcan::SocketCanBus;
///
/// let bus = SocketCanBus::open("vcan0").unwrap();
/// let transport = CanTransport::new(bus, 1, tpt_link::can::CLASSIC_MTU, 1_000_000).unwrap();
/// # let _ = transport;
/// ```
pub struct SocketCanBus {
    socket: socketcan::CanSocket,
}

impl SocketCanBus {
    /// Opens the interface named `ifname`. The socket is non-blocking, so
    /// `recv_raw` never waits.
    pub fn open(ifname: &str) -> io::Result<Self> {
        let socket = socketcan::CanSocket::open(ifname)?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket })
    }
}

impl CanBus for SocketCanBus {
    type Error = io::Error;

    fn send_raw(&mut self, id: u16, data: &[u8]) -> io::Result<()> {
        let standard = StandardId::new(id)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "identifier above 11 bits"))?;
        let frame = CanDataFrame::new(standard, data).ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidInput, "data longer than the bus MTU")
        })?;
        // A full transmit queue is reported as WouldBlock. The caller sees it as
        // a send error, and the frame is not sent.
        self.socket.write_frame(&frame)
    }

    /// Classic CAN only: this socket is not a CAN FD socket.
    fn max_data_len(&self) -> usize {
        crate::can::CLASSIC_MTU
    }

    fn recv_raw(&mut self) -> io::Result<Option<(u16, Vec<u8>)>> {
        // Foreign traffic is skipped, but only a bounded number of frames per
        // call, so a busy bus cannot keep one call from returning.
        for _ in 0..MAX_SKIPPED {
            let frame = match self.socket.read_frame() {
                Ok(frame) => frame,
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(None),
                // A signal interrupted the read. Nothing was lost.
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            // Only standard data frames carry link fragments. Remote, error and
            // extended frames are skipped.
            if let CanFrame::Data(data) = frame {
                if let Id::Standard(standard) = data.id() {
                    return Ok(Some((standard.as_raw(), data.data().to_vec())));
                }
            }
        }
        Ok(None)
    }
}
