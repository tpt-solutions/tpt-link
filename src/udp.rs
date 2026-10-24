// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! UDP transport, built on `std::net` with no extra dependencies.

use std::io::{self, ErrorKind};
use std::net::{SocketAddr, UdpSocket};

use crate::frame::{CRC_LEN, HEADER_LEN, MAX_PAYLOAD_LEN};

use crate::transport::Transport;

/// Largest datagram a frame can produce.
const MAX_DATAGRAM: usize = HEADER_LEN + MAX_PAYLOAD_LEN + CRC_LEN;

/// A non-blocking UDP socket connected to one peer.
///
/// Each frame goes in one datagram, so frame boundaries come for free.
///
/// ```no_run
/// use tpt_link::{Transport, UdpTransport};
///
/// let mut t = UdpTransport::bind("0.0.0.0:7000", "192.168.4.2:7000".parse().unwrap()).unwrap();
/// t.send(b"frame").unwrap();
/// ```
#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpSocket,
    peer: SocketAddr,
}

impl UdpTransport {
    /// Binds a local address and sets the peer that frames are sent to. The
    /// socket is non-blocking, so `try_recv` never waits.
    pub fn bind<A: std::net::ToSocketAddrs>(local: A, peer: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(local)?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket, peer })
    }

    /// The local address the socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

impl Transport for UdpTransport {
    type Error = io::Error;

    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        let sent = self.socket.send_to(frame, self.peer)?;
        if sent != frame.len() {
            return Err(io::Error::new(
                ErrorKind::WriteZero,
                "datagram only partly sent",
            ));
        }
        Ok(())
    }

    fn try_recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut buf = [0u8; MAX_DATAGRAM];
        match self.socket.recv_from(&mut buf) {
            Ok((len, _from)) => Ok(Some(buf[..len].to_vec())),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}
