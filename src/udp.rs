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
    foreign: u64,
}

impl UdpTransport {
    /// Binds a local address and sets the peer that frames are sent to. The
    /// socket is non-blocking, so `try_recv` never waits.
    pub fn bind<A: std::net::ToSocketAddrs>(local: A, peer: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(local)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            peer,
            foreign: 0,
        })
    }

    /// Datagrams dropped because they came from an address other than the peer.
    pub fn foreign(&self) -> u64 {
        self.foreign
    }

    /// The local address the socket is bound to.
    ///
    /// ```
    /// use tpt_link::UdpTransport;
    ///
    /// let t = UdpTransport::bind("127.0.0.1:0", "127.0.0.1:9".parse().unwrap()).unwrap();
    /// assert!(t.local_addr().unwrap().port() != 0);
    /// ```
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
        loop {
            match self.socket.recv_from(&mut buf) {
                Ok((len, from)) if from == self.peer => return Ok(Some(buf[..len].to_vec())),
                // The CRC is not authentication, so anyone who can reach the
                // port could inject frames. Only the peer's datagrams are kept.
                Ok(_) => self.foreign += 1,
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(None),
                // Windows reports an earlier send to a closed port as a receive
                // error on an unconnected socket. It says nothing about the
                // datagrams waiting behind it, so carry on.
                Err(e) if e.kind() == ErrorKind::ConnectionReset => {}
                Err(e) => return Err(e),
            }
        }
    }
}
