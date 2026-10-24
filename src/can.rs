// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! CAN transport. A link frame is split into fragments that fit the bus MTU
//! (8 bytes classic, 64 bytes FD) and sent as data frames. The receiver
//! reassembles them, so the rest of the stack sees one whole frame per message.
//!
//! The bus itself is behind the `CanBus` trait. SocketCAN and Windows adapters
//! implement it in their own crates or modules. `VirtualBus` is an in-memory
//! bus for tests, so CI needs no hardware.
//!
//! Identifier layout (standard 11-bit ID):
//!
//! | bits  | meaning                                             |
//! | ----- | --------------------------------------------------- |
//! | 10..8 | sender node, 0 to 7. A lower node wins arbitration. |
//! | 7..0  | message id, from the sender's own counter           |
//!
//! Each sender keeps its own counter, which wraps at 256. The receiver keeps
//! one reassembler per sending node, because message ids are only unique per
//! sender. A node never receives its own frames.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::fragment::{FragmentError, Reassembler, split};
use crate::transport::Transport;

/// Data bytes per frame on classic CAN.
pub const CLASSIC_MTU: usize = 8;
/// Data bytes per frame on CAN FD.
pub const FD_MTU: usize = 64;
/// Highest node id. Three bits of the identifier hold the node.
pub const MAX_NODE: u8 = 7;

/// A raw CAN data-frame bus. It carries no fragmentation of its own.
pub trait CanBus {
    /// Error type returned by the bus.
    type Error: std::error::Error + 'static;

    /// Most data bytes one frame on this bus can carry. `CanTransport::new`
    /// rejects an MTU above it. The default is CAN FD; a bus that carries only
    /// classic frames should return `CLASSIC_MTU`.
    fn max_data_len(&self) -> usize {
        FD_MTU
    }

    /// Sends one data frame with the 11-bit identifier `id`.
    fn send_raw(&mut self, id: u16, data: &[u8]) -> Result<(), Self::Error>;

    /// Returns the next waiting data frame and its identifier, or `None`. Never
    /// blocks.
    fn recv_raw(&mut self) -> Result<Option<(u16, Vec<u8>)>, Self::Error>;
}

/// Errors from `CanTransport`.
#[derive(Debug)]
pub enum CanError<E> {
    /// The bus failed.
    Bus(E),
    /// The frame could not be split for this MTU, for example because it is
    /// too large.
    Fragment(FragmentError),
    /// The node id does not fit in the identifier.
    InvalidNode(u8),
    /// The MTU is larger than a frame on this bus can carry, for example the
    /// FD size on a classic-only bus.
    MtuTooLarge {
        /// MTU that was asked for.
        mtu: usize,
        /// Largest data length the bus carries.
        max: usize,
    },
}

impl<E: fmt::Display> fmt::Display for CanError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bus(e) => write!(f, "bus: {e}"),
            Self::Fragment(e) => write!(f, "fragment: {e}"),
            Self::InvalidNode(n) => write!(f, "node {n} is above {MAX_NODE}"),
            Self::MtuTooLarge { mtu, max } => {
                write!(f, "MTU {mtu} is above the {max} bytes this bus carries")
            }
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for CanError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bus(e) => Some(e),
            Self::Fragment(e) => Some(e),
            Self::InvalidNode(_) | Self::MtuTooLarge { .. } => None,
        }
    }
}

/// Carries whole link frames over a CAN bus.
///
/// ```
/// use tpt_link::can::{CanTransport, VirtualBus, CLASSIC_MTU};
/// use tpt_link::Transport;
///
/// let bus = VirtualBus::new();
/// let mut a = CanTransport::new(bus.attach(), 1, CLASSIC_MTU, 1_000_000).unwrap();
/// let mut b = CanTransport::new(bus.attach(), 2, CLASSIC_MTU, 1_000_000).unwrap();
/// a.send(b"a whole frame, split across many CAN frames").unwrap();
/// assert_eq!(
///     b.try_recv().unwrap().as_deref(),
///     Some(&b"a whole frame, split across many CAN frames"[..]),
/// );
/// ```
pub struct CanTransport<B> {
    bus: B,
    node: u8,
    mtu: usize,
    timeout_us: u64,
    next_msg_id: u8,
    rx: HashMap<u8, Reassembler>,
    bad_fragments: u64,
    origin: Instant,
}

impl<B: CanBus> CanTransport<B> {
    /// Creates a transport for `node` on `bus`. `mtu` is `CLASSIC_MTU` or
    /// `FD_MTU`, or the size the bus carries. Partial messages expire after
    /// `timeout_us`.
    pub fn new(bus: B, node: u8, mtu: usize, timeout_us: u64) -> Result<Self, CanError<B::Error>> {
        if node > MAX_NODE {
            return Err(CanError::InvalidNode(node));
        }
        // Fail here rather than on the first send.
        if mtu <= crate::fragment::HEADER_LEN {
            return Err(CanError::Fragment(FragmentError::InvalidMtu(mtu)));
        }
        if mtu > bus.max_data_len() {
            return Err(CanError::MtuTooLarge {
                mtu,
                max: bus.max_data_len(),
            });
        }
        Ok(Self {
            bus,
            node,
            mtu,
            timeout_us,
            next_msg_id: 0,
            rx: HashMap::new(),
            bad_fragments: 0,
            origin: Instant::now(),
        })
    }

    /// Like `try_recv`, but the caller supplies the time, so that partial
    /// messages can be expired deterministically in tests.
    pub fn try_recv_at(&mut self, now_us: u64) -> Result<Option<Vec<u8>>, CanError<B::Error>> {
        for reassembler in self.rx.values_mut() {
            reassembler.expire(now_us);
        }
        while let Some((id, data)) = self.bus.recv_raw().map_err(CanError::Bus)? {
            // Only the low 11 bits are an identifier; mask so a bus that returns
            // more cannot create extra senders.
            let sender = ((id >> 8) & 0x7) as u8;
            if sender == self.node {
                continue;
            }
            let timeout_us = self.timeout_us;
            let reassembler = self
                .rx
                .entry(sender)
                .or_insert_with(|| Reassembler::new(timeout_us));
            match reassembler.push(now_us, &data) {
                Ok(Some(message)) => return Ok(Some(message)),
                Ok(None) => {}
                // Damaged fragments never reach the caller (principle P1).
                Err(_) => self.bad_fragments += 1,
            }
        }
        Ok(None)
    }

    /// Fragments that were malformed and dropped.
    pub fn bad_fragments(&self) -> u64 {
        self.bad_fragments
    }

    /// Partial messages replaced because their id was reused, across all senders.
    pub fn replaced_partials(&self) -> u64 {
        self.rx.values().map(Reassembler::replaced).sum()
    }

    /// Partial messages dropped by timeout, across all senders.
    pub fn expired_partials(&self) -> u64 {
        self.rx.values().map(Reassembler::expired).sum()
    }

    /// Partial messages still waiting for fragments, across all senders.
    pub fn pending(&self) -> usize {
        self.rx.values().map(Reassembler::pending).sum()
    }

    fn now_us(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_micros()).unwrap_or(u64::MAX)
    }
}

impl<B: CanBus> Transport for CanTransport<B> {
    type Error = CanError<B::Error>;

    fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        let msg_id = self.next_msg_id;
        let parts = split(msg_id, frame, self.mtu).map_err(CanError::Fragment)?;
        // Every fragment of one message uses the same identifier.
        let id = (u16::from(self.node) << 8) | u16::from(msg_id);
        for part in &parts {
            self.bus.send_raw(id, part).map_err(CanError::Bus)?;
        }
        self.next_msg_id = self.next_msg_id.wrapping_add(1);
        Ok(())
    }

    fn try_recv(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        let now = self.now_us();
        self.try_recv_at(now)
    }
}

#[derive(Default)]
struct BusState {
    queues: Vec<VecDeque<(u16, Vec<u8>)>>,
    drop_next: usize,
}

/// An in-memory CAN bus. Every frame goes to every attached node except the
/// sender, as on a real bus. It is lossless unless `drop_next` is used.
///
/// ```
/// use tpt_link::can::{CanBus, VirtualBus};
///
/// let bus = VirtualBus::new();
/// let mut a = bus.attach();
/// let mut b = bus.attach();
/// a.send_raw(0x105, b"hi").unwrap();
/// assert_eq!(b.recv_raw().unwrap(), Some((0x105, b"hi".to_vec())));
/// ```
#[derive(Clone, Default)]
pub struct VirtualBus {
    state: Arc<Mutex<BusState>>,
}

impl VirtualBus {
    /// Creates a bus with no nodes attached.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attaches a new node. Frames sent after this point reach it.
    pub fn attach(&self) -> VirtualNode {
        let mut state = self.lock();
        let index = state.queues.len();
        state.queues.push(VecDeque::new());
        VirtualNode {
            bus: self.clone(),
            index,
        }
    }

    /// Locks the shared state. A panic in another thread must not take the
    /// whole bus down, and the state stays consistent after any single push or
    /// pop, so a poisoned lock is used as it is.
    fn lock(&self) -> std::sync::MutexGuard<'_, BusState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Silently drops the next `count` frames sent on the bus.
    pub fn drop_next(&self, count: usize) {
        self.lock().drop_next += count;
    }
}

/// One attached node on a `VirtualBus`.
pub struct VirtualNode {
    bus: VirtualBus,
    index: usize,
}

impl CanBus for VirtualNode {
    type Error = Infallible;

    fn send_raw(&mut self, id: u16, data: &[u8]) -> Result<(), Infallible> {
        let mut state = self.bus.lock();
        if state.drop_next > 0 {
            state.drop_next -= 1;
            return Ok(());
        }
        for (index, queue) in state.queues.iter_mut().enumerate() {
            if index != self.index {
                queue.push_back((id, data.to_vec()));
            }
        }
        Ok(())
    }

    fn recv_raw(&mut self) -> Result<Option<(u16, Vec<u8>)>, Infallible> {
        let mut state = self.bus.lock();
        Ok(state.queues[self.index].pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{MAX_PAYLOAD_LEN, decode, encode};

    const TIMEOUT_US: u64 = 1_000_000;

    /// Delivers a fixed list of frames, in the order given. Used to test
    /// interleaving and reordering exactly.
    struct Script(VecDeque<(u16, Vec<u8>)>);

    impl CanBus for Script {
        type Error = Infallible;
        fn send_raw(&mut self, _: u16, _: &[u8]) -> Result<(), Infallible> {
            Ok(())
        }
        fn recv_raw(&mut self) -> Result<Option<(u16, Vec<u8>)>, Infallible> {
            Ok(self.0.pop_front())
        }
    }

    /// The fragments a sender would put on the bus for `frame`.
    fn fragments(node: u8, msg_id: u8, frame: &[u8], mtu: usize) -> Vec<(u16, Vec<u8>)> {
        let id = (u16::from(node) << 8) | u16::from(msg_id);
        split(msg_id, frame, mtu)
            .unwrap()
            .into_iter()
            .map(|part| (id, part))
            .collect()
    }

    fn link_frame(seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        encode(seq, payload, &mut wire).unwrap();
        wire
    }

    fn receiver(frames: Vec<(u16, Vec<u8>)>) -> CanTransport<Script> {
        CanTransport::new(Script(frames.into()), 7, CLASSIC_MTU, TIMEOUT_US).unwrap()
    }

    #[test]
    fn largest_link_frame_round_trips_on_classic_can() {
        let payload = vec![0xA5; MAX_PAYLOAD_LEN];
        let wire = link_frame(9, &payload);
        let bus = VirtualBus::new();
        let mut a = CanTransport::new(bus.attach(), 1, CLASSIC_MTU, TIMEOUT_US).unwrap();
        let mut b = CanTransport::new(bus.attach(), 2, CLASSIC_MTU, TIMEOUT_US).unwrap();
        a.send(&wire).unwrap();
        assert_eq!(b.try_recv_at(0).unwrap(), Some(wire.clone()));
        assert_eq!(decode(&wire).unwrap().0.payload, &payload[..]);
    }

    #[test]
    fn fd_mtu_round_trips() {
        let wire = link_frame(3, b"fd payload");
        let bus = VirtualBus::new();
        let mut a = CanTransport::new(bus.attach(), 0, FD_MTU, TIMEOUT_US).unwrap();
        let mut b = CanTransport::new(bus.attach(), 1, FD_MTU, TIMEOUT_US).unwrap();
        a.send(&wire).unwrap();
        assert_eq!(b.try_recv_at(0).unwrap(), Some(wire));
    }

    #[test]
    fn a_node_does_not_receive_its_own_frames() {
        let bus = VirtualBus::new();
        let mut a = CanTransport::new(bus.attach(), 4, CLASSIC_MTU, TIMEOUT_US).unwrap();
        a.send(b"echo?").unwrap();
        assert_eq!(a.try_recv_at(0).unwrap(), None);
    }

    #[test]
    fn interleaved_messages_from_two_nodes_are_kept_apart() {
        let first = link_frame(1, b"from node one, longer than one fragment");
        let second = link_frame(2, b"from node two, also longer than one fragment");
        let a = fragments(1, 0, &first, CLASSIC_MTU);
        let b = fragments(2, 0, &second, CLASSIC_MTU);
        // Alternate the two senders' fragments on the wire. Both use message id 0,
        // which is the case the per-sender reassemblers exist for.
        let mut wire = Vec::new();
        for i in 0..a.len().max(b.len()) {
            wire.extend(a.get(i).cloned());
            wire.extend(b.get(i).cloned());
        }
        let mut rx = receiver(wire);
        let mut got: Vec<Vec<u8>> = Vec::new();
        while let Some(message) = rx.try_recv_at(0).unwrap() {
            got.push(message);
        }
        assert_eq!(got, vec![first, second]);
    }

    #[test]
    fn reordered_fragments_are_reassembled() {
        let wire = link_frame(5, b"reversed on the wire");
        let mut parts = fragments(0, 1, &wire, CLASSIC_MTU);
        parts.reverse();
        let mut rx = receiver(parts);
        assert_eq!(rx.try_recv_at(0).unwrap(), Some(wire));
    }

    #[test]
    fn lost_fragment_is_never_delivered_and_later_messages_still_arrive() {
        let bus = VirtualBus::new();
        let mut a = CanTransport::new(bus.attach(), 1, CLASSIC_MTU, TIMEOUT_US).unwrap();
        let mut b = CanTransport::new(bus.attach(), 2, CLASSIC_MTU, TIMEOUT_US).unwrap();

        // Drop the first fragment of the first message.
        bus.drop_next(1);
        a.send(b"this one loses a fragment").unwrap();
        a.send(b"this one arrives").unwrap();

        assert_eq!(
            b.try_recv_at(0).unwrap().as_deref(),
            Some(&b"this one arrives"[..]),
        );
        assert_eq!(b.try_recv_at(0).unwrap(), None);
        assert_eq!(b.pending(), 1);
    }

    #[test]
    fn incomplete_message_expires_and_its_late_fragments_do_not_complete_it() {
        let wire = link_frame(6, b"a message whose last fragment is late");
        let parts = fragments(0, 2, &wire, CLASSIC_MTU);
        let (last, rest) = parts.split_last().unwrap();
        let mut rx = receiver(rest.to_vec());
        assert_eq!(rx.try_recv_at(0).unwrap(), None);
        assert_eq!(rx.pending(), 1);

        // The partial message is dropped after the timeout. The late fragment then
        // starts a new partial, so nothing is delivered.
        rx.bus.0.push_back(last.clone());
        assert_eq!(rx.try_recv_at(TIMEOUT_US + 1).unwrap(), None);
        assert_eq!(rx.pending(), 1);
    }

    #[test]
    fn frame_too_large_for_one_message_is_rejected() {
        let bus = VirtualBus::new();
        let mut a = CanTransport::new(bus.attach(), 0, CLASSIC_MTU, TIMEOUT_US).unwrap();
        let too_big = vec![0; 5 * 256 + 1];
        assert!(matches!(
            a.send(&too_big),
            Err(CanError::Fragment(FragmentError::TooLarge { .. }))
        ));
    }

    #[test]
    fn node_above_seven_is_rejected() {
        let bus = VirtualBus::new();
        let result = CanTransport::new(bus.attach(), 8, CLASSIC_MTU, TIMEOUT_US);
        assert!(matches!(result, Err(CanError::InvalidNode(8))));
    }

    #[test]
    fn mtu_above_what_the_bus_carries_is_rejected() {
        struct Classic(Script);
        impl CanBus for Classic {
            type Error = Infallible;
            fn max_data_len(&self) -> usize {
                CLASSIC_MTU
            }
            fn send_raw(&mut self, id: u16, data: &[u8]) -> Result<(), Infallible> {
                self.0.send_raw(id, data)
            }
            fn recv_raw(&mut self) -> Result<Option<(u16, Vec<u8>)>, Infallible> {
                self.0.recv_raw()
            }
        }
        let result = CanTransport::new(Classic(Script(VecDeque::new())), 0, FD_MTU, TIMEOUT_US);
        assert!(matches!(
            result,
            Err(CanError::MtuTooLarge { mtu: 64, max: 8 })
        ));
    }

    #[test]
    fn mtu_without_room_for_data_is_rejected_at_construction() {
        let bus = VirtualBus::new();
        let result = CanTransport::new(bus.attach(), 0, 3, TIMEOUT_US);
        assert!(matches!(
            result,
            Err(CanError::Fragment(FragmentError::InvalidMtu(3)))
        ));
    }

    #[test]
    fn identifier_bits_above_the_node_field_do_not_make_new_senders() {
        // 0x805 and 0x005 are the same sender once masked to 11 bits.
        let wire = link_frame(1, b"split across several fragments");
        let parts = fragments(1, 0, &wire, CLASSIC_MTU);
        let mut frames = Vec::new();
        for (i, (id, data)) in parts.into_iter().enumerate() {
            frames.push((if i % 2 == 0 { id } else { id | 0x800 }, data));
        }
        let mut rx = receiver(frames);
        assert_eq!(rx.try_recv_at(0).unwrap(), Some(wire));
    }

    #[test]
    fn malformed_fragment_is_counted_and_dropped() {
        // An empty data field has no fragment header, so it cannot be parsed.
        let mut rx = receiver(vec![(0x100, vec![])]);
        assert_eq!(rx.try_recv_at(0).unwrap(), None);
        assert_eq!(rx.bad_fragments(), 1);
    }
}
