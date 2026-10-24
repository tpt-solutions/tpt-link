// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Core messages travel inside link frame payloads and decode back unchanged.

#![cfg(feature = "proto")]

use micropb::{MessageDecode, MessageEncode, PbEncoder};
use tpt_link::frame::{decode, encode};
use tpt_link::schema::v1::{Ack, Error, Heartbeat};

/// Encodes `msg` into a link frame with sequence number `seq`.
fn frame_of<M: MessageEncode>(seq: u32, msg: &M) -> Vec<u8> {
    let mut payload = vec![0u8; M::MAX_SIZE.expect("bounded message")];
    let mut encoder = PbEncoder::new(&mut payload[..]);
    msg.encode(&mut encoder).unwrap();
    let len = msg.compute_size();
    let mut wire = Vec::new();
    encode(seq, &payload[..len], &mut wire).unwrap();
    wire
}

/// Decodes the payload of a frame into a fresh `M`.
fn message_from<M: Default + MessageDecode>(wire: &[u8]) -> M {
    let (frame, _) = decode(wire).unwrap();
    let mut msg = M::default();
    msg.decode_from_bytes(frame.payload).unwrap();
    msg
}

#[test]
fn ack_round_trips_inside_a_frame() {
    let ack = Ack { seq: 0xDEAD_BEEF };
    let wire = frame_of(11, &ack);
    assert_eq!(message_from::<Ack>(&wire), ack);
}

#[test]
fn error_round_trips_inside_a_frame() {
    let error = Error { code: 300 };
    let wire = frame_of(12, &error);
    assert_eq!(message_from::<Error>(&wire), error);
}

#[test]
fn heartbeat_is_an_empty_payload() {
    let wire = frame_of(13, &Heartbeat {});
    let (frame, _) = decode(&wire).unwrap();
    assert!(frame.payload.is_empty());
    assert_eq!(message_from::<Heartbeat>(&wire), Heartbeat {});
}

#[test]
fn default_values_are_not_sent() {
    // Proto3 omits zero-valued scalars, so a zero Ack is a zero-length payload.
    let wire = frame_of(14, &Ack { seq: 0 });
    let (frame, _) = decode(&wire).unwrap();
    assert!(frame.payload.is_empty());
    assert_eq!(message_from::<Ack>(&wire), Ack { seq: 0 });
}
