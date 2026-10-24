// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Loopback harness: two `Link`s talk over an in-memory channel, with faults
//! injected on the sending side.

use tpt_link::{Closed, FaultyTransport, Heartbeat, Link, LinkError, Loopback};

type Faulty = FaultyTransport<Loopback>;

fn linked_pair() -> (Link<Faulty>, Link<Loopback>) {
    let (a, b) = Loopback::pair();
    (Link::new(FaultyTransport::new(a)), Link::new(b))
}

#[test]
fn payloads_arrive_in_order_with_no_loss() {
    let (mut a, mut b) = linked_pair();
    for i in 0..5u8 {
        assert_eq!(a.send(&[i]).unwrap(), u32::from(i));
    }

    let got = b.poll().unwrap();
    assert_eq!(got, (0..5u8).map(|i| vec![i]).collect::<Vec<_>>());
    assert_eq!(b.stats().received, 5);
    assert_eq!(b.stats().lost, 0);
    assert_eq!(a.stats().sent, 5);
}

#[test]
fn dropped_frame_is_counted_as_lost() {
    let (mut a, mut b) = linked_pair();
    a.send(b"one").unwrap();
    a.transport_mut().drop_next(1);
    a.send(b"two").unwrap();
    a.send(b"three").unwrap();

    assert_eq!(b.poll().unwrap(), vec![b"one".to_vec(), b"three".to_vec()]);
    assert_eq!(b.stats().lost, 1);
    assert_eq!(b.stats().crc_errors, 0);
}

#[test]
fn corrupted_frame_is_dropped_and_counted() {
    let (mut a, mut b) = linked_pair();
    // Establish the sequence first. Loss before the first received frame
    // cannot be seen, because the receiver has no expected number yet.
    a.send(b"ok").unwrap();
    assert_eq!(b.poll().unwrap(), vec![b"ok".to_vec()]);

    a.transport_mut().corrupt_next(1);
    a.send(b"damaged").unwrap();
    a.send(b"fine").unwrap();

    // The damaged frame never reaches the caller. Its sequence number is lost
    // with it, so the gap shows up as one lost frame.
    assert_eq!(b.poll().unwrap(), vec![b"fine".to_vec()]);
    assert_eq!(b.stats().crc_errors, 1);
    assert_eq!(b.stats().lost, 1);
}

#[test]
fn oversize_payload_is_a_frame_error_not_sent() {
    let (mut a, mut b) = linked_pair();
    let huge = vec![0u8; tpt_link::frame::MAX_PAYLOAD_LEN + 1];
    assert!(matches!(a.send(&huge), Err(LinkError::Frame(_))));
    assert_eq!(a.stats().sent, 0);
    assert!(b.poll().unwrap().is_empty());
}

#[test]
fn peer_disconnect_is_reported_by_poll() {
    let (a, b) = Loopback::pair();
    let mut b = Link::new(b);
    drop(a);

    match b.poll() {
        Err(LinkError::Transport(Closed)) => {}
        other => panic!("expected Closed, got {other:?}"),
    }
}

#[test]
fn heartbeat_follows_traffic_and_detects_silence() {
    let (mut a, mut b) = linked_pair();
    let mut heartbeat = Heartbeat::new(100_000);

    a.send(b"alive").unwrap();
    let arrived = b.poll().unwrap();
    assert_eq!(arrived.len(), 1);
    heartbeat.on_frame(1_000);
    assert!(heartbeat.is_alive(101_000));

    // No more traffic: the link is declared dead once the timeout passes.
    assert!(!heartbeat.is_alive(101_001));
}

#[test]
fn sequence_numbers_wrap_without_counting_false_loss() {
    let (a, b) = Loopback::pair();
    let mut a = Link::new(a);
    let mut b = Link::new(b);

    // Start the sender near the top of the sequence space.
    a.set_next_seq(u32::MAX - 1);
    for payload in [b"x", b"y", b"z"] {
        a.send(payload).unwrap();
    }

    assert_eq!(b.poll().unwrap().len(), 3);
    assert_eq!(b.stats().lost, 0);
}
