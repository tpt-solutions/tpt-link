// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Serial transport checks that do not need hardware. The round trip through a
//! real port is still to be done on a bench (see todo.md).

#![cfg(feature = "serial")]

use tpt_link::serial::SerialTransport;

#[test]
fn opening_a_missing_port_is_an_error_not_a_panic() {
    assert!(SerialTransport::open("tpt-no-such-port", 115_200).is_err());
}
