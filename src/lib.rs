// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Shared wire layer for the TPT ecosystem. See `spec.txt`.
//!
//! The `frame` module is `no_std`: decoding needs only `core`, and encoding needs
//! the `alloc` feature. Everything else needs `std` (the default).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod frame;

#[cfg(feature = "std")]
pub mod can;
#[cfg(feature = "std")]
pub mod fault;
#[cfg(feature = "std")]
pub mod fragment;
#[cfg(feature = "std")]
pub mod link;
#[cfg(feature = "std")]
pub mod reconnect;
#[cfg(feature = "serial")]
pub mod serial;
#[cfg(feature = "std")]
pub mod stream;
#[cfg(feature = "std")]
pub mod transport;
#[cfg(feature = "std")]
pub mod udp;

#[cfg(feature = "std")]
pub use fault::FaultyTransport;
#[cfg(feature = "std")]
pub use link::{Heartbeat, Link, LinkError, LinkStats};
#[cfg(feature = "std")]
pub use transport::{Closed, Loopback, Transport};
#[cfg(feature = "std")]
pub use udp::UdpTransport;
