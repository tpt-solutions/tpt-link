# Changelog

All notable changes to this crate. Versions follow semver. Below 1.0.0, breaking
changes bump the minor version.

## 0.2.0

### Added
- `stream::Deframer::with_timeout`, `push_at` and `next_frame_at`. A frame that
  stalls on a corrupted length field is abandoned after the timeout, so a good
  frame behind it is delivered. Discards are counted by `timeouts()`.
- `SerialTransport::stalls()`, and a 500 ms stall timeout on the serial deframer.
- `can::CanTransport`: link frames fragmented over any `CanBus` (8-byte classic or
  64-byte FD), with one reassembler per sending node. `can::VirtualBus` is an
  in-memory bus for tests.
- `can_socketcan::SocketCanBus` (feature `can-socketcan`, Linux only), tested in
  CI over a `vcan0` interface.
- `schema`: `Heartbeat`, `Ack` and `Error` from `proto/tpt_link.proto` (feature
  `proto`). Generated with micropb by `tools/gen-schema`, and no_std compatible.
- `examples/reconnect.rs`: `Reconnector` and `Heartbeat` driving a UDP link.
- 21 doc examples on the public API.
- `.github/workflows/ci.yml`: fmt, clippy, tests on Linux, Windows and macOS,
  doc warnings, MCU no_std builds, SocketCAN over vcan0, and cargo deny.

### Known limitations
- A UDP open only binds a local socket, so backoff does not apply to a link that
  opens but goes silent. See spec section 8.
- The serial stall timeout and SocketCAN have not been checked on hardware.
- No Windows CAN adapter. Proprietary adapter runtimes fail the licence policy.

## 0.1.0

- Frame format v1 with CRC-32, and the byte-stream deframer.
- Transports: Loopback, FaultyTransport, UdpTransport, and SerialTransport
  behind the `serial` feature.
- Link with sequence numbers and loss counts, Heartbeat, Backoff and
  Reconnector.
- Fragmentation and reassembly for small-MTU transports.
