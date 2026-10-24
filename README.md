# tpt-link

Shared wire layer for the TPT ecosystem: the frame format, transports, sequencing,
heartbeat and reconnect policy. See [spec.txt](spec.txt) for the specification.

## Quickstart

```toml
[dependencies]
tpt-link = { git = "https://github.com/tpt-solutions/tpt-link", tag = "v0.2.0" }
# Inside the TPT repos: tpt-link = { path = "../tpt-link" }
```

```rust
use tpt_link::{Link, Loopback};

let (a, b) = Loopback::pair();           // swap for UdpTransport, SerialTransport, CanTransport
let (mut tx, mut rx) = (Link::new(a), Link::new(b));
tx.send(b"hello")?;
for payload in rx.poll()? {              // never blocks; damaged frames are counted and dropped
    println!("{}", String::from_utf8_lossy(&payload));
}
println!("{:?}", rx.stats());            // received, lost, crc_errors, ...
```

Minimum supported Rust version: 1.85, except for the `proto` feature, which
needs 1.88 because micropb does. The git dependency needs the `v0.2.0` tag
to be pushed first.

## Examples

Each runs with no hardware: `cargo run --example <name>`.

| Example | Shows |
| --- | --- |
| `loopback_hello` | The smallest send and receive |
| `udp_echo` | A client and an echo server over UDP |
| `fault_injection` | How drops and corruption show up in `LinkStats` |
| `heartbeat_monitor` | Declaring a silent peer dead, with injected time |
| `can_fragment` | A 600-byte frame over classic CAN, on a virtual bus |
| `session` | Typed messages, automatic heartbeats and liveness (`envelope::Session`) |
| `authenticated_udp` | Forged frames rejected over UDP (`--features auth`) |
| `reliable_link` | Exactly-once delivery over a link losing 30 % of frames (`reliable::Channel`) |
| `reconnect` | `Reconnector` and `Heartbeat` keeping a UDP link up |
| `schema_roundtrip` | A protobuf `Ack` inside a frame (`--features proto`) |

## Command-line helper

`tpt-link-cli` works offline, which is useful for frames copied out of a log or
a serial terminal:

```sh
cargo run --bin tpt-link-cli -- encode 3 "hi there"   # prints the frame as hex
cargo run --bin tpt-link-cli -- decode 0100000003...  # prints seq and payload, or the CRC error
cargo run --bin tpt-link-cli -- crc 123456789         # 0xcbf43926
```

## Choosing a transport

| Transport | Use it for | Feature | Notes |
| --- | --- | --- | --- |
| `UdpTransport` | Networks, host to host | default | Drops datagrams from any address but the peer |
| `SerialTransport` | UART, USB-CDC | `serial` | Uses the deframer with a 500 ms stall timeout |
| `CanTransport` | CAN and CAN FD buses | default | Fragments frames; needs a `CanBus` |
| `SocketCanBus` | Linux SocketCAN | `can-socketcan` | Classic CAN only for now |
| `Loopback`, `FaultyTransport` | Tests | default | In memory |

## Features

| Feature | Adds |
| --- | --- |
| `std` (default) | Transports, `Link`, heartbeat, reconnect, fragmentation |
| `alloc` | Frame encoding without `std` |
| none | `no_std` frame decoder |
| `serial` | `SerialTransport` |
| `can-socketcan` | `SocketCanBus` (Linux) |
| `proto` | Protobuf core messages in `schema` |
| `auth` | `auth::Authenticated`: encrypted, authenticated frames (see below) |

## Authentication

The CRC only catches damage. On UDP or CAN, anyone who can reach the port or the
bus can forge frames. Wrap the transport in `auth::Authenticated` and every frame
is encrypted and authenticated with ChaCha20-Poly1305, keyed with a 32-byte shared
secret. Listeners cannot read the payloads, and forged or
altered frames are dropped and counted before they reach the link.

Replays are refused too. The receiver issues a random nonce to each session, and
frames verify only under that nonce, so a recording from an earlier session fails.
Within a session, repeats and frames too far back to check are refused.

Restarts recover on their own. When the receiver restarts, the first frame it
cannot verify triggers a resync, and the sender begins a new session. That frame
and any sent before the resync arrives are lost, so use a `reliable::Channel` above
it if loss matters.

Limits: keys are shared and not rotated, and frame sizes and timing are visible. See the
`auth` module docs before relying on it.

## Troubleshooting

- **Serial port permission denied (Linux):** add your user to the `dialout`
  group, then log in again.
- **No CAN hardware:** use `VirtualBus`, or a virtual Linux interface:
  `sudo modprobe vcan && sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0`.
- **Windows CAN:** not supported yet, because the vendor runtimes fail the
  licence policy (see TODO.md).
- **Frames lost before the first one arrives are not counted:** the receiver has
  no expected sequence number until it sees a frame.
- **UDP frames never arrive:** the peer address must match the address the other
  side sends from, including the IP, or the datagrams are dropped (see `foreign()`).

## Features in brief

- **Frames**: versioned, CRC-32 checked, sequenced (`frame`).
- **Byte streams**: a deframer finds frames in serial or USB-CDC data, with a
  stall timeout for corrupted length fields (`stream`).
- **Transports**: `Loopback`, `UdpTransport`, `SerialTransport` (feature
  `serial`), and `FaultyTransport` for tests.
- **Link**: sequence numbers, loss counts, a `Heartbeat` for liveness, and a
  `Reconnector` with exponential backoff. See `examples/reconnect.rs`.
- **Messages**: an optional `envelope` layer puts a type byte (data, heartbeat,
  ack, error) in the payload, and `Session` sends heartbeats and tracks liveness.
  The frame format is unchanged, so a plain `Link` still interoperates.
- **Fragmentation**: splits messages larger than a small MTU, and reassembles them
  with expiry (`fragment`).
- **CAN**: `CanTransport` carries link frames over any `CanBus`. `SocketCanBus`
  (feature `can-socketcan`, Linux) and `VirtualBus` for tests are included.
- **Protobuf core**: `Heartbeat`, `Ack` and `Error` in `proto/tpt_link.proto`,
  generated into `schema` (feature `proto`). Regenerate with
  `cargo run --manifest-path tools/gen-schema/Cargo.toml`, which needs `protoc`.

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo test --features serial
cargo run --example reconnect   # and the other examples
cargo test --features proto
cargo test --features can-socketcan --test socketcan   # Linux, needs vcan0
cargo deny check licenses bans sources advisories
```

CI (`.github/workflows/ci.yml`) runs these checks on Linux, Windows and macOS,
and builds the core for the MCU targets `thumbv7em-none-eabihf` and
`riscv32imc-unknown-none-elf`.

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
Copyright (c) 2026 TPT Solutions.
