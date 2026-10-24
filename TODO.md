# tpt-link TODO

Legend: [x] done, [ ] to do. Section numbers refer to spec.txt.

## A. Spec audit (what exists)
- [x] 3  Frame v1 encode/decode, CRC-32, error variants (src/frame.rs)
- [x] 3  CRC check value test (0xCBF43926), bit-flip, truncation, bad version, oversize tests
- [x] 4  Stream deframer: resync, oversize skip, CRC-fail single-byte discard (src/stream.rs)
- [x] 5  Transport trait + Loopback (src/transport.rs)
- [x] 5  FaultyTransport drop/corrupt (src/fault.rs)
- [x] 5  UdpTransport (src/udp.rs)
- [x] 5  SerialTransport, `serial` feature (src/serial.rs)
- [x] 6  Link: sequence numbers, counters, loss detection, wraparound (src/link.rs)
- [x] 7  Heartbeat
- [x] 8  Backoff + Reconnector (src/reconnect.rs)
- [x] 9  Feature matrix (none/alloc/std/serial)
- [x] 10 Fragmentation + reassembly + expire() (src/fragment.rs)
- [x] 14 deny.toml licence policy
- [x] 12 Loopback, UDP integration tests; serial open-error test
- [x] 12 Doc tests on every main public type/function (21 examples; checked by reading the public API)
- [x] 12 no_std builds verified for thumbv7em-none-eabihf and riscv32imc-unknown-none-elf (core and alloc)
- [x] 8  Wire Reconnector to a live transport (examples/reconnect.rs; spec 13.5). Caveat in spec 8: UDP open never fails once bound
- [x] README: document fragmentation, reconnect, features beyond current summary

## B. Hosting and CI (spec 13.7, 12)
- [ ] Create GitHub repo (PhillipC05/tpt-link), set remote, push (default branch main; local is master)
- [ ] Decide `publish = false` stays or crate is published
- [x] CI: cargo fmt --check (.github/workflows/ci.yml, not yet run on GitHub)
- [x] CI: cargo clippy --all-targets -- -D warnings (default + serial; no-default-features lints the lib only, since tests need std)
- [x] CI: cargo test (default, --features serial, Linux + Windows + macOS) (workflow written; run locally on Windows only)
- [x] CI: cargo deny check licenses bans sources advisories (passes locally)
- [x] CI: no_std build for thumbv7em-none-eabihf and riscv32imc-unknown-none-elf
- [x] CI: doc tests + `cargo doc` with warnings denied
- [ ] Branch protection / required checks

## C. Deframer timeout (spec 4, 13.4)
- [x] Decide design: time injected per P4 (`push_at(bytes, now_us)`, `next_frame_at(now_us)`), configurable `timeout_us` via `with_timeout`
- [x] Define behaviour: on timeout with an incomplete frame, discard one byte and rescan
- [x] Count timeouts in a stat/counter (`Deframer::timeouts`, `SerialTransport::stalls`)
- [x] Implement in src/stream.rs without a global clock (edge case: a stale byte equal to the version byte is read as a frame start and costs one extra timeout)
- [x] Tests: corrupted length stalls then recovers; good frame behind a bad length is delivered; no false timeout on slow-but-valid frames
- [x] Update spec section 4 (remove "known weakness") and 13.4
- [x] Wire into SerialTransport (note: the Transport trait has no time argument, so it measures from an Instant taken at open. Not yet tried on hardware)

## D. CAN transport (spec 10, 13.3)
- [ ] Licence check of candidate crates (socketcan, windows adapter libs); record result in deny.toml/spec (no new crates added yet; the SocketCAN and Windows choices are still open)
- [x] Choose approach: `Transport` impl over CAN with fragmentation (src/can.rs, generic over `CanBus`; MTU 8 classic, 64 FD)
- [x] Define CAN ID usage (arbitration ID per node/message id) and spec it (spec 10)
- [x] Message-id (u8) allocation and wraparound rules (spec 10)
- [x] Hook `expire()` into transport tick using injected time (`CanTransport::try_recv_at`)
- [ ] Linux SocketCAN transport behind a `can` feature (vcan for tests)
- [ ] Windows adapter transport (pick adapter, e.g. PCAN/Kvaser; confirm licence)
- [x] Mock CAN bus for CI tests (no hardware): `can::VirtualBus`
- [x] Tests: fragment loss, interleaving, reorder, timeout over the mock bus
- [x] Update feature matrix (spec 9) and spec 5/10

## E. Protobuf schema (spec 1, 13.1)
- [ ] Locate or recreate the real tpt-link schema; reconcile with provisional draft in tpt-hands/proto
- [ ] Decide where schema lives (this repo `proto/`) and who consumes it
- [ ] Decide codegen strategy (prost vs hand-written); check licence per policy
- [ ] Define core messages (e.g. heartbeat, ack, error) as a minimal shared set
- [ ] Schema versioning/compat rules (spec 11 addendum)
- [ ] Tests: encode/decode round trip inside frame payload
- [ ] Update spec to own the schema section

## F. Release
- [ ] Update spec status (partly implemented -> current) and version
- [x] CHANGELOG.md
- [ ] Tag v0.2.0 after A-E complete
