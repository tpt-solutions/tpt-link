# Wire format (version 1)

This page is a byte-level guide to the frame format. The normative definition is
spec.txt, section 3. The worked examples below are the golden vectors in
[testdata/vectors.json](../testdata/vectors.json), which were produced by an
independent CRC implementation and are checked by `tests/vectors.rs`.

All multi-byte integers are little-endian.

## Layout

```
offset: 0        1 2 3 4        5 6        7 .. 6+n        7+n .. 10+n
       +--------+--------------+--------+--------------+--------------+
       |version | seq (u32 LE) | length | payload (n)  | CRC-32 (LE)  |
       | 1 B    | 4 B          | 2 B    | `length` B   | 4 B          |
       +--------+--------------+--------+--------------+--------------+
       |<-- header, 7 B ----->|                       |<- trailer ->|
       |<------ CRC covers every byte before the trailer ----------->|
```

| offset    | size | field   | meaning                                                  |
| --------- | ---- | ------- | -------------------------------------------------------- |
| 0         | 1    | version | `1`. Any other value is rejected, never guessed at.      |
| 1         | 4    | seq     | Sender's counter. Wraps at 2^32.                         |
| 5         | 2    | length  | Payload length, at most 1024 (`MAX_PAYLOAD_LEN`).        |
| 7         | n    | payload | `length` bytes, opaque to the link layer.                |
| 7 + n     | 4    | crc     | CRC-32 (IEEE 802.3) over bytes `0 .. 7 + n - 1`.         |

The smallest frame, with an empty payload, is 11 bytes. The largest is 1035 bytes.

## CRC-32

Reflected polynomial `0xEDB88320`, initial value `0xFFFFFFFF`, final XOR
`0xFFFFFFFF`. This is the same CRC as zlib, gzip and Ethernet. The check value is
`CRC-32("123456789") = 0xCBF43926`.

The CRC is stored little-endian, like every other integer in the frame.

## Worked example: `"hello"`, seq 7

Payload `68 65 6C 6C 6F` (ASCII `hello`).

```
offset  bytes                            field
------  -------------------------------  -------------------------
 0      01                               version = 1
 1..4   07 00 00 00                      seq = 7 (LE)
 5..6   05 00                            length = 5 (LE)
 7..11  68 65 6C 6C 6F                   payload "hello"
12..15  BF E1 41 6B                      CRC-32 = 0x6B41E1BF (LE)
```

Full wire bytes:

```
01 07 00 00 00 05 00 68 65 6c 6c 6f bf e1 41 6b
```

## Decoding

A receiver checks, in this order:

1. **Truncated.** The buffer ends before the header, or before `7 + length + 4`
   bytes.
2. **BadVersion.** Byte 0 is not `1`. The version is checked before the length, so
   a frame from a future version is reported as such.
3. **TooLarge.** The length field is above 1024.
4. **BadCrc.** The CRC in the trailer does not match the bytes received. Both the
   carried and computed values are reported.

A frame that fails any check is dropped and counted. It never reaches the
application (spec principle P1).

Decoding returns the payload as a slice borrowed from the input, plus the number
of bytes used, so back-to-back frames in one buffer can be decoded in turn.

## Byte-stream framing

Serial and USB-CDC deliver bytes, not frames. The deframer (`src/stream.rs`)
applies the same rules and, on a bad byte, discards one byte and rescans rather
than skipping the claimed length. Skipping the length would hide a good frame
that follows a corrupted header. See spec section 4 for the stall timeout.

## Compatibility

The version byte is the only compatibility mechanism. A change to any field
layout, the CRC, or the byte order requires a new version number. Receivers
reject unknown versions instead of guessing. The rules for the protobuf payloads
are in spec section 11 and the header of `proto/tpt_link.proto`.
