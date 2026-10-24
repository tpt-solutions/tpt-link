# Threat model: `auth::Authenticated`

Written for an independent reviewer. It describes the protocol as implemented in
`src/auth.rs`, what it is meant to resist, and what it does not resist. It is
not a security claim: the design and code have not been reviewed by anyone
other than their author.

## What is protected

- **Frame integrity and origin.** A frame that reaches the link was sealed under
  a session key that only the two ends hold.
- **Payload confidentiality** against a passive listener on the link.
- **Freshness.** A recorded frame is not accepted in a later session, and a
  repeat or a frame far back in the same session is refused.
- **Forward secrecy** of past sessions against later disclosure of the
  pre-shared key, because session keys come from ephemeral X25519 secrets that
  are discarded.

## What is not protected

- **Traffic analysis.** Frame sizes, timing and the existence of traffic are
  visible.
- **Availability.** An attacker who can drop or inject traffic can stop a link.
  A replayed hello ends the current session (see below). Authentication does not
  stop jamming.
- **The pre-shared key.** Whoever holds it can impersonate either end in new
  sessions. Past sessions stay secret, but future ones do not.
- **Key distribution.** Pre-shared keys are installed out of band. The code has
  no certificates, no enrolment, and no third party.

## Adversaries

| Adversary | Capability | Expected outcome |
| --- | --- | --- |
| Passive listener | Reads every byte on the link | Cannot read payloads. Sees sizes and timing. |
| Active forger | Injects and alters bytes, without any key | Frames are refused, and counted in `rejected()`. |
| Replayer | Records and re-injects valid frames | Refused in a later session, and in the same session when a repeat or too old. |
| Hello replayer | Re-injects a recorded hello | Makes the receiver issue a new session nonce. That ends the current session, which is denial of service and not a bypass. |
| Stale-challenge replayer | Re-injects a recorded challenge | Refused, because it does not echo the sender's current public key. |
| Key-holder | Holds the pre-shared key | Can impersonate either end in new sessions. Past sessions stay secret. |

## Protocol

Each side holds one or more pre-shared keys, each with a one-byte id. Messages:

- **Hello** (sender to receiver): type `0xC0`, key id, sender's X25519 public
  key, 16-byte HMAC-SHA256 tag over those fields under the pre-shared key.
- **Challenge** (receiver to sender): type `0xC1`, key id, fresh 16-byte nonce,
  receiver's public key, echo of the sender's public key, tag over those fields.
- **Resync** (receiver to sender): type `0xC2`, key id, tag. Sent once when the
  receiver has no session with the sender and receives a frame it cannot verify.
- **Data**: type `0xD0`, key id, fresh 12-byte random nonce, then the frame
  sealed with ChaCha20-Poly1305 under the session key. The session nonce is
  bound in as associated data.

Session key (one per direction):

    K = HKDF-SHA256(salt = psk, ikm = X25519(e_sender, e_receiver),
                    info = "tpt-link session v1" || nonce || e_sender || e_receiver)

Within a session, a 64-entry sliding window (`seqwin::SeqWindow`) refuses
repeated and stale sequence numbers. The sequence number is read from the
decrypted frame, after the frame has been authenticated.

## Primitives and dependencies

| Use | Primitive | Crate (version) |
| --- | --- | --- |
| Data sealing | ChaCha20-Poly1305 | `chacha20poly1305` 0.10 |
| Control tags | HMAC-SHA256 (truncated to 16 bytes) | `hmac` 0.12, `sha2` 0.10 |
| Key agreement | X25519 | `x25519-dalek` 2 |
| Key derivation | HKDF-SHA256 | `hkdf` 0.12 |
| Randomness | OS random source | `getrandom` 0.2 |
| Wiping secrets | `zeroize` | `zeroize` 1 |

Everything above is from RustCrypto or dalek. The composition is the author's.

## Design decisions for the reviewer to check

1. **Random message nonces.** Each data message uses a fresh 96-bit random
   nonce, not a counter. This avoids keeping nonce state across restarts. The
   bound on messages per key is about 2^48 before collisions become likely. Keys
   are per session, so a session should not carry that many messages.
2. **Ephemeral reuse across retries.** The sender reuses its ephemeral key for
   repeated hellos until the session starts. The receiver reuses its nonce and
   ephemeral key for repeated hellos while the session has carried no data.
   Both are deliberate, to stop duplicate hellos from churning state.
3. **Low-order points.** An X25519 result of all zeros is refused, on both
   sides.
4. **Key id is not in the AEAD associated data.** It is not authenticated
   separately. A wrong id selects a different key, so decryption fails. The
   check `wire[1] == psk_id` on data is a fast reject, not a security control.
5. **Control messages are not encrypted.** They carry public keys and nonces,
   and the tags cover them.

## Known weaknesses

- **Secrets in memory.** Keys and ephemeral secrets are wiped on drop, but
   intermediate copies made by the compiler (for example when a `[u8; 32]` is
   passed by value) are not. A process memory dump can expose them.
- **Lost frames at a receiver restart.** When the receiver restarts, the first
  frame it cannot verify is lost, and so are frames sent before the resync
  arrives. Nothing is replayed, but those frames do not arrive.
- **Hello flooding.** Anyone who can send a valid hello (needs the pre-shared
  key) can end a session. A replayed hello does the same without the key. Both
  are denial of service.
- **Pre-shared key rotation is manual.** Retiring a key ends sessions made with
  it, but the operator must coordinate install, activate and retire on both ends.
- **Timing side channels** in the Rust code are not analysed. The crypto crates
  are assumed to be constant-time where it matters. Tag comparisons use
  `verify_truncated_left`.
- **No formal analysis.** The handshake has not been checked with a protocol
  verifier (for example Tamarin or ProVerif).

## Tests that exercise these properties

All in `src/auth.rs`, module `tests`:

| Property | Test |
| --- | --- |
| Frames flow after the handshake | `frames_flow_once_the_session_is_up` |
| Payload not readable on the wire | `the_payload_is_not_readable_on_the_wire` |
| Fresh session keys | `session_keys_are_fresh_and_are_not_the_pre_shared_key` |
| Repeat in the same session refused | `a_repeat_within_the_session_is_refused` |
| Frame far back refused | `a_frame_far_back_in_the_session_is_refused` |
| Earlier-session frame refused | `a_frame_from_an_earlier_session_is_refused` |
| Forged hello gets no challenge | `a_forged_hello_gets_no_challenge` |
| Hello with unknown key id refused | `a_hello_naming_an_unknown_key_is_refused` |
| Tampered data refused | `a_tampered_frame_is_dropped` |
| Tampered challenge refused | `a_tampered_challenge_is_refused` |
| Stale challenge refused | `a_challenge_for_an_earlier_hello_is_refused` |
| Restart recovers via resync | `a_restarted_receiver_recovers_without_renew` |
| One resync per stream of refusals | `a_resync_is_sent_once_for_a_stream_of_refused_frames` |
| Rotation without a stale key | `rotation_starts_a_new_session_under_the_new_key` |
| Retired key refused | `a_frame_under_a_retired_key_is_refused` |
| Key-management errors | `key_management_refuses_unknown_and_active_keys` |

Not tested: a real adversary, a timing analysis, zeroing of compiler copies, and
the behaviour under loss beyond the simple cases above.

## Questions for the reviewer

1. Is the session key derivation sound for this use? In particular, is putting
   the pre-shared key in the HKDF salt, and the nonce and both public keys in
   `info`, the right composition?
2. Does the challenge's echo of the sender's public key stop every stale or
   cross-session challenge, given that the challenge is MACed under the
   pre-shared key?
3. Is reusing the receiver's ephemeral key for repeated hellos (while no data has
   been accepted) acceptable, or does it weaken forward secrecy for that session?
4. Are random 96-bit nonces acceptable at the message volumes this link will
   carry, with keys per session?
5. Should the hello and resync be rate-limited to reduce the denial-of-service
   surface?
