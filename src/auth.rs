// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Message authentication and encryption for frames carried in the open, such as
//! UDP and CAN. Enabled with the `auth` feature.
//!
//! The link CRC catches damage, but anyone who can reach the port or the bus
//! can compute it, so it cannot tell a real frame from a forged one.
//! `Authenticated` wraps a transport and seals every frame with
//! ChaCha20-Poly1305, under a session key that the two ends agree on
//! automatically.
//!
//! Each side holds pre-shared keys, identified by a one-byte id that every
//! message carries. The pre-shared key authenticates the handshake, and it also
//! feeds the session key derivation. Control messages (hello, challenge and
//! resync) carry an HMAC-SHA256 tag under the pre-shared key.
//!
//! Each session is set up like this:
//!
//! 1. A sender with no session sends a signed *hello* with a fresh X25519
//!    public key, and queues its frames.
//! 2. The receiver answers with a signed *challenge*. It holds a fresh random
//!    nonce and its own X25519 public key, and it echoes the sender's public key
//!    so the sender can match the challenge to its hello.
//! 3. Both ends compute the same session key, from the X25519 shared secret,
//!    the pre-shared key, the nonce and both public keys. Data is sealed under
//!    the session key, with the nonce bound in as associated data.
//! 4. Within a session, the sequence window refuses repeats, and refuses
//!    numbers too far back to check, rather than treating them as a restart.
//!
//! What this gives: every frame that reaches the link was made by a holder of
//! the session key, and was not altered. A replay from an earlier session or
//! from far back in this one is refused. Payloads are encrypted, so a listener
//! cannot read them. Session keys come from fresh ephemeral keys, so an earlier
//! session stays secret even if the pre-shared key leaks later.
//!
//! What it does not give:
//!
//! - **Lossless restarts.** When the receiver restarts, it sends a resync for
//!   the first frame it cannot verify, and the sender starts a new session. That
//!   frame is lost, and so are frames sent before the resync arrives. A sender
//!   that restarts begins a session on its first send. `renew` forces a new
//!   session when the application wants one.
//! - **Hello flooding protection.** A replayed hello makes the receiver issue a
//!   new nonce, which ends the current session. That is denial of service, not
//!   a way to inject frames.
//! - **Pre-shared key distribution.** The pre-shared keys are shared out of
//!   band. Rotating them is done by the application: install the new key on both
//!   ends, activate it on both, then retire the old key. See `install_key`.
//! - **Traffic analysis.** Frame sizes and timing are visible.

use std::collections::VecDeque;
use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::frame::{HEADER_LEN, VERSION};
use crate::seqwin::{Arrival, SeqWindow};
use crate::transport::Transport;

type HmacSha256 = Hmac<Sha256>;

/// Bytes in a pre-shared key, and in a session key.
pub const KEY_LEN: usize = 32;
/// Bytes of tag on each control message.
pub const TAG_LEN: usize = 16;
/// Bytes in a session nonce.
pub const NONCE_LEN: usize = 16;
/// Bytes in an X25519 public key.
const PUBLIC_LEN: usize = 32;
/// Bytes in the random nonce sent with each data message.
const MESSAGE_NONCE_LEN: usize = 12;
/// Most pre-shared keys a side holds at once. Two overlap a rotation. The rest
/// is headroom for a slow rollout.
const MAX_KEYS: usize = 4;

/// First byte of a hello. It is not a frame version, so the two never clash.
const TYPE_HELLO: u8 = 0xC0;
/// First byte of a challenge.
const TYPE_CHALLENGE: u8 = 0xC1;
/// First byte of a resync. Sent by a receiver that has no session with the
/// sender, which tells the sender to start one again with a hello.
const TYPE_RESYNC: u8 = 0xC2;
/// First byte of a data message. The frame inside is sealed, so it has no
/// readable first byte, and this type byte keeps data apart from control.
const TYPE_DATA: u8 = 0xD0;
/// Hello: type, key id, sender's public key, tag.
const HELLO_LEN: usize = 2 + PUBLIC_LEN + TAG_LEN;
/// Challenge: type, key id, nonce, receiver's public key, echo of the sender's
/// public key, tag.
const CHALLENGE_LEN: usize = 2 + NONCE_LEN + 2 * PUBLIC_LEN + TAG_LEN;
/// Frames held back while the session is being set up. The oldest are dropped
/// beyond this.
const MAX_PENDING: usize = 32;
/// While frames wait for a session, the hello is sent again after this many
/// receive calls with nothing arriving.
const HELLO_RETRY_POLLS: u32 = 8;

/// A shared secret. `Debug` output hides the bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    /// Wraps 32 bytes of key material. Generate them from a secure random source.
    pub fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(..)")
    }
}

/// Why a key operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// No key with this id is installed.
    Unknown(u8),
    /// The key is the active one, which cannot be retired. Activate another key
    /// first.
    Active(u8),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(id) => write!(f, "no key with id {id} is installed"),
            Self::Active(id) => write!(f, "key {id} is active and cannot be retired"),
        }
    }
}

impl std::error::Error for KeyError {}

/// The session this side receives under: the nonce it issued, the key derived
/// for it, and what has arrived under it.
#[derive(Debug)]
struct Issued {
    nonce: [u8; NONCE_LEN],
    /// Our ephemeral secret for this session. Kept as bytes, so the session can
    /// be answered again.
    secret: [u8; KEY_LEN],
    key: Key,
    /// The pre-shared key id the session was set up with.
    psk_id: u8,
    window: SeqWindow,
    /// True once a frame has been accepted under this session. Until then, a
    /// repeated hello gets the same challenge back, so duplicate hellos from a
    /// sender that is still setting up do not replace the session.
    in_use: bool,
}

/// The session this side sends under.
#[derive(Debug)]
struct PeerSession {
    nonce: [u8; NONCE_LEN],
    key: Key,
    psk_id: u8,
}

/// Wraps a transport and authenticates and encrypts every frame.
///
/// ```
/// use tpt_link::Loopback;
/// use tpt_link::auth::{Authenticated, KEY_LEN, Key};
/// use tpt_link::Link;
///
/// let psk = Key::new([7; KEY_LEN]);
/// let (a, b) = Loopback::pair();
/// let mut tx = Link::new(Authenticated::new(a, psk.clone()));
/// let mut rx = Link::new(Authenticated::new(b, psk));
/// tx.send(b"open valve").unwrap();
/// rx.poll().unwrap(); // the hello is answered here
/// tx.poll().unwrap(); // the challenge arrives and the queued frame goes out
/// assert_eq!(rx.poll().unwrap(), vec![b"open valve".to_vec()]);
/// ```
#[derive(Debug)]
pub struct Authenticated<T> {
    inner: T,
    /// Pre-shared keys this side accepts, by id. The active key is always among
    /// them.
    keys: Vec<(u8, Key)>,
    /// Id of the pre-shared key that new sessions are set up with.
    active: u8,
    /// Our ephemeral secret for the hello in progress, if any.
    ephemeral: Option<[u8; KEY_LEN]>,
    /// The session we send under, once the receiver has challenged us.
    peer_session: Option<PeerSession>,
    /// The session we receive under, once we have challenged the peer.
    issued: Option<Issued>,
    pending: VecDeque<Vec<u8>>,
    polls_since_hello: u32,
    /// True once a resync has been sent for the current lack of a session, so
    /// a stream of unverifiable frames gets one resync, not one per frame.
    resync_sent: bool,
    rejected: u64,
    replayed: u64,
    dropped_pending: u64,
}

impl<T> Authenticated<T> {
    /// Wraps `inner`, with `psk` as pre-shared key 0 and active. Both ends must
    /// hold the same key.
    pub fn new(inner: T, psk: Key) -> Self {
        Self {
            inner,
            keys: vec![(0, psk)],
            active: 0,
            ephemeral: None,
            peer_session: None,
            issued: None,
            pending: VecDeque::new(),
            polls_since_hello: 0,
            resync_sent: false,
            rejected: 0,
            replayed: 0,
            dropped_pending: 0,
        }
    }

    /// Accepts handshakes made under the pre-shared key `key`, identified by
    /// `id`. Installing an id that is already in use replaces its key. If the
    /// number of keys exceeds the limit, the oldest one that is not active is
    /// dropped.
    ///
    /// To rotate: install the new key on both ends, activate it on both ends,
    /// then retire the old key on both ends. Replacing the active key takes
    /// effect at once, so the peer must already hold the replacement.
    pub fn install_key(&mut self, id: u8, key: Key) {
        if let Some(slot) = self.keys.iter_mut().find(|(k, _)| *k == id) {
            slot.1 = key;
            return;
        }
        self.keys.push((id, key));
        if self.keys.len() > MAX_KEYS {
            let active = self.active;
            if let Some(oldest) = self.keys.iter().position(|(k, _)| *k != active) {
                self.keys.remove(oldest);
            }
        }
    }

    /// Makes the key with this id the one new sessions are set up with. The
    /// current session is replaced by one under the new key on the next send.
    /// Fails if no such key is installed.
    pub fn activate_key(&mut self, id: u8) -> Result<(), KeyError> {
        if self.key_ref(id).is_none() {
            return Err(KeyError::Unknown(id));
        }
        if id != self.active {
            self.active = id;
            self.start_session();
        }
        Ok(())
    }

    /// Stops accepting handshakes under the key with this id, and ends any
    /// session that was set up with it. The active key cannot be retired.
    pub fn retire_key(&mut self, id: u8) -> Result<(), KeyError> {
        if id == self.active {
            return Err(KeyError::Active(id));
        }
        let before = self.keys.len();
        self.keys.retain(|(k, _)| *k != id);
        if self.keys.len() == before {
            return Err(KeyError::Unknown(id));
        }
        if self.issued.as_ref().is_some_and(|i| i.psk_id == id) {
            self.issued = None;
        }
        if self.peer_session.as_ref().is_some_and(|s| s.psk_id == id) {
            self.peer_session = None;
        }
        Ok(())
    }

    /// The id of the pre-shared key that new sessions are set up with.
    pub fn active_key_id(&self) -> u8 {
        self.active
    }

    /// Messages dropped because they did not verify, were too short, or named a
    /// key that is not installed.
    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// Data frames that verified but were refused as repeats or as too old to
    /// check. These are replays, or duplicates from a lossy link.
    pub fn replayed(&self) -> u64 {
        self.replayed
    }

    /// Frames dropped from the queue because the session took too long to set up.
    pub fn dropped_pending(&self) -> u64 {
        self.dropped_pending
    }

    /// Mutable access to the underlying transport.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Gives back the underlying transport.
    pub fn into_inner(self) -> T {
        self.inner
    }

    fn key_ref(&self, id: u8) -> Option<&Key> {
        self.keys.iter().find(|(k, _)| *k == id).map(|(_, key)| key)
    }

    /// The active pre-shared key and its id. The active key is always installed,
    /// because `new` installs it, `install_key` never drops it, and `retire_key`
    /// refuses it.
    fn active_key(&self) -> (u8, &Key) {
        let key = self
            .key_ref(self.active)
            .expect("the active key is always installed");
        (self.active, key)
    }

    /// Forgets the session in progress, so the next hello uses a fresh
    /// ephemeral key.
    fn start_session(&mut self) {
        self.peer_session = None;
        self.ephemeral = None;
        self.polls_since_hello = 0;
    }
}

/// Tag over `parts`, keyed with `key`. The key is always a valid HMAC key
/// length, so this cannot fail.
fn tag_over(key: &Key, parts: &[&[u8]]) -> [u8; TAG_LEN] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key.0).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&full[..TAG_LEN]);
    out
}

/// True if `tag` is the tag of `parts` under `key`. Compared in constant time.
fn verify_over(key: &Key, parts: &[&[u8]], tag: &[u8]) -> bool {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key.0).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    mac.verify_truncated_left(tag).is_ok()
}

/// Fresh random bytes from the operating system. If that source is unavailable,
/// no session can be made safe, so this panics rather than return a weak value.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).expect("the operating system random source is available");
    bytes
}

/// The public key for an ephemeral secret.
fn public_of(secret: &[u8; KEY_LEN]) -> [u8; PUBLIC_LEN] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// The X25519 shared secret of `secret` and `their`. `None` if the result is all
/// zeros, which happens only when `their` is a low-order point, so the secret
/// would be known to anyone.
fn shared_secret(secret: &[u8; KEY_LEN], their: &[u8; PUBLIC_LEN]) -> Option<[u8; KEY_LEN]> {
    let shared = StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(*their));
    let bytes = *shared.as_bytes();
    if bytes == [0u8; KEY_LEN] {
        None
    } else {
        Some(bytes)
    }
}

/// The session key for one direction. It depends on the pre-shared key, the
/// shared secret, the nonce, and both public keys, so each session gets its own
/// key and both ends derive the same one.
fn session_key(
    psk: &Key,
    shared: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    hello_pub: &[u8; PUBLIC_LEN],
    challenge_pub: &[u8; PUBLIC_LEN],
) -> Key {
    let hk = Hkdf::<Sha256>::new(Some(&psk.0), shared);
    let mut info = Vec::with_capacity(19 + NONCE_LEN + 2 * PUBLIC_LEN);
    info.extend_from_slice(b"tpt-link session v1");
    info.extend_from_slice(nonce);
    info.extend_from_slice(hello_pub);
    info.extend_from_slice(challenge_pub);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(&info, &mut okm)
        .expect("32 bytes is a valid HKDF output length");
    Key(okm)
}

/// A fresh random nonce for one data message. Random 96-bit nonces are safe for
/// ChaCha20-Poly1305 at the message volumes a link carries.
fn fresh_message_nonce() -> [u8; MESSAGE_NONCE_LEN] {
    random_bytes()
}

/// A data message: its type byte, its key id, a fresh nonce, then the frame
/// sealed with ChaCha20-Poly1305 under the session key. The session nonce is
/// bound in as associated data, so a message sealed in one session does not open
/// in another.
fn data_wire(key: &Key, id: u8, session: &[u8; NONCE_LEN], frame: &[u8]) -> Vec<u8> {
    let nonce = fresh_message_nonce();
    let cipher = ChaCha20Poly1305::new_from_slice(&key.0).expect("the key is 32 bytes");
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: frame,
                aad: session,
            },
        )
        .expect("sealing a frame cannot fail");
    let mut wire = Vec::with_capacity(2 + MESSAGE_NONCE_LEN + sealed.len());
    wire.push(TYPE_DATA);
    wire.push(id);
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&sealed);
    wire
}

/// Opens a sealed message. Returns `None` unless it was sealed under this key
/// and session.
fn open_data(key: &Key, session: &[u8; NONCE_LEN], nonce: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(&key.0).expect("the key is 32 bytes");
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: sealed,
                aad: session,
            },
        )
        .ok()
}

impl<T: Transport> Authenticated<T> {
    /// Starts a new session with the peer. Call this after either side restarts
    /// or reconnects. Frames sent before the peer answers are held in the queue.
    pub fn renew(&mut self) -> Result<(), T::Error> {
        self.start_session();
        self.send_hello()
    }

    /// Sends a hello with this side's ephemeral public key. The same ephemeral
    /// key is reused for retries, so a repeated hello gets the same answer.
    fn send_hello(&mut self) -> Result<(), T::Error> {
        let secret = *self.ephemeral.get_or_insert_with(random_bytes);
        let ours = public_of(&secret);
        let (id, psk) = self.active_key();
        let mut wire = vec![TYPE_HELLO, id];
        wire.extend_from_slice(&ours);
        wire.extend_from_slice(&tag_over(psk, &[&[TYPE_HELLO], &[id], &ours]));
        self.inner.send(&wire)
    }

    /// Tells the sender that there is no session, so it should send a hello.
    fn send_resync(&mut self) -> Result<(), T::Error> {
        let (id, psk) = self.active_key();
        let mut wire = vec![TYPE_RESYNC, id];
        wire.extend_from_slice(&tag_over(psk, &[&[TYPE_RESYNC], &[id]]));
        self.inner.send(&wire)
    }

    /// The peer has no session with us. Forget our session, and start a new
    /// one. Frames that were already queued go out once the peer answers.
    fn take_resync(&mut self, wire: &[u8]) -> Result<(), T::Error> {
        if wire.len() != 2 + TAG_LEN {
            self.rejected += 1;
            return Ok(());
        }
        let id = wire[1];
        let valid = self
            .key_ref(id)
            .is_some_and(|psk| verify_over(psk, &[&[TYPE_RESYNC], &[id]], &wire[2..]));
        if !valid {
            self.rejected += 1;
            return Ok(());
        }
        self.start_session();
        self.send_hello()
    }

    /// Sends the queued frames, now that the peer's session is known.
    fn flush(&mut self) -> Result<(), T::Error> {
        let Some(session) = self.peer_session.as_ref() else {
            return Ok(());
        };
        while let Some(frame) = self.pending.pop_front() {
            let wire = data_wire(&session.key, session.psk_id, &session.nonce, &frame);
            self.inner.send(&wire)?;
        }
        Ok(())
    }

    /// Answers a hello with a challenge. The receiver's ephemeral key is reused
    /// for a hello that repeats one not yet in use, and the session key is
    /// derived from the sender's public key in this hello.
    fn answer_hello(&mut self, wire: &[u8]) -> Result<(), T::Error> {
        if wire.len() != HELLO_LEN {
            self.rejected += 1;
            return Ok(());
        }
        let id = wire[1];
        let mut theirs = [0u8; PUBLIC_LEN];
        theirs.copy_from_slice(&wire[2..2 + PUBLIC_LEN]);
        let Some(psk) = self.key_ref(id).cloned() else {
            self.rejected += 1;
            return Ok(());
        };
        if !verify_over(
            &psk,
            &[&[TYPE_HELLO], &[id], &theirs],
            &wire[2 + PUBLIC_LEN..],
        ) {
            self.rejected += 1;
            return Ok(());
        }

        let (nonce, secret, window) = match &self.issued {
            Some(issued) if !issued.in_use => (issued.nonce, issued.secret, issued.window),
            _ => (random_bytes(), random_bytes(), SeqWindow::default()),
        };
        let Some(shared) = shared_secret(&secret, &theirs) else {
            self.rejected += 1;
            return Ok(());
        };
        let ours = public_of(&secret);
        let key = session_key(&psk, &shared, &nonce, &theirs, &ours);
        self.issued = Some(Issued {
            nonce,
            secret,
            key,
            psk_id: id,
            window,
            in_use: false,
        });
        self.resync_sent = false;

        let mut out = vec![TYPE_CHALLENGE, id];
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ours);
        out.extend_from_slice(&theirs);
        out.extend_from_slice(&tag_over(
            &psk,
            &[&[TYPE_CHALLENGE], &[id], &nonce, &ours, &theirs],
        ));
        self.inner.send(&out)
    }

    /// Takes a challenge that answers our current hello, derives the session
    /// key, and sends the queued frames. A challenge that answers an earlier
    /// hello is refused, because it does not echo our current public key.
    fn take_challenge(&mut self, wire: &[u8]) -> Result<(), T::Error> {
        if wire.len() != CHALLENGE_LEN {
            self.rejected += 1;
            return Ok(());
        }
        let id = wire[1];
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&wire[2..2 + NONCE_LEN]);
        let mut theirs = [0u8; PUBLIC_LEN];
        theirs.copy_from_slice(&wire[2 + NONCE_LEN..2 + NONCE_LEN + PUBLIC_LEN]);
        let mut echo = [0u8; PUBLIC_LEN];
        echo.copy_from_slice(&wire[2 + NONCE_LEN + PUBLIC_LEN..2 + NONCE_LEN + 2 * PUBLIC_LEN]);
        let tag = &wire[2 + NONCE_LEN + 2 * PUBLIC_LEN..];

        let Some(psk) = self.key_ref(id).cloned() else {
            self.rejected += 1;
            return Ok(());
        };
        let authentic = verify_over(
            &psk,
            &[&[TYPE_CHALLENGE], &[id], &nonce, &theirs, &echo],
            tag,
        );
        let Some(secret) = self.ephemeral else {
            // No hello is outstanding, so this challenge answers nothing.
            self.rejected += 1;
            return Ok(());
        };
        if !authentic || public_of(&secret) != echo {
            self.rejected += 1;
            return Ok(());
        }
        let Some(shared) = shared_secret(&secret, &theirs) else {
            self.rejected += 1;
            return Ok(());
        };
        let key = session_key(&psk, &shared, &nonce, &echo, &theirs);
        self.peer_session = Some(PeerSession {
            nonce,
            key,
            psk_id: id,
        });
        self.polls_since_hello = 0;
        self.flush()
    }

    /// Opens a data message and checks it. Returns the frame if it is new and
    /// authentic.
    fn take_data(&mut self, wire: &[u8]) -> Result<Option<Vec<u8>>, T::Error> {
        let (session, key, psk_id) = match &self.issued {
            Some(issued) => (issued.nonce, issued.key.clone(), issued.psk_id),
            None => {
                // No session with this peer. A restart on our side is the usual
                // reason, so tell the sender to start again.
                self.rejected += 1;
                if !self.resync_sent {
                    self.resync_sent = true;
                    self.send_resync()?;
                }
                return Ok(None);
            }
        };
        if wire.len() < 2 + MESSAGE_NONCE_LEN + TAG_LEN + HEADER_LEN || wire[1] != psk_id {
            self.rejected += 1;
            return Ok(None);
        }
        let (nonce, sealed) = wire[2..].split_at(MESSAGE_NONCE_LEN);
        let Some(frame) = open_data(&key, &session, nonce, sealed) else {
            self.rejected += 1;
            return Ok(None);
        };
        if frame.first() != Some(&VERSION) {
            self.rejected += 1;
            return Ok(None);
        }
        let seq = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]);
        let Some(issued) = self.issued.as_mut() else {
            return Ok(None);
        };
        match issued.window.arrive_strict(seq) {
            Arrival::New { .. } => {
                issued.in_use = true;
                Ok(Some(frame))
            }
            Arrival::Repeat | Arrival::Stale => {
                self.replayed += 1;
                Ok(None)
            }
        }
    }
}

impl<T: Transport> Transport for Authenticated<T> {
    type Error = T::Error;

    fn send(&mut self, frame: &[u8]) -> Result<(), T::Error> {
        match &self.peer_session {
            Some(session) => {
                let wire = data_wire(&session.key, session.psk_id, &session.nonce, frame);
                self.inner.send(&wire)
            }
            None => {
                if self.pending.len() == MAX_PENDING {
                    self.pending.pop_front();
                    self.dropped_pending += 1;
                }
                self.pending.push_back(frame.to_vec());
                self.send_hello()
            }
        }
    }

    fn try_recv(&mut self) -> Result<Option<Vec<u8>>, T::Error> {
        loop {
            let Some(wire) = self.inner.try_recv()? else {
                // Nothing arrived. If frames are still waiting for a session,
                // the hello may have been lost, so send it again now and then.
                if self.peer_session.is_none() && !self.pending.is_empty() {
                    self.polls_since_hello += 1;
                    if self.polls_since_hello >= HELLO_RETRY_POLLS {
                        self.polls_since_hello = 0;
                        self.send_hello()?;
                    }
                }
                return Ok(None);
            };
            match wire.first() {
                Some(&TYPE_HELLO) => self.answer_hello(&wire)?,
                Some(&TYPE_CHALLENGE) => self.take_challenge(&wire)?,
                Some(&TYPE_RESYNC) => self.take_resync(&wire)?,
                Some(&TYPE_DATA) => {
                    if let Some(frame) = self.take_data(&wire)? {
                        return Ok(Some(frame));
                    }
                }
                _ => self.rejected += 1,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::encode;
    use crate::link::Link;
    use crate::transport::Loopback;

    fn key(byte: u8) -> Key {
        Key::new([byte; KEY_LEN])
    }

    /// A loopback end that keeps a copy of everything it sends, and can inject
    /// bytes as if they came from the peer.
    struct Recorder {
        inner: Loopback,
        log: Vec<Vec<u8>>,
    }

    impl Transport for Recorder {
        type Error = crate::transport::Closed;

        fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
            self.log.push(frame.to_vec());
            self.inner.send(frame)
        }

        fn try_recv(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            self.inner.try_recv()
        }
    }

    fn recorder(end: Loopback) -> Recorder {
        Recorder {
            inner: end,
            log: Vec::new(),
        }
    }

    /// A link frame with the given sequence number.
    fn frame(seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        encode(seq, payload, &mut wire).unwrap();
        wire
    }

    /// Sends one frame and lets both sides process what is in flight.
    fn deliver(
        tx: &mut Authenticated<Recorder>,
        rx: &mut Authenticated<Loopback>,
        frame_bytes: &[u8],
    ) -> Vec<Vec<u8>> {
        tx.send(frame_bytes).unwrap();
        let mut got = Vec::new();
        for _ in 0..4 {
            while let Some(f) = rx.try_recv().unwrap() {
                got.push(f);
            }
            while tx.try_recv().unwrap().is_some() {}
        }
        got
    }

    fn data_wires(log: &[Vec<u8>]) -> Vec<Vec<u8>> {
        log.iter()
            .filter(|w| w.first() == Some(&TYPE_DATA))
            .cloned()
            .collect()
    }

    #[test]
    fn frames_flow_once_the_session_is_up() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(b, key(1));
        let f0 = frame(0, b"open valve");
        assert_eq!(deliver(&mut tx, &mut rx, &f0), vec![f0.clone()]);
        assert_eq!(rx.rejected(), 0);
        assert_eq!(rx.replayed(), 0);
    }

    #[test]
    fn a_repeat_within_the_session_is_refused() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(b, key(1));
        deliver(&mut tx, &mut rx, &frame(0, b"open valve"));

        let recorded = data_wires(&tx.inner_mut().log)[0].clone();
        tx.inner_mut().inner.send(&recorded).unwrap();
        assert_eq!(rx.try_recv().unwrap(), None);
        assert_eq!(rx.replayed(), 1);
    }

    #[test]
    fn a_frame_from_an_earlier_session_is_refused() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(b, key(1));
        deliver(&mut tx, &mut rx, &frame(0, b"open valve"));
        let old = data_wires(&tx.inner_mut().log)[0].clone();

        // A new session: new ephemeral keys and a fresh nonce.
        tx.renew().unwrap();
        rx.try_recv().unwrap();
        tx.try_recv().unwrap();

        tx.inner_mut().inner.send(&old).unwrap();
        assert_eq!(rx.try_recv().unwrap(), None);
        assert_eq!(rx.rejected(), 1);
    }

    #[test]
    fn a_frame_far_back_in_the_session_is_refused() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(b, key(1));
        for seq in 0..70 {
            deliver(&mut tx, &mut rx, &frame(seq, b"x"));
        }
        let first = data_wires(&tx.inner_mut().log)[0].clone();
        tx.inner_mut().inner.send(&first).unwrap();
        assert_eq!(rx.try_recv().unwrap(), None);
        assert_eq!(rx.replayed(), 1);
    }

    #[test]
    fn a_forged_hello_gets_no_challenge() {
        let (x, y) = Loopback::pair();
        let mut attacker = Authenticated::new(recorder(x), key(2));
        attacker.renew().unwrap();
        let mut rx = Authenticated::new(y, key(1));
        assert_eq!(rx.try_recv().unwrap(), None);
        assert_eq!(rx.rejected(), 1);
        assert!(rx.issued.is_none());
    }

    #[test]
    fn a_hello_naming_an_unknown_key_is_refused() {
        let (mut raw, b) = Loopback::pair();
        let mut hello = vec![TYPE_HELLO, 9];
        hello.extend([0u8; PUBLIC_LEN + TAG_LEN]);
        raw.send(&hello).unwrap();
        let mut rx = Authenticated::new(b, key(1));
        assert_eq!(rx.try_recv().unwrap(), None);
        assert_eq!(rx.rejected(), 1);
        assert!(rx.issued.is_none());
    }

    #[test]
    fn a_tampered_frame_is_dropped() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(b, key(1));
        deliver(&mut tx, &mut rx, &frame(0, b"open valve"));

        let mut tampered = data_wires(&tx.inner_mut().log)[0].clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        tx.inner_mut().inner.send(&tampered).unwrap();
        assert_eq!(rx.try_recv().unwrap(), None);
        assert_eq!(rx.rejected(), 1);
    }

    #[test]
    fn a_tampered_challenge_is_refused() {
        // An attacker who changes the receiver's public key in the challenge
        // would learn nothing useful, but the sender must still refuse it.
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(recorder(b), key(1));
        tx.send(&frame(0, b"x")).unwrap();
        rx.try_recv().unwrap();
        let mut challenge = rx
            .inner_mut()
            .log
            .iter()
            .find(|w| w.first() == Some(&TYPE_CHALLENGE))
            .unwrap()
            .clone();
        challenge[2 + NONCE_LEN] ^= 0x01;
        // Discard the genuine challenge, which is still waiting for the sender.
        tx.inner_mut().inner.try_recv().unwrap();
        rx.inner_mut().inner.send(&challenge).unwrap();
        assert_eq!(tx.try_recv().unwrap(), None);
        assert_eq!(tx.rejected(), 1);
        assert!(tx.peer_session.is_none());
    }

    #[test]
    fn a_challenge_for_an_earlier_hello_is_refused() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(recorder(b), key(1));
        tx.send(&frame(0, b"x")).unwrap();
        rx.try_recv().unwrap();
        let old = rx
            .inner_mut()
            .log
            .iter()
            .find(|w| w.first() == Some(&TYPE_CHALLENGE))
            .unwrap()
            .clone();

        // Discard the genuine challenge, which is still waiting for the sender.
        tx.inner_mut().inner.try_recv().unwrap();
        // The sender starts again, so its ephemeral key has changed.
        tx.renew().unwrap();
        rx.inner_mut().inner.send(&old).unwrap();
        assert_eq!(tx.try_recv().unwrap(), None);
        assert_eq!(tx.rejected(), 1);
        assert!(tx.peer_session.is_none());
    }

    #[test]
    fn data_before_any_session_is_refused() {
        let (mut raw, b) = Loopback::pair();
        raw.send(&frame(0, b"unsigned")).unwrap();
        let mut rx = Authenticated::new(b, key(1));
        assert_eq!(rx.try_recv().unwrap(), None);
        assert_eq!(rx.rejected(), 1);
    }

    #[test]
    fn a_datagram_shorter_than_a_tag_is_dropped() {
        let (mut raw, b) = Loopback::pair();
        raw.send(&[1, 2, 3]).unwrap();
        let mut rx = Authenticated::new(b, key(1));
        assert_eq!(rx.try_recv().unwrap(), None);
        assert_eq!(rx.rejected(), 1);
    }

    #[test]
    fn frames_under_the_wrong_key_never_reach_the_link() {
        let (a, b) = Loopback::pair();
        let mut tx = Link::new(Authenticated::new(a, key(1)));
        let mut rx = Link::new(Authenticated::new(b, key(2)));
        tx.send(b"hello").unwrap();
        for _ in 0..3 {
            assert!(rx.poll().unwrap().is_empty());
            tx.poll().unwrap();
        }
        assert_eq!(rx.stats().received, 0);
    }

    #[test]
    fn queue_keeps_the_newest_frames_when_the_session_is_slow() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(b, key(1));
        for seq in 0..40 {
            tx.send(&frame(seq, b"q")).unwrap();
        }
        assert_eq!(tx.dropped_pending(), 8);

        let mut got = Vec::new();
        for _ in 0..4 {
            while let Some(f) = rx.try_recv().unwrap() {
                got.push(f);
            }
            while tx.try_recv().unwrap().is_some() {}
        }
        assert_eq!(got.len(), MAX_PENDING);
        assert_eq!(got[0], frame(8, b"q"));
    }

    #[test]
    fn the_payload_is_not_readable_on_the_wire() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(b, key(1));
        let secret = b"open valve 100%";
        deliver(&mut tx, &mut rx, &frame(0, secret));

        let wires = data_wires(&tx.inner_mut().log);
        assert_eq!(wires.len(), 1);
        assert!(!wires[0].windows(secret.len()).any(|w| w == secret));
    }

    #[test]
    fn sealing_the_same_frame_twice_gives_different_bytes() {
        let session = [9; NONCE_LEN];
        let f = frame(0, b"same");
        assert_ne!(
            data_wire(&key(1), 0, &session, &f),
            data_wire(&key(1), 0, &session, &f)
        );
    }

    #[test]
    fn session_keys_are_fresh_and_are_not_the_pre_shared_key() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(b, key(1));
        deliver(&mut tx, &mut rx, &frame(0, b"one"));
        let first = tx.peer_session.as_ref().unwrap().key.clone();
        assert_ne!(first, key(1));

        tx.renew().unwrap();
        rx.try_recv().unwrap();
        tx.try_recv().unwrap();
        let second = tx.peer_session.as_ref().unwrap().key.clone();
        assert_ne!(first, second);
    }

    #[test]
    fn a_restarted_receiver_recovers_without_renew() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(b, key(1));
        let f0 = frame(0, b"before the restart");
        assert_eq!(deliver(&mut tx, &mut rx, &f0), vec![f0.clone()]);

        // The receiver restarts: its session state is lost, but the transport
        // survives.
        let mut rx = Authenticated::new(rx.into_inner(), key(1));

        // This frame is sent under the old session and is refused. The refusal
        // makes the receiver send a resync.
        tx.send(&frame(1, b"lost")).unwrap();
        assert_eq!(rx.try_recv().unwrap(), None);
        tx.try_recv().unwrap(); // takes the resync and says hello
        assert_eq!(rx.try_recv().unwrap(), None); // answers the hello
        tx.try_recv().unwrap(); // takes the challenge

        let f2 = frame(2, b"after the restart");
        assert_eq!(deliver(&mut tx, &mut rx, &f2), vec![f2.clone()]);
    }

    #[test]
    fn a_resync_is_sent_once_for_a_stream_of_refused_frames() {
        let (a, b) = Loopback::pair();
        let mut tx = recorder(a);
        let mut rx = Authenticated::new(recorder(b), key(1));
        for seq in 0..3 {
            tx.inner
                .send(&data_wire(&key(1), 0, &[0; NONCE_LEN], &frame(seq, b"x")))
                .unwrap();
        }
        assert_eq!(rx.try_recv().unwrap(), None);
        assert_eq!(rx.rejected(), 3);

        let resyncs = rx
            .inner_mut()
            .log
            .iter()
            .filter(|w| w.first() == Some(&TYPE_RESYNC))
            .count();
        assert_eq!(resyncs, 1);
    }

    #[test]
    fn rotation_starts_a_new_session_under_the_new_key() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(b, key(1));
        let f0 = frame(0, b"before");
        assert_eq!(deliver(&mut tx, &mut rx, &f0), vec![f0.clone()]);

        rx.install_key(1, key(2));
        tx.install_key(1, key(2));
        tx.activate_key(1).unwrap();
        rx.activate_key(1).unwrap();
        let f1 = frame(1, b"after");
        assert_eq!(deliver(&mut tx, &mut rx, &f1), vec![f1.clone()]);
        assert_eq!(rx.rejected(), 0);
        assert_eq!(tx.peer_session.as_ref().unwrap().psk_id, 1);
    }

    #[test]
    fn a_frame_under_a_retired_key_is_refused() {
        let (a, b) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        let mut rx = Authenticated::new(b, key(1));
        deliver(&mut tx, &mut rx, &frame(0, b"before"));
        let old = data_wires(&tx.inner_mut().log)[0].clone();

        rx.install_key(1, key(2));
        tx.install_key(1, key(2));
        tx.activate_key(1).unwrap();
        rx.activate_key(1).unwrap();
        deliver(&mut tx, &mut rx, &frame(1, b"after"));
        rx.retire_key(0).unwrap();

        tx.inner_mut().inner.send(&old).unwrap();
        assert_eq!(rx.try_recv().unwrap(), None);
        assert_eq!(rx.rejected(), 1);
    }

    #[test]
    fn key_management_refuses_unknown_and_active_keys() {
        let (a, _) = Loopback::pair();
        let mut tx = Authenticated::new(recorder(a), key(1));
        assert_eq!(tx.activate_key(7), Err(KeyError::Unknown(7)));
        assert_eq!(tx.retire_key(0), Err(KeyError::Active(0)));
        assert_eq!(tx.retire_key(5), Err(KeyError::Unknown(5)));

        tx.install_key(1, key(2));
        tx.activate_key(1).unwrap();
        assert_eq!(tx.active_key_id(), 1);
        tx.retire_key(0).unwrap();
    }

    #[test]
    fn the_oldest_inactive_key_is_dropped_past_the_limit() {
        let (_, b) = Loopback::pair();
        let mut rx = Authenticated::new(b, key(1));
        for id in 1..=4 {
            rx.install_key(id, key(id + 1));
        }
        // Five keys were installed, so the oldest inactive one, id 1, is gone.
        assert_eq!(rx.retire_key(1), Err(KeyError::Unknown(1)));
        assert!(rx.retire_key(2).is_ok());
    }
}
