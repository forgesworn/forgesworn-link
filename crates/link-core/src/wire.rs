//! Everything on the wire that is not the card: relay frames, relay auth,
//! the reflector and the signed probes.  Spec sections 3 and 4.2.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::card::to_ipv6;
use crate::id::{NodeId, TransportKey};
use crate::rendezvous::{TAG_BYTES, Tag};

pub const RELAY_AUTH_DOMAIN: &[u8] = b"forgesworn-link/relay-auth/v1\0";

/// Largest QUIC datagram a relay frame may carry, spec 3.1.
pub const MAX_DATAGRAM: usize = 1350;
/// At most this many frames may be queued outbound per relay session, spec 3.1.
pub const MAX_QUEUED_FRAMES: usize = 64;
/// A relay session with no ping for this long is closed, spec 3.1.
pub const IDLE_CLOSE_SECONDS: u64 = 90;
/// Close reason for an oversize or malformed frame, spec 3.1.
pub const CLOSE_REASON_MALFORMED: u16 = 1;
/// Close reason when a newer session registered the same node ID (identity
/// mode) or a third session registered a tag (tag mode) and this one, the
/// oldest, was evicted, spec 3.1.  A client backs off before reconnecting.
pub const CLOSE_REASON_SUPERSEDED: u16 = 2;

// ---------------------------------------------------------------------------
// Relay auth, spec 3.1
// ---------------------------------------------------------------------------

/// `domain || u16 len || relay_host || challenge`.  The host is length-prefixed
/// so the input cannot be re-split against another relay.
pub fn relay_auth_signing_input(relay_host: &str, challenge: &[u8; 32]) -> Vec<u8> {
    let host = relay_host.as_bytes();
    let mut out = Vec::with_capacity(RELAY_AUTH_DOMAIN.len() + 2 + host.len() + 32);
    out.extend_from_slice(RELAY_AUTH_DOMAIN);
    out.extend_from_slice(&(host.len() as u16).to_be_bytes());
    out.extend_from_slice(host);
    out.extend_from_slice(challenge);
    out
}

pub fn sign_relay_auth(key: &TransportKey, relay_host: &str, challenge: &[u8; 32]) -> [u8; 64] {
    key.sign(&relay_auth_signing_input(relay_host, challenge))
}

pub fn verify_relay_auth(
    node_id: &NodeId,
    relay_host: &str,
    challenge: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    node_id.verify(&relay_auth_signing_input(relay_host, challenge), signature)
}

// ---------------------------------------------------------------------------
// Relay frames, spec 3.1
// ---------------------------------------------------------------------------

pub const FRAME_CHALLENGE: u8 = 0x01;
pub const FRAME_AUTH: u8 = 0x02;
pub const FRAME_WELCOME: u8 = 0x03;
pub const FRAME_SEND: u8 = 0x10;
pub const FRAME_RECV: u8 = 0x11;
pub const FRAME_PING: u8 = 0x20;
pub const FRAME_PONG: u8 = 0x21;
pub const FRAME_CLOSE: u8 = 0x7f;

// Rendezvous-tag routing, spec section 9 / docs/RENDEZVOUS.md.  These frames
// replace identity authentication and node-ID routing once the relay wire
// change lands behind its version bump; until then the deployed relay speaks
// the identity frames above.
pub const FRAME_REGISTER: u8 = 0x04;
pub const FRAME_SEND_TAG: u8 = 0x12;
pub const FRAME_RECV_TAG: u8 = 0x13;
/// A `Register` carries at most this many tags (a pair needs at most twelve
/// during a card transition; this bounds a whole roster).
pub const MAX_TAGS_PER_REGISTER: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Challenge([u8; 32]),
    Auth {
        node_id: NodeId,
        signature: [u8; 64],
    },
    Welcome([u8; 16]),
    Send {
        destination: NodeId,
        datagram: Vec<u8>,
    },
    Recv {
        source: NodeId,
        datagram: Vec<u8>,
    },
    /// Register the session under pair-scoped rendezvous tags, spec section 9.
    /// No identity and no signature: a tag is an unguessable capability.
    Register {
        tags: Vec<Tag>,
    },
    /// Route a datagram to whoever else registered this tag, spec section 9.
    SendTag {
        tag: Tag,
        datagram: Vec<u8>,
    },
    /// A datagram delivered by tag, spec section 9.  The source is the tag;
    /// the relay knows nothing else.
    RecvTag {
        tag: Tag,
        datagram: Vec<u8>,
    },
    Ping([u8; 8]),
    Pong([u8; 8]),
    Close(u16),
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Frame::Challenge(bytes) => one(FRAME_CHALLENGE, bytes),
            Frame::Auth { node_id, signature } => {
                let mut out = Vec::with_capacity(1 + 32 + 64);
                out.push(FRAME_AUTH);
                out.extend_from_slice(node_id.as_bytes());
                out.extend_from_slice(signature);
                out
            }
            Frame::Welcome(token) => one(FRAME_WELCOME, token),
            Frame::Send {
                destination,
                datagram,
            } => routed(FRAME_SEND, destination, datagram),
            Frame::Recv { source, datagram } => routed(FRAME_RECV, source, datagram),
            Frame::Register { tags } => {
                let mut out = Vec::with_capacity(1 + 2 + tags.len() * TAG_BYTES);
                out.push(FRAME_REGISTER);
                out.extend_from_slice(&(tags.len() as u16).to_be_bytes());
                for tag in tags {
                    out.extend_from_slice(&tag.0);
                }
                out
            }
            Frame::SendTag { tag, datagram } => routed_tag(FRAME_SEND_TAG, tag, datagram),
            Frame::RecvTag { tag, datagram } => routed_tag(FRAME_RECV_TAG, tag, datagram),
            Frame::Ping(opaque) => one(FRAME_PING, opaque),
            Frame::Pong(opaque) => one(FRAME_PONG, opaque),
            Frame::Close(reason) => one(FRAME_CLOSE, &reason.to_be_bytes()),
        }
    }

    /// Decode a frame.  `None` means malformed, which closes the session with
    /// reason 1.  Datagram bounds of 1..=1350 are enforced here.
    pub fn decode(bytes: &[u8]) -> Option<Frame> {
        let (&tag, body) = bytes.split_first()?;
        match tag {
            FRAME_CHALLENGE => Some(Frame::Challenge(fixed(body)?)),
            FRAME_AUTH => {
                if body.len() != 96 {
                    return None;
                }
                let node_id = NodeId::from_slice(&body[..32])?;
                let signature: [u8; 64] = body[32..].try_into().ok()?;
                Some(Frame::Auth { node_id, signature })
            }
            FRAME_WELCOME => Some(Frame::Welcome(fixed(body)?)),
            FRAME_SEND => {
                let (node_id, datagram) = split_routed(body)?;
                Some(Frame::Send {
                    destination: node_id,
                    datagram,
                })
            }
            FRAME_RECV => {
                let (node_id, datagram) = split_routed(body)?;
                Some(Frame::Recv {
                    source: node_id,
                    datagram,
                })
            }
            FRAME_REGISTER => {
                if body.len() < 2 {
                    return None;
                }
                let count = u16::from_be_bytes([body[0], body[1]]) as usize;
                let rest = &body[2..];
                if count > MAX_TAGS_PER_REGISTER || rest.len() != count * TAG_BYTES {
                    return None;
                }
                // Length was checked above, so every 16-byte tag is whole.
                let (chunks, _remainder) = rest.as_chunks::<TAG_BYTES>();
                Some(Frame::Register {
                    tags: chunks.iter().map(|chunk| Tag(*chunk)).collect(),
                })
            }
            FRAME_SEND_TAG => {
                let (tag, datagram) = split_routed_tag(body)?;
                Some(Frame::SendTag { tag, datagram })
            }
            FRAME_RECV_TAG => {
                let (tag, datagram) = split_routed_tag(body)?;
                Some(Frame::RecvTag { tag, datagram })
            }
            FRAME_PING => Some(Frame::Ping(fixed(body)?)),
            FRAME_PONG => Some(Frame::Pong(fixed(body)?)),
            FRAME_CLOSE => Some(Frame::Close(u16::from_be_bytes(fixed(body)?))),
            _ => None,
        }
    }
}

fn one(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(tag);
    out.extend_from_slice(body);
    out
}

fn routed(tag: u8, node_id: &NodeId, datagram: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + datagram.len());
    out.push(tag);
    out.extend_from_slice(node_id.as_bytes());
    out.extend_from_slice(datagram);
    out
}

fn fixed<const N: usize>(body: &[u8]) -> Option<[u8; N]> {
    body.try_into().ok()
}

fn split_routed(body: &[u8]) -> Option<(NodeId, Vec<u8>)> {
    if body.len() < 33 {
        return None;
    }
    let datagram = &body[32..];
    if datagram.is_empty() || datagram.len() > MAX_DATAGRAM {
        return None;
    }
    Some((NodeId::from_slice(&body[..32])?, datagram.to_vec()))
}

fn routed_tag(frame: u8, tag: &Tag, datagram: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + TAG_BYTES + datagram.len());
    out.push(frame);
    out.extend_from_slice(&tag.0);
    out.extend_from_slice(datagram);
    out
}

fn split_routed_tag(body: &[u8]) -> Option<(Tag, Vec<u8>)> {
    if body.len() <= TAG_BYTES {
        return None;
    }
    let datagram = &body[TAG_BYTES..];
    if datagram.len() > MAX_DATAGRAM {
        return None;
    }
    let mut tag = [0u8; TAG_BYTES];
    tag.copy_from_slice(&body[..TAG_BYTES]);
    Some((Tag(tag), datagram.to_vec()))
}

// ---------------------------------------------------------------------------
// UDP reflector, spec 3.2
// ---------------------------------------------------------------------------

pub const REFLECT_MAGIC: [u8; 4] = *b"FSLR";
pub const REFLECT_REQUEST: u8 = 0x01;
pub const REFLECT_REPLY: u8 = 0x02;
pub const REFLECT_REQUEST_BYTES: usize = 21;
pub const REFLECT_REPLY_BYTES: usize = 39;

pub fn reflect_request(nonce: &[u8; 16]) -> [u8; REFLECT_REQUEST_BYTES] {
    let mut out = [0u8; REFLECT_REQUEST_BYTES];
    out[..4].copy_from_slice(&REFLECT_MAGIC);
    out[4] = REFLECT_REQUEST;
    out[5..].copy_from_slice(nonce);
    out
}

pub fn parse_reflect_request(bytes: &[u8]) -> Option<[u8; 16]> {
    if bytes.len() != REFLECT_REQUEST_BYTES
        || bytes[..4] != REFLECT_MAGIC
        || bytes[4] != REFLECT_REQUEST
    {
        return None;
    }
    bytes[5..].try_into().ok()
}

pub fn reflect_reply(nonce: &[u8; 16], observed: SocketAddr) -> [u8; REFLECT_REPLY_BYTES] {
    let mut out = [0u8; REFLECT_REPLY_BYTES];
    out[..4].copy_from_slice(&REFLECT_MAGIC);
    out[4] = REFLECT_REPLY;
    out[5..21].copy_from_slice(nonce);
    out[21..37].copy_from_slice(&to_ipv6(observed.ip()).octets());
    out[37..].copy_from_slice(&observed.port().to_be_bytes());
    out
}

pub fn parse_reflect_reply(bytes: &[u8]) -> Option<([u8; 16], SocketAddr)> {
    if bytes.len() != REFLECT_REPLY_BYTES
        || bytes[..4] != REFLECT_MAGIC
        || bytes[4] != REFLECT_REPLY
    {
        return None;
    }
    let nonce: [u8; 16] = bytes[5..21].try_into().ok()?;
    let octets: [u8; 16] = bytes[21..37].try_into().ok()?;
    let port = u16::from_be_bytes([bytes[37], bytes[38]]);
    Some((
        nonce,
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port),
    ))
}

// ---------------------------------------------------------------------------
// Session-keyed probes, spec 4.2 (probe version 2)
// ---------------------------------------------------------------------------
//
// Version 1 was signed by the node's long-term key and carried both node IDs
// in clear, so an on-path observer read who was probing whom and a captured
// ping could be replayed into any later session.  Version 2 is keyed to the
// QUIC session: both sides export the same 40 bytes from the TLS session,
// the first 32 are the HMAC key and the last 8 the key id the receiver looks
// the session up by.  A probe therefore authenticates the live session, names
// nobody, and dies with the session.

pub const PROBE_MAGIC: [u8; 4] = *b"FSLP";
/// The probe version byte; a change means new vectors.
pub const PROBE_VERSION: u8 = 0x02;
pub const PROBE_PING: u8 = 0x01;
pub const PROBE_PONG: u8 = 0x02;
/// Domain separator for the probe MAC.
pub const PROBE_DOMAIN_V2: &[u8] = b"forgesworn-link/probe/v2\0";
/// The TLS exporter label (RFC 8446 section 7.5) both sides derive the probe
/// material from, with an empty context.
pub const PROBE_EXPORT_LABEL: &[u8] = b"forgesworn-link/probe/v2";
pub const PROBE_KEY_BYTES: usize = 32;
pub const PROBE_ID_BYTES: usize = 8;
/// Both sides export this many bytes: key `[0..32]`, key id `[32..40]`.
pub const PROBE_EXPORT_BYTES: usize = PROBE_KEY_BYTES + PROBE_ID_BYTES;
/// Magic, version, kind, key id, nonce.
pub const PROBE_BODY_BYTES: usize = 4 + 1 + 1 + PROBE_ID_BYTES + 16;
pub const PROBE_MAC_BYTES: usize = 32;
pub const PROBE_WIRE_BYTES: usize = PROBE_BODY_BYTES + PROBE_MAC_BYTES;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    pub kind: u8,
    /// Which session's key seals this probe.
    pub key_id: [u8; PROBE_ID_BYTES],
    pub nonce: [u8; 16],
}

impl Probe {
    pub fn body(&self) -> [u8; PROBE_BODY_BYTES] {
        let mut out = [0u8; PROBE_BODY_BYTES];
        out[..4].copy_from_slice(&PROBE_MAGIC);
        out[4] = PROBE_VERSION;
        out[5] = self.kind;
        out[6..6 + PROBE_ID_BYTES].copy_from_slice(&self.key_id);
        out[6 + PROBE_ID_BYTES..].copy_from_slice(&self.nonce);
        out
    }

    fn mac(key: &[u8; PROBE_KEY_BYTES]) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(PROBE_DOMAIN_V2);
        mac
    }

    /// The wire bytes: body, then HMAC-SHA256 over the domain and the body
    /// under the session's probe key.
    pub fn seal(&self, key: &[u8; PROBE_KEY_BYTES]) -> [u8; PROBE_WIRE_BYTES] {
        let body = self.body();
        let mut mac = Self::mac(key);
        mac.update(&body);
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; PROBE_WIRE_BYTES];
        out[..PROBE_BODY_BYTES].copy_from_slice(&body);
        out[PROBE_BODY_BYTES..].copy_from_slice(&tag);
        out
    }

    /// The key id of a datagram that has a probe's shape, so the receiver can
    /// find the session before it verifies anything.  `None` for anything
    /// that is not a version-2 probe of the right length.
    pub fn peek_key_id(bytes: &[u8]) -> Option<[u8; PROBE_ID_BYTES]> {
        if bytes.len() != PROBE_WIRE_BYTES || bytes[..4] != PROBE_MAGIC || bytes[4] != PROBE_VERSION
        {
            return None;
        }
        bytes[6..6 + PROBE_ID_BYTES].try_into().ok()
    }

    /// Verify the MAC in constant time under the session key the key id named
    /// and parse the probe.  A probe that does not verify is not a probe.
    pub fn open(bytes: &[u8], key: &[u8; PROBE_KEY_BYTES]) -> Option<Probe> {
        let key_id = Self::peek_key_id(bytes)?;
        let kind = bytes[5];
        if kind != PROBE_PING && kind != PROBE_PONG {
            return None;
        }
        let mut mac = Self::mac(key);
        mac.update(&bytes[..PROBE_BODY_BYTES]);
        mac.verify_slice(&bytes[PROBE_BODY_BYTES..]).ok()?;
        Some(Probe {
            kind,
            key_id,
            nonce: bytes[6 + PROBE_ID_BYTES..PROBE_BODY_BYTES]
                .try_into()
                .ok()?,
        })
    }
}
