//! `FSL-CARD-1`, the address card of spec section 2.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::id::{NodeId, TransportKey};

/// Domain separator for the card signature, spec 2.1.
pub const CARD_DOMAIN: &[u8] = b"forgesworn-link/card/v1\0";

pub const CARD_MAGIC: [u8; 4] = *b"FSL1";
pub const CARD_VERSION: u8 = 0x01;
pub const MIN_CARD_BYTES: usize = 126;
pub const MAX_CARD_BYTES: usize = 4096;
pub const MAX_HINTS: usize = 16;
pub const CLOCK_SKEW_SECONDS: u64 = 300;
pub const MAX_LIFETIME_SECONDS: u64 = 604_800;

pub const HINT_RELAY: u8 = 0x01;
/// A relay hint value is 1 to 255 bytes, spec 2.2 and rule 3 of 2.3.
pub const MAX_RELAY_HINT_BYTES: usize = 255;
pub const HINT_UDP: u8 = 0x02;
pub const HINT_ONION: u8 = 0x03;
/// Ephemeral rendezvous key, spec section 9 / docs/RENDEZVOUS.md: a fresh
/// 33-byte compressed secp256k1 public key, at most one per card.  Optional;
/// a card carries it when the owner wants forward-secret rendezvous tags.
pub const HINT_EPHEMERAL: u8 = 0x04;

const HEADER_BYTES: usize = 62;
const SIGNATURE_BYTES: usize = 64;

/// One hint, kept in wire form so unknown kinds survive a decode and re-encode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hint {
    pub kind: u8,
    pub value: Vec<u8>,
}

impl Hint {
    pub fn relay(url: &str) -> Self {
        Hint {
            kind: HINT_RELAY,
            value: url.as_bytes().to_vec(),
        }
    }

    pub fn udp(addr: SocketAddr) -> Self {
        let mut value = Vec::with_capacity(18);
        value.extend_from_slice(&to_ipv6(addr.ip()).octets());
        value.extend_from_slice(&addr.port().to_be_bytes());
        Hint {
            kind: HINT_UDP,
            value,
        }
    }

    pub fn onion(host: &str, port: u16) -> Self {
        let mut value = Vec::with_capacity(58);
        value.extend_from_slice(host.as_bytes());
        value.extend_from_slice(&port.to_be_bytes());
        Hint {
            kind: HINT_ONION,
            value,
        }
    }

    pub fn as_relay(&self) -> Option<&str> {
        if self.kind != HINT_RELAY {
            return None;
        }
        std::str::from_utf8(&self.value).ok()
    }

    pub fn as_udp(&self) -> Option<SocketAddr> {
        if self.kind != HINT_UDP || self.value.len() != 18 {
            return None;
        }
        let octets: [u8; 16] = self.value[..16].try_into().ok()?;
        let port = u16::from_be_bytes([self.value[16], self.value[17]]);
        Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
    }

    pub fn as_onion(&self) -> Option<(&str, u16)> {
        if self.kind != HINT_ONION || self.value.len() != 58 {
            return None;
        }
        let host = std::str::from_utf8(&self.value[..56]).ok()?;
        Some((host, u16::from_be_bytes([self.value[56], self.value[57]])))
    }

    fn encoded_len(&self) -> usize {
        3 + self.value.len()
    }
}

/// Map an IPv4 address into the v4-mapped IPv6 space the wire format uses.
pub fn to_ipv6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V6(v6) => v6,
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
    }
}

/// Undo `to_ipv6` for display and for socket use.
pub fn unmap_ipv6(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), addr.port()),
            None => addr,
        },
        IpAddr::V4(_) => addr,
    }
}

/// A verified or freshly signed card, together with its exact bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Card {
    pub node_id: NodeId,
    pub issued_at: u64,
    pub expires_at: u64,
    pub serial: u64,
    pub hints: Vec<Hint>,
    raw: Vec<u8>,
}

/// The first rule of spec 2.3 that a card failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleViolation {
    pub rule: u8,
    pub detail: &'static str,
}

impl std::fmt::Display for RuleViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "card rule {} failed: {}", self.rule, self.detail)
    }
}

impl std::error::Error for RuleViolation {}

fn fail(rule: u8, detail: &'static str) -> RuleViolation {
    RuleViolation { rule, detail }
}

/// What a verifier knows before it looks at a card, spec 2.3.
#[derive(Clone, Debug)]
pub struct VerifyContext {
    pub now: u64,
    pub highest_seen_serial: u64,
    pub expected_node_id: Option<NodeId>,
}

impl VerifyContext {
    pub fn new(now: u64) -> Self {
        VerifyContext {
            now,
            highest_seen_serial: 0,
            expected_node_id: None,
        }
    }

    pub fn expecting(mut self, node_id: NodeId) -> Self {
        self.expected_node_id = Some(node_id);
        self
    }

    pub fn after_serial(mut self, serial: u64) -> Self {
        self.highest_seen_serial = serial;
        self
    }
}

impl Card {
    /// Sign a fresh card over its exact bytes.
    pub fn sign(
        key: &TransportKey,
        issued_at: u64,
        expires_at: u64,
        serial: u64,
        hints: Vec<Hint>,
    ) -> Card {
        let body = encode_body(key.node_id(), issued_at, expires_at, serial, &hints);
        let mut signing_input = Vec::with_capacity(CARD_DOMAIN.len() + body.len());
        signing_input.extend_from_slice(CARD_DOMAIN);
        signing_input.extend_from_slice(&body);
        let signature = key.sign(&signing_input);
        let mut raw = body;
        raw.extend_from_slice(&signature);
        Card {
            node_id: key.node_id(),
            issued_at,
            expires_at,
            serial,
            hints,
            raw,
        }
    }

    /// The exact card bytes, always byte-identical to what was verified.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// The domain-prefixed body the signature covers.
    pub fn signing_input(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CARD_DOMAIN.len() + self.raw.len() - SIGNATURE_BYTES);
        out.extend_from_slice(CARD_DOMAIN);
        out.extend_from_slice(&self.raw[..self.raw.len() - SIGNATURE_BYTES]);
        out
    }

    pub fn signature(&self) -> [u8; 64] {
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&self.raw[self.raw.len() - SIGNATURE_BYTES..]);
        sig
    }

    pub fn relay_urls(&self) -> Vec<String> {
        self.hints
            .iter()
            .filter_map(|h| h.as_relay().map(str::to_owned))
            .collect()
    }

    pub fn udp_candidates(&self) -> Vec<SocketAddr> {
        self.hints.iter().filter_map(Hint::as_udp).collect()
    }

    /// Verify a card against the ordered rules of spec 2.3, reporting the first failure.
    pub fn verify(bytes: &[u8], ctx: &VerifyContext) -> Result<Card, RuleViolation> {
        // Rule 1: overall length.
        if bytes.len() < MIN_CARD_BYTES {
            return Err(fail(1, "card shorter than the 126 byte minimum"));
        }
        if bytes.len() > MAX_CARD_BYTES {
            return Err(fail(1, "card longer than the 4096 byte maximum"));
        }

        // Rule 2: magic and version.
        if bytes[..4] != CARD_MAGIC {
            return Err(fail(2, "magic is not FSL1"));
        }
        if bytes[4] != CARD_VERSION {
            return Err(fail(2, "version is not 0x01"));
        }

        let node_id = NodeId::from_slice(&bytes[5..37]).expect("32 bytes checked by rule 1");
        let issued_at = be64(&bytes[37..45]);
        let expires_at = be64(&bytes[45..53]);
        let serial = be64(&bytes[53..61]);
        let hint_count = bytes[61] as usize;
        let hints_end = bytes.len() - SIGNATURE_BYTES;

        // Rule 3: hint region.  The signature is a fixed trailer, so the verifier
        // locates it before it parses a single hint.
        if hint_count > MAX_HINTS {
            return Err(fail(3, "hint_count above 16"));
        }
        let mut offset = HEADER_BYTES;
        let mut hints = Vec::with_capacity(hint_count);
        for _ in 0..hint_count {
            if offset + 3 > hints_end {
                return Err(fail(3, "hint header runs past the signature"));
            }
            let kind = bytes[offset];
            let length = u16::from_be_bytes([bytes[offset + 1], bytes[offset + 2]]) as usize;
            let value_start = offset + 3;
            let value_end = match value_start.checked_add(length) {
                Some(end) => end,
                None => return Err(fail(3, "hint length overflows")),
            };
            if value_end > hints_end {
                return Err(fail(3, "hint value runs past the signature"));
            }
            match kind {
                HINT_RELAY if length == 0 || length > MAX_RELAY_HINT_BYTES => {
                    return Err(fail(3, "relay hint is not 1 to 255 bytes"));
                }
                HINT_UDP if length != 18 => {
                    return Err(fail(3, "udp hint is not 18 bytes"));
                }
                HINT_ONION if length != 58 => {
                    return Err(fail(3, "onion hint is not 58 bytes"));
                }
                HINT_EPHEMERAL => {
                    if length != 33 {
                        return Err(fail(3, "ephemeral hint is not 33 bytes"));
                    }
                    if !crate::rendezvous::valid_compressed_point(&bytes[value_start..value_end]) {
                        return Err(fail(
                            3,
                            "ephemeral hint does not decompress to a curve point",
                        ));
                    }
                }
                _ => {}
            }
            hints.push(Hint {
                kind,
                value: bytes[value_start..value_end].to_vec(),
            });
            offset = value_end;
        }
        if offset != hints_end {
            return Err(fail(3, "hints do not end exactly at the signature"));
        }
        if hints
            .iter()
            .filter(|hint| hint.kind == HINT_EPHEMERAL)
            .count()
            > 1
        {
            return Err(fail(3, "more than one ephemeral hint"));
        }

        // Rule 4: signature over the domain-prefixed body.
        let mut signing_input = Vec::with_capacity(CARD_DOMAIN.len() + hints_end);
        signing_input.extend_from_slice(CARD_DOMAIN);
        signing_input.extend_from_slice(&bytes[..hints_end]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[hints_end..]);
        if !node_id.verify(&signing_input, &signature) {
            return Err(fail(4, "signature does not verify under node_id"));
        }

        // Rule 5: issued too far in the future.
        if issued_at > ctx.now.saturating_add(CLOCK_SKEW_SECONDS) {
            return Err(fail(5, "issued_at is beyond the allowed clock skew"));
        }

        // Rule 6: already expired.
        if expires_at <= ctx.now {
            return Err(fail(6, "card has expired"));
        }

        // Rule 7: lifetime sanity.
        if expires_at <= issued_at {
            return Err(fail(7, "expires_at is not after issued_at"));
        }
        if expires_at - issued_at > MAX_LIFETIME_SECONDS {
            return Err(fail(7, "lifetime longer than seven days"));
        }

        // Rule 8: replay of a stale serial.
        if serial <= ctx.highest_seen_serial {
            return Err(fail(
                8,
                "serial is not above the highest previously accepted",
            ));
        }

        // Rule 9: not the peer the owner chose.
        if let Some(expected) = ctx.expected_node_id
            && expected != node_id
        {
            return Err(fail(9, "node_id is not the expected peer"));
        }

        Ok(Card {
            node_id,
            issued_at,
            expires_at,
            serial,
            hints,
            raw: bytes.to_vec(),
        })
    }
}

fn be64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("8 bytes"))
}

fn encode_body(
    node_id: NodeId,
    issued_at: u64,
    expires_at: u64,
    serial: u64,
    hints: &[Hint],
) -> Vec<u8> {
    let hint_bytes: usize = hints.iter().map(Hint::encoded_len).sum();
    let mut out = Vec::with_capacity(HEADER_BYTES + hint_bytes);
    out.extend_from_slice(&CARD_MAGIC);
    out.push(CARD_VERSION);
    out.extend_from_slice(node_id.as_bytes());
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.extend_from_slice(&expires_at.to_be_bytes());
    out.extend_from_slice(&serial.to_be_bytes());
    out.push(hints.len() as u8);
    for hint in hints {
        out.push(hint.kind);
        out.extend_from_slice(&(hint.value.len() as u16).to_be_bytes());
        out.extend_from_slice(&hint.value);
    }
    out
}
