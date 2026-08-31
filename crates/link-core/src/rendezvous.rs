//! Rendezvous-tag derivation, spec section 9 / `docs/RENDEZVOUS.md` (accepted
//! and frozen by both owners).  A tag is a pair-scoped, per-epoch routing
//! capability: the relay matches two endpoints presenting the same tag and
//! learns neither node identity nor any stable pseudonym.
//!
//! Everything here is pure derivation over opaque key bytes.  Nothing touches
//! Nostr or opens a socket; the shell supplies the pair's key material.

use std::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF salt, `docs/RENDEZVOUS.md` section 2.
pub const RENDEZVOUS_SALT: &[u8] = b"forgesworn-link/rendezvous/v1";
/// Tags rotate hourly.
pub const EPOCH_SECONDS: u64 = 3600;
/// A tag is 16 bytes.
pub const TAG_BYTES: usize = 16;
/// Pairing secrets are 16 raw bytes, encoded as 32 lowercase hex characters
/// at the product boundary.  The ASCII spelling is never HKDF input.
pub const PAIRING_SECRET_BYTES: usize = 16;
/// Domain separator for a pairing-secret rendezvous tag.
pub const PAIRING_CASE: u8 = 0x03;

/// Which ephemeral mix the pair used.  Leads the ikm as a domain separator so
/// the three modes can never be cross-interpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagCase {
    /// Neither card carries hint `0x04`; `eph_x` is 32 zero bytes.  No forward
    /// secrecy.
    None = 0x00,
    /// Exactly one card carries hint `0x04`; `eph_x = x(ECDH(eph, peer's
    /// static key))`.  Forward-secret only against compromise of the carrying
    /// side.
    One = 0x01,
    /// Both cards carry hint `0x04`; `eph_x = x(ECDH(eph_a, eph_b))`.  Full
    /// forward secrecy.
    Both = 0x02,
}

impl TagCase {
    pub fn byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(byte: u8) -> Option<TagCase> {
        match byte {
            0x00 => Some(TagCase::None),
            0x01 => Some(TagCase::One),
            0x02 => Some(TagCase::Both),
            _ => None,
        }
    }
}

/// A rendezvous tag.  `Debug` is deliberately redacted: the spec forbids the
/// relay to log tags, and nothing else should either.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag(pub [u8; TAG_BYTES]);

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tag(redacted)")
    }
}

/// `floor(unix_seconds / 3600)`.
pub fn epoch_index(unix_seconds: u64) -> u64 {
    unix_seconds / EPOCH_SECONDS
}

/// The tag derivation of `docs/RENDEZVOUS.md` section 2:
///
/// ```text
/// tag = HKDF-SHA256(
///   ikm  = case_byte || static_x || eph_x,          // 65 bytes
///   salt = "forgesworn-link/rendezvous/v1",
///   info = relay_host || 0x00 || u64be(epoch_index),
///   L    = 16,
/// )
/// ```
///
/// `relay_host` is the lowercase hostname without port, exactly as in relay
/// authentication.  Every input is symmetric, so both ends derive the same tag
/// with no ordering rule.
pub fn derive_tag(
    case: TagCase,
    static_x: &[u8; 32],
    eph_x: &[u8; 32],
    relay_host: &str,
    epoch: u64,
) -> Tag {
    let mut ikm = Zeroizing::new([0u8; 65]);
    ikm[0] = case.byte();
    ikm[1..33].copy_from_slice(static_x);
    ikm[33..65].copy_from_slice(eph_x);
    derive_from_ikm(&ikm[..], relay_host, epoch)
}

/// The first-contact pairing tag.  It is reachability only: the relay sees
/// registered tags, so end-to-end authority still requires the raw secret to
/// be proved inside the box-pinned TLS request.
///
/// ```text
/// ikm = 0x03 || pairing_secret // 17 bytes; secret is 16 raw bytes
/// ```
pub fn derive_pairing_tag(
    pairing_secret: &[u8; PAIRING_SECRET_BYTES],
    relay_host: &str,
    epoch: u64,
) -> Tag {
    let mut ikm = Zeroizing::new([0u8; 1 + PAIRING_SECRET_BYTES]);
    ikm[0] = PAIRING_CASE;
    ikm[1..].copy_from_slice(pairing_secret);
    derive_from_ikm(&ikm[..], relay_host, epoch)
}

fn derive_from_ikm(ikm: &[u8], relay_host: &str, epoch: u64) -> Tag {
    let hk = Hkdf::<Sha256>::new(Some(RENDEZVOUS_SALT), ikm);
    let mut info = Vec::with_capacity(relay_host.len() + 1 + 8);
    info.extend_from_slice(relay_host.as_bytes());
    info.push(0);
    info.extend_from_slice(&epoch.to_be_bytes());
    let mut tag = [0u8; TAG_BYTES];
    hk.expand(&info, &mut tag)
        .expect("16 bytes is a valid HKDF-SHA256 output length");
    Tag(tag)
}

/// The raw x-coordinate of the secp256k1 shared point -- NOT a library's
/// hashed `ecdh()` convenience, which silently fails every known-answer
/// vector.  `None` for an invalid scalar or a point not on the curve.
pub fn ecdh_x(private_scalar: &[u8; 32], compressed_public: &[u8; 33]) -> Option<[u8; 32]> {
    // The same canonical-tag rule as valid_compressed_point: 0x02/0x03 only.
    if !matches!(compressed_public[0], 0x02 | 0x03) {
        return None;
    }
    let secret = k256::SecretKey::from_slice(private_scalar).ok()?;
    let public = k256::PublicKey::from_sec1_bytes(compressed_public).ok()?;
    let shared = k256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let mut x = [0u8; 32];
    x.copy_from_slice(shared.raw_secret_bytes().as_slice());
    Some(x)
}

/// True when `bytes` is a valid 33-byte compressed secp256k1 point.  The card
/// verifier uses this for hint `0x04`: a value that does not decompress is a
/// malformed hint and fails the whole card.
pub fn valid_compressed_point(bytes: &[u8]) -> bool {
    // SEC1 tag 0x02/0x03 only.  from_sec1_bytes alone also parses the 0x05
    // compact form, which would give one point two spellings inside signed
    // card bytes -- and card bytes are a dedup key, so a point must have
    // exactly one.
    bytes.len() == 33
        && matches!(bytes[0], 0x02 | 0x03)
        && k256::PublicKey::from_sec1_bytes(bytes).is_ok()
}

/// A fresh ephemeral for one card: `(private scalar, compressed public key)`.
/// The caller owns the erasure duties of `docs/RENDEZVOUS.md` section 1: the
/// private scalar, and every tag and `eph_x` derived from it, MUST be erased
/// when the card expires or rotates.  That erasure is the forward secrecy.
pub fn generate_ephemeral() -> ([u8; 32], [u8; 33]) {
    let secret = k256::SecretKey::random(&mut rand::rngs::OsRng);
    let public = secret.public_key();
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&secret.to_bytes());
    let sec1 = public.to_sec1_bytes();
    let mut compressed = [0u8; 33];
    compressed.copy_from_slice(&sec1);
    (scalar, compressed)
}
