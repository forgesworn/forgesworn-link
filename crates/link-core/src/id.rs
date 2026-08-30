//! Node identity: Ed25519 transport keys, node IDs, SPKI and the synthetic address.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Domain separator for the synthetic address derivation, spec 4.1.
pub const ADDR_DOMAIN: &[u8] = b"forgesworn-link/addr/v1\0";

/// DER prefix of a SubjectPublicKeyInfo carrying an id-Ed25519 key, RFC 8410.
pub const SPKI_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// PKCS#8 v1 prefix for an id-Ed25519 private key, RFC 8410 section 7.
pub const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// The port every synthetic address uses, spec 4.1.
pub const SYNTHETIC_PORT: u16 = 7;

const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// A node ID is the 32 byte Ed25519 public key of the transport key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(NodeId(arr))
    }

    pub fn from_hex(text: &str) -> Option<Self> {
        let raw = hex::decode(text).ok()?;
        Self::from_slice(&raw)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Lowercase RFC 4648 base32 with no padding, 52 characters, spec 1.
    pub fn to_base32(&self) -> String {
        let mut bits = 0u32;
        let mut acc = 0u32;
        let mut out = String::with_capacity(52);
        for byte in self.0 {
            acc = (acc << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                out.push(BASE32_ALPHABET[((acc >> (bits - 5)) & 31) as usize] as char);
                bits -= 5;
            }
        }
        if bits > 0 {
            out.push(BASE32_ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
        }
        out
    }

    pub fn from_base32(text: &str) -> Option<Self> {
        // Canonical form only. 52 lowercase base32 characters encode 260 bits;
        // the low 4 bits of the final character are padding and MUST be zero, or
        // 16 distinct spellings would name the same node and any allowlist, cache
        // or dedup keyed on the text could be bypassed. Enforce it by length and
        // by requiring the value to re-encode to exactly this input.
        if text.len() != 52 {
            return None;
        }
        let mut bits = 0u32;
        let mut acc = 0u32;
        let mut out = Vec::with_capacity(32);
        for ch in text.bytes() {
            let value = BASE32_ALPHABET.iter().position(|c| *c == ch)? as u32;
            acc = (acc << 5) | value;
            bits += 5;
            if bits >= 8 {
                out.push(((acc >> (bits - 8)) & 0xff) as u8);
                bits -= 8;
            }
        }
        let id = Self::from_slice(&out)?;
        if id.to_base32() != text {
            return None;
        }
        Some(id)
    }

    pub fn verifying_key(&self) -> Option<VerifyingKey> {
        VerifyingKey::from_bytes(&self.0).ok()
    }

    /// The DER SubjectPublicKeyInfo for this node ID.
    pub fn spki_der(&self) -> [u8; 44] {
        let mut out = [0u8; 44];
        out[..12].copy_from_slice(&SPKI_ED25519_PREFIX);
        out[12..].copy_from_slice(&self.0);
        out
    }

    /// The stable synthetic address QUIC uses for this peer, spec 4.1.
    pub fn synthetic_addr(&self) -> SocketAddr {
        let mut hasher = Sha256::new();
        hasher.update(ADDR_DOMAIN);
        hasher.update(self.0);
        let digest = hasher.finalize();
        let mut octets = [0u8; 16];
        octets[0] = 0xfd;
        octets[1] = 0x00;
        octets[2..].copy_from_slice(&digest[..14]);
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), SYNTHETIC_PORT)
    }

    /// Strict verification (cofactored, malleability rejected), so a signed
    /// byte string has exactly one valid signature encoding and card bytes can
    /// serve as a dedup key.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        let Some(key) = self.verifying_key() else {
            return false;
        };
        key.verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.to_base32())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base32())
    }
}

/// Recover a node ID from a DER SubjectPublicKeyInfo, rejecting any other key type.
pub fn node_id_from_spki(der: &[u8]) -> Option<NodeId> {
    if der.len() != 44 || der[..12] != SPKI_ED25519_PREFIX {
        return None;
    }
    NodeId::from_slice(&der[12..])
}

/// Recover a node ID from a DER X.509 certificate by reading its SPKI, spec 1.
pub fn node_id_from_cert_der(cert: &[u8]) -> Option<NodeId> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert).ok()?;
    node_id_from_spki(parsed.tbs_certificate.subject_pki.raw)
}

/// The long-lived transport key of one node.
#[derive(Clone)]
pub struct TransportKey {
    signing: SigningKey,
    node_id: NodeId,
}

impl fmt::Debug for TransportKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TransportKey({})", self.node_id)
    }
}

impl TransportKey {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let node_id = NodeId(signing.verifying_key().to_bytes());
        TransportKey { signing, node_id }
    }

    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        Self::from_seed(seed)
    }

    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    /// PKCS#8 v1 DER, which is what rcgen and rustls both want.
    pub fn pkcs8_der(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        out[..16].copy_from_slice(&PKCS8_ED25519_PREFIX);
        out[16..].copy_from_slice(&self.seed());
        out
    }
}

#[cfg(test)]
mod base32_tests {
    use super::*;

    fn sample_id() -> NodeId {
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = index as u8;
        }
        NodeId(bytes)
    }

    #[test]
    fn round_trips_canonical() {
        let id = sample_id();
        let text = id.to_base32();
        assert_eq!(text.len(), 52);
        assert_eq!(NodeId::from_base32(&text), Some(id));
    }

    #[test]
    fn rejects_non_canonical_pad_bits() {
        // 52 base32 characters carry 260 bits; the low 4 bits of the final
        // character are padding and are zero in canonical form. A spelling that
        // sets one of those bits decodes to the same 32 bytes but is not
        // canonical, and must be rejected so the fsl:// text is a unique name.
        let id = sample_id();
        let text = id.to_base32();
        let last = *text.as_bytes().last().unwrap();
        let value = BASE32_ALPHABET.iter().position(|c| *c == last).unwrap();
        assert_eq!(
            value & 0x0f,
            0,
            "canonical final character has zero pad bits"
        );
        let sibling = BASE32_ALPHABET[value | 1] as char;
        let mut mutant = text[..text.len() - 1].to_string();
        mutant.push(sibling);
        assert_ne!(mutant, text);
        assert_eq!(
            NodeId::from_base32(&mutant),
            None,
            "a non-canonical spelling must not decode",
        );
    }

    #[test]
    fn rejects_wrong_length_and_case() {
        let text = sample_id().to_base32();
        assert_eq!(NodeId::from_base32(&text[..text.len() - 1]), None);
        assert_eq!(NodeId::from_base32(&format!("{text}a")), None);
        assert_eq!(NodeId::from_base32(&text.to_uppercase()), None);
    }
}
