//! Proof of an operator-issued relay key, independent of peer identity.

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::rendezvous::Tag;

const DOMAIN: &[u8] = b"forgesworn-link/relay-admission/v1\0";
pub const ADMISSION_PROOF_BYTES: usize = 32;
pub const RELAY_ADMISSION_KEY_BYTES: usize = 32;

/// A randomly generated secret shared by an operator and a relay client.
#[derive(Clone)]
pub struct RelayAdmissionKey(Zeroizing<[u8; RELAY_ADMISSION_KEY_BYTES]>);

impl RelayAdmissionKey {
    pub fn from_bytes(bytes: [u8; RELAY_ADMISSION_KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn from_hex(text: &str) -> Option<Self> {
        let mut bytes = Zeroizing::new([0; RELAY_ADMISSION_KEY_BYTES]);
        hex::decode_to_slice(text, bytes.as_mut()).ok()?;
        Some(Self(bytes))
    }

    pub fn proof(&self, challenge: &[u8; 32], roster: &[u8; 32]) -> [u8; ADMISSION_PROOF_BYTES] {
        self.mac(challenge, roster).finalize().into_bytes().into()
    }

    pub fn verify_proof(
        &self,
        challenge: &[u8; 32],
        roster: &[u8; 32],
        proof: &[u8; ADMISSION_PROOF_BYTES],
    ) -> bool {
        self.mac(challenge, roster).verify_slice(proof).is_ok()
    }

    fn mac(&self, challenge: &[u8; 32], roster: &[u8; 32]) -> Hmac<Sha256> {
        let mut mac = Hmac::new_from_slice(self.0.as_ref()).expect("valid HMAC key length");
        mac.update(DOMAIN);
        mac.update(challenge);
        mac.update(roster);
        mac
    }
}

impl PartialEq for RelayAdmissionKey {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}

impl Eq for RelayAdmissionKey {}

impl fmt::Debug for RelayAdmissionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelayAdmissionKey([redacted])")
    }
}

/// Hash the registration's encoded count and tags once, before checking keys.
pub fn registration_digest(tags: &[Tag]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update((tags.len() as u16).to_be_bytes());
    for tag in tags {
        hash.update(tag.0);
    }
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_matches_an_independent_hmac_vector_and_binds_the_challenge_and_roster() {
        let key = RelayAdmissionKey::from_hex(&"31".repeat(32)).unwrap();
        let tags = [Tag([0x5a; 16]), Tag([0x22; 16])];
        let roster = registration_digest(&tags);
        let challenge = [0x61; 32];
        let proof = key.proof(&challenge, &roster);
        assert_eq!(
            hex::encode(proof),
            "502de145220f57b6b94fd2ca57ad2f5d0ea17076e301abf1abef8e4485bb6e6b"
        );
        assert!(key.verify_proof(&challenge, &roster, &proof));
        assert!(!key.verify_proof(&[0x62; 32], &roster, &proof));
        assert!(!key.verify_proof(
            &challenge,
            &registration_digest(&[tags[1], tags[0]]),
            &proof
        ));
        assert_eq!(format!("{key:?}"), "RelayAdmissionKey([redacted])");
    }
}
