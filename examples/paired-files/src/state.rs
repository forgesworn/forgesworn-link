//! Local storage for one enrolled peer. The parent directory is private to the app.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use link_core::RelayAdmissionKey;
use link_core::admission::RELAY_ADMISSION_KEY_BYTES;
use link_core::card::{Card, VerifyContext};
use link_core::id::{NodeId, TransportKey};
use link_endpoint::Endpoint;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use zeroize::{Zeroize, Zeroizing};

use super::{RelayArgs, parent_directory};

const STATE_VERSION: u8 = 1;
const MAX_STATE_BYTES: u64 = 24 * 1024;

pub(super) fn read_admission_key(path: &Path) -> Result<RelayAdmissionKey> {
    let limit = (2 * RELAY_ADMISSION_KEY_BYTES + 2) as u64;
    let bytes = read_private_file(path, limit, "relay admission key file")?;
    RelayAdmissionKey::from_hex(std::str::from_utf8(&bytes)?.trim())
        .context("the admission key file must contain one 64-character hex key")
}

fn read_private_file(path: &Path, limit: u64, name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("opening the {name}"))?;
    ensure!(metadata.is_file(), "the {name} must be a regular file");
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "the opened {name} must be a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "the {name} must have owner-only permissions"
        );
    }
    let mut contents = Zeroizing::new(Vec::new());
    file.take(limit + 1).read_to_end(&mut contents)?;
    ensure!(contents.len() as u64 <= limit, "the {name} is too large");
    Ok(contents)
}

#[derive(Deserialize, Serialize)]
pub(super) struct SavedCard {
    bytes: Vec<u8>,
    verified_at: u64,
}

impl SavedCard {
    pub(super) fn new(card: &Card, verified_at: u64) -> Self {
        Self {
            bytes: card.as_bytes().to_vec(),
            verified_at,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub(super) struct SavedPair {
    version: u8,
    relay: RelayArgs,
    transport_seed: [u8; 32],
    peer: [u8; 32],
    route_secret: [u8; 32],
    // Only the sender needs an address card. The receiver already knows the
    // peer's pinned identity from the authenticated pairing connection.
    sender_card: Option<SavedCard>,
}

impl Drop for SavedPair {
    fn drop(&mut self) {
        self.transport_seed.zeroize();
        self.route_secret.zeroize();
    }
}

impl SavedPair {
    pub(super) fn new(
        relay: RelayArgs,
        key: &TransportKey,
        peer: NodeId,
        route_secret: &[u8; 32],
        sender_card: Option<SavedCard>,
    ) -> Self {
        Self {
            version: STATE_VERSION,
            relay,
            transport_seed: key.seed(),
            peer: *peer.as_bytes(),
            route_secret: *route_secret,
            sender_card,
        }
    }

    pub(super) fn load(path: &Path) -> Result<Self> {
        let contents = read_private_file(path, MAX_STATE_BYTES, "pairing file")?;
        let pair: Self = serde_json::from_slice(&contents)
            .map_err(|_| anyhow::anyhow!("invalid saved pairing record"))?;
        ensure!(
            pair.version == STATE_VERSION,
            "unsupported pairing record version"
        );
        Ok(pair)
    }

    pub(super) fn receive_peer(&self) -> Result<NodeId> {
        ensure!(
            self.sender_card.is_none(),
            "this pairing file belongs to the sender"
        );
        Ok(NodeId(self.peer))
    }

    pub(super) fn send_card(&self) -> Result<Card> {
        let card = self
            .sender_card
            .as_ref()
            .context("this pairing file belongs to the receiver")?;
        // This enrolment is already authorised locally. Verify the signed card
        // at enrolment time and keep pinning the same key on every subsequent dial.
        Ok(Card::verify(
            &card.bytes,
            &VerifyContext::new(card.verified_at).expecting(NodeId(self.peer)),
        )?)
    }

    pub(super) async fn open(&self, key_file: Option<&Path>) -> Result<Endpoint> {
        let key = TransportKey::from_seed(self.transport_seed);
        let mut config = self.relay.config(key, key_file)?;
        config.paired_routes = Some(HashMap::from([(
            NodeId(self.peer),
            Zeroizing::new(self.route_secret),
        )]));
        Endpoint::open(config).await
    }
}

pub(super) struct StagedPair {
    path: PathBuf,
    file: NamedTempFile,
}

impl StagedPair {
    pub(super) fn new(path: PathBuf) -> Result<Self> {
        match fs::symlink_metadata(&path) {
            Ok(_) => anyhow::bail!("the pairing file already exists"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("checking the pairing file path"),
        }
        let file =
            NamedTempFile::new_in(parent_directory(&path)).context("staging the pairing file")?;
        Ok(Self { path, file })
    }

    pub(super) fn save(mut self, pair: SavedPair) -> Result<()> {
        serde_json::to_writer(self.file.as_file_mut(), &pair)?;
        self.file.as_file().sync_all()?;
        self.file
            .persist_noclobber(self.path)
            .context("saving the pairing file")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_route_still_pins_the_peer_after_the_invite_expires() -> Result<()> {
        let enrolled_at = 1_700_000_000;
        let receiver = TransportKey::generate();
        let card = Card::sign(&receiver, enrolled_at, enrolled_at + 300, 1, Vec::new());
        let now = enrolled_at + 600;
        assert!(Card::verify(card.as_bytes(), &VerifyContext::new(now)).is_err());

        let pair = SavedPair::new(
            RelayArgs {
                relay: "wss://relay.example/link".into(),
                relay_cert_sha256: None,
                relay_admission_key_file: None,
            },
            &TransportKey::generate(),
            receiver.node_id(),
            &[42; 32],
            Some(SavedCard::new(&card, enrolled_at)),
        );
        assert_eq!(pair.send_card()?.node_id, receiver.node_id());
        Ok(())
    }
}
