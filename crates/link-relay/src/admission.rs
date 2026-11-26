use std::sync::{Arc, Mutex};

use anyhow::{Result, ensure};
use link_core::RelayAdmissionKey;
use link_core::admission::{ADMISSION_PROOF_BYTES, registration_digest};
use link_core::rendezvous::Tag;
use tokio::sync::watch;

/// Bounds the number of MAC checks on a new connection.
pub const MAX_ADMISSION_KEYS: usize = 256;

/// The operator's live allowlist for tag relay connections.
#[derive(Clone, Default)]
pub struct RelayAdmission(Arc<Mutex<Vec<Grant>>>);

struct Grant {
    key: RelayAdmissionKey,
    active: watch::Sender<()>,
}

impl RelayAdmission {
    /// Atomically replace the whole set. An empty set admits nobody. Existing
    /// connections using a removed key are closed, including after a regrant.
    pub fn replace_keys(&self, keys: Vec<RelayAdmissionKey>) -> Result<()> {
        ensure!(
            keys.len() <= MAX_ADMISSION_KEYS,
            "too many relay admission keys"
        );
        let mut grants = self.0.lock().expect("relay admission grants");
        if grants.iter().map(|grant| &grant.key).eq(&keys) {
            return Ok(());
        }
        ensure!(
            keys.iter()
                .enumerate()
                .all(|(i, key)| !keys[..i].contains(key)),
            "duplicate relay admission key"
        );
        let mut previous = std::mem::take(&mut *grants);
        *grants = keys
            .into_iter()
            .map(|key| {
                if let Some(i) = previous.iter().position(|grant| grant.key == key) {
                    previous.swap_remove(i)
                } else {
                    Grant {
                        key,
                        active: watch::channel(()).0,
                    }
                }
            })
            .collect();
        // The removed grants drop their final senders and wake just their sessions.
        drop(previous);
        Ok(())
    }

    pub(crate) fn admit(
        &self,
        challenge: &[u8; 32],
        tags: &[Tag],
        proof: &[u8; ADMISSION_PROOF_BYTES],
        register: impl FnOnce(),
    ) -> Option<watch::Receiver<()>> {
        let roster = registration_digest(tags);
        let grants = self.0.lock().expect("relay admission grants");
        let grant = grants
            .iter()
            .find(|grant| grant.key.verify_proof(challenge, &roster, proof))?;
        // Serialise initial registration with a concurrent grant replacement.
        register();
        Some(grant.active.subscribe())
    }
}

pub(crate) async fn revoked(active: &mut Option<watch::Receiver<()>>) {
    match active {
        Some(active) => {
            let _ = active.changed().await;
        }
        None => std::future::pending().await,
    }
}
