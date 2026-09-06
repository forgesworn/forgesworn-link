use super::{LanError, now};
use link_core::{
    card::{Card, VerifyContext},
    id::NodeId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

pub const MAX_ADMITTED_PEERS: usize = 256;

/// Persist this beside the product's trusted peer identity before using an
/// admission. An exact current card may be restored; conflicting or older
/// cards are refused. Link does not own the product's persistence transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CardCheckpoint {
    pub serial: u64,
    pub sha256: [u8; 32],
}

pub(super) fn verify_card(
    expected: NodeId,
    raw: &[u8],
    checkpoint: Option<&CardCheckpoint>,
) -> Result<(Card, CardCheckpoint), LanError> {
    if !(link_core::card::MIN_CARD_BYTES..=link_core::card::MAX_CARD_BYTES).contains(&raw.len())
        || checkpoint.is_some_and(|checkpoint| checkpoint.serial == 0)
    {
        return Err(LanError::Card);
    }
    let digest: [u8; 32] = Sha256::digest(raw).into();
    let floor = checkpoint.map_or(0, |checkpoint| {
        if checkpoint.sha256 == digest {
            checkpoint.serial.saturating_sub(1)
        } else {
            checkpoint.serial
        }
    });
    let card = Card::verify(
        raw,
        &VerifyContext::new(now())
            .expecting(expected)
            .after_serial(floor),
    )
    .map_err(|_| LanError::Card)?;
    if checkpoint
        .is_some_and(|checkpoint| checkpoint.sha256 == digest && checkpoint.serial != card.serial)
    {
        return Err(LanError::Card);
    }
    let checkpoint = CardCheckpoint {
        serial: card.serial,
        sha256: digest,
    };
    Ok((card, checkpoint))
}

pub(super) struct Lease {
    pub active: AtomicBool,
    pub expires_at: u64,
    pub deadline: Instant,
    connections: Mutex<Vec<quinn::Connection>>,
}
impl Lease {
    pub fn new(expires_at: u64, max_lifetime: Duration) -> Arc<Self> {
        Arc::new(Self {
            active: AtomicBool::new(true),
            expires_at,
            deadline: Instant::now()
                + max_lifetime.min(Duration::from_secs(expires_at.saturating_sub(now()))),
            connections: Mutex::new(Vec::new()),
        })
    }
    pub fn valid(&self) -> bool {
        self.active.load(Ordering::Acquire)
            && now() < self.expires_at
            && Instant::now() < self.deadline
    }
    pub fn revoke(&self) {
        self.active.store(false, Ordering::Release);
        for connection in self.connections.lock().expect("LAN lease").drain(..) {
            connection.close(1_u32.into(), b"admission ended");
        }
    }
    pub fn attach(&self, connection: &quinn::Connection, replace: bool) -> Result<(), LanError> {
        let mut connections = self.connections.lock().expect("LAN lease");
        if !self.valid() {
            connection.close(1_u32.into(), b"admission ended");
            return Err(LanError::Admission);
        }
        connections.retain(|connection| connection.close_reason().is_none());
        if replace {
            for previous in connections.drain(..) {
                previous.close(2_u32.into(), b"superseded");
            }
        }
        if connections.len() >= 8 {
            connection.close(1_u32.into(), b"capacity");
            return Err(LanError::Capacity);
        }
        connections.push(connection.clone());
        Ok(())
    }
    pub fn detach(&self, id: usize) {
        self.connections
            .lock()
            .expect("LAN lease")
            .retain(|connection| connection.stable_id() != id);
    }
}

struct Record {
    checkpoint: CardCheckpoint,
    admission: Option<(Card, Arc<Lease>)>,
}
pub(super) struct Book {
    records: Mutex<HashMap<NodeId, Record>>,
    pub generation: AtomicU64,
}
impl Book {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            records: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(0),
        })
    }
    pub fn admit(
        self: &Arc<Self>,
        peer: NodeId,
        raw: &[u8],
        saved: Option<&CardCheckpoint>,
    ) -> Result<LanAdmission, LanError> {
        let mut records = self.records.lock().expect("LAN book");
        if !records.contains_key(&peer) && records.len() >= MAX_ADMITTED_PEERS {
            return Err(LanError::Capacity);
        }
        let current = records.get(&peer).map(|record| &record.checkpoint);
        let floor = match (current, saved) {
            (Some(a), Some(b)) if a.serial == b.serial && a != b => return Err(LanError::Card),
            (Some(a), Some(b)) => Some(if a.serial > b.serial { a } else { b }),
            (a, b) => a.or(b),
        };
        let (card, checkpoint) = verify_card(peer, raw, floor)?;
        let lease = Lease::new(
            card.expires_at,
            Duration::from_secs(link_core::card::MAX_LIFETIME_SECONDS),
        );
        let previous = records
            .insert(
                peer,
                Record {
                    checkpoint: checkpoint.clone(),
                    admission: Some((card.clone(), lease.clone())),
                },
            )
            .and_then(|previous| previous.admission.map(|(_, lease)| lease));
        if let Some(previous) = &previous {
            previous.active.store(false, Ordering::Release);
        }
        self.generation.fetch_add(1, Ordering::AcqRel);
        drop(records);
        if let Some(previous) = previous {
            previous.revoke();
        }
        Ok(LanAdmission {
            peer,
            checkpoint,
            card,
            lease,
            book: self.clone(),
        })
    }
    pub fn get(&self, peer: NodeId) -> Option<Arc<Lease>> {
        self.records
            .lock()
            .expect("LAN book")
            .get(&peer)?
            .admission
            .as_ref()
            .and_then(|(_, lease)| lease.valid().then(|| lease.clone()))
    }
    pub fn revoke_all(&self) {
        let leases = self
            .records
            .lock()
            .expect("LAN book")
            .values_mut()
            .filter_map(|record| record.admission.take().map(|(_, lease)| lease))
            .collect::<Vec<_>>();
        self.generation.fetch_add(1, Ordering::AcqRel);
        for lease in leases {
            lease.revoke();
        }
    }
    pub fn expire(&self) {
        let leases = self
            .records
            .lock()
            .expect("LAN book")
            .values_mut()
            .filter_map(|record| {
                if record
                    .admission
                    .as_ref()
                    .is_some_and(|(_, lease)| !lease.valid())
                {
                    record.admission.take().map(|(_, lease)| lease)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for lease in leases {
            lease.revoke();
        }
    }
}

/// Keep this handle while the peer remains admitted. Replacing or dropping it
/// cancels that admission and its streams; an old handle cannot revoke a new one.
pub struct LanAdmission {
    pub(super) peer: NodeId,
    pub(super) checkpoint: CardCheckpoint,
    pub(super) card: Card,
    pub(super) lease: Arc<Lease>,
    pub(super) book: Arc<Book>,
}
impl LanAdmission {
    pub fn peer(&self) -> NodeId {
        self.peer
    }
    pub fn checkpoint(&self) -> &CardCheckpoint {
        &self.checkpoint
    }
}
impl Drop for LanAdmission {
    fn drop(&mut self) {
        self.lease.revoke();
    }
}
