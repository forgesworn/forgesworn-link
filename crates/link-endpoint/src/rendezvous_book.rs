//! The endpoint's side of tag-mode rendezvous, spec section 9.
//!
//! The shell computes the ECDH x-coordinates from the pair's cards and Nostr
//! keys and hands them over as opaque bytes; the transport never touches
//! Nostr.  From that material the book derives, per relay host, the tags to
//! register (previous, current and next epoch, so clock skew in either
//! direction cannot drop a pair at an epoch boundary), the tag to send with,
//! and the peer an inbound tag belongs to.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use link_core::id::NodeId;
use link_core::rendezvous::{
    PAIRING_SECRET_BYTES, Tag, TagCase, derive_pairing_tag, derive_tag, epoch_index,
};
use rand::RngCore;
use tokio::sync::watch;
use zeroize::Zeroizing;

/// One pair's rendezvous material, as computed by the shell from the current
/// cards.  `eph_x` is 32 zero bytes for `TagCase::None`.
#[derive(Clone, Copy, Debug)]
pub struct RendezvousPeer {
    pub case: TagCase,
    pub static_x: [u8; 32],
    pub eph_x: [u8; 32],
}

/// The registration window: previous, current and next epoch.
const EPOCH_WINDOW: [i64; 3] = [-1, 0, 1];

pub struct TagBook {
    peers: Mutex<HashMap<NodeId, RendezvousPeer>>,
    /// Short-lived first-contact routes.  Their random local route IDs are
    /// never sent on the relay wire and are not authenticated identities.
    pairing: Mutex<HashMap<NodeId, PairingRoute>>,
    /// Bumped on every change, so the relay pump re-registers within its next
    /// refresh tick instead of waiting for the epoch to turn.
    version: AtomicU64,
    /// Every relay driver watches this, so removals (including the last tag)
    /// are registered immediately rather than waiting for the minute tick.
    changes: watch::Sender<u64>,
    /// Send tags by (peer, epoch) for the relay host the session is on, so a
    /// datagram costs a hash lookup rather than an HKDF.  Cleared whenever
    /// the material changes or the session moves to another relay.
    send_cache: Mutex<SendCache>,
}

struct PairingRoute {
    secret: Zeroizing<[u8; PAIRING_SECRET_BYTES]>,
    expires_at: u64,
}

/// A live pairing-tag registration.  Dropping it removes and zeroises Link's
/// copy of the secret.  The product retains its own separately for the
/// end-to-end request proof; this handle never exposes Link's copy.
pub struct PairingRegistration {
    route: NodeId,
    expires_at: u64,
    book: Weak<TagBook>,
}

impl fmt::Debug for PairingRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingRegistration")
            .field("route", &"redacted")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl PairingRegistration {
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn is_active(&self, now_unix: u64) -> bool {
        now_unix < self.expires_at
            && self
                .book
                .upgrade()
                .is_some_and(|book| book.pairing_active(self.route, now_unix))
    }

    pub(crate) fn route(&self) -> NodeId {
        self.route
    }

    pub(crate) fn belongs_to(&self, book: &Arc<TagBook>) -> bool {
        self.book
            .upgrade()
            .is_some_and(|ours| Arc::ptr_eq(&ours, book))
    }
}

impl Drop for PairingRegistration {
    fn drop(&mut self) {
        if let Some(book) = self.book.upgrade() {
            book.remove_pairing(self.route);
        }
    }
}

#[derive(Default)]
struct SendCache {
    host: String,
    tags: HashMap<(NodeId, u64), Tag>,
}

/// Bound on cached send tags: a roster of pairs times a few epochs.  Past it
/// the cache is simply cleared and refilled.
const SEND_CACHE_CAP: usize = 4096;

impl TagBook {
    pub fn new(peers: HashMap<NodeId, RendezvousPeer>) -> Self {
        let (changes, _) = watch::channel(0);
        TagBook {
            peers: Mutex::new(peers),
            pairing: Mutex::new(HashMap::new()),
            version: AtomicU64::new(0),
            changes,
            send_cache: Mutex::new(SendCache::default()),
        }
    }

    fn bump(&self) {
        let version = self.version.fetch_add(1, Ordering::Relaxed) + 1;
        self.changes.send_replace(version);
        self.send_cache.lock().expect("send cache").tags.clear();
    }

    /// Replace one pair's material, e.g. after a card rotation.  The relay
    /// registration follows within a minute; the three-epoch window covers the
    /// seam.
    pub fn upsert(&self, peer: NodeId, material: RendezvousPeer) {
        self.peers.lock().expect("book").insert(peer, material);
        self.bump();
    }

    pub fn remove(&self, peer: NodeId) {
        self.peers.lock().expect("book").remove(&peer);
        self.bump();
    }

    /// Add one short-lived first-contact route.  The returned random node-shaped
    /// value is only a local synthetic routing key; it is never a claimed peer
    /// identity.  The secret is zeroised on removal or expiry.
    pub(crate) fn register_pairing(
        self: &Arc<Self>,
        secret: [u8; PAIRING_SECRET_BYTES],
        expires_at: u64,
    ) -> PairingRegistration {
        let route = loop {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            let candidate = NodeId(bytes);
            let peers = self.peers.lock().expect("book");
            let pairing = self.pairing.lock().expect("pairing book");
            if !peers.contains_key(&candidate) && !pairing.contains_key(&candidate) {
                break candidate;
            }
        };
        self.pairing.lock().expect("pairing book").insert(
            route,
            PairingRoute {
                secret: Zeroizing::new(secret),
                expires_at,
            },
        );
        self.bump();
        PairingRegistration {
            route,
            expires_at,
            book: Arc::downgrade(self),
        }
    }

    pub(crate) fn remove_pairing(&self, route: NodeId) -> bool {
        let removed = self
            .pairing
            .lock()
            .expect("pairing book")
            .remove(&route)
            .is_some();
        if removed {
            self.bump();
        }
        removed
    }

    fn prune_expired(&self, now_unix: u64) {
        let mut pairing = self.pairing.lock().expect("pairing book");
        let before = pairing.len();
        pairing.retain(|_, route| now_unix < route.expires_at);
        let changed = pairing.len() != before;
        drop(pairing);
        if changed {
            self.bump();
        }
    }

    pub(crate) fn pairing_active(&self, route: NodeId, now_unix: u64) -> bool {
        self.prune_expired(now_unix);
        self.pairing
            .lock()
            .expect("pairing book")
            .contains_key(&route)
    }

    #[cfg(test)]
    fn pairing_count(&self, now_unix: u64) -> usize {
        self.prune_expired(now_unix);
        self.pairing.lock().expect("pairing book").len()
    }

    /// How many send tags are cached right now.
    pub fn cache_len(&self) -> usize {
        self.send_cache.lock().expect("send cache").tags.len()
    }

    /// Monotone change counter; the relay pump re-registers when it moves.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Relaxed)
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.lock().expect("book").is_empty()
            && self.pairing.lock().expect("pairing book").is_empty()
    }

    /// Whether this book can derive an outbound rendezvous tag for `peer`.
    /// Callers use this before starting a session so a missing shell-side
    /// pairing cannot become a silent wait for a relay welcome.
    pub fn contains(&self, peer: NodeId) -> bool {
        self.peers.lock().expect("book").contains_key(&peer)
    }

    fn window(&self, now_unix: u64) -> Vec<u64> {
        let current = epoch_index(now_unix);
        EPOCH_WINDOW
            .iter()
            .filter_map(|offset| current.checked_add_signed(*offset))
            .collect()
    }

    /// Every tag this endpoint registers with `relay_host` right now: three
    /// epochs per pair.
    pub fn registration(&self, relay_host: &str, now_unix: u64) -> Vec<Tag> {
        self.prune_expired(now_unix);
        let peers = self.peers.lock().expect("book");
        let epochs = self.window(now_unix);
        let pairing = self.pairing.lock().expect("pairing book");
        let mut tags = Vec::with_capacity((peers.len() + pairing.len()) * epochs.len());
        for material in peers.values() {
            for epoch in &epochs {
                tags.push(derive_tag(
                    material.case,
                    &material.static_x,
                    &material.eph_x,
                    relay_host,
                    *epoch,
                ));
            }
        }
        for route in pairing.values() {
            for epoch in &epochs {
                tags.push(derive_pairing_tag(&route.secret, relay_host, *epoch));
            }
        }
        tags
    }

    /// The current-epoch tag for an outbound datagram to `peer`.  Derived once
    /// per (peer, relay, epoch) and served from the cache after that.
    pub fn tag_for_send(&self, peer: NodeId, relay_host: &str, now_unix: u64) -> Option<Tag> {
        self.prune_expired(now_unix);
        let epoch = epoch_index(now_unix);
        let mut cache = self.send_cache.lock().expect("send cache");
        if cache.host != relay_host {
            // A failover moved the session to another relay: every tag
            // changes with the host, so the cache starts again.
            cache.host = relay_host.to_owned();
            cache.tags.clear();
        }
        if let Some(tag) = cache.tags.get(&(peer, epoch)) {
            return Some(*tag);
        }
        let tag = if let Some(tag) = {
            let pairing = self.pairing.lock().expect("pairing book");
            pairing
                .get(&peer)
                .map(|route| derive_pairing_tag(&route.secret, relay_host, epoch))
        } {
            tag
        } else {
            let peers = self.peers.lock().expect("book");
            let material = peers.get(&peer)?;
            derive_tag(
                material.case,
                &material.static_x,
                &material.eph_x,
                relay_host,
                epoch,
            )
        };
        if cache.tags.len() >= SEND_CACHE_CAP {
            cache.tags.clear();
        }
        cache.tags.insert((peer, epoch), tag);
        Some(tag)
    }

    /// Attribute an inbound tag to its pair, over the same three-epoch window
    /// the registration covers.  `None` for a tag this endpoint never
    /// registered, which the caller drops.
    pub fn resolve(&self, tag: &Tag, relay_host: &str, now_unix: u64) -> Option<NodeId> {
        self.prune_expired(now_unix);
        let peers = self.peers.lock().expect("book");
        let epochs = self.window(now_unix);
        for (peer, material) in peers.iter() {
            for epoch in &epochs {
                let candidate = derive_tag(
                    material.case,
                    &material.static_x,
                    &material.eph_x,
                    relay_host,
                    *epoch,
                );
                if candidate == *tag {
                    return Some(*peer);
                }
            }
        }
        drop(peers);
        let pairing = self.pairing.lock().expect("pairing book");
        for (route_id, route) in pairing.iter() {
            for epoch in &epochs {
                if derive_pairing_tag(&route.secret, relay_host, *epoch) == *tag {
                    return Some(*route_id);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material(byte: u8) -> RendezvousPeer {
        RendezvousPeer {
            case: TagCase::Both,
            static_x: [byte; 32],
            eph_x: [byte.wrapping_add(1); 32],
        }
    }

    fn node(byte: u8) -> NodeId {
        NodeId([byte; 32])
    }

    #[test]
    fn registration_covers_three_epochs_per_pair() {
        let book = TagBook::new(HashMap::from([
            (node(1), material(10)),
            (node(2), material(20)),
        ]));
        let tags = book.registration("relay.example.org", 1_793_588_888);
        assert_eq!(tags.len(), 6);
        let unique: std::collections::HashSet<_> = tags.iter().map(|t| t.0).collect();
        assert_eq!(unique.len(), 6, "all tags distinct");
    }

    #[test]
    fn send_resolve_round_trip_within_the_window() {
        let peer = node(3);
        let book = TagBook::new(HashMap::from([(peer, material(30))]));
        let now = 1_793_588_888;
        let tag = book.tag_for_send(peer, "relay.example.org", now).unwrap();
        assert_eq!(book.resolve(&tag, "relay.example.org", now), Some(peer));
        // A peer's tag from one epoch back still resolves (the skew window)...
        let earlier = book
            .tag_for_send(peer, "relay.example.org", now - 3600)
            .unwrap();
        assert_eq!(book.resolve(&earlier, "relay.example.org", now), Some(peer));
        // ...but an unknown tag does not.
        assert_eq!(book.resolve(&Tag([9; 16]), "relay.example.org", now), None);
        // And the same pair on another relay derives a different tag.
        let elsewhere = book.tag_for_send(peer, "relay2.example.net", now).unwrap();
        assert_ne!(tag, elsewhere);
    }

    /// A send tag is derived once per (peer, relay, epoch) and reused for
    /// every datagram until the material changes.
    #[test]
    fn send_tags_are_cached_until_the_material_changes() {
        let peer = node(4);
        let book = TagBook::new(HashMap::from([(peer, material(40))]));
        let now = 1_793_588_888;
        let first = book.tag_for_send(peer, "relay.example.org", now).unwrap();
        assert_eq!(book.cache_len(), 1);
        assert_eq!(
            book.tag_for_send(peer, "relay.example.org", now + 5)
                .unwrap(),
            first,
            "same epoch, same tag"
        );
        assert_eq!(book.cache_len(), 1, "same epoch, same entry");
        book.upsert(peer, material(41));
        assert_eq!(book.cache_len(), 0, "an upsert clears the cache");
        assert_ne!(
            book.tag_for_send(peer, "relay.example.org", now).unwrap(),
            first,
            "new material, new tag"
        );
    }

    #[test]
    fn contains_tracks_upsert_and_remove() {
        let peer = node(5);
        let book = TagBook::new(HashMap::new());
        assert!(!book.contains(peer));
        book.upsert(peer, material(50));
        assert!(book.contains(peer));
        book.remove(peer);
        assert!(!book.contains(peer));
    }

    #[test]
    fn a_pairing_registration_routes_then_disappears_on_drop() {
        let now = 1_793_588_888;
        let book = Arc::new(TagBook::new(HashMap::new()));
        let registration = book.register_pairing([0x42; PAIRING_SECRET_BYTES], now + 600);
        let route = registration.route();

        assert!(book.pairing_active(route, now));
        assert_eq!(book.pairing_count(now), 1);
        assert_eq!(book.registration("relay.example.org", now).len(), 3);
        let tag = book
            .tag_for_send(route, "relay.example.org", now)
            .expect("pairing route sends");
        assert_eq!(book.resolve(&tag, "relay.example.org", now), Some(route));

        drop(registration);
        assert_eq!(book.pairing_count(now), 0);
        assert!(book.registration("relay.example.org", now).is_empty());
    }

    #[test]
    fn an_expired_pairing_registration_is_pruned() {
        let now = 1_793_588_888;
        let book = Arc::new(TagBook::new(HashMap::new()));
        let registration = book.register_pairing([0x24; PAIRING_SECRET_BYTES], now + 1);
        assert!(registration.is_active(now));
        assert!(!registration.is_active(now + 1));
        assert_eq!(book.pairing_count(now + 1), 0);
    }
}
