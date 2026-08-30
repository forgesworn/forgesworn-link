//! The endpoint's side of tag-mode rendezvous, spec section 9.
//!
//! The shell computes the ECDH x-coordinates from the pair's cards and Nostr
//! keys and hands them over as opaque bytes; the transport never touches
//! Nostr.  From that material the book derives, per relay host, the tags to
//! register (previous, current and next epoch, so clock skew in either
//! direction cannot drop a pair at an epoch boundary), the tag to send with,
//! and the peer an inbound tag belongs to.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use link_core::id::NodeId;
use link_core::rendezvous::{Tag, TagCase, derive_tag, epoch_index};

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
    /// Bumped on every change, so the relay pump re-registers within its next
    /// refresh tick instead of waiting for the epoch to turn.
    version: AtomicU64,
    /// Send tags by (peer, epoch) for the relay host the session is on, so a
    /// datagram costs a hash lookup rather than an HKDF.  Cleared whenever
    /// the material changes or the session moves to another relay.
    send_cache: Mutex<SendCache>,
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
        TagBook {
            peers: Mutex::new(peers),
            version: AtomicU64::new(0),
            send_cache: Mutex::new(SendCache::default()),
        }
    }

    /// Replace one pair's material, e.g. after a card rotation.  The relay
    /// registration follows within a minute; the three-epoch window covers the
    /// seam.
    pub fn upsert(&self, peer: NodeId, material: RendezvousPeer) {
        self.peers.lock().expect("book").insert(peer, material);
        self.version.fetch_add(1, Ordering::Relaxed);
        self.send_cache.lock().expect("send cache").tags.clear();
    }

    pub fn remove(&self, peer: NodeId) {
        self.peers.lock().expect("book").remove(&peer);
        self.version.fetch_add(1, Ordering::Relaxed);
        self.send_cache.lock().expect("send cache").tags.clear();
    }

    /// How many send tags are cached right now.
    pub fn cache_len(&self) -> usize {
        self.send_cache.lock().expect("send cache").tags.len()
    }

    /// Monotone change counter; the relay pump re-registers when it moves.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.peers.lock().expect("book").is_empty()
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
        let peers = self.peers.lock().expect("book");
        let epochs = self.window(now_unix);
        let mut tags = Vec::with_capacity(peers.len() * epochs.len());
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
        tags
    }

    /// The current-epoch tag for an outbound datagram to `peer`.  Derived once
    /// per (peer, relay, epoch) and served from the cache after that.
    pub fn tag_for_send(&self, peer: NodeId, relay_host: &str, now_unix: u64) -> Option<Tag> {
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
        let tag = {
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
}
