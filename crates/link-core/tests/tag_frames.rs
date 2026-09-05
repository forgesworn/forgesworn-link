//! Round-trips and bounds for the rendezvous-tag relay frames, spec section 9.
//! Language-neutral frame vectors follow with the relay implementation; these
//! pin the codec until then.

use link_core::rendezvous::Tag;
use link_core::wire::{Frame, MAX_DATAGRAM, MAX_TAGS_PER_REGISTER};

fn tag(byte: u8) -> Tag {
    Tag([byte; 16])
}

#[test]
fn register_round_trips_and_bounds_hold() {
    let frame = Frame::Register {
        tags: vec![tag(1), tag(2), tag(3)],
    };
    assert_eq!(Frame::decode(&frame.encode()), Some(frame));

    let max = Frame::Register {
        tags: (0..MAX_TAGS_PER_REGISTER).map(|i| tag(i as u8)).collect(),
    };
    assert_eq!(Frame::decode(&max.encode()), Some(max));

    // An empty replacement explicitly unregisters every tag after a session
    // is established.  The relay rejects it only as the first frame.
    let empty = Frame::Register { tags: Vec::new() };
    assert_eq!(Frame::decode(&empty.encode()), Some(empty));
    // Over-max tags and a count that disagrees with the body are malformed.
    let over = Frame::Register {
        tags: (0..=MAX_TAGS_PER_REGISTER).map(|i| tag(i as u8)).collect(),
    };
    assert_eq!(Frame::decode(&over.encode()), None);
    let mut lying = Frame::Register { tags: vec![tag(9)] }.encode();
    lying[2] = 2; // claims two tags, carries one
    assert_eq!(Frame::decode(&lying), None);
}

#[test]
fn tag_routed_datagrams_round_trip_and_bound() {
    let frame = Frame::SendTag {
        tag: tag(7),
        datagram: vec![0xAB; MAX_DATAGRAM],
    };
    assert_eq!(Frame::decode(&frame.encode()), Some(frame));

    let recv = Frame::RecvTag {
        tag: tag(8),
        datagram: vec![1],
    };
    assert_eq!(Frame::decode(&recv.encode()), Some(recv));

    // An empty datagram and an oversize one are both malformed.
    let empty = Frame::SendTag {
        tag: tag(7),
        datagram: Vec::new(),
    };
    assert_eq!(Frame::decode(&empty.encode()), None);
    let oversize = Frame::SendTag {
        tag: tag(7),
        datagram: vec![0; MAX_DATAGRAM + 1],
    };
    assert_eq!(Frame::decode(&oversize.encode()), None);
}

#[test]
fn debug_never_prints_tag_bytes() {
    let rendered = format!("{:?}", tag(0x5A));
    assert!(!rendered.contains("5a") && !rendered.contains("90"));
    assert_eq!(rendered, "Tag(redacted)");
}
