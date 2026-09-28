//! The browser relay socket's receive queue.  The page delivers messages
//! whether or not the session keeps up, so the bounds are enforced here,
//! by count and by bytes.  Past them the oldest queued datagram (`Recv` or
//! `RecvTag`) is dropped, which QUIC sees as loss; only when no datagram is
//! queued, so a control frame would be lost, does the queue refuse and the
//! session end.  Target-neutral so the rule is tested natively.

use std::collections::VecDeque;

use link_core::wire::{FRAME_RECV, FRAME_RECV_TAG, MAX_DATAGRAM};

use super::WsMessage;

pub const INBOUND_BOUND: usize = 1024;
pub const INBOUND_BYTES: usize = 2 << 20;
/// No relay message is larger than a routed datagram and its header; one
/// that is, is a protocol violation and ends the session before it is
/// copied.
pub const MAX_MESSAGE_BYTES: u32 = 16 * 1024;
const _: () = assert!(MAX_MESSAGE_BYTES as usize >= 1 + 32 + MAX_DATAGRAM);

#[derive(Default)]
pub struct InboundQueue {
    queue: VecDeque<WsMessage>,
    bytes: usize,
}

impl InboundQueue {
    /// Queue `message`, first dropping the oldest datagrams until it fits.
    /// `false` when it cannot fit without losing a control frame.
    pub fn push(&mut self, message: WsMessage) -> bool {
        let len = message_len(&message);
        while self.queue.len() >= INBOUND_BOUND || self.bytes + len > INBOUND_BYTES {
            let Some(oldest) = self.queue.iter().position(is_datagram) else {
                return false;
            };
            let dropped = self.queue.remove(oldest).expect("position is in range");
            self.bytes -= message_len(&dropped);
        }
        self.bytes += len;
        self.queue.push_back(message);
        true
    }

    pub fn pop(&mut self) -> Option<WsMessage> {
        let message = self.queue.pop_front()?;
        self.bytes -= message_len(&message);
        Some(message)
    }
}

fn message_len(message: &WsMessage) -> usize {
    match message {
        WsMessage::Binary(bytes) => bytes.len(),
        _ => 0,
    }
}

/// A relay delivery of a peer's datagram, whose loss QUIC recovers from.
fn is_datagram(message: &WsMessage) -> bool {
    matches!(message, WsMessage::Binary(bytes)
        if matches!(bytes.first(), Some(&FRAME_RECV) | Some(&FRAME_RECV_TAG)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use link_core::wire::{FRAME_CLOSE, FRAME_PONG};

    fn frame(kind: u8, len: usize) -> WsMessage {
        let mut bytes = vec![0u8; len];
        bytes[0] = kind;
        WsMessage::Binary(bytes)
    }

    fn kind(message: &WsMessage) -> u8 {
        match message {
            WsMessage::Binary(bytes) => bytes[0],
            _ => panic!("binary expected"),
        }
    }

    /// A relay that outruns the session costs it the oldest datagrams, never
    /// a control frame and never the session, while any datagram is left to
    /// drop; with only control frames queued the queue refuses.
    #[test]
    fn overflow_drops_the_oldest_datagram_and_keeps_control_frames() {
        let mut queue = InboundQueue::default();
        assert!(queue.push(frame(FRAME_PONG, 9)));
        for _ in 0..INBOUND_BOUND - 2 {
            assert!(queue.push(frame(FRAME_RECV, 40)));
        }
        assert!(queue.push(frame(FRAME_RECV_TAG, 40)));
        // Full by count: the next arrival displaces the oldest datagram.
        assert!(queue.push(frame(FRAME_CLOSE, 2)));
        assert_eq!(queue.queue.len(), INBOUND_BOUND);
        assert_eq!(kind(&queue.pop().unwrap()), FRAME_PONG, "control kept");
        let mut kinds = Vec::new();
        while let Some(message) = queue.pop() {
            kinds.push(kind(&message));
        }
        assert_eq!(kinds.len(), INBOUND_BOUND - 1);
        assert_eq!(kinds.last(), Some(&FRAME_CLOSE));
        assert_eq!(queue.bytes, 0);

        let mut controls = InboundQueue::default();
        for _ in 0..INBOUND_BOUND {
            assert!(controls.push(frame(FRAME_PONG, 9)));
        }
        assert!(!controls.push(frame(FRAME_RECV, 40)), "no datagram to drop");
    }

    /// The byte budget binds before the count when messages are large.
    #[test]
    fn the_byte_budget_bounds_the_queue() {
        let mut queue = InboundQueue::default();
        let size = MAX_MESSAGE_BYTES as usize;
        for _ in 0..INBOUND_BYTES / size + 10 {
            assert!(queue.push(frame(FRAME_RECV, size)));
        }
        assert!(queue.bytes <= INBOUND_BYTES);
        assert_eq!(queue.queue.len(), INBOUND_BYTES / size);
    }
}
