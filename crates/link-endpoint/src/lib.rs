//! ForgeSworn Link, Phase 0 endpoint.
//!
//! One QUIC connection per peer over a path socket that moves between a
//! WebSocket relay and a direct UDP address proved with signed probes.

pub mod endpoint;
pub mod netmon;
pub mod path_socket;
pub mod relay_client;
mod relay_tls;
pub mod rendezvous_book;
pub mod session;

pub use endpoint::{
    AcceptedSession, Endpoint, EndpointConfig, MAX_PAIRING_LIFETIME, MAX_PAIRING_SESSION_LIFETIME,
    PairingError, PairingSession,
};
pub use link_core::card::{Card, Hint, VerifyContext};
pub use link_core::id::{NodeId, TransportKey};
pub use link_core::path::{FailReason, PathReport, PathStatus};
pub use link_core::rendezvous::TagCase;
pub use relay_client::{RelaySpec, RelayStatus};
pub use rendezvous_book::{PairingRegistration, RendezvousPeer, TagBook};
pub use session::{Session, Stream};
