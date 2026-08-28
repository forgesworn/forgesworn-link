//! ForgeSworn Link, Phase 0 core.
//!
//! Node identity, the `FSL-CARD-1` address card, the relay and probe wire
//! formats, the single TLS identity rule, and the path status types.  Nothing
//! here opens a socket.

pub mod card;
pub mod id;
pub mod path;
pub mod tls;
pub mod wire;

pub use card::{Card, Hint, RuleViolation, VerifyContext};
pub use id::{NodeId, TransportKey};
pub use path::{FailReason, PathReport, PathStatus};
