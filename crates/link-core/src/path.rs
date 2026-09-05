//! The path status types of spec section 5.

use std::net::SocketAddr;
use std::time::Instant;

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FailReason {
    Relay,
    /// Tag mode has no rendezvous material for the requested peer.  This is
    /// local routing state, not a relay outage or an identity failure.
    Rendezvous,
    Identity,
    Timeout,
    /// A newer session from the same node ID arrived and took over, spec
    /// 4.3: one QUIC connection per peer, newest wins.  This session was
    /// closed so its stale path state cannot sabotage the new one.
    Superseded,
}

impl std::fmt::Display for FailReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailReason::Relay => f.write_str("relay"),
            FailReason::Rendezvous => f.write_str("rendezvous"),
            FailReason::Identity => f.write_str("identity"),
            FailReason::Timeout => f.write_str("timeout"),
            FailReason::Superseded => f.write_str("superseded"),
        }
    }
}

impl std::error::Error for FailReason {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathStatus {
    Idle,
    Rendezvous,
    Relayed,
    Probing,
    Direct,
    Reconnecting,
    Failed(FailReason),
}

impl PathStatus {
    /// The single word an acceptance record carries, spec 7.
    pub fn outcome(&self) -> String {
        match self {
            PathStatus::Idle => "idle".into(),
            PathStatus::Rendezvous => "rendezvous".into(),
            PathStatus::Relayed => "relayed".into(),
            PathStatus::Probing => "probing".into(),
            PathStatus::Direct => "direct".into(),
            PathStatus::Reconnecting => "reconnecting".into(),
            PathStatus::Failed(reason) => format!("failed({reason})"),
        }
    }
}

impl std::fmt::Display for PathStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.outcome())
    }
}

impl Serialize for PathStatus {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.outcome())
    }
}

/// The exact current path.  Never inferred from a successful transfer.
#[derive(Clone, Debug)]
pub struct PathReport {
    pub status: PathStatus,
    pub relay: Option<String>,
    pub direct: Option<SocketAddr>,
    pub since: Instant,
    /// Why the last transition happened.  Every transition is logged with this.
    pub cause: String,
}

impl Serialize for PathReport {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("PathReport", 5)?;
        st.serialize_field("status", &self.status)?;
        st.serialize_field("relay", &self.relay)?;
        st.serialize_field("direct", &self.direct.map(|a| a.to_string()))?;
        st.serialize_field("since_ms", &(self.since.elapsed().as_millis() as u64))?;
        st.serialize_field("cause", &self.cause)?;
        st.end()
    }
}
