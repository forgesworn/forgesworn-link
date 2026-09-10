//! Kotlin's owned boundary to Link: it supplies encrypted persisted route state;
//! Rust owns endpoint, sessions, and WebSocket handles. No Nostr data enters here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use link_core::{Card, NodeId, TransportKey, VerifyContext};
use link_endpoint::{Endpoint, EndpointConfig, RelaySpec, Session};
use link_websocket::{IncomingMessage, Socket};
use thiserror::Error;
use tokio::runtime::Runtime;
use url::Url;
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(uniffi::Record, Clone, Debug)]
pub struct LinkConfig {
    pub transport_seed: Vec<u8>,
    pub relay_urls: Vec<String>,
    pub allow_direct: bool,
    pub routes: Vec<LinkRoute>,
}
#[derive(uniffi::Record, Clone, Debug)]
pub struct LinkRoute {
    pub route_id: String,
    pub card: Vec<u8>,
    pub paired_route_secret: Vec<u8>,
    pub card_serial: u64,
}
#[derive(uniffi::Record, Clone, Debug)]
pub struct LinkPath {
    pub status: String,
    pub relay: Option<String>,
    pub direct: Option<String>,
    pub cause: String,
}

#[derive(uniffi::Error, Error, Debug)]
pub enum LinkError {
    #[error("configuration: {0}")]
    Config(String),
    #[error("route: {0}")]
    Route(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("socket: {0}")]
    Socket(String),
    #[error("the engine is stopped")]
    Stopped,
}

#[uniffi::export(callback_interface)]
pub trait LinkSocketListener: Send + Sync {
    fn on_open(&self);
    fn on_text(&self, text: String);
    fn on_closed(&self, reason: String);
}

struct RouteState {
    node: NodeId,
    serial: u64,
    card: Card,
    session: Option<Arc<Session>>,
}
struct Inner {
    endpoint: Arc<Endpoint>,
    routes: HashMap<String, RouteState>,
    stopped: bool,
}
#[derive(uniffi::Object)]
pub struct LinkEngine {
    runtime: Runtime,
    inner: Mutex<Inner>,
}
#[derive(uniffi::Object)]
pub struct LinkSocket {
    socket: Socket,
    session: Arc<Session>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .unwrap_or(0)
}
fn secret(bytes: &[u8]) -> Result<[u8; 32], LinkError> {
    bytes
        .try_into()
        .map_err(|_| LinkError::Route("paired route secret must be 32 bytes".into()))
}
/// Persisted cards are re-verified at their retained serial, not treated as new arrivals.
fn verify_route(route: &LinkRoute) -> Result<(NodeId, Card), LinkError> {
    if route.route_id.is_empty() {
        return Err(LinkError::Route("route id must not be empty".into()));
    }
    let node = route
        .card
        .get(6..38)
        .and_then(NodeId::from_slice)
        .ok_or_else(|| LinkError::Route("card has no node id".into()))?;
    let previous = route
        .card_serial
        .checked_sub(1)
        .ok_or_else(|| LinkError::Route("card serial must be positive".into()))?;
    let card = Card::verify(
        &route.card,
        &VerifyContext::new(now_unix())
            .expecting(node)
            .after_serial(previous),
    )
    .map_err(|error| LinkError::Route(error.to_string()))?;
    if card.serial != route.card_serial {
        return Err(LinkError::Route(
            "card serial does not match retained serial".into(),
        ));
    }
    Ok((node, card))
}
fn path(session: &Session) -> LinkPath {
    let report = session.path();
    LinkPath {
        status: report.status.outcome(),
        relay: report.relay,
        direct: report.direct.map(|address| address.to_string()),
        cause: report.cause,
    }
}

#[uniffi::export]
impl LinkEngine {
    #[uniffi::constructor]
    pub fn start(config: LinkConfig) -> Result<Arc<Self>, LinkError> {
        let seed: [u8; 32] = config
            .transport_seed
            .as_slice()
            .try_into()
            .map_err(|_| LinkError::Config("transport seed must be 32 bytes".into()))?;
        let mut routes = HashMap::new();
        let mut paired_routes = HashMap::new();
        for route in &config.routes {
            let (node, card) = verify_route(route)?;
            if routes.contains_key(&route.route_id) {
                return Err(LinkError::Config("duplicate route id".into()));
            }
            paired_routes.insert(node, Zeroizing::new(secret(&route.paired_route_secret)?));
            routes.insert(
                route.route_id.clone(),
                RouteState {
                    node,
                    serial: route.card_serial,
                    card,
                    session: None,
                },
            );
        }
        let mut endpoint_config = EndpointConfig::new(TransportKey::from_seed(seed));
        endpoint_config.relays = config.relay_urls.iter().map(RelaySpec::plain).collect();
        endpoint_config.allow_direct = config.allow_direct;
        // Always tag mode, including the empty case: no identity registration on later upsert.
        endpoint_config.paired_routes = Some(paired_routes);
        endpoint_config.net_poll = Duration::ZERO;
        let runtime = Runtime::new().map_err(|error| LinkError::Transport(error.to_string()))?;
        let endpoint = runtime
            .block_on(Endpoint::open(endpoint_config))
            .map_err(|error| LinkError::Transport(error.to_string()))?;
        Ok(Arc::new(Self {
            runtime,
            inner: Mutex::new(Inner {
                endpoint: Arc::new(endpoint),
                routes,
                stopped: false,
            }),
        }))
    }

    pub fn open_socket(
        &self,
        virtual_url: String,
        route_id: String,
        listener: Box<dyn LinkSocketListener>,
    ) -> Result<Arc<LinkSocket>, LinkError> {
        let url = Url::parse(&virtual_url).map_err(|error| LinkError::Socket(error.to_string()))?;
        let session = {
            // Keep the short engine lock through the first dial. This is
            // deliberate: it makes simultaneous opens coalesce before Link's
            // own newest-session-wins rule could supersede the first one.
            let mut inner = self.inner.lock().expect("engine lock");
            if inner.stopped {
                return Err(LinkError::Stopped);
            }
            let route = inner
                .routes
                .get(&route_id)
                .ok_or_else(|| LinkError::Route("route is not installed".into()))?;
            link_websocket::validate_virtual_url(&url, route.node)
                .map_err(|error| LinkError::Socket(error.to_string()))?;
            if let Some(session) = &route.session {
                session.clone()
            } else {
                let card = route.card.clone();
                let endpoint = inner.endpoint.clone();
                let session = Arc::new(
                    self.runtime
                        .block_on(endpoint.connect(&card))
                        .map_err(|error| LinkError::Transport(error.to_string()))?,
                );
                // `route` was only borrowed above and the engine lock means
                // it cannot have been removed or replaced during this dial.
                inner
                    .routes
                    .get_mut(&route_id)
                    .expect("route retained by engine lock")
                    .session = Some(session.clone());
                session
            }
        };
        let (socket, mut incoming) = self
            .runtime
            .block_on(link_websocket::open(&session, url))
            .map_err(|error| LinkError::Socket(error.to_string()))?;
        listener.on_open();
        self.runtime.spawn(async move {
            while let Some(message) = incoming.recv().await {
                match message {
                    IncomingMessage::Text(text) => listener.on_text(text),
                    IncomingMessage::Closed(reason) => {
                        listener.on_closed(reason);
                        return;
                    }
                }
            }
        });
        Ok(Arc::new(LinkSocket { socket, session }))
    }

    pub fn upsert_route(&self, route: LinkRoute) -> Result<(), LinkError> {
        let (node, card) = verify_route(&route)?;
        let route_secret = secret(&route.paired_route_secret)?;
        let previous_session = {
            let mut inner = self.inner.lock().expect("engine lock");
            if inner.stopped {
                return Err(LinkError::Stopped);
            }
            let previous = inner
                .routes
                .get(&route.route_id)
                .map(|existing| {
                    if route.card_serial <= existing.serial {
                        return Err(LinkError::Route("live card serial must increase".into()));
                    }
                    Ok((existing.node, existing.session.clone()))
                })
                .transpose()?;
            if let Some((old_node, _)) = previous.as_ref() {
                inner
                    .endpoint
                    .rendezvous_book()
                    .expect("tag mode")
                    .remove_paired(*old_node);
            }
            inner
                .endpoint
                .rendezvous_book()
                .expect("tag mode")
                .upsert_paired(node, route_secret);
            inner.routes.insert(
                route.route_id,
                RouteState {
                    node,
                    serial: route.card_serial,
                    card,
                    session: None,
                },
            );
            previous.and_then(|(_, session)| session)
        };
        // The cached session is no longer authorised for this route. Its
        // streams observe closure and each reports its terminal callback.
        if let Some(session) = previous_session {
            self.runtime.block_on(session.close(1));
        }
        Ok(())
    }
    pub fn remove_route(&self, route_id: String) -> Result<(), LinkError> {
        let session = {
            let mut inner = self.inner.lock().expect("engine lock");
            if inner.stopped {
                return Err(LinkError::Stopped);
            }
            let route = inner
                .routes
                .remove(&route_id)
                .ok_or_else(|| LinkError::Route("route is not installed".into()))?;
            inner
                .endpoint
                .rendezvous_book()
                .expect("tag mode")
                .remove_paired(route.node);
            route.session
        };
        if let Some(session) = session {
            self.runtime.block_on(session.close(1));
        }
        Ok(())
    }
    pub fn reannounce(&self) -> Result<(), LinkError> {
        let sessions: Vec<_> = {
            let inner = self.inner.lock().expect("engine lock");
            if inner.stopped {
                return Err(LinkError::Stopped);
            }
            inner
                .routes
                .values()
                .filter_map(|route| route.session.clone())
                .collect()
        };
        for session in sessions {
            session.reannounce();
        }
        Ok(())
    }
    pub fn stop(&self) {
        let sessions: Vec<_> = {
            let mut inner = self.inner.lock().expect("engine lock");
            if inner.stopped {
                return;
            }
            inner.stopped = true;
            inner
                .routes
                .values_mut()
                .filter_map(|route| route.session.take())
                .collect()
        };
        for session in sessions {
            self.runtime.block_on(session.close(1));
        }
    }
}
#[uniffi::export]
impl LinkSocket {
    pub fn send_text(&self, text: String) -> Result<(), LinkError> {
        self.socket
            .send_text(text)
            .map_err(|error| LinkError::Socket(error.to_string()))
    }
    pub fn close(&self) -> Result<(), LinkError> {
        self.socket
            .close()
            .map_err(|error| LinkError::Socket(error.to_string()))
    }
    pub fn path(&self) -> LinkPath {
        path(&self.session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_in_tag_mode_with_no_routes() {
        let engine = LinkEngine::start(LinkConfig {
            transport_seed: vec![9; 32],
            relay_urls: Vec::new(),
            allow_direct: false,
            routes: Vec::new(),
        })
        .expect("empty paired route map is a valid tag-mode start");
        engine.stop();
    }

    #[test]
    fn route_secret_is_exactly_32_bytes() {
        assert!(secret(&[0; 31]).is_err());
        assert!(secret(&[0; 32]).is_ok());
    }
}
