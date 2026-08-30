//! The Blossom blob fetcher over the ForgeSworn Link native lane.
//!
//! [`LinkFetcher`] implements `shelter_kit::BlobFetcher`, so a node registers it
//! as one more transport lane behind the Blossom router's mirror policy.  It
//! answers `fsl://` sources and rejects every other scheme with
//! [`FetchError::UnsupportedSource`], so a node holding several fetchers can
//! dispatch on the scheme.
//!
//! An `fsl` source names a node and a digest:
//!
//! ```text
//!   fsl://<node-id-base32>/<sha256>[.<ext>]
//! ```
//!
//! The node id resolves to a current [`Card`] through a [`CardResolver`] the
//! fetcher holds, the digest is what the request asks the peer for, and the
//! optional extension is ignored.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::StreamExt;
use futures_util::future::BoxFuture;
use futures_util::stream::BoxStream;
use link_core::card::Card;
use link_core::id::NodeId;
use link_endpoint::{Endpoint, PathStatus, Session, Stream};
use shelter_kit::{BlobFetcher, FetchError, FetchPath, FetchRequest, FetchedBlob};
use url::Url;

use crate::wire::{CHUNK, MAX_CONTENT_TYPE, Request, ResponseHeader, STATUS_OK};

/// Resolve a node id to a current address card.
///
/// A node backs this with whatever it already uses to discover cards, a Nostr
/// relay lookup or a local cache; the fetcher does not care where a card comes
/// from, only that it is the current one for that node.
pub trait CardResolver: Send + Sync + 'static {
    /// The current [`Card`] for `node`, or `None` when none is known.
    fn resolve(&self, node: &NodeId) -> BoxFuture<'_, Option<Card>>;
}

/// An in-memory [`CardResolver`] for tests and examples.
#[derive(Default, Clone)]
pub struct MapCardResolver {
    cards: HashMap<NodeId, Card>,
}

impl MapCardResolver {
    /// An empty resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember `card` under its own node id.
    pub fn insert(&mut self, card: Card) {
        self.cards.insert(card.node_id, card);
    }

    /// The builder form of [`insert`](Self::insert).
    pub fn with_card(mut self, card: Card) -> Self {
        self.insert(card);
        self
    }
}

impl CardResolver for MapCardResolver {
    fn resolve(&self, node: &NodeId) -> BoxFuture<'_, Option<Card>> {
        let card = self.cards.get(node).cloned();
        Box::pin(async move { card })
    }
}

/// A blob fetcher that carries bytes over the ForgeSworn Link native lane.
pub struct LinkFetcher {
    endpoint: Arc<Endpoint>,
    resolver: Arc<dyn CardResolver>,
}

impl LinkFetcher {
    /// A fetcher that dials from `endpoint` and resolves node ids with
    /// `resolver`.
    pub fn new(endpoint: Arc<Endpoint>, resolver: Arc<dyn CardResolver>) -> Self {
        Self { endpoint, resolver }
    }
}

impl BlobFetcher for LinkFetcher {
    fn fetch(&self, request: FetchRequest) -> BoxFuture<'_, Result<FetchedBlob, FetchError>> {
        let endpoint = self.endpoint.clone();
        let resolver = self.resolver.clone();
        Box::pin(async move { fetch_over_link(endpoint, resolver, request).await })
    }
}

async fn fetch_over_link(
    endpoint: Arc<Endpoint>,
    resolver: Arc<dyn CardResolver>,
    request: FetchRequest,
) -> Result<FetchedBlob, FetchError> {
    let (node, sha256) = parse_fsl_source(&request.source)?;

    let card = resolver
        .resolve(&node)
        .await
        .ok_or_else(|| FetchError::Unreachable(format!("no card known for node {node}")))?;

    let session = endpoint.connect(&card).await.map_err(|reason| {
        FetchError::Unreachable(format!("link connect to {node} failed: {reason}"))
    })?;

    let mut stream = session
        .open_stream()
        .await
        .map_err(|error| FetchError::Unreachable(format!("link open_stream failed: {error}")))?;

    stream
        .send
        .write_all(&Request::new(sha256).encode())
        .await
        .map_err(|error| FetchError::Unreachable(format!("link request write failed: {error}")))?;
    stream
        .send
        .finish()
        .map_err(|error| FetchError::Unreachable(format!("link request finish failed: {error}")))?;

    let (size, content_type) = match read_response(&mut stream).await? {
        ResponseHeader::Ok { size, content_type } => (size, content_type),
        ResponseHeader::NotFound => return Err(FetchError::UnusableStatus(404)),
        ResponseHeader::Error => return Err(FetchError::UnusableStatus(500)),
    };

    // Report the path the session actually proved, never inferred from the fact
    // the transfer started.  Only a proven direct path is Direct; every other
    // state, including a relay reconnect, is conservatively Relayed.  This lane
    // never uses Tor, HTTPS or loopback, so those are never reported.
    let path = match session.path().status {
        PathStatus::Direct => FetchPath::Direct,
        _ => FetchPath::Relayed,
    };

    let body = link_body(stream, session, size);
    Ok(FetchedBlob {
        path,
        size,
        content_type,
        body,
    })
}

/// Split an `fsl` source into its node id and raw digest.
///
/// A non-`fsl` scheme is [`FetchError::UnsupportedSource`], so a dispatcher can
/// try the next fetcher.  A structurally broken `fsl` source is
/// [`FetchError::Unreachable`]: the scheme is ours, but nothing can be reached.
fn parse_fsl_source(source: &Url) -> Result<(NodeId, [u8; 32]), FetchError> {
    if source.scheme() != "fsl" {
        return Err(FetchError::UnsupportedSource);
    }
    let host = source
        .host_str()
        .ok_or_else(|| FetchError::Unreachable("fsl source carries no node id".into()))?;
    let node = NodeId::from_base32(host).ok_or_else(|| {
        FetchError::Unreachable(format!("fsl source node id is not valid base32: {host}"))
    })?;

    let first = source
        .path()
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or_default();
    let hex_digest = first.split('.').next().unwrap_or_default();
    // Canonical lowercase hex only, so one blob has exactly one fsl text form
    // and a cache or allowlist keyed on the URL cannot be split by case.
    if hex_digest.len() != 64
        || !hex_digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(FetchError::Unreachable(format!(
            "fsl source sha256 is not 64 hex characters: {hex_digest}"
        )));
    }
    let raw = hex::decode(hex_digest).map_err(|error| {
        FetchError::Unreachable(format!("fsl source sha256 is not hex: {error}"))
    })?;
    let sha256: [u8; 32] = raw
        .try_into()
        .map_err(|_| FetchError::Unreachable("fsl source sha256 is not 32 bytes".into()))?;
    Ok((node, sha256))
}

/// Read a response header off the stream.  The content type length is read
/// before its bytes so exactly the right amount is taken, then the whole header
/// is handed to the codec to decode, keeping one parser for both directions.
async fn read_response(stream: &mut Stream) -> Result<ResponseHeader, FetchError> {
    let mut status = [0u8; 1];
    stream
        .recv
        .read_exact(&mut status)
        .await
        .map_err(|error| FetchError::Unreachable(format!("no link response header: {error}")))?;

    if status[0] != STATUS_OK {
        return ResponseHeader::decode(&status)
            .map(|(header, _)| header)
            .map_err(|error| {
                FetchError::Unreachable(format!("bad link response header: {error}"))
            });
    }

    let mut fixed = [0u8; 10];
    stream.recv.read_exact(&mut fixed).await.map_err(|error| {
        FetchError::Unreachable(format!("truncated link response header: {error}"))
    })?;
    let content_len = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
    if content_len > MAX_CONTENT_TYPE {
        return Err(FetchError::Unreachable(format!(
            "content-type length {content_len} exceeds {MAX_CONTENT_TYPE}"
        )));
    }
    let mut content_type = vec![0u8; content_len];
    if content_len > 0 {
        stream
            .recv
            .read_exact(&mut content_type)
            .await
            .map_err(|error| FetchError::Unreachable(format!("truncated content-type: {error}")))?;
    }

    let mut header = Vec::with_capacity(1 + fixed.len() + content_len);
    header.extend_from_slice(&status);
    header.extend_from_slice(&fixed);
    header.extend_from_slice(&content_type);
    ResponseHeader::decode(&header)
        .map(|(header, _)| header)
        .map_err(|error| FetchError::Unreachable(format!("bad link response header: {error}")))
}

/// The blob body as a bounded `Result<Bytes, FetchError>` stream.
///
/// The stream owns the [`Session`] so the underlying connection stays alive
/// while the body is drained, and closes it once the body ends.  It reads
/// exactly `size` bytes: it never yields more, and a short read is surfaced as
/// [`FetchError::Stream`] rather than a silently truncated blob.
fn link_body(
    stream: Stream,
    session: Session,
    size: u64,
) -> BoxStream<'static, Result<Bytes, FetchError>> {
    struct State {
        stream: Stream,
        session: Option<Session>,
        remaining: u64,
        errored: bool,
    }

    let state = State {
        stream,
        session: Some(session),
        remaining: size,
        errored: false,
    };

    futures_util::stream::unfold(state, |mut state| async move {
        if state.errored {
            return None;
        }
        if state.remaining == 0 {
            if let Some(session) = state.session.take() {
                // One blob to one connection, closed once the body is drained,
                // so a repair sweep does not leave connections lingering.
                session.close(0).await;
            }
            return None;
        }
        let want = state.remaining.min(CHUNK as u64) as usize;
        let mut buffer = vec![0u8; want];
        match state.stream.recv.read_exact(&mut buffer).await {
            Ok(()) => {
                state.remaining -= want as u64;
                Some((Ok(Bytes::from(buffer)), state))
            }
            Err(error) => {
                state.errored = true;
                if let Some(session) = state.session.take() {
                    session.close(0).await;
                }
                Some((
                    Err(FetchError::Stream(format!(
                        "link body read failed: {error}"
                    ))),
                    state,
                ))
            }
        }
    })
    .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fsl_url(digest: &str) -> Url {
        let node = NodeId([0u8; 32]).to_base32();
        Url::parse(&format!("fsl://{node}/{digest}")).expect("url")
    }

    #[test]
    fn the_digest_must_be_lowercase_hex() {
        let lower = "a".repeat(64);
        assert!(parse_fsl_source(&fsl_url(&lower)).is_ok());
        let upper = "A".repeat(64);
        assert!(matches!(
            parse_fsl_source(&fsl_url(&upper)),
            Err(FetchError::Unreachable(_))
        ));
    }

    #[test]
    fn a_foreign_scheme_is_unsupported_not_broken() {
        let url = Url::parse("https://example.org/x").expect("url");
        assert!(matches!(
            parse_fsl_source(&url),
            Err(FetchError::UnsupportedSource)
        ));
    }
}
