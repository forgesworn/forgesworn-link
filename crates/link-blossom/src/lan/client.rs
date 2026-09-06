use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use futures_util::{StreamExt, future::BoxFuture, stream::BoxStream};
use link_core::id::NodeId;
use link_endpoint::lan::{LanAdmission, LanEndpoint, LanSession, LanStream};
use sha2::{Digest, Sha256};
use shelter_kit::{BlobFetcher, FetchError, FetchPath, FetchRequest, FetchedBlob};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

use super::LanBlobLimits;
use crate::{Request, ResponseHeader, wire::CHUNK};

/// Locally selected peer, existing admission and one literal card destination.
/// This does not resolve a relay offer or create admission on the caller's behalf.
pub struct LanFetchPeer {
    admission: Arc<LanAdmission>,
    target: SocketAddr,
    serial: Arc<Semaphore>,
}
impl LanFetchPeer {
    pub fn new(admission: Arc<LanAdmission>, target: SocketAddr) -> Self {
        Self {
            admission,
            target,
            serial: Arc::new(Semaphore::new(1)),
        }
    }
}

/// Explicit `fsl://` fetcher for a dedicated LAN endpoint. Each fetch opens
/// one session and holds its per-peer slot until the body ends or is dropped.
/// A concurrent fetch to that peer fails without superseding live work.
/// Applications with an existing session use `fetch_blob_over_lan` instead.
pub struct LanFetcher {
    endpoint: Arc<LanEndpoint>,
    peers: HashMap<NodeId, Arc<LanFetchPeer>>,
    limits: LanBlobLimits,
}
impl LanFetcher {
    pub fn new(
        endpoint: Arc<LanEndpoint>,
        peers: Vec<LanFetchPeer>,
        limits: LanBlobLimits,
    ) -> Result<Self, FetchError> {
        if peers.len() > link_endpoint::lan::MAX_ADMITTED_PEERS {
            return Err(unreachable("too many locally configured LAN peers"));
        }
        let mut selected = HashMap::new();
        for peer in peers {
            if selected
                .insert(peer.admission.peer(), Arc::new(peer))
                .is_some()
            {
                return Err(unreachable("duplicate locally configured LAN peer"));
            }
        }
        Ok(Self {
            endpoint,
            peers: selected,
            limits,
        })
    }
}
impl BlobFetcher for LanFetcher {
    fn fetch(&self, request: FetchRequest) -> BoxFuture<'_, Result<FetchedBlob, FetchError>> {
        Box::pin(async move {
            let (node, hash) = selected_source(&request)?;
            check_size(request.expected_size, self.limits)?;
            let peer = self
                .peers
                .get(&node)
                .ok_or_else(|| unreachable("LAN peer is not locally selected"))?
                .clone();
            let permit = peer
                .serial
                .clone()
                .try_acquire_owned()
                .map_err(|_| unreachable("LAN peer already has an active fetch"))?;
            let deadline = Instant::now() + self.limits.operation_timeout;
            let session = tokio::time::timeout_at(
                deadline,
                self.endpoint.connect(&peer.admission, peer.target),
            )
            .await
            .map_err(|_| unreachable("LAN fetch deadline"))?
            .map_err(|_| unreachable("LAN peer connection refused or unavailable"))?;
            let session = Arc::new(session);
            let (stream, size, content_type) =
                open(&session, hash, request.expected_size, self.limits, deadline).await?;
            Ok(FetchedBlob {
                path: FetchPath::Direct,
                size,
                content_type,
                body: body(
                    stream,
                    session,
                    hash,
                    size,
                    deadline,
                    Some(OwnedFetch {
                        _endpoint: self.endpoint.clone(),
                        _peer: peer,
                        _permit: permit,
                    }),
                ),
            })
        })
    }
}

/// Fetch through a session the caller already holds. No new dial or peer
/// supersession occurs. A completed body proves its length, FIN and digest;
/// the caller still owns storage authorisation, quota and durable commit.
pub async fn fetch_blob_over_lan(
    session: &Arc<LanSession>,
    hash: [u8; 32],
    expected_size: Option<u64>,
    limits: LanBlobLimits,
) -> Result<FetchedBlob, FetchError> {
    check_size(expected_size, limits)?;
    let deadline = Instant::now() + limits.operation_timeout;
    let (stream, size, content_type) = open(session, hash, expected_size, limits, deadline).await?;
    Ok(FetchedBlob {
        path: FetchPath::Direct,
        size,
        content_type,
        body: body(stream, session.clone(), hash, size, deadline, None),
    })
}

fn selected_source(request: &FetchRequest) -> Result<(NodeId, [u8; 32]), FetchError> {
    if request.source.scheme() != "fsl" {
        return Err(FetchError::UnsupportedSource);
    }
    let url = &request.source;
    let path = url.path().strip_prefix('/').unwrap_or_default();
    let (digest, extension) = path
        .split_once('.')
        .map_or((path, None), |(hash, ext)| (hash, Some(ext)));
    if url.as_str().len() > 2048
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || path.contains('/')
        || extension.is_some_and(|ext| {
            ext.is_empty() || ext.len() > 16 || !ext.bytes().all(|b| b.is_ascii_alphanumeric())
        })
        || digest != request.sha256
    {
        return Err(unreachable(
            "LAN source is not a canonical hash-addressed peer URL",
        ));
    }
    crate::client::parse_fsl_source(url)
        .map_err(|_| unreachable("invalid LAN source identity or digest"))
}

fn check_size(size: Option<u64>, limits: LanBlobLimits) -> Result<(), FetchError> {
    if size.is_some_and(|size| size > limits.max_blob_bytes) {
        return Err(unreachable("blob exceeds the configured LAN limit"));
    }
    Ok(())
}
fn unreachable(message: &'static str) -> FetchError {
    FetchError::Unreachable(message.into())
}

async fn open(
    session: &LanSession,
    hash: [u8; 32],
    expected: Option<u64>,
    limits: LanBlobLimits,
    deadline: Instant,
) -> Result<(LanStream, u64, Option<String>), FetchError> {
    tokio::time::timeout_at(deadline, async {
        let mut stream = session
            .open_stream()
            .await
            .map_err(|_| unreachable("LAN stream refused"))?;
        stream
            .write_all(&Request::new(hash).encode())
            .await
            .map_err(|_| unreachable("LAN request interrupted"))?;
        stream
            .finish()
            .await
            .map_err(|_| unreachable("LAN request interrupted"))?;
        let response = crate::exchange::read_response(&mut stream)
            .await
            .map_err(|_| unreachable("invalid LAN response header"))?;
        match response {
            ResponseHeader::Ok { size, content_type } => {
                check_size(Some(size), limits)?;
                if expected.is_some_and(|expected| expected != size) {
                    return Err(unreachable("LAN response declared an unexpected size"));
                }
                Ok((stream, size, content_type))
            }
            response => {
                let mut extra = [0];
                if stream
                    .read(&mut extra)
                    .await
                    .map_err(|_| unreachable("LAN status interrupted"))?
                    != 0
                {
                    return Err(unreachable("LAN status contains an unexpected body"));
                }
                Err(FetchError::UnusableStatus(match response {
                    ResponseHeader::NotFound => 404,
                    ResponseHeader::UnsupportedVersion => 505,
                    _ => 500,
                }))
            }
        }
    })
    .await
    .map_err(|_| unreachable("LAN response deadline"))?
}

struct OwnedFetch {
    _endpoint: Arc<LanEndpoint>,
    _peer: Arc<LanFetchPeer>,
    _permit: OwnedSemaphorePermit,
}
fn body(
    stream: LanStream,
    session: Arc<LanSession>,
    hash: [u8; 32],
    size: u64,
    deadline: Instant,
    owned: Option<OwnedFetch>,
) -> BoxStream<'static, Result<Bytes, FetchError>> {
    struct State {
        stream: LanStream,
        _session: Arc<LanSession>,
        _owned: Option<OwnedFetch>,
        remaining: u64,
        expected: [u8; 32],
        hasher: Sha256,
        deadline: Instant,
        failed: bool,
    }
    let state = State {
        stream,
        _session: session,
        _owned: owned,
        remaining: size,
        expected: hash,
        hasher: Sha256::new(),
        deadline,
        failed: false,
    };
    futures_util::stream::unfold(state, |mut state| async move {
        if state.failed {
            return None;
        }
        let result = tokio::time::timeout_at(state.deadline, async {
            if state.remaining == 0 {
                let mut extra = [0];
                if state
                    .stream
                    .read(&mut extra)
                    .await
                    .map_err(|_| "LAN body ended without a clean FIN")?
                    != 0
                {
                    return Err("LAN body exceeded its declared size");
                }
                if <[u8; 32]>::from(state.hasher.clone().finalize()) != state.expected {
                    return Err("LAN body digest did not match its request");
                }
                return Ok(None);
            }
            let mut bytes = vec![0; state.remaining.min(CHUNK as u64) as usize];
            state
                .stream
                .read_exact(&mut bytes)
                .await
                .map_err(|_| "LAN body was truncated or admission ended")?;
            state.hasher.update(&bytes);
            state.remaining -= bytes.len() as u64;
            Ok(Some(Bytes::from(bytes)))
        })
        .await
        .unwrap_or(Err("LAN body operation deadline"));
        match result {
            Ok(None) => None,
            Ok(Some(bytes)) => Some((Ok(bytes), state)),
            Err(message) => {
                state.failed = true;
                Some((Err(FetchError::Stream(message.into())), state))
            }
        }
    })
    .boxed()
}
