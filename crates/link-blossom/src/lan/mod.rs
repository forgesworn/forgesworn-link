//! Explicit native LAN FSLB adapter. Provisional sessions cannot use this API.
//! The experimental transport and ordinary FSLB bytes remain separate layers.
use std::{sync::Arc, time::Duration};

use link_endpoint::lan::{LanEndpoint, LanSession, LanStream};
use tokio::{sync::Semaphore, task::JoinSet};

use crate::BlobSource;

#[cfg(feature = "shelter-kit")]
mod client;
#[cfg(feature = "shelter-kit")]
mod store;
#[cfg(feature = "shelter-kit")]
pub use client::{LanFetchPeer, LanFetcher, fetch_blob_over_lan};
#[cfg(feature = "shelter-kit")]
pub use store::ShelterBlobSource;

pub const MAX_SERVING_OPERATIONS: usize = 8;

/// Per-operation limits, including complete framing and body transfer.
#[derive(Clone, Copy, Debug)]
pub struct LanBlobLimits {
    pub(super) max_blob_bytes: u64,
    pub(super) operation_timeout: Duration,
}
#[derive(Debug, thiserror::Error)]
#[error("LAN blob limits require 1 byte to 8 GiB and a nonzero timeout up to one hour")]
pub struct InvalidLanBlobLimits;
impl LanBlobLimits {
    pub fn new(
        max_blob_bytes: u64,
        operation_timeout: Duration,
    ) -> Result<Self, InvalidLanBlobLimits> {
        if !(1..=8 * 1024 * 1024 * 1024).contains(&max_blob_bytes)
            || operation_timeout.is_zero()
            || operation_timeout > Duration::from_secs(3600)
        {
            return Err(InvalidLanBlobLimits);
        }
        Ok(Self {
            max_blob_bytes,
            operation_timeout,
        })
    }
}
impl Default for LanBlobLimits {
    fn default() -> Self {
        Self {
            max_blob_bytes: 1024 * 1024 * 1024,
            operation_timeout: Duration::from_secs(300),
        }
    }
}

/// Serve already admitted peers. At most eight operations run across the
/// endpoint. Cancellation drops the serving tasks; close the endpoint itself
/// when network consent ends. No transport admission grants upload authority.
pub async fn serve_lan<S: BlobSource>(
    endpoint: Arc<LanEndpoint>,
    source: Arc<S>,
    limits: LanBlobLimits,
) -> anyhow::Result<()> {
    let slots = Arc::new(Semaphore::new(MAX_SERVING_OPERATIONS));
    let mut sessions = JoinSet::new();
    loop {
        while sessions.try_join_next().is_some() {}
        tokio::select! {
            incoming = endpoint.accept() => {
                let session = Arc::new(incoming?);
                sessions.spawn(serve_session(session, source.clone(), limits, slots.clone()));
            }
            _ = sessions.join_next(), if !sessions.is_empty() => {},
        }
    }
}

async fn serve_session<S: BlobSource>(
    session: Arc<LanSession>,
    source: Arc<S>,
    limits: LanBlobLimits,
    slots: Arc<Semaphore>,
) {
    let mut requests = JoinSet::new();
    loop {
        while requests.try_join_next().is_some() {}
        tokio::select! {
            incoming = session.accept_stream() => {
                let Ok(stream) = incoming else { break; };
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    session.close();
                    break;
                };
                let source = source.clone();
                let held = session.clone();
                requests.spawn(async move {
                    let _held = held;
                    let _slot = slot;
                    // Errors terminate this stream. Never log a remote address,
                    // key, requested hash, source path or application bytes.
                    let _ = serve_lan_stream(stream, source.as_ref(), &[], limits).await;
                });
            }
            _ = requests.join_next(), if !requests.is_empty() => {},
        }
    }
}

/// One FSLB exchange over an ordinary, held LAN session. The request must end
/// at its exact fixed length before the source is consulted. Callers holding
/// several application protocols may preread up to the fixed 37-byte request.
pub async fn serve_lan_stream<S: BlobSource>(
    mut stream: LanStream,
    source: &S,
    preread: &[u8],
    limits: LanBlobLimits,
) -> anyhow::Result<()> {
    tokio::time::timeout(limits.operation_timeout, async {
        crate::exchange::serve(
            &mut stream,
            source,
            preread,
            Some(limits.max_blob_bytes),
            true,
        )
        .await?;
        stream.finish().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("LAN blob operation deadline"))?
}
