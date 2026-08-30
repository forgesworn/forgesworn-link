//! The serving side of the Blossom lane.
//!
//! [`serve`] accepts inbound Link sessions in a loop and, for each application
//! stream a peer opens, reads one hash-addressed request and streams the blob
//! back.  It holds no store of its own: the node passes a [`BlobSource`] in.

use std::sync::Arc;

use futures_util::StreamExt;
use link_core::path::FailReason;
use link_endpoint::{Endpoint, Session, Stream};
use tracing::{debug, warn};

use crate::source::{BlobBytes, BlobSource};
use crate::wire::{CHUNK, REQUEST_LEN, Request, ResponseHeader, WireError};

/// Accept sessions on `endpoint` and answer blob requests from `source`.
///
/// One task is spawned per session and one per inbound stream, so a slow or
/// stuck transfer never blocks another peer.  The loop tolerates a peer that
/// fails the identity check and carries on; it returns only when the endpoint
/// itself can no longer accept, which a caller treats as the endpoint closing.
pub async fn serve<S>(endpoint: Arc<Endpoint>, source: Arc<S>) -> anyhow::Result<()>
where
    S: BlobSource,
{
    loop {
        match endpoint.accept().await {
            Ok(session) => {
                let session = Arc::new(session);
                let source = source.clone();
                tokio::spawn(serve_session(session, source));
            }
            Err(FailReason::Identity) => {
                warn!("link-blossom rejected an inbound session on identity, still serving");
            }
            Err(reason) => {
                warn!(%reason, "link-blossom accept loop stopping");
                return Err(anyhow::anyhow!("link-blossom accept failed: {reason}"));
            }
        }
    }
}

/// Answer every application stream a single session opens until it closes.
async fn serve_session<S: BlobSource>(session: Arc<Session>, source: Arc<S>) {
    debug!(peer = %session.peer(), "link-blossom session accepted");
    // The loop ends when accept_stream errors, which is the session closing or
    // the peer opening no more streams.
    while let Ok(stream) = session.accept_stream().await {
        let source = source.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_stream(stream, source.as_ref(), &[]).await {
                debug!(%error, "link-blossom stream ended with an error");
            }
        });
    }
}

/// Answer one already-accepted stream as FSLB.
///
/// An endpoint that serves several protocols beside FSLB runs its own accept
/// loop, demultiplexes each stream on whatever prefix it read (for FSLB, the
/// four magic bytes), and hands the stream here with that prefix as `preread`;
/// a caller that consumed nothing passes an empty slice.  At most the fixed
/// 37-byte request may be preread.
pub async fn serve_stream<S: BlobSource>(
    mut stream: Stream,
    source: &S,
    preread: &[u8],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        preread.len() <= REQUEST_LEN,
        "preread longer than the fixed request"
    );
    let mut request = [0u8; REQUEST_LEN];
    request[..preread.len()].copy_from_slice(preread);
    stream
        .recv
        .read_exact(&mut request[preread.len()..])
        .await?;
    let request = match Request::decode(&request) {
        Ok(request) => request,
        Err(WireError::BadVersion(version)) => {
            // A future-version request gets a defined answer on the wire, not a
            // silent stream reset, so a newer peer can tell "too new" from
            // "broken".  Bad magic stays a reset: that is garbage, not a version.
            stream
                .send
                .write_all(&ResponseHeader::UnsupportedVersion.encode())
                .await?;
            stream.send.finish()?;
            debug!(
                version,
                "link-blossom refused an unsupported request version"
            );
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let sha256 = hex::encode(request.sha256);

    match source.get(&sha256).await {
        Some(blob) => send_blob(&mut stream, blob).await,
        None => {
            stream
                .send
                .write_all(&ResponseHeader::NotFound.encode())
                .await?;
            stream.send.finish()?;
            Ok(())
        }
    }
}

/// Write the ok header then stream the body in bounded pieces, enforcing the
/// exact declared length.  If the body errors or does not deliver exactly `size`
/// bytes the send stream is dropped without a clean finish, which resets it so
/// the client sees a truncated transfer rather than a silent short blob.
async fn send_blob(stream: &mut Stream, blob: BlobBytes) -> anyhow::Result<()> {
    let size = blob.size;
    let header = ResponseHeader::Ok {
        size,
        content_type: blob.content_type,
    };
    stream.send.write_all(&header.encode()).await?;

    let mut body = blob.body;
    let mut sent: u64 = 0;
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        for part in chunk.chunks(CHUNK) {
            sent += part.len() as u64;
            if sent > size {
                anyhow::bail!("blob source produced more than the declared {size} bytes");
            }
            stream.send.write_all(part).await?;
        }
    }
    anyhow::ensure!(
        sent == size,
        "blob source produced {sent} of the declared {size} bytes"
    );
    stream.send.finish()?;
    Ok(())
}
