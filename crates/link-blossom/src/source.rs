//! The serving side's view of a blob store.
//!
//! A node wires its own store in through [`BlobSource`], so this crate never
//! depends on any one store.  The trait answers a lower-case hex SHA-256 with a
//! size, an optional media type and a bounded byte stream, or with `None` when
//! it holds no such blob.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::StreamExt;
use futures_util::future::BoxFuture;
use futures_util::stream::BoxStream;

use crate::wire::CHUNK;

/// The bytes of one blob, still streaming.
///
/// The body is delivered in bounded pieces and is never buffered whole.  Its
/// items are `io::Result` so a disk-backed source can report a read error part
/// way through; the serving side then stops and the client sees the transfer
/// truncate rather than silently accept short bytes.
pub struct BlobBytes {
    /// The exact length of the blob in bytes.
    pub size: u64,
    /// The media type the store recorded, if any.
    pub content_type: Option<String>,
    /// The blob's bytes, in bounded chunks.
    pub body: BoxStream<'static, io::Result<Bytes>>,
}

impl BlobBytes {
    /// A blob of `size` bytes with the given media type and body stream.
    pub fn new(
        size: u64,
        content_type: Option<String>,
        body: BoxStream<'static, io::Result<Bytes>>,
    ) -> Self {
        Self {
            size,
            content_type,
            body,
        }
    }
}

impl std::fmt::Debug for BlobBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BlobBytes")
            .field("size", &self.size)
            .field("content_type", &self.content_type)
            .finish_non_exhaustive()
    }
}

/// A source of blob bytes, addressed by lower-case hex SHA-256.
///
/// The node implements this over its own store.  The implementation owns
/// nothing but the bytes: it does not see the requesting peer, authorisation or
/// retention, and returning a blob proves only that the store holds it.
pub trait BlobSource: Send + Sync + 'static {
    /// The `(size, content_type, byte stream)` for a lower-case hex SHA-256, or
    /// `None` when the store holds no such blob.
    fn get(&self, sha256: &str) -> BoxFuture<'_, Option<BlobBytes>>;
}

/// Delegation through shared ownership, so a shell holding an
/// `Arc<dyn BlobSource>` hands it to [`serve`](crate::serve) or
/// [`serve_stream`](crate::serve_stream) without a newtype.
impl<T: BlobSource + ?Sized> BlobSource for Arc<T> {
    fn get(&self, sha256: &str) -> BoxFuture<'_, Option<BlobBytes>> {
        (**self).get(sha256)
    }
}

/// An in-memory [`BlobSource`] for tests and examples.
///
/// It holds each blob's bytes whole, which a real store never does, and streams
/// them out in [`CHUNK`] sized pieces so it exercises the same streaming path as
/// a disk-backed source.
#[derive(Default, Clone)]
pub struct MapBlobSource {
    blobs: HashMap<String, (Option<String>, Bytes)>,
}

impl MapBlobSource {
    /// An empty source.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store `data` under its lower-case hex SHA-256.  The caller is trusted to
    /// pass the digest that matches the bytes; this is a test double, not a
    /// store, and does not verify.
    pub fn insert(
        &mut self,
        sha256: impl Into<String>,
        content_type: Option<String>,
        data: impl Into<Bytes>,
    ) {
        self.blobs
            .insert(sha256.into(), (content_type, data.into()));
    }

    /// The builder form of [`insert`](Self::insert).
    pub fn with_blob(
        mut self,
        sha256: impl Into<String>,
        content_type: Option<String>,
        data: impl Into<Bytes>,
    ) -> Self {
        self.insert(sha256, content_type, data);
        self
    }
}

impl BlobSource for MapBlobSource {
    fn get(&self, sha256: &str) -> BoxFuture<'_, Option<BlobBytes>> {
        let entry = self.blobs.get(sha256).cloned();
        Box::pin(async move {
            entry.map(|(content_type, data)| {
                let size = data.len() as u64;
                let body = futures_util::stream::unfold(data, |mut remaining| async move {
                    if remaining.is_empty() {
                        return None;
                    }
                    let take = remaining.len().min(CHUNK);
                    // Bytes::split_to is zero-copy, so this does not clone the blob.
                    let chunk = remaining.split_to(take);
                    Some((Ok::<Bytes, io::Error>(chunk), remaining))
                })
                .boxed();
                BlobBytes {
                    size,
                    content_type,
                    body,
                }
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_arc_dyn_source_serves_through_the_blanket_impl() {
        // The blanket impl is what makes Arc<dyn BlobSource> itself a
        // BlobSource, so a generic caller accepts it without a newtype.
        async fn via_generic<S: BlobSource>(source: &S, sha256: &str) -> Option<BlobBytes> {
            source.get(sha256).await
        }
        let source = MapBlobSource::new().with_blob("aa".repeat(32), None, "bytes");
        let shared: Arc<dyn BlobSource> = Arc::new(source);
        let hit = via_generic(&shared, &"aa".repeat(32)).await;
        assert_eq!(hit.expect("held").size, 5);
        let miss = via_generic(&shared, &"bb".repeat(32)).await;
        assert!(miss.is_none());
    }
}
