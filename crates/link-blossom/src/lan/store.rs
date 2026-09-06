use std::{
    fs::File,
    io::{self, Read},
    sync::Arc,
};

use bytes::Bytes;
use futures_util::{StreamExt, future::BoxFuture};
use shelter_kit::Store;
use tokio::sync::Semaphore;

use crate::{BlobBytes, BlobSource, wire::CHUNK};

/// Read-only adapter for the existing private store. It never creates a
/// claim, writes a blob, updates verification time or grants retention.
pub struct ShelterBlobSource {
    store: Store,
    slots: Arc<Semaphore>,
}
impl ShelterBlobSource {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            slots: Arc::new(Semaphore::new(super::MAX_SERVING_OPERATIONS)),
        }
    }
}
impl BlobSource for ShelterBlobSource {
    fn get(&self, hash: &str) -> BoxFuture<'_, Option<BlobBytes>> {
        let store = self.store.clone();
        let hash = hash.to_owned();
        let permit = self.slots.clone().try_acquire_owned();
        Box::pin(async move {
            let permit = permit.ok()?;
            // Blocking filesystem/database work owns the slot even when its
            // async caller is cancelled. No file-sized buffer is allocated.
            let (metadata, file, permit) = tokio::task::spawn_blocking(move || {
                let metadata = store.get(&hash).ok()??;
                let file = File::open(store.blob_path(&hash)).ok()?;
                let stat = file.metadata().ok()?;
                if !stat.is_file() || stat.len() != metadata.size {
                    return None;
                }
                Some((metadata, file, permit))
            })
            .await
            .ok()??;
            let body = futures_util::stream::unfold(Some((file, permit)), |state| async move {
                let (mut file, permit) = state?;
                match tokio::task::spawn_blocking(move || {
                    let mut bytes = vec![0; CHUNK];
                    let read = file.read(&mut bytes);
                    (read, bytes, file, permit)
                })
                .await
                {
                    Ok((Ok(0), _, _, _)) => None,
                    Ok((Ok(read), mut bytes, file, permit)) => {
                        bytes.truncate(read);
                        Some((Ok(Bytes::from(bytes)), Some((file, permit))))
                    }
                    _ => Some((Err(io::Error::other("local blob read failed")), None)),
                }
            })
            .boxed();
            Some(BlobBytes::new(
                metadata.size,
                Some(metadata.content_type),
                body,
            ))
        })
    }
}
