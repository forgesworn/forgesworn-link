//! Transport-independent FSLB framing. Callers own stream finish and lifetime.
use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::wire::{CHUNK, REQUEST_LEN};
#[cfg(feature = "shelter-kit")]
use crate::wire::{MAX_CONTENT_TYPE, STATUS_OK};
use crate::{BlobSource, Request, ResponseHeader, WireError};

pub(crate) async fn serve<T: AsyncRead + AsyncWrite + Unpin, S: BlobSource>(
    stream: &mut T,
    source: &S,
    preread: &[u8],
    max_size: Option<u64>,
    require_request_fin: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        preread.len() <= REQUEST_LEN,
        "preread exceeds fixed request"
    );
    let mut bytes = [0; REQUEST_LEN];
    bytes[..preread.len()].copy_from_slice(preread);
    stream.read_exact(&mut bytes[preread.len()..]).await?;
    if require_request_fin {
        let mut extra = [0];
        anyhow::ensure!(
            stream.read(&mut extra).await? == 0,
            "request has extra bytes"
        );
    }
    let request = match Request::decode(&bytes) {
        Ok(request) => request,
        Err(WireError::BadVersion(_)) => {
            stream
                .write_all(&ResponseHeader::UnsupportedVersion.encode())
                .await?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let Some(blob) = source.get(&hex::encode(request.sha256)).await else {
        stream.write_all(&ResponseHeader::NotFound.encode()).await?;
        return Ok(());
    };
    if max_size.is_some_and(|maximum| blob.size > maximum) {
        stream.write_all(&ResponseHeader::Error.encode()).await?;
        return Ok(());
    }
    stream
        .write_all(
            &ResponseHeader::Ok {
                size: blob.size,
                content_type: blob.content_type,
            }
            .encode(),
        )
        .await?;
    let mut body = blob.body;
    let mut sent = 0_u64;
    while let Some(chunk) = body.next().await {
        for part in chunk?.chunks(CHUNK) {
            sent = sent
                .checked_add(part.len() as u64)
                .ok_or_else(|| anyhow::anyhow!("blob source length overflow"))?;
            anyhow::ensure!(
                sent <= blob.size,
                "blob source exceeded its declared length"
            );
            stream.write_all(part).await?;
        }
    }
    anyhow::ensure!(
        sent == blob.size,
        "blob source was shorter than its declared length"
    );
    Ok(())
}

#[cfg(feature = "shelter-kit")]
pub(crate) async fn read_response<T: AsyncRead + Unpin>(
    stream: &mut T,
) -> std::io::Result<ResponseHeader> {
    fn invalid(error: WireError) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, error)
    }
    let mut status = [0];
    stream.read_exact(&mut status).await?;
    if status[0] != STATUS_OK {
        return ResponseHeader::decode(&status)
            .map(|(header, _)| header)
            .map_err(invalid);
    }
    let mut fixed = [0; 10];
    stream.read_exact(&mut fixed).await?;
    let length = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
    if length > MAX_CONTENT_TYPE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "content type exceeds FSLB limit",
        ));
    }
    let mut header = vec![0; 11 + length];
    header[0] = status[0];
    header[1..11].copy_from_slice(&fixed);
    stream.read_exact(&mut header[11..]).await?;
    ResponseHeader::decode(&header)
        .map(|(header, _)| header)
        .map_err(invalid)
}
