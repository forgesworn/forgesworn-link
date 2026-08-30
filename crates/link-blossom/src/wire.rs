//! The FSL-BLOSSOM request and response wire format.
//!
//! One request and one response travel over a single bidirectional Link stream.
//! Every multi-byte integer is big-endian.  The codec is deliberately tiny: it
//! frames a hash-addressed request and a header, and the blob body then follows
//! the header as raw bytes on the same stream.
//!
//! Request, fixed 37 bytes:
//!
//! ```text
//!   offset  size  field
//!   0       4     magic, ASCII "FSLB"
//!   4       1     version, 0x01
//!   5       32    sha256, raw bytes (not hex)
//! ```
//!
//! Response header:
//!
//! ```text
//!   offset  size  field
//!   0       1     status: 0x00 ok, 0x01 not found, 0x02 error
//! ```
//!
//! For `not found` and `error` the header is the single status byte and no body
//! follows.  For `ok` the status byte is followed by:
//!
//! ```text
//!   1       8     size, u64, the exact body length in bytes
//!   9       2     content_type length, u16, at most 255
//!   11      N     content_type, UTF-8, N as above (absent when N is 0)
//! ```
//!
//! and then exactly `size` bytes of body follow on the stream.  The reader
//! enforces the exact declared length: it never delivers more than `size` bytes
//! and treats a short stream as truncation.  It does not re-hash; the Blossom
//! router re-hashes every byte it accepts.

use thiserror::Error;

/// Request magic, ASCII `FSLB`.
pub const REQUEST_MAGIC: [u8; 4] = *b"FSLB";
/// The one protocol version this codec speaks.
pub const PROTOCOL_VERSION: u8 = 0x01;
/// A request is always this many bytes: 4 magic, 1 version, 32 digest.
pub const REQUEST_LEN: usize = 37;
/// A content type is bounded so a header can never grow without limit.
pub const MAX_CONTENT_TYPE: usize = 255;
/// The blob was found and its bytes follow the header.
pub const STATUS_OK: u8 = 0x00;
/// The server holds no blob under the requested digest.
pub const STATUS_NOT_FOUND: u8 = 0x01;
/// The server could not serve the blob for some other reason.
pub const STATUS_ERROR: u8 = 0x02;
/// Bodies move in pieces no larger than this, so neither side buffers a whole
/// blob in memory.
pub const CHUNK: usize = 64 * 1024;

/// Why a frame could not be decoded.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    /// The buffer ended before a full frame was present.
    #[error("buffer too short: needed {needed} bytes, had {had}")]
    Short {
        /// The number of bytes the frame required.
        needed: usize,
        /// The number of bytes actually present.
        had: usize,
    },
    /// The request magic was not `FSLB`.
    #[error("request magic is not FSLB")]
    BadMagic,
    /// The version byte named a protocol this codec does not speak.
    #[error("unsupported protocol version {0:#04x}")]
    BadVersion(u8),
    /// The response status byte was not one of the three defined values.
    #[error("unknown response status byte {0:#04x}")]
    BadStatus(u8),
    /// The declared content type ran past the 255 byte bound.
    #[error("content-type length {0} exceeds 255 bytes")]
    ContentTypeTooLong(u16),
    /// The content type bytes were not valid UTF-8.
    #[error("content-type is not valid utf-8")]
    BadContentType,
}

/// A hash-addressed request for one blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    /// The raw 32 byte SHA-256 of the wanted blob.
    pub sha256: [u8; 32],
}

impl Request {
    /// A request for the blob with this raw digest.
    pub fn new(sha256: [u8; 32]) -> Self {
        Self { sha256 }
    }

    /// Encode the request to its exact wire bytes.
    pub fn encode(&self) -> [u8; REQUEST_LEN] {
        let mut out = [0u8; REQUEST_LEN];
        out[..4].copy_from_slice(&REQUEST_MAGIC);
        out[4] = PROTOCOL_VERSION;
        out[5..REQUEST_LEN].copy_from_slice(&self.sha256);
        out
    }

    /// Decode a request from the front of `bytes`, rejecting a short buffer, the
    /// wrong magic or an unknown version.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < REQUEST_LEN {
            return Err(WireError::Short {
                needed: REQUEST_LEN,
                had: bytes.len(),
            });
        }
        if bytes[..4] != REQUEST_MAGIC {
            return Err(WireError::BadMagic);
        }
        if bytes[4] != PROTOCOL_VERSION {
            return Err(WireError::BadVersion(bytes[4]));
        }
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&bytes[5..REQUEST_LEN]);
        Ok(Self { sha256 })
    }
}

/// The header that opens a response.  The body, when there is one, follows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseHeader {
    /// The blob was found; `size` bytes of body follow the header.
    Ok {
        /// The exact length of the body in bytes.
        size: u64,
        /// The media type the server declared, if any.
        content_type: Option<String>,
    },
    /// No blob is held under the requested digest.
    NotFound,
    /// The blob could not be served for some other reason.
    Error,
}

impl ResponseHeader {
    /// Encode the header to its exact wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            ResponseHeader::Ok { size, content_type } => {
                // A media type longer than the bound is dropped whole rather
                // than truncated: a byte-boundary cut can split a UTF-8
                // character, and the peer would then reject the entire header.
                let content_type = content_type
                    .as_deref()
                    .filter(|text| text.len() <= MAX_CONTENT_TYPE)
                    .unwrap_or("")
                    .as_bytes();
                let content_len = content_type.len();
                let mut out = Vec::with_capacity(1 + 8 + 2 + content_len);
                out.push(STATUS_OK);
                out.extend_from_slice(&size.to_be_bytes());
                out.extend_from_slice(&(content_len as u16).to_be_bytes());
                out.extend_from_slice(&content_type[..content_len]);
                out
            }
            ResponseHeader::NotFound => vec![STATUS_NOT_FOUND],
            ResponseHeader::Error => vec![STATUS_ERROR],
        }
    }

    /// Decode a header from the front of `bytes`, returning the header and the
    /// number of bytes it occupied.  The body, when the status is ok, begins at
    /// that offset.  A buffer that stops mid-header is rejected rather than
    /// guessed.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), WireError> {
        let &status = bytes
            .first()
            .ok_or(WireError::Short { needed: 1, had: 0 })?;
        match status {
            STATUS_OK => {
                const FIXED: usize = 1 + 8 + 2;
                if bytes.len() < FIXED {
                    return Err(WireError::Short {
                        needed: FIXED,
                        had: bytes.len(),
                    });
                }
                let size = u64::from_be_bytes(bytes[1..9].try_into().expect("eight bytes"));
                let content_len = u16::from_be_bytes([bytes[9], bytes[10]]);
                if content_len as usize > MAX_CONTENT_TYPE {
                    return Err(WireError::ContentTypeTooLong(content_len));
                }
                let end = FIXED + content_len as usize;
                if bytes.len() < end {
                    return Err(WireError::Short {
                        needed: end,
                        had: bytes.len(),
                    });
                }
                let content_type = if content_len == 0 {
                    None
                } else {
                    let text = std::str::from_utf8(&bytes[FIXED..end])
                        .map_err(|_| WireError::BadContentType)?;
                    Some(text.to_owned())
                };
                Ok((ResponseHeader::Ok { size, content_type }, end))
            }
            STATUS_NOT_FOUND => Ok((ResponseHeader::NotFound, 1)),
            STATUS_ERROR => Ok((ResponseHeader::Error, 1)),
            other => Err(WireError::BadStatus(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_encodes_and_decodes_to_the_same_value() {
        let request = Request::new([7u8; 32]);
        let bytes = request.encode();
        assert_eq!(bytes.len(), REQUEST_LEN);
        assert_eq!(&bytes[..4], b"FSLB");
        assert_eq!(bytes[4], PROTOCOL_VERSION);
        assert_eq!(Request::decode(&bytes).expect("decodes"), request);
    }

    #[test]
    fn a_truncated_request_is_rejected() {
        let bytes = Request::new([9u8; 32]).encode();
        let error = Request::decode(&bytes[..REQUEST_LEN - 1]).expect_err("short");
        assert_eq!(
            error,
            WireError::Short {
                needed: REQUEST_LEN,
                had: REQUEST_LEN - 1
            }
        );
    }

    #[test]
    fn a_request_with_bad_magic_or_version_is_rejected() {
        let mut bytes = Request::new([1u8; 32]).encode();
        bytes[0] = b'X';
        assert_eq!(Request::decode(&bytes), Err(WireError::BadMagic));

        let mut bytes = Request::new([1u8; 32]).encode();
        bytes[4] = 0x02;
        assert_eq!(Request::decode(&bytes), Err(WireError::BadVersion(0x02)));
    }

    #[test]
    fn an_ok_response_header_round_trips_with_and_without_a_content_type() {
        for content_type in [None, Some("application/octet-stream".to_owned())] {
            let header = ResponseHeader::Ok {
                size: 5 * 1024 * 1024,
                content_type: content_type.clone(),
            };
            let bytes = header.encode();
            let (decoded, consumed) = ResponseHeader::decode(&bytes).expect("decodes");
            assert_eq!(
                consumed,
                bytes.len(),
                "the header consumed its whole buffer"
            );
            assert_eq!(decoded, header);
        }
    }

    #[test]
    fn not_found_and_error_headers_round_trip() {
        for header in [ResponseHeader::NotFound, ResponseHeader::Error] {
            let bytes = header.encode();
            assert_eq!(bytes.len(), 1);
            let (decoded, consumed) = ResponseHeader::decode(&bytes).expect("decodes");
            assert_eq!((decoded, consumed), (header, 1));
        }
    }

    #[test]
    fn a_truncated_ok_header_is_rejected() {
        let bytes = ResponseHeader::Ok {
            size: 42,
            content_type: Some("text/plain".to_owned()),
        }
        .encode();
        // Cut the buffer inside the declared content type.
        let error = ResponseHeader::decode(&bytes[..bytes.len() - 1]).expect_err("short");
        assert!(matches!(error, WireError::Short { .. }), "got {error:?}");
    }

    #[test]
    fn an_unknown_status_byte_is_rejected() {
        assert_eq!(
            ResponseHeader::decode(&[0x09]),
            Err(WireError::BadStatus(0x09))
        );
        assert_eq!(
            ResponseHeader::decode(&[]),
            Err(WireError::Short { needed: 1, had: 0 })
        );
    }

    #[test]
    fn an_over_long_content_type_is_omitted_not_truncated() {
        let header = ResponseHeader::Ok {
            size: 1,
            content_type: Some("x".repeat(MAX_CONTENT_TYPE + 45)),
        };
        let (decoded, _) = ResponseHeader::decode(&header.encode()).expect("decodes");
        assert_eq!(
            decoded,
            ResponseHeader::Ok {
                size: 1,
                content_type: None
            }
        );
    }
}
