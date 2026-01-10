//! Wire protocol definitions for the proxy system.
//!
//! This module defines the data framing protocol used for communication
//! between client and server, including the `ProxyHeader` structure and
//! length-prefixed message framing.
//!
//! # Wire Protocol Format
//!
//! All messages are framed with a length prefix and checksum:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        Message Frame                                │
//! ├──────────────┬──────────────┬─────────────────────┬────────────────┤
//! │  Checksum    │   Length     │   Encrypted Data    │   Auth Tag     │
//! │  (4 bytes)   │  (4 bytes)   │    (N bytes)        │  (16 bytes)    │
//! └──────────────┴──────────────┴─────────────────────┴────────────────┘
//!
//! Checksum = Length XOR KEY_HASH
//! ```
//!
//! # Checksum Verification
//!
//! The checksum provides a simple integrity check to detect corrupted
//! or malicious length fields. It's computed by XORing the length with
//! a secret hash value derived from the encryption key.
//!
//! # Maximum Data Size
//!
//! Messages are limited to 30MB (`MAX_DATA_SIZE`) to prevent memory
//! exhaustion attacks and ensure reasonable resource usage.

use std::borrow::Cow;
use std::fmt::Display;

use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::config::runtime;
use crate::error::{CheckSumSnafu, MaxSizeSnafu, ProtocolIoSnafu, ProxyError};

/// Type alias for data size fields in the wire protocol.
pub type DataSize = u32;

/// Maximum allowed data size (30 MB).
///
/// This limit prevents memory exhaustion from malicious or corrupted
/// length fields. Legitimate proxy traffic should never exceed this.
pub const MAX_DATA_SIZE: DataSize = 30 * 1024 * 1024;

/// Proxy connection header.
///
/// Contains the destination address and optional encryption key for
/// establishing a proxied connection.
///
/// # Wire Format
///
/// Serialized as JSON, then encrypted with AES-256-GCM:
///
/// ```json
/// {
///   "host": "example.com",
///   "port": 443,
///   "key": "optional-session-key"
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyHeader {
    /// Destination hostname or IP address.
    pub host: String,

    /// Destination port number.
    pub port: u16,

    /// Optional per-session encryption key.
    ///
    /// When present, enables additional encryption layer for the
    /// data stream (beyond the header encryption).
    pub key: Option<Cow<'static, str>>,
}

impl Display for ProxyHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Computes the checksum for a data size value.
///
/// The checksum is a simple XOR with the key hash, providing basic
/// integrity verification for the length field.
///
/// # Security Note
///
/// This is NOT a cryptographic checksum. It only provides detection
/// of accidental corruption, not protection against active attacks.
/// The actual data integrity is ensured by AES-GCM authentication.
#[inline]
pub fn get_check_sum(data: DataSize) -> DataSize {
    data ^ runtime::default_key_hash()
}

/// Reads and validates the data size from a framed message.
///
/// # Protocol
///
/// 1. Read 4-byte checksum (big-endian u32)
/// 2. Read 4-byte length (big-endian u32)
/// 3. Verify: checksum XOR key_hash == length
/// 4. Verify: length <= MAX_DATA_SIZE
///
/// # Errors
///
/// - `CheckSum`: Checksum verification failed
/// - `MaxSize`: Length exceeds maximum allowed
/// - `ProtocolIo`: I/O error during read
pub async fn get_data_size<T: crate::MyAsyncReadExt + Unpin>(
    reader: &mut T,
) -> Result<DataSize, ProxyError> {
    let msg_checksum = reader.read_u32().await.context(ProtocolIoSnafu {
        detail: "read checksum",
    })?;
    let msg_len = reader.read_u32().await.context(ProtocolIoSnafu {
        detail: "read length",
    })?;

    // Verify checksum
    if get_check_sum(msg_checksum) != msg_len {
        CheckSumSnafu { size: msg_len }.fail()?;
    }

    // Verify size limit
    if msg_len > MAX_DATA_SIZE {
        MaxSizeSnafu {
            size: msg_len,
            max: MAX_DATA_SIZE,
        }
        .fail()?;
    }

    Ok(msg_len)
}

/// Writes the data size with checksum to a framed message.
///
/// # Protocol
///
/// 1. Write 4-byte checksum (length XOR key_hash, big-endian)
/// 2. Write 4-byte length (big-endian)
///
/// # Errors
///
/// - `ProtocolIo`: I/O error during write
pub async fn set_data_size<T: crate::MyAsyncWriteExt + Unpin>(
    writer: &mut T,
    data_size: DataSize,
) -> Result<(), ProxyError> {
    writer
        .write_u32(get_check_sum(data_size))
        .await
        .context(ProtocolIoSnafu {
            detail: "write checksum",
        })?;
    writer.write_u32(data_size).await.context(ProtocolIoSnafu {
        detail: "write length",
    })?;
    Ok(())
}
