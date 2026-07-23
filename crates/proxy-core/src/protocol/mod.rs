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

/// Transport carried by a proxy connection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyTransport {
    /// A byte-stream TCP connection.
    #[default]
    Tcp,
    /// A SOCKS5 UDP association whose datagrams are framed over the TCP tunnel.
    UdpAssociate,
}

impl ProxyTransport {
    /// Returns whether this is the original TCP transport.
    ///
    /// TCP is omitted from serialized headers so a current client emits the
    /// same JSON shape as clients released before transport negotiation was
    /// introduced. UDP associations must always carry an explicit value.
    fn is_tcp(&self) -> bool {
        *self == Self::Tcp
    }
}

/// Type alias for data size fields in the wire protocol.
pub type DataSize = u32;

/// Maximum allowed data size (30 MB).
///
/// This limit prevents memory exhaustion from malicious or corrupted
/// length fields. Legitimate proxy traffic should never exceed this.
pub const MAX_DATA_SIZE: DataSize = 30 * 1024 * 1024;

/// Snapshot the checksum key used by one framed connection.
///
/// Long-lived connections must retain this value for their full lifetime.
/// Runtime configuration can change while a connection is active, but the
/// peer continues to use the key that authenticated that connection.
#[inline]
pub(crate) fn current_checksum_key() -> DataSize {
    runtime::with_secret_key(|_, hash| hash)
}

#[inline]
fn get_check_sum_with_key(data: DataSize, checksum_key: DataSize) -> DataSize {
    data ^ checksum_key
}

pub(crate) fn validate_data_size(
    msg_checksum: DataSize,
    msg_len: DataSize,
    checksum_key: DataSize,
) -> Result<DataSize, ProxyError> {
    if get_check_sum_with_key(msg_checksum, checksum_key) != msg_len {
        CheckSumSnafu { size: msg_len }.fail()?;
    }

    if msg_len > MAX_DATA_SIZE {
        MaxSizeSnafu {
            size: msg_len,
            max: MAX_DATA_SIZE,
        }
        .fail()?;
    }

    Ok(msg_len)
}

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
///
/// TCP deliberately keeps the legacy three-field shape. UDP associations add
/// `"transport":"udp_associate"`; readers default a missing value to TCP.
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

    /// Transport mode.
    ///
    /// The two serde attributes form the compatibility contract for the
    /// transport extension:
    ///
    /// - A current server treats a header from a legacy client as TCP when the field is absent.
    /// - A current client omits the default TCP value, preserving the exact legacy header shape
    ///   for older servers.
    #[serde(default, skip_serializing_if = "ProxyTransport::is_tcp")]
    pub transport: ProxyTransport,
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
    get_check_sum_with_key(data, current_checksum_key())
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

    validate_data_size(msg_checksum, msg_len, current_checksum_key())
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
    set_data_size_with_key(writer, data_size, current_checksum_key()).await
}

pub(crate) async fn set_data_size_with_key<T: crate::MyAsyncWriteExt + Unpin>(
    writer: &mut T,
    data_size: DataSize,
    checksum_key: DataSize,
) -> Result<(), ProxyError> {
    writer
        .write_u32(get_check_sum_with_key(data_size, checksum_key))
        .await
        .context(ProtocolIoSnafu {
            detail: "write checksum",
        })?;
    writer.write_u32(data_size).await.context(ProtocolIoSnafu {
        detail: "write length",
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    /// Mirrors the header understood by releases that predate UDP support.
    #[derive(Debug, Deserialize)]
    struct LegacyProxyHeader {
        host: String,
        port: u16,
        key: Option<String>,
    }

    #[test]
    fn legacy_proxy_header_defaults_to_tcp() {
        let header: ProxyHeader =
            serde_json::from_str(r#"{"host":"example.com","port":443,"key":null}"#).unwrap();
        assert_eq!(header.transport, ProxyTransport::Tcp);
    }

    #[test]
    fn current_tcp_header_keeps_legacy_wire_shape() {
        let header = ProxyHeader {
            host: "example.com".to_string(),
            port: 443,
            key: Some(Cow::Borrowed("session-key")),
            transport: ProxyTransport::Tcp,
        };

        let json = serde_json::to_string(&header).unwrap();
        assert_eq!(
            json,
            r#"{"host":"example.com","port":443,"key":"session-key"}"#
        );

        // This deserialize uses the legacy struct rather than ProxyHeader, so
        // the assertion catches accidental additions to the TCP wire shape.
        let legacy: LegacyProxyHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(legacy.host, "example.com");
        assert_eq!(legacy.port, 443);
        assert_eq!(legacy.key.as_deref(), Some("session-key"));
    }

    #[test]
    fn udp_header_serializes_explicit_transport() {
        let header = ProxyHeader {
            host: String::new(),
            port: 0,
            key: None,
            transport: ProxyTransport::UdpAssociate,
        };

        let json = serde_json::to_value(header).unwrap();
        assert_eq!(json["transport"], "udp_associate");
    }
}
