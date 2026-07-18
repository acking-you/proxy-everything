//! Unified error types for the proxy system.
//!
//! This module provides a hierarchical error structure that consolidates
//! all error types across the codebase into a single, well-organized enum.
//!
//! # Error Categories
//!
//! - `Io`: General I/O errors with context information
//! - `Crypto`: Encryption/decryption failures
//! - `Protocol`: Wire protocol violations (checksum, header, etc.)
//! - `HttpProxy`: HTTP/HTTPS proxy-specific errors
//! - `SocksProxy`: SOCKS5 proxy-specific errors
//! - `Config`: Configuration and environment errors
//! - `Serde`: JSON serialization/deserialization errors
//! - `AutoProxy`: IP geolocation and auto-proxy decision errors

use snafu::Snafu;

/// Unified error type for the proxy system.
///
/// Provides hierarchical error categorization for better error handling
/// and consistent error reporting across all modules.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum ProxyError {
    // ========== I/O Errors ==========
    /// General I/O error with context information.
    #[snafu(display("IO error [{context}]: {detail}"))]
    Io {
        context: &'static str,
        detail: String,
        source: std::io::Error,
    },

    /// I/O error without source (for simple cases).
    #[snafu(display("IO error [{context}]: {detail}"))]
    IoSimple {
        context: &'static str,
        detail: String,
    },

    // ========== Cryptography Errors ==========
    /// Encryption or decryption failure.
    #[snafu(display("Crypto error: {detail}"))]
    Crypto { detail: String },

    // ========== Protocol Errors ==========
    /// Wire protocol violation (checksum mismatch, invalid header, etc.).
    #[snafu(display("Protocol error: {detail}"))]
    Protocol { detail: String },

    /// Protocol error with I/O source.
    #[snafu(display("Protocol error: {detail}"))]
    ProtocolIo {
        detail: String,
        source: std::io::Error,
    },

    /// Data size exceeds maximum allowed.
    #[snafu(display("Data size {size} exceeds maximum {max}"))]
    MaxSize { size: u32, max: u32 },

    /// Checksum verification failed.
    #[snafu(display("Checksum mismatch for size {size}"))]
    CheckSum { size: u32 },

    // ========== HTTP Proxy Errors ==========
    /// HTTP proxy-specific error.
    #[snafu(display("HTTP proxy error: {detail}"))]
    HttpProxy { detail: String },

    /// Failed to parse host from HTTP request.
    #[snafu(display("HTTP proxy: failed to parse host from URI `{uri}`"))]
    HttpHost { uri: String },

    /// Failed to parse port from HTTP request.
    #[snafu(display("HTTP proxy: failed to parse port from URI `{uri}`"))]
    HttpPort { uri: String },

    /// Failed to parse HTTP method.
    #[snafu(display("HTTP proxy: failed to parse method from URI `{uri}`"))]
    HttpMethod { uri: String },

    /// Failed to parse URI.
    #[snafu(display("HTTP proxy: failed to parse URI"))]
    HttpUri,

    /// Failed to parse HTTP version.
    #[snafu(display("HTTP proxy: failed to parse version from URI `{uri}`"))]
    HttpVersion { uri: String },

    /// Unsupported HTTP method.
    #[snafu(display("HTTP proxy: unsupported method `{method}` for URI `{uri}`"))]
    HttpNotSupported { uri: String, method: String },

    /// Invalid HTTP proxy header.
    #[snafu(display("HTTP proxy: invalid header `{proxy}`"))]
    HttpInvalidProxy { proxy: &'static str },

    // ========== SOCKS Proxy Errors ==========
    /// SOCKS5 proxy-specific error.
    #[snafu(display("SOCKS proxy error: {detail}"))]
    SocksProxy { detail: String },

    /// SOCKS5 first handshake error.
    #[snafu(display("SOCKS5: first handshake error - {detail}"))]
    SocksFirstRequest { detail: &'static str },

    /// Unsupported SOCKS5 operation.
    #[snafu(display("SOCKS5: unsupported operation - {detail}"))]
    SocksNotSupported { detail: &'static str },

    /// Unsupported SOCKS5 address type.
    #[snafu(display("SOCKS5: unsupported address type {atyp:#x} - {detail}"))]
    SocksNotSupportedHost { atyp: u8, detail: &'static str },

    /// Unsupported SOCKS5 transport command.
    #[snafu(display("SOCKS5: unsupported command {cmd:#x} - {detail}"))]
    SocksNotSupportedTransport { cmd: u8, detail: &'static str },

    /// Invalid SOCKS5 proxy header.
    #[snafu(display("SOCKS5: invalid header `{proxy}`"))]
    SocksInvalidProxy { proxy: &'static str },

    // ========== Configuration Errors ==========
    /// Configuration or environment error.
    #[snafu(display("Config error: {detail}"))]
    Config { detail: String },

    // ========== Serialization Errors ==========
    /// JSON serialization/deserialization error.
    #[snafu(display("Serialization error"))]
    Serde { source: serde_json::Error },

    // ========== Auto-Proxy Errors ==========
    /// Failed to connect to ip-api.com.
    #[snafu(display("Auto-proxy: failed to connect to ip-api.com"))]
    AutoProxyConnect { source: std::io::Error },

    /// Failed to write to ip-api.com.
    #[snafu(display("Auto-proxy: failed to write to ip-api.com"))]
    AutoProxyWrite { source: std::io::Error },

    /// Failed to read ip-api.com response.
    #[snafu(display("Auto-proxy: failed to read ip-api.com response"))]
    AutoProxyRead { source: std::io::Error },

    /// ip-api.com returned failure.
    #[snafu(display("Auto-proxy: ip-api.com returned failure - {detail}"))]
    AutoProxyApiFailure { detail: String },

    /// DNS resolution failed.
    #[snafu(display("Auto-proxy: DNS resolution failed for `{host}`"))]
    AutoProxyDns {
        host: String,
        source: std::io::Error,
    },

    /// DNS record is empty.
    #[snafu(display("Auto-proxy: empty DNS record"))]
    AutoProxyEmptyDns,

    /// Home directory not found.
    #[snafu(display("Auto-proxy: home directory not found, set `{var}`"))]
    AutoProxyNoHome { var: &'static str },

    /// Failed to open cache file.
    #[snafu(display("Auto-proxy: failed to open cache file"))]
    AutoProxyOpenFile { source: std::io::Error },

    /// Failed to read cache file.
    #[snafu(display("Auto-proxy: failed to read cache file"))]
    AutoProxyReadFile { source: std::io::Error },

    /// HTTP response parsing error.
    #[snafu(display("Auto-proxy: HTTP response parsing error - {detail}"))]
    AutoProxyHttpParse { detail: &'static str },

    /// Content-Length parsing error.
    #[snafu(display("Auto-proxy: Content-Length parsing error"))]
    AutoProxyContentLength { source: std::num::ParseIntError },

    /// Write-ahead log error.
    #[snafu(display("Auto-proxy: WAL write error"))]
    AutoProxyWal { source: std::io::Error },

    /// UTF-8 conversion error.
    #[snafu(display("Auto-proxy: UTF-8 conversion error"))]
    AutoProxyUtf8 { source: std::string::FromUtf8Error },

    // ========== Client Errors ==========
    /// Failed to send auto-proxy request.
    #[cfg(feature = "auto-proxy")]
    #[snafu(display("Client: failed to send auto-proxy request for `{uri}`"))]
    SendAutoProxy { uri: String },

    /// Failed to receive auto-proxy response.
    #[cfg(feature = "auto-proxy")]
    #[snafu(display("Client: failed to receive auto-proxy response for `{uri}`"))]
    RecvAutoProxy { uri: String },

    /// Cannot proxy localhost.
    #[snafu(display("Client: cannot proxy localhost (127.0.0.1:{port})"))]
    LocalHost { port: u16 },

    /// Signal registration failed.
    #[snafu(display("Client: signal registration failed"))]
    RegisterSignal,

    /// Empty DNS record.
    #[snafu(display("Client: empty DNS record"))]
    EmptyDnsRecord,

    // ========== Server Errors ==========
    /// Header size exceeds maximum.
    #[snafu(display("Server: header size {size} exceeds maximum {max}"))]
    HeaderSize { size: u32, max: u32 },

    /// Decryption failed on server.
    #[snafu(display("Server: decryption failed - {detail}"))]
    ServerDecrypt { detail: String },

    // ========== Codec Errors ==========
    /// Normal codec read error.
    #[snafu(display("Codec: read error"))]
    CodecRead { source: std::io::Error },

    /// Codec decryption error.
    #[snafu(display("Codec: decryption error - {detail}"))]
    CodecDecrypt { detail: String },

    /// Codec encryption error.
    #[snafu(display("Codec: encryption error - {detail}"))]
    CodecEncrypt { detail: String },
}

// ========== Type Aliases for Backward Compatibility ==========

/// Unified Result type alias.
pub type Result<T, E = ProxyError> = std::result::Result<T, E>;

impl ProxyError {
    pub fn is_expected_disconnect(&self) -> bool {
        use std::io::ErrorKind;

        let is_expected = |kind: ErrorKind| {
            matches!(
                kind,
                ErrorKind::UnexpectedEof
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::BrokenPipe
                    | ErrorKind::NotConnected
                    | ErrorKind::TimedOut
            )
        };

        match self {
            ProxyError::Io { source, .. }
            | ProxyError::ProtocolIo { source, .. }
            | ProxyError::CodecRead { source } => is_expected(source.kind()),
            _ => false,
        }
    }
}
