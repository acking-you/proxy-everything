//! Proxy-Client: Client-side proxy implementation.
//!
//! This crate provides the client-side proxy functionality, supporting both
//! HTTP/HTTPS and SOCKS5 protocols.

pub mod cli_config;
pub mod client;

// Re-export main types
pub use client::{
    ClientConfig, ClientError, ClientRuntimeConfig, Forwarder, ForwarderProvider, HeaderContext,
    ProxierProviderType, ProxyContext, Result,
};
