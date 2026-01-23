//! Proxy-Server: Server-side proxy implementation.
//!
//! This crate provides the server-side proxy functionality, receiving
//! encrypted connections from clients and forwarding traffic to destinations.

pub mod server;

// Re-export main types
pub use server::{RelayManager, ServerConfig, ServerError, run_server_with_listener, start_server};
