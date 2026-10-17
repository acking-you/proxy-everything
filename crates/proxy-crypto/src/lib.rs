//! Configuration-free AES-GCM implementations for the existing proxy protocols.
//!
//! `legacy` preserves deployed peer framing/nonce behavior; `v3` owns the
//! authenticated record transport. Neither implements TLS or reads global
//! configuration. Streams are generic over their underlying Tokio I/O.

pub mod legacy;
pub mod v3;
