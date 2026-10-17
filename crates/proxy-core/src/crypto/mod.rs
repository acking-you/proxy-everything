//! Legacy cryptography configured at the core boundary.
//!
//! Algorithms and nonce state live in `proxy-crypto`, independently of runtime
//! settings. Only this adapter reads the application's configured header key.

pub use proxy_crypto::legacy::*;

pub fn configured_cryption() -> RingResult<Aes256GcmCryption> {
    crate::config::runtime::with_secret_key(|key, _| Aes256GcmCryption::try_new(key))
}
