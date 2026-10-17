//! Cryptographic primitives for the proxy system.
//!
//! This module provides AES-256-GCM encryption and decryption capabilities
//! for securing proxy traffic between client and server.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Encryption Flow                               │
//! │                                                                  │
//! │  Plaintext ──► Aes256GcmEncryptor ──► Ciphertext + Auth Tag     │
//! │                      │                                           │
//! │                      ▼                                           │
//! │              CounterNonceSequence                                │
//! │              (generates unique nonce)                            │
//! │                                                                  │
//! │  Ciphertext + Tag ──► Aes256GcmDecryptor ──► Plaintext          │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Security Considerations
//!
//! - **Legacy nonce scope**: The counter is unique only within one encryptor instance. Creating
//!   another instance with the same key repeats its nonce sequence. Independent
//!   connection/direction counters do not provide global nonce uniqueness. The legacy header and
//!   bidirectional stream format require a versioned protocol migration; see
//!   `docs/network-resilience.md` for the remaining security boundary.
//! - **Exhaustion**: A counter reaching its limit fails rather than wrapping.
//!
//! - **Key requirements**: The encryption key must be exactly 32 bytes (256 bits) for AES-256-GCM.
//!
//! # Example
//!
//! ```ignore
//! let mut crypto = Aes256GcmCryption::try_new(key)?;
//!
//! // Encrypt data in-place
//! let tag = crypto.encrypt(&mut data)?;
//!
//! // Decrypt data with tag appended
//! let plaintext = crypto.decrypt_with_tag(&mut ciphertext_with_tag)?;
//! ```

use ring::aead::{
    AES_256_GCM, Aad, BoundKey, NONCE_LEN, Nonce, NonceSequence, OpeningKey, SealingKey, Tag,
    UnboundKey,
};

/// Result type for ring cryptographic operations.
pub type RingResult<T> = Result<T, ring::error::Unspecified>;

/// Counter-based nonce sequence for AES-GCM.
///
/// Generates unique 12-byte nonces by incrementing a counter stored in
/// the last 4 bytes. This ensures nonce uniqueness within a single
/// encryptor instance's lifetime, not across directions or connections.
///
/// # Nonce Structure
///
/// ```text
/// ┌────────────────────────────────────────┐
/// │           12-byte Nonce                │
/// ├────────────────────┬───────────────────┤
/// │   8 bytes (zeros)  │ 4 bytes (counter) │
/// └────────────────────┴───────────────────┘
/// ```
#[derive(Clone, Copy, Default)]
pub(crate) struct CounterNonceSequence(u32, [u8; NONCE_LEN]);

impl NonceSequence for CounterNonceSequence {
    /// Advances the counter and returns the next nonce.
    ///
    /// Called once for each seal/open operation.
    fn advance(&mut self) -> RingResult<Nonce> {
        let nonce_bytes = &mut self.1;

        // Store counter in big-endian format in last 4 bytes
        let bytes = self.0.to_be_bytes();
        nonce_bytes[8..].copy_from_slice(&bytes);

        // Exhaustion must fail closed in release builds too, never wrap to a
        // previously used nonce. Existing nonces retain their wire encoding.
        self.0 = self.0.checked_add(1).ok_or(ring::error::Unspecified)?;
        Ok(Nonce::assume_unique_for_key(*nonce_bytes))
    }
}

/// Combined AES-256-GCM encryptor and decryptor.
///
/// Provides both encryption and decryption capabilities using the same key.
/// Each instance maintains independent nonce counters for sealing and opening.
///
/// # Thread Safety
///
/// This struct is NOT thread-safe. Each connection should have its own instance.
pub struct Aes256GcmCryption {
    seal: Aes256GcmEncryptor,
    open: Aes256GcmDecryptor,
}

impl Aes256GcmCryption {
    /// Creates a new cryptor with the given 32-byte key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key length is not 32 bytes.
    pub fn try_new(key: &[u8]) -> RingResult<Self> {
        Ok(Self {
            seal: Aes256GcmEncryptor::try_new(key)?,
            open: Aes256GcmDecryptor::try_new(key)?,
        })
    }

    /// Encrypts data in-place and returns the authentication tag.
    ///
    /// The data buffer is modified to contain the ciphertext.
    /// The returned tag must be transmitted alongside the ciphertext.
    pub fn encrypt(&mut self, data: &mut [u8]) -> RingResult<Tag> {
        self.seal.encrypt(data)
    }

    /// Decrypts data with the tag appended at the end.
    ///
    /// This is the preferred decryption method when ciphertext and tag
    /// are stored contiguously (as in the wire protocol).
    ///
    /// # Wire Format
    ///
    /// ```text
    /// ┌─────────────────────────────────────┐
    /// │ Ciphertext (N bytes) │ Tag (16 bytes)│
    /// └─────────────────────────────────────┘
    /// ```
    pub fn decrypt_with_tag<'a>(&mut self, data: &'a mut [u8]) -> RingResult<&'a mut [u8]> {
        self.open.decrypt_with_tag(data)
    }
}

/// AES-256-GCM encryptor.
///
/// Encrypts data using AES-256-GCM with a counter-based nonce sequence.
#[derive(Debug)]
pub struct Aes256GcmEncryptor {
    seal: SealingKey<CounterNonceSequence>,
}

impl Aes256GcmEncryptor {
    /// Creates a new encryptor with the given 32-byte key.
    pub fn try_new(key: &[u8]) -> RingResult<Self> {
        let counter = CounterNonceSequence::default();
        Ok(Self {
            seal: SealingKey::new(UnboundKey::new(&AES_256_GCM, key)?, counter),
        })
    }
}

impl Encryptor for Aes256GcmEncryptor {
    fn encrypt(&mut self, data: &mut [u8]) -> RingResult<Tag> {
        self.seal.seal_in_place_separate_tag(Aad::empty(), data)
    }
}

/// AES-256-GCM decryptor.
///
/// Decrypts data using AES-256-GCM with a counter-based nonce sequence.
#[derive(Debug)]
pub struct Aes256GcmDecryptor {
    open: OpeningKey<CounterNonceSequence>,
}

impl Aes256GcmDecryptor {
    /// Creates a new decryptor with the given 32-byte key.
    pub fn try_new(key: &[u8]) -> RingResult<Self> {
        let counter = CounterNonceSequence::default();
        Ok(Self {
            open: OpeningKey::new(UnboundKey::new(&AES_256_GCM, key)?, counter),
        })
    }
}

impl Decryptor for Aes256GcmDecryptor {
    fn decrypt_with_tag<'a>(&mut self, data: &'a mut [u8]) -> RingResult<&'a mut [u8]> {
        self.open.open_in_place(Aad::empty(), data)
    }
}

/// Trait for encryption operations.
///
/// Allows abstracting over different encryption algorithms.
pub trait Encryptor: 'static {
    /// Encrypts data in-place and returns the authentication tag.
    fn encrypt(&mut self, data: &mut [u8]) -> RingResult<Tag>;
}

/// Trait for decryption operations.
///
/// Allows abstracting over different decryption algorithms.
pub trait Decryptor {
    /// Decrypts data with the tag appended at the end.
    fn decrypt_with_tag<'a>(&mut self, data: &'a mut [u8]) -> RingResult<&'a mut [u8]>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn exhausted_nonce_sequence_never_wraps_or_panics() {
        use ring::aead::NonceSequence;
        let mut sequence = super::CounterNonceSequence(u32::MAX - 1, [0; 12]);
        assert!(sequence.advance().is_ok());
        assert!(sequence.advance().is_err());
        assert!(sequence.advance().is_err());
    }
}
