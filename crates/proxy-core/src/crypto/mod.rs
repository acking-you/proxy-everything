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
//! - **Nonce uniqueness**: Uses a counter-based nonce sequence to ensure each encryption operation
//!   uses a unique nonce. The counter is stored in the last 4 bytes of the 12-byte nonce.
//!
//! - **Per-connection instances**: Each connection should create its own `Aes256GcmCryption`
//!   instance to maintain independent nonce counters. Sharing instances across connections would
//!   cause nonce reuse.
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

use crate::config::runtime;

/// Result type for ring cryptographic operations.
pub type RingResult<T> = Result<T, ring::error::Unspecified>;

/// Counter-based nonce sequence for AES-GCM.
///
/// Generates unique 12-byte nonces by incrementing a counter stored in
/// the last 4 bytes. This ensures nonce uniqueness within a single
/// connection's lifetime.
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

        self.0 += 1; // Advance counter for next operation
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

    /// Creates a new cryptor using the default key from configuration.
    pub fn try_new_with_default_key() -> RingResult<Self> {
        runtime::with_secret_key(|key, _| Aes256GcmCryption::try_new(key))
    }

    /// Encrypts data in-place and returns the authentication tag.
    ///
    /// The data buffer is modified to contain the ciphertext.
    /// The returned tag must be transmitted alongside the ciphertext.
    pub fn encrypt(&mut self, data: &mut [u8]) -> RingResult<Tag> {
        self.seal.encrypt(data)
    }

    /// Decrypts data and verifies the authentication tag.
    ///
    /// # Arguments
    ///
    /// * `decrypted_data` - The ciphertext to decrypt
    /// * `tag` - The authentication tag to verify
    ///
    /// # Returns
    ///
    /// A tuple of (buffer, plaintext_length) where the plaintext
    /// occupies the first `plaintext_length` bytes of the buffer.
    pub fn decrypt(&mut self, decrypted_data: &[u8], tag: Tag) -> RingResult<(Vec<u8>, usize)> {
        self.open.decrypt(decrypted_data, tag)
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
    fn decrypt(&mut self, decrypted_data: &[u8], tag: Tag) -> RingResult<(Vec<u8>, usize)> {
        let mut new_data = [decrypted_data, tag.as_ref()].concat();
        let new_data_len = self.decrypt_with_tag(&mut new_data)?.len();
        Ok((new_data, new_data_len))
    }

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
    /// Decrypts data with a separate authentication tag.
    fn decrypt(&mut self, decrypted_data: &[u8], tag: Tag) -> RingResult<(Vec<u8>, usize)>;

    /// Decrypts data with the tag appended at the end.
    fn decrypt_with_tag<'a>(&mut self, data: &'a mut [u8]) -> RingResult<&'a mut [u8]>;
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    struct Timer {
        ins: Instant,
        hint: String,
    }

    impl Timer {
        fn new_with_hint(hint: String) -> Self {
            Self {
                ins: Instant::now(),
                hint,
            }
        }
    }

    impl Drop for Timer {
        fn drop(&mut self) {
            println!("{} consume time:{:?}", self.hint, self.ins.elapsed());
        }
    }

    #[test]
    fn test_encrypt() -> RingResult<()> {
        let data = String::from(
            "fdafas反对fdasfasfasfsdafdasfsdfasd范德萨发顺🤣❤️😁😍👍👍丰十大大师傅士大夫大撒发射点发士大夫大师傅大师傅士大夫士大夫阿斯蒂芬大师傅阿斯顿法大师傅看叫阿三的发就可是大家发开始打客服开始大幅喀什的开发点卡收费就开始打客服就是的咖啡肯定撒法开始打客服就是的咖啡就开始大幅扣税的急啊看发叫阿三的发生的开发就是大家可是大家发看大数据开发大数据开发大家ask发就是的咖啡的萨芬就卡死的房价开始打家开发商的JFK上的飞机卡上的纠纷开始打飞机宽带技术开发就开始大家开发建设的卡JFK大数据风控静安寺的看法角度看萨芬卡上的纠纷看静安寺的看法角度思考积分可是大家发卡是大家看法就大肆砍伐尽快打算减肥肯定是积分开始大幅技术大咖积分开始打飞机扣税的急啊看发的技术开发就是JFK十大福克斯大家开发大撒发射点幅度萨芬撒旦发发收范德萨发顺丰士大夫十大阿斯蒂芬大师傅阿斯顿附件是的客服对接撒巨大石块积分的课时费阿斯蒂芬法大师傅大师傅十大法大师傅阿斯蒂芬阿斯顿法大师傅阿斯蒂芬大师傅阿斯顿法大师傅大师傅阿斯蒂芬阿斯蒂芬士大夫阿斯蒂芬大师傅的萨芬打算减肥上岛咖啡加快速度大数据开发就是打客服看大数据开发就开始减肥卡萨丁JFK是大家看法加快速度JFK技术大咖积分喀什的开发独守空房技术大咖积分空手道解放扣税的开发商的开发接口是大家看法角度看是否扣税的急啊看发生的开发的快速减肥开始大幅就是打客服卡上的纠纷啊撒旦解放扣税的急啊看发加快速度点卡JFK啥的但是法大师傅技术大咖积分卡萨丁就反馈是大家看法啊是大家看法卡上的纠纷可是大家发喀什的开发大卡司喀什的开发就是打客服法大师傅士大夫的式咖啡机上岛咖啡就是的咖啡艰苦大师傅看上雕刻技法喀什的开发上岛咖啡就喀什的开发就是打客服卡上的纠纷技术的咖啡机肯定撒开发啊十大科技开发速度加啊反馈就是的咖啡开始大幅大师傅似的十大放假啊上岛咖啡就可是大家发空间的是否撒旦士大夫的撒娇开发是大家看法大肆砍伐就喀什的开发氨基酸的考虑非军事对抗疗法金克拉撒旦发艰苦拉萨的飞机喀什打开发就可是大家发可是大家看附件卡上的纠纷卡刷点卡技术的咖啡机可是大家发卡是大家看法静安寺的看法就可是大家发卡萨丁就开发商的急啊看飞机迪斯科发技术的咖啡机可是大家发看电视剧开发商大开始打到发大水发大水",
        );
        let mut cryption = Aes256GcmCryption::try_new_with_default_key()?;
        let mut out_buf = data.as_bytes().to_vec();
        let tag = {
            let _timer = Timer::new_with_hint("Encrypt".into());
            cryption.encrypt(&mut out_buf)?
        };
        println!("tag:{:?}", tag.as_ref());
        let (decrypted_data, len) = {
            let _timer = Timer::new_with_hint("Decrypt".into());
            cryption.decrypt(&out_buf, tag)?
        };
        assert_eq!(
            data,
            String::from_utf8(decrypted_data[..len].to_vec()).unwrap()
        );
        Ok(())
    }
}
