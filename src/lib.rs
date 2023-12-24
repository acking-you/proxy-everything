use std::fmt::Display;

pub mod client;
pub(crate) mod codec;
pub mod server;
pub(crate) mod util;

use async_trait::async_trait;
use codec::{AsyncNormalCodec, CodecError};
use futures::future;
use once_cell::sync::Lazy;
use rand::Rng;
use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, Tag, UnboundKey, AES_256_GCM,
    NONCE_LEN,
};
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use tracing_subscriber::{fmt, layer::SubscriberExt};

use codec::{AsyncDecryptCodec, AsyncEncryptCodec};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Read header error:`{detail}`"))]
    ReadHeader {
        detail: String,
        source: std::io::Error,
    },
    #[snafu(display("Write header error:`{detail}`"))]
    WriteHeader {
        detail: String,
        source: std::io::Error,
    },
    #[snafu(display("Checksum not pass: size:`{size}`"))]
    CheckSum { size: u32 },
    #[snafu(display("Data size must be less than `{size}`"))]
    MaxSize { size: u32 },
    #[snafu(display("Write data error in `codec_and_write`.detail:{detail}"))]
    WriteDataInProxy {
        detail: &'static str,
        source: std::io::Error,
    },
    #[snafu(display("Reader codec error in proxy"))]
    Codec { source: CodecError },
    #[snafu(display("Proxy error! Send data to server or client fails!,detail:{msg}"))]
    Proxy { msg: String },
    #[snafu(display("Construct cryptor error! detail:{detail}"))]
    ConstructCryptor { detail: String },
}

type Result<T, E = Error> = std::result::Result<T, E>;
type RingResult<T> = Result<T, ring::error::Unspecified>;

pub fn init_tracing() {
    let subcriber = tracing_subscriber::registry()
        .with(fmt::Layer::new().pretty().with_writer(std::io::stdout));
    tracing::subscriber::set_global_default(subcriber).expect("setting tracing default failed");
}

pub fn gen_random_key() -> String {
    const CHARSET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

    let mut rng = rand::thread_rng();
    let random_string: String = (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    random_string
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyHeader {
    pub host: String,
    pub port: u16,
    pub key: Option<String>,
}

impl Display for ProxyHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

// 256-bit key,must be 256/8 = 32 byte key and hashcode
pub static DEFAULT_KEY: Lazy<(Vec<u8>, u32)> = Lazy::new(|| {
    let default_key = "my-secret-key123my-secret-key123";
    let key = match std::env::var("SECRET_KEY") {
        Ok(k) => {
            let key = k.as_bytes();
            if key.len() != 32 {
                tracing::warn!("`SECRET_KEY` must have 256 bit(32 byte)!. current input key:{k}");
                std::process::exit(1);
            }
            key.to_vec()
        }
        Err(_) => {
            tracing::warn!("No ENV:`SECRET_KEY` provided,we use default key:{default_key}");
            default_key.as_bytes().to_vec()
        }
    };
    let hash = key.iter().fold(0u32, |hash, &byte| {
        hash.wrapping_mul(31).wrapping_add(byte as u32)
    });
    (key, hash)
});

#[derive(Clone, Copy)]
struct CounterNonceSequence(u32);

impl NonceSequence for CounterNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> RingResult<Nonce> {
        let mut nonce_bytes = vec![0; NONCE_LEN];

        let bytes = self.0.to_be_bytes();
        nonce_bytes[8..].copy_from_slice(&bytes);

        self.0 += 1; // advance the counter
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

pub struct Aes256GcmCryption {
    seal: Aes256GcmEncryptor,
    open: Aes256GcmDecryptor,
}

impl Aes256GcmCryption {
    pub fn try_new(key: &[u8]) -> RingResult<Self> {
        Ok(Self {
            seal: Aes256GcmEncryptor::try_new(key)?,
            open: Aes256GcmDecryptor::try_new(key)?,
        })
    }

    pub fn try_new_with_default_key() -> RingResult<Self> {
        Aes256GcmCryption::try_new(DEFAULT_KEY.0.as_ref())
    }

    pub fn encrypt(&mut self, data: &mut [u8]) -> RingResult<Tag> {
        self.seal.encrypt(data)
    }

    pub fn decrypt(&mut self, decrypeted_data: &[u8], tag: Tag) -> RingResult<(Vec<u8>, usize)> {
        self.open.decrypt(decrypeted_data, tag)
    }

    pub fn decrypt_with_tag<'a>(&mut self, data: &'a mut [u8]) -> RingResult<&'a mut [u8]> {
        self.open.decrypt_with_tag(data)
    }
}

#[derive(Debug)]
pub struct Aes256GcmEncryptor {
    seal: SealingKey<CounterNonceSequence>,
}

impl Aes256GcmEncryptor {
    pub fn try_new(key: &[u8]) -> RingResult<Self> {
        let counter = CounterNonceSequence(0);
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

#[derive(Debug)]
pub struct Aes256GcmDecryptor {
    open: OpeningKey<CounterNonceSequence>,
}

impl Aes256GcmDecryptor {
    pub fn try_new(key: &[u8]) -> RingResult<Self> {
        let counter = CounterNonceSequence(0);
        Ok(Self {
            open: OpeningKey::new(UnboundKey::new(&AES_256_GCM, key)?, counter),
        })
    }
}

impl Decryptor for Aes256GcmDecryptor {
    fn decrypt(&mut self, decrypeted_data: &[u8], tag: Tag) -> RingResult<(Vec<u8>, usize)> {
        let mut new_data = [decrypeted_data, tag.as_ref()].concat();
        let new_data_len = self.decrypt_with_tag(&mut new_data)?.len();
        Ok((new_data, new_data_len))
    }

    fn decrypt_with_tag<'a>(&mut self, data: &'a mut [u8]) -> RingResult<&'a mut [u8]> {
        self.open.open_in_place(Aad::empty(), data)
    }
}

pub trait Encryptor: 'static {
    fn encrypt(&mut self, data: &mut [u8]) -> RingResult<Tag>;
}

pub trait Decryptor {
    fn decrypt(&mut self, decrypeted_data: &[u8], tag: Tag) -> RingResult<(Vec<u8>, usize)>;
    fn decrypt_with_tag<'a>(&mut self, data: &'a mut [u8]) -> RingResult<&'a mut [u8]>;
}

/// Checksum for read data length
#[inline]
fn get_check_sum(data: DataSize) -> DataSize {
    data ^ DEFAULT_KEY.1
}

type DataSize = u32;

/// Max datasize when read data
pub const MAX_DATA_SIZE: DataSize = 30 * 1024 * 1024;

/// Abstraction of intermediate layers for free switching of runtimes (e.g. monoio and tokio)
#[async_trait]
pub(crate) trait MyAsyncReadExt: 'static {
    async fn read_u32(&mut self) -> Result<u32, std::io::Error>;
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error>;
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error>;
}

#[async_trait]
pub(crate) trait MyAsyncWriteExt {
    async fn write_u32(&mut self, n: u32) -> Result<(), std::io::Error>;
    async fn write(&mut self, src: &[u8]) -> Result<usize, std::io::Error>;
    async fn write_all(&mut self, src: &[u8]) -> Result<(), std::io::Error>;
}

pub(crate) async fn get_data_size<T: MyAsyncReadExt + Unpin>(reader: &mut T) -> Result<DataSize> {
    let msg_checksum = reader.read_u32().await.context(ReadHeaderSnafu {
        detail: "Read Header(checksum)",
    })?;
    let msg_len = reader.read_u32().await.context(ReadHeaderSnafu {
        detail: "Read Header(msg_len)",
    })?;
    if get_check_sum(msg_checksum) != msg_len {
        CheckSumSnafu { size: msg_len }.fail()?;
    }
    if msg_len > MAX_DATA_SIZE {
        MaxSizeSnafu {
            size: MAX_DATA_SIZE,
        }
        .fail()?;
    }
    Ok(msg_len)
}

pub(crate) async fn set_data_size<T: MyAsyncWriteExt + Unpin>(
    writer: &mut T,
    data_size: DataSize,
) -> Result<()> {
    writer
        .write_u32(get_check_sum(data_size))
        .await
        .context(WriteHeaderSnafu {
            detail: "Send Header(check_sum)",
        })?;
    writer
        .write_u32(data_size)
        .await
        .context(WriteHeaderSnafu {
            detail: "Send Header(msg_len)",
        })?;
    Ok(())
}

/// For free choice of unpacking when reading data
#[async_trait]
pub(crate) trait MyAsyncCodecReader {
    type Item<'a>
    where
        Self: 'a;
    async fn codec(&mut self) -> Result<Self::Item<'_>>;
    async fn codec_and_write<W: MyAsyncWriteExt + Send + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> Result<DataSize>;
}

#[tracing::instrument(skip_all)]
pub(crate) fn proxy_result_handle(
    client_res: Result<DataSize>,
    server_res: Result<DataSize>,
) -> Result<()> {
    match (client_res, server_res) {
        (Ok(c), Ok(s)) => {
            tracing::info!("We send {} bytes to server,send {} bytes to client", c, s);
        }
        (Ok(n), Err(e)) => {
            tracing::info!(
                "We send {} bytes to server,ot error when send to client,detail:{}",
                n,
                snafu::Report::from_error(e)
            );
        }
        (Err(e), Ok(n)) => {
            tracing::info!(
                "We send {} bytes to client,got error when send to server,detail:{}",
                n,
                snafu::Report::from_error(e)
            );
        }
        (Err(e1), Err(e2)) => ProxySnafu {
            msg: format!(
                "send to server:{},send to client:{}",
                snafu::Report::from_error(e1),
                snafu::Report::from_error(e2)
            ),
        }
        .fail()?,
    }
    Ok(())
}

fn get_decyptor_codec<R: MyAsyncReadExt + Unpin>(
    key: &impl AsRef<str>,
    reader: R,
) -> Result<AsyncDecryptCodec<R, Aes256GcmDecryptor>> {
    Ok(AsyncDecryptCodec::new(
        reader,
        Aes256GcmDecryptor::try_new(key.as_ref().as_bytes()).map_err(|e| {
            Error::ConstructCryptor {
                detail: format!("{e}"),
            }
        })?,
    ))
}

fn get_encyptor_codec<R: MyAsyncReadExt + Unpin>(
    key: impl AsRef<str>,
    reader: R,
) -> Result<AsyncEncryptCodec<R, Aes256GcmEncryptor>> {
    Ok(AsyncEncryptCodec::new(
        reader,
        Aes256GcmEncryptor::try_new(key.as_ref().as_bytes()).map_err(|e| {
            Error::ConstructCryptor {
                detail: format!("{e}"),
            }
        })?,
    ))
}

async fn start_proxy<
    ClientCodec: MyAsyncCodecReader + Send + Unpin,
    ServerCodec: MyAsyncCodecReader + Send + Unpin,
    W: MyAsyncWriteExt + Send + Unpin,
>(
    client_codec: ClientCodec,
    server_codec: ServerCodec,
    client_writer: W,
    server_writer: W,
) -> Result<()> {
    let client_to_server = codec::copy(client_codec, server_writer);
    let server_to_client = codec::copy(server_codec, client_writer);
    let (r1, r2) = future::join(client_to_server, server_to_client).await;
    proxy_result_handle(r1, r2)
}

pub(crate) async fn client_proxy_with_cryptor_codec<
    R: MyAsyncReadExt + Send + Unpin,
    W: MyAsyncWriteExt + Send + Unpin,
>(
    key: &impl AsRef<str>,
    client_reader: R,
    server_reader: R,
    client_writer: W,
    server_writer: W,
) -> Result<()> {
    tracing::info!("client start forward with random_key:{}", key.as_ref());
    start_proxy(
        get_encyptor_codec(key, client_reader)?,
        get_decyptor_codec(key, server_reader)?,
        client_writer,
        server_writer,
    )
    .await
}

pub(crate) async fn server_proxy_with_cryptor_codec<
    R: MyAsyncReadExt + Send + Unpin,
    W: MyAsyncWriteExt + Send + Unpin,
>(
    key: &impl AsRef<str>,
    client_reader: R,
    server_reader: R,
    client_writer: W,
    server_writer: W,
) -> Result<()> {
    tracing::info!("server start forward with random_key:{}", key.as_ref());
    start_proxy(
        get_decyptor_codec(key, client_reader)?,
        get_encyptor_codec(key, server_reader)?,
        client_writer,
        server_writer,
    )
    .await
}

pub(crate) async fn proxy_with_norlmal_codec<
    R: MyAsyncReadExt + Send + Unpin,
    W: MyAsyncWriteExt + Send + Unpin,
>(
    client_reader: R,
    server_reader: R,
    client_writer: W,
    server_writer: W,
) -> Result<()> {
    start_proxy(
        AsyncNormalCodec::new(client_reader),
        AsyncNormalCodec::new(server_reader),
        client_writer,
        server_writer,
    )
    .await
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
        let  data = String::from("fdafas反对fdasfasfasfsdafdasfsdfasd范德萨发顺🤣❤️😁😍👍👍丰十大大师傅士大夫大撒发射点发士大夫大师傅大师傅士大夫士大夫阿斯蒂芬大师傅阿斯顿法大师傅看叫阿三的发就可是大家发开始打客服开始大幅喀什的开发点卡收费就开始打客服就是的咖啡肯定撒法开始打客服就是的咖啡就开始大幅扣税的急啊看发叫阿三的发生的开发就是大家可是大家发看大数据开发大数据开发大家ask发就是的咖啡的萨芬就卡死的房价开始打家开发商的JFK上的飞机卡上的纠纷开始打飞机宽带技术开发就开始大家开发建设的卡JFK大数据风控静安寺的看法角度看萨芬卡上的纠纷看静安寺的看法角度思考积分可是大家发卡是大家看法就大肆砍伐尽快打算减肥肯定是积分开始大幅技术大咖积分开始打飞机扣税的急啊看发的技术开发就是JFK十大福克斯大家开发大撒发射点幅度萨芬撒旦发发收范德萨发顺丰士大夫十大阿斯蒂芬大师傅阿斯顿附件是的客服对接撒巨大石块积分的课时费阿斯蒂芬法大师傅大师傅十大法大师傅阿斯蒂芬阿斯顿法大师傅阿斯蒂芬大师傅阿斯顿法大师傅大师傅阿斯蒂芬阿斯蒂芬士大夫阿斯蒂芬大师傅的萨芬打算减肥上岛咖啡加快速度大数据开发就是打客服看大数据开发就开始减肥卡萨丁JFK是大家看法加快速度JFK技术大咖积分喀什的开发独守空房技术大咖积分空手道解放扣税的开发商的开发接口是大家看法角度看是否扣税的急啊看发生的开发的快速减肥开始大幅就是打客服卡上的纠纷啊撒旦解放扣税的急啊看发加快速度点卡JFK啥的但是法大师傅技术大咖积分卡萨丁就反馈是大家看法啊是大家看法卡上的纠纷可是大家发喀什的开发大卡司喀什的开发就是打客服法大师傅士大夫的式咖啡机上岛咖啡就是的咖啡艰苦大师傅看上雕刻技法喀什的开发上岛咖啡就喀什的开发就是打客服卡上的纠纷技术的咖啡机肯定撒开发啊十大科技开发速度加啊反馈就是的咖啡开始大幅大师傅似的十大放假啊上岛咖啡就可是大家发空间的是否撒旦士大夫的撒娇开发是大家看法大肆砍伐就喀什的开发氨基酸的考虑非军事对抗疗法金克拉撒旦发艰苦拉萨的飞机喀什打开发就可是大家发可是大家看附件卡上的纠纷卡刷点卡技术的咖啡机可是大家发卡是大家看法静安寺的看法就可是大家发卡萨丁就开发商的急啊看飞机迪斯科发技术的咖啡机可是大家发看电视剧开发商大开始打到发大水发大水");
        let mut cryption = Aes256GcmCryption::try_new_with_default_key()?;
        let mut out_buf = data.as_bytes().to_vec();
        let tag = {
            let _timer = Timer::new_with_hint("Encrypt".into());
            cryption.encrypt(&mut out_buf)?
        };
        println!("tag:{:?}", tag.as_ref());
        let (decrypeted_data, len) = {
            let _timer = Timer::new_with_hint("Decrypt".into());
            cryption.decrypt(&out_buf, tag)?
        };
        assert_eq!(
            data,
            String::from_utf8(decrypeted_data[..len].to_vec()).unwrap()
        );
        Ok(())
    }
}
