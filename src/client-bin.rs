use http_proxy::client::{start_client, CLIENT_PORT, SERVER_HOST};
use http_proxy::init_tracing;

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() {
    init_tracing();
    tracing::info!("SERVER_HOST:{}", *SERVER_HOST);
    let msg_key = std::env::var("MSG_KEY").is_ok();
    if msg_key {
        tracing::info!("`MSG_KEY=ON`, message encryption is used");
        start_client::<true>("0.0.0.0", CLIENT_PORT).await;
    } else {
        tracing::info!("MSG_KEY not set, message send raw data");
        start_client::<false>("0.0.0.0", CLIENT_PORT).await;
    }
}
