use http_proxy::client::{start_client, CLIENT_PORT, SERVER_HOST};
use http_proxy::init_tracing;
use mimalloc_rust::GlobalMiMalloc;

#[global_allocator]
static GLOBAL_MIMALLOC: GlobalMiMalloc = GlobalMiMalloc;

#[tokio::main]
async fn main() {
    init_tracing();
    tracing::info!("SERVER_HOST:{}", *SERVER_HOST);
    let msg_key = std::env::var("MSG_KEY").is_ok();
    if msg_key {
        tracing::info!("`MSG_KEY=ON`, message encryption is used");
        start_client::<true>("0.0.0.0", CLIENT_PORT).await;
    } else {
        tracing::info!("MSG_KEY not set, message will send raw data");
        start_client::<false>("0.0.0.0", CLIENT_PORT).await;
    }
}
