use http_proxy::config::{init_tracing, SERVER_PORT};
use http_proxy::server::start_server;
use mimalloc_rust::GlobalMiMalloc;

#[global_allocator]
static GLOBAL_MIMALLOC: GlobalMiMalloc = GlobalMiMalloc;
#[tokio::main]
async fn main() {
    init_tracing();
    start_server("0.0.0.0", *SERVER_PORT).await;
}
