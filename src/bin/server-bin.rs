use http_proxy::init_tracing;
use http_proxy::server::{start_server, SERVER_PORT};
use mimalloc_rust::GlobalMiMalloc;

#[global_allocator]
static GLOBAL_MIMALLOC: GlobalMiMalloc = GlobalMiMalloc;
#[tokio::main]
async fn main() {
    init_tracing();
    start_server("0.0.0.0", SERVER_PORT).await;
}
