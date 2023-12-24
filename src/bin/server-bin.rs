use http_proxy::{
    init_tracing,
    server::{start_server, SERVER_PORT},
};

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() {
    init_tracing();
    start_server("0.0.0.0", SERVER_PORT).await;
}
