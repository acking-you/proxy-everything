use http_proxy::{
    init_tracing,
    server::{start_server, SERVER_PORT},
};

#[tokio::main]
async fn main() {
    init_tracing();
    start_server("0.0.0.0", SERVER_PORT).await;
}
