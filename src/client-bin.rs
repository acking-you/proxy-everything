use http_proxy::client::{handle_client, CLIENT_PORT, SERVER_HOST};
use http_proxy::init_tracing;
use snafu::Report;

use tokio::net::TcpListener;

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() {
    init_tracing();
    tracing::info!("SERVER_HOST:{}", *SERVER_HOST);
    let listener = TcpListener::bind(("0.0.0.0", CLIENT_PORT)).await.unwrap();
    loop {
        let (client_socket, _) = listener.accept().await.unwrap();

        tokio::spawn(async move {
            if let Err(e) = handle_client(client_socket).await {
                let report = Report::from_error(e).to_string();
                tracing::error!("Error happens in client handling: {}", report);
            }
        });
    }
}
