use http_proxy::{
    init_tracing,
    server::{handle_connect, SERVER_PORT},
};
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
    let listener = TcpListener::bind(("0.0.0.0", SERVER_PORT)).await.unwrap();

    loop {
        let ret = listener.accept().await;
        let (client_socket, _) = match ret {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Accept error:{e}.pause 3s,and retry");
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                continue;
            }
        };

        tokio::spawn(async move {
            if let Err(e) = handle_connect(client_socket).await {
                let report = Report::from_error(e).to_string();
                tracing::warn!("Error happens in handling client: {}", report);
            }
        });
    }
}
