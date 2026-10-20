//! A bounded subscription server. Configurations are generated once per start;
//! requests clone reference-counted bytes and never enter the UI runtime.
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub local_port: u16,
    pub server_host: String,
    pub udp_enabled: bool,
    pub reverse_geo: bool,
}

impl Config {
    fn validate(&self) -> io::Result<()> {
        if self.local_port == 0
            || self.server_host.is_empty()
            || self.server_host.len() > 1024
            || self.server_host.chars().any(|c| c.is_control() || c == ',')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid subscription endpoint",
            ));
        }
        Ok(())
    }

    pub fn clash(&self) -> String {
        format!(
            "port: 7890\nsocks-port: 7891\nallow-lan: false\nmode: rule\nlog-level: \
             info\n\nproxies:\n  - name: \"LocalProxy\"\n    type: socks5\n    server: \
             127.0.0.1\n    port: {}\n    udp: {}\n\nproxy-groups:\n  - name: \"PROXY\"\n    \
             type: select\n    proxies:\n      - LocalProxy\n      - DIRECT\n\nrules:\n  - \
             DST-PORT,{},DIRECT\n  - IP-CIDR,127.0.0.0/8,DIRECT\n  - GEOIP,LAN,DIRECT\n  - \
             GEOIP,CN,DIRECT\n  - MATCH,PROXY\n",
            self.local_port, self.udp_enabled, self.local_port
        )
    }

    pub fn shadowrocket(&self) -> String {
        format!(
            "[General]\nbypass-system = true\nskip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, \
             172.16.0.0/12, localhost, *.local\nbypass-tun = 10.0.0.0/8, 100.64.0.0/10, \
             127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, \
             192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, \
             255.255.255.255/32\ndns-server = system\n\n[Proxy]\nLocalProxy = socks5, 127.0.0.1, \
             {}, udp={}\n\n[Rule]\nDOMAIN-SUFFIX,{},DIRECT\nGEOIP,CN,{}\nFINAL,{}",
            self.local_port,
            u8::from(self.udp_enabled),
            self.server_host,
            if self.reverse_geo {
                "LocalProxy"
            } else {
                "DIRECT"
            },
            if self.reverse_geo {
                "DIRECT"
            } else {
                "LocalProxy"
            },
        )
    }
}

struct Documents {
    clash: Bytes,
    shadowrocket: Bytes,
    base64: Bytes,
}

impl Documents {
    fn response<B>(&self, request: Request<B>) -> Response<Full<Bytes>> {
        let (body, content_type, filename) = match request.uri().path() {
            "/clash" => (&self.clash, "text/yaml; charset=utf-8", Some("clash.yaml")),
            "/shadowrocket" => (
                &self.shadowrocket,
                "text/plain; charset=utf-8",
                Some("shadowrocket.conf"),
            ),
            "/shadowrocket/base64" => (&self.base64, "text/plain; charset=utf-8", None),
            _ => {
                return Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::from_static(b"Not Found")))
                    .unwrap();
            }
        };
        let mut response = Response::builder().header("Content-Type", content_type);
        if let Some(filename) = filename {
            response = response.header(
                "Content-Disposition",
                format!("attachment; filename={filename}"),
            );
        }
        response.body(Full::new(body.clone())).unwrap()
    }
}

pub struct Server {
    address: SocketAddr,
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl Server {
    pub async fn start(address: SocketAddr, config: Config) -> io::Result<Self> {
        config.validate()?;
        let shadowrocket = config.shadowrocket();
        let documents = Arc::new(Documents {
            clash: config.clash().into(),
            base64: base64::engine::general_purpose::STANDARD
                .encode(&shadowrocket)
                .into(),
            shadowrocket: shadowrocket.into(),
        });
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let cancel = CancellationToken::new();
        let stopped = cancel.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = stopped.cancelled() => break,
                    _ = connections.join_next(), if !connections.is_empty() => {},
                    incoming = listener.accept(), if connections.len() < 32 => {
                        let Ok((stream, _)) = incoming else { break };
                        let documents = documents.clone();
                        connections.spawn(async move {
                            let service = service_fn(move |request| {
                                let response = documents.response(request);
                                async { Ok::<_, Infallible>(response) }
                            });
                            // Bound slow/incomplete LAN clients and don't retain idle sockets.
                            let _ = tokio::time::timeout(Duration::from_secs(10),
                                http1::Builder::new().keep_alive(false).max_buf_size(8192)
                                    .serve_connection(TokioIo::new(stream), service)).await;
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Ok(Self {
            address,
            cancel,
            task: Some(task),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub async fn stop(mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn serves_cached_documents_and_releases_port_with_stalled_clients() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = Config {
            local_port: 1080,
            server_host: "proxy.example".into(),
            udp_enabled: true,
            reverse_geo: true,
        };
        let server = Server::start("127.0.0.1:0".parse().unwrap(), config.clone())
            .await
            .unwrap();
        let address = server.address();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        for (path, expected) in [
            ("clash", config.clash()),
            ("shadowrocket", config.shadowrocket()),
            (
                "shadowrocket/base64",
                base64::engine::general_purpose::STANDARD.encode(config.shadowrocket()),
            ),
        ] {
            let response = client
                .get(format!("http://{address}/{path}"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.text().await.unwrap(), expected);
        }
        assert_eq!(
            client
                .get(format!("http://{address}/missing"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        let stalled = tokio::net::TcpStream::connect(address).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), server.stop())
            .await
            .unwrap();
        drop(stalled);
        let rebound = Server::start(address, config).await.unwrap();
        rebound.stop().await;
    }

    #[test]
    fn udp_and_reverse_geo_keep_existing_configuration_semantics() {
        for enabled in [false, true] {
            let config = Config {
                local_port: 1080,
                server_host: "proxy.example".into(),
                udp_enabled: enabled,
                reverse_geo: enabled,
            };
            assert!(config.clash().contains(&format!("udp: {enabled}\n")));
            assert!(
                config
                    .shadowrocket()
                    .contains(&format!("udp={}\n", u8::from(enabled)))
            );
            assert!(config.shadowrocket().ends_with(if enabled {
                "GEOIP,CN,LocalProxy\nFINAL,DIRECT"
            } else {
                "GEOIP,CN,DIRECT\nFINAL,LocalProxy"
            }));
        }
    }

    #[test]
    fn rejects_configuration_line_injection() {
        let config = Config {
            local_port: 1080,
            server_host: "proxy.example\nFINAL,DIRECT".into(),
            udp_enabled: false,
            reverse_geo: false,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn documents_match_the_previous_dart_generators_byte_for_byte() {
        let config = Config {
            local_port: 1080,
            server_host: "proxy.example".into(),
            udp_enabled: true,
            reverse_geo: true,
        };
        assert_eq!(
            config.clash(),
            include_str!("../tests/fixtures/legacy-clash.yaml").replace("\r\n", "\n")
        );
        assert_eq!(
            config.shadowrocket(),
            include_str!("../tests/fixtures/legacy-shadowrocket.conf").replace("\r\n", "\n")
        );
    }
}
