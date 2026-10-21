//! A loopback HTTP proxy that applies one app's host rules: matching requests
//! connect directly, everything else goes through the chosen local proxy.
//!
//! HTTPS stays an opaque CONNECT tunnel; nothing is decrypted. When the
//! upstream proxy is unavailable a request fails instead of quietly going
//! direct.
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use super::rules;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONNECTIONS: usize = 128;
const MAX_PROXY_HEADER: usize = 32 * 1024;

#[derive(Clone, Debug)]
pub struct Target {
    pub upstream_port: u16,
    pub rules: Vec<String>,
}

type Body = BoxBody<Bytes, hyper::Error>;

pub struct Router {
    port: u16,
    target: Arc<RwLock<Target>>,
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl Router {
    /// Listens on loopback only; port zero picks a free port.
    pub async fn start(port: u16, target: Target) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await?;
        let port = listener.local_addr()?.port();
        let target = Arc::new(RwLock::new(target));
        let cancel = CancellationToken::new();
        let (shared, stopped) = (target.clone(), cancel.clone());
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = stopped.cancelled() => break,
                    _ = connections.join_next(), if !connections.is_empty() => {},
                    incoming = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                        let Ok((stream, _)) = incoming else { continue };
                        let target = shared.clone();
                        connections.spawn(async move {
                            let service = service_fn(move |request| {
                                let target = target.read().ok().map(|target| target.clone());
                                async move {
                                    Ok::<_, Infallible>(match target {
                                        Some(target) => handle(request, target, port).await,
                                        None => status(StatusCode::INTERNAL_SERVER_ERROR),
                                    })
                                }
                            });
                            let _ = http1::Builder::new()
                                .timer(TokioTimer::new())
                                .header_read_timeout(RESPONSE_TIMEOUT)
                                .serve_connection(TokioIo::new(stream), service)
                                .with_upgrades()
                                .await;
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Ok(Self {
            port,
            target,
            cancel,
            task: Some(task),
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// New rules and upstream apply to the next request.
    pub fn set_target(&self, target: Target) {
        if let Ok(mut current) = self.target.write() {
            *current = target;
        }
    }

    pub async fn stop(mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Router {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

enum Failure {
    BadRequest,
    Upstream,
}

impl From<io::Error> for Failure {
    fn from(_: io::Error) -> Self {
        Self::Upstream
    }
}

impl From<hyper::Error> for Failure {
    fn from(_: hyper::Error) -> Self {
        Self::Upstream
    }
}

fn status(code: StatusCode) -> Response<Body> {
    let mut response = Response::new(Empty::new().map_err(|never| match never {}).boxed());
    *response.status_mut() = code;
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

async fn handle(request: Request<Incoming>, target: Target, own_port: u16) -> Response<Body> {
    let result = if request.method() == Method::CONNECT {
        tunnel(request, &target, own_port).await
    } else {
        forward(request, &target, own_port).await
    };
    result.unwrap_or_else(|failure| {
        status(match failure {
            Failure::BadRequest => StatusCode::BAD_REQUEST,
            Failure::Upstream => StatusCode::BAD_GATEWAY,
        })
    })
}

/// The destination host (unbracketed) and port, refusing anything that is not
/// a plain proxy target or that would loop back into this listener.
fn destination(
    uri: &Uri,
    connect: bool,
    target: &Target,
    own_port: u16,
) -> Result<(String, u16), Failure> {
    let authority = uri.authority().ok_or(Failure::BadRequest)?;
    if authority.as_str().contains('@') {
        return Err(Failure::BadRequest);
    }
    let port = match (connect, authority.port_u16()) {
        (_, Some(port)) => port,
        (false, None) if uri.scheme_str() == Some("http") => 80,
        _ => return Err(Failure::BadRequest),
    };
    if !connect && (uri.scheme_str() != Some("http")) {
        return Err(Failure::BadRequest);
    }
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if host.is_empty() || port == 0 || port == own_port || target.upstream_port == own_port {
        return Err(Failure::BadRequest);
    }
    Ok((host.to_owned(), port))
}

async fn connect(host: &str, port: u16) -> io::Result<TcpStream> {
    tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))?
}

fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Opens a CONNECT tunnel through the upstream proxy. Returns the stream and
/// any bytes that arrived after the proxy's response header.
async fn upstream_tunnel(
    target: &Target,
    host: &str,
    port: u16,
) -> Result<(TcpStream, Vec<u8>), Failure> {
    let mut stream = connect("127.0.0.1", target.upstream_port).await?;
    let authority = authority(host, port);
    stream
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await?;
    let read = async {
        let mut header = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(Failure::Upstream);
            }
            header.extend_from_slice(&chunk[..read]);
            if let Some(end) = header.windows(4).position(|window| window == b"\r\n\r\n") {
                let line = &header[..header.iter().position(|&b| b == b'\r').unwrap_or(0)];
                let accepted = (line.starts_with(b"HTTP/1.1 2") || line.starts_with(b"HTTP/1.0 2"))
                    && line.len() >= 13
                    && line[10..12].iter().all(u8::is_ascii_digit)
                    && line[12] == b' ';
                if !accepted {
                    return Err(Failure::Upstream);
                }
                return Ok(header.split_off(end + 4));
            }
            if header.len() > MAX_PROXY_HEADER {
                return Err(Failure::Upstream);
            }
        }
    };
    let rest = tokio::time::timeout(CONNECT_TIMEOUT, read)
        .await
        .map_err(|_| Failure::Upstream)??;
    Ok((stream, rest))
}

async fn tunnel(
    request: Request<Incoming>,
    target: &Target,
    own_port: u16,
) -> Result<Response<Body>, Failure> {
    let (host, port) = destination(request.uri(), true, target, own_port)?;
    let (mut upstream, rest) = if rules::bypasses(&target.rules, &host) {
        (connect(&host, port).await?, Vec::new())
    } else {
        upstream_tunnel(target, &host, port).await?
    };
    tokio::spawn(async move {
        let Ok(upgraded) = hyper::upgrade::on(request).await else {
            return;
        };
        let mut client = TokioIo::new(upgraded);
        if !rest.is_empty() && client.write_all(&rest).await.is_err() {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    });
    Ok(Response::new(
        Empty::new().map_err(|never| match never {}).boxed(),
    ))
}

/// Removes hop-by-hop headers, including any the Connection header names.
fn strip_hop_headers(headers: &mut HeaderMap) {
    let named = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    for name in [
        "connection",
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain(named)
    {
        headers.remove(name.as_str());
    }
}

async fn forward(
    request: Request<Incoming>,
    target: &Target,
    own_port: u16,
) -> Result<Response<Body>, Failure> {
    let (host, port) = destination(request.uri(), false, target, own_port)?;
    let direct = rules::bypasses(&target.rules, &host);
    let stream = if direct {
        connect(&host, port).await?
    } else {
        connect("127.0.0.1", target.upstream_port).await?
    };
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(connection);
    let (mut parts, body) = request.into_parts();
    strip_hop_headers(&mut parts.headers);
    let host_header = if port == 80 {
        host.clone()
    } else {
        authority(&host, port)
    };
    parts.headers.insert(
        header::HOST,
        HeaderValue::from_str(&host_header).map_err(|_| Failure::BadRequest)?,
    );
    if direct {
        // An origin server expects origin-form; the upstream proxy keeps the
        // absolute target.
        parts.uri = parts
            .uri
            .path_and_query()
            .map_or("/", |path| path.as_str())
            .parse()
            .map_err(|_| Failure::BadRequest)?;
    }
    let response = tokio::time::timeout(
        RESPONSE_TIMEOUT,
        sender.send_request(Request::from_parts(parts, body)),
    )
    .await
    .map_err(|_| Failure::Upstream)??;
    let (mut parts, body) = response.into_parts();
    strip_hop_headers(&mut parts.headers);
    parts
        .headers
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    Ok(Response::from_parts(parts, body.boxed()))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// A minimal upstream proxy that records request lines and checks that no
    /// proxy credentials or named hop headers reach it.
    async fn upstream(seen: Arc<Mutex<Vec<String>>>) -> (u16, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
                    assert!(!text.contains("proxy-authorization") && !text.contains("x-hop"));
                    let line = String::from_utf8_lossy(&head)
                        .lines()
                        .next()
                        .unwrap()
                        .to_owned();
                    let request = line.rsplit_once(' ').unwrap().0.to_owned();
                    seen.lock().unwrap().push(request.clone());
                    if request.starts_with("CONNECT") {
                        // The tunnel's first bytes ride along with the reply.
                        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
                        let (mut read, mut write) = stream.split();
                        let _ = tokio::io::copy(&mut read, &mut write).await;
                    } else {
                        let length = text
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length: "))
                            .and_then(|value| value.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        let mut body = vec![0u8; length];
                        stream.read_exact(&mut body).await.unwrap();
                        let reply = format!("upstream:{}", String::from_utf8_lossy(&body));
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: \
                             close\r\n\r\n{reply}",
                            reply.len()
                        );
                        stream.write_all(response.as_bytes()).await.unwrap();
                    }
                });
            }
        });
        (port, task)
    }

    async fn echo() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        port
    }

    async fn exchange(router: u16, request: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", router)).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    async fn tunnel_echoes(router: u16, target: &str) {
        let mut stream = TcpStream::connect(("127.0.0.1", router)).await.unwrap();
        stream
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        assert!(head.starts_with(b"HTTP/1.1 200 "), "{target}");
        stream.write_all(b"opaque tunnel bytes").await.unwrap();
        let mut echoed = [0u8; 19];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed, b"opaque tunnel bytes");
    }

    #[tokio::test]
    async fn routes_http_and_opaque_connect_strips_credentials_and_fails_closed() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (upstream_port, upstream_task) = upstream(seen.clone()).await;
        let echo_port = echo().await;
        let defaults = rules::DEFAULT_RULES.map(String::from).to_vec();
        let router = Router::start(
            0,
            Target {
                upstream_port,
                rules: defaults.clone(),
            },
        )
        .await
        .unwrap();
        let port = router.port();

        let response = exchange(
            port,
            "POST http://public.invalid/upload HTTP/1.1\r\nHost: \
             public.invalid\r\nProxy-Authorization: test-only\r\nConnection: x-hop\r\nX-Hop: \
             remove\r\nContent-Length: 7\r\n\r\npayload",
        )
        .await;
        assert!(response.ends_with("upstream:payload"), "{response}");

        // Loopback is always direct; everything else, IPv6 included, is not.
        for target in [
            "public.invalid:443",
            &format!("127.0.0.1:{echo_port}"),
            "[2001:db8::1]:443",
        ] {
            tunnel_echoes(port, target).await;
        }
        assert_eq!(
            *seen.lock().unwrap(),
            [
                "POST http://public.invalid/upload",
                "CONNECT public.invalid:443",
                "CONNECT [2001:db8::1]:443"
            ]
        );

        let recursive = exchange(
            port,
            &format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: x\r\n\r\n"),
        )
        .await;
        assert!(recursive.starts_with("HTTP/1.1 400"), "{recursive}");

        upstream_task.abort();
        let _ = upstream_task.await;
        router.set_target(Target {
            upstream_port,
            rules: defaults,
        });
        let unavailable = exchange(
            port,
            "GET http://public.invalid/ HTTP/1.1\r\nHost: public.invalid\r\n\r\n",
        )
        .await;
        assert!(unavailable.starts_with("HTTP/1.1 502"), "{unavailable}");
        router.stop().await;
    }
}
