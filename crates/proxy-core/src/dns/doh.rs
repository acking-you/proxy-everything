//! DNS-over-HTTPS (RFC 8484) exchanges.
//!
//! TLS authenticates the resolver, so an on-path attacker can block the
//! exchange but cannot change its answer. Certificates are always verified:
//! a lookup that cannot complete fails instead of trusting a plaintext or
//! unverified path.

use std::sync::LazyLock;
use std::time::Duration;

use moka::sync::Cache;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use snafu::ResultExt;
use tokio::time::Instant;
use url::Url;

use super::wire::{self, Answer, Query};
use super::{ExchangeError, HttpsSnafu};

const DNS_MESSAGE: &str = "application/dns-message";
const MAX_MESSAGE: usize = u16::MAX as usize;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_CLIENTS: u64 = 16;

/// A client per runtime, because a pooled connection is driven by a task on
/// the runtime that opened it. The FFI creates one runtime per proxy handle.
pub(crate) fn shared_client() -> Result<reqwest::Client, ExchangeError> {
    static CLIENTS: LazyLock<Cache<tokio::runtime::Id, reqwest::Client>> = LazyLock::new(|| {
        Cache::builder()
            .max_capacity(MAX_CLIENTS)
            .time_to_idle(CLIENT_IDLE_TIMEOUT)
            .build()
    });
    let runtime = tokio::runtime::Handle::current().id();
    CLIENTS
        .try_get_with(runtime, || {
            configure(crate::util::http_client_builder()).build()
        })
        .map_err(|source| ExchangeError::HttpsClient { source })
}

/// Settings every DoH client needs, whatever its trust roots.
pub(crate) fn configure(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder
        // The system proxy can be this process's own listener.
        .no_proxy()
        // A redirect could lead to plaintext HTTP or an unrelated host.
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .connect_timeout(CONNECT_TIMEOUT)
        .pool_idle_timeout(POOL_IDLE_TIMEOUT)
        .pool_max_idle_per_host(2)
}

/// Sends `query` to `url` with POST and checks the answer against it.
pub(crate) async fn exchange(
    client: &reqwest::Client,
    url: &Url,
    query: &Query,
    deadline: Instant,
) -> Result<Answer, ExchangeError> {
    let request = async {
        // The error would otherwise print the URL, whose path or query can
        // hold an account token.
        let mut response = client
            .post(url.clone())
            .header(CONTENT_TYPE, DNS_MESSAGE)
            .header(ACCEPT, DNS_MESSAGE)
            .body(query.bytes().to_vec())
            .send()
            .await
            .map_err(reqwest::Error::without_url)
            .context(HttpsSnafu)?;
        let status = response.status();
        if !status.is_success() {
            return Err(ExchangeError::HttpStatus { status });
        }
        let is_dns_message = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case(DNS_MESSAGE));
        if !is_dns_message {
            return Err(ExchangeError::ContentType);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_MESSAGE as u64)
        {
            return Err(ExchangeError::Oversized);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(reqwest::Error::without_url)
            .context(HttpsSnafu)?
        {
            if body.len() + chunk.len() > MAX_MESSAGE {
                return Err(ExchangeError::Oversized);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    };
    let body = tokio::time::timeout_at(deadline, request)
        .await
        .map_err(|_| ExchangeError::TimedOut)??;
    // TLS already rules out injection, so a TC bit only means the server
    // could not fit the whole answer; the addresses present are still its own.
    wire::parse(query, &body)
        .map(|response| response.answer)
        .map_err(ExchangeError::from)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::convert::Infallible;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;

    use http_body_util::{BodyExt, Full};
    use hyper::body::{Bytes, Incoming};
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::dns::wire::tests::{addresses_reply_to, name};
    use crate::dns::wire::{Family, Layout};

    const CERT: &[u8] = include_bytes!("../../tests/fixtures/quic-cert.pem");
    const KEY: &[u8] = include_bytes!("../../tests/fixtures/quic-key.pem");
    const REAL: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 20));

    /// What the test server does with a well-formed DoH request body.
    pub(crate) type Handler = Arc<dyn Fn(&[u8]) -> Response<Full<Bytes>> + Send + Sync>;

    pub(crate) fn dns_response(body: Vec<u8>) -> Response<Full<Bytes>> {
        Response::builder()
            .header(CONTENT_TYPE, DNS_MESSAGE)
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    /// A DoH server on loopback, presenting the localhost test certificate.
    pub(crate) async fn fake_server(handler: Handler) -> SocketAddr {
        let certificate = CertificateDer::from_pem_slice(CERT).unwrap();
        let key = PrivateKeyDer::from_pem_slice(KEY).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    let Ok(stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |request: Request<Incoming>| {
                        let handler = Arc::clone(&handler);
                        async move {
                            let valid = request.method() == hyper::Method::POST
                                && request.uri().path() == "/dns-query"
                                && request
                                    .headers()
                                    .get(CONTENT_TYPE)
                                    .is_some_and(|value| value == DNS_MESSAGE);
                            let body = request.into_body().collect().await.unwrap().to_bytes();
                            let response = if valid {
                                handler(&body)
                            } else {
                                Response::builder()
                                    .status(StatusCode::BAD_REQUEST)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap()
                            };
                            Ok::<_, Infallible>(response)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        address
    }

    /// A DoH client that trusts only the test certificate.
    pub(crate) fn trusting_client() -> reqwest::Client {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(CERT).unwrap())
            .unwrap();
        client_with_roots(roots)
    }

    fn client_with_roots(roots: rustls::RootCertStore) -> reqwest::Client {
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        configure(reqwest::Client::builder().tls_backend_preconfigured(tls))
            .build()
            .unwrap()
    }

    pub(crate) fn url(server: SocketAddr) -> Url {
        Url::parse(&format!("https://{server}/dns-query")).unwrap()
    }

    fn query() -> Query {
        Query::new(&name("node.example"), Family::V4, 0, Layout::Padded)
    }

    async fn exchange_with(
        handler: Handler,
        client: &reqwest::Client,
    ) -> Result<Answer, ExchangeError> {
        let server = fake_server(handler).await;
        let deadline = Instant::now() + Duration::from_secs(5);
        exchange(client, &url(server), &query(), deadline).await
    }

    #[tokio::test]
    async fn verified_server_answer_is_returned() {
        let handler: Handler = Arc::new(|request: &[u8]| {
            // RFC 8484 §4.1: the ID is zero, and the query is padded.
            assert_eq!(&request[..2], [0, 0]);
            assert_eq!(request.len() % 128, 0);
            dns_response(addresses_reply_to(request, &[REAL]))
        });
        let answer = exchange_with(handler, &trusting_client()).await.unwrap();
        assert_eq!(
            answer,
            Answer::Addresses {
                addresses: vec![REAL],
                ttl: 300
            }
        );
    }

    #[tokio::test]
    async fn untrusted_certificate_fails_closed() {
        let handler: Handler =
            Arc::new(|request: &[u8]| dns_response(addresses_reply_to(request, &[REAL])));
        let client = client_with_roots(rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ));
        let error = exchange_with(handler, &client).await.unwrap_err();
        assert!(matches!(error, ExchangeError::Https { .. }), "{error}");
    }

    #[tokio::test]
    async fn wrong_content_type_is_rejected() {
        let handler: Handler = Arc::new(|request: &[u8]| {
            let mut response = dns_response(addresses_reply_to(request, &[REAL]));
            response
                .headers_mut()
                .insert(CONTENT_TYPE, "application/dns-json".parse().unwrap());
            response
        });
        let error = exchange_with(handler, &trusting_client())
            .await
            .unwrap_err();
        assert!(matches!(error, ExchangeError::ContentType), "{error}");
    }

    #[tokio::test]
    async fn content_type_parameters_are_accepted() {
        let handler: Handler = Arc::new(|request: &[u8]| {
            let mut response = dns_response(addresses_reply_to(request, &[REAL]));
            response.headers_mut().insert(
                CONTENT_TYPE,
                "Application/DNS-Message; charset=binary".parse().unwrap(),
            );
            response
        });
        assert!(exchange_with(handler, &trusting_client()).await.is_ok());
    }

    #[tokio::test]
    async fn error_status_and_redirects_are_not_followed() {
        for status in [
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::MOVED_PERMANENTLY,
        ] {
            let handler: Handler = Arc::new(move |_: &[u8]| {
                Response::builder()
                    .status(status)
                    .header(hyper::header::LOCATION, "http://127.0.0.1/dns-query")
                    .header(CONTENT_TYPE, DNS_MESSAGE)
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            });
            let error = exchange_with(handler, &trusting_client())
                .await
                .unwrap_err();
            assert!(
                matches!(error, ExchangeError::HttpStatus { status: got } if got == status),
                "{error}"
            );
        }
    }

    #[tokio::test]
    async fn oversized_body_is_rejected() {
        let handler: Handler = Arc::new(|_: &[u8]| dns_response(vec![0; MAX_MESSAGE + 1]));
        let error = exchange_with(handler, &trusting_client())
            .await
            .unwrap_err();
        assert!(matches!(error, ExchangeError::Oversized), "{error}");
    }

    #[tokio::test]
    async fn answer_for_another_question_is_rejected() {
        let handler: Handler = Arc::new(|_: &[u8]| {
            let other = Query::new(&name("other.example"), Family::V4, 0, Layout::Padded);
            dns_response(addresses_reply_to(other.bytes(), &[REAL]))
        });
        let error = exchange_with(handler, &trusting_client())
            .await
            .unwrap_err();
        assert!(matches!(error, ExchangeError::Mismatched), "{error}");
    }

    #[tokio::test]
    async fn error_reports_do_not_reveal_the_url_path() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let url = Url::parse(&format!("https://{address}/secret-token")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let error = exchange(&trusting_client(), &url, &query(), deadline)
            .await
            .unwrap_err();
        let report = crate::util::error_report(&error);
        assert!(!report.contains("secret-token"), "{report}");
    }
}
