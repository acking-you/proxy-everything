//! A separate test process starts without an implicitly installed TLS provider.
#[test]
fn http_clients_initialize_tls_without_external_setup() {
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    for _ in 0..2 {
        proxy_core::util::http_client_builder()
            .no_proxy()
            .https_only(true)
            .build()
            .expect("HTTPS client must initialize without a provider panic");
    }
    assert!(rustls::crypto::CryptoProvider::get_default().is_some());
}
