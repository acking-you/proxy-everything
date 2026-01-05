# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Build
cargo build                          # Debug build
cargo build --release                # Release build
make build-cli-release               # Build CLI (recommended client)
make build-client-release            # Build simple client
make build-server-release            # Build server

# Test
cargo test                           # Run all tests
cargo test <test_name>               # Run single test

# Run binaries
cargo run --bin http-proxy-cli -- -s <server-ip> -c <local-port>
cargo run --bin http-proxy-server -- -h 0.0.0.0 -p 1081
```

## Architecture

Three-layer proxy system with AES-256-GCM encryption:

```
Application → Client (local:1080) → [encrypted] → Server (remote:1081) → Destination
```

### Key Modules

- `src/lib.rs` - Core encryption (`Aes256GcmCryption`), `ProxyHeader`, and bidirectional forwarding functions
- `src/client/mod.rs` - Client entry point, `ForwarderProvider` trait for protocol abstraction
- `src/client/http.rs` - HTTP/HTTPS CONNECT handling
- `src/client/socks.rs` - SOCKS5 protocol implementation
- `src/client/auto_proxy.rs` - Geo-based routing via ip-api.com (CN=direct, others=proxy; reversible via `REVERSE_GEO_PROXY`)
- `src/server/mod.rs` - Server-side decryption and forwarding, supports transparent proxy chaining
- `src/codec/mod.rs` - `AsyncEncryptCodec`/`AsyncDecryptCodec`/`AsyncNormalCodec` for stream processing
- `src/config/mod.rs` - Environment variable configuration (`SERVER_HOST`, `CLIENT_PORT`, `SECRET_KEY`, etc.)

### Wire Protocol

```
[4-byte checksum][4-byte length][encrypted data][16-byte auth tag]
```

### Feature Flags

- `tokio` (default) - Tokio runtime
- `monoio` - Monoio runtime (io_uring)
- `auto-proxy` (default) - Geo-based auto routing
- `cli-dep` (default) - CLI argument parsing

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_HOST` | Remote proxy server address | - |
| `SERVER_PORT` | Remote proxy server port | 1081 |
| `CLIENT_PORT` | Local listening port | 1080 |
| `SECRET_KEY` | 32-byte encryption key | - |
| `PROXY_KEYWORDS` | Domains to proxy (comma-separated) | google,youtube,github... |
| `NONPROXY_KEYWORDS` | Domains to direct connect | bilibili,baidu,taobao... |
| `REVERSE_GEO_PROXY` | Reverse geo logic (CN=proxy, others=direct) | false |
| `TURELY_PROXY_SERVER` | Transparent proxy chain target | - |

## Toolchain

Rust stable 1.87.0 (see `rust-toolchain.toml`)
