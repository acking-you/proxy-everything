# proxy-everything

Lightweight encrypted proxy system establishing secure tunnels between client and server using AES-256-GCM.

## Overview

**Core Features**:
- Encrypted proxy service (HTTP/HTTPS/SOCKS5)
- Geo-based intelligent routing (CN direct, overseas via proxy)
- Cross-platform support (Linux/macOS/Windows/Android/iOS)
- FFI interface for Flutter UI integration

**Data Flow**:
```
Application → Client(local:1080) → [AES-256-GCM] → Server(remote:1081) → Target
```

## Architecture

### Component Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Flutter UI   │  │ CLI Client   │  │ TUI Monitor  │      │
│  │ (ui/flutter) │  │ (http-proxy- │  │ (proxy-tui)  │      │
│  │              │  │  cli)        │  │              │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │ FFI             │ Direct          │ Direct        │
└─────────┼─────────────────┼─────────────────┼──────────────┘
          │                 │                 │
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────┐
│                      Proxy Core Layer                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Client (crates/proxy-client/)                        │   │
│  │  ├─ HTTP/HTTPS Handler (http.rs)                    │   │
│  │  ├─ SOCKS5 Handler (socks.rs)                       │   │
│  │  └─ Auto Proxy (auto_proxy.rs) - Geo routing        │   │
│  └──────────────────────────────────────────────────────┘   │
│                         │ Encryption                         │
│                         ▼                                    │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Codec Layer (crates/proxy-core/src/codec/)           │   │
│  │  ├─ AsyncEncryptCodec - Encrypt stream              │   │
│  │  ├─ AsyncDecryptCodec - Decrypt stream              │   │
│  │  └─ AsyncNormalCodec - Plaintext passthrough        │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                         │ Network
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                      Server Layer                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Server (crates/proxy-server/)                        │   │
│  │  ├─ Decrypt ProxyHeader                             │   │
│  │  ├─ Connect to target                               │   │
│  │  ├─ Bidirectional forwarding                        │   │
│  │  └─ Metrics collection (proxy-core/metrics/)        │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Control Plane (crates/proxy-core/src/control/)       │   │
│  │  ├─ Node management (AddNode/RemoveNode/ListNodes)  │   │
│  │  └─ Metrics query (GetRealtimeStats/GetTopN)        │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Key Modules

| Module | Path | Purpose |
|--------|------|---------|
| **Core** | `crates/proxy-core/src/lib.rs` | Crypto primitives, ProxyHeader, bidirectional forwarding |
| **Client** | `crates/proxy-client/src/client/mod.rs` | Main loop, protocol abstraction (ForwarderProvider) |
| **Server** | `crates/proxy-server/src/server/mod.rs` | Connection handling, metrics collection |
| **Codec** | `crates/proxy-core/src/codec/` | Encrypt/decrypt streams, frame processing |
| **Config** | `crates/proxy-core/src/config/mod.rs` | Environment vars, runtime config (ArcSwap zero-copy) |
| **FFI** | `crates/proxy-ffi/src/lib.rs` | C-compatible interface for Flutter |
| **Metrics** | `crates/proxy-core/src/metrics/mod.rs` | DashMap sharded storage, connection stats |
| **Control** | `crates/proxy-core/src/control/` | Node discovery, metrics query API |
| **Protocol** | `crates/proxy-core/src/protocol/mod.rs` | Data frame format definitions |
| **TUI** | `crates/proxy-tui/src/tui/` | Terminal UI for monitoring |

## Directory Structure

```
proxy-everything/
├── Cargo.toml                    # Workspace root configuration
├── crates/
│   ├── proxy-core/               # Core library (shared by all crates)
│   │   └── src/
│   │       ├── lib.rs            # Core encryption and forwarding logic
│   │       ├── error.rs          # Error types
│   │       ├── transport.rs      # TCP connection helpers
│   │       ├── codec/            # Encrypt/decrypt codecs
│   │       ├── config/           # Configuration and runtime state
│   │       ├── control/          # Control plane protocol
│   │       ├── crypto/           # AES-256-GCM encryption
│   │       ├── geo/              # GeoIP lookup
│   │       ├── metrics/          # Connection metrics
│   │       ├── nodes/            # Node management
│   │       ├── protocol/         # Wire protocol definitions
│   │       └── util/             # Utilities
│   ├── proxy-client/             # Client implementation
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── cli_config.rs     # CLI configuration
│   │       ├── client/           # HTTP/HTTPS/SOCKS5 handlers
│   │       └── bin/main.rs       # http-proxy-cli binary
│   ├── proxy-server/             # Server implementation
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── server/           # Server logic
│   │       └── bin/main.rs       # http-proxy-server binary
│   ├── proxy-tui/                # TUI monitoring interface
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── tui/              # TUI components
│   │       └── bin/main.rs       # proxy-tui binary
│   └── proxy-ffi/                # FFI interface for Flutter
│       └── src/lib.rs            # C-compatible interface
├── ui/flutter/                   # Flutter UI (submodule)
├── deps/                         # External dependencies (submodules)
│   ├── sysproxy-rs/              # System proxy library
│   └── kanal/                    # Channel library
├── .github/workflows/
│   ├── build-deploy.yaml         # Build binaries and FFI libs
│   └── cargo-test.yaml           # CI tests
└── config.template.toml          # Configuration template
```

## Build & Test

### Build Commands

```bash
# Debug build (all crates)
cargo build --workspace

# Release build (all crates)
cargo build --workspace --release

# Build specific crate
cargo build -p proxy-client --release
cargo build -p proxy-server --release
cargo build -p proxy-tui --release

# Build FFI library (for Flutter)
cargo build -p proxy-ffi --release
```

### Test Commands

```bash
# Run all tests
cargo test --workspace

# Run specific test
cargo test <test_name>

# Run clippy checks
cargo clippy --workspace --all-targets
```

### Run Binaries

```bash
# Run server
cargo run -p proxy-server -- -H 0.0.0.0 -p 1081

# Run CLI client
cargo run -p proxy-client -- -s <server-ip> -c <local-port>

# Run TUI monitor
cargo run -p proxy-tui
```

## Workspace Structure

| Crate | Description | Binary |
|-------|-------------|--------|
| `proxy-core` | Core library (crypto, codec, config, protocol) | - |
| `proxy-client` | Client implementation | `http-proxy-cli` |
| `proxy-server` | Server implementation | `http-proxy-server` |
| `proxy-tui` | TUI monitoring interface | `proxy-tui` |
| `proxy-ffi` | FFI interface for Flutter | `libhttp_proxy.so/dylib/dll` |

## Feature Flags

| Crate | Feature | Default | Description |
|-------|---------|---------|-------------|
| `proxy-core` | `auto-proxy` | ✓ | Geo-based auto routing dependencies |
| `proxy-client` | `auto-proxy` | ✓ | Enable auto-proxy in client |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_HOST` | Remote proxy server address | 127.0.0.1 |
| `SERVER_PORT` | Remote proxy server port | 1081 |
| `CLIENT_PORT` | Local listening port | 1080 |
| `SECRET_KEY` | 32-byte encryption key | `my-secret-key123my-secret-key123` |
| `PROXY_KEYWORDS` | Domain keywords to proxy (comma-separated) | google,youtube,github... |
| `NONPROXY_KEYWORDS` | Domain keywords for direct connection | bilibili,baidu,taobao... |
| `REVERSE_GEO_PROXY` | Reverse geo logic (CN=proxy, overseas=direct) | false |
| `TURELY_PROXY_SERVER` | Transparent proxy chain target (ip:port) | - |
| `NEED_CODEC_IP` | Server IPs requiring encryption | SERVER_HOST + 64.23.159.180 |

## Release Workflow

### Version Numbering Rules

**IMPORTANT**: Always use `0.4.x` series for stable releases, NOT `0.5.x`.

- **Stable releases**: `0.4.0`, `0.4.1`, `0.4.2`, ... `0.4.14`, `0.4.15`, etc.
- **Experimental releases**: `0.5.0`, `0.5.1` (reserved for experimental features)

**Reason**: The `0.5.x` series is reserved for experimental and unstable features. All production releases should increment the `0.4.x` series to maintain stability and compatibility.

When creating a new release tag:
```bash
# Check latest 0.4.x version
git tag --sort=-v:refname | grep "^0\.4\." | head -1

# Create next version (e.g., if latest is 0.4.14, create 0.4.15)
git tag 0.4.15
git push origin 0.4.15
```

### 1. Create Tag to Trigger Build

```bash
# Create tag in proxy-everything repo
git tag 0.4.12
git push origin 0.4.12
```

This triggers `.github/workflows/build-deploy.yaml` to build:
- **Binaries**: `http-proxy-cli-{VERSION}-{TARGET}.tar.gz`, `http-proxy-server-{VERSION}-{TARGET}.tar.gz`
- **FFI libs**: `libhttp_proxy-{VERSION}-{TARGET}.tar.gz` (contains `.so`/`.dylib`/`.dll`/`.a`)

### 2. Trigger Flutter UI Build

```bash
# Use gh CLI to trigger Flutter UI build
gh workflow run build.yaml \
  --repo Proxy-UI/Proxy-UI-Flutter \
  -f lib_version=0.4.12 \
  -f create_release=true \
  -f release_tag=v0.4.12
```

Flutter UI workflow will:
1. Download FFI libs from `acking-you/proxy-everything` for the specified version
2. Place libs in platform directories (android/ios/macos/windows/linux)
3. Build Flutter apps for all platforms
4. Create GitHub Release

### 3. Release Artifacts

**proxy-everything Release**:
- `http-proxy-cli-0.4.12-x86_64-unknown-linux-musl.tar.gz` - Linux CLI client
- `http-proxy-server-0.4.12-x86_64-unknown-linux-musl.tar.gz` - Linux server
- `libhttp_proxy-0.4.12-aarch64-linux-android.tar.gz` - Android ARM64 FFI lib
- `libhttp_proxy-0.4.12-aarch64-apple-ios.tar.gz` - iOS ARM64 FFI lib
- ... (other platforms)

**Flutter UI Release**:
- `proxy_with_flutter-windows-amd64-portable.zip` - Windows portable
- `proxy_with_flutter-windows-amd64_setup.zip` - Windows installer
- `proxy_with_flutter-linux.zip` - Linux archive
- `proxy_with_flutter-linux.AppImage` - Linux AppImage
- `proxy_with_flutter-arm64.apk` - Android ARM64
- `proxy_with_flutter-macos.dmg` - macOS DMG

## FFI Interface

### Core Functions

```rust
// Create proxy handle
pub extern "C" fn proxy_create() -> *mut ProxyHandle

// Start proxy
pub extern "C" fn proxy_start(
    handle: *mut ProxyHandle,
    config: *const ProxyConfig
) -> i32

// Stop proxy
pub extern "C" fn proxy_stop(handle: *mut ProxyHandle) -> i32

// Destroy handle
pub extern "C" fn proxy_destroy(handle: *mut ProxyHandle)

// Set log callback
pub extern "C" fn proxy_set_log_callback(
    callback: extern "C" fn(*const c_char, *const c_char, *const c_char)
)
```

### ProxyConfig Structure

```rust
#[repr(C)]
pub struct ProxyConfig {
    pub server_host: *const c_char,      // Server address
    pub server_port: u16,                // Server port
    pub local_port: u16,                 // Local listening port
    pub session_key: *const c_char,      // Session key (optional)
    pub auto_proxy: bool,                // Enable auto proxy
    pub reverse_geo: bool,               // Reverse geo logic
    pub cache_dir: *const c_char,        // Cache directory
    pub need_codec_ips: *const c_char,   // IPs requiring encryption (comma-separated)
    pub force_codec: bool,               // Force encryption for all connections
    pub set_system_proxy: bool,          // Set system proxy (desktop only)
}
```

### Flutter Integration Example

```dart
// lib/src/ffi/proxy_ffi.dart
final DynamicLibrary _lib = Platform.isAndroid
    ? DynamicLibrary.open('libhttp_proxy.so')
    : Platform.isIOS
        ? DynamicLibrary.process()
        : Platform.isMacOS
            ? DynamicLibrary.open('libhttp_proxy.dylib')
            : Platform.isWindows
                ? DynamicLibrary.open('http_proxy.dll')
                : DynamicLibrary.open('libhttp_proxy.so');

final proxyCreate = _lib.lookupFunction<
    Pointer<ProxyHandle> Function(),
    Pointer<ProxyHandle> Function()>('proxy_create');

final proxyStart = _lib.lookupFunction<
    Int32 Function(Pointer<ProxyHandle>, Pointer<ProxyConfig>),
    int Function(Pointer<ProxyHandle>, Pointer<ProxyConfig>)>('proxy_start');
```

## Wire Protocol

### ProxyHeader (JSON, AES-256-GCM encrypted)

```json
{
  "host": "example.com",
  "port": 443,
  "key": "optional-session-key"
}
```

### Data Frame Format

```
[4-byte checksum][4-byte length][encrypted data][16-byte auth tag]

Checksum = length XOR key_hash
Max data size = 30MB
```

## Design Decisions

### Performance
- **Zero-copy config**: `ArcSwap` for lock-free config reads
- **DashMap sharding**: Reduces lock contention in metrics storage
- **Connection pooling**: Auto proxy uses `kanal` channels for batch query processing

### Security
- **AES-256-GCM**: Provides encryption and authentication
- **Checksum validation**: Prevents length field tampering
- **Max data size**: 30MB limit prevents memory exhaustion attacks

### Extensibility
- **Protocol abstraction**: `ForwarderProvider` trait supports adding new protocols
- **Control plane**: Supports node discovery and cluster management
- **Transparent proxy chain**: `TURELY_PROXY_SERVER` enables multi-level proxying

## Submodule Management

```bash
# Initialize all submodules
git submodule update --init --recursive

# Update submodules to latest version
git submodule update --remote

# Check submodule status
git submodule status
```

**Submodules**:
- `deps/sysproxy-rs` - System proxy library (https://github.com/zzzgydi/sysproxy-rs.git)
- `ui/flutter` - Flutter UI (https://github.com/Proxy-UI/Proxy-UI-Flutter.git)

## Troubleshooting

### Common Issues

**1. FFI Library Loading Failure**
- Check library file is in correct directory
- Android: `android/app/src/main/jniLibs/{abi}/libhttp_proxy.so`
- iOS: Ensure static library is linked to Xcode project
- macOS: `Frameworks/libhttp_proxy.dylib`

**2. Connection Failure**
- Check `SERVER_HOST` and `SERVER_PORT` configuration
- Verify server is running: `netstat -an | grep 1081`
- Check firewall rules

**3. Auto Proxy Not Working**
- Check `auto-proxy` feature is enabled
- View cache file: `~/http-proxy-cli-config/proxy-cache.txt`
- Check ip-api.com accessibility

**4. System Proxy Setup Failure**
- Ensure `sysproxy-rs` submodule is initialized
- Check for admin privileges (Windows/macOS)

## References

- **Rust toolchain**: 1.87.0 (see `rust-toolchain.toml`)
- **Crypto library**: `ring` (AES-256-GCM)
- **Async runtime**: `tokio` (default) or `monoio` (io_uring)
- **Flutter version**: 3.38.6 (see `ui/flutter/.github/workflows/build.yaml`)
