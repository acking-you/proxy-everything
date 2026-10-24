# CipherRelay（密流）

A self-hosted encrypted proxy: a Rust server, a local HTTP/HTTPS/SOCKS5 client
and a Flutter app for Windows, macOS, Linux, Android and iOS. The repository
and binaries keep their `proxy-everything` names; protocols and application
identifiers stay compatible.

```
App ─► local client (HTTP · SOCKS5 · TUN) ══ encrypted, over TCP or QUIC ══► server ─► Internet
                                                                               └─► relay ─► …
```

## Features

- **Encrypted native sessions**: TCP, UDP and ICMP payloads are always
  encrypted (AES-256-GCM), node probes included.
- **Wire protocols**: legacy, the default, works with every deployed node; v3
  needs no extra round trip.
- **Carriers**: TCP by default, or TLS 1.3 QUIC per node. A switch affects new
  sessions only.
- **Local proxy**: HTTP, HTTPS CONNECT and SOCKS5, including UDP ASSOCIATE, on
  one port. Optionally sets the system proxy.
- **TUN capture**: whole-device capture with process bypass and loop prevention
  on desktop; the platform VPN API on mobile.
- **Routing**: geo-based direct or proxy decisions, a reverse mode and keyword lists.
- **Control plane**: nodes, groups, relay chains with load balancing, metrics
  and a managed SOCKS5 endpoint that rejects mainland China source IPs
  (Hong Kong, Macao and Taiwan remain eligible).
- **App proxies**: send single apps through the proxy without TUN (macOS and Windows).

## Quick start

### Server

```bash
docker run -d --name proxy-server --restart=always -p 1081:1081 \
  -e SECRET_KEY=your-32-char-secret-key \
  ackingliu/http2-server:latest
```

Open TCP 1081 in the firewall and use a private 32-byte `SECRET_KEY`. The
one-line systemd installer, multiple instances and every variable are in
[server deployment](docs/server-deployment.md) and [systemd](docs/systemd-deployment.md).
QUIC needs an additional UDP listener and a certificate: [QUIC carrier](docs/quic-transport.md).

### App

Install CipherRelay from the [app releases](https://github.com/Proxy-UI/Proxy-UI-Flutter/releases),
add the server as a node, and connect. Per-platform notes are in [client usage](docs/client-usage.md).

### CLI

Download `http-proxy-cli` from the [releases](https://github.com/acking-you/proxy-everything/releases):

```bash
./http-proxy-cli -s YOUR_SERVER -c 7890 --set-system-proxy   # TCP
./http-proxy-cli -s quic://YOUR_SERVER:10811 -c 7890         # QUIC
./http-proxy-cli -s YOUR_SERVER -c 7890 --tun                # capture all traffic (administrator)
```

Without `--set-system-proxy`, point applications at `127.0.0.1:7890` (HTTP or
SOCKS5). Options, TOML configuration, SOCKS5 UDP and TUN are covered in
[client usage](docs/client-usage.md).

## Transport choices

| Setting | Default | Alternative | Before switching |
| --- | --- | --- | --- |
| Wire protocol | legacy | v3: `PROXY_WIRE_PROTOCOL=v3` or the app toggle | Upgrade every relay and server; `PROXY_REQUIRE_V3=1` then rejects legacy ([v3](docs/secure-transport-v3.md)) |
| Carrier | TCP: a bare `host` | QUIC: `quic://host:port` | Deploy a QUIC listener with a certificate ([QUIC](docs/quic-transport.md)) |

The two combine freely, and neither changes what a session carries.
Compatibility and recovery behaviour: [network resilience](docs/network-resilience.md).

## Management

| Tool | Purpose |
| --- | --- |
| `proxy-tui` | Terminal monitor and runtime configuration of nodes, groups, relay and metrics |
| `http-proxy-admin` | Scriptable control CLI with JSON output, including managed SOCKS5 |

```bash
proxy-tui -H 127.0.0.1 -p 1081 -k SESSION_KEY --token ADMIN_TOKEN
http-proxy-admin -H 127.0.0.1 -p 1081 -k SESSION_KEY ping
```

In the TUI, the `Nodes` tab takes `host:port`, while the `Relay` tab needs a
typed target such as `node host:port`, `group_ref asia` or a full proxy URL.
See [TUI and admin CLI](docs/metrics-monitoring.md), [dynamic relay](docs/dynamic-relay-config.md)
and [managed SOCKS5](docs/managed-socks5.md).

## Documentation

- **Use and deploy**: [client usage](docs/client-usage.md) ·
  [server (Docker)](docs/server-deployment.md) · [systemd](docs/systemd-deployment.md) ·
  [QUIC carrier](docs/quic-transport.md) · [managed SOCKS5](docs/managed-socks5.md) ·
  [dynamic relay](docs/dynamic-relay-config.md) · [metrics and management](docs/metrics-monitoring.md) ·
  [Android VPN](docs/android-vpn.md) · [iOS](docs/ios-development.md) ·
  [Mac App Store edition](docs/mac-app-store.md)
- **Protocols and design**: [v3 wire protocol](docs/secure-transport-v3.md) ·
  [network resilience](docs/network-resilience.md) · [TUN ICMP echo](docs/tun-icmp-echo.md) ·
  [node probe batching](docs/node-probe-batch.md) · [Rust UI runtime](docs/rust-ui-runtime.md) ·
  [galaxy geometry](docs/galaxy-geometry.md)
- **Operations and records**: [releasing](docs/releasing.md) ·
  [admin test script](docs/admin-test.md) · [QUIC validation](docs/quic-validation.md) ·
  [node sync incident](docs/node-sync-incident.md) · [memory investigation](docs/memory-usage-investigation.md)

## Development

```bash
cargo build --workspace
cargo test --workspace
```

On Windows (MSVC toolchain, VS 2022 Build Tools with C++, CMake, FVM):

```powershell
.\scripts\windows\build.ps1 -Configuration Debug   # Rust, FFI DLL and the Flutter app
.\scripts\windows\run-ui.ps1                       # app with hot reload
```

The Flutter app lives in the `ui/flutter` submodule and runs only through FVM.
`proxy-core` owns the single mimalloc build (`deps/better_mimalloc_rs`) used by
every binary and the FFI library. Layout, checks, compatibility rules and
packaging are in [AGENTS.md](AGENTS.md); release steps are in [releasing](docs/releasing.md).

## Editions and naming

Every platform shows **CipherRelay** (`CipherRelay.exe`, `CipherRelay`,
`CipherRelay.app`). Bundle and package IDs, storage, protocols and Windows
single-instance keys are unchanged from Proxy UI, so upgrades keep their
settings. macOS has two editions: the direct download (a Developer ID DMG with
system proxy, TUN helper, LAN access and process bypass) and a sandboxed Mac App
Store edition with a Packet Tunnel and separate settings
([Mac App Store](docs/mac-app-store.md)). For release file names, see
[client packaging](ui/flutter/README.md#application-and-package-names).
