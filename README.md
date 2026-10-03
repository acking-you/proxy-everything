# CipherRelay（密流）

A self-hosted encrypted proxy with AES-256-GCM encryption and a cross-platform client.
The source repository remains `proxy-everything`; existing protocol, binary and application identifiers remain compatible.

```
Client (local) ──► [encrypted] ──► Server (remote) ──► Internet
```

## macOS editions

CipherRelay is the new product name for Proxy UI. Both distribution paths remain
available in the source:

| Edition | App bundle | Build target | Distribution |
| --- | --- | --- | --- |
| Direct download | `CipherRelay.app` | `Runner` | Developer ID signed and notarized DMG |
| Mac App Store | `CipherRelay Store.app` | `appstore` / `RunnerStore` | Sandboxed app with Packet Tunnel extension; App Review required |

The direct edition retains its system proxy, privileged TUN helper, LAN access
and process bypass features. The store edition has its own bundle ID and data
container. See [Mac App Store development](docs/mac-app-store.md) for the build
and capability differences. Store preparation does not mean Apple has approved
the app.

Existing bundle/package IDs, Dart imports, executable names on Windows/Linux,
protocols and storage identifiers stay compatible. Repository URLs remain
unchanged. On macOS, replace the previous direct-download app with
`CipherRelay.app`; renaming does not migrate data between the two editions.

## Secure transport migration

Native **0.4.32** and UI **1.2.18+44** add an explicitly selected v2 transport
with fresh connection material and separate direction keys for TCP, UDP and
control traffic. Upgrade all relays/servers first, then enable **Secure transport
v2** or `PROXY_WIRE_PROTOCOL=v2`; after migration, servers can require it with
`PROXY_REQUIRE_V2=1`. Existing profiles retain legacy compatibility and its
nonce-reuse limitation. See [the wire format and migration guide](docs/secure-transport-v2.md).

## Quick Start

### Server

```bash
docker run -d --name proxy-server --restart=always -p 1081:1081 \
  -e SECRET_KEY=your-32-char-secret-key \
  ackingliu/http2-server:latest
```

> Open port 1081 in your cloud firewall first!

[Full server deployment guide →](docs/server-deployment.md)

### Server (binary, one-click systemd)

Installs `http-proxy-server` as a systemd service using the COS binary.
Defaults: `HOST=0.0.0.0`, `PORT=1081`, `SECRET_KEY=my-secret-key123my-secret-key123`.

```bash
curl -fsSL https://mybucket-1331094534.cos.ap-hongkong.myqcloud.com/proxy-everything/install-proxy-server.sh | bash
```

To download a different filename from the same COS bucket:

```bash
curl -fsSL https://mybucket-1331094534.cos.ap-hongkong.myqcloud.com/proxy-everything/install-proxy-server.sh | bash -s -- http-proxy-server-aarch64-unknown-linux-musl.tar.gz
```

For multiple instances on one host, use a unique `SERVICE_NAME` and `PORT`.
Custom service names now get isolated state directories automatically; set
`PROXY_DATA_DIR` only if you want to override that path.

> Change `SECRET_KEY` for production deployments.

### Client

Download `http-proxy-cli` from [releases](https://github.com/acking-you/proxy-everything/releases), then:

```bash
./http-proxy-cli -s YOUR_SERVER_IP -c 7890 --set-system-proxy
```

The `--set-system-proxy` flag auto-configures your OS proxy settings. Without it, configure system proxy to `127.0.0.1:7890` manually.

The Flutter UI keeps its HTTP/SOCKS5 listener on `127.0.0.1` by default. Enable
**Allow LAN** in Proxy Configuration to bind `0.0.0.0` instead. The local
listener has no client authentication, so enable this only on trusted networks
and restrict the port with the host firewall. When enabled, the UI shows a
copyable `http://<Wi-Fi-IP>:<port>` link for other devices on the same network.

[Full client usage guide →](docs/client-usage.md)

#### SOCKS5 UDP

The same local port also supports RFC 1928 `UDP ASSOCIATE`. No separate UDP
listen port is required: a SOCKS5 client opens the TCP control connection on
the configured client port and receives an ephemeral UDP relay address.
UDP is enabled by default in both the CLI and Flutter client. Use
`--udp false`, `udp = false` in the client TOML, or the Flutter configuration
switch when a TCP-only local listener is required.

- UDP datagrams preserve message boundaries while being framed over the
  client/server TCP tunnel.
- `--msg-key` encrypts each UDP tunnel frame as an independent authenticated
  message.
- A configured SOCKS5/SOCKS5H upstream can relay UDP. HTTP CONNECT upstreams
  cannot carry UDP and the association is rejected explicitly.
- SOCKS5 fragmentation (`FRAG != 0`) is not supported and fragmented packets
  are dropped, as permitted by RFC 1928.
- Idle associations expire after 300 seconds. Override this on both client and
  server with `UDP_ASSOCIATION_IDLE_TIMEOUT_SECS`.

System HTTP proxy settings do not redirect application UDP automatically. The
application, TUN adapter, or other ingress must explicitly use SOCKS5 UDP.

#### Local TUN mode

The CLI and Windows Flutter client can capture device traffic through the
bundled `tun2proxy` dependency and forward it to the client's local SOCKS5
listener. This captures TCP and, while SOCKS5 UDP is enabled, UDP without
per-application proxy settings:

```powershell
http-proxy-cli.exe -s YOUR_SERVER_IP -c 7890 --tun
```

TUN always targets `socks5://127.0.0.1:<client-port>`; the same local port also
continues accepting HTTP proxy requests. Native code prevents loops at three
levels: it forces client-owned sessions through the configured remote proxy,
installs physical routes for every resolved remote proxy address, and keeps the
client executable in the process-bypass policy. Additional processes can bypass
TUN with repeatable `--tun-bypass-process` options. Use `--tun-list-processes`
to list currently running Windows executable names.

Windows setup leaves every existing default route untouched and captures IPv4
with two owned `/1` routes. Shutdown and hot switching cancel all managed TUN
sessions before restoring only those exact routes and the previous DNS state;
the cleanup path never performs a broad deletion of `0.0.0.0/0`.

TUN mode requires administrator privileges. The Windows CLI requests UAC
elevation in the existing terminal. The Flutter application normally runs
unelevated and requests UAC only when its top-level TUN switch is enabled after
the local listener has started; the elevated replacement remains a GUI process
and does not open a terminal. Windows builds bundle `wintun.dll` next to the
CLI or UI executable. See the [client usage guide](docs/client-usage.md#tun-mode)
for configuration and runtime process updates.

### Proxy TUI

`proxy-tui` is a control-plane monitor and runtime config tool. It is not a
local forwarding client like `http-proxy-cli`, and it does not turn on system
proxy settings for you.

Build and run:

```bash
cargo build --release -p proxy-tui
./target/release/proxy-tui -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY --token YOUR_ADMIN_TOKEN
```

Key differences inside the UI:

- `Nodes` tab: `a` adds a node and expects plain `host:port`
- `Groups` tab: add or remove existing node IDs from a group
- `Relay` tab: `a` adds a relay target and expects a typed target spec, not a bare address

Relay target formats:

- `node <host:port> [weight]`
- `node_ref <node_id> [weight]`
- `group_ref <group_id>`
- `proxy <proxy_url> [weight]`
- `socks5://user:pass@host:port [weight]`
- `socks5h://user:pass@host:port [weight]`
- `http://user:pass@host:port [weight]`

Typical relay flow:

1. Add an upstream server in `Nodes` with `host:port` if you want to manage it as a named node.
2. Optionally create a group and add node IDs into that group.
3. Switch to `Relay`, press `a`, then enter one of:
   - `node 44.218.33.171:1081`
   - `node_ref 44.218.33.171:1081`
   - `group_ref asia`
   - `proxy socks5://relay-user:secret@44.218.33.171:1080`
   - `http://relay-user:secret@44.218.33.171:8080`
4. Press `e` to enable relay if it is still disabled.

Proxy relay notes:

- `socks5://` uses local DNS resolution before dialing the proxy target.
- `socks5h://` sends the original hostname to the SOCKS5 proxy for remote DNS resolution.
- Username/password auth is supported for both SOCKS5 and HTTP CONNECT proxies.
- Relay status and the TUI redact proxy passwords from displayed target addresses.

Common pitfall:

- In the `Relay` tab, entering only `44.218.33.171:1081` will fail with `Unknown target type`.
  That input works in `Nodes`, but `Relay` requires the target type prefix such as `node`.
- In the `Relay` tab, a bare proxy URL is valid because the scheme already identifies the target type.
  For example, `socks5://user:pass@44.218.33.171:1080` works, but `44.218.33.171:1080` does not.
- In the current implementation, a node ID is usually the same as the `host:port`
  you added earlier, so `node_ref 44.218.33.171:1081` can be valid after the node
  has already been registered.

[Dynamic relay guide →](docs/dynamic-relay-config.md)

### Admin CLI

`http-proxy-admin` is the script-friendly control-plane CLI. It prints JSON
responses compatible with the control protocol and supports:

- `ping`
- `nodes list/add/remove`
- `groups list/create/delete/add-node/remove-node`
- `relay get/status/enable/disable/add-target/remove-target/set-algo`
- `metrics realtime/connections/buckets/top-n`

Build and run:

```bash
cargo build --release --bin http-proxy-admin
./target/release/http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY ping
```

[Metrics & management guide →](docs/metrics-monitoring.md)

## Documentation

- [Network resilience review](docs/network-resilience.md) - 0.4.31 / UI 1.2.17+43 recovery fixes, limits, validation, and remaining legacy protocol risk
- [Server Deployment (Docker)](docs/server-deployment.md) - Docker deployment guide
- [Server Deployment (Systemd)](docs/systemd-deployment.md) - Binary + systemd deployment
- [Client Usage](docs/client-usage.md) - Windows, Linux, macOS, Android, iOS
- [Mac App Store development](docs/mac-app-store.md) - Sandboxed app and Packet Tunnel build
- [Admin Test Script](docs/admin-test.md) - How to run `http-proxy-admin` control-plane tests
- [Metrics Monitoring](docs/metrics-monitoring.md) - TUI + admin CLI for management and realtime metrics

## CipherRelay releases

For a UI release with native changes, first dispatch `build-deploy.yaml` on the
intended source branch with a new `release_version` (for example `0.4.30`).
Manual runs publish the FFI libraries, including the macOS TUN helper, only
after every native build succeeds. They skip server binaries and Docker image
publication. Numeric tag pushes retain the full release workflow.

Then dispatch `ui/flutter/.github/workflows/build.yaml` in
`Proxy-UI/Proxy-UI-Flutter`, passing that native `lib_version`, a new UI
`release_tag`, and `create_release=true`. Wait for all desktop jobs and the
release job to succeed, and inspect the attached macOS, Windows, and Linux
packages. Mobile application packages must be built and signed locally.

## Windows Development

Prerequisites:

- Rust MSVC toolchain selected by `rust-toolchain.toml`
- Visual Studio 2022 Build Tools with Desktop development with C++
- CMake
- FVM 4.x; the Flutter submodule pins Flutter 3.38.6 in `.fvmrc`

Build the Rust command-line programs, FFI DLL, and Flutter Windows app together:

```powershell
.\scripts\windows\build.ps1 -Configuration Debug
```

Run a command-line component and pass its arguments after `--`:

```powershell
.\scripts\windows\run-cli.ps1 server -- -H 127.0.0.1 -p 1081
.\scripts\windows\run-cli.ps1 client -- -s 127.0.0.1 -p 1081 -c 1080
```

Start the Flutter desktop app with hot reload. The script builds and stages
`http_proxy.dll` and `wintun.dll` before invoking the project-pinned Flutter SDK:

```powershell
.\scripts\windows\run-ui.ps1
```

Run Flutter commands from `ui/flutter` through FVM only, for example
`fvm flutter test` and `fvm dart format lib test`.

## Features

- AES-256-GCM encryption
- HTTP/HTTPS/SOCKS5 proxy support, including SOCKS5 UDP ASSOCIATE
- Local TUN capture with mandatory self-process loop prevention
- Auto-routing based on geo-location
- Reverse geo mode (`--reverse-geo`): proxy CN sites, direct for others
- Auto system proxy setup (`--set-system-proxy`): Linux/macOS/Windows
- Transparent proxy chain mode
- Multi-platform support

## Allocator (advanced)

This repo vendors a fork of the Rust mimalloc wrapper at `deps/better_mimalloc_rs`.
It exists to:

- Pin the C allocator to a specific fork (`https://github.com/acking-you/mimalloc`)
- Expose RSS-related tuning knobs at build time and runtime

The allocator is provided by the vendored `deps/better_mimalloc_rs` submodule.
`proxy-core` owns the single process-wide allocator policy, so the client,
server, TUI, administration tools, Flutter FFI library, and embedded TUN stack
all use the same pinned mimalloc build and tuning. See
`deps/better_mimalloc_rs/README.md` for configuration details.

### RSS tuning

Every proxy artifact uses the original aggressive RSS-reclaim configuration in
code to prioritize faster memory return under load. The policy is applied once
before the first Rust allocation rather than being duplicated by each binary.
