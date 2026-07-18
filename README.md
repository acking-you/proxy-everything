# proxy-everything

A lightweight encrypted proxy with AES-256-GCM encryption.

```
Client (local) ──► [encrypted] ──► Server (remote) ──► Internet
```

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

- [Server Deployment (Docker)](docs/server-deployment.md) - Docker deployment guide
- [Server Deployment (Systemd)](docs/systemd-deployment.md) - Binary + systemd deployment
- [Client Usage](docs/client-usage.md) - Windows, Linux, macOS, Android, iOS
- [Admin Test Script](docs/admin-test.md) - How to run `http-proxy-admin` control-plane tests
- [Metrics Monitoring](docs/metrics-monitoring.md) - TUI + admin CLI for management and realtime metrics

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
`http_proxy.dll` before invoking the project-pinned Flutter SDK:

```powershell
.\scripts\windows\run-ui.ps1
```

Run Flutter commands from `ui/flutter` through FVM only, for example
`fvm flutter test` and `fvm dart format lib test`.

## Features

- AES-256-GCM encryption
- HTTP/HTTPS/SOCKS5 proxy support, including SOCKS5 UDP ASSOCIATE
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

The allocator is provided by the vendored `deps/better_mimalloc_rs` submodule,
which gives us predictable tuning behavior for long-running proxy servers. See
`deps/better_mimalloc_rs/README.md` for configuration details.

### RSS tuning

The binaries always use an aggressive RSS-reclaim configuration in code to
prioritize faster memory return under load.
