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

## Documentation

- [Server Deployment (Docker)](docs/server-deployment.md) - Docker deployment guide
- [Server Deployment (Systemd)](docs/systemd-deployment.md) - Binary + systemd deployment
- [Client Usage](docs/client-usage.md) - Windows, Linux, macOS, Android, iOS
- [Admin Test Script](docs/admin-test.md) - How to run `http-proxy-admin` control-plane tests
- [Metrics Monitoring](docs/metrics-monitoring.md) - TUI + admin CLI for realtime metrics

## Features

- AES-256-GCM encryption
- HTTP/HTTPS/SOCKS5 proxy support
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
