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

### Client

Download `http-proxy-cli` from [releases](https://github.com/acking-you/proxy-everything/releases), then:

```bash
./http-proxy-cli -s YOUR_SERVER_IP -c 7890
```

Configure system proxy to `127.0.0.1:7890` and you're done.

[Full client usage guide →](docs/client-usage.md)

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
- Transparent proxy chain mode
- Multi-platform support
