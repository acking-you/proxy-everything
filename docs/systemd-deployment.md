# Systemd Deployment Guide

Deploy proxy-server as a native systemd service (without Docker).

## Prerequisites

- Linux server (Ubuntu/Debian/CentOS/RHEL/Arch)
- Root access
- Port 1081 open in firewall

---

## Quick Start

### 1. Download Binary

```bash
# Detect architecture and download
ARCH=$(uname -m)
case $ARCH in
  x86_64)  TARGET="x86_64-unknown-linux-musl" ;;
  aarch64) TARGET="aarch64-unknown-linux-musl" ;;
  *)       echo "Unsupported: $ARCH"; exit 1 ;;
esac

curl -LO "https://github.com/acking-you/proxy-everything/releases/latest/download/http-proxy-server-${TARGET}.tar.gz"
tar -xzf http-proxy-server-*.tar.gz
mv http-proxy-server-*/http-proxy-server /usr/local/bin/
chmod +x /usr/local/bin/http-proxy-server
rm -rf http-proxy-server-*
```

### 2. Create Service

```bash
# Generate random SECRET_KEY
SECRET_KEY=$(head -c 32 /dev/urandom | base64 | head -c 32)
echo "Your SECRET_KEY: $SECRET_KEY"

SERVICE_NAME=proxy-server
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=Proxy Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
Environment="SECRET_KEY=${SECRET_KEY}"
Environment="RUST_LOG=info"
ExecStart=/bin/sh -c 'ulimit -n 65535 && exec /usr/local/bin/http-proxy-server -p 1081'
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
```

### 3. Start Service

```bash
SERVICE_NAME=proxy-server
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
systemctl start ${SERVICE_NAME}
systemctl status ${SERVICE_NAME}
```

---

## Interactive Setup (Alternative)

Use the management script for guided configuration:

```bash
curl -LO https://raw.githubusercontent.com/acking-you/proxy-everything/dev/services/proxy-server-ctl.sh
chmod +x proxy-server-ctl.sh
sudo ./proxy-server-ctl.sh
```

The script prompts for:
- `SECRET_KEY` (32 characters)
- `PORT` (default: 1081)
- `Upstream proxy` (optional, for relay mode)
- `CONTROL_SESSION_KEY` (optional, for encrypted control)
- `Log level` (default: info)

---

## Service Management

| Action | Command |
|--------|---------|
| Start | `systemctl start proxy-server` |
| Stop | `systemctl stop proxy-server` |
| Restart | `systemctl restart proxy-server` |
| Status | `systemctl status proxy-server` |
| Logs (follow) | `journalctl -u proxy-server -f` |
| Logs (last 100) | `journalctl -u proxy-server -n 100` |
| Enable auto-start | `systemctl enable proxy-server` |
| Disable auto-start | `systemctl disable proxy-server` |

> Tip: Replace `proxy-server` with your custom service name if you run multiple instances.

---

## Multiple Instances (Different Ports)

Use a unique systemd service name per port to avoid conflicts:

```bash
# Instance on 1081
SERVICE_NAME=proxy-server-1081
SECRET_KEY=$(head -c 32 /dev/urandom | base64 | head -c 32)
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=Proxy Server (1081)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
Environment="SECRET_KEY=${SECRET_KEY}"
Environment="RUST_LOG=info"
ExecStart=/bin/sh -c 'ulimit -n 65535 && exec /usr/local/bin/http-proxy-server -p 1081'
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${SERVICE_NAME}
```

Repeat with a different `SERVICE_NAME` and `-p` value (for example `proxy-server-1082` on port `1082`).

---

## Configuration

### Environment Variables

Add to service file under `[Service]` section:

```ini
Environment="SECRET_KEY=your-32-character-secret-key!!"
Environment="RUST_LOG=info"
Environment="TURELY_PROXY_SERVER=upstream:1081"        # Optional: initial relay target
Environment="CONTROL_SESSION_KEY=another-32-char-key"  # Optional: control encryption
Environment="CONTROL_ADMIN_TOKEN=admin-token"          # Optional: admin auth
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | Yes | - | 32-character encryption key |
| `SERVER_PORT` | No | 1081 | Listening port |
| `TURELY_PROXY_SERVER` | No | - | Initial upstream (auto-added to relay) |
| `RUST_LOG` | No | info | Log level: error/warn/info/debug |
| `CONTROL_SESSION_KEY` | No | - | 32-char key for control encryption |
| `CONTROL_ADMIN_TOKEN` | No | - | Admin token for privileged ops |
| `NODE_ID` | No | auto | Stable node identifier |
| `NODE_ADVERTISE_ADDR` | No | auto | Address for node sync |

### Data Persistence

Configuration stored in `~/.proxy-everything/`:

| File | Content |
|------|---------|
| `nodes.json` | Registered nodes and groups |
| `relay.json` | Relay targets and load balancing |

Files persist across restarts. Edit manually or via control protocol.

---

## Advanced Configuration

### Relay Mode with Load Balancing

Start with initial upstream, add more targets at runtime:

```ini
# In service file
Environment="TURELY_PROXY_SERVER=primary-server:1081"
```

Then via control protocol:
```rust
AddRelayTarget { target: Node { addr: "backup-server:1081", weight: 1 } }
SetRelayAlgo { algo: Weighted }
```

### High Connection Limits

For high-traffic servers, increase file descriptor limits:

```bash
# /etc/security/limits.conf
* soft nofile 65535
* hard nofile 65535
```

Or in service file:
```ini
LimitNOFILE=65535
```

### Custom Port

```ini
Environment="SERVER_PORT=8080"
ExecStart=/bin/sh -c 'ulimit -n 65535 && exec /usr/local/bin/http-proxy-server -p 8080'
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check status and logs
systemctl status proxy-server
journalctl -u proxy-server -n 50 --no-pager

# Common issues:
# - SECRET_KEY not 32 characters
# - Port already in use
# - Binary not found or not executable
```

### Port Already in Use

```bash
lsof -i :1081
kill -9 $(lsof -t -i :1081)
systemctl start proxy-server
```

### Check Resource Usage

```bash
# Find PID
pgrep -f http-proxy-server

# Monitor resources
top -p $(pgrep -f http-proxy-server)

# Memory details
cat /proc/$(pgrep -f http-proxy-server)/status | grep -E "^(VmSize|VmRSS|Threads):"
```

### Update Binary

```bash
systemctl stop proxy-server

# Re-download (same as Quick Start step 1)
ARCH=$(uname -m)
case $ARCH in
  x86_64)  TARGET="x86_64-unknown-linux-musl" ;;
  aarch64) TARGET="aarch64-unknown-linux-musl" ;;
esac
curl -LO "https://github.com/acking-you/proxy-everything/releases/latest/download/http-proxy-server-${TARGET}.tar.gz"
tar -xzf http-proxy-server-*.tar.gz
mv http-proxy-server-*/http-proxy-server /usr/local/bin/
rm -rf http-proxy-server-*

systemctl start proxy-server
```

---

## Uninstall

```bash
systemctl stop proxy-server
systemctl disable proxy-server
rm /etc/systemd/system/proxy-server.service
rm /usr/local/bin/http-proxy-server
rm -rf ~/.proxy-everything/  # Optional: remove data
systemctl daemon-reload
```
