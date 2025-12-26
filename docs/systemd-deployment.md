# Systemd Deployment (Binary)

This guide covers deploying proxy-server as a systemd service without Docker.

## Prerequisites

- Linux server (Ubuntu/Debian/CentOS/RHEL)
- Root access
- Port 1081 (or custom) open in firewall

## Quick Start

### 1. Download Binary

```bash
# x86_64
curl -LO https://github.com/acking-you/proxy-everything/releases/latest/download/http-proxy-server-x86_64-unknown-linux-musl.tar.gz
tar -xzf http-proxy-server-*.tar.gz
mv http-proxy-server-*/http-proxy-server /root/
chmod +x /root/http-proxy-server

# ARM64 (aarch64)
curl -LO https://github.com/acking-you/proxy-everything/releases/latest/download/http-proxy-server-aarch64-unknown-linux-musl.tar.gz
tar -xzf http-proxy-server-*.tar.gz
mv http-proxy-server-*/http-proxy-server /root/
chmod +x /root/http-proxy-server
```

### 2. Run Management Script

```bash
curl -LO https://raw.githubusercontent.com/acking-you/proxy-everything/dev/services/proxy-server-ctl.sh
chmod +x proxy-server-ctl.sh
sudo ./proxy-server-ctl.sh
```

### 3. Choose "Install/Configure"

The script will prompt for:
- `SECRET_KEY` (required, 32 characters)
- `PORT` (default: 1081)
- `Upstream proxy` (optional, for chain mode)
- `Log level` (default: info)

### 4. Start Service

Choose option 2 to start the service.

---

## Manual Installation

If you prefer manual setup:

### Create Service File

```bash
cat > /etc/systemd/system/proxy-server.service << 'EOF'
[Unit]
Description=Proxy Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
Environment="SECRET_KEY=your-32-character-secret-key!!"
Environment="RUST_LOG=info"
ExecStart=/bin/sh -c 'ulimit -n 65535 && exec /root/http-proxy-server -p 1081'
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
```

### Enable and Start

```bash
systemctl daemon-reload
systemctl enable proxy-server
systemctl start proxy-server
```

### Check Status

```bash
systemctl status proxy-server
```

---

## Management Commands

| Action | Command |
|--------|---------|
| Start | `systemctl start proxy-server` |
| Stop | `systemctl stop proxy-server` |
| Restart | `systemctl restart proxy-server` |
| Status | `systemctl status proxy-server` |
| Logs | `journalctl -u proxy-server -f` |
| Enable auto-start | `systemctl enable proxy-server` |
| Disable auto-start | `systemctl disable proxy-server` |

---

## Configuration Options

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | Yes | - | 32-byte encryption key |
| `SERVER_PORT` | No | 1081 | Listening port |
| `TURELY_PROXY_SERVER` | No | - | Upstream proxy (chain mode) |
| `RUST_LOG` | No | info | Log level (error/warn/info/debug) |

### Chain Mode

To forward traffic through another proxy:

```bash
Environment="TURELY_PROXY_SERVER=upstream-server:1081"
```

---

## Troubleshooting

### Check if service is running

```bash
systemctl status proxy-server
```

### View logs

```bash
# Last 100 lines
journalctl -u proxy-server -n 100

# Follow logs
journalctl -u proxy-server -f
```

### Check resource usage

```bash
# Find PID
pgrep -f http-proxy-server

# View resources
top -p $(pgrep -f http-proxy-server)
```

### Port already in use

```bash
# Find process using port
lsof -i :1081

# Kill if needed
kill -9 $(lsof -t -i :1081)
```
