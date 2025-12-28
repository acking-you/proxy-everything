# Server Deployment

> **Important**: Before deployment, open port `1081` (or your custom port) in your cloud provider's security group / firewall settings.

## Quick Start with Management Script (Recommended)

```bash
# Download script
curl -fsSL https://raw.githubusercontent.com/acking-you/proxy-everything/dev/scripts/proxy-ctl.sh -o /usr/local/bin/proxy-ctl
chmod +x /usr/local/bin/proxy-ctl

# Initialize config (optional, uses defaults if skipped)
proxy-ctl init

# Start server (uses default SECRET_KEY)
proxy-ctl start

# Update to latest version
proxy-ctl update

# Other commands
proxy-ctl status    # Check status
proxy-ctl logs 100  # View last 100 lines
proxy-ctl stop      # Stop server
```

Config file location: `/etc/proxy-server.conf`

## Docker (Manual)

### Quick Start (Ubuntu/Debian)

```bash
# Install Docker (skip if already installed)
curl -fsSL https://get.docker.com | sh

# Create data directory (for persistence)
mkdir -p /opt/proxy-data

# Deploy proxy server (replace YOUR_SECRET_KEY with a 32-char string)
docker run -d --name proxy-server --restart=always -p 1081:1081 \
  -v /opt/proxy-data:/root/.proxy-everything \
  -e SECRET_KEY=YOUR_SECRET_KEY \
  ackingliu/http2-server:latest
```

### Quick Start (CentOS/RHEL)

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh
systemctl start docker && systemctl enable docker

# Create data directory
mkdir -p /opt/proxy-data

# Deploy
docker run -d --name proxy-server --restart=always -p 1081:1081 \
  -v /opt/proxy-data:/root/.proxy-everything \
  -e SECRET_KEY=YOUR_SECRET_KEY \
  ackingliu/http2-server:latest
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | 32-byte encryption key (required) | - |
| `SERVER_PORT` | Server listening port | 1081 |
| `TURELY_PROXY_SERVER` | Upstream proxy for chain mode | - |
| `DB_PATH` | Embedded DB path (Turso local file) | `data/proxy.db` |
| `CONTROL_ADMIN_TOKEN` | Control-plane admin token (optional) | - |
| `CONTROL_REQUIRE_ENCRYPTION` | Require encrypted control payloads | `true` |
| `CONTROL_SESSION_KEY` | Control-plane session key (32 bytes, optional) | - |
| `NODE_ADVERTISE_ADDR` | Advertised node address for sync | - |
| `NODE_ID` | Stable node id (defaults to advertise addr) | - |
| `NODE_SYNC_INTERVAL_SECS` | Node sync interval in seconds | `30` |

## Advanced Configuration

### Chain Mode (Transparent Proxy)

Route traffic through another proxy server:

```bash
docker run -d --restart=always -p 1081:1081 \
  -e SECRET_KEY=your-key \
  -e TURELY_PROXY_SERVER=upstream-server:1081 \
  ackingliu/http2-server:latest
```

### Custom Port

```bash
docker run -d --restart=always -p 8080:8080 \
  -e SERVER_PORT=8080 \
  -e SECRET_KEY=your-key \
  ackingliu/http2-server:latest
```

## Binary Deployment

Download from [releases](https://github.com/acking-you/proxy-everything/releases) and run:

```bash
export SECRET_KEY=your-32-byte-secret-key
./http-proxy-server -h 0.0.0.0 -p 1081
```

## Metrics DB & Control Plane

The server stores per-IP metrics and connection records in the embedded database.

**Admin CLI examples** (requires `CONTROL_ADMIN_TOKEN` if set):

```bash
# List nodes
http-proxy-admin -s 127.0.0.1 -p 1081 --token YOUR_TOKEN nodes list

# Add node and broadcast
http-proxy-admin -s 127.0.0.1 -p 1081 --token YOUR_TOKEN nodes add 10.0.0.2:1081

# Query IP stats
http-proxy-admin -s 127.0.0.1 -p 1081 --token YOUR_TOKEN sql \
  "SELECT * FROM ip_stats ORDER BY last_seen_ms DESC LIMIT 10;"
```

## Container Management

```bash
# View running containers
docker ps

# View logs
docker logs proxy-server

# Stop and remove container (if config is wrong)
docker stop proxy-server && docker rm proxy-server

# Restart with correct config
docker run -d --name proxy-server --restart=always -p 1081:1081 \
  -e SECRET_KEY=YOUR_CORRECT_KEY \
  ackingliu/http2-server:latest
```

## Remote Update (Pull New Image & Restart)

Update container to latest image with minimal downtime (~1-3 seconds):

```bash
# Using management script (recommended)
proxy-ctl update

# Or manual one-liner
docker pull ackingliu/http2-server:latest && \
docker stop proxy-server && \
docker rm proxy-server && \
docker run -d --name proxy-server --restart=always -p 1081:1081 \
  -v /opt/proxy-data:/root/.proxy-everything \
  -e SECRET_KEY=my-secret-key123my-secret-key123 \
  ackingliu/http2-server:latest
```

### Remote Update via SSH

```bash
# Using script (if installed on server)
ssh user@your-server "proxy-ctl update"

# Or direct command
ssh user@your-server "docker pull ackingliu/http2-server:latest && \
  docker stop proxy-server && docker rm proxy-server && \
  docker run -d --name proxy-server --restart=always -p 1081:1081 \
  -v /opt/proxy-data:/root/.proxy-everything \
  -e SECRET_KEY=my-secret-key123my-secret-key123 ackingliu/http2-server:latest"
```

## Data Persistence

The server stores data in `/root/.proxy-everything/` inside the container:
- `nodes.json` - Cluster node information

Mount a host directory to preserve data across container restarts:

```bash
-v /opt/proxy-data:/root/.proxy-everything
```

Without this mount, node data will be lost when container is removed.
