# Server Deployment Guide

> **Prerequisites**: Open port `1081` (or custom port) in your firewall/security group before deployment.

## Table of Contents

- [Quick Start](#quick-start)
- [Deployment Options](#deployment-options)
- [Configuration](#configuration)
- [Dynamic Relay](#dynamic-relay)
- [Best Practices](#best-practices)
- [Operations](#operations)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### One-Command Deploy (Docker)

```bash
# Create data directory and start server
mkdir -p /opt/proxy-data && \
docker run -d --name proxy-server --restart=always \
  -p 1081:1081 \
  -v /opt/proxy-data:/root/.proxy-everything \
  -e SECRET_KEY=$(head -c 32 /dev/urandom | base64 | head -c 32) \
  ackingliu/http2-server:latest
```

### Using Management Script (Recommended)

```bash
# Install script
curl -fsSL https://raw.githubusercontent.com/acking-you/proxy-everything/dev/scripts/proxy-ctl.sh \
  -o /usr/local/bin/proxy-ctl && chmod +x /usr/local/bin/proxy-ctl

# Initialize and start
proxy-ctl init    # Create config at /etc/proxy-proxy.conf
proxy-ctl start   # Start container
```

---

## Deployment Options

### Docker (Recommended)

```bash
docker run -d --name proxy-server --restart=always \
  -p 1081:1081 \
  -v /opt/proxy-data:/root/.proxy-everything \
  -e SECRET_KEY=your-32-character-secret-key!! \
  ackingliu/http2-server:latest
```

### Binary

Download from [releases](https://github.com/acking-you/proxy-everything/releases):

```bash
export SECRET_KEY=your-32-character-secret-key!!
./http-proxy-server -H 0.0.0.0 -p 1081
```

### Systemd Service

See [systemd-deployment.md](./systemd-deployment.md) for detailed instructions.

For multiple instances on one host, use a unique service name per port, for example:

```bash
SERVICE_NAME=proxy-server-1081 PORT=1081 bash install-proxy-server.sh
SERVICE_NAME=proxy-server-1082 PORT=1082 bash install-proxy-server.sh
```

---

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | Yes | - | 32-character encryption key |
| `SERVER_PORT` | No | 1081 | Listening port |
| `TURELY_PROXY_SERVER` | No | - | Initial upstream target (auto-added to relay) |
| `CONTROL_SESSION_KEY` | No | - | 32-char key for control protocol encryption |
| `CONTROL_REQUIRE_ENCRYPTION` | No | true | Require encrypted control messages |
| `CONTROL_ADMIN_TOKEN` | No | - | Admin token for privileged operations |
| `NODE_ID` | No | auto | Stable node identifier |
| `NODE_ADVERTISE_ADDR` | No | auto | Address advertised to other nodes |

### Data Persistence

Server stores configuration in `/root/.proxy-everything/`:

| File | Content |
|------|---------|
| `nodes.json` | Registered nodes and groups |
| `relay.json` | Relay targets and load balancing config |

**Always mount a volume** to preserve data:
```bash
-v /opt/proxy-data:/root/.proxy-everything
```

---

## Dynamic Relay

The server supports runtime-configurable relay with load balancing.

### Setup via Environment Variable

```bash
# Start with initial upstream - automatically enables relay
docker run -d --name proxy-server --restart=always \
  -p 1081:1081 \
  -v /opt/proxy-data:/root/.proxy-everything \
  -e SECRET_KEY=your-key \
  -e TURELY_PROXY_SERVER=upstream.server:1081 \
  ackingliu/http2-server:latest
```

### Add More Targets at Runtime

Via control protocol (proxy-tui or ControlClient):

```rust
// Add second upstream with higher weight
AddRelayTarget { target: Node { addr: "10.0.0.2:1081", weight: 2 } }

// Switch to weighted load balancing
SetRelayAlgo { algo: Weighted }
```

### Load Balancing Algorithms

| Algorithm | Use Case |
|-----------|----------|
| `RoundRobin` | Equal distribution (default) |
| `Weighted` | Prioritize faster/larger servers |
| `LeastConn` | Route to least busy server |
| `Random` | Simple random selection |

### Node Groups

Organize servers by region or role:

```rust
// Create regional group
CreateGroup { group_id: "asia", name: "Asia Servers" }

// Add servers to group
AddNode { addr: "10.0.0.1:1081" }
AddNodeToGroup { group_id: "asia", node_id: "10.0.0.1:1081" }

// Use group as relay target (all nodes in group participate)
AddRelayTarget { target: GroupRef { group_id: "asia" } }
```

### Configuration File Format

`relay.json` (auto-persisted):

```json
{
  "enabled": true,
  "targets": [
    { "type": "node", "addr": "10.0.0.1:1081", "weight": 1 },
    { "type": "group_ref", "group_id": "asia" }
  ],
  "algo": "Weighted",
  "health_check_interval_secs": 30
}
```

---

## Best Practices

### Security

1. **Generate strong SECRET_KEY**
   ```bash
   # Generate random 32-char key
   head -c 32 /dev/urandom | base64 | head -c 32
   ```

2. **Enable control encryption** for remote management
   ```bash
   -e CONTROL_SESSION_KEY=another-32-char-key-here!!
   -e CONTROL_REQUIRE_ENCRYPTION=true
   ```

3. **Use admin token** for privileged operations
   ```bash
   -e CONTROL_ADMIN_TOKEN=your-admin-token
   ```

4. **Restrict port access** - Only expose 1081 to trusted IPs if possible

### High Availability

1. **Multi-node relay** - Add multiple upstream targets for failover
   ```rust
   AddRelayTarget { target: Node { addr: "primary:1081", weight: 2 } }
   AddRelayTarget { target: Node { addr: "backup:1081", weight: 1 } }
   SetRelayAlgo { algo: Weighted }
   ```

2. **Use LeastConn** for uneven workloads
   ```rust
   SetRelayAlgo { algo: LeastConn }
   ```

3. **Regional groups** - Organize by geography for latency optimization
   ```rust
   CreateGroup { group_id: "us-west", name: "US West" }
   CreateGroup { group_id: "us-east", name: "US East" }
   ```

### Performance

1. **Always mount data volume** - Prevents config loss and reduces startup time

2. **Set appropriate ulimits** for high connection counts
   ```bash
   docker run --ulimit nofile=65535:65535 ...
   ```

3. **Use host networking** for maximum throughput (advanced)
   ```bash
   docker run --network host -e SERVER_PORT=1081 ...
   ```

### Operations

1. **Start simple, scale later**
   - Begin with `TURELY_PROXY_SERVER` for single upstream
   - Add more targets dynamically as needed
   - Configuration persists across restarts

2. **Monitor with proxy-tui**
   - Real-time connection stats
   - Relay status and health
   - Node management

3. **Regular updates**
   ```bash
   proxy-ctl update  # or docker pull + restart
   ```

---

## Operations

### Container Management

```bash
proxy-ctl status          # Check status
proxy-ctl logs 100        # Last 100 log lines
proxy-ctl stop            # Stop server
proxy-ctl restart         # Restart server
proxy-ctl update          # Pull latest image and restart
```

### Remote Update

```bash
# Via SSH
ssh user@server "proxy-ctl update"

# Manual
docker pull ackingliu/http2-server:latest && \
docker stop proxy-server && docker rm proxy-server && \
docker run -d --name proxy-server --restart=always \
  -p 1081:1081 \
  -v /opt/proxy-data:/root/.proxy-everything \
  -e SECRET_KEY=your-key \
  ackingliu/http2-server:latest
```

---

## Troubleshooting

### Connection Refused

```bash
# Check if container is running
docker ps | grep proxy-server

# Check logs for errors
docker logs proxy-server --tail 50

# Verify port is listening
netstat -tlnp | grep 1081
```

### Config Not Persisting

```bash
# Ensure volume is mounted
docker inspect proxy-server | grep -A5 Mounts

# Check data directory
ls -la /opt/proxy-data/
```

### Relay Not Working

```bash
# Check relay status via logs
docker logs proxy-server | grep -i relay

# Verify relay.json exists and is valid
cat /opt/proxy-data/relay.json
```

### High Memory Usage

```bash
# Check container stats
docker stats proxy-server

# Restart to clear connection state
docker restart proxy-server
```

### SECRET_KEY Mismatch

Client and server must use identical `SECRET_KEY`. Verify both sides:
```bash
# On server
docker inspect proxy-server | grep SECRET_KEY

# On client
echo $SECRET_KEY
```
