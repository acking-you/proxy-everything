# Server Deployment

> **Important**: Before deployment, open port `1081` (or your custom port) in your cloud provider's security group / firewall settings.

## Docker (Recommended)

### Quick Start (Ubuntu/Debian)

```bash
# Install Docker (skip if already installed)
curl -fsSL https://get.docker.com | sh

# Deploy proxy server (replace YOUR_SECRET_KEY with a 32-char string)
docker run -d --name proxy-server --restart=always -p 1081:1081 \
  -e SECRET_KEY=YOUR_SECRET_KEY \
  ackingliu/http2-server:latest
```

### Quick Start (CentOS/RHEL)

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh
systemctl start docker && systemctl enable docker

# Deploy
docker run -d --name proxy-server --restart=always -p 1081:1081 \
  -e SECRET_KEY=YOUR_SECRET_KEY \
  ackingliu/http2-server:latest
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | 32-byte encryption key (required) | - |
| `SERVER_PORT` | Server listening port | 1081 |
| `TURELY_PROXY_SERVER` | Upstream proxy for chain mode | - |

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
