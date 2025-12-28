#!/bin/bash
# proxy-ctl.sh - Multi-instance proxy server management script
# Usage: ./proxy-ctl.sh [instance] <command> [options]
#
# Supports running multiple instances on the same node:
#   - proxy (default): Normal proxy mode on port 1081
#   - relay: Transparent relay mode on port 11111

set -e

# Instance name (first arg if it's a known instance, otherwise "proxy")
INSTANCE="${1:-proxy}"
case "$INSTANCE" in
    proxy|relay)
        shift
        ;;
    start|stop|restart|update|logs|status|shell|init|help|--help|-h)
        INSTANCE="proxy"
        ;;
    *)
        # Check if it's a custom instance name (not a command)
        if [[ "$1" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]] && [[ ! "$1" =~ ^(start|stop|restart|update|logs|status|shell|init)$ ]]; then
            shift
        else
            INSTANCE="proxy"
        fi
        ;;
esac

# Configuration file per instance
CONFIG_FILE="${PROXY_CONFIG:-/etc/proxy-${INSTANCE}.conf}"

# Load config if exists
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
fi

# Default configurations per instance
case "$INSTANCE" in
    relay)
        # Relay instance defaults
        IMAGE="${PROXY_IMAGE:-ackingliu/http2-server:latest}"
        CONTAINER="${PROXY_CONTAINER:-proxy-relay}"
        PORT="${PROXY_PORT:-11111}"
        DATA_DIR="${PROXY_DATA_DIR:-/opt/proxy-relay-data}"
        SECRET_KEY="${SECRET_KEY:-my-secret-key123my-secret-key123}"
        # Relay mode requires TURELY_PROXY_SERVER to be set
        TURELY_PROXY_SERVER="${TURELY_PROXY_SERVER:-}"
        ;;
    *)
        # Default proxy instance
        IMAGE="${PROXY_IMAGE:-ackingliu/http2-server:latest}"
        CONTAINER="${PROXY_CONTAINER:-proxy-server}"
        PORT="${PROXY_PORT:-1081}"
        DATA_DIR="${PROXY_DATA_DIR:-/opt/proxy-data}"
        SECRET_KEY="${SECRET_KEY:-my-secret-key123my-secret-key123}"
        TURELY_PROXY_SERVER="${TURELY_PROXY_SERVER:-}"
        ;;
esac

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} ${CYAN}[$INSTANCE]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} ${CYAN}[$INSTANCE]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} ${CYAN}[$INSTANCE]${NC} $1"; }

check_config() {
    # In relay mode, TURELY_PROXY_SERVER must be set
    if [ "$INSTANCE" = "relay" ] && [ -z "$TURELY_PROXY_SERVER" ]; then
        log_error "TURELY_PROXY_SERVER must be set for relay instance!"
        log_error "Edit $CONFIG_FILE or set environment variable"
        exit 1
    fi
    # In normal mode, SECRET_KEY must be 32 chars
    if [ -z "$TURELY_PROXY_SERVER" ] && [ ${#SECRET_KEY} -ne 32 ]; then
        log_error "SECRET_KEY must be exactly 32 characters! Current: ${#SECRET_KEY}"
        exit 1
    fi
}

do_start() {
    check_config

    if docker ps -q -f name="^${CONTAINER}$" | grep -q .; then
        log_warn "Container '$CONTAINER' is already running"
        return 0
    fi

    # Remove stopped container if exists
    docker rm "$CONTAINER" 2>/dev/null || true

    # Create data directory
    mkdir -p "$DATA_DIR"

    # Build docker run command
    local mode_info="normal proxy"
    local extra_env=""
    if [ -n "$TURELY_PROXY_SERVER" ]; then
        mode_info="transparent relay -> $TURELY_PROXY_SERVER"
        extra_env="-e TURELY_PROXY_SERVER=$TURELY_PROXY_SERVER"
    fi

    log_info "Starting $CONTAINER on port $PORT in $mode_info mode..."
    docker run -d --name "$CONTAINER" --restart=always \
        -p "${PORT}:${PORT}" \
        -v "${DATA_DIR}:/root/.proxy-everything" \
        -e SECRET_KEY="$SECRET_KEY" \
        -e SERVER_PORT="$PORT" \
        ${extra_env} \
        ${CONTROL_ADMIN_TOKEN:+-e CONTROL_ADMIN_TOKEN="$CONTROL_ADMIN_TOKEN"} \
        ${NODE_ADVERTISE_ADDR:+-e NODE_ADVERTISE_ADDR="$NODE_ADVERTISE_ADDR"} \
        "$IMAGE"

    log_info "Container started successfully"
    docker ps | grep "$CONTAINER"
}

do_stop() {
    log_info "Stopping $CONTAINER..."
    docker stop "$CONTAINER" 2>/dev/null || log_warn "Container not running"
}

do_restart() {
    do_stop
    sleep 1
    do_start
}

do_update() {
    check_config

    log_info "Pulling latest image..."
    docker pull "$IMAGE"

    log_info "Stopping old container..."
    docker stop "$CONTAINER" 2>/dev/null || true
    docker rm "$CONTAINER" 2>/dev/null || true

    log_info "Starting new container..."
    do_start

    log_info "Update complete!"
}

do_logs() {
    docker logs -f "$CONTAINER" ${1:+--tail $1}
}

do_status() {
    if docker ps -q -f name="^${CONTAINER}$" | grep -q .; then
        log_info "Container '$CONTAINER' is running"
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(NAMES|$CONTAINER)"
    else
        log_warn "Container '$CONTAINER' is not running"
        return 1
    fi
}

do_shell() {
    docker exec -it "$CONTAINER" /bin/sh
}

do_status_all() {
    echo -e "${GREEN}=== All Proxy Instances ===${NC}"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(NAMES|proxy)"
}

show_help() {
    cat << EOF
Multi-Instance Proxy Server Management Script

Usage: $0 [instance] <command> [options]

Instances:
  proxy     Normal proxy mode (default, port 1081)
  relay     Transparent relay mode (port 11111)
  <custom>  Custom instance name (uses /etc/proxy-<name>.conf)

Commands:
  start     Start the proxy server
  stop      Stop the proxy server
  restart   Restart the proxy server
  update    Pull latest image and restart
  logs [n]  Show logs (optionally last n lines)
  status    Show container status
  shell     Open shell in container
  init      Create config file with default settings
  all       Show status of all instances

Configuration:
  Each instance uses its own config file:
    proxy:  /etc/proxy-proxy.conf
    relay:  /etc/proxy-relay.conf

  Environment variables (override config):
    PROXY_IMAGE          Docker image
    PROXY_CONTAINER      Container name
    PROXY_PORT           Server port
    PROXY_DATA_DIR       Data directory
    SECRET_KEY           32-char encryption key
    CONTROL_ADMIN_TOKEN  Admin token (optional)
    NODE_ADVERTISE_ADDR  Node address for sync (optional)
    TURELY_PROXY_SERVER  Upstream proxy for relay mode

Deployment Modes:
  1. Normal Proxy Mode (instance: proxy):
     Client -> [decrypt] -> Server -> Destination

  2. Transparent Relay Mode (instance: relay):
     Client -> Server -> [forward as-is] -> Upstream Proxy

Examples:
  # Initialize config files
  $0 proxy init           # Create /etc/proxy-proxy.conf
  $0 relay init           # Create /etc/proxy-relay.conf

  # Start instances
  $0 start                # Start default proxy instance
  $0 proxy start          # Same as above
  $0 relay start          # Start relay instance

  # Manage instances
  $0 proxy status         # Check proxy status
  $0 relay logs 100       # View relay logs
  $0 all                  # Show all instances status

  # Update all instances
  $0 proxy update && $0 relay update
EOF
}

do_init() {
    if [ -f "$CONFIG_FILE" ]; then
        log_warn "Config file already exists: $CONFIG_FILE"
        cat "$CONFIG_FILE"
        return 0
    fi

    case "$INSTANCE" in
        relay)
            cat > "$CONFIG_FILE" << 'EOF'
# Proxy Relay Instance Configuration
# This instance runs in transparent relay mode

# Docker image
PROXY_IMAGE="ackingliu/http2-server:latest"

# Container name
PROXY_CONTAINER="proxy-relay"

# Server port (relay typically uses different port)
PROXY_PORT="11111"

# Data directory
PROXY_DATA_DIR="/opt/proxy-relay-data"

# Encryption key (must match client config)
SECRET_KEY="my-secret-key123my-secret-key123"

# REQUIRED: Upstream proxy server for transparent relay
# Format: host:port
TURELY_PROXY_SERVER="your-real-proxy:1081"

# Optional: Admin token
# CONTROL_ADMIN_TOKEN="your-admin-token"

# Optional: Advertised address for node sync
# NODE_ADVERTISE_ADDR="your-public-ip:11111"
EOF
            ;;
        *)
            cat > "$CONFIG_FILE" << 'EOF'
# Proxy Server Configuration
# This instance runs in normal proxy mode

# Docker image
PROXY_IMAGE="ackingliu/http2-server:latest"

# Container name
PROXY_CONTAINER="proxy-server"

# Server port
PROXY_PORT="1081"

# Data directory
PROXY_DATA_DIR="/opt/proxy-data"

# 32-character encryption key
SECRET_KEY="my-secret-key123my-secret-key123"

# Optional: Admin token for control plane
# CONTROL_ADMIN_TOKEN="your-admin-token"

# Optional: Advertised address for node sync
# NODE_ADVERTISE_ADDR="your-public-ip:1081"

# Optional: Enable relay mode (leave empty for normal proxy)
# TURELY_PROXY_SERVER="upstream-proxy:1081"
EOF
            ;;
    esac

    log_info "Config file created: $CONFIG_FILE"
    log_info "Edit it to customize settings, then run: $0 $INSTANCE start"
}

# Main command dispatch
CMD="${1:-help}"
shift 2>/dev/null || true

case "$CMD" in
    start)   do_start ;;
    stop)    do_stop ;;
    restart) do_restart ;;
    update)  do_update ;;
    logs)    do_logs "$1" ;;
    status)  do_status ;;
    shell)   do_shell ;;
    init)    do_init ;;
    all)     do_status_all ;;
    help|--help|-h) show_help ;;
    *)       show_help ;;
esac
