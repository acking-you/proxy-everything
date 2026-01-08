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
        shift || true
        ;;
    start|stop|restart|update|logs|status|shell|init|help|--help|-h|all)
        INSTANCE="proxy"
        ;;
    *)
        # Check if it's a custom instance name (not a command)
        if [[ "$1" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]] && [[ ! "$1" =~ ^(start|stop|restart|update|logs|status|shell|init)$ ]]; then
            shift || true
        else
            INSTANCE="proxy"
        fi
        ;;
esac

# Set instance-specific defaults FIRST (before loading config)
case "$INSTANCE" in
    relay)
        # Relay instance defaults
        DEFAULT_CONTAINER="proxy-relay"
        DEFAULT_PORT="11111"
        DEFAULT_DATA_DIR="/opt/proxy-relay-data"
        ;;
    *)
        # Default proxy instance
        DEFAULT_CONTAINER="proxy-server"
        DEFAULT_PORT="1081"
        DEFAULT_DATA_DIR="/opt/proxy-data"
        ;;
esac

# Configuration file per instance
CONFIG_FILE="${PROXY_CONFIG:-/etc/proxy-${INSTANCE}.conf}"

# Load config if exists (overrides defaults)
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
fi

# Apply defaults (config file values take precedence)
IMAGE="${PROXY_IMAGE:-ackingliu/http2-server:latest}"
CONTAINER="${PROXY_CONTAINER:-$DEFAULT_CONTAINER}"
PORT="${PROXY_PORT:-$DEFAULT_PORT}"
DATA_DIR="${PROXY_DATA_DIR:-$DEFAULT_DATA_DIR}"
SECRET_KEY="${SECRET_KEY:-my-secret-key123my-secret-key123}"
TURELY_PROXY_SERVER="${TURELY_PROXY_SERVER:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} ${CYAN}[$INSTANCE]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} ${CYAN}[$INSTANCE]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} ${CYAN}[$INSTANCE]${NC} $1"; }

confirm_port() {
    local default_port="$1"
    read -p "确认端口 [$default_port]: " input_port
    echo "${input_port:-$default_port}"
}

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

    # 确认端口
    PORT=$(confirm_port "$PORT")

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
    local docker_cmd="docker run -d --name $CONTAINER --restart=always"
    docker_cmd="$docker_cmd -p ${PORT}:${PORT}"
    docker_cmd="$docker_cmd -v ${DATA_DIR}:/root/.proxy-everything"
    docker_cmd="$docker_cmd -e SECRET_KEY=$SECRET_KEY"
    docker_cmd="$docker_cmd -e SERVER_PORT=$PORT"

    if [ -n "$TURELY_PROXY_SERVER" ]; then
        mode_info="transparent relay -> $TURELY_PROXY_SERVER"
        docker_cmd="$docker_cmd -e TURELY_PROXY_SERVER=$TURELY_PROXY_SERVER"
    fi

    [ -n "$CONTROL_ADMIN_TOKEN" ] && docker_cmd="$docker_cmd -e CONTROL_ADMIN_TOKEN=$CONTROL_ADMIN_TOKEN"
    [ -n "$NODE_ADVERTISE_ADDR" ] && docker_cmd="$docker_cmd -e NODE_ADVERTISE_ADDR=$NODE_ADVERTISE_ADDR"
    docker_cmd="$docker_cmd $IMAGE"

    log_info "Starting $CONTAINER on port $PORT in $mode_info mode..."
    log_info "Command: $docker_cmd"
    eval "$docker_cmd"

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
    local container="${1:-$CONTAINER}"

    # 检查容器是否存在
    if ! docker inspect "$container" &>/dev/null; then
        log_error "Container '$container' not found"
        exit 1
    fi

    # 从 inspect 提取配置
    local image=$(docker inspect --format '{{.Config.Image}}' "$container")
    local name=$(docker inspect --format '{{.Name}}' "$container" | sed 's/^\///')
    local restart=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$container")

    # 提取端口映射
    local ports=$(docker inspect --format '{{range $p, $conf := .HostConfig.PortBindings}}-p {{(index $conf 0).HostPort}}:{{$p}} {{end}}' "$container" | sed 's|/tcp||g')

    # 提取挂载卷
    local binds=$(docker inspect --format '{{range .HostConfig.Binds}}-v {{.}} {{end}}' "$container")

    # 提取环境变量（过滤默认值）
    local envs=""
    while IFS= read -r env; do
        [ -z "$env" ] && continue
        case "$env" in
            PATH=*|HOME=/http2-server/conf|SERVER_PORT=1081) continue ;;
            *) envs="$envs -e $env" ;;
        esac
    done < <(docker inspect --format '{{range .Config.Env}}{{.}}{{"\n"}}{{end}}' "$container")

    # 拉取新镜像
    log_info "Pulling latest image: $image"
    docker pull "$image"

    # 停止并删除旧容器
    log_info "Stopping container: $container"
    docker stop "$container"
    docker rm "$container"

    # 构建并执行新命令
    local docker_cmd="docker run -d --name $name"
    [ "$restart" != "no" ] && [ -n "$restart" ] && docker_cmd="$docker_cmd --restart=$restart"
    docker_cmd="$docker_cmd $ports $binds $envs $image"

    log_info "Starting new container..."
    log_info "Command: $docker_cmd"
    eval "$docker_cmd"

    log_info "Update complete!"
    docker ps | grep "$name"
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
    # 确认端口
    PORT=$(confirm_port "$PORT")

    if [ -f "$CONFIG_FILE" ]; then
        log_warn "Config file already exists: $CONFIG_FILE"
        cat "$CONFIG_FILE"
        return 0
    fi

    case "$INSTANCE" in
        relay)
            cat > "$CONFIG_FILE" << EOF
# Proxy Relay Instance Configuration
# This instance runs in transparent relay mode

# Docker image
PROXY_IMAGE="ackingliu/http2-server:latest"

# Container name
PROXY_CONTAINER="proxy-relay"

# Server port (relay typically uses different port)
PROXY_PORT="$PORT"

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
# NODE_ADVERTISE_ADDR="your-public-ip:$PORT"
EOF
            ;;
        *)
            cat > "$CONFIG_FILE" << EOF
# Proxy Server Configuration
# This instance runs in normal proxy mode

# Docker image
PROXY_IMAGE="ackingliu/http2-server:latest"

# Container name
PROXY_CONTAINER="proxy-server"

# Server port
PROXY_PORT="$PORT"

# Data directory
PROXY_DATA_DIR="/opt/proxy-data"

# 32-character encryption key
SECRET_KEY="my-secret-key123my-secret-key123"

# Optional: Admin token for control plane
# CONTROL_ADMIN_TOKEN="your-admin-token"

# Optional: Advertised address for node sync
# NODE_ADVERTISE_ADDR="your-public-ip:$PORT"

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
    update)  do_update "$1" ;;
    logs)    do_logs "$1" ;;
    status)  do_status ;;
    shell)   do_shell ;;
    init)    do_init ;;
    all)     do_status_all ;;
    help|--help|-h) show_help ;;
    *)       show_help ;;
esac
