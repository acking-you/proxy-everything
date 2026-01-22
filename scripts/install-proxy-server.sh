#!/usr/bin/env bash
set -Eeuo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Error handler
on_error() {
  local line=$1
  error "Script failed at line $line"
  error "Please check the error message above and try again."
  exit 1
}
trap 'on_error $LINENO' ERR

info "Starting proxy-server installation..."

# Configuration
BASE_URL="https://mybucket-1331094534.cos.ap-hongkong.myqcloud.com/proxy-everything"
DEFAULT_FILE="http-proxy-server-x86_64-unknown-linux-musl.tar.gz"
BIN_NAME="http-proxy-server"
INSTALL_DIR="/opt/proxy-everything"
SERVICE_NAME="proxy-server"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
DEFAULT_HOST="0.0.0.0"
DEFAULT_PORT="1081"
DEFAULT_SECRET_KEY="my-secret-key123my-secret-key123"

# Optional overrides via environment variables
HOST="${HOST:-$DEFAULT_HOST}"
PORT="${PORT:-$DEFAULT_PORT}"
SECRET_KEY="${SECRET_KEY:-$DEFAULT_SECRET_KEY}"
RUST_LOG="${RUST_LOG:-info}"

info "Configuration:"
info "  - Host: $HOST"
info "  - Port: $PORT"
info "  - Install dir: $INSTALL_DIR"

is_valid_port() {
  local port="$1"
  [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

port_in_use() {
  local port="$1"
  # Note: Use subshell and || true to prevent pipefail from triggering ERR trap
  # Also removed -H flag as it's not supported in older ss versions
  if command -v ss >/dev/null 2>&1; then
    if (ss -ltnu "sport = :$port" 2>/dev/null || true) | awk 'NF && !/^Netid/ {found=1} END {exit !found}'; then
      return 0
    fi
    return 1
  fi
  if command -v netstat >/dev/null 2>&1; then
    if (netstat -ltnu 2>/dev/null || true) | awk '$4 ~ /:'"$port"'$/ {found=1} END {exit !found}'; then
      return 0
    fi
    return 1
  fi
  if command -v lsof >/dev/null 2>&1; then
    if lsof -iTCP:"$port" -sTCP:LISTEN -P -n >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi
  if command -v fuser >/dev/null 2>&1; then
    if fuser -n tcp "$port" >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi
  return 2
}

ensure_port_available() {
  local port="$1"
  if ! is_valid_port "$port"; then
    echo "Invalid PORT: $port" >&2
    echo "Set PORT to a number between 1 and 65535." >&2
    exit 1
  fi

  local attempts=0
  while true; do
    local status=0
    if port_in_use "$port"; then
      status=0
    else
      status=$?
    fi
    case $status in
      0)
        echo "Port $port is already in use." >&2
        echo "You can choose another port by setting PORT or editing the systemd unit." >&2
        if [ -t 0 ]; then
          read -r -p "Enter a free port (or press Enter to abort): " new_port
          if [ -z "$new_port" ]; then
            echo "Aborting. Example:" >&2
            echo "  PORT=1082 bash install-proxy-server.sh" >&2
            exit 1
          fi
          if ! is_valid_port "$new_port"; then
            echo "Invalid PORT: $new_port" >&2
            continue
          fi
          port="$new_port"
          PORT="$new_port"
          attempts=$((attempts + 1))
          if [ "$attempts" -ge 5 ]; then
            echo "Too many attempts. Aborting." >&2
            exit 1
          fi
          continue
        else
          echo "Non-interactive shell detected." >&2
          echo "Re-run with a free port, for example:" >&2
          echo "  PORT=1082 bash install-proxy-server.sh" >&2
          exit 1
        fi
        ;;
      1)
        return 0
        ;;
      2)
        echo "Warning: cannot detect whether port $port is in use (missing ss/netstat/lsof/fuser)." >&2
        echo "Continuing without port check." >&2
        return 0
        ;;
      *)
        echo "Unexpected port check status: $status" >&2
        exit 1
        ;;
    esac
  done
}

# Resolve download URL (first arg is filename or full URL)
REQUESTED_FILE="${1:-$DEFAULT_FILE}"
if [[ "$REQUESTED_FILE" == http://* || "$REQUESTED_FILE" == https://* ]]; then
  DOWNLOAD_URL="$REQUESTED_FILE"
  ARCHIVE_NAME=$(basename "$REQUESTED_FILE")
else
  ARCHIVE_NAME="$REQUESTED_FILE"
  DOWNLOAD_URL="${BASE_URL}/${ARCHIVE_NAME}"
fi

# Re-run with sudo if needed
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  info "Requesting root privileges..."
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E bash "$0" "$@"
  fi
  error "This script must be run as root."
  exit 1
fi

success "Running as root"

# Verify required tools
info "Checking required tools..."
for cmd in tar systemctl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    error "Missing required command: $cmd"
    exit 1
  fi
done
success "Required tools available"

# Choose a downloader
if command -v curl >/dev/null 2>&1; then
  DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
  DOWNLOADER="wget"
else
  error "Missing required command: curl or wget"
  exit 1
fi

# Prepare temp workspace
TMP_DIR=$(mktemp -d)
cleanup() {
  rm -rf "$TMP_DIR"
}
trap 'cleanup; on_error $LINENO' ERR
trap cleanup EXIT

ARCHIVE_PATH="${TMP_DIR}/${ARCHIVE_NAME}"

# Download release archive
info "Downloading from: $DOWNLOAD_URL"
if [ "$DOWNLOADER" = "curl" ]; then
  curl -fL --retry 3 --connect-timeout 10 --max-time 300 -o "$ARCHIVE_PATH" "$DOWNLOAD_URL"
else
  wget -O "$ARCHIVE_PATH" "$DOWNLOAD_URL"
fi
success "Download completed"

# Extract and locate binary
info "Extracting archive..."
mkdir -p "$TMP_DIR/extract"
tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR/extract"
BIN_PATH=$(find "$TMP_DIR/extract" -type f -name "$BIN_NAME" -perm -u+x | head -n 1)
if [ -z "$BIN_PATH" ]; then
  error "${BIN_NAME} binary not found in archive."
  exit 1
fi
success "Binary extracted: $BIN_PATH"

# Install binary
info "Installing binary to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/conf"
install -m 0755 "$BIN_PATH" "${INSTALL_DIR}/${BIN_NAME}"
success "Binary installed"

# Verify port availability BEFORE removing existing service
# This prevents leaving the system without a service if port check fails
info "Checking port $PORT availability..."
ensure_port_available "$PORT"
success "Port $PORT is available"

# Stop and remove existing service if present
info "Removing existing service (if any)..."
if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
  info "Stopping existing service..."
  systemctl stop "${SERVICE_NAME}.service"
fi
if systemctl is-enabled --quiet "${SERVICE_NAME}.service"; then
  info "Disabling existing service..."
  systemctl disable "${SERVICE_NAME}.service"
fi
if [ -f "$SERVICE_PATH" ]; then
  rm -f "$SERVICE_PATH"
fi
success "Old service removed"

# Write systemd unit
info "Creating systemd service..."
cat > "$SERVICE_PATH" <<UNIT
[Unit]
Description=proxy-everything server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment=HOME=${INSTALL_DIR}/conf
Environment=RUST_LOG=${RUST_LOG}
Environment=SECRET_KEY=${SECRET_KEY}
Environment=SERVER_PORT=${PORT}
ExecStart=${INSTALL_DIR}/${BIN_NAME} -H ${HOST} -p ${PORT}
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

# Ensure full network access (no restrictions)
PrivateNetwork=no
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
IPAddressAllow=any

[Install]
WantedBy=multi-user.target
UNIT
success "Systemd service file created: $SERVICE_PATH"

# Reload systemd and start service
info "Starting service..."
systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"

# Verify service is running
sleep 1
if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
  success "Service started successfully!"
  echo ""
  echo -e "${GREEN}========================================${NC}"
  echo -e "${GREEN}  Installation completed successfully!  ${NC}"
  echo -e "${GREEN}========================================${NC}"
  echo ""
  echo "Service name: ${SERVICE_NAME}.service"
  echo "Listening on: ${HOST}:${PORT}"
  echo ""
  echo "Useful commands:"
  echo "  systemctl status ${SERVICE_NAME}    # Check status"
  echo "  journalctl -u ${SERVICE_NAME} -f    # View logs"
  echo "  systemctl restart ${SERVICE_NAME}   # Restart service"
else
  error "Service failed to start!"
  echo ""
  echo "Check logs with: journalctl -u ${SERVICE_NAME} -n 50"
  systemctl status "${SERVICE_NAME}.service" --no-pager || true
  exit 1
fi
