#!/usr/bin/env bash
set -euo pipefail

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
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E bash "$0" "$@"
  fi
  echo "This script must be run as root." >&2
  exit 1
fi

# Verify required tools
for cmd in tar systemctl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
done

# Choose a downloader
if command -v curl >/dev/null 2>&1; then
  DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
  DOWNLOADER="wget"
else
  echo "Missing required command: curl or wget" >&2
  exit 1
fi

# Prepare temp workspace
TMP_DIR=$(mktemp -d)
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

ARCHIVE_PATH="${TMP_DIR}/${ARCHIVE_NAME}"

# Download release archive
if [ "$DOWNLOADER" = "curl" ]; then
  curl -fL --retry 3 --connect-timeout 10 --max-time 300 -o "$ARCHIVE_PATH" "$DOWNLOAD_URL"
else
  wget -O "$ARCHIVE_PATH" "$DOWNLOAD_URL"
fi

# Extract and locate binary
mkdir -p "$TMP_DIR/extract"
tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR/extract"
BIN_PATH=$(find "$TMP_DIR/extract" -type f -name "$BIN_NAME" -perm -u+x | head -n 1)
if [ -z "$BIN_PATH" ]; then
  echo "${BIN_NAME} binary not found in archive." >&2
  exit 1
fi

# Install binary
mkdir -p "$INSTALL_DIR"
install -m 0755 "$BIN_PATH" "${INSTALL_DIR}/${BIN_NAME}"

# Stop and remove existing service if present
if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
  systemctl stop "${SERVICE_NAME}.service"
fi
if systemctl is-enabled --quiet "${SERVICE_NAME}.service"; then
  systemctl disable "${SERVICE_NAME}.service"
fi
if [ -f "$SERVICE_PATH" ]; then
  rm -f "$SERVICE_PATH"
fi

# Write systemd unit
cat > "$SERVICE_PATH" <<UNIT
[Unit]
Description=proxy-everything server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment=RUST_LOG=${RUST_LOG}
Environment=SECRET_KEY=${SECRET_KEY}
ExecStart=${INSTALL_DIR}/${BIN_NAME} -H ${HOST} -p ${PORT}
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT

# Reload systemd and start service
systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"

echo "proxy-server is installed and running."
echo "Service name: ${SERVICE_NAME}.service"
