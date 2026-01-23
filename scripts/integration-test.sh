#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-18081}"
LOG_DIR="${LOG_DIR:-/tmp/proxy-everything-test}"
SERVER_LOG="$LOG_DIR/proxy-server.log"

mkdir -p "$LOG_DIR"

export CONTROL_REQUIRE_ENCRYPTION="${CONTROL_REQUIRE_ENCRYPTION:-false}"
export SERVER_HOST="$HOST"
export SERVER_PORT="$PORT"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

printf "[info] building proxy-server...\n"
cargo build -p proxy-server >/dev/null

printf "[info] starting proxy-server on %s:%s...\n" "$HOST" "$PORT"
cargo run -p proxy-server --bin http-proxy-server -- -H "$HOST" -p "$PORT" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

printf "[info] waiting for server...\n"
for _ in $(seq 1 40); do
  if python - <<PY
import socket
s = socket.socket()
s.settimeout(0.2)
try:
    s.connect(("$HOST", int("$PORT")))
    s.close()
    raise SystemExit(0)
except Exception:
    raise SystemExit(1)
PY
  then
    break
  fi
  sleep 0.25
done

printf "[info] running control-plane smoke test...\n"
cargo run -p proxy-server --bin control-smoke -- --host "$HOST" --port "$PORT"

printf "[info] integration test completed successfully.\n"
