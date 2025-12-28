#!/bin/bash
# Test script for http-proxy-admin CLI
# Validates all control plane operations

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Config
SERVER_PORT=${SERVER_PORT:-12081}
CLIENT_PORT=${CLIENT_PORT:-12080}
# Use the default key that server falls back to
DEFAULT_KEY="my-secret-key123my-secret-key123"
# 32-byte session key for control plane tests
CONTROL_KEY=${CONTROL_KEY:-"control-session-key-32-bytes!!!!"}
ADMIN_TOKEN=${ADMIN_TOKEN:-"admin-token-for-tests"}

# PIDs
SERVER_PID=""
CLIENT_PID=""
TEST_HOME=""

cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    sleep 0.5
    [ -n "$TEST_HOME" ] && rm -rf "$TEST_HOME"
}
trap cleanup EXIT

log_ok() { echo -e "${GREEN}✓ $1${NC}"; }
log_fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }
log_info() { echo -e "${YELLOW}→ $1${NC}"; }

require_32_bytes() {
    local key_name=$1
    local key_value=$2
    if [ "${#key_value}" -ne 32 ]; then
        log_fail "$key_name must be 32 bytes (got ${#key_value})"
    fi
}

# Build
log_info "Building binaries..."
cd "$PROJECT_DIR"
cargo build --release --bin http-proxy-server --bin http-proxy-client --bin http-proxy-admin 2>/dev/null \
    || cargo build --bin http-proxy-server --bin http-proxy-client --bin http-proxy-admin

SERVER_BIN="$PROJECT_DIR/target/release/http-proxy-server"
CLIENT_BIN="$PROJECT_DIR/target/release/http-proxy-client"
ADMIN_BIN="$PROJECT_DIR/target/release/http-proxy-admin"
[ ! -f "$SERVER_BIN" ] && SERVER_BIN="$PROJECT_DIR/target/debug/http-proxy-server"
[ ! -f "$CLIENT_BIN" ] && CLIENT_BIN="$PROJECT_DIR/target/debug/http-proxy-client"
[ ! -f "$ADMIN_BIN" ] && ADMIN_BIN="$PROJECT_DIR/target/debug/http-proxy-admin"

[ ! -f "$SERVER_BIN" ] && log_fail "Server binary not found"
[ ! -f "$ADMIN_BIN" ] && log_fail "Admin binary not found"

log_ok "Binaries ready"

# Kill existing processes on ports
kill_port() {
    local port=$1
    local pid
    pid=$(lsof -ti:$port 2>/dev/null || true)
    if [ -n "$pid" ]; then
        log_info "Killing existing process on port $port (PID: $pid)"
        kill -9 $pid 2>/dev/null || true
        sleep 0.5
    fi
}

start_server() {
    local port=$1
    shift
    local envs=("$@")

    kill_port "$port"
    log_info "Starting server on port $port..."
    TEST_HOME=$(mktemp -d)
    env "${envs[@]}" HOME="$TEST_HOME" "$SERVER_BIN" -H 127.0.0.1 -p "$port" >/dev/null 2>&1 &
    SERVER_PID=$!
    sleep 1

    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        log_fail "Server failed to start"
    fi
    log_ok "Server started (PID: $SERVER_PID)"
}

stop_server() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
        sleep 0.5
    fi
}

start_client() {
    local port=$1
    local server_port=$2

    kill_port "$port"
    log_info "Starting client on port $port -> server $server_port..."
    SERVER_HOST=127.0.0.1 SERVER_PORT="$server_port" CLIENT_PORT="$port" "$CLIENT_BIN" >/dev/null 2>&1 &
    CLIENT_PID=$!
    sleep 1

    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        log_fail "Client failed to start"
    fi
    log_ok "Client started (PID: $CLIENT_PID)"
}

stop_client() {
    if [ -n "$CLIENT_PID" ]; then
        kill "$CLIENT_PID" 2>/dev/null || true
        CLIENT_PID=""
        sleep 0.5
    fi
}

# JSON helpers (use python for strict validation)
assert_json_ok_type() {
    local response=$1
    local expected_type=$2
    if ! RESPONSE_JSON="$response" python - "$expected_type" <<'PY'
import json
import os
import sys

expected = sys.argv[1]
try:
    data = json.loads(os.environ.get("RESPONSE_JSON", ""))
except Exception as exc:
    raise SystemExit(f"invalid json: {exc}")
if data.get("ok") is not True:
    raise SystemExit(f"expected ok=true, got: {data}")
result = data.get("result")
if not isinstance(result, dict) or result.get("type") != expected:
    raise SystemExit(f"expected result.type={expected}, got: {result}")
PY
    then
        echo "$response"
        log_fail "Expected ok=true with result.type=$expected_type"
    fi
}

assert_json_error_contains() {
    local response=$1
    local expected=$2
    if ! RESPONSE_JSON="$response" python - "$expected" <<'PY'
import json
import os
import sys

expected = sys.argv[1]
try:
    data = json.loads(os.environ.get("RESPONSE_JSON", ""))
except Exception as exc:
    raise SystemExit(f"invalid json: {exc}")
if data.get("ok") is not False:
    raise SystemExit(f"expected ok=false, got: {data}")
err = data.get("error") or ""
if expected not in err:
    raise SystemExit(f"expected error containing '{expected}', got: {err}")
PY
    then
        echo "$response"
        log_fail "Expected ok=false with error containing '$expected'"
    fi
}

assert_nodes_contains() {
    local response=$1
    local addr=$2
    if ! RESPONSE_JSON="$response" python - "$addr" <<'PY'
import json
import os
import sys

addr = sys.argv[1]
try:
    data = json.loads(os.environ.get("RESPONSE_JSON", ""))
except Exception as exc:
    raise SystemExit(f"invalid json: {exc}")
if data.get("ok") is not True:
    raise SystemExit(f"expected ok=true, got: {data}")
result = data.get("result") or {}
if result.get("type") != "nodes":
    raise SystemExit(f"expected result.type=nodes, got: {result}")
nodes = result.get("nodes") or []
found = any(
    n.get("addr") == addr or n.get("node_id") == addr
    for n in nodes
    if isinstance(n, dict)
)
if not found:
    raise SystemExit(f"node not found: {addr}")
PY
    then
        echo "$response"
        log_fail "Expected nodes list to contain $addr"
    fi
}

assert_nodes_not_contains() {
    local response=$1
    local addr=$2
    if ! RESPONSE_JSON="$response" python - "$addr" <<'PY'
import json
import os
import sys

addr = sys.argv[1]
try:
    data = json.loads(os.environ.get("RESPONSE_JSON", ""))
except Exception as exc:
    raise SystemExit(f"invalid json: {exc}")
if data.get("ok") is not True:
    raise SystemExit(f"expected ok=true, got: {data}")
result = data.get("result") or {}
if result.get("type") != "nodes":
    raise SystemExit(f"expected result.type=nodes, got: {result}")
nodes = result.get("nodes") or []
found = any(
    n.get("addr") == addr or n.get("node_id") == addr
    for n in nodes
    if isinstance(n, dict)
)
if found:
    raise SystemExit(f"node still present: {addr}")
PY
    then
        echo "$response"
        log_fail "Expected nodes list to not contain $addr"
    fi
}

assert_array_limit() {
    local response=$1
    local expected_type=$2
    local field=$3
    local limit=$4
    if ! RESPONSE_JSON="$response" python - "$expected_type" "$field" "$limit" <<'PY'
import json
import os
import sys

expected_type = sys.argv[1]
field = sys.argv[2]
limit = int(sys.argv[3])
try:
    data = json.loads(os.environ.get("RESPONSE_JSON", ""))
except Exception as exc:
    raise SystemExit(f"invalid json: {exc}")
if data.get("ok") is not True:
    raise SystemExit(f"expected ok=true, got: {data}")
result = data.get("result") or {}
if result.get("type") != expected_type:
    raise SystemExit(f"expected result.type={expected_type}, got: {result}")
arr = result.get(field)
if not isinstance(arr, list):
    raise SystemExit(f"expected {field} list, got: {type(arr)}")
if len(arr) > limit:
    raise SystemExit(f"expected len({field}) <= {limit}, got: {len(arr)}")
PY
    then
        echo "$response"
        log_fail "Expected $field list length <= $limit"
    fi
}

generate_traffic() {
    log_info "Generating traffic for metrics..."
    curl -s --proxy "http://127.0.0.1:$CLIENT_PORT" "http://httpbin.org/get" --max-time 30 >/dev/null || true
    curl -s --proxy "http://127.0.0.1:$CLIENT_PORT" "https://httpbin.org/get" --max-time 30 >/dev/null || true
    curl -s --proxy "http://127.0.0.1:$CLIENT_PORT" "http://httpbin.org/bytes/1024" --max-time 30 >/dev/null || true
    sleep 1
    log_ok "Traffic generated"
}

# Ensure control key length is valid for AES-256
require_32_bytes "CONTROL_KEY" "$CONTROL_KEY"

# ============================================================================
# Phase 1: Base admin functionality (default key, no token)
# ============================================================================
log_info "Phase 1: Base admin CLI tests"
start_server "$SERVER_PORT"
start_client "$CLIENT_PORT" "$SERVER_PORT"
generate_traffic

ADMIN_BASE=("$ADMIN_BIN" -H 127.0.0.1 -p "$SERVER_PORT" -k "$DEFAULT_KEY")

# Test 1: Ping
log_info "Test 1: Ping server..."
RESPONSE=$("${ADMIN_BASE[@]}" ping)
assert_json_ok_type "$RESPONSE" "pong"
log_ok "Test 1 passed: Ping works"

# Test 2: List nodes (initial)
log_info "Test 2: List nodes..."
RESPONSE=$("${ADMIN_BASE[@]}" nodes list)
assert_json_ok_type "$RESPONSE" "nodes"
log_ok "Test 2 passed: List nodes works"

# Test 3: Add node
log_info "Test 3: Add node..."
NODE_ADDR="192.168.1.100:1081"
RESPONSE=$("${ADMIN_BASE[@]}" nodes add "$NODE_ADDR")
assert_json_ok_type "$RESPONSE" "ack"
log_ok "Test 3 passed: Add node works"

# Test 4: List nodes (verify added)
log_info "Test 4: Verify node added..."
RESPONSE=$("${ADMIN_BASE[@]}" nodes list)
assert_nodes_contains "$RESPONSE" "$NODE_ADDR"
log_ok "Test 4 passed: Node appears in list"

# Test 5: Remove node
log_info "Test 5: Remove node..."
RESPONSE=$("${ADMIN_BASE[@]}" nodes remove "$NODE_ADDR")
assert_json_ok_type "$RESPONSE" "ack"
log_ok "Test 5 passed: Remove node works"

# Test 6: Verify node removed
log_info "Test 6: Verify node removed..."
RESPONSE=$("${ADMIN_BASE[@]}" nodes list)
assert_nodes_not_contains "$RESPONSE" "$NODE_ADDR"
log_ok "Test 6 passed: Node removed from list"

# Test 7: Realtime stats
log_info "Test 7: Get realtime stats..."
RESPONSE=$("${ADMIN_BASE[@]}" metrics realtime)
assert_json_ok_type "$RESPONSE" "realtime_stats"
log_ok "Test 7 passed: Realtime stats works"

# Test 8: Recent connections (limit)
log_info "Test 8: Get recent connections..."
RESPONSE=$("${ADMIN_BASE[@]}" metrics connections --limit 10)
assert_array_limit "$RESPONSE" "connections" "connections" 10
log_ok "Test 8 passed: Recent connections works"

# Test 9: Time buckets (minute)
log_info "Test 9: Get time buckets (minute)..."
RESPONSE=$("${ADMIN_BASE[@]}" metrics buckets --granularity minute --count 5)
assert_array_limit "$RESPONSE" "time_buckets" "buckets" 5
log_ok "Test 9 passed: Time buckets (minute) works"

# Test 10: Time buckets (hour, short form)
log_info "Test 10: Get time buckets (hour, short form)..."
RESPONSE=$("${ADMIN_BASE[@]}" metrics buckets --granularity h --count 3)
assert_array_limit "$RESPONSE" "time_buckets" "buckets" 3
log_ok "Test 10 passed: Time buckets (hour) works"

# Test 11: Time buckets (day, short form)
log_info "Test 11: Get time buckets (day, short form)..."
RESPONSE=$("${ADMIN_BASE[@]}" metrics buckets --granularity d --count 2)
assert_array_limit "$RESPONSE" "time_buckets" "buckets" 2
log_ok "Test 11 passed: Time buckets (day) works"

# Test 12: Top-N hosts
log_info "Test 12: Get top-N hosts..."
RESPONSE=$("${ADMIN_BASE[@]}" metrics top-n --category hosts --limit 10)
assert_array_limit "$RESPONSE" "top_n" "entries" 10
log_ok "Test 12 passed: Top-N hosts works"

# Test 13: Top-N IPs (short form)
log_info "Test 13: Get top-N IPs (short form)..."
RESPONSE=$("${ADMIN_BASE[@]}" metrics top-n --category ip --limit 5)
assert_array_limit "$RESPONSE" "top_n" "entries" 5
log_ok "Test 13 passed: Top-N IPs works"

# Test 14: Invalid granularity
log_info "Test 14: Invalid granularity..."
RESPONSE=$("${ADMIN_BASE[@]}" metrics buckets --granularity week --count 1 2>&1 || true)
if echo "$RESPONSE" | grep -qi "invalid granularity"; then
    log_ok "Test 14 passed: Invalid granularity rejected"
else
    echo "$RESPONSE"
    log_fail "Test 14 failed: Invalid granularity not rejected"
fi

# Test 15: Invalid category
log_info "Test 15: Invalid category..."
RESPONSE=$("${ADMIN_BASE[@]}" metrics top-n --category ports --limit 1 2>&1 || true)
if echo "$RESPONSE" | grep -qi "invalid category"; then
    log_ok "Test 15 passed: Invalid category rejected"
else
    echo "$RESPONSE"
    log_fail "Test 15 failed: Invalid category not rejected"
fi

stop_client
stop_server

# ============================================================================
# Phase 2: Admin token + session key env fallback
# ============================================================================
log_info "Phase 2: Admin token + session key env tests"
start_server "$SERVER_PORT" "CONTROL_ADMIN_TOKEN=$ADMIN_TOKEN" "CONTROL_SESSION_KEY=$CONTROL_KEY"

ADMIN_ENV_BASE=("$ADMIN_BIN" -H 127.0.0.1 -p "$SERVER_PORT")

# Test 16: Unauthorized without token
log_info "Test 16: Unauthorized without token..."
RESPONSE=$(CONTROL_SESSION_KEY="$CONTROL_KEY" "${ADMIN_ENV_BASE[@]}" ping 2>&1 || true)
assert_json_error_contains "$RESPONSE" "unauthorized"
log_ok "Test 16 passed: Missing token rejected"

# Test 17: Unauthorized with wrong token
log_info "Test 17: Unauthorized with wrong token..."
RESPONSE=$(CONTROL_SESSION_KEY="$CONTROL_KEY" "${ADMIN_ENV_BASE[@]}" --token "wrong-token" ping 2>&1 || true)
assert_json_error_contains "$RESPONSE" "unauthorized"
log_ok "Test 17 passed: Wrong token rejected"

# Test 18: Authorized with correct token (env session key)
log_info "Test 18: Authorized with correct token..."
RESPONSE=$(CONTROL_SESSION_KEY="$CONTROL_KEY" "${ADMIN_ENV_BASE[@]}" --token "$ADMIN_TOKEN" ping)
assert_json_ok_type "$RESPONSE" "pong"
log_ok "Test 18 passed: Token + env session key works"

stop_server

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}All Admin CLI tests passed!${NC}"
echo -e "${GREEN}========================================${NC}"
