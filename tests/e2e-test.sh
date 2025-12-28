#!/bin/bash
# End-to-end test script for proxy-everything
# Tests full chain: curl -> client -> server -> httpbin.org

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Config
SERVER_PORT=${SERVER_PORT:-11081}
CLIENT_PORT=${CLIENT_PORT:-11080}
SECRET_KEY=${SECRET_KEY:-"test-secret-key-for-e2e-testing!"}

# PIDs for cleanup
SERVER_PID=""
CLIENT_PID=""

cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    sleep 0.5
}
trap cleanup EXIT

log_ok() { echo -e "${GREEN}✓ $1${NC}"; }
log_fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }
log_info() { echo -e "${YELLOW}→ $1${NC}"; }

# Build binaries
log_info "Building binaries..."
cd "$PROJECT_DIR"
cargo build --release --bin http-proxy-server --bin http-proxy-client 2>/dev/null || cargo build --bin http-proxy-server --bin http-proxy-client

SERVER_BIN="$PROJECT_DIR/target/release/http-proxy-server"
CLIENT_BIN="$PROJECT_DIR/target/release/http-proxy-client"
[ ! -f "$SERVER_BIN" ] && SERVER_BIN="$PROJECT_DIR/target/debug/http-proxy-server"
[ ! -f "$CLIENT_BIN" ] && CLIENT_BIN="$PROJECT_DIR/target/debug/http-proxy-client"

[ ! -f "$SERVER_BIN" ] && log_fail "Server binary not found"
[ ! -f "$CLIENT_BIN" ] && log_fail "Client binary not found"

log_ok "Binaries ready"

# Kill existing processes on target ports
kill_port() {
    local port=$1
    local pid=$(lsof -ti:$port 2>/dev/null)
    if [ -n "$pid" ]; then
        log_info "Killing existing process on port $port (PID: $pid)"
        kill -9 $pid 2>/dev/null
        sleep 0.5
    fi
}

kill_port "$SERVER_PORT"
kill_port "$CLIENT_PORT"

# Start server
log_info "Starting server on port $SERVER_PORT..."
SECRET_KEY="$SECRET_KEY" "$SERVER_BIN" -H 127.0.0.1 -p "$SERVER_PORT" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 1

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    log_fail "Server failed to start"
fi
log_ok "Server started (PID: $SERVER_PID)"

# Start client
log_info "Starting client on port $CLIENT_PORT -> server $SERVER_PORT..."
SECRET_KEY="$SECRET_KEY" SERVER_HOST=127.0.0.1 SERVER_PORT="$SERVER_PORT" CLIENT_PORT="$CLIENT_PORT" "$CLIENT_BIN" >/dev/null 2>&1 &
CLIENT_PID=$!
sleep 1

if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    log_fail "Client failed to start"
fi
log_ok "Client started (PID: $CLIENT_PID)"

# Test 1: Basic HTTP request through proxy
log_info "Test 1: Basic HTTP GET via proxy..."
RESPONSE=$(curl -s --proxy "http://127.0.0.1:$CLIENT_PORT" "http://httpbin.org/get" --max-time 30)
if echo "$RESPONSE" | grep -q '"Host": "httpbin.org"'; then
    log_ok "Test 1 passed: HTTP GET works"
else
    log_fail "Test 1 failed: HTTP GET response invalid"
fi

# Test 2: HTTPS request through proxy (CONNECT)
log_info "Test 2: HTTPS GET via proxy (CONNECT tunnel)..."
RESPONSE=$(curl -s --proxy "http://127.0.0.1:$CLIENT_PORT" "https://httpbin.org/get" --max-time 30)
if echo "$RESPONSE" | grep -q '"Host": "httpbin.org"'; then
    log_ok "Test 2 passed: HTTPS CONNECT works"
else
    log_fail "Test 2 failed: HTTPS response invalid"
fi

# Test 3: POST request
log_info "Test 3: HTTP POST via proxy..."
RESPONSE=$(curl -s --proxy "http://127.0.0.1:$CLIENT_PORT" -X POST -d "test=data" "http://httpbin.org/post" --max-time 30)
if echo "$RESPONSE" | grep -q '"test": "data"'; then
    log_ok "Test 3 passed: HTTP POST works"
else
    log_fail "Test 3 failed: POST data not echoed"
fi

# Test 4: Large data transfer
log_info "Test 4: Large data transfer (10KB)..."
RESPONSE=$(curl -s --proxy "http://127.0.0.1:$CLIENT_PORT" "http://httpbin.org/bytes/10240" --max-time 60 | wc -c)
if [ "$RESPONSE" -ge 10000 ]; then
    log_ok "Test 4 passed: Received $RESPONSE bytes"
else
    log_fail "Test 4 failed: Expected >=10000 bytes, got $RESPONSE"
fi

# Test 5: Multiple concurrent requests
log_info "Test 5: Concurrent requests..."
CURL_PIDS=""
for i in 1 2 3 4 5; do
    curl -s --proxy "http://127.0.0.1:$CLIENT_PORT" "http://httpbin.org/get?n=$i" --max-time 30 >/dev/null &
    CURL_PIDS="$CURL_PIDS $!"
done
for pid in $CURL_PIDS; do
    wait $pid
done
log_ok "Test 5 passed: Concurrent requests completed"

# Test 6: Headers preservation
log_info "Test 6: Custom headers..."
RESPONSE=$(curl -s --proxy "http://127.0.0.1:$CLIENT_PORT" -H "X-Custom-Header: test-value" "http://httpbin.org/headers" --max-time 30)
if echo "$RESPONSE" | grep -q "X-Custom-Header"; then
    log_ok "Test 6 passed: Headers preserved"
else
    log_fail "Test 6 failed: Custom header not found"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}All E2E tests passed!${NC}"
echo -e "${GREEN}========================================${NC}"
