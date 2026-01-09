#!/bin/bash
# Build script for iOS targets
# Usage: ./scripts/build-ios.sh [device|simulator|all]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_DIR/target/ios"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if rustup targets are installed
check_targets() {
    log_info "Checking Rust targets..."

    if ! rustup target list --installed | grep -q "aarch64-apple-ios"; then
        log_warn "Installing aarch64-apple-ios target..."
        rustup target add aarch64-apple-ios
    fi

    if ! rustup target list --installed | grep -q "aarch64-apple-ios-sim"; then
        log_warn "Installing aarch64-apple-ios-sim target..."
        rustup target add aarch64-apple-ios-sim
    fi
}

# Build for iOS device (arm64)
build_device() {
    log_info "Building for iOS device (aarch64-apple-ios)..."
    RUSTFLAGS="--cfg ios_build" cargo rustc --lib --release --target aarch64-apple-ios --features ios --no-default-features -- --crate-type=staticlib

    mkdir -p "$OUTPUT_DIR/device"
    cp "$PROJECT_DIR/target/aarch64-apple-ios/release/libhttp_proxy.a" "$OUTPUT_DIR/device/"
    log_info "Device build complete: $OUTPUT_DIR/device/libhttp_proxy.a"
}

# Build for iOS simulator (arm64)
build_simulator() {
    log_info "Building for iOS simulator (aarch64-apple-ios-sim)..."
    RUSTFLAGS="--cfg ios_build" cargo rustc --lib --release --target aarch64-apple-ios-sim --features ios --no-default-features -- --crate-type=staticlib

    mkdir -p "$OUTPUT_DIR/simulator"
    cp "$PROJECT_DIR/target/aarch64-apple-ios-sim/release/libhttp_proxy.a" "$OUTPUT_DIR/simulator/"
    log_info "Simulator build complete: $OUTPUT_DIR/simulator/libhttp_proxy.a"
}

# Create XCFramework
create_xcframework() {
    log_info "Creating XCFramework..."

    XCFRAMEWORK_PATH="$OUTPUT_DIR/HttpProxy.xcframework"
    rm -rf "$XCFRAMEWORK_PATH"

    xcodebuild -create-xcframework \
        -library "$OUTPUT_DIR/device/libhttp_proxy.a" \
        -headers "$PROJECT_DIR/ios/include" \
        -library "$OUTPUT_DIR/simulator/libhttp_proxy.a" \
        -headers "$PROJECT_DIR/ios/include" \
        -output "$XCFRAMEWORK_PATH"

    log_info "XCFramework created: $XCFRAMEWORK_PATH"
}

# Generate C header
generate_header() {
    log_info "Generating C header..."

    mkdir -p "$PROJECT_DIR/ios/include"
    cat > "$PROJECT_DIR/ios/include/proxy_ffi.h" << 'EOF'
#ifndef PROXY_FFI_H
#define PROXY_FFI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Result codes
typedef enum {
    PROXY_OK = 0,
    PROXY_INVALID_PARAM = -1,
    PROXY_CONNECTION_FAILED = -2,
    PROXY_RUNTIME_ERROR = -3,
    PROXY_ALREADY_RUNNING = -4,
    PROXY_NOT_RUNNING = -5,
} ProxyResult;

// Opaque handle
typedef struct ProxyHandle ProxyHandle;

// Configuration
typedef struct {
    const char* server_host;
    uint16_t server_port;
    uint16_t local_port;
    const char* session_key;
} ProxyConfig;

// API functions
ProxyHandle* proxy_create(void);
ProxyResult proxy_start(ProxyHandle* handle, const ProxyConfig* config);
ProxyResult proxy_stop(ProxyHandle* handle);
void proxy_destroy(ProxyHandle* handle);
int proxy_is_running(const ProxyHandle* handle);
void proxy_init_logging(void);

#ifdef __cplusplus
}
#endif

#endif // PROXY_FFI_H
EOF

    log_info "Header generated: $PROJECT_DIR/ios/include/proxy_ffi.h"
}

# Main
cd "$PROJECT_DIR"

case "${1:-all}" in
    device)
        check_targets
        generate_header
        build_device
        ;;
    simulator)
        check_targets
        generate_header
        build_simulator
        ;;
    all)
        check_targets
        generate_header
        build_device
        build_simulator
        create_xcframework
        ;;
    *)
        echo "Usage: $0 [device|simulator|all]"
        exit 1
        ;;
esac

log_info "Build complete!"
