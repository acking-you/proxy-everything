#!/bin/bash
# Build static library for iOS
# Usage: ./scripts/build-ios.sh [debug|release]

set -e

BUILD_TYPE="${1:-release}"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="$PROJECT_ROOT/ios/ProxyEverything/ProxyEverything"

echo "Building iOS static library ($BUILD_TYPE)..."

# Add iOS targets if not already added
rustup target add aarch64-apple-ios 2>/dev/null || true

cd "$PROJECT_ROOT"

if [ "$BUILD_TYPE" = "release" ]; then
    cargo build --release --target aarch64-apple-ios --features ios --lib
    cp target/aarch64-apple-ios/release/libhttp_proxy.a "$OUTPUT_DIR/"
else
    cargo build --target aarch64-apple-ios --features ios --lib
    cp target/aarch64-apple-ios/debug/libhttp_proxy.a "$OUTPUT_DIR/"
fi

echo "Static library built: $OUTPUT_DIR/libhttp_proxy.a"
