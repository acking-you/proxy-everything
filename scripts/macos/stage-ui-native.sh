#!/usr/bin/env bash
# Build and stage the macOS native artifacts the Flutter UI loads.
#
# Two files are needed, not one: the FFI library the app links against, and the
# privileged TUN helper that creates the utun device. macOS refuses to create
# that device without root and cannot elevate a running GUI, so the helper is
# started through an administrator prompt and must ship inside the bundle.
set -euo pipefail

CONFIGURATION="Debug"
SKIP_BUILD=0

usage() {
    cat <<'EOF'
Usage: stage-ui-native.sh [--configuration Debug|Release] [--skip-build]

Builds proxy-ffi and http-proxy-tun-helper, then stages both into
ui/flutter/native/macos/ where the Xcode embed phase picks them up.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --configuration)
            CONFIGURATION="${2:-}"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

case "$CONFIGURATION" in
    Debug) CARGO_PROFILE="debug" ;;
    Release) CARGO_PROFILE="release" ;;
    *)
        echo "Unsupported configuration: $CONFIGURATION (expected Debug or Release)" >&2
        exit 1
        ;;
esac

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "This script stages macOS artifacts and must run on macOS." >&2
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo was not found. Install the Rust toolchain first." >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

if [[ "$SKIP_BUILD" -eq 0 ]]; then
    profile_args=()
    if [[ "$CONFIGURATION" == "Release" ]]; then
        profile_args+=(--release)
    fi
    # Two invocations on purpose. `--bin` is a target filter applied across the
    # whole package selection, so asking for the helper in the same command
    # silently drops proxy-ffi's library target and leaves a stale dylib staged.
    cargo build -p proxy-ffi "${profile_args[@]}"
    cargo build -p proxy-client --bin http-proxy-tun-helper "${profile_args[@]}"
fi

SOURCE_DIR="$REPO_ROOT/target/$CARGO_PROFILE"
NATIVE_DIR="$REPO_ROOT/ui/flutter/native/macos"
mkdir -p "$NATIVE_DIR"

SOURCE_DYLIB="$SOURCE_DIR/libhttp_proxy.dylib"
SOURCE_HELPER="$SOURCE_DIR/http-proxy-tun-helper"
for artifact in "$SOURCE_DYLIB" "$SOURCE_HELPER"; do
    if [[ ! -f "$artifact" ]]; then
        echo "Native artifact was not produced: $artifact" >&2
        exit 1
    fi
done

DEST_DYLIB="$NATIVE_DIR/libhttp_proxy.dylib"
cp -f "$SOURCE_DYLIB" "$DEST_DYLIB"
# Without an @rpath install name the bundled app looks for the dylib at its
# absolute build path and fails to load it.
install_name_tool -id "@rpath/libhttp_proxy.dylib" "$DEST_DYLIB"
codesign --force --sign - "$DEST_DYLIB"
echo "Staged Flutter native library: $DEST_DYLIB"

DEST_HELPER="$NATIVE_DIR/http-proxy-tun-helper"
cp -f "$SOURCE_HELPER" "$DEST_HELPER"
codesign --force --sign - "$DEST_HELPER"
echo "Staged privileged TUN helper: $DEST_HELPER"
