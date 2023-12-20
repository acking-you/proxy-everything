#!/bin/bash
SCRIPT_DIR=$(cd `dirname $0`; pwd)
PROJECT_DIR="$SCRIPT_DIR/../.."

cd $PROJECT_DIR

echo "Build(Release)..."
cargo build --bin http-proxy-client --release
echo "Build success!"