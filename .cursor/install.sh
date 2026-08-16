#!/usr/bin/env bash
# Cloud Agent install script for proxy-everything.
#
# Idempotent bootstrap for the Rust workspace: it fetches the path-dependency
# submodules under deps/ and warms the build cache. It is safe to run repeatedly.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# The Rust workspace's path dependencies (kanal, uni-stream, better_mimalloc_rs,
# rust-smallvec, tun2proxy, ipstack, sysproxy-rs) live in git submodules whose
# .gitmodules entries use SSH URLs. Cloud Agents authenticate over HTTPS with a
# token, so rewrite git@github.com: to https://github.com/ before cloning.
git config --global url."https://github.com/".insteadOf "git@github.com:"

# Initialize only the submodules the Rust workspace builds against. The nested
# mimalloc C source under better_mimalloc_rs is required by the allocator, hence
# --recursive. ui/flutter is a separate Flutter app and is intentionally left
# uninitialized; the Rust workspace excludes it.
git submodule update --init --recursive \
  deps/kanal \
  deps/uni-stream \
  deps/better_mimalloc_rs \
  deps/rust-smallvec \
  deps/tun2proxy \
  deps/ipstack \
  deps/sysproxy-rs

# Build the entire workspace so the target cache is warm for the agent. This also
# compiles the vendored mimalloc C source through better_mimalloc_rs.
cargo build --workspace
