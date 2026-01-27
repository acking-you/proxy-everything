# Repository Guidelines

This repository contains an encrypted HTTP/HTTPS/SOCKS5 proxy system (client + server) written in Rust.

## Project Structure & Module Organization

- `crates/` – workspace crates:
  - `proxy-core` (crypto/codec/protocol/control/relay/metrics/config)
  - `proxy-client` (HTTP/HTTPS/SOCKS5 client)
  - `proxy-server` (server implementation)
  - `proxy-tui` (terminal monitor UI)
  - `proxy-ffi` (FFI for Flutter)
- `crates/*/src/bin/` – binaries:
  - `http-proxy-server`
  - `http-proxy-cli`
  - `proxy-tui`
- `docs/` – deployment and usage guides.
- `docker/` – Dockerfiles for building images.
- `scripts/` + `Makefile` – release/cross-build and image helpers.
- `services/` – ops scripts (e.g., systemd helpers).
- `assets/` – screenshots and diagrams.
- `ui/` – Flutter UI and related assets.

## Build, Test, and Development Commands

- `cargo build --workspace` / `cargo build --workspace --release` – compile workspace.
- `cargo test` / `cargo test <name>` – run unit tests (or a single test).
- `cargo run -p proxy-server --bin http-proxy-server -- -H 0.0.0.0 -p 1081` – run the server locally.
- `cargo run -p proxy-client --bin http-proxy-cli -- -s <server-ip> -c <local-port>` – run the client CLI.
- `make build-server-release` / `make build-cli-release` – run the scripted release builds.
- **Pre-commit requirement**: always run `make clippy` and fix issues, then run `make fmt` before committing.

## Coding Style & Naming Conventions

- Rust edition: 2024; toolchain: stable (`rust-toolchain.toml`).
- Formatting: run `make fmt` (rules in `rustfmt.toml`, 4-space indentation).
- Linting: run `make clippy` before committing.
- Follow Rust naming: `snake_case` (functions/modules), `CamelCase` (types), `SCREAMING_SNAKE_CASE` (consts).

## Testing Guidelines

- Tests are primarily unit tests colocated with code (e.g., `mod tests { ... }`).
- Name tests by behavior (e.g., `encrypt_round_trip`, `parse_proxy_header_invalid`).

## Commit & Pull Request Guidelines

- Commit messages generally follow Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`, `ci:`, `build:`.
- PRs should include: what/why, how to test (exact commands), and any doc/config updates in `docs/` if behavior changes.

## Security & Configuration Notes

- Treat `SECRET_KEY` (32-byte key) as sensitive: don’t log it and don’t commit real values.
- Common configuration is via environment variables; see `crates/proxy-core/src/config/` and `docs/` for details.
