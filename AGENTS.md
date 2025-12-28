# Repository Guidelines

This repository contains an encrypted HTTP/HTTPS/SOCKS5 proxy (client + server) written in Rust.

## Project Structure & Module Organization

- `src/` – library crate with core modules (`client/`, `server/`, `codec/`, `crypto/`, `config/`, `protocol/`, `util/`).
- `src/bin/` – binaries:
  - `http-proxy-server` (remote server)
  - `http-proxy-client` (simple client)
  - `http-proxy-cli` (recommended client CLI)
- `docs/` – deployment and usage guides.
- `docker/` – Dockerfiles for building images.
- `scripts/` + `Makefile` – release/cross-build and image helpers.
- `services/` – ops scripts (e.g., systemd helpers).
- `assets/` – screenshots and diagrams.

## Build, Test, and Development Commands

- `cargo build` / `cargo build --release` – compile debug/release binaries.
- `cargo test` / `cargo test <name>` – run unit tests (or a single test).
- `cargo run --bin http-proxy-server -- -h 0.0.0.0 -p 1081` – run the server locally.
- `cargo run --bin http-proxy-cli -- -s <server-ip> -c <local-port>` – run the client CLI.
- `make build-server-release` / `make build-cli-release` – run the scripted release builds.

## Coding Style & Naming Conventions

- Rust edition: 2024; toolchain: stable (`rust-toolchain.toml`).
- Formatting: run `cargo fmt --all` (rules in `rustfmt.toml`, 4-space indentation).
- Linting: prefer `cargo clippy --all-targets --all-features` before opening a PR.
- Follow Rust naming: `snake_case` (functions/modules), `CamelCase` (types), `SCREAMING_SNAKE_CASE` (consts).

## Testing Guidelines

- Tests are primarily unit tests colocated with code (e.g., `mod tests { ... }`).
- Name tests by behavior (e.g., `encrypt_round_trip`, `parse_proxy_header_invalid`).

## Commit & Pull Request Guidelines

- Commit messages generally follow Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`, `ci:`, `build:`.
- PRs should include: what/why, how to test (exact commands), and any doc/config updates in `docs/` if behavior changes.

## Security & Configuration Notes

- Treat `SECRET_KEY` (32-byte key) as sensitive: don’t log it and don’t commit real values.
- Common configuration is via environment variables; see `src/config/` and `docs/` for details.
