# Repository Guidelines

## Scope and Priorities

This repository contains an encrypted HTTP/HTTPS/SOCKS5 proxy implemented in
Rust, plus a Flutter desktop/mobile client. Keep changes narrowly scoped,
preserve existing wire behavior, and prefer the abstractions already present in
the owning crate.

When instructions conflict, prioritize correctness and compatibility in this
order: wire protocol, security, data integrity, graceful shutdown, observability,
then local implementation simplicity.

## Repository Layout

- `crates/proxy-core`: protocol, codecs, crypto, config, relay, metrics, nodes.
- `crates/proxy-client`: local HTTP/HTTPS/SOCKS5 proxy and client CLI.
- `crates/proxy-server`: remote server, admin CLI, control plane, relay routing.
- `crates/proxy-tui`: terminal control-plane interface.
- `crates/proxy-ffi`: C ABI consumed by Flutter; builds as `http_proxy`.
- `deps/tun2proxy`: TUN capture, route setup, and runtime process bypass.
- `ui/flutter`: Flutter UI Git submodule.
- `scripts/windows`: supported Windows build and run entry points.
- `scripts/build`, `scripts/release`, `docker`, `services`: release and operations.
- `docs`: user-facing behavior, deployment, and troubleshooting.

The primary binaries are `http-proxy-server`, `http-proxy-cli`,
`http-proxy-admin`, and `proxy-tui`.

## Toolchains

### Rust

- Use the toolchain pinned by `rust-toolchain.toml`; do not override it locally
  in project files.
- Windows builds use the MSVC target and require Visual Studio 2022 Build Tools
  with the Desktop development with C++ workload plus CMake.
- Keep `Cargo.lock` committed and update it only when dependency resolution
  actually changes.

### Flutter and FVM

- Flutter is managed exclusively with FVM.
- `ui/flutter/.fvmrc` is the source of truth and currently pins Flutter 3.38.6.
- Never use bare `flutter` or `dart` commands for this project. Use
  `fvm flutter ...` and `fvm dart ...` from `ui/flutter`.
- Run `fvm install` after cloning or after the pinned SDK changes.
- Do not commit `.fvm/`, `.dart_tool/`, `build/`, or `ui/flutter/native/`.
  The native directory contains staged build products, not source.

## Windows Workflows

Run these from the repository root in PowerShell:

```powershell
# Build all Rust binaries, the FFI DLL, and the Flutter Windows app.
.\scripts\windows\build.ps1 -Configuration Debug
.\scripts\windows\build.ps1 -Configuration Release

# Run a Rust command-line component.
.\scripts\windows\run-cli.ps1 server -- -H 127.0.0.1 -p 1081
.\scripts\windows\run-cli.ps1 client -- -s 127.0.0.1 -p 1081 -c 1080
.\scripts\windows\run-cli.ps1 admin -- --help
.\scripts\windows\run-cli.ps1 tui -- --help

# Build/stage http_proxy.dll and start Flutter with hot reload.
.\scripts\windows\run-ui.ps1 -Mode Debug
```

`stage-ui-native.ps1` is the single source of truth for placing
`target/<profile>/http_proxy.dll` and `wintun.dll` under
`ui/flutter/native/windows/<architecture>/`. Do not duplicate this copy logic
in ad hoc commands or commit the resulting DLL.

## Direct Development Commands

```bash
cargo build --workspace
cargo test --workspace
cargo test -p proxy-core <test-name>
cargo run -p proxy-server --bin http-proxy-server -- -H 127.0.0.1 -p 1081
cargo run -p proxy-client --bin http-proxy-cli -- -s 127.0.0.1 -p 1081 -c 1080
```

From `ui/flutter`:

```bash
fvm flutter pub get
fvm flutter analyze --no-fatal-infos
fvm flutter test
fvm dart format lib test
fvm flutter run -d windows
```

On POSIX systems, the pre-commit sequence remains `make clippy` followed by
`make fmt`. On Windows, use the equivalent Cargo commands. For repository code,
strict Clippy should pass without linting vendored dependencies:

```bash
cargo clippy -p proxy-core -p proxy-client -p proxy-server -p proxy-tui -p proxy-ffi --all-targets --all-features --no-deps -- -D warnings
cargo fmt -p proxy-core -p proxy-client -p proxy-server -p proxy-tui -p proxy-ffi -- --check
```

## Rust Engineering Conventions

- Rust edition is 2024. Use `rustfmt.toml` and standard Rust naming.
- Keep ownership boundaries between crates. Shared wire, relay, and codec logic
  belongs in `proxy-core`; frontend protocol handling belongs in `proxy-client`;
  destination forwarding belongs in `proxy-server`.
- Prefer typed parsers and enums over stringly typed branching.
- Avoid new abstractions unless they remove meaningful duplication or match an
  established pattern.
- Comments should explain protocol requirements, invariants, unsafe code, or
  non-obvious platform behavior. Do not narrate straightforward assignments.
- Keep public API documentation accurate when behavior or wire format changes.

## Protocol Compatibility

- Existing TCP clients and servers must remain interoperable across upgrades.
- `ProxyHeader.transport` is backward compatible by design: readers default a
  missing value to TCP, and writers omit the TCP default from JSON.
- New transport fields must have a legacy-safe default or be explicitly
  versioned. Do not add `deny_unknown_fields` to wire structs.
- SOCKS5 UDP packets preserve datagram boundaries. `FRAG != 0` is unsupported
  and must be dropped without terminating an otherwise valid association.
- UDP associations are owned by their TCP control connection and must remain
  pinned to the validated client endpoint.
- Protocol changes require unit tests for parsing/framing plus end-to-end tests
  for both encrypted and unencrypted paths. Compatibility changes require a
  legacy-reader or legacy-writer test in each affected direction.

## Flutter and FFI Conventions

- Keep Dart FFI declarations synchronized with exported functions and layouts
  in `proxy-ffi`; integer widths, ownership, and free functions are part of the
  ABI contract.
- Never free Rust-owned memory from Dart except through the matching exported
  Rust free function.
- Build and stage a fresh DLL after changing `proxy-ffi`, `proxy-client`, or
  `proxy-core` before testing the UI.
- Keep UI state and blocking native calls off the render path. Preserve the
  existing provider/service boundaries.
- TUN integrations must enforce the current executable in native process
  bypass state; UI configuration is not a security or loop-prevention boundary.
- Update `pubspec.lock` when dependency resolution changes. Generated Flutter
  plugin files should change only when dependencies or platform configuration
  change.

## Testing Expectations

- Scale coverage with risk. Parser fixes need focused unit tests; shared codecs,
  transports, FFI, and user workflows need integration coverage.
- Name tests by behavior, for example `legacy_proxy_header_defaults_to_tcp`.
- Network tests must bind loopback and ephemeral ports; do not depend on public
  services unless the test is explicitly marked as such.
- Tests must clean up listeners, cancellation tokens, temporary state, and OS
  proxy settings even on expected error paths.
- For Flutter changes, run analyze and tests with FVM. For Windows integration
  changes, also build the Windows desktop bundle and verify `http_proxy.dll` is
  next to `proxy_ui.exe`.

## Logging and Security

- Use structured `tracing` fields. Log association and connection lifecycle at
  `info`, recoverable rejection reasons at `debug` or `warn`, and per-packet
  details only at `debug` or `trace`.
- Include transport, direction, peer/destination, byte counts, and close reason
  where useful. Never log secret/session keys, proxy passwords, auth headers,
  decrypted headers, or user payloads.
- Treat `SECRET_KEY`, control session keys, admin tokens, and external proxy
  credentials as sensitive. Documentation and tests must use placeholders.
- Preserve RAII cleanup for system proxy changes and cancellation-aware shutdown.

## Git and Submodules

- The worktree may already contain user changes. Never reset or overwrite them.
- `ui/flutter` and `deps/*` are submodules. Report changes inside a submodule
  separately from the parent gitlink state.
- Do not update submodule commits unless the task requires it. Do not commit
  generated build artifacts from a submodule.
- Use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
  `build:`, `ci:`). A PR should state what changed, why, exact verification
  commands, protocol/ABI impact, and documentation changes.

## Completion Checklist

Before handing off a change:

1. Inspect both root and affected submodule status.
2. Run focused tests while iterating.
3. Run strict Clippy and Rust formatting checks for Rust changes.
4. Run `cargo test --workspace` for shared or protocol changes.
5. Run FVM analyze/test/build for Flutter or FFI changes.
6. Confirm Windows UI bundles contain both `http_proxy.dll` and `wintun.dll`.
7. Confirm no secrets, generated binaries, caches, or unrelated files are staged.
8. Update README/docs whenever commands, configuration, or behavior changed.
