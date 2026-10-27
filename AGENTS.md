# Repository Guidelines

An encrypted HTTP/HTTPS/SOCKS5 proxy in Rust with a Flutter client. Keep
changes narrowly scoped, keep wire behaviour compatible, and use the
abstractions the owning crate already has. When goals conflict, rank them:
wire protocol, security, data integrity, graceful shutdown, observability,
then implementation simplicity.

## Layout

| Path | Contents |
| --- | --- |
| `crates/proxy-crypto` | Configuration-free crypto and generic v3 records |
| `crates/proxy-core` | Wire format, sessions, TCP/QUIC carriers, codecs, config, relay, metrics, nodes, allocator |
| `crates/proxy-client` | Local HTTP/HTTPS/SOCKS5 proxy, TUN integration, `http-proxy-cli` |
| `crates/proxy-server` | Server, control plane, relay routing, managed SOCKS5, `http-proxy-admin` |
| `crates/proxy-tui` | Terminal control-plane UI, `proxy-tui` |
| `crates/proxy-ffi` | C ABI for Flutter, built as `http_proxy` |
| `crates/proxy-ui-services`, `proxy-updater`, `galaxy-geometry` | App services such as app proxies, the updater, galaxy projection |
| `deps/*` | Submodules, including `tun2proxy` (TUN, routes, process bypass) and `quinn` (QUIC) |
| `ui/flutter` | Flutter app (submodule) |
| `scripts/` | Per-platform build/run entry points, `build` and `release` packaging, `bench` |
| `docs/` | User-facing behaviour, deployment and troubleshooting |

## Toolchains

- **Rust**: the toolchain pinned by `rust-toolchain.toml`; never override it in
  project files. Windows uses the MSVC target with Visual Studio 2022 Build
  Tools (Desktop development with C++) and CMake. Keep `Cargo.lock` committed,
  and change it only when dependency resolution changes.
- **Flutter**: FVM only. `ui/flutter/.fvmrc` pins the SDK (Flutter 3.47.8).
  Never run bare `flutter` or `dart`; use `fvm flutter …` and `fvm dart …` from
  `ui/flutter`, and run `fvm install` after cloning or an SDK change. Never
  commit `.fvm/`, `.dart_tool/`, `build/` or `ui/flutter/native/`, which holds
  staged build products.

## Commands

```bash
cargo build --workspace
cargo test --workspace
cargo test -p proxy-core <test-name>
cargo run -p proxy-server --bin http-proxy-server -- -H 127.0.0.1 -p 1081
cargo run -p proxy-client --bin http-proxy-cli -- -s 127.0.0.1 -p 1081 -c 1080
```

Windows, from the repository root in PowerShell:

```powershell
.\scripts\windows\build.ps1 -Configuration Debug     # or Release; add -Offline to reuse caches
.\scripts\windows\run-cli.ps1 server -- -H 127.0.0.1 -p 1081   # also client, admin, tui
.\scripts\windows\run-ui.ps1 -Mode Debug             # stage http_proxy.dll, hot reload
```

`stage-ui-native.ps1` is the only code that copies
`target/<profile>/http_proxy.dll` and `wintun.dll` into
`ui/flutter/native/windows/<architecture>/`. Don't duplicate it in ad hoc
commands, and never commit the DLLs.

Flutter, from `ui/flutter`:

```bash
fvm flutter pub get
fvm flutter analyze --no-fatal-infos
fvm flutter test
fvm dart format lib test
```

A worktree nested inside the main checkout, such as `.claude/worktrees/…`,
cannot build `tun2proxy` or `ipstack`: their build scripts run `cargo
metadata`, which resolves the outer checkout's workspace. Build those crates
from a worktree outside the checkout.

## Checks before committing

Run `make clippy` and then `make fmt` (on Windows, the equivalent Cargo
commands). Strict Clippy must pass for repository crates without linting
vendored dependencies:

```bash
cargo clippy -p proxy-crypto -p proxy-core -p proxy-client -p proxy-server -p proxy-tui -p proxy-ffi --all-targets --all-features --no-deps -- -D warnings
cargo fmt -p proxy-crypto -p proxy-core -p proxy-client -p proxy-server -p proxy-tui -p proxy-ffi -- --check
```

For `tun2proxy` changes, also run its own checks:

```powershell
cargo test --manifest-path deps/tun2proxy/Cargo.toml
cargo clippy --manifest-path deps/tun2proxy/Cargo.toml --all-targets --all-features -- -D warnings
cargo fmt --manifest-path deps/tun2proxy/Cargo.toml -- --check
```

## Engineering rules

### Rust

- Edition 2024, `rustfmt.toml`, standard naming.
- Keep crate boundaries: shared wire, relay, codec and carrier logic belongs in
  `proxy-core`, frontend protocol handling in `proxy-client`, and destination
  forwarding in `proxy-server`.
- Prefer typed parsers and enums, such as `UpstreamAddress`, over stringly
  typed branching.
- Add an abstraction only when it removes real duplication or matches an
  established pattern.
- Comments explain protocol requirements, invariants, unsafe code and
  non-obvious platform behaviour, not straightforward assignments.
- Keep public API documentation accurate when behaviour or wire format changes.
- `proxy-core::allocator` alone selects mimalloc and its RSS tuning. Never
  declare another `#[global_allocator]` or tune the allocator in leaf crates;
  embedded components such as `tun2proxy` inherit it.

### Protocol compatibility

- Existing TCP clients and servers must stay interoperable across upgrades.
- `ProxyHeader.transport` defaults a missing value to TCP, and writers omit
  that default. New wire fields need a legacy-safe default or explicit
  versioning. Never add `deny_unknown_fields` to wire structs.
- The carrier (TCP or QUIC) is chosen per session from the node address. It
  never changes the wire protocol, and there is no silent fallback between
  carriers. `CarrierStream` behaves the same on both: `shutdown` half-closes,
  and dropping delivers the bytes already written before closing.
- SOCKS5 UDP preserves datagram boundaries. Drop `FRAG != 0` packets without
  ending an otherwise valid association. A UDP association belongs to its
  control connection and stays pinned to the validated client endpoint.
- Protocol changes need parsing and framing unit tests plus end-to-end tests
  over both legacy and v3. Compatibility changes need a legacy-reader or
  legacy-writer test for each affected direction.

### Flutter and FFI

- Keep Dart FFI declarations in sync with `proxy-ffi` exports and layouts.
  Integer widths, ownership and free functions are part of the ABI.
- Free Rust-owned memory from Dart only through the matching Rust free function.
- After changing `proxy-ffi`, `proxy-client` or `proxy-core`, build and stage a
  fresh native library before testing the UI.
- Keep UI state and blocking native calls off the render path, and preserve
  the provider and service boundaries.
- TUN integrations must enforce the current executable in native process
  bypass. UI configuration is not a security or loop-prevention boundary.
- Update `pubspec.lock` only when resolution changes. Generated plugin files
  change only with dependencies or platform configuration.

### Tests

- Scale coverage with risk. Parser fixes need focused unit tests; shared
  codecs, carriers, FFI and user workflows need integration coverage.
- Name tests by behaviour, for example `legacy_proxy_header_defaults_to_tcp`.
- Network tests bind loopback and ephemeral ports and never depend on public
  services unless explicitly marked.
- Clean up listeners, cancellation tokens, temporary state and OS proxy
  settings, including on expected error paths.
- For Flutter changes, run analyze and tests with FVM. For Windows integration
  changes, also build the desktop bundle and confirm `http_proxy.dll` sits next
  to `CipherRelay.exe`.

### Logging and security

- Use structured `tracing` fields. Log connection and association lifecycle at
  `info`, recoverable rejections at `debug` or `warn`, and per-packet detail
  only at `debug` or `trace`.
- Include carrier, transport, direction, peer or destination, byte counts and
  close reason where useful. Never log secret or session keys, proxy passwords,
  auth headers, decrypted headers or payloads.
- Treat `SECRET_KEY`, control session keys, admin tokens and external proxy
  credentials as sensitive; docs and tests use placeholders.
- Preserve RAII cleanup of system proxy changes and cancellation-aware shutdown.

## Releases and packaging

Every package handed to a user is an upgradeable release, even for local
testing. "Publish" means verified, versioned local artifacts unless the user
explicitly asks for a tag, push or upload. The CI release flow is described in
[docs/releasing.md](docs/releasing.md).

**Mobile packages are built locally, never by CI.** CI-built APKs and IPAs
carry a new debug certificate on every run and cannot upgrade an installed app
(the evidence is in [docs/releasing.md](docs/releasing.md#3-mobile-packages-built-locally)).
The release workflow collects desktop artifacts only; never add `*.apk` or
`*.ipa` to it. Never move the signing key into CI on your own initiative.

### Android

- Before every package, increment the build number in `ui/flutter/pubspec.yaml`
  (`version: <name>+<build>`), even when the name stays the same. Never reuse or
  decrease a build number that may already be installed.
- Keep the application ID `com.proxyui.proxy_ui`. An APK updates an installed
  copy only when the ID and signing certificate match and its effective
  `versionCode` is greater.
- Release builds use the local debug key. Never delete, regenerate or replace
  `%USERPROFILE%\.android\debug.keystore`; a signing migration must be planned
  explicitly, because a new key breaks in-place upgrades.
- Split APKs per ABI; build a universal APK only on request. Build `arm64-v8a`
  for modern devices, plus `armeabi-v7a` or `x86_64` when the target needs it.
- After changing `proxy-core`, `proxy-client`, `proxy-ffi` or `tun2proxy`,
  rebuild the native library first. Never package stale staged `.so` files.

```powershell
.\scripts\android\build-native.ps1 -Configuration Release -Architectures aarch64
# all supported ABIs: -Architectures x86_64,aarch64,armv7
# then, from ui/flutter:
fvm flutter build apk --release --target-platform android-arm64 --split-per-abi
```

- Flutter adds ABI offsets to split version codes. Check every APK with
  `aapt dump badging` (package, `versionName`, effective `versionCode`, SDKs,
  ABI) and `apksigner verify --print-certs`, and compare the certificate digest
  with the previous release.
- Name deliverables `cipherrelay-v<name>-<build>-android-<abi>.apk` in an
  ignored build location. Report the absolute path, ABI, `versionName`,
  effective `versionCode`, size, SHA-256 and certificate result.

### Windows

```powershell
.\scripts\windows\build.ps1 -Configuration Release
# When vswhere fails but VS 2022 Build Tools is installed:
.\scripts\windows\build.ps1 -Configuration Release -Offline `
  -VisualStudioPath "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
```

- The explicit-path fallback builds with MSVC and Ninja Multi-Config in a child
  process into `ui/flutter/build/windows/x64-explicit-msvc/runner/Release`. It
  doesn't repair the registry, change the SDK or stop desktop processes.
- Never stop a running `proxy_ui` to build or package. If a file is locked, use
  a separate output directory or report the lock.
- A release is the whole `ui/flutter/build/windows/<architecture>/runner/Release`
  directory. Confirm it contains `CipherRelay.exe`, `http_proxy.dll`,
  `wintun.dll`, `flutter_windows.dll`, `data` and the plugin files.
- Package it as `ui/flutter/build/packages/cipherrelay-v<name>-<build>-windows-<architecture>.zip`
  with a single top-level application directory, inspect the archive, and
  report its path, version, architecture, size and SHA-256.

### Verification and commits

- Run the relevant Rust checks plus FVM analyze and tests before packaging. A
  successful compile alone is not release verification.
- Commit inside affected submodules first, then their gitlinks and root
  changes. Use Conventional Commits, report each hash, and confirm the root and
  submodule worktrees are clean.
- Never commit APKs, ZIPs, `ui/flutter/build/` or `ui/flutter/native/`.
- Never tag, push, create a remote release or upload artifacts unless the user
  explicitly asks for that action.

## Git and submodules

- The worktree may already contain user changes. Never reset or overwrite them.
- `ui/flutter` and `deps/*` are submodules. Report changes inside a submodule
  separately from the parent gitlink.
- Update submodule commits only when the task requires it. Before merging a
  root PR, re-pin each submodule to the commit merged on its default branch.
- Use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
  `build:`, `ci:`). A PR states what changed and why, the exact verification
  commands, protocol and ABI impact, and documentation changes.

## Completion checklist

1. Inspect root and affected submodule status.
2. Run focused tests while iterating.
3. Run strict Clippy and the formatting check for Rust changes.
4. Run `cargo test --workspace` for shared or protocol changes.
5. Run FVM analyze, test and build for Flutter or FFI changes.
6. Confirm Windows bundles contain both `http_proxy.dll` and `wintun.dll`.
7. Confirm no secrets, binaries, caches or unrelated files are staged.
8. Update the README and docs when commands, configuration or behaviour change.
