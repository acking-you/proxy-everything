# Shared Rust runtime and Windows recovery

CipherRelay 2.0.8 uses native 0.6.7. Rebuild and stage the native library with
the UI on every platform: the new asynchronous control and update exports are
required. Existing proxy wire formats and older C exports are unchanged.

## Windows update recovery

The previous Windows updater launched PowerShell with Dart's detached process
mode. A local reproduction on Windows PowerShell 5.1 showed that both detached
modes returned without executing even the first script statement. The normal
process mode worked. Consequently a complete download could be followed by an
application exit without installation.

`proxy-updater` now supplies `cipherrelay-updater.exe`. The UI starts its prepare
mode normally. It copies a worker beside the verified download, requests
elevation, pins the outgoing process handle, and acknowledges readiness before
the UI begins graceful shutdown. The worker verifies size/SHA-256, waits for the
specific process to exit, pins the verified installer file against replacement,
runs Inno Setup, and checks the installed ProductVersion before reopening.
Cancelled or timed-out shutdown cannot install on a later unrelated exit.
Installer failures retain the package, `install-status.json` and `installer.log`.

The complete Windows bundle must contain the updater, `CipherRelay.exe`,
`http_proxy.dll`, `wintun.dll`, Flutter, plugins and data. The supported staging
script and both local/CI packaging checks enforce this. An installation with
the old broken updater needs one manual installation of 2.0.8; its existing
preferences and storage identity are preserved.

## Windows game lobby DNS

On the affected machine, the running 2.0.6 installation logged failure to start
Windows DNS caller attribution with Win32 error 8. An elevated trace inventory
found a `CipherRelay-DNS-*` session owned by an exited process. Without caller
attribution, shared Dnscache requests could not inherit the game's process
exclusion and followed the upstream DNS path instead. This fits delayed lobby
HTTP/DNS setup while established gameplay remains usable; it is not evidence
of a new gameplay UDP transport fault.

Before creating its DNS trace, tun2proxy now reclaims only precisely named
CipherRelay sessions whose owner is provably absent or exited. A live process,
a reused PID, access-denied owner checks and other applications' sessions are
preserved. Startup errors identify the failed ETW API. Administrator integration
tests exercise a real abruptly exited child, preserve a concurrent live trace,
perform real process-attributed DNS, and verify removal of an exclusion restores
the upstream path on the same socket. No packet framing or Android transport
behavior changes.

## Dart audit and ownership

The audit covered handwritten Dart under `lib/`, including services, FFI,
providers, models, screens, galaxy code, widgets and updates. Generated
localizations remain generated output.

| Area | Result and ownership |
| --- | --- |
| Update HTTP, download buffers, SHA-256, Ed25519 | `proxy-updater` streams with backpressure, checks signed metadata, publishes only verified files and cancels stalled bodies. Rust bounds metadata and outstanding progress; Dart presents size, received bytes and speed. |
| Proxy/TUN start-stop-switch, latency, catalog requests | Shared native workers replace per-call Dart isolates. The existing UI operation queue retains exclusive handle lifetime. Native admission rejects overlapping borrows; destroy consumes ownership only after acceptance. |
| Process enumeration | Rust workers enumerate OS processes and executable metadata without blocking the render isolate. The picker retains presentation, search and tree expansion. |
| Logging | One native bounded queue owns disk writes, rotation and flush. Native log callbacks are marked already persisted; Dart no longer writes a duplicate copy. UI-generated diagnostics enter the same native writer. |
| Subscription sharing | Independent `proxy-ui-services` crate owns HTTP and cached Clash/Shadowrocket documents. Golden fixtures preserve previous output. Connections, headers, request time and shutdown are bounded. UI retains LAN address selection and explicit enable/disable. |
| Galaxy math | `galaxy-geometry` owns clipped segment projection, planet orbits/entrance/migration, star positions and country overlap resolution. Reusable native buffers avoid per-frame temporary geometry. Native segment batches release the duplicate Dart world-line graph. |
| Galaxy invalidation | Health/latency changes preserve orbit buffers and cached country layout. Topology, coordinates and orbit parameters invalidate them. Dart compatibility math remains for older libraries and reference tests. |
| Node filters, process-tree presentation | Remain with their UI-owned models. Sending those objects back through JSON on every keystroke would duplicate representation; OS enumeration and network queries already run in Rust. |
| Preferences, model decoding, one-time storage migration | Small configuration state stays with existing providers/plugins and preserves persisted formats. Atomic storage migration remains asynchronous and is not on a frame loop. |
| Window, tray, theming, localization, painting and hit testing | Flutter/plugin ownership remains. Moving widget state across FFI would add synchronization and duplicate object graphs. |
| Android VpnService/package installer; Apple Network Extension and bundle installation | Platform bridges and OS installation tools remain. Shared HTTP/crypto/computation uses Rust on those platforms too. |
| LAN interface selection and desktop lifecycle | Asynchronous OS enumeration, user preferences and graceful UI cleanup stay in their existing service boundaries. |

Native diagnostics rotate at 64 MiB per file with at most eight retained files,
protecting active-file leases. The producer queue is bounded by 1,024 messages
and 8 MiB. Overflows are reported. Existing historical Dart log files are not
deleted as part of this migration.

## Measurement and checks

The reproducible layout benchmark compares **AOT Dart** with a **Release Rust**
DLL and includes allocation, copying and FFI overhead. On the maintainer's
Windows machine, 48 crowded countries, 50 measured samples after warmup:

| Calculation | Median |
| --- | ---: |
| Previous Dart map-based relaxation | 12,278 µs |
| Rust relaxation including FFI | 603 µs |
| Unchanged layout cache | 2 µs |

This is about 20.4× for that calculation, not an application-wide FPS claim.
The benchmark checks coordinates against the previous implementation before
timing. Results vary with hardware and topology.

```powershell
# Root: focused crates plus the normal workspace and strict checks.
cargo test -p proxy-updater -p proxy-ui-services -p galaxy-geometry -p proxy-ffi
cargo test --workspace
cargo test --manifest-path deps/tun2proxy/Cargo.toml
cargo clippy --manifest-path deps/tun2proxy/Cargo.toml --all-targets --all-features -- -D warnings

# ui/flutter, using a freshly built Release DLL.
$env:CIPHERRELAY_NATIVE_TEST_LIB = "D:\rust_pro\proxy-everything\target\release\http_proxy.dll"
$env:GALAXY_NATIVE_LIBRARY = $env:CIPHERRELAY_NATIVE_TEST_LIB
fvm flutter analyze --no-fatal-infos
fvm flutter test
fvm dart compile exe tool/benchmark_native_layout.dart -o build/benchmark_native_layout.exe
.\build\benchmark_native_layout.exe $env:CIPHERRELAY_NATIVE_TEST_LIB
```

The updater tests run actual helper/installer fixture processes without changing
the installed application. They cover exit ordering, paths with spaces/Unicode,
cancelled shutdown, package modification, installer errors and falsely reported
success. FFI tests cover real callbacks, ownership, cancellation, subscription
shutdown, and galaxy math parity. The real Windows DNS tests are ignored by
default because they require administrator ETW access.
