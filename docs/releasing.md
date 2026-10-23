# Releasing

Native binaries and libraries are built here; the apps are built in
`Proxy-UI/Proxy-UI-Flutter`. Tags, pushes and remote releases are the
maintainer's call. Local packaging and verification rules are in
[AGENTS.md](../AGENTS.md#releases-and-packaging).

## 1. Native artifacts

Dispatch `build-deploy.yaml` on the intended source branch with a new
`release_version` (for example `0.4.37`), or push a numeric tag. Either one
rebuilds the server, client, admin and TUI programs for all eight targets, plus
twelve FFI archives that include the macOS TUN helper.

Publishing requires all 44 archives to pass content and source-commit
verification. Each archive contains `build-info.json`, and the release adds
`SHA256SUMS` and `release-manifest.json`. Only numeric tag pushes publish
Docker images.

## 2. Apps

Dispatch `ui/flutter/.github/workflows/build.yaml` in `Proxy-UI/Proxy-UI-Flutter`
with that native `lib_version`, a new UI `release_tag`, and
`create_release=true`. The workflow checks the native hashes before staging the
libraries. Wait for every desktop job and the release job, then inspect the
attached macOS, Windows and Linux packages.

## 3. Mobile packages, built locally

Android APKs and iOS IPAs are built and signed on the maintainer's machine and
attached to the CI-created release by hand. CI may compile them as a check, but
its output is never distributed.

The reason is the signing key. Release builds are signed with the debug
configuration, and each CI runner generates a fresh debug keystore, so every CI
build carries a different certificate. Measured on three published releases:

| Release | Certificate (SHA-256, truncated) |
| --- | --- |
| v1.2.7 | `08fb5536…3354` |
| v1.2.8 | `6852dc3d…51b5` |
| v1.2.9 | `d99b01d4…f987` |
| local `~/.android/debug.keystore` | `5ac9aa7c…305c` |

Android refuses an update whose certificate differs, so those releases could
not upgrade one another: users had to uninstall and lose their data. Local
builds carry the stable key in the last row and upgrade cleanly. Storing that
key as a CI secret would also work, but it puts a signing key on GitHub; that
is the maintainer's decision, never an agent's.
