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

Dispatch `ui/flutter/.github/workflows/build.yaml` from `main` in
`Proxy-UI/Proxy-UI-Flutter` with the native `lib_version`, a new UI
`release_tag`, and `create_release=true`. The workflow checks native input
hashes before building the desktop and Android packages. The publication job
verifies the package matrix and signs the shared Ed25519 update manifest.

## 3. Android signing and updates

Before packaging, increase the Android build number in the Flutter
`pubspec.yaml`. To build APKs for an existing release, dispatch
`android-hotfix.yaml` on `main` with the existing `release_tag` and the chosen
native `lib_version`. It checks the existing manifest signature and package
hashes, adds the verified APKs and updates the signed manifest and `SHA256SUMS`.
The manifest records the Android build and its Flutter and native commits.

The `android-package.yaml` workflow builds unsigned split APKs for
`arm64-v8a`, `armeabi-v7a` and `x86_64`. A separate runner signs them with the
existing `androiddebugkey` from the `ANDROID_RELEASE_KEYSTORE` environment
secret in `Proxy-UI/Proxy-UI-Flutter`. The `android-release` environment is
restricted to the `main` branch. The maintainer provisions the original
keystore as base64; enrollment preserves the local copy for recovery.

Verify that all three APKs carry the published certificate with SHA-256
`5ac9aa7c2a99b410864e7e88b4ec9a28771ddadf69c620a9b18b8dd66ac8305c`
and application ID `com.proxyui.proxy_ui`. Flutter adds ABI offsets to the
build number. Each APK must have a greater effective code than the installed
APK for that ABI to upgrade in place. The workflow checks the certificate,
package, native library, ABI, version name and effective version code.

iOS packages are built and signed locally.
