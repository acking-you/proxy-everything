# Android VPN Development

The Flutter Android client captures device traffic with Android's
`VpnService`; it does not create routes or a TUN device from Rust. The active
data path is:

```text
Android application TCP/UDP
  -> VpnService TUN file descriptor
  -> tun2proxy
     -> TCP and proxy-enabled UDP -> socks5://127.0.0.1:<local-port>
        -> proxy-everything client -> remote proxy server -> destination
     -> UDP when SOCKS5 UDP is off
        -> direct fallback on  -> physical network -> destination
        -> direct fallback off -> blocked
```

Virtual DNS remains local in every UDP policy and accepts both UDP and
length-prefixed TCP queries on port 53, so TCP applications can still resolve
hostnames without external UDP. Direct UDP fallback matches
Mihomo's behavior for an outbound without UDP support, but that traffic does
not traverse the proxy. Fake-IP hostnames are resolved over the TCP proxy before
the direct UDP socket is opened, preventing resolver recursion through the VPN.
Internationalized DNS labels are retained in their ASCII/Punycode wire form
when a fake IP is converted back to a hostname. Rendering an IDN such as
`xn--ngstr-lra8j.com` as Unicode is useful for display, but forwarding that
display string to a remote SOCKS or system resolver can make an otherwise valid
Google CDN destination unresolvable.

`ProxyVpnService` retains the `ParcelFileDescriptor`. The platform channel
passes its integer descriptor to `proxy_start_android_tun`, which duplicates
it synchronously. Rust owns and closes only that duplicate. Closing either the
VPN or native forwarding therefore cannot double-close a descriptor owned by
the other layer.

## Application policy

Open **VPN Applications** on the main Proxy page to choose one of three modes:

| Mode | Android `VpnService.Builder` policy |
|------|-------------------------------------|
| **All** | Every eligible application uses the VPN except Proxy Everything |
| **Bypass** | Selected applications and Proxy Everything bypass the VPN |
| **Only** | Only selected applications use the VPN |

In **Proxy Configuration**, leave **Direct UDP fallback** enabled to send
captured UDP directly when **SOCKS5 UDP** is off. Disable both switches for a
strict TCP-only VPN that blocks captured non-DNS UDP. The same policy is used
by desktop TUN mode.

Allowed and disallowed application lists are mutually exclusive Android APIs,
so the UI always applies exactly one policy. Changing the policy while the VPN
is active drains native TUN sessions, recreates the Android interface, and
keeps the local proxy listener running. If recreation fails, the previous
policy is restored.

Proxy Everything is always outside its own VPN. In **All** and **Bypass** it is
added to the disallowed list; in **Only** it is omitted from the allowed list.
This is a loop-prevention invariant, not a user preference: the same process
owns both the local SOCKS5 listener and the upstream connection.

The app requests `QUERY_ALL_PACKAGES` to show installed, enabled applications
that hold the `INTERNET` permission. A Play-distributed build must declare this
core VPN use case in Play Console and satisfy Google Play's package-visibility
policy before release.

## Build native libraries

Install the Android SDK and NDK selected by Flutter, then run the supported
PowerShell staging script from the repository root:

```powershell
.\scripts\android\build-native.ps1 -Configuration Debug `
  -Architectures x86_64,aarch64,armv7
```

The script installs the required Rust targets, builds `proxy-ffi` with the NDK
Clang linker, and stages the uncommitted libraries in:

```text
ui/flutter/native/android/x86_64/libhttp_proxy.so
ui/flutter/native/android/arm64-v8a/libhttp_proxy.so
ui/flutter/native/android/armeabi-v7a/libhttp_proxy.so
```

Use `-Configuration Release` for a release build. The default NDK is
`28.2.13676358`, matching the Flutter 3.38.6 Android toolchain; override
`-NdkVersion` only when the pinned Flutter SDK changes.

Build the Flutter package with FVM:

```powershell
Set-Location ui\flutter
fvm install
fvm flutter pub get

# x86_64 emulator
fvm flutter build apk --debug --target-platform android-x64

# Physical devices plus x86_64 emulators
fvm flutter build apk --release `
  --target-platform "android-arm,android-arm64,android-x64"
```

`ui/flutter/pubspec.yaml` uses Flutter's `versionName+versionCode` form, for
example `1.2.9+2`. Android only accepts an in-place update when the new APK has
the same application ID and signing certificate and its numeric `versionCode`
is not lower than the installed package. Increment the value after `+` for
every Android release. Flutter adds an ABI-specific prefix to APKs produced by
`--split-per-abi` (for example, ARM64 build number `2` becomes version code
`2002`), so update a split APK with the new APK for the same architecture. Do
not replace an installed split release with a universal or debug APK whose
effective version code is lower. Previously the project omitted
`+build-number`, so every release reused the same base code and normal
package-installer updates could be rejected even though the saved application
data was compatible.

The release build currently uses the local Android debug certificate for
compatibility with existing installations. Keep and back up the original
`%USERPROFILE%\.android\debug.keystore`: replacing it changes the signing
identity and Android cannot update an app signed by the old certificate. A
future production signing-key migration must be planned separately rather than
silently replacing this file.

The current Android release build still uses the debug signing configuration.
Configure a private release keystore before publishing an APK or app bundle.

## Run and debug

Install an x86_64 debug APK and launch it:

```powershell
$adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
& $adb devices -l
& $adb -s emulator-5554 install -r `
  build\app\outputs\flutter-apk\app-debug.apk
& $adb -s emulator-5554 shell monkey -p com.proxyui.proxy_ui 1
```

In the app:

1. Configure the remote server and local listener port.
2. Start the local proxy.
3. Optionally select an application policy.
4. Enable **VPN Service** and approve Android's VPN consent dialog.

The VPN notification remains visible while capture is active and exposes a
disconnect action. Android permits only one prepared VPN application per user;
starting another VPN can revoke this service.

Useful checks:

```powershell
# TUN address, IPv4/IPv6 default routes, DNS, owner UID, and app UID ranges
& $adb -s emulator-5554 shell dumpsys connectivity |
  Select-String -Pattern 'VPN CONNECTED|tun0|DnsAddresses|OwnerUid|Uids:'

# Foreground VpnService state
& $adb -s emulator-5554 shell dumpsys activity services `
  com.proxyui.proxy_ui

# TCP connection generated by a captured UID
& $adb -s emulator-5554 shell toybox nc -z -w 8 1.1.1.1 80
```

The VPN interface uses `172.19.0.1/30`,
`fdfe:dcba:9876::1/126`, IPv4 and IPv6 default routes, and MTU 1500. Its DNS
portal is `172.19.0.2`, while fake-IP allocations remain in tun2proxy's
separate `198.18.0.0/15` pool. The ranges must not overlap: Android probes a
VPN DNS server with opportunistic DNS-over-TLS, and a portal/fake-IP collision
can send that probe to an unrelated hostname. tun2proxy rejects TCP port 853
only for the configured virtual portal, making Android fall back immediately
to the local plain-DNS handler instead of proxying an unreachable private
address until timeout.

## 16 KB page-size verification

Use an Android 15 or newer `google_apis_ps16k` emulator image. Confirm its page
size, then install and exercise the same x86_64 APK:

```powershell
& $adb -s emulator-5556 shell getconf PAGESIZE
# Expected: 16384
```

Verify APK zip alignment and ELF load-segment alignment before release:

```powershell
& "$env:LOCALAPPDATA\Android\Sdk\build-tools\36.0.0\zipalign.exe" `
  -c -P 16 -v 4 build\app\outputs\flutter-apk\app-debug.apk

& "$env:ANDROID_NDK_HOME\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe" `
  -lW native\android\x86_64\libhttp_proxy.so |
  Select-String LOAD
# Every LOAD line must report alignment 0x4000 or greater.
```

## Troubleshooting

- Start the local proxy before enabling **VPN Service**. Native forwarding
  deliberately rejects a TUN descriptor when the SOCKS5 listener is absent.
- Complete TCP and UDP capture requires a remote server from the same release.
  If UDP readiness fails against an older server, upgrade the server. Otherwise
  disable SOCKS5 UDP and choose either direct fallback or strict UDP blocking.
- If Android reports another VPN, disconnect it first. Only one VPN interface
  can own the user's default VPN routes.
- An empty **Only** selection is rejected. Uninstalled packages in a stored
  policy are ignored when Android rebuilds the interface.
- Do not remove the Proxy Everything package exclusion in Kotlin. Rust socket
  protection cannot replace Android's per-UID loop barrier in this design.
