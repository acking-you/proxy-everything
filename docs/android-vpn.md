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

Fake-IP allocations are persisted in the application's private support
directory and restored before the VPN starts. Android services such as Google
Play can retain DNS answers across a VPN restart or an in-place CipherRelay
upgrade; without persistent mappings, a cached `198.18.0.0/15` address could be
reassigned to another hostname and make an otherwise working TCP or QUIC path
look offline. The cache is append-only during normal allocation and is compacted
after enough entries become stale. A truncated final record is repaired at the
next start.

### IPv4 DNS on exits without IPv6

The Android VPN keeps both `0.0.0.0/0` and `::/0` capture routes. These routes
prevent bypass; they do not prove that a proxy server has an IPv6 Internet
connection. Like the desktop default, Android now uses the native TUN's IPv4
DNS policy instead of unconditionally enabling AAAA answers. Ordinary UDP and
TCP DNS replies retain A records and remove AAAA records. Fake-IP remains an
independent, opt-in setting. This does not change native protocol framing or
the Android VPN's IPv6 capture route.

With an IPv4-only exit, a captured IPv6 TCP connection can complete its local
handshake before the remote connection fails. TLS then closes or resets even
though an IPv4 request to the same website succeeds. Racing initial TCP
connections does not necessarily recover a later TLS failure; see
[RFC 8305, section 9](https://www.rfc-editor.org/rfc/rfc8305.html#section-9).
Node latency/egress probes use an HTTP endpoint and do not certify IPv6 or
HTTPS reachability.

This was reproduced with Android 2.0.6+71 through the UAE and Poland exits:
certificate-validated IPv4 HTTPS succeeded, while IPv6 TLS failed. Switching
the same APK to Fake-IP removed the failing IPv6 choices. The UAE exit had
no global IPv6 route. The Singapore control also failed IPv6, so this finding
is not specific to one country. Desktop IPv4 HTTPS and HTTP/2 controls passed.
The user's physical phone/browser was not available for direct validation.

Follow-up controls also covered the Hong Kong node. Build 72 fetched Google
and YouTube pages through its Android VPN with Fake-IP and UDP disabled. A
fresh desktop browser using an Android-owned CONNECT socket through that VPN
received HTTP 200 for both sites over HTTP/2 and TLS 1.3. This exercises browser
TLS through Android forwarding, but is not a test of Android Chrome's own DNS
selection. Separate native sockets bound to the physical Windows interface
also established TLS without passing through the active Singapore TUN.
These controls do not reproduce or explain the reported difference between
Singapore and the other nodes on the physical phone; the IPv6 defect and its
fix should not be presented as proof of that complete diagnosis.
The user subsequently confirmed that build 72 resolved the reported failures
on the physical phone. This confirms the fix's practical result without adding
a packet trace explaining the original per-node difference.

Restart the VPN and the affected application after an upgrade if it retained
old DNS answers. Literal IPv6 destinations and application-managed encrypted
DNS are outside this DNS compatibility policy and still need an IPv6-capable
exit. Do not remove the `::/0` capture route as a workaround.

UDP readiness is separate: an old server can pass the TCP node probe but close
the UDP association before acknowledging it. Upgrade that server for SOCKS5
UDP support, or disable SOCKS5 UDP; disable direct UDP fallback as well when
all captured traffic must stay inside the proxy. The client deliberately
reports this preflight failure instead of silently leaking UDP directly.

`ProxyVpnService` retains the `ParcelFileDescriptor`. The platform channel
passes its integer descriptor to `proxy_start_android_tun`, which duplicates
it synchronously. Rust owns and closes only that duplicate. Closing either the
VPN or native forwarding therefore cannot double-close a descriptor owned by
the other layer.

## Application policy

Open **VPN Applications** on the main Proxy page to choose one of three modes:

| Mode | Android `VpnService.Builder` policy |
|------|-------------------------------------|
| **All** | Every eligible application uses the VPN except CipherRelay |
| **Bypass** | Selected applications and CipherRelay bypass the VPN |
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

CipherRelay is always outside its own VPN. In **All** and **Bypass** it is
added to the disallowed list; in **Only** it is omitted from the allowed list.
This is a loop-prevention invariant, not a user preference: the same process
owns both the local SOCKS5 listener and the upstream connection.

That platform-enforced exclusion also allows the local listener to preserve
the configured auto-proxy decision while VPN capture is active. Android TUN
therefore does not enable the desktop-only `force_proxy` loop guard. Desktop
TUN retains that guard because it does not have Android's package-level routing
boundary.

The service registers a default-network callback and explicitly publishes the
current non-VPN network through `VpnService.setUnderlyingNetworks`. This is
updated when Wi-Fi or mobile connectivity changes. Some update schedulers,
including vendor-customized Google Play builds, reject work from network
capabilities before opening a payload connection; leaving Android or an OEM to
infer the VPN's underlying transport can therefore produce an immediate
"offline" result even while ordinary sockets work. The VPN start log records
the underlying and VPN transports together with their validated and metered
capabilities so this preflight path can be distinguished from DNS, TCP, and UDP
failures.

Establishing the Java VPN interface happens before Rust can attach the duplicated
TUN descriptor. Android may begin connectivity validation during that short
window, when no packet consumer exists yet. The Flutter startup sequence now
waits for native TUN readiness and then polls the live VPN
`NET_CAPABILITY_VALIDATED` state. It does not report VPN startup success until
validation completes; after ten seconds it tears the incomplete VPN down and
reports the captured capabilities instead of leaving update schedulers to emit
a misleading offline error.

The app requests `QUERY_ALL_PACKAGES` to show installed, enabled applications
that hold the `INTERNET` permission. The package catalog is read with requested
permissions in one query and cached in memory. Icons are fetched lazily only
for visible rows, batched across a frame, and kept in a bounded LRU cache. A
Play-distributed build must declare this core VPN use case in Play Console and
satisfy Google Play's package-visibility policy before release.

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
- Do not remove the CipherRelay package exclusion in Kotlin. Rust socket
  protection cannot replace Android's per-UID loop barrier in this design.

## Android HTTPS certificate verification

Rust HTTP clients on Android use the shared `proxy_core::util::http_client_builder`
and bundled Mozilla public roots from `webpki-roots`. Certificate chains,
hostnames, and validity periods remain verified; update manifests and downloads
also retain their signature and SHA-256 checks. This path does not require Java
VM initialization when Flutter loads the library through Dart FFI. Desktop
clients continue using their platform certificate verifier. Android custom
user-installed certificate authorities are not included in this public-root store.

For an Android update hotfix, install the previous release on a persistent test
device, upgrade with `adb install -r`, and exercise **Check for updates** in the
release APK. Confirm the signed manifest is retrieved, repeated checks and a
background/foreground cycle preserve the process, and an unavailable network
shows an error without exiting. A launch or proxy-start smoke test alone does
not cover the update HTTPS path.

With an English or Chinese UI, run the repeatable release smoke check:

```powershell
python scripts/android/verify-update-check.py --adb "$env:LOCALAPPDATA/Android/Sdk/platform-tools/adb.exe" --serial emulator-5554 --expected-code 4077 --output target/android-update-check.json
```

It checks the installed version, taps the actual update control, waits for a
successful signed-manifest result, and repeats after backgrounding the app.
