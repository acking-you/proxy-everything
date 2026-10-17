# Network resilience review: native 0.4.31 / UI 1.2.17+43

This review starts from native commit `1847db9`, tun2proxy `071b8a4`, and
ProxyUI `34f9189`. It covers connection setup, TCP/UDP forwarding, Windows
physical egress recovery, native resource ownership, and UI lifecycle/status.
It does not establish the cause of any particular past Wi-Fi outage.

## Windows follow-up against the working v1.2.15 release (2026-10-14)

The comparison baseline is the published UI **v1.2.15+38**, native **0.4.30**,
with tun2proxy **a718098**. The affected published UI **v1.2.23+53** uses native
**0.4.38** and tun2proxy **c38e108**. The embedded revision strings in both
downloaded Windows DLLs confirm these TUN revisions.
The older process still running during investigation logged revision `980f7c3`,
so it was not used as a substitute for the actual v1.2.15 release baseline.

- **Confirmed regression in automatic egress refresh:** native 0.4.31 added
  periodic Windows egress discovery and stopped pinning `args.bind_interface`
  to the initial physical interface. Device creation only copied its actual
  name into route setup, leaving `args.tun` unset for the forwarding runtime.
  Refresh then failed to exclude the created adapter's LUID: its `/1` route
  could win, followed by heuristic physical-interface fallback. Pass the
  actual device name to both consumers. Tests cover automatic naming and
  selection with competing capture/physical routes. The reported logs show
  fallback to the expected WLAN, so this defect alone does **not** establish
  the cause of the complete outage.
- **Changed TCP deadline:** v1.2.15 waited for the OS connect result; 0.4.31+
  applies three seconds per address within an eight-second overall budget.
  The reported `TCP address timed out` is generated here, before wire-protocol
  negotiation. Transient loss or slow route recovery can therefore fail sooner.
  A packet capture was not taken; neither retransmission loss nor a route loop
  was established. The subsequent audit removed these two added limits and
  separated the local client's 15-second input deadline from outbound dialing.
  TUN setup now uses its existing configured TCP timeout (600 seconds by
  default), rather than imposing another hidden ten-second limit while waiting
  for the local SOCKS reply. DNS lookup, external-proxy negotiation, control
  requests and health probes retain their own separately scoped deadlines.
- **Loopback versus upstream:** both published DLLs passed HTTP and SOCKS5
  requests through the same three endpoints (12 requests, all HTTP 200), using
  separate ephemeral loopback ports, TUN/system proxy disabled and no persistent
  cache. Six additional socket-scoped physical-interface TCP probes succeeded.
  The existing old TUN remained active, so these are baseline/protocol checks,
  not verification of the new TUN's routes or the GUI executable's firewall
  treatment. Preferences, routes, system proxy and the existing process were
  unchanged by these checks.
- **Startup status:** four affected starts logged roughly 0.35–0.69 seconds
  from native TUN startup to adapter/route readiness. Those timestamps do not
  cover all UI, elevation and queued-operation delays. Readiness currently
  certifies adapter/route setup, not an end-to-end usable upstream connection.
- **DNS mode:** failures appeared with both proxied real DNS and Fake-IP.
  Cached `198.19.*` addresses can persist after Fake-IP is disabled; retained
  reverse mappings are intentional upgrade compatibility, not evidence that
  new Fake-IP allocation is still enabled.

The Windows refresh path is platform-specific; macOS uses its helper and
different route/interface APIs. This explains why macOS success does not
validate Windows egress selection, but is not itself proof of an outage cause.
Live adapter activation, capture/return routing and GUI startup latency remain
unverified: this investigation must not disconnect the user's running TUN.

Initial follow-up verification passed 84 tun2proxy tests, 252 workspace tests (seven
existing ignored cases), strict tun2proxy and first-party Clippy, Rust formatting,
Flutter analysis (existing informational diagnostics), 108 regular Flutter
tests plus the separately enabled release-DLL ABI test (two macOS store tests
remain skipped), and an offline font-rendering check. The supported Windows
Release build produced a complete bundle with freshly built `http_proxy.dll`,
`wintun.dll`, plugins and the Windows-only Noto Sans SC asset/license. Its DLL
also passed six isolated HTTP/SOCKS requests across the same endpoints. The
Chinese font covers all 473 CJK characters used by the UI translation; previews
at 100%, 125%, 150% and 200% include both themes and log fallback. This is not a
live TUN acceptance test and no replacement release was published.

## Full audit follow-up (2026-10-14, unreleased source changes)

Three passes cover the v1.2.15 comparison and current implementation, failure /
cancellation paths after repair, and final compatibility/build verification.
These are review passes in this task, not independent external approvals.
The fixes retain the existing wire formats, versioned FFI layouts, application
identity, saved settings and explicit Fake-IP selection.

| Confirmed defect | Repair and regression coverage |
| --- | --- |
| A single IP is abandoned after three seconds; outer client/TUN deadlines also truncate its TCP retries | Outbound dialing follows the OS retry policy and caller cancellation; a simulated 20-second connection succeeds, while an incomplete SOCKS input still expires and releases its setup slot |
| HTTP authority parsing splits IPv6 colons and includes a query in a host without a slash | Parse bracketed IPv6 and authority boundaries; reject malformed ports/authorities; retain the entire original URI in parse errors |
| CONNECT reports success before opening the upstream; SOCKS upstream errors only close the stream | Send CONNECT 200 only after upstream setup, otherwise 502; SOCKS sends a failure reply; loopback tests cover both |
| Timed-out TUN cleanup loses its completion receiver and allows overlapping starts | Keep ownership across timeout, refuse replacement until completion, and distinguish a closed worker channel from confirmed cleanup |
| A failed route/DNS restore is logged but the FFI stop still reports success | Preserve a typed teardown error through the in-process native runner and stop channel; retain the listener and bypass state on failure |
| Combined FFI start bypasses the separately owned TUN lifecycle; reused listener handles can race old cleanup | Both TUN entry points share readiness/teardown; join the listener and its tracked connections before reuse |
| Destruction or failed startup can abort route restoration | Cancel TUN, await its cleanup, then release the listener/runtime; fake-worker tests never create an adapter |
| Desktop Quit exits even when stop fails, and idle UI snapshots can skip pending native cleanup | Always ask the owning service to stop; propagate failures and cancel exit; a later successful cleanup permits exit |
| An optional malformed list discards otherwise usable saved configuration | Parse each optional list defensively without losing the saved endpoint; preserve data and show startup migration errors instead of a blank window |
| Disposal during asynchronous initialization can resume the elevation/start workflow or notify dead listeners | Guard initialization, starts and callbacks after disposal; regression uses a fake service |
| FFI logs silently truncate at 8 KiB and a later message can overwrite structured fields | Preserve complete admitted messages and every structured field; bound total queued bytes/count instead; HTTP logs keep method/URI/version and SOCKS logs keep the command/destination |

Review also covered virtual-DNS journal recovery, process/loopback bypass,
TCP/UDP framing, secure/legacy compatibility and desktop/mobile release
collection. Existing tests for these paths remain enabled. Server relay,
control-plane and health-probe deadlines are separate policies; this repair
does not indiscriminately remove every timeout in the repository.

The existing legacy cryptographic limitation described below remains a
deployment migration requirement; changing its bytes or silently selecting v3
would break compatibility with older servers. No live TUN, route, DNS, system
proxy, active executable or saved preference was intentionally changed by this
audit. Real Windows TUN activation and macOS/mobile runtime acceptance still
require a separate test window.

Final Windows verification for these source changes:

- `cargo test --workspace`: **266 passed, seven existing ignored tests**.
- `cargo test --manifest-path deps/tun2proxy/Cargo.toml`: **85 passed**.
- Strict first-party and tun2proxy Clippy with `-D warnings`, and their Rust
  formatting checks passed.
- `fvm flutter analyze --no-fatal-infos`: passed, with 26 existing informational
  tray API deprecations. `fvm flutter test --no-pub`: **112 passed, three skipped**;
  enabling the rebuilt DLL separately passed the native V8/V7 ABI test, leaving
  only the two platform-specific Store skips unexercised.
- Native release, desktop collection and macOS packaging unit tests: **16 passed**.
  They use fixtures/mocks and do not publish or notarize a release.
- Supported offline Windows Release build passed. The complete bundle includes
  the fresh native DLL, Wintun, Flutter runtime/plugins and the Windows-only
  Noto Sans SC font/license. Native staging and bundle DLL hashes match:
  `c0da2e75e685fd7de3bcf04047bbd21c75c30bd59d986be426dfb55ca3e00826`.
- The rebuilt DLL passed **six HTTP/SOCKS requests** across the same three nodes
  and **30 stop/restart cycles on one handle/port**, including cancellation of
  an admitted SOCKS client. These use ephemeral loopback listeners, no TUN,
  no system proxy and no persistent cache. They do not validate new TUN routes.
- Before/after snapshots match for the old process (PID 47136 and its start
  time), preferences SHA-256, IPv4 route table and system-proxy settings.

Build/test logs and isolated probe results are under the ignored local
`target/audit-20261014/` directory. The verification bundle retains the current
source version **1.2.23+53 / native 0.4.38**; it is not a newly versioned release
or an upgrade package. These source changes are proposed for review without a
new tag or release upload.

## Corrected behavior

| Failure | Change | Owning source |
| --- | --- | --- |
| One failed DNS address holds subsequent candidates behind OS SYN retries | Race up to two addresses, promote the other address family, cancel losing attempts, refresh failed cached DNS results | `crates/proxy-core/src/transport.rs` |
| Cancelled DNS/process lookups leave many blocking jobs behind | Acquire bounded permits before dispatch; the OS job retains its permit even when its waiter is cancelled | `transport.rs`, `deps/tun2proxy/src/process/mod.rs` |
| A partial local greeting is treated as a complete request; pipelined SOCKS requests are consumed as greeting bytes | Read exactly the greeting length or complete HTTP header, retaining following bytes on the socket | `crates/proxy-client/src/client/mod.rs`, `transport.rs` |
| HTTP CONNECT consumes a coalesced destination greeting | Peek for the header boundary and consume only that header; format IPv6 CONNECT authorities with brackets | `transport.rs` |
| The initial ordinary HTTP request bypasses the selected encryption codec | Replay the header through the same codec and nonce sequence as later body bytes | `crates/proxy-client/src/client/http.rs`, `crates/proxy-core/src/codec/mod.rs` |
| Incomplete local/server handshakes and silent external proxies hold resources indefinitely | Bound setup time and pending handshake counts; leave established streams free of a new idle deadline | client/server connection handlers, `transport.rs` |
| Full geo lookup queue stalls before the decision timeout even starts | Fall back to the configured proxy immediately when enqueue fails | client `need_proxy` |
| Malformed first UDP packet pins a port-zero SOCKS association to the wrong endpoint | Validate the datagram before accepting its endpoint | client `udp.rs` |
| Windows retains obsolete gateway/interface routes after reconnection | Reconcile owned bypass routes against connected physical routes, using prefix and route/interface metrics | `deps/tun2proxy/src/windows_network_config.rs` |
| Direct process bypass retains an obsolete interface or DHCP DNS snapshot | Refresh Windows egress off the forwarding executor; new sessions use the latest snapshot | tun2proxy `lib.rs`, `direct.rs` |
| A failed forwarding direction waits for its peer until idle expiry | Propagate errors, cancel the opposite pump, reset failed or capacity-rejected TCP sessions; preserve normal EOF half-close behavior | tun2proxy `lib.rs` |
| Cancelled server sessions leak active-connection counts | Use a drop guard | `crates/proxy-server/src/server/connection.rs` |
| Native warning storms or a stalled UI accumulate callback work/strings | Bound warning rate and total queued bytes/count; preserve complete accepted messages and report suppression | `crates/proxy-ffi/src/logging.rs` |
| Stop, latency checks and destruction overlap across Dart isolates | Serialize handle borrowers and defer off-thread destruction until borrowers return | UI `native_operation_queue.dart`, `proxy_service.dart` |
| Queued native logs call a closed Dart callback | Retain a single callback for the UI isolate lifetime | UI `proxy_service.dart` |
| UI remains connected when the worker dies without emitting a log | Independently reconcile native status once per second; retain a surviving TUN's visible stop control | UI `proxy_provider.dart` |
| Debug output exposes session keys or upstream proxy passwords | Remove secret fields and redact external proxy Debug output | client `mod.rs`, core `relay/mod.rs` |
| Legacy nonce counter panics in debug or wraps in release | Fail closed at exhaustion, retaining the wire encoding of existing counters | core `crypto/mod.rs` |

## Budgets and ownership

- DNS: 4,096 cached hostnames, five-minute TTL, three-second lookup budget,
  eight OS lookups at once, same-host coalescing and a two-second refresh floor.
  A timed-out OS call may continue, but it continues to occupy its slot.
- TCP address selection: OS TCP retries, 250 ms initial stagger, at most two
  live attempts. Immediate failure advances immediately; caller cancellation
  drops all attempts. External SOCKS5/HTTP negotiation has a 15-second budget
  after its TCP connection is established.
- Local client input: 15 seconds, at most 256 pending setups, HTTP headers capped
  at 32 KiB. Relay incoming headers: ten seconds, at most 512 pending headers.
- TUN: the existing one-second interface monitor also reconciles owned bypass
  routes. A separate sequential two-second egress lookup updates new sessions.
  TCP connect/proxy negotiation uses the existing configured TCP timeout
  (600 seconds by default) after handler creation, not an additional ten seconds.
- Route recovery installs a replacement before deleting its owned predecessor.
  Offline state retains the loop barrier. Failed deletion retains both ownership
  records for cleanup. Preexisting replacements never become teardown-owned.
  Capture/default routes and unrelated routes are not removed by recovery.
- Process discovery uses one blocking lookup per matcher, with asynchronous
  waiters. Established sessions retain their pinned process identity.
- Native logs: 512 ordinary plus 64 warning/error callbacks per second, with a
  suppression summary; at most 1,024 pending strings totaling at most 8 MiB.
  Accepted messages are complete, including their original request URI and
  error context. Embedded NULs are escaped for the C-string ABI. Queue overflow
  is reported as dropped entries rather than silently truncating a message.
  Rust's matching free function releases each allocation and its slot.

Existing TCP sessions cannot migrate between physical network paths. Recovery
helps new connections and gives failed callers a prompt failure so they can
retry. It cannot make a genuinely offline interface deliver traffic.

## Validation and safe rollout

Regression coverage includes fragmented and pipelined HTTP/SOCKS greetings,
HTTP request headers and bodies through plain and encrypted relays, coalesced
CONNECT response payloads, silent external proxies, bounded address racing,
partial server headers, cancellation metrics, UDP endpoint poisoning, Windows
route ownership/rollback, bounded logs, and Dart operation/disposal ordering.
The modified loopback HTTP CONNECT and SOCKS5 tests fail with the original
greeting implementation and pass with the fix.

Windows route tests use mock operations. Builds and loopback tests run in a
separate Windows directory. Verification does not switch the live TUN, change
DNS, restart the current proxy, or deliberately disconnect Wi-Fi. Consequently,
real adapter handover and live TUN routing recovery remain unverified.

The 2026-10-03 checks passed 215 Linux and 219 Windows workspace tests (six
preexisting ignored tests on each), 54 Linux and 75 Windows tun2proxy tests,
strict Clippy on both platforms, formatting, Flutter analysis, and 99 Flutter
tests (two preexisting skips). Windows x64 Release binaries and `http_proxy.dll`
built successfully. The complete UI build stopped at Visual Studio discovery:
Flutter reported no suitable toolchain, and the installed `vswhere.exe` failed
with `0x80070583` / `0x80070008` despite the available Rust MSVC toolchain.
That first pass produced no complete Windows UI bundle. The 0.4.32 / 1.2.18+44
follow-up builds the complete app using the explicit installed MSVC path and
Ninja, without repairing the system toolchain or restarting the host. See the
optional `-VisualStudioPath` argument in `scripts/windows/build.ps1`. The app is
packaged separately and has not replaced the running proxy.

Use the complete Windows release directory or ZIP, not an isolated EXE/DLL.
The native and UI sources must move together. The supported build command is
`scripts/windows/build.ps1 -Configuration Release`; use `-Offline` when Cargo,
Pub and Flutter's Windows build dependencies are already cached. Cargo uses
the committed lockfile; Flutter dependency resolution runs once before build.

## Legacy AEAD nonce reuse and the v3 migration

The old wire protocol initializes the AES-GCM counter to zero in each
encryptor. Headers reuse a configured long-term key across connections, and
bidirectional streams use the same session key with independent counters.
This repeats key/nonce pairs. A per-stream overflow check does **not** repair
that design, and removing key logs does not make the protocol cryptographically
sound. No exploitation or historical compromise was established by this review.
The uniqueness requirement and consequences are specified in
[NIST SP 800-38D, section 8 and appendix A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).

A complete fix must version the connection preface and update both endpoints:

1. Authenticate the protocol version and a fresh connection salt, and derive
   separate client-to-server and server-to-client keys with explicit
   domain separation. Never reuse the legacy shared-key/zero-counter scheme.
2. Specify replay handling, framing limits, nonce exhaustion, and authentication
   failure behavior. Reject a failed authenticated negotiation instead of
   silently downgrading it to the legacy format.
3. Add mixed-version and adversarial tests, then stage server support before
   switching clients. Legacy remains the compatibility default; protocol
   selection is explicit and failures must never silently change it.

Native 0.4.33 / UI 1.2.19+45 supplies the separately selected
[zero-extra-RTT transport v3](secure-transport-v3.md). It uses fresh sender salts
and separate direction keys for the header and all traffic, including UDP and
control. Legacy profiles remain compatible and retain the old security
limitation. The unused one-RTT transport was removed. Deployment must follow the
documented server-first migration; development does not switch running services.

## Follow-up verification (0.4.32 / 1.2.18+44)

The complete workspace passed 225 Linux and 229 Windows tests (six existing
ignored tests on each), strict first-party Clippy on both platforms, formatting,
Flutter analysis, and 100 Flutter tests (two existing skips). The Windows x64
Release bundle built from the same source and contains native 0.4.32 and UI
1.2.18+44. Native TUN source is unchanged from the preceding 54 Linux / 75 Windows
test pass. Actual Wi-Fi handover and live TUN recovery remain untested because
the running proxy and network configuration must remain untouched.


## Zero-extra-RTT follow-up (0.4.33 / 1.2.19+45)

The unused challenge transport is replaced by the explicitly selected v3
transport. Legacy is still the default. Setup writes are coalesced, secure reads
reuse their decryption buffer. The 0.4.34 follow-up removes plaintext retry
copies under backpressure too. See [the v3 guide](secure-transport-v3.md) for wire semantics,
replay limits, test results and measured buffer/CPU differences.


## CR and framing follow-up (0.4.34 / 1.2.20+46)

Windows tracks desired bypass routes separately from rows it owns. A handover
that borrows an existing route retains the destination for subsequent recovery,
and cleanup deletes only owned rows. Automatic interface selection stays
automatic after the first network setup; a manually selected adapter stays pinned.
Physical default selection respects the interface's DisableDefaultRoutes flag.
IP Helper table allocations use an RAII guard, without copying whole OS tables.

Control messages and UDP datagrams now share one bounded framing implementation.
Partial reads survive cancellation, malformed/authentication failures are terminal,
and a cancelled partial write cannot append a second message. Writers reuse
one buffer and coalesce prefix/body/tag into one write; UDP hot paths borrow the
reader's packet instead of copying it. TCP wire bytes and the default legacy
protocol do not change. V3 writes obey buffered AsyncWrite ownership and flush
at framework message boundaries, without retaining a second plaintext record.
The node probe and initial HTTP request use that same flushing writer. A
one-byte transport regression reproduces the previous stalled-response bug
without a flush and completes with the shared writer. Echo DNS also reuses the
bounded resolver, retaining its concurrency slot through OS lookup cancellation.

The DNS dependency update uses Hickory's fixed encoder for
[GHSA-q2qq-hmj6-3wpp](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-q2qq-hmj6-3wpp).
The TUN DNS paths preserve their existing validation and filtering with the
stable message API. The uni-stream fallback now awaits the async resolver
directly, reusing its cache without an additional blocking job or hostname copy.
A regression occupies the runtime's only blocking worker and verifies that the
async lookup still completes. These DNS dependencies require Rust 1.88 or later;
the project's pinned toolchain already meets that requirement.

Local empty/oversized frame validation leaves the writer usable and consumes
no encryption nonce. Encryption/I/O failures and cancelled sends remain terminal.

[TUN Echo support](tun-icmp-echo.md) adds real remote IPv4/IPv6 ping. It does not
turn temporary Wi-Fi loss into reachability or recover established TCP sessions.

Verification: 243 Linux / 247 Windows workspace tests; tun2proxy 56 / 79;
strict Clippy and formatting passed on both platforms. ProxyUI analysis and
100 tests passed (two existing skips). The Windows release bundle pairs UI
1.2.20+46 with a freshly built, hash-matched native 0.4.34 DLL. Real packet-path
Echo was verified through isolated Linux loopback, including both ICMP socket
types, native relays and Fake-IP targets. Live Windows TUN/Wi-Fi handover was
not exercised; the existing running proxy process was not restarted.

## Windows TCP resets and elevation handoff (2026-10-17)

### Confirmed transport regression

An isolated Windows reproduction compared the v1.2.15/native 0.4.30 and
v1.2.24/native 0.4.39 releases. Commit `06670c85479df2dd28ea10f1d4741360cc91151b`
introduced `TCP_NODELAY` and combined the legacy header into one write. With
session encoding disabled, the next TLS ClientHello consequently appeared at
TCP payload offset zero. Specific SNI values triggered injected resets on the
measured network. Restoring only Nagle or only the old header writes did not
remove the trigger; relying on accidental coalescing is not a fix.

The decisive control replayed identical bytes through the same node. A combined
532-byte proxy header/ClientHello received TLS responses twice; splitting the
same stream into 70 and 462 bytes received RSTs twice. Keeping that split and
replacing only the equal-length SNI with `www.example.com` received responses
twice. Captures verified actual segment boundaries and equal stream hashes,
not merely application write calls. All six connections first received the
normal server SYN-ACK. These are small causal controls, not estimates of the
failure rate or complete TLS certificate-validation tests.

Full GUI failures were also correlated from the guest process/socket through
NAT to the host's physical WLAN. Abnormal SYN-ACK/RST packets arrived on that
interface before a different normal server SYN-ACK. Other connections received
server ACKs or TLS responses after the injected RST. The observations identify
incoming interference, not a specific injecting device or operator. Subsequent
node probes can fail before sending their own request; a probe's `10054` alone
cannot identify the request that triggered interference or its duration.

The failure reproduced with real TUN disabled and requests through the local
HTTP proxy, and in a clean guest without the investigated QQ/TAO components.
Fake-IP on/off did not resolve it. No host TUN restart, cache deletion, default
route replacement, or user configuration overwrite was needed. The macOS
packet-path difference and every historical reset were not independently proven.

### TCP protection and compatibility

Application TCP connections through a native proxy now always select a session
key before writing the proxy header. This includes HTTP CONNECT, SOCKS CONNECT,
plain HTTP sent through a native proxy rule, DNS-over-TCP, and node probes. TLS
ClientHello and subsequent bytes traverse the existing legacy framed codec,
regardless of packet segmentation. Explicitly supplied session keys are kept;
otherwise a fresh key is generated for each connection. There is no plaintext
retry or automatic protocol downgrade after an error.

The wire format is unchanged: legacy TCP still uses the original encrypted
`host`/`port`/`key` header and data frames. Historical servers already understand
that non-null key. Current servers continue to accept both encrypted and
unencrypted old clients. V3 remains opt-in, supplies its own encryption, and
skips the inner legacy codec; opaque native relays preserve the selected wire
format. Legacy's previously documented nonce limitations still apply: this
compatibility repair does not claim to replace the v3 security migration.

Direct destinations and external HTTP/SOCKS upstreams keep their existing wire
behavior. Saved `forceCodec=false`, CLI `msg_key=false`, and empty codec-IP lists
no longer disable native TCP protection. The force-codec/msg-key flag still
adds session encoding to UDP/ICMP tunnels. No saved setting is rewritten, and
Fake-IP, DNS routing, TUN bypass, timeout policy and socket options are unchanged.
The node-probe `force_codec` argument is retained for C ABI compatibility; both
values now probe the same protected TCP path used by applications.

Regression coverage uses real loopback HTTP/SOCKS listeners and an independent
historical header/data-frame reader. It checks that neither the TLS SNI nor
HTTP plaintext occurs anywhere in the upstream stream, with fragmented writes,
fragmented responses and request half-close. Other tests cover encrypted
DNS-over-TCP, node probes, both old-client/server compatibility directions,
plain/encrypted UDP, V3 and relay paths. No live user network is required.

Windows binary checks also compared the released v1.2.24 DLL against the rebuilt
DLL using a loopback filter that resets any stream containing a synthetic SNI.
All three released default TCP cases failed; all eight rebuilt cases passed,
including force-codec on/off and node probes. The rebuilt DLL also passed twelve
HTTP/CONNECT/SOCKS exchanges through an actual native 0.4.30 server built from
`2adfc542851dfeb11bfd7b5a01ae1330511ea80f`, both directly and through an old native
relay. These local tests use separate temporary state, not the user's TUN.

### Read-only connection diagnostics

Node probes carry a process-local `connection_id` and separately record name
resolution, measured TCP connect time, header preparation/write, request write
and response wait. Cancellation retains the actual last phase. Native error
codes, including Windows `10054`, survive the error chain.

Windows observations include live socket endpoints, `IP_UNICAST_IF` /
`IPV6_UNICAST_IF`, source-constrained `GetBestRoute2`, and `SIO_TCP_INFO`. A route
snapshot is explicitly not labelled actual packet egress: correlate process,
local port, peer and time with TCPIP ETW and physical packet capture. A reset
without that correlation remains unattributed. TCP RTT estimates and the
separately measured connect duration are distinct; synchronous diagnostic cost
is reported. Queries do not change sockets, routes, DNS or the FFI layout, and
unsupported statistics cannot fail a connection. Request destinations and
connection errors remain visible; keys and payloads are not logged.

### Elevation handoff is a separate defect

Windows crash events and a native-only reproducer identified an access
violation in `cnativeapi.dll` 0.5.2's tray destructor during `ExitProcess`.
Explicitly destroying the tray before process teardown avoided the reproduced
crash. This explains the abnormal relaunch delay, not the TCP resets above.

The GUI now awaits native listener/system-proxy cleanup, drains tray work,
releases the tray and flushes logs before exiting for the elevated replacement.
Both page and tray entry points share this ordering; ordinary quit also releases
the tray. The handoff has an eight-second cleanup budget, below the child's
ten-second single-instance wait. Each awaited step checks the remaining budget:
late completion after a timeout cannot resume the exit sequence. Failed cleanup
keeps the window open for a retry. Once tray teardown starts, closing the window
retries explicit cleanup/quit and minimizing cannot hide it behind the removed
icon. The retry uses the current proxy state even after tray listeners detach.
Saved TUN intent is preserved for the elevated child. No test restarts the
currently running old application.
