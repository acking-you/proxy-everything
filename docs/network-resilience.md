# Network resilience review: native 0.4.31 / UI 1.2.17+43

This review starts from native commit `1847db9`, tun2proxy `071b8a4`, and
ProxyUI `34f9189`. It covers connection setup, TCP/UDP forwarding, Windows
physical egress recovery, native resource ownership, and UI lifecycle/status.
It does not establish the cause of any particular past Wi-Fi outage.

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
| Native warning storms or a stalled UI accumulate callback work/strings | Bound warning rate, message size, and outstanding native allocations; report suppression | `crates/proxy-ffi/src/logging.rs` |
| Stop, latency checks and destruction overlap across Dart isolates | Serialize handle borrowers and defer off-thread destruction until borrowers return | UI `native_operation_queue.dart`, `proxy_service.dart` |
| Queued native logs call a closed Dart callback | Retain a single callback for the UI isolate lifetime | UI `proxy_service.dart` |
| UI remains connected when the worker dies without emitting a log | Independently reconcile native status once per second; retain a surviving TUN's visible stop control | UI `proxy_provider.dart` |
| Debug output exposes session keys or upstream proxy passwords | Remove secret fields and redact external proxy Debug output | client `mod.rs`, core `relay/mod.rs` |
| Legacy nonce counter panics in debug or wraps in release | Fail closed at exhaustion, retaining the wire encoding of existing counters | core `crypto/mod.rs` |

## Budgets and ownership

- DNS: 4,096 cached hostnames, five-minute TTL, three-second lookup budget,
  eight OS lookups at once, same-host coalescing and a two-second refresh floor.
  A timed-out OS call may continue, but it continues to occupy its slot.
- TCP address selection: eight seconds including DNS, three seconds per
  address, 250 ms initial stagger, at most two live attempts. Immediate failure
  advances immediately. External SOCKS5/HTTP setup has a 15-second total budget.
- Local handshake: 15 seconds, at most 256 pending setups, HTTP headers capped
  at 32 KiB. Relay incoming headers: ten seconds, at most 512 pending headers.
- TUN: the existing one-second interface monitor also reconciles owned bypass
  routes. A separate sequential two-second egress lookup updates new sessions.
  TCP connect/proxy negotiation has a ten-second deadline after handler creation;
  this is not a ten-second bound on all process lookup or DNS work.
- Route recovery installs a replacement before deleting its owned predecessor.
  Offline state retains the loop barrier. Failed deletion retains both ownership
  records for cleanup. Preexisting replacements never become teardown-owned.
  Capture/default routes and unrelated routes are not removed by recovery.
- Process discovery uses one blocking lookup per matcher, with asynchronous
  waiters. Established sessions retain their pinned process identity.
- Native logs: 512 ordinary plus 64 warning/error callbacks per second, with a
  suppression summary; at most 1,024 pending strings, each at most 8 KiB.
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

[TUN Echo support](tun-icmp-echo.md) adds real remote IPv4/IPv6 ping. It does not
turn temporary Wi-Fi loss into reachability or recover established TCP sessions.

Verification: 240 Linux / 244 Windows workspace tests; tun2proxy 56 / 79;
strict Clippy and formatting passed on both platforms. ProxyUI analysis and
100 tests passed (two existing skips). The Windows release bundle pairs UI
1.2.20+46 with a freshly built, hash-matched native 0.4.34 DLL. Real packet-path
Echo was verified through isolated Linux loopback, including both ICMP socket
types, native relays and Fake-IP targets. Live Windows TUN/Wi-Fi handover was
not exercised; the existing running proxy process was not restarted.
