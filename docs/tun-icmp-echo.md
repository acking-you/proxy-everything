# TUN ICMP Echo

Native 0.4.34 / ProxyUI 1.2.20+46 forwards ordinary IPv4 and IPv6 ping packets
that enter TUN through the configured native proxy exit. Existing platform
address-family capture settings still apply. A reply is injected only after that
exit receives a matching Echo reply from the target. Its payload must match;
the original identifier, sequence and TUN-side checksums are restored. Fake-IP
destinations use the virtual DNS hostname and resolve at the exit.

The exit's OS must allow ICMP sockets. Linux/Android first use a datagram ping
socket when `net.ipv4.ping_group_range` permits the service's group, then try a
raw socket when its existing privileges permit it. Other supported socket
platforms use the same datagram/raw fallback; Windows raw sockets usually need
an elevated server. Socket failure is an error, never a fabricated successful
ping. No permissions, capabilities or system settings are changed automatically.
The TUN client does not need a local ICMP socket.

## Compatibility and scope

- Upgrade the client and final native exit for this additional transport.
  Existing legacy TCP/UDP wire formats and the default protocol are unchanged.
  Old exits cannot provide Echo; errors never trigger a direct-network fallback.
- Native opaque relay hops forward the Echo stream. External HTTP/SOCKS proxy
  exits have no matching facility and are explicitly rejected.
- This covers unfragmented Echo request/reply within TUN MTU, including IPv6.
  It does not tunnel arbitrary IP protocols, ICMP errors, traceroute, path-MTU
  discovery, multicast or broadcasts. Reply IP TTL/hop-limit belongs to the
  reconstructed TUN packet, not the remote host. Ping RTT includes proxy transit.
- Echo always follows the native proxy exit; TCP/UDP process and geographic
  direct-routing rules are not applied to Echo.

## Wire and resource use

The embedded TUN enables tun2proxy's opt-in `--icmp-echo` extension. Standalone
tun2proxy keeps it disabled by default. Enabling it requires a loopback SOCKS5
endpoint without authentication that implements private command `0xe0`.
`DST.ADDR` is the IP or virtual DNS hostname; `DST.PORT` is 4 or 6 for the IP
family. The greeting/request are pipelined. Local packets use a two-byte big
endian length followed by the ICMP Echo packet (8–65535 bytes).

The native proxy header adds `transport: "icmp_echo"`, with target `host` and
family `port`. Each direction then uses the shared checksum/length framing,
including optional legacy data encryption, or the selected v3 outer stream.
The first probe follows the header immediately; there is no extra capability
probe or remote setup round trip. Unsupported/failed sessions close; receipt
of the local SOCKS success response alone is not proof of target reachability.

Each TUN instance allows at most 64 Echo flows and four queued requests per
flow, in addition to its TCP/UDP session cap. Each flow reuses its local/remote
TCP connection and exit ICMP socket, with one probe in flight. Requests expire
four seconds after entering the TUN queue, including connection setup and
queue wait. Idle flows close after 15 seconds; the local bridge/exit also have
20-second idle bounds. Full queues drop packets without blocking TCP/UDP.

Each server process permits at most 64 Echo sessions. DNS/socket setup and each
probe are bounded to four seconds; frame sizes are checked before allocation.
DNS uses the shared expiring cache and eight-slot resolver limit. A timed-out
lookup retains its slot until the underlying OS call finishes, so retries cannot
accumulate unbounded blocking DNS tasks.
Buffers are reused. Source, type, code, identifier, sequence and actual payload
are checked before accepting a reply. Linux ping socket identifiers are assigned
by the kernel; raw probes use a checked process-wide counter. Sockets retire
before sequence reuse. Timeout or protocol failure closes the entire flow so
late replies cannot complete a request on its replacement. TUN shutdown owns
and cancels all flow tasks; idle operation starts no new Echo tasks or timers.

## Verification

The ignored `provider_forwards_real_echo_v4_v6_legacy_and_v3` integration test
passes raw IP packets through the real packet adapter, IP stack, local SOCKS
listener, native server and OS ICMP socket. It checks IPv4/IPv6 payloads,
identifier/sequence restoration and checksums across legacy plain/encrypted
and v3 modes, including consecutive requests on one flow, direct/opaque-relay
paths and virtual DNS Fake-IP targets.

On Linux, run it inside a disposable user/network namespace with its own
loopback interface; it needs no changes to host routes, DNS or the live proxy:

```sh
cargo test -p proxy-client --features network-extension --test packet_tunnel --no-run --locked
unshare --user --map-root-user --net sh -c 'ip link set lo up && cargo test --offline -p proxy-client --features network-extension --test packet_tunnel provider_forwards_real_echo_v4_v6_legacy_and_v3 -- --ignored'
```

The same test passes with a namespace-local ping group range `0 0`, permitting
the mapped test user, to cover the datagram socket path. Both raw and datagram
paths were verified; no host setting was changed. Unit tests cover malformed replies,
checksum mismatches, silence (no synthetic success), sequence exhaustion,
fragmented local framing and invalid extension configurations. A live Windows
TUN ping and native macOS/Android runs require separate platform validation.
