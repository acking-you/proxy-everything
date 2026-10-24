# QUIC carrier

A native session makes three independent choices:

| Choice | Options | Selected by |
| --- | --- | --- |
| Carrier | TCP (default) or QUIC | The node address: `host` or `quic://host` |
| Wire protocol | legacy (default) or v3 | `PROXY_WIRE_PROTOCOL` or the app setting ([v3](secure-transport-v3.md)) |
| Destination | TCP, UDP association or ICMP | The request (`ProxyHeader.transport`) |

QUIC replaces only the carrier. Every session keeps its legacy or v3 framing
inside its own QUIC stream, so relays, control requests, SOCKS5 UDP and ICMP
work unchanged, and nodes and relay routes can mix carriers. There is no TCP
fallback: a QUIC failure fails that session, and choosing TCP is explicit.

## Server

QUIC listens on a UDP port next to the TCP listener. It needs a certificate
whose SAN matches the host clients dial, and the same 32-byte `SECRET_KEY` as
the clients. Like TCP, QUIC also accepts the built-in default key; migrating
an existing node to QUIC does not require changing its clients' key. A private
random key is recommended for deployments. Certificate validation remains
mandatory regardless of the application key:

```sh
export SECRET_KEY='<32-byte secret shared with clients>'
http-proxy-server -H 0.0.0.0 -p 1081 \
  --quic-listen 0.0.0.0:10811 \
  --quic-cert /etc/proxy/fullchain.pem --quic-key /etc/proxy/private-key.pem
```

`PROXY_QUIC_LISTEN`, `PROXY_QUIC_CERT` and `PROXY_QUIC_KEY` are the environment
equivalents. Open the **UDP** port in the host and cloud firewalls; with Docker,
add `-p 10811:10811/udp` and mount the certificate. TCP clients are unaffected.

## Client

```sh
http-proxy-cli -s quic://proxy.example:10811 -c 1080
# equivalent:
http-proxy-cli -s proxy.example -p 10811 --transport quic -c 1080
```

- TOML: `server_host = "quic://proxy.example"` or `transport = "quic"`, plus an
  optional `quic_ca = "/path/to/ca.pem"`.
- `--transport` overrides the address's scheme. A port in the address overrides
  `-p`; otherwise the usual CLI, TOML, `SERVER_PORT`, then 1081 order applies.
- Certificates are verified against the Mozilla roots. Add a private CA with
  `--quic-ca`, `quic_ca` or `PROXY_QUIC_CA` (the variable also covers the app's
  native library). Host names are always verified; there is no insecure mode.

In the app, choose QUIC for the node, or paste a `quic://host:port` address.

## Switching upstreams

A new endpoint or carrier applies to new sessions only. Established TCP
connections, QUIC streams and UDP associations keep their carrier until they end.

| Where | Behaviour |
| --- | --- |
| App, `proxy_switch_upstream(handle, host, port)` | `host` may be `quic://…`; a bare host switches back to TCP. The local listener keeps running. |
| Windows TUN | Installs the new host's bypass routes and probes the chosen carrier before publishing it. A failure keeps the old upstream. |
| macOS and Linux TUN | Carrier and port change live. A different host needs TUN restarted, so its bypass routes are refreshed. |
| iOS packet tunnel | `proxy_packet_tunnel_switch_upstream`, through the existing method channel. |
| CLI | Fixed at start. |

Managed SOCKS5 links always use the node's plain or advertised host, whichever
carrier fetched them.

## Detecting QUIC nodes

A catalogue entry names a node's TCP address only; its QUIC listener is a
separate UDP port. `GetQuicEndpoint` returns the port of the QUIC listener the
node bound, or none. Like `ListNodes`, it needs only the session key. Nodes that
predate the operation reject it, which clients treat as unknown rather than as
"no QUIC".

The app asks the whole catalogue after each refresh with the `quic_endpoints`
operation: one call, answered in order, 16 nodes at a time by default, each with
its own deadline. It marks capable nodes and can test one over QUIC by probing
`quic://<host>:<port>`, where `<host>` is the address the app reached the node at.
The node's certificate must cover that name.

## How it works

**Handshake.** TLS 1.3 with ALPN `proxy-everything/1`; 0-RTT is disabled.
Unvalidated client addresses first receive a QUIC Retry. The first stream then
authenticates the application: each side sends HMAC-SHA256 keyed with
`SECRET_KEY` over 32 bytes exported from TLS (label
`EXPORTER-proxy-everything-quic-v1`, context `client` or `server`) and verifies
the peer's tag. Because the tag is bound to this TLS connection, it cannot be
replayed on another. The server allows one stream before authentication and
1024 concurrent streams after it.

**Streams.** Each further bidirectional stream carries one native session.
Closing a stream mirrors closing a TCP socket: `shutdown` sends FIN and keeps
reading, and dropping the stream delivers what was written, then FIN, and stops
unread input. Sibling streams are unaffected. UDP datagrams keep their
boundaries inside the stream; QUIC DATAGRAM frames are not used.

**Client pool.** One authenticated connection is shared per runtime, host, port,
resolved addresses, credential digest and trust generation, with up to 32
entries. Dialing races addresses the way TCP does: IPv4 and IPv6 interleaved, a
250 ms stagger, 4 s per attempt and 16 dials at once. If every cached address
fails, DNS is refreshed once. A session has 10 s to obtain a stream.
Application bytes are never replayed; only a dial, which sends none, is retried.

**Keep-alive.** The client pings every 10 s, so idle sessions and NAT bindings
survive the 30 s idle timeout. A pooled connection with no open or new sessions
for 30–60 s is closed, so an idle client stops pinging.

**Server limits.** 64 concurrent handshakes, separate from 128 authenticated
connections, so peers that never authenticate cannot displace clients. Streams
are bounded per connection and by the header admission shared with TCP.
Connection migration is enabled; quinn validates a new path before using it,
so NAT rebinding or a network change keeps sessions. Receive windows are 1 MiB
per stream and 8 MiB per connection, the send window is 8 MiB, and the handshake
buffer is 4 MiB. Unidirectional streams and datagrams are disabled.

**Health probes.** Relay health checks of `quic://` targets dial and
authenticate a fresh connection, then close it. Opening a stream on a pooled
connection would succeed locally and prove nothing.

**Shutdown.** Stopping the client or server closes its connections and waits
at most 3 s for close frames to drain.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Each address times out after about 4 s | UDP is blocked: firewall, security group, or Docker's `/udp` mapping |
| Certificate or name error | The SAN must match the dialed host; add a private CA with `--quic-ca` or `PROXY_QUIC_CA` |
| `QUIC application authentication failed` | `SECRET_KEY` differs between client and server |
| Slow or lossy transfers | Keep GSO off (below) and compare with TCP using the benchmark |

GSO is off by default because the tested path silently dropped offloaded
segments ([validation record](quic-validation.md)). Set `PROXY_QUIC_GSO=true`
only on hosts where it was verified; other values are rejected. CUBIC is the
congestion controller.

`RUST_LOG=info,proxy_core::quic=debug` logs connection totals (RTT, congestion
window, MTU, loss, UDP I/O, flow-control blocking) when a stream closes, and
the authenticated handshake time of each dial.

### Benchmark

`scripts/bench/quic_transport.py` compares two running local proxies, one per
carrier, against a controlled origin. It alternates their order, verifies every
byte and never changes system proxy settings. Use fresh proxies for cold-start
numbers, and keep payload, wire protocol and certificate checks identical:

```sh
# Exit server, with a certificate valid for 127.0.0.1:
python3 scripts/bench/quic_origin.py --cert origin.pem --key origin-key.pem
# Client, with the port the origin printed:
python3 scripts/bench/quic_transport.py \
  --tcp-proxy http://127.0.0.1:18080 --quic-proxy http://127.0.0.1:18081 \
  --origin https://127.0.0.1:ORIGIN_PORT --ca origin.pem \
  --mib 8 --rounds 3 --output target/quic-benchmark.json
```

## Tests

```sh
cargo test -p proxy-core quic::
cargo test -p proxy-server --test quic_transport
```

Both use loopback listeners. They cover TLS, ALPN and credential rejection,
stream close semantics, mixed legacy and v3 streams, concurrent transfers,
half-close, reuse and reconnect, control requests, UDP boundaries, live
endpoint switching, health probes, managed SOCKS5, and relays in both carrier
directions.
