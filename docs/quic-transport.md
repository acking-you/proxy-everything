# TCP and QUIC upstream carriers

Every native proxy negotiation selects its own upstream carrier. Bare
`host:port` addresses retain TCP; `quic://host:port` selects authenticated QUIC.
Both listeners can run together, and relay routes and nodes can mix carriers.
`ProxyHeader.transport` still describes the destination (TCP, UDP association,
or ICMP); its JSON and legacy-safe TCP default have not changed.

## Configuration and live switching

Start a server with a certificate chain whose SAN matches the client's host,
the corresponding PEM private key, and an explicit non-default 32-byte
`SECRET_KEY` shared with its clients:

```sh
export SECRET_KEY='<your-existing-32-byte-secret>'
http-proxy-server -H 0.0.0.0 -p 1081 \
  --quic-listen 0.0.0.0:10811 \
  --quic-cert /etc/proxy/fullchain.pem --quic-key /etc/proxy/private-key.pem
```

The equivalent listener variables are `PROXY_QUIC_LISTEN`, `PROXY_QUIC_CERT`
and `PROXY_QUIC_KEY`. Open the selected **UDP** port in the host and cloud
firewalls. TCP 1081 remains available to existing clients. Container deployments
also need `-p 10811:10811/udp` and certificate mounts.

```sh
http-proxy-cli -s quic://proxy.example -p 10811 -c 1080
# Equivalent explicit CLI selection:
http-proxy-cli -s proxy.example -p 10811 --transport quic -c 1080
```

TOML accepts `transport = "quic"` and optional `quic_ca = "/path/to/ca.pem"`.
The CLI carrier option overrides the URI's carrier. An explicit URI port takes
precedence over the separate port. Without a URI port, the normal CLI, TOML,
environment, then 1081 precedence applies. External HTTP/SOCKS upstream proxies
continue to use their existing URL configuration.

Clients verify certificates using the Mozilla root store. Private deployments
can add a PEM trust anchor with `--quic-ca` or `PROXY_QUIC_CA`; the latter
also applies to native library consumers when QUIC trust is first initialized.
Rust callers can use `quic::configure_trust` to replace additional trust for
future connections. Existing authenticated streams retain their original trust.
There is no insecure certificate mode.

In Flutter, select TCP or QUIC in proxy configuration, or select a node whose
address includes `quic://`. Saving an endpoint-only change or selecting a node
while connected updates subsequent negotiations without restarting the local
listener, subject to the TUN route constraints below.
Existing TCP connections, QUIC streams and UDP associations keep their original
upstream until they end. Switching to an unavailable endpoint therefore affects
new sessions, not established ones.
QUIC availability and authentication are checked by the native session dial;
the UI does not require a TCP listener on the QUIC endpoint's UDP port.
Managed SOCKS5 sharing links use the node's plain host (or advertised host),
regardless of which carrier was used to retrieve the link.

The existing `proxy_switch_upstream(handle, host, port)` ABI accepts
`quic://host`; passing a bare host switches back to TCP. Windows TUN prepares
route bypass and probes the chosen carrier before publishing the endpoint.
Other desktop TUN platforms allow a carrier/port change on the same host;
changing the host requires restarting capture to refresh bypass routes.
Apple's packet provider exposes the additive
`proxy_packet_tunnel_switch_upstream` entry point through its existing method
channel and persists the change in its configuration store.
The CLI options select the initial endpoint; the CLI does not expose a live
configuration command or file watcher.

## Authentication, reuse and failure boundaries

Quinn uses TLS 1.3 and ALPN `proxy-everything/1`. QUIC 0-RTT is disabled.
The first bidirectional stream authenticates the application before business
streams are admitted: each side sends a 32-byte HMAC-SHA256 and FIN. The key is
`SECRET_KEY`; the message is 32 bytes from the TLS exporter label
`EXPORTER-proxy-everything-quic-v1`, with separate `client` and `server`
contexts. Each side verifies the opposite role's tag. This binds authentication
to this TLS connection and prevents copying a tag to another connection.

Each subsequent bidirectional QUIC stream carries one unchanged native session:
legacy or v3 framing, HTTP forwarding, CONNECT, control-plane requests, or a
framed UDP/ICMP association. UDP retains datagram boundaries inside the reliable
stream; QUIC DATAGRAM is not used. Selecting QUIC does not change the configured
legacy/v3 protocol.

The client caches up to 32 connection entries for 60 seconds of cache inactivity,
separated by Tokio runtime, host, port, resolved addresses, credential digest and
trust generation. Concurrent requests to the same entry share an authenticated
connection. There are 16 concurrent dial slots. A negotiation/open-stream
deadline is 10 seconds, with a 4-second TLS attempt per resolved address.
DNS uses the existing resolver's deadlines.

The server admits at most 128 connections and 512 active business streams
globally, with 64 concurrent bidirectional streams per authenticated connection.
Before authentication only one stream is permitted. Stream/connection receive
windows are 1/8 MiB, the send window is 8 MiB, the idle timeout is 30 seconds,
and the incoming handshake buffer is bounded at 4 MiB. Unvalidated addresses
receive a QUIC Retry; server migration, unidirectional streams and datagrams
are disabled.

Write shutdown sends FIN without closing the read half. Cancelling an unfinished
stream sends RESET/STOP without closing sibling streams. Runtime shutdown closes
owned connections and bounds endpoint draining to 3 seconds. A later session
can reconnect after connection loss; application bytes are never replayed.

Blocked UDP, certificate/name mismatch, ALPN mismatch or failed authentication
fails the selected QUIC request. There is no silent TCP fallback. Check UDP
reachability and certificate identity, or explicitly choose a TCP node for new
negotiations. A QUIC-capable listener must be deployed before selecting it;
existing TCP clients and servers require no configuration changes.

## Performance diagnostics

CUBIC remains the congestion controller. Generic Segmentation Offload (GSO)
is disabled by default: the lb7666 tests observed severe packet loss with
offloaded sends despite successful socket writes. Hosts with a verified GSO
path can set `PROXY_QUIC_GSO=true` before starting to reduce transmit syscall
overhead. `false` is the default; other values are rejected. This changes
packet batching, not authentication, stream semantics or the TCP/QUIC choice.

Set `RUST_LOG=info,proxy_core::quic=debug` to record cumulative connection
statistics when streams close: RTT, congestion window, MTU, lost/sent packets,
UDP bytes and I/O counts, and peer flow-control blocking. These are connection
totals shared by all streams, not per-request counters. Connection creation
also records authenticated handshake duration.

`scripts/bench/quic_transport.py` compares two already-running local proxies
against a controlled HTTP(S) origin. It alternates TCP/QUIC ordering, verifies
download bytes and upload SHA-256, and saves each sample so timeouts remain
visible. It does not modify system proxy settings. See `--help` for the
origin contract and arguments; use fresh proxy processes for cold-connection
measurements. Keep payload, v3/legacy mode, certificate verification and origin
identical between carriers. A matching loopback-only origin is included:

```sh
# On the exit server, using a certificate valid for 127.0.0.1:
python3 scripts/bench/quic_origin.py --cert origin.pem --key origin-key.pem
# On the client, substitute the port printed by the origin and the two local proxies:
python3 scripts/bench/quic_transport.py \
  --tcp-proxy http://127.0.0.1:18080 --quic-proxy http://127.0.0.1:18081 \
  --origin https://127.0.0.1:ORIGIN_PORT --ca origin.pem \
  --mib 8 --rounds 3 --output target/quic-benchmark.json
```

## Verification

Focused automated coverage:

```sh
cargo test -p proxy-core tls_identity_alpn_and_application_credentials
cargo test -p proxy-server --test quic_transport
```

The integration test uses ephemeral loopback TCP/UDP listeners and covers mixed
legacy/v3 streams, concurrent transfer, half-close, cancellation isolation,
connection reuse/reconnect, control requests, UDP boundaries, runtime endpoint
switching and TCP-to-QUIC/QUIC-to-TCP opaque relays. Existing compatibility
tests continue to cover legacy readers/writers. See the
[deployment validation record](quic-validation.md) for public-network evidence.
