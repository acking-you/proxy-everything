# Low-latency encrypted transport v3

V3 adds **zero proxy-handshake round trips** beyond the underlying TCP setup.
The client sends its hello, encrypted destination header, and application data
without waiting for the server. Legacy remains the default on the CLI and UI,
and upgraded servers accept legacy clients unless explicitly configured otherwise.
The unused challenge-based transport was removed, including its wire selector.

## Wire contract

Client first flight:

```text
PXY3 | version=3 | control_flag | reserved=0,0 | client_salt[32] | records...
```

Server first flight:

```text
server_salt[32] | records...
```

Each sender generates its 32-byte salt using the OS random source. The client
hello and server salt are each coalesced with that sender's first encrypted
record, including an EOF record if it sends no data. The server never needs to
send a challenge before reading the request. A client can start uploading before
reading any response. No probe connection, negotiation retry, timer, background
worker, persistent replay database, or replay cache is added.

Both directions use AES-256-GCM. HKDF-SHA256 runs once per direction per endpoint,
not per record, with the configured 32-byte secret as input key material:

| Direction | HKDF salt | HKDF info components |
| --- | --- | --- |
| Client to server | client_salt | `proxy-everything-v3`, complete 8-byte preface, `client-to-server` |
| Server to client | client_salt concatenated with server_salt | `proxy-everything-v3`, complete 8-byte preface, `server-to-client` |

The client derives its receive key only after reading the response salt. The
server's independent randomness matters: replaying a client hello must not make
it encrypt a different response with the same key/nonce pair. Binding responses
to the client salt prevents moving a response into another client's connection.
Flags and version are authenticated through key derivation. Random corruption or
a modified salt/flag fails authentication before plaintext is returned.

This is the same general per-stream random-salt approach described in the
[Shadowsocks AEAD documentation](https://shadowsocks.org/doc/aead.html), with an
explicit direction domain and response binding. It is not Shadowsocks wire
compatible. Unlike pb-mapper's already-authenticated per-leg key distribution,
proxy-everything starts with a configured shared secret; those two setup paths
cannot directly share the same data-key design.

Records are `ciphertext_length:u32be | ciphertext | tag[16]`, capped at 16 KiB
plaintext. The nonce is four zero bytes followed by a checked 64-bit sequence
number. AAD binds the sequence and ciphertext length. Each record adds 20 bytes;
setup adds 40 client bytes and 32 response bytes, without an extra round trip.
The authenticated plaintext starts with the existing checksum/length/JSON header.
That complete header is sent as one encrypted record. TCP bytes, framed UDP and
control messages use the same authenticated stream, without an inner legacy cipher.
The header's optional key retains its control authorization role.

An authenticated empty record half-closes a sending direction. Raw EOF before
that record, authentication failures, invalid lengths, counter exhaustion and
I/O errors are terminal. Record and response-salt read progress belong to the
stream, so cancelling a read does not lose framing. A pending write owns sealed
bytes and reserves its counter before I/O; resuming with changed unacknowledged
plaintext fails. Decrypted data is read directly from the existing receive buffer.
A plaintext retry copy is allocated only when socket writes actually block.

## Security boundary and compatibility

V3 deliberately does not reject whole-connection request replays, including
across restarts and servers sharing a secret. Record duplication/reordering
inside a connection still fails. Do not use transport encryption as an
application's exactly-once execution guarantee. HTTPS/SSH retain their own
end-to-end protection; sensitive control operations still require the existing
control credential/admin token. PSK transport does not provide forward secrecy.

Legacy interoperability cannot repair an unmodified old peer's nonce reuse.
Keep the compatibility mode when an older server/relay remains in a path:

| Client | Server/path | Outcome |
| --- | --- | --- |
| Old client | New default server | Original legacy wire format works |
| New default client | Old server or relay | Original legacy wire format works |
| New v3 client | All-v3-capable path | Encrypted with zero extra handshake RTT |
| New v3 client | Old server or relay | Fails; never retries as legacy |
| Old client | New server explicitly requiring v3 | Rejected intentionally |

Opaque relays pass the complete v3 stream to the terminating server. Control
connections terminate at the chosen relay; the authenticated control flag must
match the decoded destination. TCP_NODELAY is enabled on outgoing connections,
accepted proxy sockets and relay hops to avoid small-write delays.

## Configuration and UI

1. Install native **0.4.33** or later on servers and relays, retaining the existing
   secret and default legacy acceptance during mixed-version operation.
2. Leave **Low-latency encrypted transport (v3)** off for default compatibility.
   Enable it explicitly when the whole path supports v3, or select
   `PROXY_WIRE_PROTOCOL=v3` in a CLI process. `legacy` remains the default.
3. Optionally set `PROXY_REQUIRE_V3=1` on upgraded servers to reject legacy.
   This does not change server-originated control/discovery connections; select
   their wire version separately when migrating them.

ProxyUI **1.2.19+45** uses `ProxyConfigV7` / `proxy_start_v7` and an explicit
`proxy_probe_node_v3` protocol argument. Wire values are 0 (legacy) or 3 (v3);
unknown versions fail before starting a worker. V1-V5 configuration ABIs remain
legacy. Their version numbers are unrelated to the transport version.
The unused challenge transport and its V6/probe-v2 entry points are removed.
The native Mac App Store Packet Tunnel ABI still supports legacy only and
explicitly rejects secure transport selection.

## Verification

Tests prove the first request can be sent by an **AsyncWrite-only** client and
accepted by an **AsyncRead-only** server. A challenge/response round trip cannot
occur in that test. A loopback integration matrix covers legacy/v3 HTTP, SOCKS,
UDP, control, opaque relays and external SOCKS chains. Independent historical
readers/writers check both directions of legacy compatibility, with payload
cryptography on and off. Adversarial cases cover response binding, fresh response
keys after repeated hellos, partial salt/record reads, cancellation, altered retry
buffers, tampering, ordering, truncation, counter exhaustion and half-close.

The release microbenchmark excludes sockets, TCP setup and WAN latency:

```sh
cargo test --release -p proxy-core secure_transport::bench::records_and_setup -- --ignored --nocapture
```

It warms up before nine samples and reuses payload/record buffers. Report its
per-record CPU time and retained buffer capacities separately from whole-tunnel
throughput; local microbenchmarks are not evidence of WAN throughput gains.

Local Linux/WSL2 comparison (2026-10-05): eight alternating before/after runs,
each containing warmup plus nine samples, pinned to one available CPU after
other Rust builds/tests finished. The baseline is the removed one-RTT prototype,
not the unencrypted legacy path.

| Measurement | Before | V3 |
| --- | ---: | ---: |
| Construct stream with both direction keys installed | 900.73 ns | 938.31 ns |
| Encrypt/write/read/decrypt one 256-byte record | 150.40 ns | 150.98 ns |
| Encrypt/write/read/decrypt one 16-KiB record | 3006.67 ns | 2783.36 ns |
| Retained record buffers for one sender + receiver, 16 KiB | 81,944 B | 32,804 B |

The 16-KiB case uses about 60% less record-buffer capacity and 7.4% less CPU
wall time in this microbenchmark. Small-record time is essentially unchanged;
complete key/stream setup costs about 38 ns more. V3 defers the client's receive
key until the first response, so that complete-setup benchmark is not its initial
request critical path. Buffer counts exclude sockets, allocator bookkeeping and
stream structs; backpressure may retain one additional bounded plaintext retry
buffer. There is no claim of a measured WAN throughput improvement.

The 0.4.33 workspace passed 233 Linux and 237 Windows tests; seven tests were
ignored on each platform, including the separately executed manual benchmark.
Strict first-party Clippy passed on both platforms, along with Rust formatting.
ProxyUI 1.2.19+45 passed Windows Flutter analysis and 100 tests (two existing
skips), and the complete Windows x64 release bundle built with a fresh FFI DLL.
Live proxy/TUN recovery and native macOS/Android builds were not exercised in
this change; no running proxy, network configuration or Codex mapping was altered.
