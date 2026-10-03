# Secure transport v2 (native 0.4.32 / UI 1.2.18+44)

The legacy AES-GCM format repeats key/nonce pairs across connection headers
and bidirectional data. V2 replaces that format for a connection; it does not
run legacy encryption inside another cipher. Keeping legacy mode enabled does
not remove its security limitation.

## Wire and ownership

The client sends `PXY2 | version=2 | control_flag | reserved=0,0 | random[32]`.
The server validates the preface and sends a fresh 32-byte random challenge.
Both use the configured 32-byte `SECRET_KEY` (the UI's session-key field) as
HKDF-SHA256 input key material. Salt is `client_random || server_random`.
HKDF info includes `proxy-everything-v2`, the full eight-byte preface, and
`client-to-server` or `server-to-client`. Both directions therefore have separate
AES-256-GCM keys, even when their counters have the same value. Each connection
has fresh material; a restarted server needs no persistent replay database.

Records are `ciphertext_length:u32be | ciphertext | tag[16]`, with at most
16 KiB of plaintext. The nonce is four zero bytes followed by the direction's
64-bit counter. AAD includes that counter and the length. Counters start at zero,
advance monotonically, and fail closed before overflow. Authenticated plaintext starts with the existing length-delimited JSON header.
Subsequent bytes carry TCP, framed UDP, or control messages; all of them stay
inside the same authenticated record stream. The
inner legacy data cipher is disabled. The optional header key retains its
existing control authorization role.

Reads keep partial lengths, ciphertext and decrypted bytes in the stream.
Cancelling a read future does not lose record progress. A pending write keeps
its ciphertext and advances the nonce before any bytes are written; resuming
with different unacknowledged bytes closes the stream. Authentication, sequence,
length and I/O errors are terminal. An authenticated empty record closes one
sending direction; an unauthenticated EOF is a truncation error.

The shared ten-second/512-slot incoming handshake budget includes protocol
recognition, random exchange and authenticated header parsing. Each record adds
20 bytes; connection setup adds 72 public bytes and one round trip. The extra
round trip lets the server reject recorded requests across restarts or separate
servers sharing the same secret, without unbounded replay caches or extra disk
writes. This PSK design does not provide forward secrecy: protect and rotate the
configured secret; the public example/default key is not a production secret.

## Relay and compatibility behavior

Opaque proxy relays forward the entire data handshake and encrypted stream to
the terminating server. They do not decrypt/re-encrypt records or reuse endpoint
keys. Control connections terminate on the selected relay; the control flag is
bound into key derivation and checked against the authenticated header. External
SOCKS/HTTP upstreams receive ordinary destination traffic after v2 termination.
All proxy-everything relays in a v2 path must support the preface.

Legacy clients remain byte compatible, including TCP headers without the
`transport` field. The v2 preface cannot be mistaken for a valid legacy header
length, even if its magic coincides with a legacy checksum. An authenticated
handshake failure never causes a new legacy connection.

## Coordinated migration

1. Install native 0.4.32 or newer on every relay and terminating server, keeping
   its existing secret and legacy acceptance while old clients are present.
2. Select **Secure transport v2** in ProxyUI, or set `PROXY_WIRE_PROTOCOL=v2`
   for CLI clients, control/admin tools and discovery workers. Restart only the
   applications being deliberately upgraded. Existing profiles and older FFI
   entry points keep legacy mode. New FFI clients use `ProxyConfigV6` /
   `proxy_start_v6`; node probes have an explicit protocol argument and do not
   change a running client's mode.
3. Verify HTTP, SOCKS TCP, UDP, control and every intermediate relay. Then set
   `PROXY_REQUIRE_V2=1` on servers to reject legacy traffic. Server-originated
   control/discovery connections also need `PROXY_WIRE_PROTOCOL=v2`.

The native Packet Tunnel ABI used by the Mac App Store edition has not migrated;
that edition explicitly rejects a v2 start rather than silently using legacy.
The Windows/ordinary native FFI path has v2 support. No live proxy, TUN, DNS,
route or Codex process was changed during development or verification.

## Verification

The regression matrix covers legacy and v2 HTTP/UDP, encrypted legacy payloads,
control authorization, v2-only rejection, opaque relays and external SOCKS chains.
Record tests cover direction/connection/challenge separation, partial-read and
partial-write cancellation, altered retry buffers, tampering, replay/reordering,
truncation, bounds, exhaustion, large payloads and authenticated half-close.
Additional regressions cover encrypted node probes and immediate cancellation
of a silent peer when server-side forwarding fails.
