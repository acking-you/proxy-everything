# QUIC validation on lb7666

Validation on 2026-10-23 used an isolated authenticated server on TCP 12111 and
UDP 10811, with a separate state directory and temporary credentials. Existing
services were left running. Loopback-only HTTP, HTTPS and UDP echo origins on
the server avoided third-party service variability. The client explicitly
trusted the temporary certificate with SAN `lb7666.top`; HTTPS origin identity
was separately verified. Both carriers used the same v3 inner protocol.

Verified behavior:

- HTTP proxy, HTTPS CONNECT, SOCKS5 HTTP and SOCKS5 HTTPS each uploaded and
  downloaded 1 MiB with exact byte/SHA-256 verification.
- 16 concurrent 1 MiB HTTPS transfers completed correctly on each carrier.
- SOCKS5 UDP preserved 3-, 4096- and 3-byte packets; a preceding fragmented
  packet was dropped without closing the association.
- UDP packet headers captured on the server confirmed real bidirectional
  traffic on UDP 10811. No payload capture was saved.
- The rebuilt native FFI retained one handle and local listener through
  TCP → QUIC → TCP → QUIC. New HTTPS connections worked after every switch;
  the original HTTPS keepalive connection remained usable. Shutdown took
  approximately 0.19 seconds in this run.
- Unreachable UDP failed in 4.03 seconds. Wrong certificate name, an untrusted
  certificate and wrong application credentials failed before business payload
  in 0.04, 0.05 and 0.14 seconds respectively. No TCP fallback is implemented.

The initial single-stream 8 MiB HTTPS download sample (three sequential runs
per carrier) had median elapsed times of 0.474 seconds for TCP and 1.238 seconds
for QUIC: approximately 16.9 and 6.5 MiB/s. These are observations for this
network and payload, not a general performance claim. They include a local
proxy and origin TLS; curl's local-proxy connect time is not the upstream
handshake time. QUIC performance tuning and further measurements are ongoing.

Local verification passed the workspace Rust tests, strict repository Clippy,
focused QUIC authentication and multiplexing tests, Flutter analyze/tests,
a fresh native macOS application build and the iOS simulator packet-extension
build. The focused integration also covers half-close, stream cancellation,
reconnect, control operations, managed SOCKS5 through QUIC, and opaque relays
in both TCP/QUIC directions. CI validates the Linux/macOS/Windows Rust paths
and builds Windows Flutter against the native library from the same PR.
