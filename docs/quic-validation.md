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
handshake time.

Further trials exposed substantial variation in this public path. With GSO
enabled, CUBIC's 8 MiB downloads took 53.58, 36.54 and 30.19 seconds during a
lossy interval. One connection reported 1815 lost packets out of 4736 sent
and a congestion window of about 5 KiB, with no peer flow-control blocking.
TCP also experienced retransmissions and intermittent long transfers.

Disabling GSO while keeping CUBIC produced downloads of 0.449, 20.442 and
0.339 seconds (median 17.8 MiB/s), with TCP interleaved between trials. The
first fast transfer had 4 losses out of 6088 sent packets. Re-enabling GSO
then caused all three 8 MiB download trials to exceed a 30-second deadline.
This supported disabling GSO by default on the tested path, while retaining
`PROXY_QUIC_GSO=true` for hosts that verify its CPU/throughput benefits.
It did not eliminate network variability: the GSO-disabled QUIC uploads took
25.88, 0.277 and 7.074 seconds. These small public-network samples must not be
read as a general QUIC-versus-TCP speedup.

Quinn's experimental BBR was also evaluated and rejected for the default.
Although two downloads completed in about 3.2 seconds, one 8 MiB download
generated roughly 90 MiB of UDP transmission with over 65,000 lost packets,
and an upload took 15.95 seconds. The final implementation retains CUBIC and
the original flow-control memory bounds.

The reusable benchmark alternates carrier ordering and validates every
successful transfer. Its origin and runner are
`scripts/bench/quic_origin.py` and `scripts/bench/quic_transport.py`.
Neither changes system proxy settings, and origin TLS verification stays on.

Local verification passed the workspace Rust tests, strict repository Clippy,
focused QUIC authentication and multiplexing tests, Flutter analyze/tests,
a fresh native macOS application build and the iOS simulator packet-extension
build. The focused integration also covers half-close, stream cancellation,
reconnect, control operations, managed SOCKS5 through QUIC, and opaque relays
in both TCP/QUIC directions. CI validates the Linux/macOS/Windows Rust paths
and builds Windows Flutter against the native library from the same PR.
