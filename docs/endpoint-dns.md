# Endpoint DNS

`--endpoint-dns` (or `endpoint_dns` in `config.toml`, or the `ENDPOINT_DNS`
environment variable) chooses how a process resolves the hostnames of the
**proxy endpoints it dials itself**: native nodes, server relay targets and
external upstream proxies. It does not change how proxied or direct
destinations are resolved. The default is `system`, which keeps the behaviour
of earlier releases.

```bash
# Resolve the node through the built-in DNS-over-HTTPS list; fail rather than
# fall back to plaintext DNS.
http-proxy-cli -s node.example.com -p 1081 -c 1080 --endpoint-dns encrypted

# Your own DoH server first, the built-in list next, and plaintext system DNS
# only when every encrypted resolver failed.
http-proxy-cli -s node.example.com --endpoint-dns "https://203.0.113.53/dns-query,encrypted,system"

# A relay server resolving its upstream targets.
ENDPOINT_DNS=encrypted http-proxy-server -p 1081 -t upstream.example.com:1081
```

None of this has been validated against the Great Firewall or any other live
censor. It is a design based on published measurements, verified with local
fakes. See [Limitations](#limitations).

## Where pollution reaches this proxy

| Lookup | Resolved by | Exposed to local DNS injection? |
| --- | --- | --- |
| Proxied destination (HTTP/SOCKS5 target, `socks5h://`) | The remote server, or the upstream proxy, inside the encrypted session | No |
| TUN DNS (captured port-53 queries) | `--tun-dns-server`, reached over TCP through the proxy | No, from the local network |
| Direct destination (auto-proxy direct, website rule, bypassed process) | The system resolver | Yes, by design: these are hosts the user routes outside the proxy |
| **Native node, QUIC node, TUN route bypass, Windows live switch** | The system resolver | **Yes, governed by this policy now** |
| **External upstream proxy (`--upstream-proxy`), its SOCKS5 UDP control connection** | The system resolver | **Yes, governed by this policy now** |
| **Relay target on a server (`-t`, relay config) and its health checks; control-plane connections to nodes** | The server's system resolver | **Yes, governed by this policy now** |

The endpoint lookups happen before any tunnel exists, in plaintext, on the
network the user is trying to get out of. That has three consequences:

- **Availability.** One forged answer sends the client to a wrong address, and
  the five-minute DNS cache keeps it there. The native protocol's pre-shared key
  (and QUIC's certificate check) mean the wrong host cannot impersonate the
  node, so the result is a failed connection rather than a decrypted one.
- **Credentials.** An external HTTP or SOCKS5 upstream proxy authenticates with
  a password. If its hostname is poisoned, that password is sent to whatever
  address the forger chose.
- **Fingerprinting.** The node's hostname is visible to the network in every
  plaintext lookup.

## What the paper found

CircumVolve (Zohaib et al., *Automated Discovery of Censorship Evasion
Strategies Using Large Language Models*, ACM CCS 2026,
[paper](https://gfw.report/publications/ccs26/en/)) evolves DNS queries that
evade injection-based censors (§4.2). Its description of the censors matters
as much as the queries it found:

- The GFW is **on-path**. When the QNAME matches, up to three independent
  injectors race forged responses with public addresses ahead of the real
  answer. **The query is not dropped**, so the real resolver's answer arrives
  later as well.
- Iran's censor is **in-path**. It drops the query and answers with static
  private addresses.

Table 2 lists which query shapes passed each censor and which public resolvers
(Cloudflare, Google, Quad9) answered them. The rows that passed all three GFW
injectors:

| Shape (Table 2) | GFW injectors 1–3 | Iran | Cloudflare | Google | Quad9 |
| --- | --- | --- | --- | --- | --- |
| Deep pointer chain (more than 18 jumps) | passed | passed | rejected | answered | rejected |
| **Q2 points to Q1 (`0xC00C`)** | passed | detected | answered | answered | rejected |
| Falsified QDCOUNT | passed | detected | answered | rejected | rejected |
| Q2 with another QTYPE | passed | detected | answered | answered | rejected |
| Decoy domain as Q2 | passed | detected | answered | answered | rejected |

The other compression, EDNS(0), flag and opcode variants passed only some of
the injectors. A program counted as valid in the paper's first stage when any
one of the three resolvers answered it.

## What this change takes from it

**The censor model, adopted as the default defence.** Because the GFW races
forged answers instead of suppressing the real one, the robust answer is not
to win the parser race but to stop asking in plaintext. The `encrypted` preset
and `https://` entries use DNS-over-HTTPS (RFC 8484). TLS authenticates the
resolver, so an on-path censor can block the exchange but cannot change its
answer. Encryption also hides the node's name from the network. This covers
both censor models, including Iran's drop-and-answer behaviour, which no
plaintext technique in the paper handles reliably.

**Race detection for plaintext resolvers.** `udp://` resolvers are still useful
where DoH is blocked or for a resolver on a trusted path. Every exchange uses a
fresh connected socket with a random ID, and after the first matching response
it keeps listening for 300 ms. Two responses that disagree mean injection; the
whole exchange is discarded instead of choosing one, and the lookup moves to
the next resolver. A truncated (TC) answer is retried over TCP.

**The two-question shape, as an explicit experiment.** `udp://IP?shape=dual-question`
sends the *Q2 points to Q1* layout: QDCOUNT=2, the second question a
compression pointer (`0xC00C`) to the first, with the same type and class. Of
the shapes that passed all three injectors, it is the one with the widest
resolver support in Table 2 (Cloudflare and Google). It is well-formed
compression (a backward pointer), and it does not send a second, unrelated
domain. A reply that echoes only the first question is accepted.

It is never selected implicitly, and the client logs a warning when it is
configured, because:

- RFC 9619 requires QDCOUNT=1 for queries. Quad9 rejected the shape, and home
  routers, ISP resolvers and system stub resolvers were not measured at all.
- Iran's censor detected it.
- A two-question query is rare enough to be a fingerprint in itself. Once
  deployed, a censor can match on it, which the paper's discussion of
  operational risk anticipates.
- It is still plaintext: it changes what the injectors parse, not the fact that
  the answer is unauthenticated and the name is visible.
- It is one measurement campaign, not a production guarantee.

**Not adopted:**

| Shape | Reason |
| --- | --- |
| Deep pointer chain | Only Google answered it. It is also exactly the pattern hardened parsers reject as a pointer loop or a decompression bomb. |
| Forward pointers, padding plus forward pointer, domain in EDNS(0) | Violate RFC 1035 §4.1.4 (pointers must point backwards); only Google answered; partial injector bypass. |
| Split labels via pointer | All three resolvers answered it, but it passed only two of the three GFW injectors, so the third still poisons the answer. |
| Falsified QDCOUNT, ANCOUNT/ARCOUNT/NSCOUNT > 0 | Header deliberately inconsistent with the body; rejected by Google and Quad9. |
| Decoy domain | Discloses a second name and asks a resolver a question the client does not need. |
| Q2 with another QTYPE | Requests a record type the client discards, for no advantage over the chosen shape. |
| TC/Z bits, non-standard opcode | Passed one injector at most; rejected by Quad9, and by Google for the opcode. |

## Configuration

A policy is a comma-separated list, tried in order:

| Entry | Meaning |
| --- | --- |
| `system` | The platform resolver, and, if it fails, the secondary resolvers the client already used (AliDNS, DNSPod, Google, all plaintext). Alone it is the default. **As the last entry** it is a plaintext fallback, consulted only after every other entry failed, and it logs a warning when used. Anywhere else it is rejected. |
| `encrypted` | Cloudflare and Google DoH, by IP address: `https://1.1.1.1`, `https://8.8.8.8`, `https://[2606:4700:4700::1111]`, `https://[2001:4860:4860::8888]` (all `/dns-query`). |
| `https://host[:port][/path]` | An RFC 8484 server. The path defaults to `/dns-query`; a query string is kept. Certificates are always verified, against the platform trust store (the Mozilla roots on Android). |
| `udp://IP[:port]` | A plaintext resolver by IP address (default port 53), with race detection. |
| `udp://IP[:port]?shape=dual-question` | The same, with the experimental two-question query. |

Rules: at most eight resolvers; duplicates count once; `udp://` takes an IP
address, not a name. A DoH URL with credentials, a fragment or plain `http://`
is rejected. An invalid policy stops the CLI and server at startup. An invalid
`ENDPOINT_DNS` read by an embedder makes every endpoint lookup fail, with the
error logged once, rather than silently using the system resolver.

Precedence for `http-proxy-cli`: `--endpoint-dns`, then `endpoint_dns` in the
config file, then `ENDPOINT_DNS`, then `system`. `--endpoint-dns` is saved to
the config file like other options:

```toml
endpoint_dns = ["https://203.0.113.53/dns-query", "encrypted"]
```

`http-proxy-server` takes `--endpoint-dns` or `ENDPOINT_DNS`. Embedders,
including the FFI library, read `ENDPOINT_DNS` on the first endpoint lookup.
Rust embedders can call `proxy_core::transport::set_endpoint_dns`. The startup
banner and logs show the policy without URL paths or query strings, which can
carry account tokens.

**Prefer IP-literal DoH URLs.** The DoH client resolves a hostname in its own
URL with the system resolver. A poisoned answer there only makes TLS
verification fail (closed), but the name is visible and the lookup can be
blocked. The `encrypted` preset uses addresses for that reason.

**The preset is not a promise of reachability.** Public DoH addresses can be
blocked by address or SNI on exactly the networks this targets. Then
`encrypted` lookups fail closed. A DoH endpoint you operate, for example on a
relay server by IP address, or an explicit trailing `system`, are the
alternatives.

## Behaviour and budgets

- **Scope:** endpoint lookups only. IP literals skip DNS entirely. Destinations
  keep the system resolver and their own cache entries, so an endpoint answer
  never serves a destination lookup or the reverse.
- **Time:** network resolvers share a 5-second budget per lookup; a trailing
  `system` adds the usual 3-second system budget. `system` alone keeps the
  3-second budget.
- **Order:** resolvers start in order. The next one starts when the previous
  fails or after 500 ms without an answer, with at most two in flight. The
  first answer wins, and the losers are cancelled.
- **Families:** A and AAAA are asked concurrently. Once one family has
  addresses, the other gets 300 ms more. IPv4 addresses are listed first.
- **Plaintext latency:** every `udp://` lookup waits out the 300 ms detection
  window after its first response, and retransmits once after 1 s without one.
- **DoH:** POST, message ID 0, EDNS(0) padding to 128-byte blocks (RFC 8467),
  HTTP/1.1 keep-alive, no proxy, no redirects, HTTPS only, 3-second connect
  timeout, at most 64 KiB per response, `application/dns-message` required.
- **Validation:** responses must match the ID, opcode and question; CNAME
  chains are followed for up to eight hops, and loops are rejected. Records for
  other names are ignored. Malformed messages, including compression-pointer
  loops, are rejected by the decoder.
- **Unroutable answers** (`0.0.0.0/8`, multicast, `240.0.0.0/4`, broadcast,
  `::`, IPv6 multicast) are discarded for every endpoint lookup, including
  `system`. This is a behaviour change: an endpoint name that resolves *only*
  to such addresses now fails with `AddrNotAvailable` instead of dialling, for
  example, `0.0.0.0`, which reaches the local host. Private and loopback
  addresses are kept, because LAN and local nodes are legitimate, so Iran-style
  private-address injection is caught only by DoH.
- **Cache:** answers from network resolvers are kept for their TTL, clamped to
  30 s – 5 min. NXDOMAIN and NODATA are kept for 5–60 s (the negative TTL from
  the SOA record when present) when the policy has no fallback; with a
  fallback, the system resolver is asked instead. Changing the policy
  invalidates its earlier answers. Concurrent lookups of one name share a
  single resolution.
- **Concurrency:** at most eight network endpoint lookups at once, separate
  from the eight system-resolver slots.
- **Failure:** without a trailing `system`, a lookup that no resolver answered
  returns an error naming each resolver (redacted) and its failure.

## Platform notes

- **Desktop TUN:** tun2proxy answers port-53 traffic from the client's own,
  bypassed, process with its physical DNS relay (AliDNS, DNSPod, then the
  adapter's DNS), whatever server the query was addressed to. While desktop TUN
  is active, a `udp://` resolver is therefore not the server that answers, the
  injection check sees only the relay's single reply, and the two-question shape
  is refused by the relay. The client logs a warning when TUN starts with such a
  policy; use `https://` entries with TUN. DoH works because the client's own
  sockets bypass the tunnel. Route bypasses are computed from the same endpoint
  cache the carriers dial from.
- **macOS GUI TUN helper:** the privileged helper resolves the node for its
  route bypass with its own default policy. The Flutter UI does not expose this
  setting yet, so the GUI and helper agree on `system`.
- **Mobile:** the FFI library honours `ENDPOINT_DNS`, but the mobile UIs do not
  set it.

## Limitations

- **No live validation.** Nothing here was tested against the GFW, Iran's
  censor or real public resolvers. The tests use loopback fakes. The
  two-question shape's evasion is the paper's observation, not this project's.
- **Race detection is not authentication.** It catches a forgery only when a
  different response also arrives within 300 ms of the first. A censor that
  drops the real answer (Iran), an injector that answers only after the window,
  loss of the real response, or one consistent forgery all go undetected. ID,
  port and question matching stop only off-path guessing. Use DoH when the
  answer matters.
- **DoH can be blocked.** Encrypted resolution then fails closed, which is an
  availability cost. A trailing `system` trades that for plaintext answers.
- **The DoH operator is trusted** and learns the endpoint names it is asked
  for. DNSSEC is not validated.
- **TTL floor:** a 30-second minimum reuse time can delay failover for names
  published with a shorter TTL.

## Verification

Deterministic tests, with no public services:

- `crates/proxy-core/src/dns/`: query encoding (standard, padded, dual-question
  layouts); hostile messages (pointer self-loops, cycles and forward pointers,
  overlong labels, truncated records); ID, question and type matching; CNAME
  loops; negative TTLs; injected races and noise; retransmission; TC-to-TCP
  retry; DoH certificate failure, content type, status, redirect, size limit,
  and URL redaction; hedging and deadlines with a paused clock.
- `crates/proxy-core/src/transport.rs`: fail-closed versus explicit fallback;
  invalid policy; negative caching; policy-generation cache keys; coalesced
  concurrent lookups; destination and endpoint cache separation; sinkhole-only
  answers.
- `crates/proxy-core/tests/endpoint_dns.rs`: a separate process with a global
  policy and a loopback resolver. A node is dialled at the address the policy
  resolves, an injected race fails closed instead of dialling either answer,
  and an external HTTP proxy is reached through the policy.
- CLI parsing and config persistence in `http-proxy-cli` and
  `http-proxy-server`.

## References

- A. Zohaib, J. Sippe, J. Sheffey, M. Wu, E. Wustrow, A. Houmansadr.
  *CircumVolve: Automated Discovery of Censorship Evasion Strategies Using
  Large Language Models.* ACM CCS 2026. §4.2, Table 2.
- Anonymous, A. A. Niaki, N. P. Hoang, P. Gill, A. Houmansadr. *Triplet
  Censors: Demystifying Great Firewall's DNS Censorship Behavior.* FOCI 2020.
- RFC 1035 §4.1.4 (compression), RFC 2308 (negative caching), RFC 5452
  (resilience against forged answers), RFC 7830 and RFC 8467 (EDNS(0)
  padding), RFC 8484 (DNS-over-HTTPS), RFC 9619 (QDCOUNT is one).
