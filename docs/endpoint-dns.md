# Endpoint DNS

`--endpoint-dns` (or `endpoint_dns` in `config.toml`, or the `ENDPOINT_DNS`
environment variable) chooses how a process resolves the hostnames of the
**proxy endpoints it dials itself**: native nodes, server relay targets and
external upstream proxies. It does not change how proxied or direct
destinations are resolved.

The default is **`auto`**: built-in DNS-over-HTTPS first, with the platform
resolver only while nothing on the path is seen forging answers. Builds that
promise not to contact third-party resolvers (`proxy-core/no-external-geo`,
including the Mac App Store edition) keep `system` as their default instead.

```bash
# Default: DoH first; the system resolver only while the path looks clean.
http-proxy-cli -s node.example.com -p 1081 -c 1080

# Strict DoH only; fail rather than fall back to plaintext DNS.
http-proxy-cli -s node.example.com -p 1081 -c 1080 --endpoint-dns encrypted

# Your own DoH server first, the built-in list next, and plaintext system DNS
# only when every encrypted resolver failed.
http-proxy-cli -s node.example.com --endpoint-dns "https://203.0.113.53/dns-query,encrypted,system"

# A relay server resolving its upstream targets under the same default.
http-proxy-server -p 1081 -t upstream.example.com:1081
```

None of this has been validated against the Great Firewall or any other live
censor. It is a design based on published measurements, verified with local
fakes. See [Limitations](#limitations). It does **not** advertise a guaranteed
bypass: ordinary transaction-ID / source-address / question matching is not
enough against a real on-path injector, and neither is this policy on every
network.

## Where pollution reaches this proxy

| Lookup | Resolved by | Exposed to local DNS injection? |
| --- | --- | --- |
| Proxied destination (HTTP/SOCKS5 target, `socks5h://`) | The remote server, or the upstream proxy, inside the encrypted session | No |
| TUN DNS (captured app port-53 queries, fake-IP or real-IP mode) | Fake-IP pool, or `--tun-dns-server` reached through the proxy | No, from the local network; the exit node's view of `tun_dns_server` still matters in real-IP mode |
| Direct destination (auto-proxy direct, website rule, bypassed process) | The system resolver, or tun2proxy's physical DNS relay for bypassed processes under desktop TUN | Yes, by design: these are hosts the user routes outside the proxy |
| **Native node, QUIC node, TUN route bypass, Windows live switch, macOS helper remote host** | This policy (`auto` by default) | Governed by this policy |
| **External upstream proxy (`--upstream-proxy`), its SOCKS5 UDP control connection** | This policy | Governed by this policy |
| **Relay target on a server (`-t`, relay config) and its health checks; control-plane connections to nodes** | This policy on the server | Governed by this policy |

The endpoint lookups happen before any tunnel exists, on the network the user
is trying to get out of. That has three consequences:

- **Availability.** One forged answer sends the client to a wrong address, and
  the DNS cache keeps it there. The native protocol's pre-shared key (and
  QUIC's certificate check) mean the wrong host cannot impersonate the node,
  so the result is a failed connection rather than a decrypted one.
- **Credentials.** An external HTTP or SOCKS5 upstream proxy authenticates with
  a password. If its hostname is poisoned, that password is sent to whatever
  address the forger chose.
- **Fingerprinting.** The node's hostname is visible to every resolver that is
  asked, and to the network on every plaintext lookup.

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

Hoang et al., *How Great is the Great Firewall? Measuring China's DNS
Censorship* (USENIX Security 2021), supplies the forged-address picture this
policy uses as a heuristic: forged IPv4 answers are public addresses outside
mainland space (§5), forged IPv6 answers lie in the Teredo prefix `2001::/32`
(§5.1), and ~99% of poisoned responses arrive within ~364 ms of the first
forged one from one mainland vantage (§7.2).

## What this change takes from them

**Authenticated resolution as the primary defence.** Because the GFW races
forged answers instead of suppressing the real one, the robust answer is not
to win the parser race but to stop asking in plaintext. DoH (RFC 8484)
authenticates the resolver: an on-path censor can block the exchange but
cannot change its answer. Encryption also hides the node's name from passive
observers of the query. This covers both censor models for the authenticated
leg, including Iran's drop-and-answer behaviour, which no plaintext technique
in CircumVolve handles reliably.

**The `auto` cascade.** Global DoH presets (Cloudflare / Google by IP) are
taken as-is when they answer. Mainland DoH presets (AliDNS / DNSPod by IP)
stay reachable on many censored networks, but their own upstream queries cross
the same filter, so their caches can hold its forgeries. A mainland answer
whose addresses all lie inside mainland space, RFC 1918 / 6598, ULA, or the
`198.18.0.0/15` fake-IP stand-in range is accepted; one that points outside
that space needs a second opinion (plaintext witnesses and/or the platform
resolver naming one of the same addresses, or silence from every other
source). Under injection the policy escalates, may send the paper's
two-question shape to the witnesses, and only uses an address that a trailing
response of a contested exchange also carries. Otherwise it fails closed
rather than hand over a forgery.

**Race detection for plaintext resolvers and witnesses.** `udp://` resolvers
and `auto`'s witnesses use a fresh connected socket with a random ID. After
the first matching response the client keeps listening for 400 ms (sized from
Hoang et al. §7.2). Two responses that disagree mean injection; the exchange
is discarded instead of choosing one. A truncated (TC) answer is retried over
TCP. Teredo `2001:0::/32` answers are treated as unroutable for endpoints.

**The two-question shape, as an explicit experiment (and an `auto` escalation
tool).** `udp://IP?shape=dual-question` sends the *Q2 points to Q1* layout:
QDCOUNT=2, the second question a compression pointer (`0xC00C`) to the first.
Of the shapes that passed all three injectors, it has the widest resolver
support in Table 2 (Cloudflare and Google). In a listed policy it is never
selected implicitly, and the client logs a warning when it is configured.
`auto` may send it only after injection is already observed.

**Not adopted as a default dependency:** deep pointer chains, forward
pointers, falsified header counts, decoy domains, and the other Table 2 rows
that only some injectors missed or that resolvers largely rejected. See the
earlier PR discussion and CircumVolve Table 2 for the per-row reasons.

## Configuration

| Entry | Meaning |
| --- | --- |
| `auto` | Complete policy on its own. Built-in global and mainland DoH, witnesses, and the platform resolver under the cascade above. Cannot be combined with other entries. **Default**, except in `no-external-geo` builds. |
| `system` | The platform resolver alone. **As the last entry of a list** it is a plaintext fallback after every other entry failed. Anywhere else in a list it is rejected. |
| `encrypted` | Cloudflare and Google DoH, by IP: `https://1.1.1.1`, `https://8.8.8.8`, `https://[2606:4700:4700::1111]`, `https://[2001:4860:4860::8888]` (all `/dns-query`). |
| `https://host[:port][/path]` | An RFC 8484 server. Path defaults to `/dns-query`. Certificates are always verified. |
| `udp://IP[:port]` | A plaintext resolver by IP (default port 53), with race detection. |
| `udp://IP[:port]?shape=dual-question` | The same, with the experimental two-question query. |

Rules: at most eight listed resolvers; duplicates count once; `udp://` takes
an IP, not a name. A DoH URL with credentials, a fragment or plain `http://`
is rejected. An invalid policy stops the CLI and server at startup. An invalid
`ENDPOINT_DNS` makes every endpoint lookup fail until a valid policy is set.

Precedence for `http-proxy-cli`: `--endpoint-dns`, then `endpoint_dns` in the
config file, then `ENDPOINT_DNS`, then the build default:

```toml
# endpoint_dns = ["auto"]   # default when omitted
# endpoint_dns = ["encrypted"]
endpoint_dns = ["https://203.0.113.53/dns-query", "encrypted"]
```

`http-proxy-server` takes `--endpoint-dns` or `ENDPOINT_DNS`; omitting both
keeps the build default. The FFI `start` map accepts optional `endpoint_dns`
(text or entry list). Handle-free JSON
`{"operation":"endpoint_dns","action":"get"|"check"|"set",...}` reads, dry-runs
or replaces the process policy. Packet-tunnel configs accept optional
`endpointDns`. The macOS privileged TUN helper receives the GUI's policy in
`HelperConfig.endpoint_dns` so it resolves `remote_host` under the same rules.

Hosts-file pins outrank every non-`system` policy. Single-label names and
names under local suffixes (`.lan`, `.local`, `.home.arpa`, …) go to the
platform resolver alone under `auto`, so split-horizon and LAN names are not
sent to public DoH.

## Behaviour and budgets

- **Scope:** endpoint lookups only. IP literals skip DNS. Destinations keep the
  system resolver and their own cache entries.
- **Time:** network / `auto` lookups share a 5-second budget (`auto` leaves a
  250 ms margin so it can report why it failed). A listed policy's trailing
  `system` adds the usual 3-second system budget. `system` alone keeps 3 s.
- **Order (listed):** next resolver after failure or 500 ms, at most two in
  flight. **`auto`:** hedge 200 ms, at most four authenticated attempts,
  platform resolver may stand alone after 600 ms or when authenticated
  resolvers are exhausted / missing.
- **Families:** A and AAAA concurrently; 300 ms grace once one family has
  addresses. IPv4 listed first.
- **Plaintext window:** 400 ms after the first matching response for `udp://`
  and witnesses.
- **DoH:** POST, message ID 0, EDNS(0) padding to 128-byte blocks, HTTP/1.1
  keep-alive, no proxy, no redirects, HTTPS only, certificate verification
  always on.
- **Unroutable filter:** discards `0.0.0.0/8`, multicast, `240.0.0.0/4`,
  broadcast, `::`, IPv6 multicast, and Teredo `2001:0::/32` for every endpoint
  lookup, including `system`.
- **Cache:** record TTL clamped to 30 s – 5 min; negative answers 5–60 s when
  there is no fallback; policy generation invalidates earlier answers.
- **Desktop TUN capture guard:** while an in-process or macOS-helper TUN
  session runs, `PlaintextDnsCapture` tells `auto` that plaintext queries from
  this process are answered by tun2proxy's physical DNS relay, so witnesses
  are skipped (verdict `Unobserved`) rather than treated as a clean path.

## Platform notes (TUN DNS audit)

| Path | What actually happens |
| --- | --- |
| Windows / Linux desktop TUN | After the route-bypass resolution, this process's port-53 traffic is answered by tun2proxy's physical relay (AliDNS / DNSPod / …). `auto` holds `PlaintextDnsCapture` for the session. App DNS still uses fake-IP or proxied real DNS; bypassed apps' DNS stays plaintext on that relay. |
| macOS GUI + privileged helper | The helper receives `endpoint_dns` and applies it before resolving `remote_host`. Both sides hold the capture guard for the helper session. |
| Apple Network Extension / packet tunnel | Provider sockets are exempt in the kernel; optional `endpointDns` applies before the first lookup. No capture guard (nothing rewrites the provider's port 53). |
| Android | App excluded from VPN; platform resolver is plaintext on the underlying network. `ENDPOINT_DNS` / FFI `endpoint_dns` still govern node lookups. |
| Store builds (`no-external-geo`) | Default stays `system`; DoH presets are not contacted unless the user configures them explicitly in a non-Store build. |

`udp://` under desktop TUN is still answered by the physical relay; the client
warns and recommends `https://` / `auto` / `encrypted`. App-level DoH/DoT
inside bypassed apps is ordinary traffic. Windows SMHNR / IPv6 DNS and Linux
`nss-resolve` caveats are unchanged. The Flutter UI lives in a separate
repository; with `auto` as the native default it is protected without a new
toggle, and can later wire `endpoint_dns` on `start` / `endpoint_dns`
operations / `endpointDns` on the packet-tunnel config.

## Limitations

- **No live validation.** Nothing here was tested against the GFW, Iran's
  censor or real public resolvers. Tests use loopback fakes and a paused clock.
- **`auto` is opportunistic.** Blocking every DoH server downgrades toward the
  platform resolver. Strict `encrypted` exists when that is unacceptable.
- **The “forgeries are outside mainland space” rule is a heuristic** from Hoang
  et al. (2020 data), not a CircumVolve claim and not a cryptographic property.
- **A global resolver's answer is taken as-is**, which is wrong for a
  blocklisted name whose authoritative servers sit inside the mainland (Hoang
  §6: polluted records in public resolvers).
- **Race detection is not authentication.** A path that drops the real response
  (Iran), a lone forged response, forgeries slower than the 400 ms window, or
  static-group forgeries that always carry one address, all read as clean;
  `auto` is then as exposed as the platform resolver.
- **Under desktop TUN, witnesses are unavailable** (`Unobserved`), so
  blocklisted names answered only by mainland DoH are not detected as forged
  by the race check.
- **Privacy:** `auto` discloses endpoint hostnames to Cloudflare/Google and
  possibly Alibaba/Tencent; it may send plaintext witness queries and ask the
  platform resolver.
- **Split-horizon names** need `system` or a hosts pin if they must not go to
  public DoH.
- **DoH can be blocked** by address or SNI; then authenticated resolution fails
  and `auto` falls back under its rules.

## Verification

Deterministic tests, with no public services:

- `crates/proxy-core/src/dns/` including `auto.rs`: cascade, second-opinion and
  placeholder rules, benches, verdicts, dual-question escalation, capture
  guard, local names / hosts pins; virtual time.
- Loopback DoH / UDP fakes; transport cache behaviour; integration
  `endpoint_dns.rs` and `endpoint_dns_default.rs`.
- CLI / server / FFI / packet-tunnel / macOS helper config parsing and
  fail-closed invalid policies.

## References

- A. Zohaib, J. Sippe, J. Sheffey, M. Wu, E. Wustrow, A. Houmansadr.
  *CircumVolve: Automated Discovery of Censorship Evasion Strategies Using
  Large Language Models.* ACM CCS 2026. §4.2, Table 2.
- N. P. Hoang, A. A. Niaki, J. Dalek, J. Knockel, P. Lin, B. Marczak,
  M. Crete-Nishihata, P. Gill, M. Polak. *How Great is the Great Firewall?
  Measuring China's DNS Censorship.* USENIX Security 2021. §5, §6, §7.
- Anonymous, A. A. Niaki, N. P. Hoang, P. Gill, A. Houmansadr. *Triplet
  Censors: Demystifying Great Firewall's DNS Censorship Behavior.* FOCI 2020.
- RFC 1035 §4.1.4, RFC 2308, RFC 5452, RFC 7830 / 8467, RFC 8484, RFC 9619.
