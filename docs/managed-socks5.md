# Managed server-side SOCKS5

`http-proxy-server` can expose an additional SOCKS5 listener for standard proxy
clients. It supports TCP `CONNECT` (IPv4, IPv6, and domain names) and UDP
`ASSOCIATE`, with mandatory username/password authentication. BIND and the
CipherRelay-specific ICMP command are not supported on this endpoint.

Mainland China client IPs are always refused before authentication, including
IPv6 and IPv4-mapped IPv6 peers. Hong Kong, Macao and Taiwan are not part of this
block. It applies to the managed SOCKS5 endpoint's incoming TCP peer, not to
proxy destinations or the native encrypted TCP/QUIC listeners.

Traffic leaves the way the node's native traffic does: directly, or through the
node's relay target (another node or an external SOCKS5/HTTP proxy) when relay
is enabled. Existing encrypted native connections, the local client's
no-authentication listener, and the FFI interfaces keep their behavior.

## Who can do what

| Action | Needs | Where |
| --- | --- | --- |
| Read a node's `socks5://` link | The node's session key | The app shows it on the node's details; `http-proxy-admin socks5 link` |
| Enable, disable, change or inspect SOCKS5 | `CONTROL_ADMIN_TOKEN` | `http-proxy-admin` only |

Anyone holding the session key can already use the native proxy, so the link is
not a new privilege: it lets them use SOCKS5-only applications. Changing the
endpoint opens a public port and hands out credentials, so it needs an admin
token that proxy users do not hold:

- The server must set `CONTROL_ADMIN_TOKEN`. Without it, every SOCKS5
  management request is refused.
- The token must differ from `SECRET_KEY` and `CONTROL_SESSION_KEY`; the app
  sends its session key as the token, so a shared value would make every user
  an administrator. The server logs a warning and refuses management in that case.

When an admin token is configured, `ping`, `nodes list`, `groups list` and the
SOCKS5 link need only the session key; every other control request needs the
token. The app reads only those four.

The app has no SOCKS5 controls. It shows a node's link, with the password
hidden until revealed and a copy button, only while that node is serving
SOCKS5; links are fetched again when the node catalogue is refreshed.

## CLI

Build the server and management CLI from the same source revision:

```bash
cargo build --release -p proxy-server --bin http-proxy-server --bin http-proxy-admin
```

At first startup the server generates a username (`cipherrelay`) and a 256-bit
random password, independent of `SECRET_KEY`. The listener is **disabled by
default**, with a saved bind address of `0.0.0.0:1080`. The native control port
remains unchanged (normally 1081).

Give the admin process the server's key (`SECRET_KEY`, or `CONTROL_SESSION_KEY`
when the deployment has a separate control key) and its `CONTROL_ADMIN_TOKEN`.
`--session-key` and `--token` work too. Do not put real keys in scripts or
checked-in examples.

```bash
# These commands connect to the native control port, not the SOCKS5 port.
http-proxy-admin -H SERVER_IP -p 1081 socks5 status
http-proxy-admin -H SERVER_IP -p 1081 socks5 enable --listen 0.0.0.0:1080
http-proxy-admin -H SERVER_IP -p 1081 socks5 link
http-proxy-admin -H SERVER_IP -p 1081 socks5 rotate-key
http-proxy-admin -H SERVER_IP -p 1081 socks5 disable
```

| Command | Effect |
| --- | --- |
| `status` | Settings, credentials, `running`, `last_error`, `active_sessions` |
| `enable [--listen ADDR]` | Start the listener; without `--listen` the saved address is used |
| `disable` | Close the listener and every session |
| `rotate-key` | Generate a new password |
| `set-credentials [--username NAME] [--password-stdin]` | Choose the username and/or read a password from the first line of stdin |
| `set-advertise HOST[:PORT]` / `set-advertise --clear` | The address links name, for NAT, port mapping or a domain |
| `set-policy [--udp on\|off] [--private-destinations allow\|deny] [--max-sessions N] [--handshake-timeout SECS]` | UDP, destination and resource policy |
| `allow add CIDR...` / `allow remove CIDR...` / `allow clear` | Additional client allowlist; empty allows sources outside the mainland China block |
| `link [--host HOST]` | The `socks5://` link; the host defaults to `-H` unless one is advertised |
| `sessions` | Active sessions: id, client, command, destination, start time |
| `kick --id N` / `kick --peer IP` / `kick --all` | Close sessions |

Every command prints JSON. `status` and the changing commands return the same
status object, including the password, so treat the output as a secret:

```json
{
  "ok": true,
  "error": null,
  "result": {
    "type": "socks5_status",
    "status": {
      "config": {
        "enabled": true,
        "listen": "0.0.0.0:1080",
        "username": "cipherrelay",
        "password": "<generated-password>",
        "udp": true,
        "allow_private_destinations": false,
        "max_sessions": 1024,
        "handshake_timeout_secs": 10
      },
      "running": true,
      "last_error": null,
      "active_sessions": 0
    }
  }
}
```

`link` prints `{"ok":true,"result":{"type":"socks5_link","url":"socks5://…","udp":true}}`.
Usernames and passwords are percent-encoded in links.

Changes to credentials, policy or the bind address revoke every session before
the command returns; clients reconnect with the current settings. Changing only
the advertised address keeps sessions. Port zero selects a free port and saves
the actual one. Moving between overlapping addresses on one port, such as
`127.0.0.1:1080` and `0.0.0.0:1080`, closes the old listener first and restores
it if the new address cannot be bound. Neither operation affects native sessions.

## Network policy

The server checks the actual TCP peer against the bundled mainland China IPv4
and IPv6 ranges before reading a SOCKS5 greeting or allocating a session.
The source allowlist, including `0.0.0.0/0` or `::/0`, cannot override this
block. Both `CONNECT` and `UDP ASSOCIATE` require that TCP connection, and UDP
packets remain pinned to the admitted peer. No online geolocation lookup is
performed on incoming connections.

The range source and pinned revision are recorded in
`crates/proxy-core/data/china-ip/manifest.json`. IP allocation and routing can
change; refresh the bundled snapshot with
`python3 scripts/geo/update-china-ip.py --revision FULL_COMMIT_SHA` and rebuild
to apply updated ranges. A connection through another proxy is classified by
that proxy's source IP as seen by this server.

SOCKS5 follows [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) and
username/password authentication follows
[RFC 1929](https://www.rfc-editor.org/rfc/rfc1929). Standard SOCKS5 does not
encrypt its authentication exchange or payload; the encrypted control plane
protects credential retrieval only. For untrusted networks, carry SOCKS5 through
SSH/VPN/TLS or use CipherRelay's encrypted native transport, and restrict the
listener with `allow` or a firewall.

Because a captured password must not reach the server's own services,
destinations that are not globally routable are refused by default: loopback,
private (RFC 1918, IPv6 ULA), link-local (including cloud metadata at
`169.254.169.254`), carrier-grade NAT, benchmarking/fake-IP, documentation,
multicast and reserved ranges. Names are resolved first and only allowed
addresses are contacted, so `localhost` is refused too. A refused CONNECT gets
reply `0x02`; a refused datagram is dropped. Through a relay, addresses are
checked here and names are resolved by the relay. `set-policy
--private-destinations allow` lifts the restriction.

UDP associations use separate ephemeral UDP ports, announced in the SOCKS5
reply. Permit those UDP ports in host/cloud firewalls. A client that reaches a
private server address from a public one is behind NAT and is told the public
address: the advertised IP when `set-advertise` names one, otherwise the node's
`NODE_ADVERTISE_ADDR` or detected public IP. LAN, loopback and directly
addressed clients get the address they connected to. Arbitrary NAT port
remapping and TCP-only SSH forwarding cannot carry UDP associations.

Each UDP association belongs to its authenticated TCP connection and is pinned
to its peer IP and requested UDP port, or the first valid packet's port when
zero. On a dual-stack `[::]` listener, IPv4 clients are matched by their IPv4
address. Closing TCP releases UDP resources; stray bytes on it are ignored.
Malformed packets, fragmented packets (`FRAG != 0`), unexpected client
endpoints and unsolicited destination replies are dropped. Idle associations
expire after 300 seconds by default (`UDP_ASSOCIATION_IDLE_TIMEOUT_SECS`).

The listener admits `max_sessions` sessions (default 1,024), at most 128 of them
still authenticating. Authentication and the request share
`handshake_timeout_secs` (default 10); the outbound connect has its own
ten-second deadline and failures get the matching SOCKS5 reply. Sessions appear
in the node's connection metrics with their destination and are counted as
active connections.

## Persistence and failure handling

Settings live in `socks5.json` under `PROXY_DATA_DIR`, or `~/.proxy-everything`
when unset. Keep this file across upgrades. Writes use a temporary file
followed by atomic replacement; on Unix the file has mode 0600. Windows uses the
state directory's inherited ACL, so keep that directory accessible only to the
service account and administrators.

SOCKS5 problems never stop the native proxy:

- If `socks5.json` cannot be created, the server starts with SOCKS5 disabled and
  `status` reports why; a later change saves it once the directory is writable.
- If it exists but cannot be read or parsed, SOCKS5 stays unavailable,
  `status` reports the error, and changes are refused until it is repaired or
  removed. It is never replaced with different keys.
- A saved enabled listener is restored at startup without rewriting the file.
  If its port is occupied, `status` reports `enabled: true`, `running: false`
  and an error. Credentials and policy can still change; free the port and run
  `enable` again, or choose another address.

A failed bind on `enable` or a failed write leaves the previous live
configuration and password intact. Changes are serialized and finish even if
the requesting control connection disappears. Atomic replacement protects
readers from partial files; it does not guarantee directory metadata survives
a sudden power loss on every filesystem.

## Control API and compatibility

The framed control protocol gains these request types:

| Request `type` | Fields | Result | Access |
| --- | --- | --- | --- |
| `get_socks5_endpoint` | None | `socks5_endpoint` (`endpoint` is null unless running) | Session key |
| `get_socks5_status` | None | `socks5_status` | Admin |
| `set_socks5_enabled` | `enabled`, optional `listen` (only when enabling) | `socks5_status` | Admin |
| `rotate_socks5_key` | None | `socks5_status` | Admin |
| `update_socks5_config` | `update`: any of `username`, `password`, `advertise` (empty clears), `udp`, `allow_private_destinations`, `max_sessions`, `handshake_timeout_secs`, `clear_allowed_sources`, `remove_allowed_sources`, `add_allowed_sources` | `socks5_status` | Admin |
| `list_socks5_sessions` | None | `socks5_sessions` | Admin |
| `close_socks5_sessions` | optional `id`, optional `peer`; neither closes all | `socks5_sessions_closed` | Admin |

All of them require an encrypted control session, including when
`CONTROL_REQUIRE_ENCRYPTION=false`, and work over encrypted legacy and v3
transport. The app reads links through the `socks5_endpoint` operation of
`proxy_operation_start_v1`, so no FFI symbol changes. Older servers do not
answer it and the app shows no link for them; older admin binaries keep their
existing commands but cannot manage SOCKS5.

## Verification

`cargo test -p proxy-server --test managed_socks5 --locked` covers encrypted
legacy/v3 management, the admin-token rules, client link reads, CLI JSON/exit
codes, authentication rejection, TCP half-close, IPv4/IPv6/domain addressing,
destination policy, source allow lists, UDP boundaries/source checks, dual-stack
UDP, relay egress for TCP and UDP, session listing and closing, revocation,
persistence/restart without rewrites, failed restore, overlapping address moves,
bind/write failures, unusable state files, and the handshake deadline.
`cargo test --workspace --locked` also exercises the native protocol and the
local SOCKS5 paths that share the request parser and UDP relay.
