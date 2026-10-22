# Managed server-side SOCKS5

`http-proxy-server` can expose an additional SOCKS5 listener for standard proxy
clients. It supports TCP `CONNECT` (IPv4, IPv6, and domain names) and UDP
`ASSOCIATE`, with mandatory username/password authentication. BIND and the
CipherRelay-specific ICMP command are not supported on this endpoint.

This endpoint forwards directly from the server to the destination. Native
relay targets and load balancing do not apply to it. Existing encrypted native
connections, the local client's no-authentication listener, and Flutter/FFI
interfaces keep their existing behavior.

## CLI

Build the server and management CLI from the same source revision:

```bash
cargo build --release -p proxy-server --bin http-proxy-server --bin http-proxy-admin
```

Start the server as usual. At first startup it generates a username
(`cipherrelay`) and a 256-bit random password, independent of `SECRET_KEY`.
The SOCKS5 listener is **disabled by default**, with a saved bind address of
`0.0.0.0:1080`. The native control port remains unchanged (normally 1081).

Set `SECRET_KEY` in the admin process to the server's native encryption key.
Use `CONTROL_SESSION_KEY` if the deployment has a separate control session key,
and `CONTROL_ADMIN_TOKEN` if the server requires an admin token. Existing CLI
`--session-key` and `--token` options also work. Do not put real keys in scripts
or checked-in examples.

```bash
# These commands connect to the native control port, not the SOCKS5 port.
http-proxy-admin -H SERVER_IP -p 1081 socks5 status
http-proxy-admin -H SERVER_IP -p 1081 socks5 enable --listen 0.0.0.0:1080
http-proxy-admin -H SERVER_IP -p 1081 socks5 rotate-key
http-proxy-admin -H SERVER_IP -p 1081 socks5 disable
```

`enable` without `--listen` reuses the saved address. Use `127.0.0.1:1080`
for local/SSH-forwarded access or `[::]:1080` for an IPv6 listener; dual-stack
behavior depends on the operating system. Port zero selects a free port and
saves the actual bound port. Changing the bind address revokes old sessions.

Every command returns JSON, including the current username and password:

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
        "password": "<generated-password>"
      },
      "running": true,
      "last_error": null
    }
  }
}
```

Treat this output as a secret. Debug formatting and normal server logs redact
or omit the password. The bind address is not necessarily the address a remote
client should dial: replace `0.0.0.0` with the server's reachable IP or hostname.
Configure a standard SOCKS5 client with that address, port, username, and password.

`disable` closes the listener and all existing TCP/UDP sessions before replying.
`rotate-key` generates a new password, keeps the current bind address and enabled
state, and revokes all previous sessions before replying. Old passwords stop
working immediately; clients must reconnect with the returned password.
Neither operation restarts or revokes encrypted native proxy sessions.

## Persistence and failure handling

Settings live in `socks5.json` under `PROXY_DATA_DIR`, or
`~/.proxy-everything` when unset. Keep this file across upgrades. Writes use a
temporary file followed by atomic replacement; on Unix the file has mode 0600.
Windows uses the state directory's inherited ACL, so keep that directory
accessible only to the service account and administrators.

A failed bind or state-file write leaves the previous live configuration and
password intact. Mutations are serialized and finish even if the requesting
control connection disappears. A valid saved enabled state is restored on
startup. If its port is occupied, the native proxy/control plane remains
available, and `status` reports `enabled: true`, `running: false`, and an error.
Free the port and run `enable` again, or choose another address. A corrupt state
file causes startup to fail explicitly instead of silently generating new keys.
Atomic replacement protects readers from partial files; it does not guarantee
directory metadata survives a sudden power loss on every filesystem.

## Control API and compatibility

The existing framed control protocol gains three request types:

| Request `type` | Additional fields | Result |
| --- | --- | --- |
| `get_socks5_status` | None | `socks5_status` |
| `set_socks5_enabled` | `enabled: bool`, optional `listen: "IP:port"` | `socks5_status` |
| `rotate_socks5_key` | None | `socks5_status` |

The existing `token` field and authorization check apply. `listen` is accepted
only when enabling. All three operations require an encrypted control session,
including when `CONTROL_REQUIRE_ENCRYPTION=false`. They work over encrypted
legacy and v3 transport. Existing operation names, fields, and default transport
behavior are unchanged; older admin binaries continue to support their existing
commands but cannot manage SOCKS5. No Dart or FFI ABI changes are involved.

## Network and resource limits

SOCKS5 follows [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) and
username/password authentication follows
[RFC 1929](https://www.rfc-editor.org/rfc/rfc1929). Standard SOCKS5 does not encrypt
its authentication exchange or payload. The encrypted control plane protects
credential retrieval; it does not encrypt SOCKS5 traffic. For untrusted networks,
carry SOCKS5 through SSH/VPN/TLS or use CipherRelay's encrypted native transport.
Allow the listener's TCP port only where access is intended.

UDP associations use separate ephemeral UDP ports, announced in the SOCKS5
reply. Permit the applicable UDP ports in host/cloud firewalls when using UDP.
Behind a 1:1 NAT, set `NODE_ADVERTISE_ADDR=PUBLIC_IP:NATIVE_PORT` so the reply
advertises the reachable IP. Public-IP discovery is used when available.
Arbitrary NAT port remapping and TCP-only SSH forwarding cannot carry these UDP
associations. Loopback peers always receive a loopback address.

Each UDP association belongs to its authenticated TCP connection and is pinned
to its peer IP and requested UDP port, or the first valid packet's port when
zero. Closing TCP releases UDP resources. Malformed packets, fragmented packets
(`FRAG != 0`), unexpected client endpoints, and unsolicited destination replies
are dropped. Datagram boundaries remain intact. Idle associations expire after
300 seconds by default (`UDP_ASSOCIATION_IDLE_TIMEOUT_SECS` overrides this).

The listener permits at most 1,024 simultaneous sessions, with at most 128
undergoing setup. Authentication, request parsing, and destination connection
share a ten-second deadline. Established TCP sessions preserve half-close
behavior and use the existing forwarding/metrics implementation. Request
framing, UDP endpoint validation, direct UDP relay, and address codecs are shared
with the existing client/core implementation.

## Verification

`cargo test -p proxy-server --test managed_socks5 --locked` covers encrypted
legacy/v3 management, CLI JSON/exit codes, authentication rejection, TCP
half-close, IPv4/IPv6/domain addressing, UDP boundaries/source checks,
revocation, persistence/restart, failed restore, bind/write failures, and setup
timeout. `cargo test --workspace --locked` also exercises the original native
protocol and local SOCKS5 paths after the shared parsing refactor.
