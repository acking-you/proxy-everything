# Local controller

The CLI and desktop subscription page can expose the same HTTP/1 JSON API on
`127.0.0.1`. It is off by default. The controller has its own port and bearer
token, independent of the proxy listener, LAN subscription URLs and server
control-plane credentials.

## Enable it

**Desktop** — Open **Subscription → Local control API**, turn the switch on,
and copy the URL and access token. Each start allocates a free port and a
fresh token. The API reads the Nodes page's catalogue and uses its reported
TCP and QUIC ports. Refresh the Nodes page to discover additional nodes or
transports. You can inspect the catalogue with the proxy stopped. Start the
proxy before switching. Closing the app or turning off the switch ends access.
This entry is available in Windows, Linux and non-App-Store macOS desktop builds.

**CLI** — Set `CIPHERRELAY_CONTROLLER_TOKEN` to a dedicated random secret of
32–256 printable ASCII characters without spaces. For example, in a POSIX shell:

```sh
export CIPHERRELAY_CONTROLLER_TOKEN="$(openssl rand -hex 32)"
http-proxy-cli -f config.toml --controller-port 9090
```

Set `controller_port = 9090` in the TOML file to enable it on later launches,
or pass `--controller-port 0` to print a free port at startup. Each CLI launch
begins with the normal configured upstream. Declare the allowed alternatives
in the same file, using at most one address per carrier and ID:

```toml
server_host = "west.example"
server_port = 1081
listen_host = "127.0.0.1"
[controller_nodes]
west = ["tcp://west.example:1081", "quic://west.example:10811"]
east = ["tcp://east.example:1081"]
```

The CLI adds the reserved ID `startup` when the initial endpoint has no matching
entry. CLI selection is available for native upstreams. An external SOCKS/HTTP
upstream uses a different forwarding path.

## Calls

Fetch `GET /v1/openapi.json` to discover the operations and their JSON schemas.
Use the URL and token of the instance you want to control. All routes require
the `Authorization: Bearer` header. Requests with a browser Origin are rejected.
Keep the token out of URLs, subscription documents, logs and model prompts.

```sh
base=http://127.0.0.1:9090
auth="Authorization: Bearer $CIPHERRELAY_CONTROLLER_TOKEN"
curl --noproxy '*' -sS -H "$auth" "$base/v1/openapi.json"
curl --noproxy '*' -sS -H "$auth" "$base/v1/nodes"
curl --noproxy '*' -sS -H "$auth" "$base/v1/status"
curl --noproxy '*' -sS -H "$auth" -H 'Content-Type: application/json' \
  -d '{"node_id":"west","transport":"quic","close_existing":true}' "$base/v1/switch"
```

| Operation | Successful response |
| --- | --- |
| `GET /v1/nodes` | `{"nodes":[{"id":"west","endpoints":[{"host":"west.example","port":1081,"transport":"tcp"},{"host":"west.example","port":10811,"transport":"quic"}]}]}` |
| `GET /v1/status` | `{"running":true,"local_port":1080,"active":{"node_id":"west","endpoint":{"host":"west.example","port":1081,"transport":"tcp"}}}` |
| `POST /v1/switch` | The committed status object, in the same shape as `GET /v1/status`. |

`running` describes the local listener. When stopped, `local_port` and
`active` are null. An active desktop endpoint outside the catalogue has a
null `node_id`. Reachability is determined when dialing the upstream or during
platform-specific TUN preparation.

A switch takes an exact node ID and one of its listed transports. It preserves
the local listener. Established connections continue by default. Set
`close_existing: true` to cancel open HTTP and SOCKS sessions (including UDP
associations) on this listener after committing the selection. This also works
when selecting the current node again. A desktop switch updates the normal
saved selection. Windows TUN prepares the selected route before publishing
the endpoint. On other desktop platforms the app can refresh capture around a
host change. In CLI TUN mode outside Windows, switch carriers on the same host
or stop capture before changing hosts.

Errors use `{"error":{"kind":"unknown_node","message":"…"}}`.
Branch on the status and `kind`. A failed or interrupted switch can be reconciled
with a fresh status read before issuing another mutation.

| HTTP | Kinds |
| --- | --- |
| 400 | `invalid_request` (including oversized or malformed switch bodies) |
| 401 | `unauthorized` |
| 404 / 405 | `unknown_node`, `not_found` / `method_not_allowed` |
| 409 | `not_running`, `busy`, `switch_failed` |
| 422 / 503 | `unsupported_transport` / `unavailable` |

## Website rules

Open **Website rules** to add, edit or delete a rule in the desktop app or
Android client. The editor works while the HTTP controller is off. In the
CLI, enable the controller to edit rules. Subsequent launches also load the
saved rules with the controller off.

Each rule selects either a direct connection or a catalogue node and one of its
available carriers. Saving a node rule pins the displayed host, port and carrier.
Re-save the rule to adopt a changed catalogue endpoint. Editing a rule leaves
the global selection and established tunnels alone. A connection to a selected
node that fails reports a forwarding failure.

- `example.com` matches the exact domain on any port.
- `*.example.com` matches children at any depth. Add a separate entry for the apex.
- `api.example.com:443` limits a rule to that port. Pasting an HTTP(S) URL
  keeps the domain and effective port. Paths and queries are discarded.
- Exact hosts take precedence over wildcard suffixes. Among suffixes the
  longest wins. A port-qualified rule wins over an otherwise identical one.
- Rules apply when opening an HTTP, HTTPS CONNECT or SOCKS5 CONNECT stream.
  Matching uses the host the client supplied. A numeric destination can match
  an IP rule; encrypted paths and the domain behind an IP are unavailable.
  SOCKS5 UDP associations retain their existing association-wide routing.
  Process bypass, mandatory direct exceptions and protected DNS keep precedence.

The CLI stores rules next to its TOML profile as `<filename>.sites.json`. The app
uses `website-rules.json` in its support directory. API updates atomically replace
the file and publish a new in-memory snapshot. Up to 256 website rules fit in
one profile.

```sh
curl --noproxy '*' -H "$auth" "$base/v1/rules"
curl --noproxy '*' -X PUT -H "$auth" -H 'Content-Type: application/json' \
  -d '{"site":"*.example.com:443","target":{"action":"node","node_id":"west","transport":"quic"}}' "$base/v1/rules"
curl --noproxy '*' -X PUT -H "$auth" -H 'Content-Type: application/json' \
  -d '{"site":"intranet.example.com","target":{"action":"direct"}}' "$base/v1/rules"
curl --noproxy '*' -X DELETE -H "$auth" -H 'Content-Type: application/json' \
  -d '{"site":"*.example.com:443"}' "$base/v1/rules"
```

All three operations return `{"rules":[...]}` on success. Rule errors include
`invalid_rule` (400) and `rule_storage` (409).

## Composing calls in CodeMode

Run this JavaScript in a local runtime with access to loopback and inject
`base` and `token` from the host. A remotely hosted agent needs a local tool
that can issue these requests.

```js
async function call(path, body) {
  const response = await fetch(base + '/v1/' + path, {
    method: body ? 'POST' : 'GET',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: body && JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok) throw Object.assign(new Error(result.error.message), result.error);
  return result;
}

const { nodes } = await call('nodes');
const node = nodes.find(n => n.endpoints.some(e => e.transport === 'quic'));
const before = await call('status');
if (node && before.running &&
    (before.active?.node_id !== node.id || before.active?.endpoint.transport !== 'quic')) {
  await call('switch', { node_id: node.id, transport: 'quic' });
}
```
