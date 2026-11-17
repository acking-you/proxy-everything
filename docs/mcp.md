# CipherRelay MCP server

The [local controller](local-controller.md) also speaks the Model Context
Protocol. It serves Streamable HTTP at `http://127.0.0.1:<port>/mcp` on the
same port and with the same bearer token as the REST API. An agent adds it once
and then calls three tools: no HTTP helper, token plumbing or JSON parsing.

| Tool | Does | Arguments |
| --- | --- | --- |
| `get_proxy_state` | Reads the listener, the active upstream, the nodes and the website rules | `include_nodes` (default `true`) |
| `switch_node` | Selects the node and transport new connections use | `node_id`, optional `transport` (`tcp`/`quic`; TCP when offered), optional `close_existing` |
| `set_website_rule` | Sends one website directly or through a node, or back to the default route | `site`, `route` (`direct`/`node`/`default`), `node_id` and optional `transport` for `node` |

Every tool returns the same typed result, so code-mode clients generate one
result type for all three:

```json
{
  "running": true,
  "local_port": 1080,
  "active": {"node_id": "west", "endpoint": {"host": "west.example", "port": 10811, "transport": "quic"}},
  "nodes": [{"id": "west", "endpoints": [{"host": "west.example", "port": 1081, "transport": "tcp"}, {"host": "west.example", "port": 10811, "transport": "quic"}]}],
  "website_rules": [
    {"site": "*.example.com:443", "route": "node", "node_id": "west", "endpoint": {"host": "west.example", "port": 10811, "transport": "quic"}},
    {"site": "intranet.example.com", "route": "direct"}
  ]
}
```

`nodes` appears only when requested; `switch_node` and `set_website_rule` leave
it out. A refused call is a tool error (`isError: true`) whose text starts with
the same stable kind the REST API uses, for example
`unknown_node: Use a node ID from the node list.` Matching rules for `site` are
the ones described under [website rules](local-controller.md#website-rules).

## 1. Turn on the API

**Desktop** — Open **Subscription → Local control API** and turn it on. The
first start picks a free port and a token. Both stay the same after restarts,
and the API comes back on with the app, so an agent is set up only once.
**Connect an agent** shows the exact setup below with your port and token
filled in, and copies it.

**CLI** — Choose a fixed port and a token of 32–256 printable ASCII characters
without spaces:

```sh
export CIPHERRELAY_CONTROLLER_TOKEN="$(openssl rand -hex 32)"
http-proxy-cli -f config.toml --controller-port 9090
```

## 2. Add it to the agent

Replace `<PORT>` and `<TOKEN>`, or copy the filled-in version from the app.

**Claude Code** — run once:

```sh
claude mcp add --transport http --scope user cipherrelay http://127.0.0.1:<PORT>/mcp --header "Authorization: Bearer <TOKEN>"
```

**Codex** — add to `~/.codex/config.toml`:

```toml
[mcp_servers.cipherrelay]
url = "http://127.0.0.1:<PORT>/mcp"
http_headers = { Authorization = "Bearer <TOKEN>" }
```

To keep the token out of the file, set `CIPHERRELAY_CONTROLLER_TOKEN` in the
environment Codex starts from and use
`bearer_token_env_var = "CIPHERRELAY_CONTROLLER_TOKEN"` instead of
`http_headers`.

**JSON clients** — Cursor (`~/.cursor/mcp.json`), a project's `.mcp.json` and
similar clients take:

```json
{
  "mcpServers": {
    "cipherrelay": {
      "type": "http",
      "url": "http://127.0.0.1:<PORT>/mcp",
      "headers": { "Authorization": "Bearer <TOKEN>" }
    }
  }
}
```

VS Code uses the same entry under `"servers"` instead of `"mcpServers"`.

**Clients that only start local commands** — bridge stdio to HTTP with
[`mcp-remote`](https://www.npmjs.com/package/mcp-remote). Passing the header
through `env` avoids quoting problems with the space in it:

```json
{
  "mcpServers": {
    "cipherrelay": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://127.0.0.1:<PORT>/mcp", "--header", "Authorization:${CIPHERRELAY_AUTH}"],
      "env": { "CIPHERRELAY_AUTH": "Bearer <TOKEN>" }
    }
  }
}
```

## 3. Check it

Ask the agent to call `get_proxy_state` with `include_nodes: false`. A result
with `running` and `website_rules` means it is connected. An HTTP 401 means the
token is wrong or was replaced; a refused connection means the API or the CLI
is not running, or the port changed.

## Instructions for an agent installing this

1. Ask the user to turn on **Local control API** and to paste what **Connect an
   agent** copies for your client, or to give you the CLI's port and the name
   of the environment variable that holds its token.
2. Apply it with the method in step 2 for your client. Prefer an environment
   variable reference where the client supports one. Never print the token in
   chat, commit it or write it to a log.
3. Call `get_proxy_state` with `include_nodes: false` to confirm, then tell the
   user which client now has the `cipherrelay` server.

## Using the tools from code

Code-mode runtimes turn each tool into a typed function. The exact namespace
depends on the host; with a `cipherrelay` object it reads:

```js
const state = await cipherrelay.get_proxy_state({});
const quic = state.nodes.find(n => n.endpoints.some(e => e.transport === 'quic'));
if (quic && state.running && state.active?.node_id !== quic.id) {
  await cipherrelay.switch_node({ node_id: quic.id, transport: 'quic' });
}
await cipherrelay.set_website_rule({ site: '*.example.com', route: 'node', node_id: quic.id });
await cipherrelay.set_website_rule({ site: 'intranet.example.com', route: 'direct' });
```

## Security

- The server listens on `127.0.0.1` only. Every request needs the bearer token,
  requests carrying a browser `Origin` are refused, and the `Host` header must
  name a loopback address, which blocks DNS rebinding.
- The app stores the port and token in its preferences, readable by your user
  account. **Issue a new token** on the card replaces it; every configured
  agent then needs the new one.
- Agent configuration files hold the token unless the client reads it from an
  environment variable. Treat them like any other credential file.
