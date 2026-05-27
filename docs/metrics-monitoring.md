# Metrics & Management (TUI + Admin CLI)

This project exposes proxy metrics and management operations over the **control plane**. There are two ways to interact:

- **`proxy-tui`**: interactive terminal UI
- **`http-proxy-admin`**: CLI with JSON output (script-friendly)

Both tools use the same control API and require the same credentials.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Authentication & Encryption](#control-plane-authentication--encryption)
- [Terminal UI (proxy-tui)](#1-terminal-ui-proxy-tui)
- [Admin CLI (http-proxy-admin)](#2-admin-cli-http-proxy-admin)
  - [Metrics Commands](#metrics-commands)
  - [Node Commands](#node-commands)
  - [Relay Commands](#relay-commands)
  - [Node Group Commands](#node-group-commands)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

- Server is running and reachable on its proxy port (default `1081`)
- If the server enforces control encryption (default: `true`), you must provide
  a **control session key** that matches the server configuration
- If the server is configured with `CONTROL_ADMIN_TOKEN`, you must pass it

---

## Control Plane Authentication & Encryption

The control connection is validated in two steps:

1) **Session key** (encryption)
2) **Admin token** (optional)

### Session key sources

The client tools look for a session key in this order:

1. CLI flag `-k/--session-key`
2. Environment variable `CONTROL_SESSION_KEY`
3. Environment variable `SECRET_KEY`

If the server has `CONTROL_REQUIRE_ENCRYPTION=true` (default), a session key is
**required**. Make sure the key used by the client matches the server:

- Server picks a session key in this order:
  1. `CONTROL_SESSION_KEY`
  2. `SECRET_KEY`
  3. Built-in default key (`my-secret-key123my-secret-key123`)

### Admin token

If the server sets `CONTROL_ADMIN_TOKEN`, the tools must include `--token` with
the same value or requests will return `"unauthorized"`.

---

## 1) Terminal UI (proxy-tui)

### Build

```bash
cargo build --release -p proxy-tui
```

### Run

```bash
./target/release/proxy-tui \
  -H 127.0.0.1 \
  -p 1081 \
  -k YOUR_SESSION_KEY \
  --token YOUR_ADMIN_TOKEN
```

### Options

- `-H, --server-host`  Proxy server host
- `-p, --server-port`  Proxy server port (default: `1081`)
- `-k, --session-key`  Control session key (32 bytes)
- `--token`            Admin token (if required by server)
- `-r, --refresh`      Refresh interval in seconds (default: `2`)

### TUI Tabs

- **Nodes**: cluster node list (if node discovery is configured)
- **Groups**: node group management
- **Relay**: relay configuration and status
- **Realtime**: active connections, CPU, memory, uptime + recent minute buckets
- **Connections**: last 20 connection records
- **Top-N**: top hosts and top client IPs by traffic

### Keys

- `q` / `Esc` - quit
- `Tab` / `Right` - next tab
- `Shift+Tab` / `Left` - previous tab
- `r` - refresh
- `Up` / `Down` - move selection in Nodes / Groups / Relay
- `Enter` - switch server (Nodes tab)
- `/` - filter (Connections / Top-N)
- `PgUp` / `PgDn` - page (Connections / Top-N)

#### Node management (Nodes tab)

- `a` - add node (input: `host:port`)
- `d` - delete node (selected)
  - Self node cannot be removed and will show `[self]`

#### Group management (Groups tab)

- `a` - create group (input: `<group_id> <name>`)
- `d` - delete group (selected)
- `g` - add node to group (input: `<node_id>`, typically `host:port`)
- `x` - remove node from group (input: `<node_id>`)

#### Relay management (Relay tab)

- `e` - enable/disable relay
- `l` - cycle load-balancing algorithm
- `a` - add relay target
  - `node <host:port> [weight]`
  - `node_ref <node_id> [weight]`
  - `group_ref <group_id>`
  - `proxy <proxy_url> [weight]`
  - Or paste a full proxy URL directly: `socks5://...`, `socks5h://...`, `http://...`
- `d` - remove selected relay target
- `c` - set relay config (JSON)
  - Example:
    `{"enabled":true,"targets":[{"type":"group_ref","group_id":"asia"},{"type":"external_proxy","proxy_url":"socks5://relay-user:secret@127.0.0.1:1080","weight":1}],"algo":"round_robin","health_check_interval_secs":30}`

Relay display notes:

- Plain `host:port` is only valid in the `Nodes` tab or as `node <host:port>` in the `Relay` tab.
- Full proxy URLs work directly in the `Relay` tab because the scheme identifies the target type.
- Displayed relay targets redact proxy passwords in status and UI output.

---

## 2) Admin CLI (http-proxy-admin)

### Build

```bash
cargo build --release --bin http-proxy-admin
```

### Common flags

```bash
http-proxy-admin -H <SERVER_HOST> -p <SERVER_PORT> -k <SESSION_KEY> --token <ADMIN_TOKEN>
```

### Metrics commands

#### Realtime stats

```bash
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY metrics realtime
```

Fields:
- `active_connections`
- `cpu_percent`
- `memory_bytes`
- `uptime_secs`

#### Recent connections

```bash
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY \
  metrics connections --limit 20
```

Each record contains client IP, destination, bytes up/down, latency, duration,
start/end timestamps, and optional error.

#### Time buckets

```bash
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY \
  metrics buckets --granularity minute --count 10
```

- `--granularity`: `minute`, `hour`, `day` (short forms: `m`, `h`, `d`)
- `--count`: number of buckets to return

#### Top-N (hosts / IPs)

```bash
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY \
  metrics top-n --category hosts --limit 10

http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY \
  metrics top-n --category ips --limit 10
```

- `--category`: `hosts`/`host` or `ips`/`ip`

---

## Node Commands

Manage discovered nodes directly from the control plane.

### List nodes

```bash
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY nodes list
```

### Add node

```bash
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY \
  nodes add 10.0.0.1:1081
```

### Remove node

```bash
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY \
  nodes remove 10.0.0.1:1081
```

---

## Relay Commands

Manage dynamic relay configuration at runtime.

### Get relay config

```bash
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY relay get
```

Returns:
- `enabled`: whether relay is active
- `targets`: list of upstream targets (nodes or group refs)
- `algo`: load balancing algorithm
- `health_check_interval_secs`: health check interval

### Enable/disable relay

```bash
# Enable relay
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY relay enable

# Disable relay
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY relay disable
```

### Add relay target

```bash
# Add a node target
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY \
  relay add-target --addr 10.0.0.1:1081 --weight 1

# Add a group reference
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY \
  relay add-target --group-id asia-servers
```

### Remove relay target

```bash
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY \
  relay remove-target --index 0
```

### Set load balancing algorithm

```bash
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY \
  relay set-algo --algo weighted
```

Algorithms: `round-robin`, `random`, `weighted`, `least-conn`

### Get relay status

```bash
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY relay status
```

Returns current relay state including resolved targets and health status.

---

## Node Group Commands

Organize nodes into groups for easier management.

### List groups

```bash
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY groups list
```

### Create group

```bash
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY \
  groups create --id asia --name "Asia Servers"
```

### Delete group

```bash
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY \
  groups delete --id asia
```

### Add node to group

```bash
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY \
  groups add-node --group-id asia --node-id 10.0.0.1:1081
```

### Remove node from group

```bash
http-proxy-admin -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY \
  groups remove-node --group-id asia --node-id 10.0.0.1:1081
```

---

## Troubleshooting

- **`unauthorized`**
  - `CONTROL_ADMIN_TOKEN` is set on the server; pass `--token`.
- **No response / connection rejected**
  - Session key mismatch or missing. Provide `-k` or set `CONTROL_SESSION_KEY`.
- **`invalid value`**
  - Use allowed values shown in `--help`, including `minute|hour|day|m|h|d`
    and `hosts|host|ips|ip`.

---

## Security Notes

- Use a strong, private 32-byte session key in production.
- Avoid using the built-in default key outside of local testing.
