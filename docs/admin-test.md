# Admin Test Script (http-proxy-admin)

This document explains how to use the automated admin control‑plane test script:
`tests/admin-test.sh`.

The script spins up a local server and client, generates traffic, and validates
all `http-proxy-admin` control‑plane operations (nodes + metrics), including
admin‑token and session‑key scenarios.

---

## Prerequisites

- Rust toolchain (`cargo`, `rustc`)
- `curl`
- `lsof`
- `python3` (used for JSON validation)

Ports `12080` (client) and `12081` (server) must be free, unless you override them.

---

## Quick Start

From the repo root:

```bash
./tests/admin-test.sh
```

The script builds binaries (release if possible), launches server + client,
executes admin CLI calls, and prints pass/fail results.

---

## What It Tests

Phase 1 (default key, no admin token):
- `ping`
- `nodes list/add/remove`
- `metrics realtime`
- `metrics connections --limit`
- `metrics buckets --granularity {minute,hour,day}`
- `metrics top-n --category {hosts,ips}`
- Invalid parameters (granularity/category)

Phase 2 (admin token + session key from env):
- Unauthorized request without token
- Unauthorized request with wrong token
- Authorized request with correct token

---

## Configuration (Environment Variables)

You can override defaults by exporting environment variables before running:

```bash
SERVER_PORT=13081 \
CLIENT_PORT=13080 \
CONTROL_KEY='control-session-key-32-bytes!!!!' \
ADMIN_TOKEN='my-admin-token' \
./tests/admin-test.sh
```

### Variables

- `SERVER_PORT` (default: `12081`)
- `CLIENT_PORT` (default: `12080`)
- `CONTROL_KEY` (default: `control-session-key-32-bytes!!!!`)
  - Must be **exactly 32 bytes**
- `ADMIN_TOKEN` (default: `admin-token-for-tests`)

### Note on `SECRET_KEY`

`http-proxy-admin` control payloads are encrypted. The server uses the following
fallback order when encryption is required:

1. `CONTROL_SESSION_KEY`
2. `SECRET_KEY`
3. Built-in default key (`my-secret-key123my-secret-key123`)

If you have a custom `SECRET_KEY` in your shell environment, Phase 1 will fail
because the admin CLI uses the built-in default key. Either:

- Unset `SECRET_KEY` before running, or
- Set `SECRET_KEY` to the built‑in default key for the test run

Example:

```bash
SECRET_KEY='my-secret-key123my-secret-key123' ./tests/admin-test.sh
```

---

## Output

The script prints a green check for each test and exits non‑zero on failure.
On errors, it prints the raw admin response for debugging.

---

## Troubleshooting

- **"unrecognized subcommand 'topn'"**
  - Use `metrics top-n` (with a dash), not `topn`.
- **"unauthorized"**
  - You started the server with `CONTROL_ADMIN_TOKEN` but didn’t pass `--token`.
- **"invalid granularity" / "invalid category"**
  - Allowed granularity: `minute`, `hour`, `day` (or `m`, `h`, `d`).
  - Allowed category: `ips`/`ip` or `hosts`/`host`.
- **Port already in use**
  - Change `SERVER_PORT` / `CLIENT_PORT` or stop the conflicting process.

---

## Clean Up

The script traps `EXIT` and cleans up server/client processes automatically.
It also uses a temporary `HOME` directory to avoid modifying your real
`~/.proxy-everything/nodes.json`.
