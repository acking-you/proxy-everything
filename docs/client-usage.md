# Client Usage

## Quick Start

1. Download `http-proxy-cli` from [releases](https://github.com/acking-you/proxy-everything/releases) (choose your platform)
2. Run: `http-proxy-cli -s <server-ip> -c <local-port> --set-system-proxy`
3. Done! The `--set-system-proxy` flag auto-configures your OS proxy.

Without `--set-system-proxy`, manually configure system proxy to `127.0.0.1:<local-port>`.

## CLI Options

| Option | Description |
|--------|-------------|
| `-s, --server-host` | Server IP/domain (required) |
| `-c, --client-port` | Local port (default: 1080) |
| `-p, --server-port` | Server port (default: 1081) |
| `-k, --key` | 32-byte encryption key |
| `--set-system-proxy` | Auto-set OS proxy (Linux/macOS/Windows) |
| `--reverse-geo` | Reverse geo logic: proxy CN, direct others |
| `-m, --msg-key` | Enable random message key |
| `--udp <true\|false>` | Enable SOCKS5 UDP ASSOCIATE (default: `true`) |
| `--tun` | Capture device traffic with a local TUN interface |
| `--tun-bypass-process <name>` | Bypass TUN for an executable name (repeatable) |
| `--tun-list-processes` | List running Windows executable names and exit |

---

## SOCKS5 UDP ASSOCIATE

`http-proxy-cli` accepts RFC 1928 UDP associations on the same local port used
for HTTP and SOCKS5 TCP. The SOCKS5 control connection stays on TCP while the
client is given a temporary UDP relay address.

UDP is enabled by default. Configure the application to use
`127.0.0.1:<client-port>` as a SOCKS5 proxy and enable UDP in that application.
Use `--udp false` (or `udp = false` in TOML) only when a TCP-only listener is
required. A minimal flow is:

```text
Application -- SOCKS5 UDP --> http-proxy-cli
            -- framed tunnel --> http-proxy-server -- UDP --> destination
```

Operational details:

- Client and server must both contain UDP-association support. Older servers
  cannot interpret the new `udp_associate` transport header. If the remote end
  closes before the readiness byte, the client now reports this as a likely
  server-version mismatch instead of the unhelpful `unexpected end of file`.
- UDP always uses the configured remote proxy server. TCP keyword/GeoIP split
  routing is not applied per UDP datagram.
- `--msg-key` enables AES-256-GCM authentication and encryption per UDP frame.
- `socks5://` and `socks5h://` upstream proxies support UDP ASSOCIATE when the
  upstream server implements it. `socks5://` resolves domain targets locally;
  `socks5h://` sends domain names to the upstream proxy.
- HTTP CONNECT upstream proxies do not support UDP.
- RFC 1928 fragmentation is not reassembled. Packets with `FRAG != 0` are
  dropped to keep association memory bounded.
- The UDP client address is pinned to the TCP control peer and the first valid
  UDP endpoint, preventing the local relay from becoming an open UDP proxy.
- Associations close with their TCP control connection and also expire after
  300 seconds without traffic. Set `UDP_ASSOCIATION_IDLE_TIMEOUT_SECS` on both
  sides to change the timeout.
- System HTTP proxy settings, including `--set-system-proxy`, do not capture UDP
  automatically. Use an application with SOCKS5 UDP support or a TUN adapter
  that emits SOCKS5 UDP ASSOCIATE.

---

## TUN Mode

TUN mode sends device traffic to the SOCKS5 listener already hosted on the
client port. It does not require a second proxy process or a separately
installed TUN device:

```text
Application TCP/UDP -> Wintun -> tun2proxy -> 127.0.0.1:<client-port>
                    -> proxy-everything client -> remote server -> destination
```

The local port is a protocol-multiplexed HTTP/SOCKS5 listener, but tun2proxy
deliberately uses its SOCKS5 endpoint because SOCKS5 preserves both TCP and UDP
semantics. A successful local listener bind is therefore a prerequisite for
starting TUN. TUN mode uses virtual DNS so resolver traffic is answered inside
the tunnel and the original domain is forwarded to the proxy instead of adding
a direct DNS route.

On Windows, keep `wintun.dll` in the same directory as
`http-proxy-cli.exe` or `proxy_ui.exe`. The supported build and staging scripts
place it there automatically.

### CLI

Enable complete TCP and UDP capture:

```powershell
.\http-proxy-cli.exe -s YOUR_SERVER_IP -p 1081 -c 1080 --tun --udp true
```

List current process names and let selected applications use the physical
network directly:

```powershell
.\http-proxy-cli.exe --tun-list-processes
.\http-proxy-cli.exe -s YOUR_SERVER_IP -c 1080 --tun `
  --tun-bypass-process browser.exe `
  --tun-bypass-process downloader
```

Equivalent TOML configuration:

```toml
tun = true
udp = true
tun_bypass_processes = ["browser.exe", "downloader"]
```

Executable matching is case-insensitive and a trailing `.exe` is optional.
User-selected bypasses apply to new TCP or UDP sessions. When a live policy
change affects an established session, tun2proxy closes that relay so the
application reconnects through the new route. The TUN adapter and system routes
remain in place.

### Flutter UI

Start the local proxy from the primary Proxy page, then enable the top-level
**TUN Mode** switch. The switch is disabled until `127.0.0.1:<client-port>` is
listening, remains busy until Wintun and route setup report ready, and stays off
when native setup fails. Setup errors include the failing stage, the underlying
Windows detail, and any tunnel/VPN adapters that were already active. **TUN
Bypass** opens a Task Manager-style Windows picker with executable names, live
PIDs, instance counts, and paths. It is available before startup and while the
proxy is connected. Applying a selection updates native routing immediately,
reconnects affected established sessions, and does not recreate the TUN
adapter.

The current UI executable appears as a required, disabled selection. This is
not only a presentation rule: Rust always appends the current executable after
every configuration or runtime replacement, so malformed imported settings or
an FFI caller cannot remove it.

### Privileges and shutdown

Creating Wintun and changing default routes require administrator privileges.
The Windows CLI requests UAC elevation and reconnects the elevated child to the
original console instead of opening a new terminal. The Windows Flutter runner
uses `asInvoker`, so HTTP/SOCKS5-only operation never prompts. Enabling TUN
launches an elevated replacement of the same GUI with `ShellExecute runas`; no
terminal is created. The original process releases the local port and the new
process retries the listener handoff before it creates Wintun.

Normal cancellation restores the routes through the TUN setup guard. A hard
process termination or machine crash can prevent graceful cleanup; restarting
the application and stopping TUN normally, or resetting the affected routes,
restores the expected state.

Only one application should own the fixed proxy-everything Wintun adapter and
its catch-all route. If another VPN/TUN application or another proxy-everything
instance is already active, startup stops before changing routes and names the
detected adapter. Stop it before retrying TUN mode. The GUI error is the
authoritative setup result; a generic numeric `RuntimeError` is retained only
for native ABI compatibility.

### Loop-prevention invariant

Loop prevention does not depend on one best-effort process lookup. Before the
catch-all route is installed, the client resolves its remote proxy endpoint and
adds each address as a physical route bypass. While TUN is active, it also
suppresses auto-proxy direct connections so every client-owned outbound session
uses that protected endpoint. Finally, the current executable is always kept in
the runtime process-bypass policy and cannot be removed through CLI, TOML,
Flutter, or FFI input. Without these protections, the remote connection would
be captured by Wintun, returned to the local SOCKS5 listener, and repeated.

The Auto Proxy preference is retained, but its direct-routing branch is paused
while TUN is active and resumes after TUN is disabled. This guarantees that
"all traffic through TUN" does not create client-owned direct-socket loops.

Other bypassed processes connect directly to their original destinations and
therefore do not use the proxy. Do not add an application to the bypass list if
its traffic should remain proxied.

TUN TCP continues to work with `--udp false`; captured UDP is rejected by the
local SOCKS5 listener in that configuration. Leave UDP enabled for complete
device TCP and UDP forwarding. HTTP upstream proxies cannot relay UDP, while a
SOCKS5 upstream must implement UDP ASSOCIATE.

When UDP is enabled, TUN startup performs an end-to-end SOCKS5 UDP ASSOCIATE
preflight before creating Wintun or changing routes. This catches an old remote
server, blocked UDP relay, or incompatible upstream immediately. Disable UDP
explicitly only when TCP-only TUN operation is intentional.

---

## Windows

1. Download `http-proxy-cli-*-x86_64-pc-windows-msvc.zip` from [releases](https://github.com/acking-you/proxy-everything/releases)

2. Extract and open Command Prompt in that directory:
   ```cmd
   .\http-proxy-cli.exe -s YOUR_SERVER_IP -c 7890 --set-system-proxy
   ```

3. (With `--set-system-proxy`) System proxy is auto-configured. Skip to step 5.

4. (Without `--set-system-proxy`) Configure system proxy manually:
   - Open Settings → Network & Internet → Proxy
   - Enable "Use a proxy server"
   - Address: `127.0.0.1`, Port: `7890`

   ![Windows Proxy Settings 1](../assets/win-proxy1.png)
   ![Windows Proxy Settings 2](../assets/win-proxy2.png)

5. (Optional) Create `start_proxy.bat` for quick launch:
   ```bat
   @echo off
   http-proxy-cli.exe -s YOUR_SERVER_IP -c 7890
   pause
   ```

---

## Linux

1. Download `http-proxy-cli-*-x86_64-unknown-linux-musl.tar.gz` from [releases](https://github.com/acking-you/proxy-everything/releases)

2. Extract and run:
   ```bash
   tar -xzf http-proxy-cli-*-linux-musl.tar.gz
   chmod +x http-proxy-cli
   ./http-proxy-cli -s YOUR_SERVER_IP -c 7890 --set-system-proxy
   ```

3. (With `--set-system-proxy`) System proxy is auto-configured via gsettings (GNOME). For other DEs, configure manually.

4. (Without `--set-system-proxy`) Configure system proxy manually:

   **GNOME (Ubuntu, Fedora):**
   ```bash
   gsettings set org.gnome.system.proxy mode 'manual'
   gsettings set org.gnome.system.proxy.http host '127.0.0.1'
   gsettings set org.gnome.system.proxy.http port 7890
   gsettings set org.gnome.system.proxy.https host '127.0.0.1'
   gsettings set org.gnome.system.proxy.https port 7890
   ```

   **KDE:**
   - System Settings → Network Settings → Proxy → Manual
   - HTTP/HTTPS Proxy: `127.0.0.1:7890`

   **Terminal only:**
   ```bash
   export http_proxy=http://127.0.0.1:7890
   export https_proxy=http://127.0.0.1:7890
   ```

5. (Optional) Create systemd service for auto-start:
   ```bash
   sudo tee /etc/systemd/system/proxy-client.service << EOF
   [Unit]
   Description=Proxy Client
   After=network.target

   [Service]
   ExecStart=/path/to/http-proxy-cli -s YOUR_SERVER_IP -c 7890
   Restart=always

   [Install]
   WantedBy=multi-user.target
   EOF

   sudo systemctl enable --now proxy-client
   ```

---

## macOS

1. Download `http-proxy-cli-*-x86_64-apple-darwin.tar.gz` from [releases](https://github.com/acking-you/proxy-everything/releases)

2. Extract and run:
   ```bash
   tar -xzf http-proxy-cli-*-apple-darwin.tar.gz
   chmod +x http-proxy-cli
   ./http-proxy-cli -s YOUR_SERVER_IP -c 7890 --set-system-proxy
   ```

3. (With `--set-system-proxy`) System proxy is auto-configured via networksetup.

4. (Without `--set-system-proxy`) Configure system proxy manually:
   - System Preferences → Network → Advanced → Proxies
   - Enable "Web Proxy (HTTP)" and "Secure Web Proxy (HTTPS)"
   - Server: `127.0.0.1`, Port: `7890`

   Or via terminal:
   ```bash
   networksetup -setwebproxy "Wi-Fi" 127.0.0.1 7890
   networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 7890
   ```

---

## Android

1. Download `http-proxy-cli-*-armv7-unknown-linux-musleabi.tar.gz` (32-bit) or `aarch64-unknown-linux-musl` (64-bit)

2. Use Termux to run:
   ```bash
   pkg install proot
   tar -xzf http-proxy-cli-*.tar.gz
   chmod +x http-proxy-cli
   ./http-proxy-cli -s YOUR_SERVER_IP -c 7890
   ```

3. Configure Wi-Fi proxy:
   - Settings → Wi-Fi → Long press connected network → Modify network
   - Proxy: Manual
   - Hostname: `127.0.0.1`, Port: `7890`

**Alternative:** Use apps like "Proxy Server" or "Every Proxy" to set system-wide proxy.

---

## iOS

**Option 1: iSH (Alpine Linux emulator)**

1. Install [iSH](https://apps.apple.com/app/ish-shell/id1436902243) from App Store

2. In iSH terminal:
   ```bash
   # Install dependencies
   apk add curl tar

   # Download ARM binary (iSH emulates x86)
   curl -LO https://github.com/acking-you/proxy-everything/releases/latest/download/http-proxy-cli-x86_64-unknown-linux-musl.tar.gz
   tar -xzf http-proxy-cli-*.tar.gz
   chmod +x http-proxy-cli
   ./http-proxy-cli -s YOUR_SERVER_IP -c 7890
   ```

3. Configure Wi-Fi proxy:
   - Settings → Wi-Fi → Tap (i) on connected network
   - HTTP Proxy → Manual
   - Server: `127.0.0.1`, Port: `7890`

> Note: iSH performance is limited due to emulation.

**Option 2: Wi-Fi Proxy (direct connection)**
- Settings → Wi-Fi → Tap (i) on connected network
- HTTP Proxy → Manual
- Server: `YOUR_SERVER_IP`, Port: `1081`

> This connects directly to server without local encryption layer.

**Option 3: Third-party proxy apps**
- Apps like Shadowrocket, Quantumult X, or Surge support custom proxy configurations
