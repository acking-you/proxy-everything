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
| `--tun-udp-direct-fallback <true\|false>` | Send UDP directly when proxy UDP is off; `false` blocks it (default: `true`) |
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
client port. It does not require a second proxy process:

```text
Application TCP/UDP -> Wintun -> tun2proxy -> 127.0.0.1:<client-port>
                    -> proxy-everything client -> remote server -> destination
```

On Android, the Flutter client replaces Wintun and desktop route setup with an
Android `VpnService` interface. Kotlin owns the TUN descriptor, Rust forwards a
duplicate through the same tun2proxy and local SOCKS5 path, and Android applies
capture policy by application package name.

The local port is a protocol-multiplexed HTTP/SOCKS5 listener, but tun2proxy
deliberately uses its SOCKS5 endpoint because SOCKS5 preserves both TCP and UDP
semantics. A successful local listener bind is therefore a prerequisite for
starting TUN. TUN mode uses virtual DNS so resolver traffic is answered inside
the tunnel and the original domain is forwarded to the proxy instead of adding
a direct DNS route. Android exposes that resolver at `172.19.0.2`, outside the
`198.18.0.0/15` fake-IP pool, so its opportunistic private-DNS probe cannot
collide with an allocated application hostname.

The Flutter client supplies a stable private application-support directory on
Android, iOS, Windows, macOS, and Linux. The CLI uses its existing
`~/http-proxy-cli-config` data directory. TUN virtual-DNS allocations are
restored from those locations before capture starts, so cached fake-IP answers
remain valid across process restarts and in-place upgrades on every supported
client platform. Embedders using the FFI should likewise provide a stable
`cache_dir`; leaving it null intentionally disables persistent client state.

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
On Windows, selecting a launcher or Task Manager-style application root also
bypasses its live child-process tree. The matcher uses the ToolHelp process
snapshot, which remains available when a protected game process rejects direct
process-handle access. If the application already cached a virtual-DNS address,
the direct route restores the real destination through the physical interface.
User-selected bypasses apply to new TCP or UDP sessions. On Windows and macOS,
Apply evaluates existing sessions against the executable and ancestor identities
recorded when each session began. Adding an unrelated application leaves existing
bypasses, including the proxy's own connections, intact; it does not rescan the
system socket table for every connection. A session whose owner could not be
identified keeps its original proxied route until it reconnects.

When a live policy change affects an established session, tun2proxy explicitly
resets that TCP connection so the application can reconnect through the new
route. This also applies to DNS over TCP. Affected UDP relays are released and
the next datagram creates a relay under the updated policy. The TUN adapter,
physical egress binding, fake-IP mappings, and system routes remain in place.

### Flutter UI

Start the local proxy from the primary Proxy page, then enable the top-level
**TUN Mode** switch. The switch is disabled until `127.0.0.1:<client-port>` is
listening, remains busy until Wintun and route setup report ready, and stays off
when native setup fails. Setup errors include the failing stage, the underlying
Windows detail, and any tunnel/VPN adapters that were already active. **TUN
Bypass** opens a Task Manager-style Windows picker with executable names, live
PIDs, instance counts, executable icons, paths, and expandable launcher/child
process trees. Selecting a parent application implicitly selects its descendants
because native routing matches the socket owner against its live ancestor chain.
The picker is available before startup and while the proxy is connected.
Applying a selection updates native routing immediately, reconnects affected
established sessions, and does not recreate the TUN adapter.

The Flutter listener is loopback-only by default. **Proxy Configuration >
Allow LAN** explicitly changes the listener to `0.0.0.0:<client-port>` so
devices on the same network can use its HTTP or SOCKS5 endpoint. This endpoint
does not authenticate LAN clients; keep the option disabled on untrusted
networks and use the operating-system firewall to limit access. The UI displays
the current Wi-Fi address as a copyable `http://<address>:<client-port>` link
after LAN access is enabled.

The current UI executable appears as a required, disabled selection. This is
not only a presentation rule: Rust always appends the current executable after
every configuration or runtime replacement, so malformed imported settings or
an FFI caller cannot remove it.

### Android Flutter UI

On Android the desktop process picker is replaced by **VPN Applications**.
Choose **All** to capture every eligible application, **Bypass** to let selected
applications use the physical network, or **Only** to capture only selected
applications. The picker displays installed application names, package names,
icons, and system-app status. Application metadata is cached after the first
package query, while icons are loaded only for visible rows in small batches;
opening the picker therefore does not decode every installed application icon
before showing the list. The refresh button explicitly rebuilds both caches. A
live policy change recreates the Android VPN interface while keeping the local
proxy listener active.

The CipherRelay package is always outside its own VPN so its upstream
socket cannot be captured and returned to the local listener. Android shows its
standard one-time VPN consent dialog on first use and a foreground notification
while capture is active. See [Android VPN Development](android-vpn.md) for the
build, descriptor-ownership, application-policy, and emulator workflow.

### Privileges and shutdown

Creating Wintun and changing default routes require administrator privileges.
The Windows CLI requests UAC elevation and reconnects the elevated child to the
original console instead of opening a new terminal. The Windows Flutter runner
uses `asInvoker`, so HTTP/SOCKS5-only operation never prompts. Enabling TUN
launches an elevated replacement of the same GUI with `ShellExecute runas`; no
terminal is created. The original process releases the local port and the new
process retries the listener handoff before it creates Wintun.

On Windows, setup preserves the existing physical, WSL, and VPN default routes.
It captures IPv4 with two more-specific `/1` routes plus a session-owned
`0.0.0.0/0` compatibility row so forwarding consumers such as WSL HNS NAT
select Wintun even when they initialize after TUN startup. The IP Helper
transaction also snapshots and enables IPv4 forwarding on Wintun and WSL HNS
`vEthernet` interfaces. Wintun temporarily uses weak-host send/receive so
NAT-translated packets whose addresses belong to another interface can traverse
the TUN. A monitor applies the policy to WSL interfaces created or replaced
after TUN startup. Teardown restores only interface fields and route rows
changed by the current session, together with the previous TUN DNS setting.
Startup failures roll back the same transaction instead of deleting every
`0.0.0.0/0` route or guessing which physical default gateway should be
recreated.

Normal cancellation first cancels and drains the TUN TCP, UDP, UdpGW, and
socket-transfer tasks, then restores routes, interface settings, and DNS
through the setup guard.
This prevents old relays from surviving a node hot switch while network state
is already being replaced. A hard process termination or machine crash can
still prevent user-space cleanup; after such an event, inspect and remove only
the two `/1` rows and the `0.0.0.0/0` row whose interface and next hop identify
the proxy-everything Wintun adapter. Never use an unqualified default-route
deletion.

Only one application should own the fixed proxy-everything Wintun adapter and
its capture routes. If another VPN/TUN application or another proxy-everything
instance is already active, startup stops before changing routes and names the
detected adapter. Stop it before retrying TUN mode. The GUI error is the
authoritative setup result; a generic numeric `RuntimeError` is retained only
for native ABI compatibility.

### Loop-prevention invariant

Loop prevention does not depend on one best-effort process lookup. Before the
capture routes are installed, the client resolves its remote proxy endpoint and
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

The Windows picker combines live processes with installed Win32 applications
registered through App Paths, Uninstall metadata, and Start Menu Shell links.
For registrations that only expose an application directory, scanning is
bounded by depth and entry count rather than walking arbitrary drives. Use the
All, Running, and Installed views to control list density. Launcher trees are
expanded on first load so protected child processes remain individually
selectable. Executable names keep their original casing, and search accepts
registered aliases and common initialisms; for example, either `lol` or
`英雄联盟` finds `League of Legends.exe` even when it is not currently running.

IPv4 and IPv6 multicast UDP is always treated as local-link traffic rather than
sent to an Internet proxy. Direct relays select the physical multicast
interface explicitly; on Windows, `IP_UNICAST_IF` is insufficient because it
does not control multicast egress. Without the multicast-specific binding, an
SSDP packet such as `239.255.255.250:1900` can return through Wintun, create a
new proxy-ui UDP socket, and amplify into a self-sustaining relay loop.

TUN TCP continues to work with `--udp false`. By default, virtual DNS remains
inside the TUN resolver while other captured UDP is relayed directly instead
of being sent to the local SOCKS5 listener. This matches the practical fallback
used when a selected outbound cannot carry UDP, but it means non-DNS UDP
bypasses the configured proxy. Add `--tun-udp-direct-fallback false` to block
captured non-DNS UDP instead. Virtual DNS remains available in strict mode so
TCP applications can still resolve hostnames, including through DNS-over-TCP
on port 53. Embedders can declare local DNS portal addresses with repeatable
`--virtual-dns-portal`; opportunistic TLS probes to port 853 on those exact
addresses are failed locally so the operating system promptly returns to plain
DNS. HTTP upstream proxies cannot
relay UDP, while a SOCKS5 upstream must implement UDP ASSOCIATE.

Embedded desktop and Android clients allow up to 1024 concurrent TUN sessions.
The standalone tun2proxy CLI keeps its conservative 200-session default. Each
session is accounted for by an owned permit so completion, cancellation, and
task failure all release capacity. Limit warnings report separate TCP and UDP
counts, which distinguishes a genuine TCP connection surge from UDP or QUIC
flows consuming the shared budget. UDP proxy setup is bounded by the configured
UDP timeout so an unavailable UDP upstream cannot retain a slot indefinitely.

When a direct UDP flow targets a virtual DNS address, tun2proxy resolves its
stored hostname with DNS-over-TCP through the working TCP proxy before opening
the direct UDP socket. This avoids feeding the hostname back into Android's VPN
resolver and receiving a second fake IP.

When UDP is enabled, TUN startup performs an end-to-end SOCKS5 UDP ASSOCIATE
preflight before creating Wintun or changing routes. This catches an old remote
server, blocked UDP relay, or incompatible upstream immediately. Disable UDP
explicitly and select either the default direct fallback or strict blocking.

### Desktop log safeguards

The GUI requests native logs at `INFO` by default. Selecting a more verbose
level changes the native callback threshold, but burst delivery remains capped
and reports how many low-priority records were omitted. The in-memory viewer is
an O(1) 1,000-entry queue and refreshes at most ten times per second. Disk
logging batches writes, bounds its pending queue, caps each hourly file at 64
MiB, and retains at most 512 MiB across hourly files. These limits keep packet
or connection storms from turning diagnostic work into forwarding latency or
unbounded memory growth.

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

Use the Flutter Android client for whole-device IPv4/IPv6 capture. Configure
and start the local proxy, choose an application policy under **VPN
Applications**, then enable **VPN Service** and approve Android's consent
dialog. Manual Wi-Fi proxy settings are not required.

For local builds, physical-device ABIs, package visibility, and 4 KB/16 KB
emulator verification, follow [Android VPN Development](android-vpn.md).

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
