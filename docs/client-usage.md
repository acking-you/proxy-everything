# Client Usage

## Quick Start

1. Download `http-proxy-cli` from [releases](https://github.com/acking-you/proxy-everything/releases) (choose your platform)
2. Run: `http-proxy-cli -s <server-ip> -c <local-port>`
3. Configure system proxy to `127.0.0.1:<local-port>`
4. Done! Open YouTube and enjoy.

---

## Windows

1. Download `http-proxy-cli-*-x86_64-pc-windows-msvc.zip` from [releases](https://github.com/acking-you/proxy-everything/releases)

2. Extract and open Command Prompt in that directory:
   ```cmd
   .\http-proxy-cli.exe -s YOUR_SERVER_IP -c 7890
   ```

3. Configure system proxy:
   - Open Settings → Network & Internet → Proxy
   - Enable "Use a proxy server"
   - Address: `127.0.0.1`, Port: `7890`

   ![Windows Proxy Settings 1](../assets/win-proxy1.png)
   ![Windows Proxy Settings 2](../assets/win-proxy2.png)

4. (Optional) Create `start_proxy.bat` for quick launch:
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
   ./http-proxy-cli -s YOUR_SERVER_IP -c 7890
   ```

3. Configure system proxy:

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

4. (Optional) Create systemd service for auto-start:
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
   ./http-proxy-cli -s YOUR_SERVER_IP -c 7890
   ```

3. Configure system proxy:
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
