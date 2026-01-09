# ProxyEverything iOS

iOS client for ProxyEverything proxy system.

## Prerequisites

- Xcode 15+
- Rust toolchain with iOS target: `rustup target add aarch64-apple-ios`

## Build

1. Build the static library:
```bash
./scripts/build-ios.sh release
```

2. Open `ios/ProxyEverything/ProxyEverything.xcodeproj` in Xcode

3. Build and run on device/simulator

## Usage

The app works with [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) for global proxy support.

### Setup Steps

1. Start ProxyEverything app, configure server address and port
2. In Shadowrocket, add a HTTP proxy pointing to `127.0.0.1:7890` (or your configured port)
3. Import the geo routing rules from `ios/docs/shadowrocket.conf`
4. Enable Shadowrocket VPN

### Proxy Modes

- **Forward Proxy** (users in China): China IPs direct, foreign IPs via proxy
- **Reverse Proxy** (users abroad): Foreign IPs direct, China IPs via proxy

See `ios/docs/` for detailed user guides in Chinese and English.

## Project Structure

```
ios/
├── ProxyEverything/          # Xcode project
│   └── ProxyEverything/
│       ├── ContentView.swift       # Main UI
│       ├── ProxyCore.swift         # FFI wrapper
│       ├── proxy_ffi.h             # C header
│       └── libhttp_proxy.a         # Static library (built locally)
├── docs/                     # Documentation
│   ├── ios-user-guide-cn.md
│   ├── ios-user-guide-en.md
│   ├── ios-development-guide.md
│   └── shadowrocket.conf
└── include/                  # C headers for FFI
```
