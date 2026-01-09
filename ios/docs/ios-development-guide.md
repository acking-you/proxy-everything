# iOS Development Guide

This guide covers building and integrating the ProxyEverything library into iOS applications.

## Architecture Overview

```text
┌─────────────────────────────────────────────────────────────┐
│                     iOS Application                          │
│  ┌─────────────────┐    ┌─────────────────────────────────┐ │
│  │   SwiftUI App   │───▶│         ProxyCore.swift         │ │
│  │  (ContentView)  │    │      (Swift FFI Wrapper)        │ │
│  └─────────────────┘    └───────────────┬─────────────────┘ │
│                                         │                    │
│                         ┌───────────────▼─────────────────┐ │
│                         │      proxy_ffi.h (C Header)     │ │
│                         └───────────────┬─────────────────┘ │
└─────────────────────────────────────────┼───────────────────┘
                                          │
┌─────────────────────────────────────────▼───────────────────┐
│                   libhttp_proxy.a (Rust)                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   ffi.rs    │  │  codec.rs   │  │    geo/query.rs     │  │
│  │ (C FFI API) │  │ (Encryption)│  │  (Geo Lookup)       │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- macOS with Xcode 15+
- Rust toolchain (stable 1.87.0+)
- iOS targets installed:

  ```bash
  rustup target add aarch64-apple-ios
  rustup target add aarch64-apple-ios-sim
  ```

## Quick Start

### 1. Build the Rust Library

```bash
# Build for both device and simulator, create XCFramework
./scripts/build-ios.sh all

# Or build individually
./scripts/build-ios.sh device     # Device only (aarch64-apple-ios)
./scripts/build-ios.sh simulator  # Simulator only (aarch64-apple-ios-sim)
```

Output files:

- `target/ios/device/libhttp_proxy.a` - Device static library
- `target/ios/simulator/libhttp_proxy.a` - Simulator static library
- `target/ios/HttpProxy.xcframework` - Universal XCFramework
- `ios/include/proxy_ffi.h` - C header file

### 2. Integrate into Xcode Project

1. Add `libhttp_proxy.a` to your project:
   - Drag `target/ios/device/libhttp_proxy.a` into Xcode
   - Or use the XCFramework for universal support

2. Add the C header:
   - Copy `ios/include/proxy_ffi.h` to your project
   - Create a bridging header that imports it

3. Link required frameworks:
   - `Security.framework`
   - `libresolv.tbd`

### 3. Configure Bridging Header

Create `YourApp-Bridging-Header.h`:

```c
#ifndef YourApp_Bridging_Header_h
#define YourApp_Bridging_Header_h

#include "proxy_ffi.h"

#endif
```

---

## FFI API Reference

### Data Types

```c
// Result codes
typedef enum {
    PROXY_OK = 0,
    PROXY_INVALID_PARAM = -1,
    PROXY_CONNECTION_FAILED = -2,
    PROXY_RUNTIME_ERROR = -3,
    PROXY_ALREADY_RUNNING = -4,
    PROXY_NOT_RUNNING = -5,
} ProxyResult;

// Configuration
typedef struct {
    const char* server_host;   // Remote server hostname
    uint16_t server_port;      // Remote server port
    uint16_t local_port;       // Local listening port
    const char* session_key;   // Encryption key (32 bytes)
    int auto_proxy;            // 0 = disabled, 1 = enabled
    int reverse_geo;           // 0 = CN direct, 1 = CN proxy
} ProxyConfig;
```

### Functions

| Function                       | Description                              |
| ------------------------------ | ---------------------------------------- |
| `proxy_create()`               | Create a new proxy handle                |
| `proxy_start(handle, config)`  | Start proxy with configuration           |
| `proxy_stop(handle)`           | Stop the proxy                           |
| `proxy_destroy(handle)`        | Free resources                           |
| `proxy_is_running(handle)`     | Check if proxy is running (returns 0/1)  |
| `proxy_init_logging()`         | Initialize logging subsystem             |

### Tunnel API (for Network Extension)

| Function                       | Description                              |
| ------------------------------ | ---------------------------------------- |
| `proxy_start_tunnel(config)`   | Start tunnel proxy (global instance)     |
| `proxy_stop_tunnel()`          | Stop tunnel proxy                        |
| `proxy_is_running_tunnel()`    | Check if tunnel is running               |

---

## Swift Integration

### ProxyCore Wrapper

```swift
import Foundation

class ProxyCore {
    private var handle: OpaquePointer?

    init() {
        proxy_init_logging()
        handle = proxy_create()
    }

    deinit {
        if let handle = handle {
            proxy_destroy(handle)
        }
    }

    func start(
        serverHost: String,
        serverPort: UInt16,
        localPort: UInt16,
        sessionKey: String,
        autoProxy: Bool,
        reverseGeo: Bool
    ) -> Bool {
        guard let handle = handle else { return false }

        return serverHost.withCString { hostPtr in
            sessionKey.withCString { keyPtr in
                var config = ProxyConfig(
                    server_host: hostPtr,
                    server_port: serverPort,
                    local_port: localPort,
                    session_key: keyPtr,
                    auto_proxy: autoProxy ? 1 : 0,
                    reverse_geo: reverseGeo ? 1 : 0
                )
                return proxy_start(handle, &config) == PROXY_OK
            }
        }
    }

    func stop() -> Bool {
        guard let handle = handle else { return false }
        return proxy_stop(handle) == PROXY_OK
    }

    var isRunning: Bool {
        guard let handle = handle else { return false }
        return proxy_is_running(handle) != 0
    }
}
```

### Usage Example

```swift
let proxy = ProxyCore()

// Start proxy
let success = proxy.start(
    serverHost: "your-server.com",
    serverPort: 11112,
    localPort: 7890,
    sessionKey: "your-32-byte-secret-key-here!!!",
    autoProxy: false,
    reverseGeo: false
)

if success {
    print("Proxy started on 127.0.0.1:7890")
}

// Check status
if proxy.isRunning {
    print("Proxy is running")
}

// Stop proxy
proxy.stop()
```

---

## Configuration Options

### Auto Proxy (Geo-based Routing)

The `auto_proxy` and `reverse_geo` parameters control geo-based traffic routing:

| `auto_proxy` | `reverse_geo` | Behavior                                  |
| ------------ | ------------- | ----------------------------------------- |
| 0            | -             | All traffic via proxy                     |
| 1            | 0             | CN direct, others via proxy (Forward)     |
| 1            | 1             | CN via proxy, others direct (Reverse)     |

### When to Use Auto Proxy

Whether to enable Auto Proxy depends on your deployment scenario:

#### With Shadowrocket (iOS VPN)

When using Shadowrocket + ProxyEverything together:

- **Auto Proxy: OFF** (set `auto_proxy = 0`)
- Geo routing is handled by Shadowrocket's GEOIP rules
- If Auto Proxy is enabled, direct connections from ProxyEverything will be intercepted by Shadowrocket VPN, causing an infinite loop

#### Without Shadowrocket (Standalone)

When using ProxyEverything alone (Mac client, WiFi proxy, etc.):

- **Auto Proxy: ON** (set `auto_proxy = 1`)
- Set `reverse_geo` based on your use case:

| Mode            | `reverse_geo` | Use Case                                |
| --------------- | ------------- | --------------------------------------- |
| Forward Proxy   | 0             | In China, access foreign websites       |
| Reverse Proxy   | 1             | Abroad, access Chinese websites         |

### Session Key

The session key must be exactly 32 bytes. It's used for AES-256-GCM encryption between client and server.

---

## Project Structure

```text
ios/
├── ProxyEverything/           # Xcode project
│   └── ProxyEverything/
│       ├── ProxyEverythingApp.swift
│       ├── ContentView.swift
│       ├── ProxyCore.swift    # Swift FFI wrapper
│       └── ProxyEverything-Bridging-Header.h
├── include/
│   └── proxy_ffi.h            # C header (auto-generated)
└── docs/
    ├── ios-development-guide.md
    ├── ios-user-guide-en.md
    └── ios-user-guide-cn.md
```

---

## Build Script Reference

```bash
./scripts/build-ios.sh [device|simulator|all]
```

| Option      | Description                                       |
| ----------- | ------------------------------------------------- |
| `device`    | Build for physical iOS devices (aarch64-apple-ios)|
| `simulator` | Build for iOS Simulator (aarch64-apple-ios-sim)   |
| `all`       | Build both and create XCFramework                 |

The script automatically:

1. Checks and installs required Rust targets
2. Generates the C header file
3. Builds static libraries
4. Creates XCFramework (when using `all`)

---

## Troubleshooting

### Build Errors

**"target aarch64-apple-ios not installed"**

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
```

**Linker errors in Xcode**

- Ensure `libhttp_proxy.a` is added to "Link Binary With Libraries"
- Add `Security.framework` and `libresolv.tbd`

### Runtime Errors

**Proxy fails to start**

- Check if port 7890 is already in use
- Verify server host is reachable
- Check Xcode console for detailed error logs

**Connection timeout**

- Verify server is running and accessible
- Check firewall/security group settings on server
- Ensure correct port is configured

### Debugging

Enable verbose logging by checking Xcode console output. The Rust library logs to stdout with `tracing` crate.

---

## Network Extension (Advanced)

For system-wide VPN functionality, implement a Packet Tunnel Provider using the tunnel API:

```swift
// In your PacketTunnelProvider
override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
    var config = ProxyConfig(...)
    let result = proxy_start_tunnel(&config)
    if result == 0 {
        completionHandler(nil)
    } else {
        completionHandler(NSError(domain: "ProxyTunnel", code: Int(result)))
    }
}

override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
    proxy_stop_tunnel()
    completionHandler()
}
```

> **Note**: Network Extension requires Apple Developer Program membership and specific entitlements.
