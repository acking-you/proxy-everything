//
//  ProxyCore.swift
//  ProxyEverything
//
//  Created by Jye10032 on 2026/1/9.
//

import Foundation

/// Swift wrapper for the Rust proxy FFI
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

    /// Start the proxy with the given configuration
    func start(serverHost: String, serverPort: UInt16, localPort: UInt16, sessionKey: String, autoProxy: Bool, reverseGeo: Bool) -> Bool {
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

    /// Stop the proxy
    func stop() -> Bool {
        guard let handle = handle else { return false }
        return proxy_stop(handle) == PROXY_OK
    }

    /// Check if proxy is running
    var isRunning: Bool {
        guard let handle = handle else { return false }
        return proxy_is_running(handle) != 0
    }
}
