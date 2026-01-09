#ifndef PROXY_FFI_H
#define PROXY_FFI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Result codes
typedef enum {
    PROXY_OK = 0,
    PROXY_INVALID_PARAM = -1,
    PROXY_CONNECTION_FAILED = -2,
    PROXY_RUNTIME_ERROR = -3,
    PROXY_ALREADY_RUNNING = -4,
    PROXY_NOT_RUNNING = -5,
} ProxyResult;

// Opaque handle to the proxy client
typedef struct ProxyHandle ProxyHandle;

// Configuration for the proxy
typedef struct {
    const char* server_host;    // Remote proxy server hostname/IP
    uint16_t server_port;       // Remote proxy server port
    uint16_t local_port;        // Local listening port
    const char* session_key;    // Encryption session key
    int auto_proxy;             // 0 = disabled (always proxy), 1 = enabled (geo-based)
    int reverse_geo;            // 0 = CN direct, 1 = CN proxy (reverse mode)
} ProxyConfig;

// Create a new proxy handle
// Returns NULL on failure
ProxyHandle* proxy_create(void);

// Start the proxy with the given configuration
// Returns PROXY_OK on success
ProxyResult proxy_start(ProxyHandle* handle, const ProxyConfig* config);

// Stop the proxy
// Returns PROXY_OK on success
ProxyResult proxy_stop(ProxyHandle* handle);

// Destroy the proxy handle and free resources
// The handle must not be used after this call
void proxy_destroy(ProxyHandle* handle);

// Check if proxy is running
// Returns 1 if running, 0 otherwise
int proxy_is_running(const ProxyHandle* handle);

// Initialize logging (call once at app startup)
void proxy_init_logging(void);

// ============================================
// Network Extension (Tunnel) API
// These functions are for use in PacketTunnelProvider
// ============================================

// Alias for ProxyConfig used in tunnel context
typedef ProxyConfig ProxyFFIConfig;

// Start proxy tunnel (for Network Extension)
// Returns 0 on success, non-zero on failure
int proxy_start_tunnel(const ProxyFFIConfig* config);

// Stop proxy tunnel
void proxy_stop_tunnel(void);

// Check if tunnel proxy is running
// Returns 1 if running, 0 otherwise
int proxy_is_running_tunnel(void);

#ifdef __cplusplus
}
#endif

#endif // PROXY_FFI_H
