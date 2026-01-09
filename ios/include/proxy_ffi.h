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

// Opaque handle
typedef struct ProxyHandle ProxyHandle;

// Configuration
typedef struct {
    const char* server_host;
    uint16_t server_port;
    uint16_t local_port;
    const char* session_key;
    int auto_proxy;   // 0 = disabled (always proxy), 1 = enabled (geo-based)
    int reverse_geo;  // 0 = CN direct, 1 = CN proxy (reverse mode)
} ProxyConfig;

// API functions
ProxyHandle* proxy_create(void);
ProxyResult proxy_start(ProxyHandle* handle, const ProxyConfig* config);
ProxyResult proxy_stop(ProxyHandle* handle);
void proxy_destroy(ProxyHandle* handle);
int proxy_is_running(const ProxyHandle* handle);
void proxy_init_logging(void);

#ifdef __cplusplus
}
#endif

#endif // PROXY_FFI_H
