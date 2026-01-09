# iOS Proxy User Guide

## Overview

This solution combines Shadowrocket with ProxyEverything to achieve global proxy (WiFi + Cellular) and geo-based routing.

Two modes are available based on your use case:

| Mode | Use Case | Routing Rule |
| ---- | -------- | ------------ |
| Forward Proxy | Access foreign websites from China | China IPs direct, foreign IPs via proxy |
| Reverse Proxy | Access Chinese websites from abroad | Foreign IPs direct, China IPs via proxy |

## Prerequisites

- Shadowrocket installed on iPhone
- ProxyEverything installed on iPhone
- Remote proxy server deployed (e.g., ackingliu.top:11112)

---

## Forward Proxy Mode

Use case: Access Google, YouTube, GitHub, etc. from China.

### How It Works (Forward)

```text
                        Shadowrocket Rule Matching
                               │
              ┌────────────────┴────────────────┐
              ↓                                 ↓
         China IP                          Foreign IP
              ↓                                 ↓
           Direct                         LocalProxy
                                              ↓
                                    ProxyEverything (127.0.0.1:7890)
                                              ↓
                                    Remote Server (abroad)
                                              ↓
                                         Destination
```

Traffic flow:

- Access Baidu, Taobao (Chinese sites) → Direct connection (no proxy)
- Access Google, YouTube (foreign sites) → Via remote proxy server

### ProxyEverything Configuration (Forward)

1. Open ProxyEverything app
2. Configure server settings:
   - Server: `ackingliu.top`
   - Port: `11112`
   - Local Port: `7890`
3. Auto Proxy: **OFF** (geo routing handled by Shadowrocket)
4. Tap Start Proxy, ensure status turns green

### Shadowrocket Configuration (Forward)

```conf
[General]
bypass-system = true
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local
bypass-tun = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32
dns-server = system

[Proxy]
LocalProxy = http, 127.0.0.1, 7890

[Rule]
DOMAIN-SUFFIX,ackingliu.top,DIRECT
GEOIP,CN,DIRECT
FINAL,LocalProxy
```

Rule explanation:

| Rule | Target | Description |
| ---- | ------ | ----------- |
| `DOMAIN-SUFFIX,ackingliu.top,DIRECT` | Direct | Prevent loop |
| `GEOIP,CN,DIRECT` | Direct | China IPs direct |
| `FINAL,LocalProxy` | Proxy | All other traffic via proxy |

---

## Reverse Proxy Mode

Use case: Access bilibili, Taobao, NetEase Music, etc. from abroad.

### How It Works (Reverse)

```text
                        Shadowrocket Rule Matching
                               │
              ┌────────────────┴────────────────┐
              ↓                                 ↓
        Foreign IP                          China IP
              ↓                                 ↓
           Direct                         LocalProxy
                                              ↓
                                    ProxyEverything (127.0.0.1:7890)
                                              ↓
                                    Remote Server (in China)
                                              ↓
                                         Destination
```

Traffic flow:

- Access Google, YouTube (foreign sites) → Direct connection (no proxy)
- Access bilibili, Taobao (Chinese sites) → Via remote proxy server

### ProxyEverything Configuration (Reverse)

1. Open ProxyEverything app
2. Configure server settings:
   - Server: `ackingliu.top`
   - Port: `11112`
   - Local Port: `7890`
3. Auto Proxy: **OFF** (geo routing handled by Shadowrocket)
4. Tap Start Proxy, ensure status turns green

### Shadowrocket Configuration (Reverse)

```conf
[General]
bypass-system = true
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local
bypass-tun = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32
dns-server = system

[Proxy]
LocalProxy = http, 127.0.0.1, 7890

[Rule]
DOMAIN-SUFFIX,ackingliu.top,DIRECT
GEOIP,CN,LocalProxy
FINAL,DIRECT
```

Rule explanation:

| Rule | Target | Description |
| ---- | ------ | ----------- |
| `DOMAIN-SUFFIX,ackingliu.top,DIRECT` | Direct | Prevent loop |
| `GEOIP,CN,LocalProxy` | Proxy | China IPs via proxy |
| `FINAL,DIRECT` | Direct | All other traffic direct |

---

## Common Setup Steps

### Import Shadowrocket Configuration

1. Save configuration as `.conf` file
2. Transfer to iPhone via AirDrop or iCloud
3. Open file on iPhone, select "Open with Shadowrocket"

### Enable Shadowrocket

1. Open Shadowrocket
2. Set Global Routing to "Config"
3. Verify LocalProxy node shows latency (e.g., 1ms)
4. Toggle connection switch ON

---

## Why Must Auto Proxy Be Disabled?

When using Shadowrocket + ProxyEverything together, geo routing must be handled at the Shadowrocket level:

1. Shadowrocket as VPN intercepts all traffic
2. If ProxyEverything's Auto Proxy decides a request should go "direct"
3. This "direct" request gets intercepted by Shadowrocket VPN again
4. Creates an infinite loop

Shadowrocket operates at the VPN level and can truly implement "direct" connections (bypassing local proxy).

---

## Troubleshooting

### LocalProxy shows "Timeout"

- Verify ProxyEverything is running (green status)
- Confirm local port is 7890

### Cannot access internet

1. Confirm ProxyEverything status is green
2. Verify Shadowrocket Global Routing is set to "Config"
3. Check Xcode console logs for traffic flow

### Loop issue

Ensure `DOMAIN-SUFFIX,ackingliu.top,DIRECT` rule exists and has higher priority than GEOIP rules.

---

## Notes

- Start ProxyEverything BEFORE connecting Shadowrocket
- This solution only supports TCP traffic; UDP (games, video calls) is not proxied
- For UDP support, ProxyEverything needs SOCKS5 protocol implementation
