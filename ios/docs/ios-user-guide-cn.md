# iOS 代理使用指南

## 概述

本方案通过 Shadowrocket + ProxyEverything 配合使用，实现全局代理（WiFi + 蜂窝数据）和 Geo 分流。

根据使用场景分为两种模式：

| 模式 | 适用场景 | 分流规则 |
| ---- | -------- | -------- |
| 正向代理 | 在中国访问国外网站 | 中国 IP 直连，国外 IP 走代理 |
| 反向代理 | 在国外访问中国网站 | 国外 IP 直连，中国 IP 走代理 |

## 前置条件

- iPhone 已安装 Shadowrocket
- iPhone 已安装 ProxyEverything
- 远程代理服务器已部署（如 ackingliu.top:11112）

---

## 正向代理模式

适用场景：在中国访问 Google、YouTube、GitHub 等国外网站。

### 连接原理

```
                        Shadowrocket 规则匹配
                               │
              ┌────────────────┴────────────────┐
              ↓                                 ↓
         中国 IP                            国外 IP
              ↓                                 ↓
           直连                          LocalProxy
                                              ↓
                                    ProxyEverything (127.0.0.1:7890)
                                              ↓
                                    远程服务器 (国外)
                                              ↓
                                         目标网站
```

流量路径说明：
- 访问百度、淘宝等中国网站 → 直连（不经过代理）
- 访问 Google、YouTube 等国外网站 → 通过远程服务器代理

### ProxyEverything 配置

1. 打开 ProxyEverything 应用
2. 配置服务器信息：
   - Server: `ackingliu.top`
   - Port: `11112`
   - Local Port: `7890`
3. Auto Proxy 设置：**关闭**（Geo 分流由 Shadowrocket 处理）
4. 点击 Start Proxy，确保状态变为绿色

### Shadowrocket 配置

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

规则说明：

| 规则 | 目标 | 说明 |
| ---- | ---- | ---- |
| `DOMAIN-SUFFIX,ackingliu.top,DIRECT` | 直连 | 避免回环 |
| `GEOIP,CN,DIRECT` | 直连 | 中国 IP 直连 |
| `FINAL,LocalProxy` | 代理 | 其他流量走代理 |

---

## 反向代理模式

适用场景：在国外访问 bilibili、淘宝、网易云音乐等中国网站。

### 连接原理

```
                        Shadowrocket 规则匹配
                               │
              ┌────────────────┴────────────────┐
              ↓                                 ↓
         国外 IP                            中国 IP
              ↓                                 ↓
           直连                          LocalProxy
                                              ↓
                                    ProxyEverything (127.0.0.1:7890)
                                              ↓
                                    远程服务器 (中国)
                                              ↓
                                         目标网站
```

流量路径说明：
- 访问 Google、YouTube 等国外网站 → 直连（不经过代理）
- 访问 bilibili、淘宝等中国网站 → 通过远程服务器代理

### ProxyEverything 配置

1. 打开 ProxyEverything 应用
2. 配置服务器信息：
   - Server: `ackingliu.top`
   - Port: `11112`
   - Local Port: `7890`
3. Auto Proxy 设置：**关闭**（Geo 分流由 Shadowrocket 处理）
4. 点击 Start Proxy，确保状态变为绿色

### Shadowrocket 配置

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

规则说明：

| 规则 | 目标 | 说明 |
| ---- | ---- | ---- |
| `DOMAIN-SUFFIX,ackingliu.top,DIRECT` | 直连 | 避免回环 |
| `GEOIP,CN,LocalProxy` | 代理 | 中国 IP 走代理 |
| `FINAL,DIRECT` | 直连 | 其他流量直连 |

---

## 通用配置步骤

### 导入 Shadowrocket 配置

1. 将配置文件保存为 `.conf` 文件
2. 通过 AirDrop 或 iCloud 传输到 iPhone
3. 在 iPhone 上打开文件，选择用 Shadowrocket 打开

### 启用 Shadowrocket

1. 打开 Shadowrocket
2. 确认全局路由设置为「配置」
3. 确认 LocalProxy 节点显示延迟（如 1ms）
4. 打开连接开关

---

## 为什么 Auto Proxy 要关闭？

当使用 Shadowrocket + ProxyEverything 组合时，Geo 分流必须在 Shadowrocket 层面处理，原因如下：

1. Shadowrocket 作为 VPN 截获所有流量
2. 如果 ProxyEverything 的 Auto Proxy 判断某个请求需要"直连"
3. 这个"直连"请求会被 Shadowrocket VPN 再次截获
4. 形成回环死循环

Shadowrocket 在 VPN 层面做分流，可以真正实现"直连"（绕过本地代理）。

---

## 常见问题

### LocalProxy 显示"超时"

- 检查 ProxyEverything 是否已启动（状态为绿色）
- 检查本地端口是否为 7890

### 无法上网

1. 确认 ProxyEverything 状态为绿色
2. 确认 Shadowrocket 全局路由为「配置」
3. 检查 Xcode 控制台日志，确认流量经过本地代理

### 回环问题

确保 `DOMAIN-SUFFIX,ackingliu.top,DIRECT` 规则存在且优先级高于 GEOIP 规则。

---

## 注意事项

- 必须先启动 ProxyEverything，再连接 Shadowrocket
- 本方案仅支持 TCP 流量，UDP 流量（游戏、视频通话）不走代理
- 如需 UDP 支持，需要 ProxyEverything 支持 SOCKS5 协议
