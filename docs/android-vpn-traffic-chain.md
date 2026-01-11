# Android VPN 全局代理链路深度解析（以一次网页请求为例）

本文解释：当你在 Android 手机上打开浏览器访问一个网页时，流量如何从 **Android 内核** 进入 **VPN TUN**，再进入 **Flutter → Rust FFI → Rust TUN 核心**，最终通过 **远端 http-proxy-server** 访问目标站点，并把响应原路返回到浏览器。

> **范围**：只讲当前仓库实现的“端到端链路”和关键机制，重点覆盖 **TCP 转发必须走 `start_proxy`/codec 链路**、**socket protect 防回环**、**TUN 包↔TCP 流 的转换**。  
> **代码版本**：基于当前工作区（未提交），行号以本文写作时为准。

---

## 1. 先给结论：一张总览图

```text
Browser (Chrome)
  │   (TCP/UDP sockets)
  ▼
Android kernel TCP/IP stack
  │   (all routes -> VPN)
  ▼
VpnService TUN (fd)
  │   (read/write IP packets)
  ▼
Rust TunHandler (smoltcp per-flow TCP stack)
  │   (packet <-> stream bridge via tokio::io::duplex)
  ▼
start_proxy() + AsyncEncrypt/DecryptCodec
  │   (framing + optional data encryption)
  ▼
TCP to http-proxy-server (protected socket, bypass VPN)
  │
  ▼
Remote http-proxy-server -> connect(dest) -> start_proxy() -> dest
```

这张图里的“两个关键拐点”：

1) **从“包”到“流”**：TUN 里是 IP packet，但代理协议是 TCP stream，所以需要用户态 TCP 栈（这里用 smoltcp）把包终止成可读写的字节流。见 `src/tun.rs:74`、`src/tun.rs:224`。

2) **从“流”到“加密代理链路”**：客户端到服务端并不是简单 `copy()`；如果 `ProxyHeader.key` 存在，服务端会走加密 codec（长度前缀 + tag + 解密/加密）。因此 **VPN TCP 转发必须走 `start_proxy()` 链路**，否则服务端无法解码。见 `src/lib.rs:199`、`src/server/mod.rs:694`、`src/tun.rs:434`。

---

## 2. 关键术语：不要混淆这几把“钥匙”和“层”

### 2.1 TUN / FD / protect

- **TUN**：一个虚拟网卡设备文件；读到的是“发出去的 IP 包”，写进去的是“回来的 IP 包”。
- **FD**：Android `VpnService.Builder.establish()` 得到的 `ParcelFileDescriptor`，通过 `detachFd()` 交给 Rust。见 `ui/flutter/android/.../ProxyVpnService.kt:82`。
- **protect(fd)**：告诉 Android“这个 socket 不要走 VPN”，否则会出现“代理 socket 也被 VPN 捕获 → 再进入 TUN → 自己抓自己”的路由循环。见 `ui/flutter/android/.../ProxyVpnService.kt:48`、`src/ffi.rs:506`。

### 2.2 两层“加密/校验”

当前协议中有两层相关机制（它们服务于不同目的）：

1) **协议 framing 的 checksum/length**：`set_data_size()` 写入「checksum + length」。checksum 的计算依赖运行时 `SECRET_KEY` 的 hash。见 `src/protocol/mod.rs:154`（本文不展开细节）。  
2) **数据面加密 codec（可选）**：当 `ProxyHeader.key` 存在时，数据流走 `AsyncEncryptCodec/AsyncDecryptCodec`（长度前缀 + ciphertext + tag）。见 `src/lib.rs:237`、`src/codec/mod.rs:359`。

> **Key Point**：`ProxyHeader.key` 是否存在，直接决定服务端走“普通转发”还是“加密 codec 转发”。服务端逻辑在 `src/server/mod.rs:694`。

---

## 3. 从“点一下 Start VPN”开始：控制链路怎么把 FD 交给 Rust

### 3.1 Android 端：建立 VPN、拿到 TUN FD、通知 Flutter

核心流程在 `ProxyVpnService.onStartCommand()`：

- `Builder().addAddress().addRoute().addDnsServer().setMtu()` 配置 VPN  
- `tunInterface = builder.establish()` 建立 TUN  
- `tunFd = tunInterface?.detachFd()` 得到“可跨层传递”的 raw fd  
- `notifyFlutter("vpn_started", {"fd": tunFd})` 通知 Flutter 侧拿 fd 继续做事  

对应代码：`ui/flutter/android/app/src/main/kotlin/com/proxyui/proxy_ui/ProxyVpnService.kt:65`

### 3.2 Flutter 端：收到 vpn_started 事件后，通过 FFI 启动 Rust VPN 核心

`ProxyState` 在初始化时注册 MethodChannel handler，收到 `vpn_started` 后调用 `_handleVpnStarted(tunFd)`：`ui/flutter/lib/src/providers/proxy_provider.dart:76`、`ui/flutter/lib/src/providers/proxy_provider.dart:326`。

`_handleVpnStarted()` 做了两件事：

1) 调用 `_ffi.proxyInitConfig(config)` 初始化 Rust 运行时配置（server host/port/SECRET_KEY 等）  
2) 调用 `_ffi.proxyStartVpn(handle, tunFd, nullptr)` 启动 Rust 侧的 TUN handler  

对应代码：`ui/flutter/lib/src/ffi/proxy_service.dart:160`、`src/ffi.rs:188`、`src/ffi.rs:577`。

---

## 4. 以一次“打开网页”为例：数据平面完整链路（DNS + TCP + HTTPS）

假设你在浏览器里访问：

- URL：`https://example.com/`
- 远端代理服务器：`SERVER_HOST:SERVER_PORT`（由 UI 配置）

### 4.1 DNS（UDP）阶段：先把域名解析成 IP

浏览器/系统 resolver 会先发 UDP DNS 查询（通常到 `8.8.8.8:53`，因为 VPN Builder 配了 DNS）。这会变成一条 UDP 包流入 TUN。

Rust 侧处理点：

- `TunHandler.start()` 解析 IPv4 包，根据 `next_header` 分发。UDP 分支见 `src/tun.rs:172`。
- 当前实现是“单报文 best-effort”：创建 `UdpSocket`，`protect` 后 `connect`，发送 payload，等待一次响应，然后把响应封装成“从 DNS server 回来的 UDP 包”写回 TUN。见 `src/tun.rs:595`。

> **Gotcha**：这是为了让“基本上网”先跑通（尤其 DNS），并非完整 UDP/QUIC 代理实现（例如 HTTP/3 需要更完整的 UDP 处理）。

### 4.2 TCP 建连阶段：TUN 里看到的是 SYN 包，而不是“可读写的 stream”

当 DNS 得到 `example.com -> 93.184.216.34` 后，浏览器会发起 TCP 连接到 `93.184.216.34:443`。

这时进入 TUN 的是 TCP 包（SYN/SYN-ACK/ACK/PSH...），要把它代理出去，需要先把它变成“应用层可读写的字节流”：

- `TunHandler.start()` 在 TCP 分支里按 4 元组 `(src_ip,src_port,dst_ip,dst_port)` 建连接表，并为新流 `spawn handle_tcp_connection(dst_ip,dst_port,...)`。见 `src/tun.rs:113`、`src/tun.rs:154`。

### 4.3 TCP 转发的关键：必须走 `start_proxy()`/codec 链路（否则服务端无法解码）

这里是本文最关键的点：`handle_tcp_connection()` 不是简单把“从 TUN 收到的 payload”直接 `write_all` 到服务端。

原因：服务端会根据 `ProxyHeader.key` 决定是否启用加密 codec（见 `src/server/mod.rs:694`）。一旦启用，服务端期望收到的是：

```text
[checksum u32][len u32][ciphertext ...][tag 16B]
```

这些 framing 与加解密逻辑由 `start_proxy()` 驱动：

- `start_proxy()`：并发跑 `codec::copy()` 两个方向（client->server、server->client）。见 `src/lib.rs:199`。
- `client_proxy_with_cryptor_codec()`：client->server 用 `AsyncEncryptCodec`，server->client 用 `AsyncDecryptCodec`。见 `src/lib.rs:237`。

因此在 VPN TCP 转发里，正确做法是：

1) **先与远端代理服务器建立 TCP（并 protect 防回环）**  
2) **发送 ProxyHeader**（告诉服务端目标 `dst_ip:dst_port` + 数据面 key）  
3) **把“来自 TUN 的明文 stream”接到 `client_proxy_with_cryptor_codec()` 上**  

对应实现就在 `src/tun.rs:224`：

- 连接 proxy server（关键：在 connect 之前 protect）：`src/tun.rs:249`  
- 发送 ProxyHeader：`src/tun.rs:282`  
- 启动加密代理 pipeline：`src/tun.rs:440`（内部调用 `crate::client_proxy_with_cryptor_codec` → `start_proxy`）

### 4.4 “包↔流”的桥：smoltcp + tokio::io::duplex

`handle_tcp_connection()` 同时做两件事：

1) **smoltcp 负责 TCP 状态机**：在用户态“扮演目标服务器”，和浏览器完成三次握手、维护 seq/ack、收发 payload。  
   - 为每个连接创建 `Interface + TcpSocket.listen(dst_port)`（本实现按“每条流一套 smoltcp 栈”简化）。见 `src/tun.rs:420`、`src/tun.rs:433`。
2) **tokio::io::duplex 负责把 smoltcp 的 payload 接到 start_proxy 上**：  
   - `duplex(64*1024)` 创建一对内存流 `(proxy_end, tun_end)`：`src/tun.rs:247`  
   - `proxy_end` 交给 `client_proxy_with_cryptor_codec()` 当“客户端侧 stream”  
   - `tun_end` 留在 smoltcp 循环里：把 `TcpSocket.recv_slice()` 的明文写入 `tun_end`，把从 `tun_end` 读到的响应写入 `TcpSocket.send_slice()`  
   - 这就完成了从 packet world 到 start_proxy codec world 的桥接。见 `src/tun.rs:475`、`src/tun.rs:543`。

### 4.5 HTTPS/TLS 与 HTTP：在代理层看来只是“字节流”

当 TCP 连接建立后，浏览器会发 TLS ClientHello、完成握手，然后发送 HTTP/2 或 HTTP/1.1 请求。

在我们的链路里：

- Rust VPN 核心不做 MITM，不解 TLS，只做字节转发  
- 这些字节经过 `AsyncEncryptCodec` 加密发送到远端服务端  
- 服务端解密后把明文转发到真正的 `example.com:443`（见 `src/server/mod.rs:687`）  
- 真实站点的 TLS 响应回到服务端后再被加密回传，最终由 smoltcp 写回 TUN，浏览器正常解 TLS

---

## 5. 防回环机制：为什么一定要 protect？怎么做到“同步回调”？

### 5.0 为什么 Rust 里要用 JNI？

在 VPN 模式下，Rust 侧会创建 socket 去连接 **远端代理服务器**（`connect(proxy_server)`），但这个 socket **必须不走 VPN**，否则会被系统再次送回 TUN，形成“自己代理自己”的回环。

Android 提供的唯一标准解法是 `VpnService.protect(fd)`（Java/Kotlin API），它要求你拿到 **socket 的 fd** 并同步调用，告诉系统“这条连接走物理网卡，不走 VPN”。因此 Rust 想在数据面里正确 `protect + connect`，就需要通过 **JNI** 直接调用到 Android 的 `VpnService.protect()`。

> ⚠️ **Gotcha：为什么不用 Flutter MethodChannel？**
> - Rust 侧 `protect(fd) -> bool` 需要 **同步返回值**，而 MethodChannel 是异步的。
> - `protect()` 通常发生在 **非 UI 线程**、并且必须在 `connect()` 前立刻完成，否则仍可能回环。
> - 所以这里用 JNI 做“同步桥接”，而不是让 Rust 去等 Flutter 的异步回调。

### 5.1 问题：如果不 protect，会发生什么？

如果 Rust 在 VPN 模式下创建了一个 TCP socket 去连接代理服务器，而这个 socket **也走 VPN**：

```text
Rust -> connect(proxy_server)
  └─(route through VPN)→ 这条 connect 的包又被送进 TUN
       └→ TunHandler 又尝试代理它 → 无限递归/死循环/连不上
```

因此必须对“代理核心创建的 socket”调用 `VpnService.protect(fd)`，强制它走物理网络接口。

### 5.2 难点：Rust 侧需要“同步的 protect(fd)->bool”，而 MethodChannel 是异步

解决方案：Rust 直接通过 JNI 回调到 Android 静态方法（同步返回 bool）：

- Kotlin 声明 `external fun nativeRegisterProtectCallback()` 并在 `init { loadLibrary; nativeRegisterProtectCallback() }` 调用注册：`ui/flutter/android/.../ProxyVpnService.kt:32`  
- Rust 导出 JNI 函数 `Java_com_proxyui_proxy_1ui_ProxyVpnService_nativeRegisterProtectCallback`，保存 `JavaVM` 并 `proxy_register_protect_callback(Some(android_protect_socket))`：`src/ffi.rs:486`  
- Rust 侧的 `android_protect_socket(fd)` 调 JNI `ProxyVpnService.protectSocketFromJNI(fd)`：`src/ffi.rs:506`  
- Kotlin 侧 `protectSocketFromJNI(fd)` 最终调用 `instance?.protect(fd)`：`ui/flutter/android/.../ProxyVpnService.kt:52`

> **Key Point**：这条链路是“同步调用”，适合在 connect 之前执行（见 `src/tun.rs:249`），而不是通过异步 MethodChannel。

---

## 6. 你真正需要关注的“执行链路清单”（从浏览器到远端）

以一次 `https://example.com/` 为例，按时间顺序：

1) 用户点击 Start VPN  
2) Android `ProxyVpnService` 建立 TUN，`detachFd()`，发 `vpn_started(fd)`：`ui/flutter/android/.../ProxyVpnService.kt:65`  
3) Flutter 收到事件，调用 `ProxyService.startVpn()`：`ui/flutter/lib/src/providers/proxy_provider.dart:326`  
4) Flutter FFI 调 `proxy_init_config()` 设置 server host/port/SECRET_KEY 等：`src/ffi.rs:188`  
5) Flutter FFI 调 `proxy_start_vpn(handle, tun_fd, NULL)`：`src/ffi.rs:577`  
6) Rust `TunHandler.start()` 读 TUN 包并分流：`src/tun.rs:74`  
7) DNS UDP：`handle_udp_datagram()` 直接发到 DNS，构造响应包写回 TUN：`src/tun.rs:595`  
8) TCP SYN：`handle_tcp_connection(dst_ip,dst_port,...)`：`src/tun.rs:224`  
9) `handle_tcp_connection()`：
   - protect + connect proxy server：`src/tun.rs:249`
   - 发送 ProxyHeader（包含目的 `dst_ip:dst_port` + 数据面 key）：`src/tun.rs:282`
   - `tokio::io::duplex` 建桥：`src/tun.rs:247`
   - 启动 `client_proxy_with_cryptor_codec()`（内部走 `start_proxy()`）：`src/tun.rs:440`、`src/lib.rs:199`
   - smoltcp 与浏览器完成 TCP 并在循环里桥接 payload：`src/tun.rs:475`、`src/tun.rs:543`
10) 远端 `http-proxy-server`：
   - 读 framing length + header_buf：`src/server/mod.rs:590`
   - 解密 ProxyHeader：`src/server/mod.rs:639`
   - connect(dest)：`src/server/mod.rs:687`
   - 若 header.key 存在 → `proxy_with_metrics_cryptor` → server 侧 `start_proxy()`：`src/server/mod.rs:694`

---

## 7. 现状限制与下一步（务必知道）

- **IPv4 only**：`src/tun.rs:328`（IPv6 会直接 bail）  
- **UDP 仅单报文 best-effort**：能覆盖 DNS，但不等于完整 UDP/QUIC 代理：`src/tun.rs:595`  
- **每条 TCP 流一套 smoltcp Interface/SocketSet**：实现简单但不是最高性能形态（后续可改为全局 Interface + 多 socket）  

---

## 8. Code Index（按链路定位）

### Android (Kotlin)
- `ui/flutter/android/app/src/main/kotlin/com/proxyui/proxy_ui/ProxyVpnService.kt:65`：建立 VPN、`detachFd()`、发 `vpn_started`
- `ui/flutter/android/app/src/main/kotlin/com/proxyui/proxy_ui/ProxyVpnService.kt:32`：JNI 注册 protect 回调
- `ui/flutter/android/app/src/main/kotlin/com/proxyui/proxy_ui/VpnPlugin.kt:28`：MethodChannel start/stop/prepare

### Flutter (Dart)
- `ui/flutter/lib/src/providers/proxy_provider.dart:76`：监听 `vpn_started` 等事件
- `ui/flutter/lib/src/providers/proxy_provider.dart:326`：收到 fd 后启动 Rust VPN 核心
- `ui/flutter/lib/src/ffi/proxy_service.dart:160`：FFI 调 `proxy_init_config` + `proxy_start_vpn`

### Rust (FFI/JNI)
- `src/ffi.rs:188`：`proxy_init_config`
- `src/ffi.rs:486`：JNI `nativeRegisterProtectCallback` → 注册 protect callback
- `src/ffi.rs:577`：`proxy_start_vpn` 启动 `TunHandler`

### Rust (VPN 数据面)
- `src/tun.rs:74`：`TunHandler.start()` 主循环（TUN read/write + 分流）
- `src/tun.rs:224`：`handle_tcp_connection()`（TCP 包→流→start_proxy→proxy server）
- `src/tun.rs:595`：`handle_udp_datagram()`（DNS 等 UDP best-effort）

### Rust (核心转发)
- `src/lib.rs:199`：`start_proxy()`（双向 copy 的“核心链路”）
- `src/codec/mod.rs:359`：`AsyncEncryptCodec`/`AsyncDecryptCodec` 的 framing + 加解密
- `src/server/mod.rs:578`：服务端收包、解 header、选择 cryptor/normal
