# 在自己的 iPhone / iPad 上使用 CipherRelay

iOS 版本通过 `NEPacketTunnelProvider` 接管 IP 流量。Flutter 主应用负责节点、
配置和连接按钮，独立扩展负责 Rust 转发；主应用进入后台时不需要保持 Flutter
运行。主应用和扩展使用同一个签名团队，通过共享 Keychain 引用传递配置。

个人付费 Apple Developer Program 账号可以使用开发签名安装，不需要上架
App Store。登录同一个 Apple ID 本身不等于设备已经登记或配对。

## 本地构建

需要 macOS、完整 Xcode、CocoaPods、仓库固定的 Rust 工具链和 FVM。
设备最低系统版本为 iOS / iPadOS 15。
首次准备 Flutter SDK 时，在 `ui/flutter` 执行 `fvm install`。

从仓库根目录运行：

```bash
# 编译 Apple Silicon / Intel Mac 对应的模拟器版本。
python3 scripts/ios/build.py --simulator

# 安装到一个已经启动的模拟器。先通过 simctl 查询其 UUID。
xcrun simctl list devices booted
python3 scripts/ios/build.py --simulator --install SIMULATOR_UUID

# 编译真机版本，但不签名；用于检查 iOS SDK 和扩展链接。
python3 scripts/ios/build.py --unsigned

# 真机开发签名。TEAM_ID 是开发者团队 ID，不是 Apple ID 邮箱。
python3 scripts/ios/build.py --team TEAM_ID

# 安装并启动到已经配对、解锁的真机。
xcrun xctrace list devices
python3 scripts/ios/build.py --team TEAM_ID --install DEVICE_UDID
```

脚本会先编译带 `network-extension` feature 的 Rust 静态库，再执行 FVM、
CocoaPods 和 Xcode 构建。真机和模拟器的 arm64 库分别存放在
`ui/flutter/native/ios/iphoneos` 与 `iphonesimulator`，避免混用平台产物。
Rust 均使用 release 构建；模拟器的 Flutter 使用 Debug，真机默认 Release。

输出分别位于 `ui/flutter/build/ios-vpn-simulator` 和
`ui/flutter/build/ios-vpn-device`。其中 `verification.json` 记录版本、架构、
主可执行文件 SHA-256，以及是否验证了真机签名。未签名构建无法安装到真机。
这些目录和原生库目录都不应提交。

## 真机签名与授权

1. 在 Xcode 的 Settings → Accounts 登录付费开发者账号。
2. 用数据线连接设备，解锁并信任 Mac；按系统要求开启 Developer Mode。
3. 主应用 `com.proxyui.proxyUi` 和扩展 `com.proxyui.proxyUi.PacketTunnel`
   必须属于同一团队。两者均需要 Network Extensions 的 Packet Tunnel 权限，
   以及签名前缀下的 `com.proxyui.proxyUi.vpn` Keychain 共享组。
4. 通过上述带 `--team` 的命令构建，允许 Xcode 自动更新 provisioning profiles。
   如果账号无权创建这些 Bundle ID，需要先解决账号归属；不要单独修改扩展 ID。
5. 首次打开应用后配置服务器并连接，在 iOS 系统弹窗中允许添加 VPN 配置。

支持已有 Xcode 登录，也支持通过环境变量提供 `APPLE_API_KEY_PATH`、
`APPLE_API_KEY_ID`、`APPLE_API_ISSUER_ID`。私钥应保存在仓库外；脚本不会上传
构建到 App Store Connect。开发描述文件过期前需要重新构建并覆盖安装。

## 功能与验证边界

- iOS 的连接按钮同时启停 VPN 和扩展内的本地代理；没有桌面管理员 helper、
  进程绕过列表、独立 TUN 开关或局域网配置分享服务。
- iOS 的自动分流仅对 TCP 使用随应用发布的中国 IPv4/IPv6 地址库：
  中国大陆地址直连，其余地址经节点转发；反向模式交换这两种选择，局域网保持直连。
  这是目的 IP 的属地规则，并非网站品牌或域名后缀规则；国内 CDN 上的国外网站也可能直连。
  域名通过阿里公共 DNS 的 HTTPS 接口解析，TLS 校验保持开启，并固定解析器引导地址，
  避免查询被 Fake-IP DNS 捕获。直连仅使用已判定的地址；代理仍传域名给节点解析。
  DNS 结果按 TTL 缓存，最多 1024 条；查询失败短暂走代理并重试，不写永久分流缓存。
  关闭自动分流时 TCP 均经节点转发。
  UDP 使用固定规则，不受 TCP Auto 或反向属地开关影响：大陆和本地网络目标始终直连；
  境外目标默认返回 ICMP/ICMPv6 端口不可达，避免浏览器的 HTTP/3 探测静默超时。
  主动开启“UDP 代理”后才经节点转发境外 UDP。DNS 门户始终按 Fake-IP 或 DNS-over-TCP 配置处理。
  开启前必须获得服务端 UDP 关联就绪确认；不支持、拒绝或超时会阻止 VPN 启动并明确报错。
  域名先通过会话内 DoH 缓存解析，再按真实目标 IP 判断；解析失败时不开直连，
  UDP 代理开启则交给节点解析，否则拒绝。旧配置的 `udpDirectFallback` 不再覆盖此固定规则。
  macOS 商店版仍禁用 TCP Auto。
  iOS 新配置默认启用 Fake-IP DNS，将域名保留到节点解析，避免手机优先连接
  节点不支持的 IPv6 地址而出现 TLS 错误或长时间超时。已有配置可开启
  “TUN Fake-IP DNS”并重新连接；显式关闭该选项仍会使用配置的真实 DNS 服务器。
  普通个人设备无法提供按 App 绕过列表；[Apple 的 Per-App VPN 需要 MDM 管理](https://developer.apple.com/documentation/networkextension/netunnelprovidermanager)。
  当前该入口不支持 V3 开关，启用时会报错，
  不会静默降级；默认使用已有加密传输。
- 模拟器可验证启动、FFI、配置和界面。点击连接会明确报告需要真机，
  不会伪造 VPN 连接成功。
- Rust 的 `packet_tunnel` 集成测试在 loopback 上验证真实 IP 数据包、
  DNS、TCP、UDP、服务器转发和关闭，但不能代替 iOS 系统隧道验证。
- 真机验收应覆盖：首次授权、访问服务器、DNS、TCP/UDP、前后台切换、
  锁屏、Wi-Fi/蜂窝切换、节点切换及断开后恢复联网。实现和构建成功不代表
  这些系统行为已经通过验收。

```bash
cargo test -p proxy-client --features network-extension --test packet_tunnel
cargo test -p proxy-ffi --features network-extension --lib
cd ui/flutter
fvm flutter analyze --no-fatal-infos
fvm flutter test
```

iOS 与 macOS 共用 `ui/flutter/darwin` 下的 Swift 控制器、配置存储和
Packet Tunnel provider，Dart 侧共用 `ApplePacketTunnelProxyService`。

扩展的长期读包循环会逐包释放 Cocoa 临时对象，iOS 同时将活动转发会话限制为
128、TCP 接收窗口缓冲限制为 16 KiB，以适应扩展的 50 MB 内存上限。
扩展私有容器中的 `Library/Application Support/ProxyUI/packet-tunnel-status.json`
每 5 秒覆盖一次，记录进程 ID、运行时间、进出包数、字节数、拥塞丢包数和内存占用，
自动分流时还记录 `routing` 中的 `directTcp`、`proxyTcp` 和 `dnsFailures`。
这些计数为 TCP 路线决策次数，不代表成功请求数；需结合请求结果验收。不记录目的地址或报文内容。调试时可通过 `xcrun devicectl device copy from`
的 `appDataContainer` 域和扩展 Bundle ID 读取，核实后台转发是否仍在运行。

本地 SOCKS5 UDP 通道显式绑定 loopback 源地址。iOS NetworkExtension 中，
绑定通配地址的 UDP socket 可能连接成功，却在首次发送时返回
`EADDRNOTAVAIL`（错误 49）；仅检查 UDP 握手成功不能证明数据报已经转发。

中国地址库来源为 MIT 许可的 [china-operator-ip](https://github.com/gaoyifan/china-operator-ip)，
固定提交和源文件摘要见 `crates/proxy-core/data/china-ip/manifest.json`。
升级地址库时使用 `python3 scripts/geo/update-china-ip.py --revision FULL_COMMIT_SHA`，
重新执行 GeoIP 和分流测试后随下一版应用发布；运行时不下载规则。

连接期间的节点探测通过系统 provider 消息交给 VPN 扩展执行，使用扩展的系统豁免
socket，避免包含应用的探测流量先经过当前节点再连接候选节点。与其他平台一样，
每批最多同时执行 16 个异步探测，复用 Rust 的控制运行时，不为每个节点阻塞一个
GCD 线程。扩展同时接纳最多 32 个探测，为另一批或单次探测保留余量。
VPN 断开后该批次报错，不切换到包含应用内重试。未连接时继续直接探测。

iOS 对仅有一个 IP 的 TCP 目标，在握手仍未完成 250 ms 后最多启动一次备用连接，
沿用双栈连接最多两个候选的限制。最快成功的连接负责后续协议和业务数据，另一个
立即取消；立即成功或拒绝的连接不会重试。此策略覆盖原生节点探测和 TCP 转发，
减少首个 SYN 丢失造成的秒级等待。测速仍包含实际等待时间；它不缓存低延迟结果，
也不能消除连接建立后的线路丢包或节点限速。桌面和 Android 的连接策略保持原样。
