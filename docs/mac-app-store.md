# Mac App Store 版本开发

商店版使用 `appstore` scheme：Flutter 管理节点和界面，Swift 通过
`NETunnelProviderManager` 管理系统 VPN，Rust 内核在 Packet Tunnel 扩展中转发
TCP/UDP。适用于 macOS 13 及以上。

1.2.16（42）已于 2026 年 9 月 14 日完成商店签名、上传处理与正式提交，提交时状态为
“等待审核”。尚未通过 App Review。编译、回环测试及商店上传校验不代表完成系统级
VPN 验证；没有开发描述文件的 `--unsigned` 产物仍只能用于构建检查。

## 两个发行渠道与名称

产品统一使用 CipherRelay（密流）。直装版仍使用 `Runner` 目标和原有 Bundle ID
`com.proxyui.proxyUi`，输出 `CipherRelay.app`。原有系统代理、管理员 TUN helper、
LAN 访问、进程旁路及 Developer ID 签名/公证流程均保留。
商店版使用 `RunnerStore` 目标，输出 `CipherRelay Store.app`，使用独立 Bundle ID
`com.proxyui.proxyUi.store`。两者的数据容器独立，可以并存。
Dart 包名、FFI 库名、既有配置键和网络协议不随品牌名称修改。

## 构建

从包含子模块的主仓库根目录运行。Rust 使用 `rust-toolchain.toml`，Flutter 使用
`ui/flutter/.fvmrc`。需要 Xcode、命令行工具、CocoaPods 和 FVM。

```bash
git submodule update --init --recursive
python3 scripts/macos/build-app-store.py --architectures universal --unsigned
```

构建脚本编译带 `mac-app-store` feature 的静态库和动态库，分别提供给扩展和主程序。
它同时设置 Swift 编译条件与 Dart 的 `MAC_APP_STORE=true`，避免主程序与原生库能力不一致。
`native/macos-app-store/`、`target/macos-app-store/` 和 Flutter `build/` 是生成目录。

输出：`ui/flutter/build/macos-app-store/Build/Products/Release-appstore/CipherRelay Store.app`。
可用 `--architectures arm64` 缩短本机调试构建时间。

开发签名需要团队拥有以下两个 App ID，均启用 Network Extensions，并使用允许共享
Keychain 组的 Mac App Development 描述文件。调试机器需在团队设备列表中。

| 目标 | Bundle ID |
| --- | --- |
| RunnerStore | `com.proxyui.proxyUi.store` |
| PacketTunnel | `com.proxyui.proxyUi.store.PacketTunnel` |

两者的 Keychain 组是 `$(AppIdentifierPrefix)com.proxyui.proxyUi.store.shared`。
不要把 Developer ID 公证凭据当作开发描述文件；公证 API 密钥的角色也未必允许创建描述文件。
在 Xcode 登录有相应权限的开发者账号后：

```bash
python3 scripts/macos/build-app-store.py --team YOUR_TEAM_ID --architectures arm64
python3 scripts/macos/build-app-store.py --team YOUR_TEAM_ID --archive
```

第二条生成双架构 Release 的 `ui/flutter/build/macos-app-store/CipherRelay.xcarchive`。
归档使用开发签名；提交到商店还需要 Mac App Distribution 和 Mac Installer Distribution
证书（含本机私钥），以及分别绑定主程序和扩展的 Mac App Store 描述文件。
两份分发描述文件均需允许 Packet Tunnel 与共享 Keychain 组。安装后可导出：

```bash
python3 scripts/macos/export-app-store.py \
  --archive ui/flutter/build/macos-app-store/CipherRelay.xcarchive \
  --output ui/flutter/build/macos-app-store/export \
  --team YOUR_TEAM_ID
```

默认描述文件名分别为 `CipherRelay Mac App Store` 和
`CipherRelay Mac App Store Packet Tunnel`，也可通过参数指定。
只有显式添加 `--upload` 才会上传构建；上传需要 `APPLE_API_KEY_PATH`、
`APPLE_API_KEY_ID`、`APPLE_API_ISSUER_ID`，密钥文件必须保存在仓库之外。
输出目录必须为空，脚本不会覆盖已有导出。上传不等于提交审核或通过审核。
也可通过 Xcode Organizer 执行 Validate App 和分发。

## 实现边界

- 独立 Bundle ID、数据容器和输出目录；不会自动读取 DMG 版的设置。可通过现有配置导入功能迁移。
- 主开关统一控制 VPN。商店版隐藏管理员 TUN、进程旁路、macOS helper 排障和 LAN 代理开关。
  导入旧设置时也会关闭系统代理修改、LAN 代理和进程旁路；原生 FFI 拒绝管理员 TUN 和系统代理操作。
- 保留节点目录、目标地址/域名分流、加密代理协议及本地日志。商店版隐藏并拒绝启动 LAN 订阅分享服务。
  系统默认路由进入 VPN；局域网具体路由、多播以及系统保留流量遵循 Network Extension 的规则，未实现断网保护。
- `PacketTunnelProvider` 只使用公开 `NEPacketTunnelFlow` 数据包接口，不通过 KVC 获取私有文件描述符。
  Swift 串行化输入和生命周期，独立读线程处理输出，停止先取消，再等待读线程退出后释放 Rust 指针。
- Rust 桥接校验 IPv4/IPv6 长度及 1500 字节 MTU，双向适配队列各最多 256 个包。
  输入拥塞时丢包，输出使用背压；这不代表第三方 IP 栈的所有内部队列都有相同上限。
- `tun2proxy::run_with_system_managed_network` 不创建 TUN、修改路由、探测出口或枚举进程。
  扩展内的出站连接依赖系统提供的隧道排除规则，需通过实际 VPN 测试验证网络切换与回环行为。
- 完整连接配置存入共享 Data Protection Keychain；VPN 偏好只存持久引用。
  Rust 缓存位于扩展自己的 Application Support 目录。主程序与扩展不共享磁盘容器。
- 系统断开连接会更新界面。切换节点先停止旧 VPN、探测新节点，再启动新 VPN；失败会尝试恢复旧节点。
- 扩展日志进入 macOS unified logging，子系统为 `com.proxyui.proxyUi.store.PacketTunnel`，
  端点信息按 private 记录；主程序日志页面目前只显示主程序日志。扩展日志尚未回传该页面。
- UDP 适配直接使用 connected socket 的 send/recv，修复 macOS 对 connected socket 使用 send_to 时的 EISCONN 错误。

## 验证

```bash
cargo test --workspace --features proxy-ffi/mac-app-store
cargo clippy -p proxy-core -p proxy-client -p proxy-server -p proxy-tui -p proxy-ffi --all-targets --all-features --no-deps -- -D warnings
cargo fmt -p proxy-core -p proxy-client -p proxy-server -p proxy-tui -p proxy-ffi -- --check
cargo test --manifest-path deps/tun2proxy/Cargo.toml
cargo clippy --manifest-path deps/tun2proxy/Cargo.toml --all-targets --all-features -- -D warnings
cargo fmt --manifest-path deps/tun2proxy/Cargo.toml -- --check
cd ui/flutter
fvm flutter analyze --no-fatal-infos
fvm flutter test
fvm flutter test test/macos_vpn_service_test.dart --dart-define=MAC_APP_STORE=true
```

`crates/proxy-client/tests/packet_tunnel.rs` 在回环端口启动真正的代理服务器与 echo 服务，
验证 DNS、IPv4 TCP/UDP、IPv6 UDP 在加密和非加密模式下经过整个数据包适配链，
并验证取消能唤醒阻塞读取、释放监听端口。它不会修改主机路由、系统代理或 DNS。

打包验证器检查版本、架构、原生 feature 标记和 helper 缺失；签名模式进一步检查签名、
沙盒和 Network Extension entitlement、描述文件有效期及共享 Keychain 组。
`--unsigned` 跳过签名相关检查，不能作为可运行或可上架的证明。

完成签名后，还需在独立测试环境覆盖：首次系统授权与拒绝、重新打开应用、TCP/UDP 与 DNS、
IPv6、切换节点失败回退、系统设置中断开、扩展异常退出、睡眠唤醒及网络切换。
这些系统级场景不能由回环测试替代。

## 发布条件

Apple 的 [App Review 规则 5.4](https://developer.apple.com/app-store/review/guidelines/#vpn-apps)
要求 VPN 应用由组织会员发布。个人会员可以推进开发；沙盒实现不会改变这个发布条件。
开发签名、商店分发签名、Developer ID 公证属于不同流程。

参考：[App Sandbox](https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox)、
[Network Extension 部署](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)、
[VPN 路由规则](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic)。

## 上架资料与待解决事项

产品描述应明确：连接用户自行部署的兼容服务器，不提供预置节点或节点订阅。
启用相应加密配置后，保护范围是客户端与代理服务器之间的代理连接；直接分流、
UDP 直连回退以及服务器到目标站点的链路，不能统一宣传为加密或端到端加密。
商店版仍然使用 Network Extension 与 macOS VPN 授权，改名和选择“工具”分类
不会改变其实际网络行为，也不保证适用规则 5.4 的豁免。

商店版通过 `proxy-core/no-external-geo` 编译特性拒绝外部地理查询与数据库下载，
并在配置导入、Dart 通道和 Packet Tunnel 入口禁用自动地理分流及反向地理查询。
直装版保持原有地理查询能力。首次启动 Store 版会先展示中英文数据说明，确认前
不创建代理服务；应用内可随时重新查看。公开隐私政策位于
[privacy-policy.md](../ui/flutter/docs/privacy-policy.md)。连接测试仍可能访问
`www.gstatic.com/generate_204`，用户指定的服务器、DNS 和目标站点接收实际网络请求。

商店版提供明确标注的离线演示：首次隐私页面点击“Explore demo / 体验演示”，
或进入应用后点击播放图标。可编辑示例主机、增删选取示例节点、模拟连接与断开并
查看演示事件。此页面只修改内存，不调用 VPN、网络或持久化设置；退出即清空。
演示不会验证真实转发，也不包含审核服务器。审核备注必须如实说明这一限制，
Apple 仍可要求可用服务器或拒绝审核。维护者已选择按此方案尝试提交，不以保证通过为前提。

截图可通过 Flutter 无头渲染离线演示页面生成，不启动系统 VPN。当前维护者的工作 Mac
不运行 VPN 验证，不修改 iOA、系统路由或代理设置。提交后以 App Store Connect 的
审核状态为准，不得将功能测试、开发签名、上传或归档成功表述为 App Review 通过。
