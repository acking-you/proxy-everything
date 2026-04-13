# 动态 Relay 配置功能说明

本文档说明本次分支实现的动态 Relay 能力、核心特性与使用方式，并给出配置与控制协议示例。

## 功能概览

- **动态 Relay 配置**：服务端可在运行时切换为上游转发模式，无需重启即可增删上游目标。
- **负载均衡算法**：支持 RoundRobin / Random / Weighted / LeastConn 四种策略。
- **节点分组管理**：支持创建节点组并在 Relay 配置中引用组，实现集群化管理。
- **控制协议扩展**：新增 Relay 与节点组相关的控制指令，便于运维自动化。
- **状态监控增强**：`GetRelayStatus` 返回目标健康状态与连接数（LeastConn 可反映实时连接）。
- **配置持久化**：Relay 配置与节点信息自动持久化到本地文件，重启后可恢复。
- **向后兼容**：保留 `TURELY_PROXY_SERVER` 启动方式，并与动态 Relay 机制融合。

## 关键数据与持久化

- 默认数据目录：`~/.proxy-everything/`
- 持久化文件：
  - `nodes.json`：节点与节点组信息
  - `relay.json`：Relay 配置
- Docker 部署时，数据目录由 `PROXY_DATA_DIR` 控制（详见 `scripts/proxy-ctl.sh`）。

## 使用方式

### 1) 兼容模式：使用 TURELY_PROXY_SERVER

在启动服务端时设置环境变量：

```
TURELY_PROXY_SERVER=upstream.example.com:1081
```

行为说明：

- **首次启动**：若 `relay.json` 尚无配置，则自动添加该上游并启用 Relay。
- **后续启动**：若已有 `relay.json`，则优先使用持久化配置，忽略环境变量。

此模式适用于快速接入单一上游，或平滑迁移到动态 Relay。

### 2) 推荐模式：使用控制协议动态配置

控制协议通过 `proxy_core::control::ControlClient` 调用，以下为常见操作示例：

```rust
use proxy_core::control::{ControlClient, ControlOp, ControlRequest};
use proxy_core::relay::{LoadBalanceAlgo, RelayConfig, UpstreamTarget};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut client = ControlClient::connect("127.0.0.1", 1081, None).await?;

    // 创建节点组
    client
        .request(ControlRequest {
            token: None,
            op: ControlOp::CreateGroup {
                group_id: "asia".to_string(),
                name: "Asia Servers".to_string(),
            },
        })
        .await?;

    // 添加节点并加入组
    client
        .request(ControlRequest {
            token: None,
            op: ControlOp::AddNode {
                addr: "10.0.0.1:1081".to_string(),
            },
        })
        .await?;
    client
        .request(ControlRequest {
            token: None,
            op: ControlOp::AddNodeToGroup {
                group_id: "asia".to_string(),
                node_id: "10.0.0.1:1081".to_string(),
            },
        })
        .await?;

    // 设置 Relay 配置并启用
    let config = RelayConfig {
        enabled: true,
        targets: vec![
            UpstreamTarget::group_ref("asia"),
            UpstreamTarget::node_weighted("backup.server:1081", 2),
        ],
        algo: LoadBalanceAlgo::Weighted,
        health_check_interval_secs: 30,
    };

    client
        .request(ControlRequest {
            token: None,
            op: ControlOp::SetRelayConfig { config },
        })
        .await?;

    Ok(())
}
```

### 3) 查询 Relay 状态

调用 `GetRelayStatus` 可获得当前算法与目标状态：

- `healthy`：健康标记（由运行时健康标记更新）
- `connections`：仅在 LeastConn 下反映实时连接数

```
ControlOp::GetRelayStatus
```

### 4) 使用 proxy-tui 完成配置（推荐）

`proxy-tui` 已覆盖节点、节点组与 Relay 配置的完整控制能力，适合交互式运维。

#### 构建与运行

```bash
cargo build --release -p proxy-tui
./target/release/proxy-tui -H 127.0.0.1 -p 1081 -k YOUR_SESSION_KEY --token YOUR_ADMIN_TOKEN
```

#### 常用操作

- **节点管理（Nodes）**
  - `a` 添加节点：输入 `host:port`
  - `d` 删除节点：删除当前选中节点
  - `Enter` 切换目标服务器（多节点场景）
- **节点组管理（Groups）**
  - `a` 创建节点组：输入 `<group_id> <name>`
  - `d` 删除节点组
  - `g` 添加节点到组：输入 `<node_id>`（通常为 `host:port`）
  - `x` 从组移除节点：输入 `<node_id>`
- **Relay 配置（Relay）**
  - `e` 启用/禁用 Relay
  - `l` 切换负载均衡算法
  - `a` 添加 Relay 目标：
    - `node <host:port> [weight]`
    - `node_ref <node_id> [weight]`
    - `group_ref <group_id>`
    - `proxy <proxy_url> [weight]`
    - 也可直接粘贴完整代理 URL：`socks5://...`、`socks5h://...`、`http://...`
  - `d` 删除选中 Relay 目标
  - `c` 直接设置完整 Relay 配置（JSON）

外部代理说明：

- `socks5://user:pass@host:port`：通过 SOCKS5 中转，目标域名先在本机解析。
- `socks5h://user:pass@host:port`：通过 SOCKS5 中转，并让代理端执行远端 DNS 解析。
- `http://user:pass@host:port`：通过 HTTP CONNECT 中转。
- SOCKS5 和 HTTP CONNECT 都支持用户名/密码认证。
- TUI 与 `GetRelayStatus` 会隐藏密码，不会把 `pass` 回显到界面里。
- `Relay` 页面仍然不接受裸 `host:port` 作为外部代理输入；如果不是 `node ...`，就必须带协议头。

JSON 示例：

```json
{
  "enabled": true,
  "targets": [
    { "type": "group_ref", "group_id": "asia" },
    { "type": "node", "addr": "backup.server:1081", "weight": 2 },
    {
      "type": "external_proxy",
      "proxy_url": "socks5://relay-user:secret@127.0.0.1:1080",
      "weight": 1
    }
  ],
  "algo": "weighted",
  "health_check_interval_secs": 30
}
```

## 常见控制指令一览

- Relay 配置：
  - `GetRelayConfig` / `SetRelayConfig` / `SetRelayEnabled`
  - `AddRelayTarget` / `RemoveRelayTarget`
  - `SetRelayAlgo` / `GetRelayStatus`
- 节点组管理：
  - `CreateGroup` / `DeleteGroup` / `ListGroups`
  - `AddNodeToGroup` / `RemoveNodeFromGroup`

## 运行与测试建议

- 格式化：`cargo fmt --all`
- 测试：`cargo test --workspace`
- Lint：`cargo clippy --all-targets --all-features`

## 注意事项

- Relay 模式依赖控制协议进行动态配置，建议为控制协议配置 `CONTROL_ADMIN_TOKEN` 及 `CONTROL_SESSION_KEY`。
- 若服务端运行在 Docker 环境，请确保 `PROXY_DATA_DIR` 挂载到持久化目录，避免配置丢失。
- 通过控制协议删除节点后，该节点会被加入阻止列表以避免同步再次自动加入；如需恢复，重新添加该节点即可。
