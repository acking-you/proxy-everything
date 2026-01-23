# 内存占用上升问题排查与修复

## 背景现象
- 新版本 `http-proxy-server` 在单连接长时间带宽测试下，内存峰值明显高于旧版本（例如 110MB vs 80MB）。
- 内存上去后基本不下降。
- 旧版本部署在 Docker 中，使用 `docker stats` 观察；新版本为 systemd 服务，使用 `systemctl status` 观察。

## 测量口径差异（必须先对齐）
`docker stats` 与 `systemctl status` 并不是同一口径：
- `docker stats` 读取容器 cgroup 的内存统计，通常包含页缓存与共享页。
- `systemctl status` 展示的是服务 cgroup 或主进程的 RSS（实现依系统版本不同）。

为了保证可比性，建议统一口径：
- 同机对比：`cat /proc/<pid>/status | grep VmRSS`
- cgroup 对比：`cat /sys/fs/cgroup/<cgroup>/memory.current`

> 口径不一致会导致“看起来变大”但实际没有直接可比结论。

## 排查路径（按步骤缩小范围）
1. **DNS 排除**
   - 单连接、长时间大流量测试 ≈ 单次解析或少量解析。
   - 因此“DNS 频繁解析导致内存上升”的概率很低。

2. **代码路径审计（新增功能导致的常驻内存）**
   - 发现系统指标采集新增了 `sysinfo::System::new_all()` 的用法。
   - `new_all()` 会枚举全部进程/线程（Linux 上还包含 `/proc/<pid>/task/<tid>`），并保留内部缓存。
   - 这类内存通常会**一次性上涨后常驻**，符合“上去后难以下来”的特征。

3. **数据流与缓冲区增长路径**
   - 传输链路使用 `AsyncNormalCodec` 自适应 buffer。
   - 原实现虽然“标注为 shrink”，但仅调用 `Vec::resize`，并不会回收 capacity。
   - 因此在高吞吐时 buffer 会增长，之后即使流量下降也不释放容量。

## 数据流示意（ASCII）

### 1) 带宽测试的数据流
```text
Client
  │  大流量长连接
  ▼
[AsyncNormalCodec]  (buffer 逐步扩张到上限)
  │  encrypt + frame
  ▼
Server
  │  decrypt + frame
  ▼
[AsyncNormalCodec]  (buffer 同步扩张)
  │
  ▼
Destination
```

### 2) 系统指标采集的数据流
```text
Metrics Loop (5s)
  │
  ├─ sysinfo::System::new_all()  (旧逻辑)
  │    └─ 枚举所有进程/任务 → 缓存常驻
  │
  └─ refresh_cpu / refresh_memory / refresh_processes
```

## 真实问题定位
- **问题 1：系统指标采集过重**
  - 使用 `System::new_all()` 导致枚举全部进程 + 任务，产生常驻内存。
  - 对“只采集本进程 + 系统 CPU/RAM”来说是多余的。

- **问题 2：缓冲区缩小不回收**
  - `AsyncNormalCodec` 的 shrink 逻辑只缩 `len` 不缩 `capacity`。
  - 在大流量场景下 buffer 扩张到高水位，之后内存无法回落。

## 修复方案（已实现）
1. **最小化 sysinfo 采集范围**
   - 避免 `System::new_all()`。
   - 仅刷新：
     - CPU 使用率
     - 内存（RAM）
     - 当前进程 CPU+内存（且 `without_tasks()`）
   - 磁盘仅刷新 `storage` 字段。
2. **缓冲区真实 shrink**
   - 当需要缩小 buffer 时使用：
     - `truncate()` + `shrink_to()`
   - 确保 capacity 被释放回 allocator，降低 RSS 常驻。
3. **解密缓冲区也支持 shrink**
   - 解密路径根据帧大小逐步收缩，避免单次大帧后长期占用大块内存。

## 预期效果
- 系统指标采集的常驻内存显著下降。
- 大流量结束后，缓冲区不会永久占用大容量。

## 分配器差异说明（mimalloc / tcmalloc / jemalloc）
> 这一节从分配器设计与运行时行为解释“RSS 回落速度”和“常驻占用”的差异。
> 你的实测（同样测试场景）：
> - **mimalloc：峰值约 180MB，回落慢**
> - **tcmalloc：峰值约 80MB，RSS 回落快**

### 共同点：都做缓存与分级管理
- **线程本地缓存**（thread cache）：减少锁争用，提升分配/释放延迟表现。
- **中心缓存/全局缓存**：跨线程复用，降低碎片。
- **页级回收策略**：控制何时把空闲页返还给 OS。

差异主要在**回收触发条件与回收力度**。

### mimalloc：延迟优先，回收更保守
- 更倾向保留缓存以降低分配/释放延迟与抖动。
- 回收策略相对保守，空闲页更可能长期保留在进程内。
- 适合极致延迟/吞吐，但 RSS 回落速度慢。

### tcmalloc：回收更积极
- 后台回收机制更主动（malloc-best-effort 会启动后台动作）。
- 更倾向快速把空闲页返还给 OS。
- 对长时间运行服务的 RSS 更友好。

### jemalloc：可控性强（适合长服务/数据库场景）
- 通过 **arena + decay** 控制回收节奏（如 `dirty_decay_ms` / `muzzy_decay_ms`）。
- 可在“延迟 vs 回收”之间调参折中。
- 运行行为可预测、可调优，常用于长期服务的稳定内存管理。

### 为什么你看到 RSS 差异这么明显？
- 你的场景是**长时间运行服务**，测试结束后的回落速度高度依赖分配器回收策略。
- mimalloc 更保守 ⇒ **RSS 回落慢**。
- tcmalloc 更积极 ⇒ **RSS 回落快**。
- 再叠加本次“缓冲区 shrink + sysinfo 精简”，回收效果被进一步放大。

### 直觉总结
- **mimalloc**：更偏“低延迟优先”，内存更愿意留着复用 → RSS 回落慢
- **tcmalloc / jemalloc**：更偏“长期服务内存稳定” → RSS 回落快、占用更低

## 验证建议
1. **同口径对比**（必要）
   - 使用 `VmRSS` 或 cgroup `memory.current` 对齐统计口径。

2. **压测步骤**
   - 单连接持续带宽测试（保持一致的流量与时间）。
   - 观察峰值与结束后 5~10 分钟的回落情况。

3. **回归检查**
   - 确认 CPU 采集、内存采集与进程指标仍能在 TUI/控制面板显示。

## 相关代码位置
- `crates/proxy-core/src/codec/mod.rs`
  - `AsyncNormalCodec::resize` 使用 `shrink_to` 回收 capacity。
  - `AsyncDecryptCodec` 根据帧大小进行渐进式 shrink。
- `crates/proxy-server/src/server/mod.rs`
  - 新增 `SysinfoMetrics` 结构与最小化刷新逻辑。
