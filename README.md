## arkime-rust

面向 Linux 的 Arkime Rust 重写项目（当前阶段）。

本次重点补充你提到的内容：

- 更细分的 layer 解析：Ethernet / VLAN / ARP / IPv4 / IPv6 / TCP / UDP。
- pcap 存储：支持 `pcap` 与 `pcapng` 两种写入格式。
- 对象存储对接抽象：`local_fs` / `s3` / `ceph` 统一配置入口（当前实现为兼容写入路径骨架，便于后续接 SDK）。
- 元数据索引与搜索：记录 IP/端口/VLAN/长度/时间戳/网卡等元数据，提供基础按 IP 检索能力。

### 当前设计目标（modern Rust）

- Linux 优先：抓包主路径优先适配 Linux，Windows 先保留可移植接口（port）而非立即实现。
- 后端可插拔：统一抽象 `libpcap / pfring / raw socket / dpdk / ebpf`，先实现 `libpcap` 兼容路径，其他后端预留 Linux 适配点。
- 配置分层合并：`config.toml + 环境变量`（Viper 风格，`ARKIME_RUST__...` 覆盖）。
- 动态网卡：支持周期性发现新增/移除网卡。
- VLAN 策略：默认监听父以太网接口并在包内解析 VLAN；仅在用户显式指定时监听 VLAN 子接口（如 `eth0.100`）。

### 使用

```bash
cargo run -- config --config src/config.toml
cargo run -- capture --config src/config.toml
```

环境变量覆盖示例：

```bash
export ARKIME_RUST__CAPTURE__BACKEND=libpcap
export ARKIME_RUST__STORAGE__FORMAT=pcapng
export ARKIME_RUST__STORAGE__BACKEND=s3
export ARKIME_RUST__STORAGE__ENDPOINT=http://127.0.0.1:9000
```

### 配置重点

- `storage.backend`: `local_fs | s3 | ceph`
- `storage.format`: `pcap | pcapng`
- `storage.local_path`: 本地落盘目录
- `storage.bucket` / `storage.endpoint`: 对象存储兼容字段
- `index.enabled`: 是否启用元数据索引
- `index.max_entries`: 内存索引最大保留条数

### 当前状态说明

- 目前运行时仅实现 `libpcap` 兼容抓包后端（基于 `pnet` datalink）。
- `pfring/raw_socket/dpdk/ebpf` 已纳入统一后端抽象，待 Linux 专用 runtime adapter 实现。
- 已具备“抓包 -> 解包 -> 过滤 -> 会话聚合 -> pcap/pcapng 存储 -> 元数据索引”的基础链路。

> NOTE: You must place Packet.lib from the WinPcap Developers pack in a directory named lib, in the root of this repository. Alternatively, you can use any of the locations listed in the %LIB%/$Env:LIB environment variables. For the 64 bit toolchain it is in WpdPack/Lib/x64/Packet.lib, for the 32 bit toolchain, it is in WpdPack/Lib/Packet.lib.
