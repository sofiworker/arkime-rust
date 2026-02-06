## arkime-rust

面向 Linux 的 Arkime Rust 重写项目（当前阶段）。

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
export ARKIME_RUST__NET__LINK_PATTERNS='["eth*","ens*"]'
```

### 当前状态说明

- 目前运行时仅实现 `libpcap` 兼容后端（基于 `pnet` datalink）。
- `pfring/raw_socket/dpdk/ebpf` 已纳入统一后端抽象，待 Linux 专用 runtime adapter 实现。

> NOTE: You must place Packet.lib from the WinPcap Developers pack in a directory named lib, in the root of this repository. Alternatively, you can use any of the locations listed in the %LIB%/$Env:LIB environment variables. For the 64 bit toolchain it is in WpdPack/Lib/x64/Packet.lib, for the 32 bit toolchain, it is in WpdPack/Lib/Packet.lib.
