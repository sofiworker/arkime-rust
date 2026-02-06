## arkime-rust

使用 Rust 重写 Arkime 抓包核心的实验性版本，目标是：

- 支持高性能抓包能力扩展（`libpcap`、`pfring`、`raw socket`、`dpdk`、`ebpf` 作为可配置后端）。
- 默认保留对以太网主网卡抓包并解 VLAN 的能力，避免直接监听 VLAN 子接口造成重复资源消耗。
- 允许用户显式指定 VLAN 子接口（如 `eth0.100`）时再单独监听。
- 配置采用类似 Go Viper 的“文件 + 环境变量”合并模式（环境变量优先）。
- 具备动态网卡发现所需的接口筛选基础（按通配符匹配接口）。

> NOTE: You must place Packet.lib from the WinPcap Developers pack in a directory named lib, in the root of this repository. Alternatively, you can use any of the locations listed in the %LIB%/$Env:LIB environment variables. For the 64 bit toolchain it is in WpdPack/Lib/x64/Packet.lib, for the 32 bit toolchain, it is in WpdPack/Lib/Packet.lib.

### 配置说明

配置文件位于 `src/config.toml`，并支持环境变量覆盖：

- 前缀：`ARKIME_RUST`
- 层级分隔符：`__`
- 示例：`ARKIME_RUST__CAPTURE__BACKEND=ebpf`

常见字段：

- `capture.backend`: 当前抓包后端。
- `capture.enabled_backends`: 允许启用的后端集合。
- `net.link_patterns`: 接口匹配规则，如 `eth*`、`ens*`。
