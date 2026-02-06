## arkime-rust

Experimental rewrite of Arkime capture core in Rust.

### Goals

- Linux-first capture path.
- Pluggable capture backends (implemented today: a `libpcap`-compatible path via `pnet` datalink).
- Planned backends: `pfring`, `raw_socket`, `dpdk`, `ebpf` via Linux runtime adapters.
- Capture pipeline scaffold: capture -> parse -> filter -> session aggregation -> pcap/pcapng record -> metadata index.
- Config layering: `src/config.toml` merged with environment variables. Prefix `ARKIME_RUST`, separator `__`.

### Usage

```bash
cargo run -- config --config src/config.toml
cargo run -- capture --config src/config.toml
```

Environment overrides example:

```bash
export ARKIME_RUST__CAPTURE__BACKEND=libpcap
export ARKIME_RUST__STORAGE__FORMAT=pcapng
export ARKIME_RUST__STORAGE__BACKEND=s3
export ARKIME_RUST__STORAGE__ENDPOINT=http://127.0.0.1:9000
```

### Config Notes

- `storage.backend`: `local_fs | s3 | ceph` (currently the file writer is local; other backends are config scaffolding).
- `storage.format`: `pcap | pcapng`
- `storage.local_path`: local output directory
- `index.enabled`: enable in-memory metadata index
- `index.max_entries`: max retained metadata entries

### Interface Selection (VLAN)

By default, capture listens on parent Ethernet interfaces and parses VLAN tags inside packets.
VLAN sub-interfaces (for example `eth0.100`) are ignored unless explicitly configured via `net.link_patterns`.

### Windows Note (Npcap/WinPcap)

> NOTE: You must place `Packet.lib` from the WinPcap Developers Pack in a directory named `lib`,
> in the root of this repository. Alternatively, you can use any of the locations listed in the
> `%LIB%` / `$Env:LIB` environment variables. For the 64-bit toolchain it is in
> `WpdPack/Lib/x64/Packet.lib`, for the 32-bit toolchain, it is in `WpdPack/Lib/Packet.lib`.

