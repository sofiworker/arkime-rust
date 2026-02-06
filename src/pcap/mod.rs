use crate::conf::{IndexConfig, StorageBackend, StorageConfig, StorageFormat};
use crate::layer::{ParsedPacket, TransportInfo};
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct PacketMetadata {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub iface: String,
    pub capture_len: u32,
    pub wire_len: u32,
    pub vlan_id: Option<u16>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

#[derive(Default)]
pub struct MetadataIndex {
    entries: Vec<PacketMetadata>,
}

impl MetadataIndex {
    pub fn add(&mut self, item: PacketMetadata, cfg: &IndexConfig) {
        self.entries.push(item);
        if self.entries.len() > cfg.max_entries {
            let drop_n = self.entries.len() - cfg.max_entries;
            self.entries.drain(0..drop_n);
        }
    }

    pub fn search_by_ip(&self, ip: IpAddr) -> Vec<&PacketMetadata> {
        self.entries
            .iter()
            .filter(|m| m.src_ip == Some(ip) || m.dst_ip == Some(ip))
            .collect()
    }
}

trait PacketSink: Send {
    fn write_packet(&mut self, frame: &[u8], ts_sec: u32, ts_usec: u32) -> io::Result<()>;
}

struct PcapSink {
    writer: BufWriter<File>,
}

impl PcapSink {
    fn new(file: File) -> io::Result<Self> {
        let mut writer = BufWriter::new(file);
        // PCAP global header (little-endian)
        writer.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
        writer.write_all(&2u16.to_le_bytes())?;
        writer.write_all(&4u16.to_le_bytes())?;
        writer.write_all(&0i32.to_le_bytes())?;
        writer.write_all(&0u32.to_le_bytes())?;
        writer.write_all(&65535u32.to_le_bytes())?;
        writer.write_all(&1u32.to_le_bytes())?; // LINKTYPE_ETHERNET
        Ok(Self { writer })
    }
}

impl PacketSink for PcapSink {
    fn write_packet(&mut self, frame: &[u8], ts_sec: u32, ts_usec: u32) -> io::Result<()> {
        let len = frame.len() as u32;
        self.writer.write_all(&ts_sec.to_le_bytes())?;
        self.writer.write_all(&ts_usec.to_le_bytes())?;
        self.writer.write_all(&len.to_le_bytes())?;
        self.writer.write_all(&len.to_le_bytes())?;
        self.writer.write_all(frame)?;
        self.writer.flush()
    }
}

struct PcapNgSink {
    writer: BufWriter<File>,
    wrote_if_block: bool,
}

impl PcapNgSink {
    fn new(file: File) -> io::Result<Self> {
        let mut writer = BufWriter::new(file);
        // Section Header Block
        writer.write_all(&0x0A0D0D0Au32.to_le_bytes())?;
        writer.write_all(&28u32.to_le_bytes())?;
        writer.write_all(&0x1A2B3C4Du32.to_le_bytes())?;
        writer.write_all(&1u16.to_le_bytes())?;
        writer.write_all(&0u16.to_le_bytes())?;
        writer.write_all(&(-1i64).to_le_bytes())?;
        writer.write_all(&28u32.to_le_bytes())?;
        Ok(Self {
            writer,
            wrote_if_block: false,
        })
    }

    fn ensure_interface_block(&mut self) -> io::Result<()> {
        if self.wrote_if_block {
            return Ok(());
        }
        // Interface Description Block
        self.writer.write_all(&1u32.to_le_bytes())?;
        self.writer.write_all(&20u32.to_le_bytes())?;
        self.writer.write_all(&1u16.to_le_bytes())?; // LINKTYPE_ETHERNET
        self.writer.write_all(&0u16.to_le_bytes())?;
        self.writer.write_all(&65535u32.to_le_bytes())?;
        self.writer.write_all(&20u32.to_le_bytes())?;
        self.wrote_if_block = true;
        Ok(())
    }
}

impl PacketSink for PcapNgSink {
    fn write_packet(&mut self, frame: &[u8], ts_sec: u32, ts_usec: u32) -> io::Result<()> {
        self.ensure_interface_block()?;
        let packet_len = frame.len() as u32;
        let padded_len = (packet_len + 3) & !3;
        let block_len = 32 + padded_len;

        self.writer.write_all(&6u32.to_le_bytes())?; // EPB
        self.writer.write_all(&block_len.to_le_bytes())?;
        self.writer.write_all(&0u32.to_le_bytes())?; // interface id
        self.writer.write_all(&ts_sec.to_le_bytes())?;
        self.writer.write_all(&(ts_usec * 1000).to_le_bytes())?; // ns approximation
        self.writer.write_all(&packet_len.to_le_bytes())?;
        self.writer.write_all(&packet_len.to_le_bytes())?;
        self.writer.write_all(frame)?;
        for _ in 0..(padded_len - packet_len) {
            self.writer.write_all(&[0])?;
        }
        self.writer.write_all(&block_len.to_le_bytes())?;
        self.writer.flush()
    }
}

pub struct PacketRecorder {
    sink: Box<dyn PacketSink>,
    index: MetadataIndex,
    index_cfg: IndexConfig,
}

impl PacketRecorder {
    pub fn new(storage: &StorageConfig, index_cfg: &IndexConfig) -> io::Result<Self> {
        let file = open_output_file(storage)?;
        let sink: Box<dyn PacketSink> = match storage.format {
            StorageFormat::Pcap => Box::new(PcapSink::new(file)?),
            StorageFormat::PcapNg => Box::new(PcapNgSink::new(file)?),
        };

        Ok(Self {
            sink,
            index: MetadataIndex::default(),
            index_cfg: index_cfg.clone(),
        })
    }

    pub fn record(&mut self, iface: &str, frame: &[u8], parsed: &ParsedPacket) -> io::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let ts_sec = now.as_secs() as u32;
        let ts_usec = now.subsec_micros();

        self.sink.write_packet(frame, ts_sec, ts_usec)?;

        let (src_ip, dst_ip, src_port, dst_port, vlan_id) = if let Some(flow) = &parsed.flow {
            let (sp, dp) = match flow.transport {
                TransportInfo::Tcp { src_port, dst_port } => (Some(src_port), Some(dst_port)),
                TransportInfo::Udp { src_port, dst_port } => (Some(src_port), Some(dst_port)),
                TransportInfo::Other => (None, None),
            };
            (Some(flow.src), Some(flow.dst), sp, dp, flow.vlan_id)
        } else {
            (None, None, None, None, None)
        };

        self.index.add(
            PacketMetadata {
                ts_sec,
                ts_usec,
                iface: iface.to_string(),
                capture_len: frame.len() as u32,
                wire_len: frame.len() as u32,
                vlan_id,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            },
            &self.index_cfg,
        );

        Ok(())
    }

    pub fn search_by_ip(&self, ip: IpAddr) -> Vec<&PacketMetadata> {
        self.index.search_by_ip(ip)
    }
}

fn open_output_file(storage: &StorageConfig) -> io::Result<File> {
    let base = PathBuf::from(&storage.local_path);
    create_dir_all(&base)?;

    let file_name = match storage.backend {
        StorageBackend::LocalFs => "capture-local",
        StorageBackend::S3 => "capture-s3-compatible",
        StorageBackend::Ceph => "capture-ceph-compatible",
    };

    let ext = match storage.format {
        StorageFormat::Pcap => "pcap",
        StorageFormat::PcapNg => "pcapng",
    };

    OpenOptions::new()
        .create(true)
        .append(true)
        .open(base.join(format!("{}.{}", file_name, ext)))
}

#[cfg(test)]
mod tests {
    use super::{MetadataIndex, PacketMetadata};
    use crate::conf::IndexConfig;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn search_index_by_ip() {
        let mut idx = MetadataIndex::default();
        let cfg = IndexConfig {
            max_entries: 10,
            enabled: true,
        };

        idx.add(
            PacketMetadata {
                ts_sec: 0,
                ts_usec: 0,
                iface: "eth0".to_string(),
                capture_len: 64,
                wire_len: 64,
                vlan_id: None,
                src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                dst_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
                src_port: Some(1),
                dst_port: Some(2),
            },
            &cfg,
        );

        assert_eq!(
            idx.search_by_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
                .len(),
            1
        );
        assert_eq!(
            idx.search_by_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
                .len(),
            0
        );
    }
}
