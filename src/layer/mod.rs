use std::net::IpAddr;
use serde_json::Value;

pub mod plugins;
pub mod engine;
pub mod builtin;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NetworkInfo {
    Ipv4,
    Ipv6,
    Arp,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransportInfo {
    Tcp { src_port: u16, dst_port: u16 },
    Udp { src_port: u16, dst_port: u16 },
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub transport: TransportInfo,
    pub vlan_id: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub flow: Option<FlowKey>,
    pub network: NetworkInfo,
    pub ethertype: u16,
    pub payload_len: usize,
    pub extras: Vec<LayerExtra>,
}

#[derive(Debug, Clone)]
pub struct LayerExtra {
    pub plugin: String,
    pub data: Value,
}

pub fn parse_packet(frame: &[u8]) -> Option<ParsedPacket> {
    // Legacy convenience entrypoint (no dynamic plugins).
    // Capture runtime uses `engine::LayerEngine` so the layer stack is Arkime-like and extensible.
    engine::LayerEngine::default().parse(frame)
}

#[cfg(test)]
mod tests {
    use super::{parse_packet, NetworkInfo, TransportInfo};

    #[test]
    fn parse_ipv4_udp_vlan_packet() {
        let frame: [u8; 46] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x81, 0x00,
            0x00, 0x64, 0x08, 0x00, 0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,
            0x00, 0x00, 10, 0, 0, 1, 10, 0, 0, 2, 0x1f, 0x90, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
        ];

        let parsed = parse_packet(&frame).expect("must parse");
        let flow = parsed.flow.expect("must have flow");

        assert_eq!(parsed.network, NetworkInfo::Ipv4);
        assert_eq!(flow.vlan_id, Some(100));
        assert_eq!(
            flow.transport,
            TransportInfo::Udp {
                src_port: 8080,
                dst_port: 53
            }
        );
    }

    #[test]
    fn parse_arp_packet() {
        let frame: [u8; 42] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x06,
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 10,
            0, 0, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 2,
        ];
        let parsed = parse_packet(&frame).expect("must parse");
        assert_eq!(parsed.network, NetworkInfo::Arp);
        assert!(parsed.flow.is_none());
    }

    #[test]
    fn parse_ipv4_icmp_echo_request() {
        // Ethernet(14) + IPv4(20) + ICMP(8)
        // IPv4 header checksum is set to 0 (we don't validate checksums in parser).
        let frame: [u8; 42] = [
            // eth dst/src/type
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08,
            0x00,
            // ipv4 ver/ihl,tos,len
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 10, 0,
            0, 1, 10, 0, 0, 2,
            // icmp type=8 code=0 csum=0 id=0x1234 seq=0x0001
            0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01,
        ];

        let parsed = parse_packet(&frame).expect("must parse");
        assert_eq!(parsed.network, NetworkInfo::Ipv4);
        assert!(parsed.extras.iter().any(|e| e.plugin == "icmp"));
    }
}
