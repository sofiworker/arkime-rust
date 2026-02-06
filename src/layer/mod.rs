use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherType, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::vlan::VlanPacket;
use pnet::packet::Packet;

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
}

pub fn parse_packet(frame: &[u8]) -> Option<ParsedPacket> {
    let eth = EthernetPacket::new(frame)?;

    match eth.get_ethertype() {
        EtherType(0x8100) | EtherType(0x88A8) => {
            let vlan = VlanPacket::new(eth.payload())?;
            parse_l3(
                vlan.payload(),
                vlan.get_ethertype(),
                Some(vlan.get_vlan_identifier()),
            )
        }
        other => parse_l3(eth.payload(), other, None),
    }
}

fn parse_l3(payload: &[u8], ethertype: EtherType, vlan_id: Option<u16>) -> Option<ParsedPacket> {
    match ethertype.0 {
        0x0800 => parse_ipv4(payload, ethertype, vlan_id),
        0x86DD => parse_ipv6(payload, ethertype, vlan_id),
        0x0806 => parse_arp(payload, ethertype),
        _ => Some(ParsedPacket {
            flow: None,
            network: NetworkInfo::Other,
            ethertype: ethertype.0,
            payload_len: payload.len(),
        }),
    }
}

fn parse_ipv4(payload: &[u8], ethertype: EtherType, vlan_id: Option<u16>) -> Option<ParsedPacket> {
    let ipv4 = Ipv4Packet::new(payload)?;
    let src = IpAddr::V4(Ipv4Addr::from(ipv4.get_source().octets()));
    let dst = IpAddr::V4(Ipv4Addr::from(ipv4.get_destination().octets()));
    let transport = parse_l4(ipv4.payload(), ipv4.get_next_level_protocol());

    Some(ParsedPacket {
        flow: Some(FlowKey {
            src,
            dst,
            transport,
            vlan_id,
        }),
        network: NetworkInfo::Ipv4,
        ethertype: ethertype.0,
        payload_len: payload.len(),
    })
}

fn parse_ipv6(payload: &[u8], ethertype: EtherType, vlan_id: Option<u16>) -> Option<ParsedPacket> {
    let ipv6 = Ipv6Packet::new(payload)?;
    let src = IpAddr::V6(Ipv6Addr::from(ipv6.get_source().octets()));
    let dst = IpAddr::V6(Ipv6Addr::from(ipv6.get_destination().octets()));
    let transport = parse_l4(ipv6.payload(), ipv6.get_next_header());

    Some(ParsedPacket {
        flow: Some(FlowKey {
            src,
            dst,
            transport,
            vlan_id,
        }),
        network: NetworkInfo::Ipv6,
        ethertype: ethertype.0,
        payload_len: payload.len(),
    })
}

fn parse_arp(payload: &[u8], ethertype: EtherType) -> Option<ParsedPacket> {
    let _arp = ArpPacket::new(payload)?;
    Some(ParsedPacket {
        flow: None,
        network: NetworkInfo::Arp,
        ethertype: ethertype.0,
        payload_len: payload.len(),
    })
}

fn parse_l4(payload: &[u8], protocol: IpNextHeaderProtocol) -> TransportInfo {
    match protocol.0 {
        6 => {
            if let Some(tcp) = TcpPacket::new(payload) {
                return TransportInfo::Tcp {
                    src_port: tcp.get_source(),
                    dst_port: tcp.get_destination(),
                };
            }
            TransportInfo::Other
        }
        17 => {
            if let Some(udp) = UdpPacket::new(payload) {
                return TransportInfo::Udp {
                    src_port: udp.get_source(),
                    dst_port: udp.get_destination(),
                };
            }
            TransportInfo::Other
        }
        _ => TransportInfo::Other,
    }
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
}
