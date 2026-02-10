use crate::layer::plugins::LayerPluginManager;
use crate::layer::{FlowKey, LayerExtra, NetworkInfo, ParsedPacket, TransportInfo};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherType, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::vlan::VlanPacket;
use pnet::packet::Packet;
use serde_json::Value;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// Arkime-like concept:
// - L2/L3/L4 are parsed deterministically.
// - L7 is selected by classifiers (typically port-based) and parsed by registered parsers.

pub struct PacketContext<'a> {
    pub frame: &'a [u8],
    pub ethertype: u16,
    pub vlan_id: Option<u16>,
    pub network: NetworkInfo,
    pub ip_proto: u8,
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    pub transport: TransportInfo,
    pub l4_payload: &'a [u8],
}

pub trait L7Parser: Send + Sync {
    fn name(&self) -> &'static str;
    fn parse(&self, ctx: &PacketContext) -> Option<Value>;
}

pub struct LayerEngine {
    udp_by_port: HashMap<u16, Vec<Box<dyn L7Parser>>>,
    tcp_by_port: HashMap<u16, Vec<Box<dyn L7Parser>>>,
    ip_by_proto: HashMap<u8, Vec<Box<dyn L7Parser>>>,
    plugins: LayerPluginManager,
}

impl Default for LayerEngine {
    fn default() -> Self {
        Self::new(LayerPluginManager::default())
    }
}

impl LayerEngine {
    pub fn new(plugins: LayerPluginManager) -> Self {
        let mut eng = Self {
            udp_by_port: HashMap::new(),
            tcp_by_port: HashMap::new(),
            ip_by_proto: HashMap::new(),
            plugins,
        };

        // Built-in parsers (subset of common Arkime-style analyzers).
        eng.register_udp_port(53, Box::new(crate::layer::builtin::dns::DnsParser));
        eng.register_tcp_port(53, Box::new(crate::layer::builtin::dns::DnsParser)); // DNS over TCP
        eng.register_udp_port(5353, Box::new(crate::layer::builtin::dns::DnsParser)); // mDNS
        eng.register_tcp_port(80, Box::new(crate::layer::builtin::http::HttpParser));
        eng.register_tcp_port(8080, Box::new(crate::layer::builtin::http::HttpParser));
        eng.register_tcp_port(8000, Box::new(crate::layer::builtin::http::HttpParser));
        eng.register_tcp_port(443, Box::new(crate::layer::builtin::tls::TlsParser));
        eng.register_udp_port(443, Box::new(crate::layer::builtin::quic::QuicParser)); // QUIC (common)
        eng.register_udp_port(8443, Box::new(crate::layer::builtin::quic::QuicParser));
        eng.register_tcp_port(22, Box::new(crate::layer::builtin::ssh::SshParser));
        eng.register_udp_port(67, Box::new(crate::layer::builtin::dhcp::DhcpParser));
        eng.register_udp_port(68, Box::new(crate::layer::builtin::dhcp::DhcpParser));
        eng.register_udp_port(123, Box::new(crate::layer::builtin::ntp::NtpParser));
        eng.register_udp_port(3478, Box::new(crate::layer::builtin::stun::StunParser));
        eng.register_udp_port(5349, Box::new(crate::layer::builtin::stun::StunParser));
        eng.register_tcp_port(6379, Box::new(crate::layer::builtin::redis::RedisParser));
        eng.register_tcp_port(3306, Box::new(crate::layer::builtin::mysql::MysqlParser));
        eng.register_tcp_port(5432, Box::new(crate::layer::builtin::postgres::PostgresParser));
        eng.register_tcp_port(5672, Box::new(crate::layer::builtin::amqp::AmqpParser));
        eng.register_tcp_port(11211, Box::new(crate::layer::builtin::memcached::MemcachedParser));
        eng.register_tcp_port(1883, Box::new(crate::layer::builtin::mqtt::MqttParser));
        eng.register_tcp_port(8883, Box::new(crate::layer::builtin::mqtt::MqttParser));
        eng.register_udp_port(161, Box::new(crate::layer::builtin::snmp::SnmpParser));
        eng.register_udp_port(162, Box::new(crate::layer::builtin::snmp::SnmpParser));
        eng.register_udp_port(5060, Box::new(crate::layer::builtin::sip::SipParser));
        eng.register_tcp_port(5060, Box::new(crate::layer::builtin::sip::SipParser));
        eng.register_tcp_port(5061, Box::new(crate::layer::builtin::sip::SipParser)); // often TLS in practice

        // Non-port protocols (classified by IP protocol number / IPv6 next header).
        eng.register_ip_proto(1, Box::new(crate::layer::builtin::icmp::IcmpParser)); // ICMP
        eng.register_ip_proto(58, Box::new(crate::layer::builtin::icmp::Icmpv6Parser)); // ICMPv6
        eng.register_ip_proto(47, Box::new(crate::layer::builtin::gre::GreParser)); // GRE
        eng.register_ip_proto(4, Box::new(crate::layer::builtin::ipip::IpInIpParser)); // IPv4-in-IPv4
        eng.register_ip_proto(41, Box::new(crate::layer::builtin::ipip::Ipv6InIpv4Parser)); // IPv6-in-IPv4
        eng.register_ip_proto(50, Box::new(crate::layer::builtin::esp::EspParser)); // ESP
        eng.register_ip_proto(51, Box::new(crate::layer::builtin::ah::AhParser)); // AH
        eng.register_ip_proto(89, Box::new(crate::layer::builtin::ospf::OspfParser)); // OSPF (v2/v3 share proto)
        eng.register_ip_proto(2, Box::new(crate::layer::builtin::igmp::IgmpParser)); // IGMP
        eng.register_ip_proto(88, Box::new(crate::layer::builtin::eigrp::EigrpParser)); // EIGRP
        eng.register_ip_proto(103, Box::new(crate::layer::builtin::pim::PimParser)); // PIM
        eng.register_ip_proto(112, Box::new(crate::layer::builtin::vrrp::VrrpParser)); // VRRP
        eng.register_ip_proto(132, Box::new(crate::layer::builtin::sctp::SctpParser)); // SCTP
        eng
    }

    pub fn register_udp_port(&mut self, port: u16, parser: Box<dyn L7Parser>) {
        self.udp_by_port.entry(port).or_default().push(parser);
    }

    pub fn register_tcp_port(&mut self, port: u16, parser: Box<dyn L7Parser>) {
        self.tcp_by_port.entry(port).or_default().push(parser);
    }

    pub fn register_ip_proto(&mut self, proto: u8, parser: Box<dyn L7Parser>) {
        self.ip_by_proto.entry(proto).or_default().push(parser);
    }

    pub fn parse(&self, frame: &[u8]) -> Option<ParsedPacket> {
        let eth = EthernetPacket::new(frame)?;
        match eth.get_ethertype() {
            EtherType(0x8100) | EtherType(0x88A8) => {
                let vlan = VlanPacket::new(eth.payload())?;
                self.parse_l3(
                    frame,
                    vlan.payload(),
                    vlan.get_ethertype(),
                    Some(vlan.get_vlan_identifier()),
                )
            }
            other => self.parse_l3(frame, eth.payload(), other, None),
        }
    }

    fn parse_l3(
        &self,
        frame: &[u8],
        l3_payload: &[u8],
        ethertype: EtherType,
        vlan_id: Option<u16>,
    ) -> Option<ParsedPacket> {
        let mut extras: Vec<LayerExtra> = Vec::new();

        let (flow, network) = match ethertype.0 {
            0x0800 => {
                let ipv4 = Ipv4Packet::new(l3_payload)?;
                let src = IpAddr::V4(Ipv4Addr::from(ipv4.get_source().octets()));
                let dst = IpAddr::V4(Ipv4Addr::from(ipv4.get_destination().octets()));

                let transport = self.parse_l4_and_l7(
                    frame,
                    ethertype.0,
                    vlan_id,
                    NetworkInfo::Ipv4,
                    src,
                    dst,
                    ipv4.payload(),
                    ipv4.get_next_level_protocol(),
                    &mut extras,
                );

                (
                    Some(FlowKey {
                        src,
                        dst,
                        transport,
                        vlan_id,
                    }),
                    NetworkInfo::Ipv4,
                )
            }
            0x86DD => {
                let ipv6 = Ipv6Packet::new(l3_payload)?;
                let src = IpAddr::V6(Ipv6Addr::from(ipv6.get_source().octets()));
                let dst = IpAddr::V6(Ipv6Addr::from(ipv6.get_destination().octets()));

                let transport = self.parse_l4_and_l7(
                    frame,
                    ethertype.0,
                    vlan_id,
                    NetworkInfo::Ipv6,
                    src,
                    dst,
                    ipv6.payload(),
                    ipv6.get_next_header(),
                    &mut extras,
                );

                (
                    Some(FlowKey {
                        src,
                        dst,
                        transport,
                        vlan_id,
                    }),
                    NetworkInfo::Ipv6,
                )
            }
            0x0806 => {
                let _ = ArpPacket::new(l3_payload)?;
                (None, NetworkInfo::Arp)
            }
            _ => (None, NetworkInfo::Other),
        };

        // External protocol parsers (so/dll). These are called last and can add arbitrary fields.
        extras.extend(self.plugins.parse_extras(frame));

        Some(ParsedPacket {
            flow,
            network,
            ethertype: ethertype.0,
            payload_len: l3_payload.len(),
            extras,
        })
    }

    fn parse_l4_and_l7(
        &self,
        frame: &[u8],
        ethertype: u16,
        vlan_id: Option<u16>,
        network: NetworkInfo,
        src: IpAddr,
        dst: IpAddr,
        l4_bytes: &[u8],
        proto: IpNextHeaderProtocol,
        extras: &mut Vec<LayerExtra>,
    ) -> TransportInfo {
        let ip_proto = proto.0;
        match ip_proto {
            6 => {
                if let Some(tcp) = TcpPacket::new(l4_bytes) {
                    let transport = TransportInfo::Tcp {
                        src_port: tcp.get_source(),
                        dst_port: tcp.get_destination(),
                    };
                    let ctx = PacketContext {
                        frame,
                        ethertype,
                        vlan_id,
                        network,
                        ip_proto,
                        src: Some(src),
                        dst: Some(dst),
                        transport: transport.clone(),
                        l4_payload: tcp.payload(),
                    };
                    self.run_l7(
                        &ctx,
                        &self.tcp_by_port,
                        tcp.get_source(),
                        tcp.get_destination(),
                        extras,
                    );
                    // Also run any proto-level decoders that might apply.
                    self.run_ip_proto(&ctx, extras);
                    return transport;
                }
                TransportInfo::Other
            }
            17 => {
                if let Some(udp) = UdpPacket::new(l4_bytes) {
                    let transport = TransportInfo::Udp {
                        src_port: udp.get_source(),
                        dst_port: udp.get_destination(),
                    };
                    let ctx = PacketContext {
                        frame,
                        ethertype,
                        vlan_id,
                        network,
                        ip_proto,
                        src: Some(src),
                        dst: Some(dst),
                        transport: transport.clone(),
                        l4_payload: udp.payload(),
                    };
                    self.run_l7(
                        &ctx,
                        &self.udp_by_port,
                        udp.get_source(),
                        udp.get_destination(),
                        extras,
                    );
                    self.run_ip_proto(&ctx, extras);
                    return transport;
                }
                TransportInfo::Other
            }
            _ => {
                let ctx = PacketContext {
                    frame,
                    ethertype,
                    vlan_id,
                    network,
                    ip_proto,
                    src: Some(src),
                    dst: Some(dst),
                    transport: TransportInfo::Other,
                    l4_payload: l4_bytes,
                };
                self.run_ip_proto(&ctx, extras);
                TransportInfo::Other
            }
        }
    }

    fn run_ip_proto(&self, ctx: &PacketContext, extras: &mut Vec<LayerExtra>) {
        if let Some(parsers) = self.ip_by_proto.get(&ctx.ip_proto) {
            for p in parsers {
                if let Some(v) = p.parse(ctx) {
                    extras.push(LayerExtra {
                        plugin: p.name().to_string(),
                        data: v,
                    });
                }
            }
        }
    }

    fn run_l7(
        &self,
        ctx: &PacketContext,
        map: &HashMap<u16, Vec<Box<dyn L7Parser>>>,
        src_port: u16,
        dst_port: u16,
        extras: &mut Vec<LayerExtra>,
    ) {
        // Arkime does classification by both src/dst ports (client/server ambiguity).
        for port in [dst_port, src_port] {
            if let Some(parsers) = map.get(&port) {
                for p in parsers {
                    if let Some(v) = p.parse(ctx) {
                        extras.push(LayerExtra {
                            plugin: p.name().to_string(),
                            data: v,
                        });
                    }
                }
            }
        }
    }
}
