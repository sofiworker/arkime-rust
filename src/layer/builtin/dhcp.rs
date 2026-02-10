use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};
use std::net::Ipv4Addr;

pub struct DhcpParser;

impl L7Parser for DhcpParser {
    fn name(&self) -> &'static str {
        "dhcp"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        let p = ctx.l4_payload;
        // BOOTP fixed header is 236 bytes + 4 cookie
        if p.len() < 240 {
            return None;
        }

        let op = p[0];
        let hlen = p[2] as usize;
        let xid = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
        let ciaddr = Ipv4Addr::new(p[12], p[13], p[14], p[15]).to_string();
        let yiaddr = Ipv4Addr::new(p[16], p[17], p[18], p[19]).to_string();
        let siaddr = Ipv4Addr::new(p[20], p[21], p[22], p[23]).to_string();
        let giaddr = Ipv4Addr::new(p[24], p[25], p[26], p[27]).to_string();

        // client hardware address (first 16 bytes; only first hlen meaningful)
        let chaddr = if hlen >= 6 && p.len() >= 28 + 6 {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                p[28], p[29], p[30], p[31], p[32], p[33]
            )
        } else {
            String::new()
        };

        // Magic cookie
        if &p[236..240] != [99, 130, 83, 99] {
            return None;
        }

        let mut msg_type: Option<u8> = None;
        let mut hostname: Option<String> = None;
        let mut requested_ip: Option<String> = None;
        let mut server_id: Option<String> = None;

        let mut i = 240;
        while i < p.len() {
            let opt = p[i];
            i += 1;
            match opt {
                0 => continue,    // pad
                255 => break,     // end
                _ => {
                    if i >= p.len() {
                        break;
                    }
                    let len = p[i] as usize;
                    i += 1;
                    if i + len > p.len() {
                        break;
                    }
                    let data = &p[i..i + len];
                    i += len;

                    match opt {
                        53 if len == 1 => msg_type = Some(data[0]),
                        12 => hostname = std::str::from_utf8(data).ok().map(|s| s.to_string()),
                        50 if len == 4 => {
                            requested_ip = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string())
                        }
                        54 if len == 4 => {
                            server_id = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string())
                        }
                        _ => {}
                    }
                }
            }
        }

        Some(json!({
            "op": op,
            "xid": xid,
            "chaddr": chaddr,
            "ciaddr": ciaddr,
            "yiaddr": yiaddr,
            "siaddr": siaddr,
            "giaddr": giaddr,
            "msg_type": msg_type,
            "hostname": hostname,
            "requested_ip": requested_ip,
            "server_id": server_id
        }))
    }
}

