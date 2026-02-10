use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct QuicParser;

impl L7Parser for QuicParser {
    fn name(&self) -> &'static str {
        "quic"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        let p = ctx.l4_payload;
        if p.len() < 2 {
            return None;
        }

        // QUIC header form bit: 1 = long header, 0 = short header
        let first = p[0];
        let long_header = (first & 0x80) != 0;
        if !long_header {
            // Short header: we can't reliably parse without keys; still mark as QUIC-like.
            // Heuristic: fixed bit must be 1 in QUIC v1.
            if (first & 0x40) == 0 {
                return None;
            }
            return Some(json!({
                "header": "short",
                "first_byte": first
            }));
        }

        // Long header basic fields:
        // 0: flags, 1..4: version, then DCID len + DCID, SCID len + SCID.
        if p.len() < 6 {
            return None;
        }
        let ver = u32::from_be_bytes([p[1], p[2], p[3], p[4]]);
        let mut off = 5;
        let dcid_len = *p.get(off)? as usize;
        off += 1;
        if off + dcid_len > p.len() {
            return None;
        }
        let dcid = hex(&p[off..off + dcid_len]);
        off += dcid_len;

        let scid_len = *p.get(off)? as usize;
        off += 1;
        if off + scid_len > p.len() {
            return None;
        }
        let scid = hex(&p[off..off + scid_len]);

        Some(json!({
            "header": "long",
            "version": ver,
            "dcid": dcid,
            "scid": scid
        }))
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::engine::PacketContext;
    use crate::layer::{NetworkInfo, TransportInfo};

    #[test]
    fn parses_quic_long_header_dcid_scid() {
        // Minimal QUIC long header:
        // flags=0xc3, version=1, dcid_len=4, dcid=01020304, scid_len=2, scid=aabb
        let payload = [
            0xc3, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x02, 0x03, 0x04, 0x02, 0xaa, 0xbb,
        ];
        let ctx = PacketContext {
            frame: &payload,
            ethertype: 0x0800,
            vlan_id: None,
            network: NetworkInfo::Ipv4,
            ip_proto: 17,
            src: None,
            dst: None,
            transport: TransportInfo::Udp {
                src_port: 55555,
                dst_port: 443,
            },
            l4_payload: &payload,
        };
        let v = QuicParser.parse(&ctx).unwrap();
        assert_eq!(v["header"], "long");
        assert_eq!(v["version"], 1);
        assert_eq!(v["dcid"], "01020304");
        assert_eq!(v["scid"], "aabb");
    }
}
