use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct StunParser;

impl L7Parser for StunParser {
    fn name(&self) -> &'static str {
        "stun"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        let p = ctx.l4_payload;
        if p.len() < 20 {
            return None;
        }

        // STUN message format:
        // 0..2: type, 2..4: length, 4..8: magic cookie (0x2112A442), 8..20: transaction id
        let typ = u16::from_be_bytes([p[0], p[1]]);
        let len = u16::from_be_bytes([p[2], p[3]]) as usize;
        let cookie = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
        if cookie != 0x2112_A442 {
            return None;
        }
        if 20 + len > p.len() {
            // May be truncated; still consider it STUN.
        }

        let method = typ & 0x0fef; // rough (not full RFC mapping)
        let klass = (typ & 0x0110) >> 4;
        let txid = hex(&p[8..20]);

        Some(json!({
            "type": typ,
            "len": len,
            "class": klass,
            "method": method,
            "txid": txid
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

