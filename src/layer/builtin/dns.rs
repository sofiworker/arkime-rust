use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct DnsParser;

impl L7Parser for DnsParser {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        if ctx.l4_payload.len() < 12 {
            return None;
        }

        let flags = u16::from_be_bytes([ctx.l4_payload[2], ctx.l4_payload[3]]);
        let opcode = (flags >> 11) & 0x0f;
        let rcode = flags & 0x0f;
        if opcode > 5 || rcode > 15 {
            return None;
        }

        let id = u16::from_be_bytes([ctx.l4_payload[0], ctx.l4_payload[1]]);
        let qd = u16::from_be_bytes([ctx.l4_payload[4], ctx.l4_payload[5]]);
        let an = u16::from_be_bytes([ctx.l4_payload[6], ctx.l4_payload[7]]);
        let ns = u16::from_be_bytes([ctx.l4_payload[8], ctx.l4_payload[9]]);
        let ar = u16::from_be_bytes([ctx.l4_payload[10], ctx.l4_payload[11]]);

        Some(json!({
            "id": id,
            "opcode": opcode,
            "rcode": rcode,
            "qdcount": qd,
            "ancount": an,
            "nscount": ns,
            "arcount": ar
        }))
    }
}

