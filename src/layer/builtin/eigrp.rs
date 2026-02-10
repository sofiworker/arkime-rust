use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct EigrpParser;

impl L7Parser for EigrpParser {
    fn name(&self) -> &'static str {
        "eigrp"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        // IP protocol 88
        if ctx.ip_proto != 88 {
            return None;
        }
        let p = ctx.l4_payload;
        if p.len() < 20 {
            return None;
        }
        let ver = p[0];
        let opcode = p[1];
        let flags = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
        let seq = u32::from_be_bytes([p[8], p[9], p[10], p[11]]);
        let ack = u32::from_be_bytes([p[12], p[13], p[14], p[15]]);
        let asn = u16::from_be_bytes([p[16], p[17]]);

        Some(json!({
            "version": ver,
            "opcode": opcode,
            "flags": flags,
            "seq": seq,
            "ack": ack,
            "as": asn
        }))
    }
}

