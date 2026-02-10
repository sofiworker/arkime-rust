use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct IcmpParser;
pub struct Icmpv6Parser;

impl L7Parser for IcmpParser {
    fn name(&self) -> &'static str {
        "icmp"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        if ctx.ip_proto != 1 {
            return None;
        }
        let p = ctx.l4_payload;
        if p.len() < 4 {
            return None;
        }
        let typ = p[0];
        let code = p[1];

        // Echo request/reply have id/seq at bytes 4..8
        let mut id = None;
        let mut seq = None;
        if (typ == 8 || typ == 0) && p.len() >= 8 {
            id = Some(u16::from_be_bytes([p[4], p[5]]));
            seq = Some(u16::from_be_bytes([p[6], p[7]]));
        }

        Some(json!({
            "type": typ,
            "code": code,
            "id": id,
            "seq": seq
        }))
    }
}

impl L7Parser for Icmpv6Parser {
    fn name(&self) -> &'static str {
        "icmpv6"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        if ctx.ip_proto != 58 {
            return None;
        }
        let p = ctx.l4_payload;
        if p.len() < 4 {
            return None;
        }
        let typ = p[0];
        let code = p[1];

        let mut id = None;
        let mut seq = None;
        if (typ == 128 || typ == 129) && p.len() >= 8 {
            id = Some(u16::from_be_bytes([p[4], p[5]]));
            seq = Some(u16::from_be_bytes([p[6], p[7]]));
        }

        Some(json!({
            "type": typ,
            "code": code,
            "id": id,
            "seq": seq
        }))
    }
}

