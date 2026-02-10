use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct OspfParser;

impl L7Parser for OspfParser {
    fn name(&self) -> &'static str {
        "ospf"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        // IP protocol 89
        if ctx.ip_proto != 89 {
            return None;
        }
        let p = ctx.l4_payload;
        if p.len() < 24 {
            return None;
        }
        let ver = p[0];
        let typ = p[1];
        let len = u16::from_be_bytes([p[2], p[3]]) as usize;
        let router_id = format!("{}.{}.{}.{}", p[4], p[5], p[6], p[7]);
        let area_id = format!("{}.{}.{}.{}", p[8], p[9], p[10], p[11]);
        let auth_type = u16::from_be_bytes([p[14], p[15]]);

        Some(json!({
            "version": ver,
            "type": typ,
            "len": len,
            "router_id": router_id,
            "area_id": area_id,
            "auth_type": auth_type
        }))
    }
}

