use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct PimParser;

impl L7Parser for PimParser {
    fn name(&self) -> &'static str {
        "pim"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        // IP protocol 103
        if ctx.ip_proto != 103 {
            return None;
        }
        let p = ctx.l4_payload;
        if p.len() < 4 {
            return None;
        }
        let ver = p[0] >> 4;
        let typ = p[0] & 0x0f;
        let checksum = u16::from_be_bytes([p[2], p[3]]);

        Some(json!({
            "version": ver,
            "type": typ,
            "checksum": checksum
        }))
    }
}

