use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct EspParser;

impl L7Parser for EspParser {
    fn name(&self) -> &'static str {
        "esp"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        // IP protocol 50
        if ctx.ip_proto != 50 {
            return None;
        }
        let p = ctx.l4_payload;
        if p.len() < 8 {
            return None;
        }
        let spi = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
        let seq = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
        Some(json!({
            "spi": spi,
            "seq": seq
        }))
    }
}

