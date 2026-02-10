use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct AhParser;

impl L7Parser for AhParser {
    fn name(&self) -> &'static str {
        "ah"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        // IP protocol 51
        if ctx.ip_proto != 51 {
            return None;
        }
        let p = ctx.l4_payload;
        if p.len() < 12 {
            return None;
        }
        let next = p[0];
        let payload_len_words = p[1] as usize;
        let spi = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
        let seq = u32::from_be_bytes([p[8], p[9], p[10], p[11]]);
        // AH payload length is in 32-bit words, minus 2.
        let hdr_len = (payload_len_words + 2) * 4;
        Some(json!({
            "next_header": next,
            "spi": spi,
            "seq": seq,
            "header_len": hdr_len
        }))
    }
}

