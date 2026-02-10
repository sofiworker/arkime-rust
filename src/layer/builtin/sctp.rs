use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct SctpParser;

impl L7Parser for SctpParser {
    fn name(&self) -> &'static str {
        "sctp"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        // IP protocol 132
        if ctx.ip_proto != 132 {
            return None;
        }
        let p = ctx.l4_payload;
        if p.len() < 12 {
            return None;
        }
        let src_port = u16::from_be_bytes([p[0], p[1]]);
        let dst_port = u16::from_be_bytes([p[2], p[3]]);
        let vtag = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
        let crc = u32::from_le_bytes([p[8], p[9], p[10], p[11]]); // SCTP uses CRC32c LE

        Some(json!({
            "src_port": src_port,
            "dst_port": dst_port,
            "vtag": vtag,
            "crc32c": crc
        }))
    }
}

