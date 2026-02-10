use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct NtpParser;

impl L7Parser for NtpParser {
    fn name(&self) -> &'static str {
        "ntp"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        let p = ctx.l4_payload;
        if p.len() < 48 {
            return None;
        }
        let li_vn_mode = p[0];
        let li = (li_vn_mode >> 6) & 0x03;
        let vn = (li_vn_mode >> 3) & 0x07;
        let mode = li_vn_mode & 0x07;
        let stratum = p[1];
        let poll = p[2] as i8;
        let precision = p[3] as i8;
        Some(json!({
            "li": li,
            "version": vn,
            "mode": mode,
            "stratum": stratum,
            "poll": poll,
            "precision": precision
        }))
    }
}

