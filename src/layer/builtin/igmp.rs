use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct IgmpParser;

impl L7Parser for IgmpParser {
    fn name(&self) -> &'static str {
        "igmp"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        // IP protocol 2
        if ctx.ip_proto != 2 {
            return None;
        }
        let p = ctx.l4_payload;
        if p.len() < 8 {
            return None;
        }
        let typ = p[0];
        let max_resp = p[1];
        let group = format!("{}.{}.{}.{}", p[4], p[5], p[6], p[7]);

        Some(json!({
            "type": typ,
            "max_resp_time": max_resp,
            "group": group
        }))
    }
}

