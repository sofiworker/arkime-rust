use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct VrrpParser;

impl L7Parser for VrrpParser {
    fn name(&self) -> &'static str {
        "vrrp"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        // IP protocol 112
        if ctx.ip_proto != 112 {
            return None;
        }
        let p = ctx.l4_payload;
        if p.len() < 8 {
            return None;
        }
        let ver = p[0] >> 4;
        let typ = p[0] & 0x0f;
        let vrid = p[1];
        let priority = p[2];
        let count_ip = p[3];
        let adv_interval = p[5];

        Some(json!({
            "version": ver,
            "type": typ,
            "vrid": vrid,
            "priority": priority,
            "count_ip": count_ip,
            "advert_interval": adv_interval
        }))
    }
}

