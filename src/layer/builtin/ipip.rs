use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct IpInIpParser; // proto 4
pub struct Ipv6InIpv4Parser; // proto 41

impl L7Parser for IpInIpParser {
    fn name(&self) -> &'static str {
        "ipip"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        if ctx.ip_proto != 4 {
            return None;
        }
        parse_inner_ip(ctx.l4_payload)
            .map(|inner| json!({ "inner": inner, "proto": 4 }))
    }
}

impl L7Parser for Ipv6InIpv4Parser {
    fn name(&self) -> &'static str {
        "ipv6_in_ipv4"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        if ctx.ip_proto != 41 {
            return None;
        }
        parse_inner_ip(ctx.l4_payload)
            .map(|inner| json!({ "inner": inner, "proto": 41 }))
    }
}

fn parse_inner_ip(p: &[u8]) -> Option<Value> {
    if p.is_empty() {
        return None;
    }
    let ver = p[0] >> 4;
    if ver == 4 {
        if p.len() < 20 {
            return Some(json!({ "version": 4 }));
        }
        let ihl = (p[0] & 0x0f) as usize * 4;
        if ihl < 20 || ihl > p.len() {
            return Some(json!({ "version": 4 }));
        }
        let proto = p[9];
        let src = format!("{}.{}.{}.{}", p[12], p[13], p[14], p[15]);
        let dst = format!("{}.{}.{}.{}", p[16], p[17], p[18], p[19]);
        return Some(json!({
            "version": 4,
            "proto": proto,
            "src": src,
            "dst": dst
        }));
    }
    if ver == 6 {
        if p.len() < 40 {
            return Some(json!({ "version": 6 }));
        }
        let next = p[6];
        let src = hex16(&p[8..24]);
        let dst = hex16(&p[24..40]);
        return Some(json!({
            "version": 6,
            "next_header": next,
            "src": src,
            "dst": dst
        }));
    }
    None
}

fn hex16(b: &[u8]) -> String {
    // Not a full RFC5952 formatter, just stable output.
    let mut s = String::new();
    for (i, ch) in b.chunks(2).enumerate() {
        if i > 0 {
            s.push(':');
        }
        if ch.len() == 2 {
            s.push_str(&format!("{:02x}{:02x}", ch[0], ch[1]));
        }
    }
    s
}

