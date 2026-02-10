use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct SshParser;

impl L7Parser for SshParser {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        let p = ctx.l4_payload;
        if p.len() < 4 {
            return None;
        }
        if !p.starts_with(b"SSH-") {
            return None;
        }
        let end = p.iter().position(|b| *b == b'\n').unwrap_or(p.len());
        let line = &p[..end];
        let s = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
        Some(json!({ "banner": s }))
    }
}

