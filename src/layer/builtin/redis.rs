use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct RedisParser;

impl L7Parser for RedisParser {
    fn name(&self) -> &'static str {
        "redis"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        let p = ctx.l4_payload;
        if p.len() < 3 {
            return None;
        }

        // RESP starts with one of: + - : $ *
        let first = p[0];
        if !matches!(first, b'+' | b'-' | b':' | b'$' | b'*') {
            return None;
        }

        // Capture a short preview line (up to first CRLF/LF).
        let end = p
            .windows(2)
            .position(|w| w == b"\r\n")
            .or_else(|| p.iter().position(|b| *b == b'\n'))
            .unwrap_or(p.len());
        let line = &p[..end.min(256)];
        let s = std::str::from_utf8(line).ok()?.trim_end_matches('\r');

        Some(json!({
            "first_byte": (first as char).to_string(),
            "line": s
        }))
    }
}

