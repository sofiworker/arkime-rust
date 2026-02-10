use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct MemcachedParser;

impl L7Parser for MemcachedParser {
    fn name(&self) -> &'static str {
        "memcached"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        let p = ctx.l4_payload;
        if p.len() < 4 {
            return None;
        }

        // Binary protocol magic is 0x80 (request) or 0x81 (response).
        if p[0] == 0x80 || p[0] == 0x81 {
            if p.len() < 24 {
                return None;
            }
            let opcode = p[1];
            let key_len = u16::from_be_bytes([p[2], p[3]]);
            let total_body = u32::from_be_bytes([p[8], p[9], p[10], p[11]]);
            return Some(json!({
                "proto": "binary",
                "magic": p[0],
                "opcode": opcode,
                "key_len": key_len,
                "total_body": total_body
            }));
        }

        // ASCII protocol: one line command.
        let end = p
            .windows(2)
            .position(|w| w == b"\r\n")
            .or_else(|| p.iter().position(|b| *b == b'\n'))
            .unwrap_or(p.len());
        let line = &p[..end.min(256)];
        let s = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
        let cmd = s.split_whitespace().next().unwrap_or("");
        if !is_ascii_cmd(cmd) {
            return None;
        }
        Some(json!({
            "proto": "ascii",
            "cmd": cmd,
            "line": s
        }))
    }
}

fn is_ascii_cmd(cmd: &str) -> bool {
    matches!(
        cmd,
        "get"
            | "gets"
            | "set"
            | "add"
            | "replace"
            | "append"
            | "prepend"
            | "cas"
            | "delete"
            | "incr"
            | "decr"
            | "touch"
            | "stats"
            | "version"
            | "quit"
    )
}

