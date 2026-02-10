use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct MysqlParser;

impl L7Parser for MysqlParser {
    fn name(&self) -> &'static str {
        "mysql"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        let p = ctx.l4_payload;
        // MySQL packets have 4-byte header: 3-byte length + 1-byte seq
        if p.len() < 5 {
            return None;
        }
        let len = (p[0] as usize) | ((p[1] as usize) << 8) | ((p[2] as usize) << 16);
        let seq = p[3];
        if len == 0 || 4 + len > p.len() {
            // might be truncated; still allow heuristics
        }

        let payload = &p[4..];
        if payload.is_empty() {
            return None;
        }

        // Server handshake starts with protocol version 0x0a.
        if payload[0] == 0x0a {
            let server_version = read_cstring(&payload[1..]).unwrap_or_default();
            return Some(json!({
                "type": "handshake",
                "seq": seq,
                "server_version": server_version
            }));
        }

        // Client command packet starts with command byte.
        let cmd = payload[0];
        if cmd <= 0x1f {
            return Some(json!({
                "type": "command",
                "seq": seq,
                "cmd": cmd
            }));
        }

        None
    }
}

fn read_cstring(b: &[u8]) -> Option<String> {
    let end = b.iter().position(|x| *x == 0)?;
    std::str::from_utf8(&b[..end]).ok().map(|s| s.to_string())
}

