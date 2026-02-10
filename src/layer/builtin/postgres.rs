use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct PostgresParser;

impl L7Parser for PostgresParser {
    fn name(&self) -> &'static str {
        "postgres"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        let p = ctx.l4_payload;
        if p.len() < 8 {
            return None;
        }

        // Startup packet: int32 len, int32 protocol
        let len = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as usize;
        let code = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
        if len < 8 {
            return None;
        }

        // SSLRequest (80877103), CancelRequest (80877102), Startup (196608 == 3.0)
        if code == 80877103 {
            return Some(json!({ "type": "ssl_request", "len": len }));
        }
        if code == 80877102 {
            return Some(json!({ "type": "cancel_request", "len": len }));
        }
        if code == 196608 {
            // Parse key/value pairs (user, database) best-effort.
            let mut user = None;
            let mut db = None;
            let data = &p[8..p.len().min(len)];
            let mut parts = data.split(|b| *b == 0);
            loop {
                let k = parts.next()?;
                if k.is_empty() {
                    break;
                }
                let v = parts.next().unwrap_or(&[]);
                let ks = std::str::from_utf8(k).ok()?;
                let vs = std::str::from_utf8(v).ok().unwrap_or("");
                if ks == "user" {
                    user = Some(vs.to_string());
                } else if ks == "database" {
                    db = Some(vs.to_string());
                }
                if user.is_some() && db.is_some() {
                    break;
                }
            }
            return Some(json!({
                "type": "startup",
                "len": len,
                "protocol": "3.0",
                "user": user,
                "database": db
            }));
        }

        None
    }
}

