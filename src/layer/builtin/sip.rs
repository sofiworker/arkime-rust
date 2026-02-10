use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct SipParser;

impl L7Parser for SipParser {
    fn name(&self) -> &'static str {
        "sip"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        // SIP is text-based (RFC 3261). We only do a per-packet heuristic parse.
        let p = ctx.l4_payload;
        if p.len() < 8 {
            return None;
        }
        let s = std::str::from_utf8(&p[..p.len().min(4096)]).ok()?;
        let first_line = s.lines().next()?.trim_end_matches('\r');
        if first_line.is_empty() {
            return None;
        }

        let mut it = first_line.split_whitespace();
        let a = it.next()?;
        let b = it.next().unwrap_or("");
        let c = it.next().unwrap_or("");

        let kind: &str;
        let mut method = None;
        let mut uri = None;
        let mut status = None;

        if a.starts_with("SIP/2.0") {
            // Response: SIP/2.0 200 OK
            kind = "response";
            status = b.parse::<u16>().ok();
        } else if c.starts_with("SIP/2.0") {
            // Request: INVITE sip:user@domain SIP/2.0
            kind = "request";
            method = Some(a.to_string());
            uri = Some(b.to_string());
        } else {
            return None;
        }

        // Lightweight header extraction.
        let mut call_id = None;
        let mut from = None;
        let mut to = None;
        let mut cseq = None;

        for line in s.lines().skip(1) {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                break;
            }
            if let Some(v) = header_val(line, "Call-ID").or_else(|| header_val(line, "i")) {
                call_id = Some(v.to_string());
            } else if let Some(v) = header_val(line, "From").or_else(|| header_val(line, "f")) {
                from = Some(v.to_string());
            } else if let Some(v) = header_val(line, "To").or_else(|| header_val(line, "t")) {
                to = Some(v.to_string());
            } else if let Some(v) = header_val(line, "CSeq") {
                cseq = Some(v.to_string());
            }
            if call_id.is_some() && from.is_some() && to.is_some() && cseq.is_some() {
                break;
            }
        }

        Some(json!({
            "kind": kind,
            "method": method,
            "uri": uri,
            "status": status,
            "call_id": call_id,
            "from": from,
            "to": to,
            "cseq": cseq
        }))
    }
}

fn header_val<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    if line.len() < name.len() + 1 {
        return None;
    }
    if !line[..name.len()].eq_ignore_ascii_case(name) {
        return None;
    }
    let rest = line[name.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    Some(rest)
}
