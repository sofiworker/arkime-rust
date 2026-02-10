use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct HttpParser;

impl L7Parser for HttpParser {
    fn name(&self) -> &'static str {
        "http"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        let p = ctx.l4_payload;
        if p.len() < 16 {
            return None;
        }

        // Only parse HTTP/1.x plaintext heuristically (Arkime does stream-based parsing; we do per-packet).
        let first_line_end = find_crlf(p).or_else(|| find_lf(p))?;
        let first_line = &p[..first_line_end];
        let first_line_str = std::str::from_utf8(first_line).ok()?;

        if let Some(v) = parse_request_line(first_line_str) {
            let (host, ua) = parse_headers(&p[skip_newline(p, first_line_end)..]);
            return Some(json!({
                "type": "request",
                "method": v.method,
                "uri": v.uri,
                "version": v.version,
                "host": host,
                "user_agent": ua
            }));
        }

        if let Some(v) = parse_response_line(first_line_str) {
            return Some(json!({
                "type": "response",
                "version": v.version,
                "status": v.status,
                "reason": v.reason
            }));
        }

        None
    }
}

struct RequestLine<'a> {
    method: &'a str,
    uri: &'a str,
    version: &'a str,
}

struct ResponseLine<'a> {
    version: &'a str,
    status: u16,
    reason: &'a str,
}

fn parse_request_line(s: &str) -> Option<RequestLine<'_>> {
    let mut it = s.split_whitespace();
    let method = it.next()?;
    let uri = it.next()?;
    let version = it.next()?;
    if !is_http_method(method) {
        return None;
    }
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    Some(RequestLine {
        method,
        uri,
        version,
    })
}

fn parse_response_line(s: &str) -> Option<ResponseLine<'_>> {
    let mut it = s.split_whitespace();
    let version = it.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    let status_s = it.next()?;
    let status = status_s.parse::<u16>().ok()?;
    let reason = it.next().unwrap_or("");
    Some(ResponseLine {
        version,
        status,
        reason,
    })
}

fn is_http_method(m: &str) -> bool {
    matches!(
        m,
        "GET"
            | "POST"
            | "PUT"
            | "DELETE"
            | "HEAD"
            | "OPTIONS"
            | "PATCH"
            | "CONNECT"
            | "TRACE"
    )
}

fn parse_headers(bytes: &[u8]) -> (Option<String>, Option<String>) {
    // Scan up to 8KB for headers; stop at blank line.
    let scan = &bytes[..bytes.len().min(8192)];
    let s = match std::str::from_utf8(scan) {
        Ok(s) => s,
        Err(_) => return (None, None),
    };

    let mut host = None;
    let mut ua = None;

    for line in s.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if let Some(v) = line.strip_prefix("Host:").or_else(|| line.strip_prefix("host:")) {
            host = Some(v.trim().to_string());
        } else if let Some(v) = line
            .strip_prefix("User-Agent:")
            .or_else(|| line.strip_prefix("user-agent:"))
        {
            ua = Some(v.trim().to_string());
        }
        if host.is_some() && ua.is_some() {
            break;
        }
    }

    (host, ua)
}

fn find_crlf(p: &[u8]) -> Option<usize> {
    p.windows(2).position(|w| w == b"\r\n")
}

fn find_lf(p: &[u8]) -> Option<usize> {
    p.iter().position(|b| *b == b'\n')
}

fn skip_newline(p: &[u8], line_end: usize) -> usize {
    if line_end + 2 <= p.len() && &p[line_end..line_end + 2] == b"\r\n" {
        return line_end + 2;
    }
    if line_end + 1 <= p.len() && p[line_end] == b'\n' {
        return line_end + 1;
    }
    line_end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::engine::PacketContext;
    use crate::layer::{NetworkInfo, TransportInfo};

    #[test]
    fn parses_http_request_line_and_host() {
        let payload = b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let ctx = PacketContext {
            frame: payload,
            ethertype: 0x0800,
            vlan_id: None,
            network: NetworkInfo::Ipv4,
            ip_proto: 6,
            src: None,
            dst: None,
            transport: TransportInfo::Tcp {
                src_port: 12345,
                dst_port: 80,
            },
            l4_payload: payload,
        };
        let v = HttpParser.parse(&ctx).unwrap();
        assert_eq!(v["type"], "request");
        assert_eq!(v["method"], "GET");
        assert_eq!(v["host"], "example.com");
    }
}
