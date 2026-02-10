use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct TlsParser;

impl L7Parser for TlsParser {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        let p = ctx.l4_payload;
        if p.len() < 5 {
            return None;
        }

        // TLS record header: type(1) version(2) len(2)
        let content_type = p[0];
        if content_type != 0x16 {
            // Only handshake for now
            return None;
        }
        let ver = u16::from_be_bytes([p[1], p[2]]);
        let rec_len = u16::from_be_bytes([p[3], p[4]]) as usize;
        if p.len() < 5 + rec_len {
            return None;
        }

        // Handshake message begins at offset 5
        if rec_len < 4 {
            return None;
        }
        let hs_type = p[5];
        if hs_type != 0x01 {
            // ClientHello only
            return Some(json!({
                "record_type": content_type,
                "version": ver,
                "handshake_type": hs_type
            }));
        }

        // Minimal ClientHello parse to extract SNI and ALPN if present.
        let mut off = 5;
        off += 1; // hs_type
        if off + 3 > p.len() {
            return None;
        }
        let hs_len = ((p[off] as usize) << 16) | ((p[off + 1] as usize) << 8) | (p[off + 2] as usize);
        off += 3;
        if off + hs_len > p.len() {
            return None;
        }

        if off + 2 + 32 + 1 > p.len() {
            return None;
        }
        let client_version = u16::from_be_bytes([p[off], p[off + 1]]);
        off += 2;
        off += 32; // random
        let sid_len = p[off] as usize;
        off += 1 + sid_len;
        if off + 2 > p.len() {
            return None;
        }
        let cs_len = u16::from_be_bytes([p[off], p[off + 1]]) as usize;
        off += 2 + cs_len;
        if off + 1 > p.len() {
            return None;
        }
        let comp_len = p[off] as usize;
        off += 1 + comp_len;

        if off + 2 > p.len() {
            return Some(json!({
                "record_type": content_type,
                "version": ver,
                "client_version": client_version
            }));
        }
        let ext_len = u16::from_be_bytes([p[off], p[off + 1]]) as usize;
        off += 2;
        if off + ext_len > p.len() {
            return None;
        }

        let exts = &p[off..off + ext_len];
        let (sni, alpn) = parse_extensions(exts);

        Some(json!({
            "record_type": content_type,
            "version": ver,
            "client_version": client_version,
            "sni": sni,
            "alpn": alpn
        }))
    }
}

fn parse_extensions(exts: &[u8]) -> (Option<String>, Option<Vec<String>>) {
    let mut i = 0;
    let mut sni = None;
    let mut alpn = None;

    while i + 4 <= exts.len() {
        let typ = u16::from_be_bytes([exts[i], exts[i + 1]]);
        let len = u16::from_be_bytes([exts[i + 2], exts[i + 3]]) as usize;
        i += 4;
        if i + len > exts.len() {
            break;
        }
        let data = &exts[i..i + len];
        i += len;

        match typ {
            0x0000 => {
                // server_name
                if data.len() < 2 {
                    continue;
                }
                let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if data.len() < 2 + list_len || list_len < 3 {
                    continue;
                }
                let mut j = 2;
                while j + 3 <= 2 + list_len {
                    let name_type = data[j];
                    let name_len = u16::from_be_bytes([data[j + 1], data[j + 2]]) as usize;
                    j += 3;
                    if j + name_len > data.len() {
                        break;
                    }
                    if name_type == 0 {
                        if let Ok(host) = std::str::from_utf8(&data[j..j + name_len]) {
                            sni = Some(host.to_string());
                            break;
                        }
                    }
                    j += name_len;
                }
            }
            0x0010 => {
                // ALPN
                if data.len() < 2 {
                    continue;
                }
                let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if data.len() < 2 + list_len {
                    continue;
                }
                let mut protos = Vec::new();
                let mut j = 2;
                while j < 2 + list_len {
                    let l = data[j] as usize;
                    j += 1;
                    if j + l > data.len() {
                        break;
                    }
                    if let Ok(s) = std::str::from_utf8(&data[j..j + l]) {
                        protos.push(s.to_string());
                    }
                    j += l;
                }
                if !protos.is_empty() {
                    alpn = Some(protos);
                }
            }
            _ => {}
        }
    }

    (sni, alpn)
}

