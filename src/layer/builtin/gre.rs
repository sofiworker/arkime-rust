use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct GreParser;

impl L7Parser for GreParser {
    fn name(&self) -> &'static str {
        "gre"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        // IPv4 GRE is proto 47.
        if ctx.ip_proto != 47 {
            return None;
        }
        let p = ctx.l4_payload;
        if p.len() < 4 {
            return None;
        }

        let flags_version = u16::from_be_bytes([p[0], p[1]]);
        let proto = u16::from_be_bytes([p[2], p[3]]);

        // Minimal GRE header: flags/version + protocol type.
        let version = flags_version & 0x0007;
        let checksum_present = (flags_version & 0x8000) != 0;
        let key_present = (flags_version & 0x2000) != 0;
        let seq_present = (flags_version & 0x1000) != 0;
        let routing_present = (flags_version & 0x4000) != 0;

        // Compute header length (base 4 + optional fields).
        let mut off = 4usize;
        if checksum_present || routing_present {
            // checksum(2) + reserved(2)
            off += 4;
        }
        if key_present {
            off += 4;
        }
        if seq_present {
            off += 4;
        }

        Some(json!({
            "version": version,
            "protocol_type": format!("0x{:04x}", proto),
            "checksum_present": checksum_present,
            "routing_present": routing_present,
            "key_present": key_present,
            "seq_present": seq_present,
            "header_len": off
        }))
    }
}

