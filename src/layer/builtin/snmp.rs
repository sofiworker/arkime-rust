use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct SnmpParser;

impl L7Parser for SnmpParser {
    fn name(&self) -> &'static str {
        "snmp"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        let p = ctx.l4_payload;
        // SNMP is BER/ASN.1. We do a minimal sanity check for SEQUENCE.
        if p.len() < 8 {
            return None;
        }
        if p[0] != 0x30 {
            return None;
        }
        let (seq_len, hdr) = ber_len(&p[1..])?;
        let _ = seq_len;

        // Next: INTEGER version
        let mut off = 1 + hdr;
        if off + 2 > p.len() || p[off] != 0x02 {
            return None;
        }
        let (vlen, vh) = ber_len(&p[off + 1..])?;
        off += 1 + vh;
        if off + vlen > p.len() || vlen == 0 || vlen > 4 {
            return None;
        }
        let mut ver = 0u32;
        for &b in &p[off..off + vlen] {
            ver = (ver << 8) | (b as u32);
        }

        Some(json!({
            "version": ver
        }))
    }
}

fn ber_len(b: &[u8]) -> Option<(usize, usize)> {
    if b.is_empty() {
        return None;
    }
    let x = b[0];
    if (x & 0x80) == 0 {
        return Some((x as usize, 1));
    }
    let n = (x & 0x7f) as usize;
    if n == 0 || n > 4 || b.len() < 1 + n {
        return None;
    }
    let mut v = 0usize;
    for &bb in &b[1..1 + n] {
        v = (v << 8) | (bb as usize);
    }
    Some((v, 1 + n))
}

