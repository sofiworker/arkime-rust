use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct MqttParser;

impl L7Parser for MqttParser {
    fn name(&self) -> &'static str {
        "mqtt"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        let p = ctx.l4_payload;
        if p.len() < 2 {
            return None;
        }

        // MQTT fixed header: 1st byte type/flags, then Remaining Length (varint).
        let first = p[0];
        let msg_type = first >> 4;
        if msg_type == 0 || msg_type > 15 {
            return None;
        }
        let (rem_len, consumed) = decode_varint(&p[1..])?;
        let total = 1 + consumed + rem_len;
        if total > p.len() {
            // Packet may be truncated; still treat as MQTT if header looks valid.
        }

        // CONNECT packet has variable header that starts with protocol name length + "MQTT".
        let mut proto = None;
        if msg_type == 1 {
            let vh = 1 + consumed;
            if vh + 2 <= p.len() {
                let nlen = u16::from_be_bytes([p[vh], p[vh + 1]]) as usize;
                if vh + 2 + nlen <= p.len() {
                    if let Ok(s) = std::str::from_utf8(&p[vh + 2..vh + 2 + nlen]) {
                        proto = Some(s.to_string());
                    }
                }
            }
        }

        Some(json!({
            "type": msg_type,
            "flags": first & 0x0f,
            "remaining_len": rem_len,
            "protocol": proto
        }))
    }
}

fn decode_varint(b: &[u8]) -> Option<(usize, usize)> {
    let mut mul = 1usize;
    let mut val = 0usize;
    let mut i = 0usize;
    for &x in b.iter().take(4) {
        i += 1;
        val += ((x & 0x7f) as usize) * mul;
        if (x & 0x80) == 0 {
            return Some((val, i));
        }
        mul *= 128;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::engine::PacketContext;
    use crate::layer::{NetworkInfo, TransportInfo};

    #[test]
    fn parses_mqtt_connect_header() {
        // CONNECT with protocol name "MQTT" (length=4), version=4.
        // Fixed header: type=1, remaining length=10
        let payload = [
            0x10, 0x0a, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c,
        ];
        let ctx = PacketContext {
            frame: &payload,
            ethertype: 0x0800,
            vlan_id: None,
            network: NetworkInfo::Ipv4,
            ip_proto: 6,
            src: None,
            dst: None,
            transport: TransportInfo::Tcp {
                src_port: 12345,
                dst_port: 1883,
            },
            l4_payload: &payload,
        };
        let v = MqttParser.parse(&ctx).unwrap();
        assert_eq!(v["type"], 1);
        assert_eq!(v["protocol"], "MQTT");
    }
}
