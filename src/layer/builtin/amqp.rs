use crate::layer::engine::{L7Parser, PacketContext};
use serde_json::{json, Value};

pub struct AmqpParser;

impl L7Parser for AmqpParser {
    fn name(&self) -> &'static str {
        "amqp"
    }

    fn parse(&self, ctx: &PacketContext) -> Option<Value> {
        let p = ctx.l4_payload;
        if p.len() < 8 {
            return None;
        }
        // AMQP protocol header: "AMQP" 0 0 9 1 for 0-9-1
        if &p[..4] != b"AMQP" {
            return None;
        }
        let v0 = p[4];
        let v1 = p[5];
        let v2 = p[6];
        let v3 = p[7];
        Some(json!({
            "magic": "AMQP",
            "version": [v0, v1, v2, v3]
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::engine::PacketContext;
    use crate::layer::{NetworkInfo, TransportInfo};

    #[test]
    fn parses_amqp_protocol_header() {
        let payload = [b'A', b'M', b'Q', b'P', 0, 0, 9, 1];
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
                dst_port: 5672,
            },
            l4_payload: &payload,
        };
        let v = AmqpParser.parse(&ctx).unwrap();
        assert_eq!(v["magic"], "AMQP");
        assert_eq!(v["version"][2], 9);
    }
}
