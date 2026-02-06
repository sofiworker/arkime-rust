use crate::layer::FlowKey;
use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct SessionMetrics {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Default)]
pub struct SessionTable {
    sessions: HashMap<FlowKey, SessionMetrics>,
    total_packets: u64,
    total_bytes: u64,
}

impl SessionTable {
    pub fn observe_packet(&mut self, flow: FlowKey, frame_len: usize) {
        self.total_packets += 1;
        self.total_bytes += frame_len as u64;

        let entry = self.sessions.entry(flow).or_default();
        entry.packets += 1;
        entry.bytes += frame_len as u64;
    }

    pub fn totals(&self) -> (u64, u64, usize) {
        (self.total_packets, self.total_bytes, self.sessions.len())
    }
}

#[cfg(test)]
mod tests {
    use super::SessionTable;
    use crate::layer::{FlowKey, TransportInfo};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn aggregate_packets_by_flow() {
        let mut table = SessionTable::default();
        let flow = FlowKey {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            transport: TransportInfo::Tcp {
                src_port: 12345,
                dst_port: 80,
            },
            vlan_id: None,
        };

        table.observe_packet(flow.clone(), 64);
        table.observe_packet(flow, 128);

        let (packets, bytes, sessions) = table.totals();
        assert_eq!(packets, 2);
        assert_eq!(bytes, 192);
        assert_eq!(sessions, 1);
    }
}
