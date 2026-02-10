use crate::layer::{FlowKey, TransportInfo};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Default, Clone)]
pub struct SessionMetrics {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
struct SessionEntry {
    metrics: SessionMetrics,
    #[allow(dead_code)]
    first_seen: Instant,
    last_seen: Instant,
}

#[derive(Debug)]
pub struct SessionTable {
    sessions: HashMap<FlowKey, SessionEntry>,
    total_packets: u64,
    total_bytes: u64,
    tcp_timeout: Duration,
    udp_timeout: Duration,
    max_entries: usize,
}

impl Default for SessionTable {
    fn default() -> Self {
        let now = Instant::now();
        Self::new(
            Duration::from_secs(300),
            Duration::from_secs(resolve_udp_timeout_secs(0)),
            1_000_000,
            now,
        )
    }
}

impl SessionTable {
    pub fn new(tcp_timeout: Duration, udp_timeout: Duration, max_entries: usize, _now: Instant) -> Self {
        Self {
            sessions: HashMap::new(),
            total_packets: 0,
            total_bytes: 0,
            tcp_timeout,
            udp_timeout,
            max_entries,
        }
    }

    pub fn observe_packet(&mut self, flow: FlowKey, frame_len: usize, now: Instant) {
        self.total_packets += 1;
        self.total_bytes += frame_len as u64;

        if !self.sessions.contains_key(&flow) && self.sessions.len() >= self.max_entries {
            // Best-effort cap: evict an arbitrary session to keep memory bounded.
            if let Some(key) = self.sessions.keys().next().cloned() {
                self.sessions.remove(&key);
            }
        }

        let entry = self.sessions.entry(flow).or_insert_with(|| SessionEntry {
            metrics: SessionMetrics::default(),
            first_seen: now,
            last_seen: now,
        });

        entry.metrics.packets += 1;
        entry.metrics.bytes += frame_len as u64;
        entry.last_seen = now;
    }

    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.sessions.len();
        self.sessions.retain(|flow, entry| {
            let timeout = match flow.transport {
                TransportInfo::Tcp { .. } => self.tcp_timeout,
                TransportInfo::Udp { .. } => self.udp_timeout,
                TransportInfo::Other => self.udp_timeout,
            };
            now.duration_since(entry.last_seen) <= timeout
        });
        before.saturating_sub(self.sessions.len())
    }

    pub fn totals(&self) -> (u64, u64, usize) {
        (self.total_packets, self.total_bytes, self.sessions.len())
    }
}

/// Resolve UDP session timeout from config.
/// If `configured_secs` is 0, attempts to read OS/kernel defaults (Linux conntrack) and otherwise falls back.
pub fn resolve_udp_timeout_secs(configured_secs: u64) -> u64 {
    if configured_secs > 0 {
        return configured_secs;
    }

    #[cfg(target_os = "linux")]
    {
        // Typical defaults: nf_conntrack_udp_timeout=30, nf_conntrack_udp_timeout_stream=180
        if let Ok(s) = std::fs::read_to_string("/proc/sys/net/netfilter/nf_conntrack_udp_timeout") {
            if let Ok(v) = s.trim().parse::<u64>() {
                if v > 0 {
                    return v;
                }
            }
        }
        if let Ok(s) =
            std::fs::read_to_string("/proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream")
        {
            if let Ok(v) = s.trim().parse::<u64>() {
                if v > 0 {
                    return v;
                }
            }
        }
    }

    30
}

#[cfg(test)]
mod tests {
    use super::SessionTable;
    use crate::layer::{FlowKey, TransportInfo};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    #[test]
    fn aggregate_packets_by_flow() {
        let now = Instant::now();
        let mut table = SessionTable::new(Duration::from_secs(300), Duration::from_secs(30), 1000, now);
        let flow = FlowKey {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            transport: TransportInfo::Tcp {
                src_port: 12345,
                dst_port: 80,
            },
            vlan_id: None,
        };

        table.observe_packet(flow.clone(), 64, now);
        table.observe_packet(flow, 128, now);

        let (packets, bytes, sessions) = table.totals();
        assert_eq!(packets, 2);
        assert_eq!(bytes, 192);
        assert_eq!(sessions, 1);
    }
}
