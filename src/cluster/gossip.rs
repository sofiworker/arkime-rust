use crate::cluster::metadata::{now_millis, LwwMap, LwwValue};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct GossipConfig {
    pub node_id: String,
    pub bind_addr: SocketAddr,
    pub peers: Vec<SocketAddr>,
    pub heartbeat_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
enum GossipMsg {
    Heartbeat {
        node_id: String,
        ts_millis: u64,
        snapshot: Vec<(String, LwwValue)>,
    },
    Set {
        key: String,
        value: LwwValue,
    },
}

#[derive(Clone)]
pub struct GossipCluster {
    cfg: GossipConfig,
    store: Arc<Mutex<LwwMap>>,
}

impl GossipCluster {
    pub fn new(cfg: GossipConfig) -> Self {
        Self {
            cfg,
            store: Arc::new(Mutex::new(LwwMap::default())),
        }
    }

    pub fn store(&self) -> Arc<Mutex<LwwMap>> {
        Arc::clone(&self.store)
    }

    pub fn set_json(&self, key: &str, value: Value) {
        let v = LwwValue {
            ts_millis: now_millis(),
            node_id: self.cfg.node_id.clone(),
            value,
        };
        if let Ok(mut s) = self.store.lock() {
            s.set(key.to_string(), v.clone());
        }
        // Best-effort: direct send to peers is done by the heartbeat loop.
    }

    pub async fn run(self) -> io::Result<()> {
        let sock = UdpSocket::bind(self.cfg.bind_addr).await?;
        info!(
            "cluster.gossip bind={} peers={}",
            self.cfg.bind_addr,
            self.cfg.peers.len()
        );

        let rx_store = Arc::clone(&self.store);
        let tx_store = Arc::clone(&self.store);
        let peers = self.cfg.peers.clone();
        let node_id = self.cfg.node_id.clone();

        let mut tick = interval(Duration::from_secs(self.cfg.heartbeat_secs.max(1)));

        let mut buf = vec![0u8; 64 * 1024];

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    // Heartbeat: send snapshot to peers.
                    let snapshot = {
                        let s = tx_store.lock().expect("cluster store lock poisoned");
                        s.snapshot().into_iter().collect::<Vec<_>>()
                    };
                    let msg = GossipMsg::Heartbeat {
                        node_id: node_id.clone(),
                        ts_millis: now_millis(),
                        snapshot,
                    };
                    let bytes = match serde_json::to_vec(&msg) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("cluster.gossip serialize heartbeat failed: {}", e);
                            continue;
                        }
                    };

                    for p in &peers {
                        let _ = sock.send_to(&bytes, p).await;
                    }

                    // Also publish a local node heartbeat key for convenience.
                    if let Ok(mut s) = tx_store.lock() {
                        s.set(
                            format!("/nodes/{}/heartbeat", node_id),
                            LwwValue{
                                ts_millis: now_millis(),
                                node_id: node_id.clone(),
                                value: json!({"ok": true}),
                            },
                        );
                    }
                }
                recv = sock.recv_from(&mut buf) => {
                    let Ok((n, _src)) = recv else { continue };
                    let msg: GossipMsg = match serde_json::from_slice(&buf[..n]) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    match msg {
                        GossipMsg::Heartbeat { node_id: _other, ts_millis: _t, snapshot } => {
                            let mut m = std::collections::HashMap::new();
                            for (k, v) in snapshot {
                                m.insert(k, v);
                            }
                            if let Ok(mut s) = rx_store.lock() {
                                s.merge(m);
                            }
                        }
                        GossipMsg::Set { key, value } => {
                            if let Ok(mut s) = rx_store.lock() {
                                s.set(key, value);
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn parse_socket_addr(s: &str) -> io::Result<SocketAddr> {
    s.parse::<SocketAddr>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

