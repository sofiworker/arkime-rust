use crate::capture::backend::build_backend;
use crate::capture::interface::{InterfaceHandler, InterfaceState};
use crate::conf::ArkimeConfig;
use crate::core::session::{resolve_udp_timeout_secs, SessionTable};
use crate::filter::PacketFilter;
use crate::layer::engine::LayerEngine;
use crate::pcap::PacketRecorder;
use crate::plugins::PluginManager;
use crate::route::render_stats;
use crate::service::RuntimeStats;
use serde_json::json;
use pnet::datalink::NetworkInterface;
use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};
use tracing::info;

pub struct Capture {
    config: ArkimeConfig,
}

#[derive(Clone)]
struct CapturedFrame {
    iface: String,
    data: Vec<u8>,
}

#[derive(Clone)]
enum InterfaceEvent {
    Added(NetworkInterface),
    Removed(String),
}

struct ProcessState {
    session_table: SessionTable,
    plugins: PluginManager,
    recorder: PacketRecorder,
    layer_engine: LayerEngine,
}

struct InterfaceTask {
    stop: Arc<AtomicBool>,
    // Dropping this permit returns capacity to the pool ("thread returned to pool").
    _permit: tokio::sync::OwnedSemaphorePermit,
    _join: tokio::task::JoinHandle<()>,
}

impl Capture {
    pub fn new(config: ArkimeConfig) -> Self {
        Self { config }
    }

    pub async fn run_async(&self) -> Result<(), Error> {
        self.validate_backend()?;

        if !self.config.net.dynamic_interfaces && self.config.net.link_patterns.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "net.link_patterns is empty but net.dynamic_interfaces=false; configure at least one pattern (e.g. [\"eth0\"] or [\"eth*\"])",
            ));
        }

        let capture_threads = if self.config.capture.max_interface_threads == 0 {
            num_cpus::get().max(1)
        } else {
            self.config.capture.max_interface_threads.max(1)
        };

        let processing_threads = if self.config.capture.processing_threads == 0 {
            num_cpus::get().max(1)
        } else {
            self.config.capture.processing_threads.max(1)
        };

        let udp_timeout =
            Duration::from_secs(resolve_udp_timeout_secs(self.config.session.udp_timeout_secs));
        let tcp_timeout = Duration::from_secs(self.config.session.tcp_timeout_secs);

        let session_table = SessionTable::new(
            tcp_timeout,
            udp_timeout,
            self.config.session.max_entries,
            Instant::now(),
        );

        let plugins = PluginManager::default();
        let recorder = PacketRecorder::new(&self.config.storage, &self.config.index)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

        let plugins_mgr = crate::layer::plugins::LayerPluginManager::load(&self.config.layer.plugins)
            .unwrap_or_default();
        let layer_engine = LayerEngine::new(plugins_mgr);

        let state = Arc::new(Mutex::new(ProcessState {
            session_table,
            plugins,
            recorder,
            layer_engine,
        }));

        // Cluster metadata (decentralized gossip). Capture keeps running even if cluster is disabled.
        if self.config.cluster.enabled && self.config.cluster.mode == crate::conf::ClusterMode::Gossip {
            if let Ok(bind) = crate::cluster::gossip::parse_socket_addr(&self.config.cluster.bind_addr) {
                let mut peers = Vec::new();
                for p in &self.config.cluster.peers {
                    if let Ok(a) = crate::cluster::gossip::parse_socket_addr(p) {
                        peers.push(a);
                    }
                }

                let gc = crate::cluster::gossip::GossipCluster::new(crate::cluster::gossip::GossipConfig {
                    node_id: self.config.cluster.node_id.clone(),
                    bind_addr: bind,
                    peers,
                    heartbeat_secs: self.config.cluster.heartbeat_secs,
                });

                // Publish a basic node metadata record.
                gc.set_json(
                    &format!("/nodes/{}/info", self.config.cluster.node_id),
                    json!({
                        "mode": "capture",
                        "pid": std::process::id(),
                    }),
                );

                tokio::spawn(async move {
                    let _ = gc.run().await;
                });
            }
        }

        let filter = PacketFilter::from_config(
            &self.config.net.bpf_filter,
            self.config.capture.snaplen,
        )?;

        let (frame_tx, frame_rx) = mpsc::channel::<CapturedFrame>(16_384);
        let frame_rx = Arc::new(tokio::sync::Mutex::new(frame_rx));

        for _ in 0..processing_threads {
            let rx = Arc::clone(&frame_rx);
            let state2 = Arc::clone(&state);
            tokio::spawn(processing_worker(rx, state2, filter.clone()));
        }

        let sem = Arc::new(Semaphore::new(capture_threads));
        let mut iface_tasks: HashMap<String, InterfaceTask> = HashMap::new();
        let mut desired: HashSet<String> = HashSet::new();

        let (evt_tx, mut evt_rx) = mpsc::channel::<InterfaceEvent>(4096);

        // Producer: interface discovery.
        let interface_handler = InterfaceHandler::new(self.config.net.link_patterns.clone());
        if self.config.net.dynamic_interfaces {
            let discovery_interval = Duration::from_secs(self.config.net.discovery_interval_secs);
            tokio::spawn(async move {
                let mut interface_state = InterfaceState::default();
                loop {
                    let interfaces = interface_handler.get_up_interfaces();
                    let delta = interface_state.diff(interfaces);

                    for removed in delta.removed {
                        if evt_tx.send(InterfaceEvent::Removed(removed)).await.is_err() {
                            return;
                        }
                    }

                    for added in delta.added {
                        if evt_tx.send(InterfaceEvent::Added(added)).await.is_err() {
                            return;
                        }
                    }

                    tokio::time::sleep(discovery_interval).await;
                }
            });
        } else {
            // Static: send one-time adds then stop.
            for iface in interface_handler.get_up_interfaces() {
                evt_tx
                    .send(InterfaceEvent::Added(iface))
                    .await
                    .map_err(|_| Error::new(ErrorKind::BrokenPipe, "interface event channel closed"))?;
            }
        }

        let mut last_report = Instant::now();
        let mut last_expire = Instant::now();

        loop {
            // Drain interface events.
            while let Ok(ev) = evt_rx.try_recv() {
                match ev {
                    InterfaceEvent::Removed(name) => {
                        desired.remove(&name);
                        if let Some(task) = iface_tasks.remove(&name) {
                            info!("interface removed: {name}");
                            task.stop.store(true, Ordering::Relaxed);
                            // permit drops when task drops
                        }
                    }
                    InterfaceEvent::Added(iface) => {
                        if desired.contains(&iface.name) {
                            continue;
                        }
                        desired.insert(iface.name.clone());

                        let name = iface.name.clone();
                        let name2 = name.clone();
                        let sem2 = Arc::clone(&sem);
                        let tx2 = frame_tx.clone();
                        let stop = Arc::new(AtomicBool::new(false));
                        let stop2 = Arc::clone(&stop);
                        let cfg = self.config.clone();
                        let filter2 = filter.clone();

                        // Acquire a permit asynchronously; when acquired, run capture loop on blocking pool.
                        let permit = sem2.clone().acquire_owned().await.map_err(|_| {
                            Error::new(ErrorKind::Other, "interface semaphore closed")
                        })?;

                        // If the interface was removed while waiting for a permit, skip starting.
                        if !desired.contains(&name) {
                            continue;
                        }

                        let join = tokio::task::spawn_blocking(move || {
                            let mut backend = match build_backend(&cfg.capture.backend, &cfg.capture, &iface) {
                                Ok(b) => b,
                                Err(e) => {
                                    info!("build backend failed iface={} err={}", name2, e);
                                    return;
                                }
                            };

                            info!("interface added: {} backend={:?}", name2, cfg.capture.backend);

                            loop {
                                if stop2.load(Ordering::Relaxed) {
                                    break;
                                }

                                match backend.recv() {
                                    Ok(frame) => {
                                        let data = frame.to_vec();
                                        if !filter2.allow_frame(&data) {
                                            continue;
                                        }
                                        // Bounded channel provides backpressure; if full, we drop frames here.
                                        if tx2
                                            .try_send(CapturedFrame {
                                                iface: name2.clone(),
                                                data,
                                            })
                                            .is_err()
                                        {
                                            // drop on overload
                                        }
                                    }
                                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                                    Err(e) => {
                                        info!("capture recv error iface={} err={}", name2, e);
                                        std::thread::sleep(Duration::from_millis(50));
                                    }
                                }
                            }
                        });

                        iface_tasks.insert(
                            name.clone(),
                            InterfaceTask {
                                stop,
                                _permit: permit,
                                _join: join,
                            },
                        );
                    }
                }
            }

            if last_report.elapsed() >= Duration::from_secs(5) {
                self.report_stats(&state);
                last_report = Instant::now();
            }

            if last_expire.elapsed() >= Duration::from_secs(1) {
                self.expire_sessions(&state);
                last_expire = Instant::now();
            }

            if !self.config.net.dynamic_interfaces {
                // Static mode: nothing else to do here; just idle.
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn expire_sessions(&self, state: &Arc<Mutex<ProcessState>>) {
        let mut st = match state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let expired = st.session_table.expire(Instant::now());
        if expired > 0 {
            info!("sessions expired={expired}");
        }
    }

    fn report_stats(&self, state: &Arc<Mutex<ProcessState>>) {
        let st = match state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let (packets, bytes, sessions) = st.session_table.totals();
        let stats = RuntimeStats {
            packets,
            bytes,
            sessions,
        };
        info!("stats {}", render_stats(stats));

        if self.config.index.enabled {
            let matched = st
                .recorder
                .search_by_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
            info!("index.search_by_ip(127.0.0.1) -> {} hits", matched.len());
        }
    }

    fn validate_backend(&self) -> Result<(), Error> {
        if self
            .config
            .capture
            .enabled_backends
            .iter()
            .any(|b| b == &self.config.capture.backend)
        {
            return Ok(());
        }

        Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "backend {:?} is not in enabled_backends",
                self.config.capture.backend
            ),
        ))
    }
}

async fn processing_worker(
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<CapturedFrame>>>,
    state: Arc<Mutex<ProcessState>>,
    filter: PacketFilter,
) {
    loop {
        let frame = {
            let mut guard = rx.lock().await;
            guard.recv().await
        };

        let Some(frame) = frame else {
            return;
        };

        if !filter.allow_frame(&frame.data) {
            continue;
        }

        // Serialize state updates for now; later we can shard session/index/recording.
        let mut st = match state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let Some(packet) = st.layer_engine.parse(&frame.data) else {
            continue;
        };

        if let Some(flow) = packet.flow.clone() {
            st.session_table
                .observe_packet(flow, frame.data.len(), Instant::now());
        }

        if let Err(e) = st.recorder.record(&frame.iface, &frame.data, &packet) {
            info!("record error iface={} err={}", frame.iface, e);
        }

        st.plugins.on_packet(&packet);
    }
}
