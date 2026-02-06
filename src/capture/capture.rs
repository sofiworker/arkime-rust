use crate::capture::backend::{build_backend, PacketCaptureBackend};
use crate::capture::interface::{InterfaceHandler, InterfaceState};
use crate::conf::ArkimeConfig;
use crate::core::session::SessionTable;
use crate::filter::PacketFilter;
use crate::layer::parse_packet;
use crate::pcap::PacketRecorder;
use crate::plugins::PluginManager;
use crate::route::render_stats;
use crate::service::RuntimeStats;
use pnet::datalink::NetworkInterface;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::time::{Duration, Instant};

pub struct Capture {
    config: ArkimeConfig,
}

impl Capture {
    pub fn new(config: ArkimeConfig) -> Self {
        Self { config }
    }

    pub fn run(&self) -> Result<(), Error> {
        self.validate_backend()?;

        let interface_handler = InterfaceHandler::new(self.config.net.link_patterns.clone());
        let mut interface_state = InterfaceState::default();
        let mut workers: HashMap<String, Box<dyn PacketCaptureBackend>> = HashMap::new();

        let mut session_table = SessionTable::default();
        let mut plugins = PluginManager::default();
        let filter = PacketFilter;
        let mut recorder = PacketRecorder::new(&self.config.storage, &self.config.index)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

        let mut last_report = Instant::now();

        loop {
            let interfaces = interface_handler.get_interfaces();
            let delta = interface_state.diff(interfaces.clone());

            for removed in delta.removed {
                workers.remove(&removed);
                println!("interface removed: {removed}");
            }

            for added in delta.added {
                let worker =
                    build_backend(&self.config.capture.backend, &self.config.capture, &added)?;
                println!(
                    "interface added: {} backend={:?}",
                    added.name, self.config.capture.backend
                );
                workers.insert(added.name.clone(), worker);
            }

            self.capture_once(
                &interfaces,
                &mut workers,
                &filter,
                &mut session_table,
                &mut plugins,
                &mut recorder,
            )?;

            if last_report.elapsed() >= Duration::from_secs(5) {
                let (packets, bytes, sessions) = session_table.totals();
                let stats = RuntimeStats {
                    packets,
                    bytes,
                    sessions,
                };
                println!("stats {}", render_stats(stats));

                if self.config.index.enabled {
                    let matched = recorder.search_by_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
                    println!("index.search_by_ip(127.0.0.1) -> {} hits", matched.len());
                }

                last_report = Instant::now();
            }

            if !self.config.net.dynamic_interfaces {
                break;
            }

            thread::sleep(Duration::from_secs(self.config.net.discovery_interval_secs));
        }

        Ok(())
    }

    fn capture_once(
        &self,
        interfaces: &[NetworkInterface],
        workers: &mut HashMap<String, Box<dyn PacketCaptureBackend>>,
        filter: &PacketFilter,
        session_table: &mut SessionTable,
        plugins: &mut PluginManager,
        recorder: &mut PacketRecorder,
    ) -> Result<(), Error> {
        for iface in interfaces {
            let Some(worker) = workers.get_mut(&iface.name) else {
                continue;
            };

            if let Ok(frame) = worker.recv() {
                let Some(packet) = parse_packet(frame) else {
                    continue;
                };

                if !filter.allow(&packet) {
                    continue;
                }

                if let Some(flow) = packet.flow.clone() {
                    session_table.observe_packet(flow, frame.len());
                }

                recorder
                    .record(&iface.name, frame, &packet)
                    .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

                plugins.on_packet(&packet);
            }
        }

        Ok(())
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

