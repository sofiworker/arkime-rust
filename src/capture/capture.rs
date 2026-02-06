use crate::capture::backend::{build_backend, PacketCaptureBackend};
use crate::capture::interface::{InterfaceHandler, InterfaceState};
use crate::conf::ArkimeConfig;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::{EtherType, EthernetPacket};
use pnet::packet::vlan::VlanPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::thread;
use std::time::Duration;

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

            self.capture_once(&interfaces, &mut workers);

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
    ) {
        for iface in interfaces {
            let Some(worker) = workers.get_mut(&iface.name) else {
                continue;
            };

            if let Ok(packet) = worker.recv() {
                if let Some(summary) = packet_summary(packet) {
                    println!(
                        "capture backend={:?} iface={} {}",
                        self.config.capture.backend, iface.name, summary
                    );
                }
            }
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

fn packet_summary(packet: &[u8]) -> Option<String> {
    let eth = EthernetPacket::new(packet)?;
    match eth.get_ethertype() {
        EtherType(0x8100) | EtherType(0x88A8) => {
            let vlan = VlanPacket::new(eth.payload())?;
            Some(format!(
                "vlan={} inner_ethertype=0x{:x}",
                vlan.get_vlan_identifier(),
                vlan.get_ethertype().0
            ))
        }
        other => Some(format!("ethertype=0x{:x}", other.0)),
    }
}

#[cfg(test)]
mod tests {
    use super::packet_summary;

    #[test]
    fn parse_vlan_packet() {
        let frame: [u8; 18] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x81, 0x00, // vlan ethertype
            0x00, 0x64, // vlan id 100
            0x08, 0x00, // inner ipv4
        ];
        let msg = packet_summary(&frame).expect("summary");
        assert!(msg.contains("vlan=100"));
    }
}
