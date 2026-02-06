use crate::capture::interface::InterfaceHandler;
use crate::conf::ArkimeConfig;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherType, EthernetPacket};
use pnet::packet::vlan::VlanPacket;
use pnet::packet::Packet;
use std::io::{Error, ErrorKind};

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
        let interfaces = interface_handler.get_interfaces();

        for interface in interfaces {
            let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "unsupported datalink channel type",
                    ))
                }
                Err(err) => return Err(Error::new(ErrorKind::Other, err.to_string())),
            };

            if let Ok(packet) = rx.next() {
                if let Some(summary) = packet_summary(packet) {
                    println!(
                        "capture backend={:?} iface={} {}",
                        self.config.capture.backend, interface.name, summary
                    );
                }
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
