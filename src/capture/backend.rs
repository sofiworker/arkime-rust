use crate::conf::{CaptureBackend, CaptureConfig};
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{DataLinkReceiver, NetworkInterface};
use std::io::{Error, ErrorKind};

pub trait PacketCaptureBackend: Send {
    fn recv(&mut self) -> Result<&[u8], Error>;
}

pub fn build_backend(
    backend: &CaptureBackend,
    capture_config: &CaptureConfig,
    iface: &NetworkInterface,
) -> Result<Box<dyn PacketCaptureBackend>, Error> {
    match backend {
        CaptureBackend::Libpcap => Ok(Box::new(PnetBackend::new(capture_config, iface)?)),
        CaptureBackend::Pfring
        | CaptureBackend::RawSocket
        | CaptureBackend::Dpdk
        | CaptureBackend::Ebpf => Err(Error::new(
            ErrorKind::Unsupported,
            format!(
                "backend {:?} is planned for Linux runtime adapters; currently only libpcap-compatible path is implemented",
                backend
            ),
        )),
    }
}

struct PnetBackend {
    rx: Box<dyn DataLinkReceiver>,
}

impl PnetBackend {
    fn new(capture_config: &CaptureConfig, iface: &NetworkInterface) -> Result<Self, Error> {
        let mut dl_config = datalink::Config::default();
        dl_config.read_timeout = Some(std::time::Duration::from_millis(
            capture_config.read_timeout_ms,
        ));
        dl_config.promiscuous = capture_config.promisc;

        match datalink::channel(iface, dl_config) {
            Ok(Ethernet(_, rx)) => Ok(Self { rx }),
            Ok(_) => Err(Error::new(
                ErrorKind::Unsupported,
                "unsupported datalink channel type",
            )),
            Err(err) => Err(Error::new(ErrorKind::Other, err.to_string())),
        }
    }
}

impl PacketCaptureBackend for PnetBackend {
    fn recv(&mut self) -> Result<&[u8], Error> {
        self.rx
            .next()
            .map_err(|err| Error::new(ErrorKind::WouldBlock, err.to_string()))
    }
}
