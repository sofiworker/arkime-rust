use pnet::datalink;
use std::sync::Mutex;

pub struct InterfaceHandler {
    interface_list: Mutex<Vec<datalink::NetworkInterface>>,
}

impl InterfaceHandler {
    pub fn new() -> Self {
        Self {
            interface_list: Mutex::new(vec![]),
        }
    }

    pub fn listen_interface_d(&self) {
        let listen_interfaces_thread = tokio::spawn(async { loop {} });
    }

    pub fn get_interfaces(&self) -> Vec<datalink::NetworkInterface> {
        self.interface_list.lock().unwrap()?
    }
}
