use pnet::datalink;
use std::sync::Mutex;

pub struct InterfaceHandler {
    interface_list: Mutex<Vec<datalink::NetworkInterface>>,
}

impl InterfaceHandler {
    pub fn new() -> Self {
        Self {
            interface_list: Mutex::new(Vec::new()),
        }
    }

    pub fn listen_interface(&self) {
        let listen_interfaces_thread = tokio::spawn(async {
            // loop {
            //     datalink::interfaces()
            // }
        });
    }

    pub fn get_interfaces(&self) -> Vec<datalink::NetworkInterface> {
        // let guard = self.interface_list.lock().unwrap();
        // guard.clone()
        datalink::interfaces()
    }
}
