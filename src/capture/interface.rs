use pnet::datalink;

pub struct InterfaceHandler {
    interface_list: Vec<String>,
}

impl InterfaceHandler {
    pub fn new() -> Self {
        Self {
            interface_list: vec![],
        }
    }

    pub fn listen_interface(&self) {
    }

    pub fn get_interfaces(&self) -> Vec<datalink::NetworkInterface> {
        return vec![];
    }
}
