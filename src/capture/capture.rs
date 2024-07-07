extern crate pnet;

use crate::capture::interface;
use crate::core::session;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use std::sync::Arc;
use std::{borrow::Borrow, collections::HashMap, io::Error, sync::Mutex};
use tokio::task;

pub struct Capture {
    capture_pool: Arc<Mutex<HashMap<String, task::JoinHandle<u32>>>>,
    capture_interface_list: Vec<NetworkInterface>,
}

impl Capture {
    pub fn new() -> Self {
        Self {
            capture_pool: Arc::new(Mutex::new(HashMap::new())),
            capture_interface_list: Vec::new(),
        }
    }

    pub fn run(&self) -> Result<(), Error> {
        let interface_handler = interface::InterfaceHandler::new();
        loop {
            // here to handle interface modify
            let new_interfaces = interface_handler.get_interfaces();

            let running_map: HashMap<String, NetworkInterface> = self
                .capture_interface_list
                .iter()
                .fold(HashMap::new(), |mut map, item| {
                    map.insert(item.name.clone(), item.clone());
                    map
                });

            let del: Vec<String> = new_interfaces
                .iter()
                .map(|x| match running_map.get(&x.name) {
                    Some(n) => Some(n.name.clone()),
                    _ => None,
                })
                .filter(|x| x.is_some())
                .map(|x| x.unwrap())
                .collect();

            let add: Vec<NetworkInterface> = new_interfaces
                .iter()
                .map(|x| match running_map.get(&x.name) {
                    Some(n) => Some(n.clone()),
                    _ => None,
                })
                .filter(|x| x.is_some())
                .map(|x| x.unwrap())
                .collect();

            let mut pool = self.capture_pool.lock().unwrap();
            for name in del {
                let thread = pool.get(&name);
                thread.unwrap().abort();
                pool.remove(&name);
            }
            self.start_capture(add);
        }
    }

    fn start_capture(&self, interface_list: Vec<NetworkInterface>) {
        let mut pool = self.capture_pool.lock().unwrap();
        for interface in interface_list {
            let interface_name = interface.clone().name;
            let thread = tokio::spawn(async move {
                let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
                    Ok(Ethernet(tx, rx)) => (tx, rx),
                    Ok(_) => panic!("Unhandled channel type"),
                    Err(e) => panic!(
                        "An error occurred when creating the datalink channel: {}",
                        e
                    ),
                };

                // println!("the listen interface is {}", interface.name);

                loop {
                    match rx.next() {
                        Ok(packet) => {
                            let packet: EthernetPacket<'_> = EthernetPacket::new(packet).unwrap();
                            // tx.build_and_send(1, packet.packet().len());
                            // packet.payload();
                            // session::Session::session_find_or_create();
                            println!("----------->{}", interface.name);
                        }
                        Err(e) => {
                            // If an error occurs, we can handle it here
                            panic!("An error occurred while reading: {}", e);
                        }
                    }
                }
            });
            pool.insert(interface_name, thread);
        }
    }
}
