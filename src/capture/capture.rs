extern crate pnet;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use std::{
    borrow::{Borrow, BorrowMut},
    collections::HashMap,
    io::Error,
    sync::{self, Arc, Mutex},
};
use tokio::sync::broadcast::{self, Receiver, Sender};

pub struct Capture {
    pub tx: broadcast::Sender<InterfaceMsg>,
    pub rx: broadcast::Receiver<InterfaceMsg>,
    pub capture_pool: sync::Mutex<HashMap<i32, i32>>,
}

impl Capture {
    pub fn new() -> Self {
        let (tx, rx) = broadcast::channel(1000);
        Capture {
            tx: tx,
            rx: rx,
            capture_pool: Mutex::new(HashMap::new()),
        }
    }

    pub fn run(&self) -> Result<(), Error> {
        let listen_interfaces_thread = tokio::spawn(async { loop {} });
        let interfaces = datalink::interfaces();
        for interface in interfaces {
            if interface.is_loopback() {
                continue;
            }
            let thread = tokio::spawn(async move {
                // Create a new channel, dealing with layer 2 packets
                let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
                    Ok(Ethernet(tx, rx)) => (tx, rx),
                    Ok(_) => panic!("Unhandled channel type"),
                    Err(e) => panic!(
                        "An error occurred when creating the datalink channel: {}",
                        e
                    ),
                };

                loop {
                    match rx.next() {
                        Ok(packet) => {
                            let packet = EthernetPacket::new(packet).unwrap();
                            // tx.build_and_send(1, packet.packet().len());
                        }
                        Err(e) => {
                            // If an error occurs, we can handle it here
                            panic!("An error occurred while reading: {}", e);
                        }
                    }
                }
            });
            let mut task = self.capture_pool.lock().unwrap();
            task.insert(0, 1);
        }
        Ok(())
    }
}

pub enum InterfaceMsgKind {
    Add,
    Del,
}

#[derive(Debug, Clone)]
pub struct InterfaceMsg {}
