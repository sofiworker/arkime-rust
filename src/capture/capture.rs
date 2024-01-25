extern crate pnet;

use std::sync::mpsc;

use lazy_static::lazy_static;
use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use tokio::sync::watch;

use crate::conf;

pub struct Capture {

}

impl Capture {
    pub fn get<'a>() -> &'a Self {
        lazy_static! {
            static ref CACHE :Capture = Capture::default();
        }
        &CACHE
    }
}

impl Default for Capture {
    fn default() -> Self {

        Capture{
            
        }
    }
}


#[derive(Debug)]
enum InterfaceMsg {
    Add{
        Name: String,
    },
    Del {
        Name: String,
    }
}


pub fn start_capture() {
    let (tx, mut rx) = watch::channel("hello");
    tokio::spawn(async move {
        // Use the equivalent of a "do-while" loop so the initial value is
        // processed before awaiting the `changed()` future.
        loop {
            println!("{}! ", *rx.borrow_and_update());
            if rx.changed().await.is_err() {
                break;
            }
        }
    });
}



pub fn listen_interface_dynamic() {
    let interfaces = datalink::interfaces();
}