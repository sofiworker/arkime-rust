use std::collections::HashMap;

pub struct Session {
    session_id: String,
    pub session_list: HashMap<SessionKind, Session>,
}

pub struct SessionTree{

}

pub struct SessionTreeNode{
    
}

pub struct TcpData {
    seq: u32,
    ack: u32,
    len: u16,
    data_offset: u16,
}

pub struct Packet {
    writer_file_pos: u64,
    read_file_pos: u64,
    writer_file_num: u32,
    hash: u32,
    pktlen: u32,
    payload_len: u32,
    payload_offset: u32,
    v6: bool,
    capied: bool,
    outer_ip_offset: u32,
    vlan_id: u32,
}

impl Session {

    pub fn flush() {}

    pub fn close() {}

    pub fn get_session_id() -> String {
        String::new()
    }

    // pub fn init_session() -> Session {
    //     Session {
    //         session_id: String::new(),
    //     }
    // }

    pub fn session_find_or_create() -> () {
        // return Session {
        //     session_id: String::from("value"),
        // };
    }

    pub fn get_session_by_id(session_id: String) -> () {
        // return Session {
        //     session_id: String::from("value"),
        // };
    }
}

pub enum SessionKind {
    Tcp,
    Udp,
    Uknown
}