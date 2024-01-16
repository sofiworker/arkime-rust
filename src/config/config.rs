use serde_derive::Deserialize;
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    static ref INSTANCE: Mutex<Config> = Mutex::new(Config::new());
}

#[derive(Deserialize, Debug)]
pub struct Config {
    net: NetConfig,
    service: ServiceConfig,
    log: LogConfig,
}

#[derive(Deserialize, Debug)]
pub struct NetConfig {
    bpf_filter: String,
    link_name: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct ServiceConfig {
    host: String,
    port: u32,
}

#[derive(Deserialize, Debug)]
pub struct LogConfig {
    level: String,
    output: String,
}


impl Config {
    fn new() -> Config {
        
    }
}

pub fn set_config(c: Config) {

}


pub fn get_config() ->Config {

}