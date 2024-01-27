use lazy_static::lazy_static;
use serde_derive::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub net: NetConfig,
    pub service: ServiceConfig,
    pub log: LogConfig,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NetConfig {
    pub dynamic_interfaces: bool,
    pub bpf_filter: String,
    pub link_name: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServiceConfig {
    host: String,
    port: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LogConfig {
    level: String,
    output: String,
}

impl Default for Config {
    fn default() -> Self {
        let file_path = "src/config.toml";

        let mut file = match File::open(file_path) {
            Ok(f) => f,
            Err(e) => panic!("error is op en conf {e}"),
        };

        let mut str = String::new();
        match file.read_to_string(&mut str) {
            Ok(s) => s,
            Err(e) => panic!("error read str {}", e),
        };

        toml::from_str(&str).expect("parse config file failed")
    }
}

impl Config {
    pub fn get<'a>() -> &'a Self {
        lazy_static! {
            static ref CACHE: Config = Config::default();
        }
        &CACHE
    }
}
