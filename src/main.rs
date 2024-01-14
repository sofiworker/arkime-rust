use std::{fs::{read, File}, io::Read};
use toml;
use config::config as c;

pub mod config;
pub mod services;

fn main() {
    let mut config_file = File::open("config.toml").expect("can't open config file");
    let mut content = String::new();
    config_file.read_to_string(&mut content).expect("read config to string failed");
    let conf: c::Config = toml::from_str(&content).expect("无法解析TOML文件");
    println!("{:?}", conf);
}