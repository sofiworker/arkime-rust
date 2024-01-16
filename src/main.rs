use config::config as conf;
use std::{
    fs::{File},
    io::Read,
};
use toml;

pub mod config;
pub mod service;
pub mod log;

#[tokio::main]
fn main() {
    let config_path = String::from("src/config.toml");
    let mut config_file = File::open(config_path)
        .expect("can't open config file");
    let mut contents = String::new();
    config_file
        .read_to_string(&mut contents)
        .expect("read config to string failed");
    let conf: conf::Config = toml::from_str(&contents).unwrap();
    println!("{:#?}", conf);

}
