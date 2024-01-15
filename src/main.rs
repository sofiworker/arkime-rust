use config::config as conf;
use std::{
    fs::{read, File},
    io::Read,
};
use toml;

pub mod config;
pub mod services;

fn main() {
    let mut config_file = File::open("/root/workspace/rust/arkime-rust/src/config.toml")
        .expect("can't open config file");
    let mut contents = String::new();
    config_file
        .read_to_string(&mut contents)
        .expect("read config to string failed");
    let conf: conf::Config = toml::from_str(&contents).unwrap();
    println!("{:#?}", conf);
}
