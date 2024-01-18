use config::config as conf;
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    iterator::Signals,
};
use std::{
    fs::File,
    io::Read,
};
use toml;

pub mod config;
pub mod core;
pub mod log;
pub mod plugins;
pub mod service;

#[tokio::main]
async fn main() {
    let config_path = String::from("src/config.toml");
    let mut config_file = File::open(config_path).expect("can't open config file");
    let mut contents = String::new();
    config_file
        .read_to_string(&mut contents)
        .expect("read config to string failed");
    let conf: conf::Config = toml::from_str(&contents).unwrap();
    println!("{:#?}", conf);

    

    // 创建一个 Signals 迭代器，用于捕获信号
    let mut signals = Signals::new(&[SIGINT, SIGTERM]).expect("Error creating signal iterator");
    for signal in signals.forever() {
        match signal {
            SIGINT => {
                println!("Received SIGINT");
                // 执行 SIGINT 信号的操作
                // ...
                break;
            }
            SIGTERM => {
                println!("Received SIGTERM");
                // 执行 SIGTERM 信号的操作
                // ...
                break;
            }
            _ => panic!(),
        }
    }

    println!("Program exited");
}
