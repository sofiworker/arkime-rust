use std::{
    io::Read,
};
use toml;
use ctrlc;

#[cfg(linux)]
use tokio::signal::unix::{signal, SignalKind};
#[cfg(windows)]
use tokio::signal::windows::{ctrl_c};

pub mod core;
pub mod log;
pub mod plugins;
pub mod service;
pub mod route;
mod filter;
mod conf;
mod cmd;

#[tokio::main]
async fn main() {
    conf::Config::get();

    tokio::spawn(async {
        init_capture();
    });

    #[cfg(linux)]
        let mut stream = signal(SignalKind::hangup())?;
    #[cfg(linux)]
    stream.recv().await;

    #[cfg(windows)]
        let mut signal = ctrl_c().unwrap();
    #[cfg(windows)]
    signal.recv().await;
}


fn init_capture() {

    println!("111111111");
}