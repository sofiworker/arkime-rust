use std::process;

use capture::capture::Capture;
use tokio::signal;

mod capture;
mod cmd;
mod conf;
pub mod core;
mod filter;
pub mod log;
pub mod plugins;
pub mod route;
pub mod service;

#[tokio::main]
async fn main() {
    conf::Config::get();

    // here to start handle interfaces and data capture
    tokio::spawn(async {
        init_capture();
    });
    match signal::ctrl_c().await {
        Ok(()) => {
            println!("bye!!!!");
            process::exit(0);
        }
        Err(err) => {
            eprintln!("Unable to listen for shutdown signal: {}", err);
        }
    }
}

fn init_capture() {
    let capture = Capture::new();
    match capture.run() {
        Ok(_) => {}
        Err(e) => {
            panic!("{}", e);
        }
    }
}
