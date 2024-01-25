use tokio::signal;

pub mod core;
pub mod log;
pub mod plugins;
pub mod service;
pub mod route;
mod filter;
mod conf;
mod cmd;
mod capture;

#[tokio::main]
async fn main() {
    conf::Config::get();

    // here to start handle interfaces and data capture
    tokio::spawn(async {
        init_capture();
    });

    match signal::ctrl_c().await {
        Ok(()) => {
            println!("bye!!!!")
        },
        Err(err) => {
            eprintln!("Unable to listen for shutdown signal: {}", err);
        },
    }
}


fn init_capture() {
    capture::start_capture();
}