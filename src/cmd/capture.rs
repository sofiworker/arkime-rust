use std::process;
use clap::{command, value_parser, Arg, ArgAction, ArgGroup, ArgMatches, Command};
use tokio::signal;
use crate::capture::capture::Capture;

pub fn capture() -> Command {
    Command::new("capture")
}


async fn start_capture() {
    // here to start handle interfaces and data capture
    tokio::spawn(async {
        let capture = Capture::new();
        match capture.run() {
            Ok(_) => {}
            Err(e) => {
                panic!("{}", e);
            }
        }
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