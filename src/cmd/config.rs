use clap::{Arg, Command};

pub fn config() -> Command {
    Command::new("config").args(
        [
            Arg::new("test"),
            Arg::new("")
        ]
    )
}