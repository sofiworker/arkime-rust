use crate::conf::ArkimeConfig;
use clap::Command;

pub fn config() -> Command {
    Command::new("config").about("show merged config")
}

pub fn show_config() {
    match ArkimeConfig::load() {
        Ok(cfg) => println!("{cfg:#?}"),
        Err(err) => eprintln!("load config failed: {err}"),
    }
}
