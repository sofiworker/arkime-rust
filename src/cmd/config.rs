use crate::conf::ArkimeConfig;
use clap::{Arg, Command};

pub fn config() -> Command {
    Command::new("config").about("show merged config").arg(
        Arg::new("config")
            .long("config")
            .default_value("src/config.toml")
            .help("config file path"),
    )
}

pub fn show_config(config_path: &str) {
    match ArkimeConfig::load_from_path(config_path) {
        Ok(cfg) => println!("{cfg:#?}"),
        Err(err) => eprintln!("load config failed: {err}"),
    }
}
