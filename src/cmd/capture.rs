use crate::capture::capture::Capture;
use crate::conf::ArkimeConfig;
use clap::{Arg, Command};

pub fn capture() -> Command {
    Command::new("capture")
        .about("start packet capture")
        .arg(
            Arg::new("config")
                .long("config")
                .default_value("src/config.toml")
                .help("config file path"),
        )
}

pub fn start_capture(config_path: Option<&str>) {
    let config = match config_path {
        Some(path) => ArkimeConfig::load_from_path(path).expect("failed to load config"),
        None => ArkimeConfig::load().expect("failed to load config"),
    };

    let capture = Capture::new(config);
    if let Err(err) = capture.run() {
        eprintln!("capture error: {err}");
    }
}

