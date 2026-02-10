use crate::capture::tokio_runtime::Capture;
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

    if let Err(err) = crate::logging::init(&config.log) {
        eprintln!("init logging failed: {err}");
    }

    let capture = Capture::new(config);
    // Linux-first: use Tokio runtime as the orchestrator. Capture itself uses spawn_blocking for
    // the current blocking pnet backend, but stays within Tokio-managed pools.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    if let Err(err) = rt.block_on(capture.run_async()) {
        eprintln!("capture error: {err}");
    }
}

