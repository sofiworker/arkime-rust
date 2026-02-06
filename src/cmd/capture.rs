use crate::capture::capture::Capture;
use crate::conf::ArkimeConfig;
use clap::Command;

pub fn capture() -> Command {
    Command::new("capture").about("start packet capture")
}

pub fn start_capture() {
    let config = ArkimeConfig::load().expect("failed to load config");
    let capture = Capture::new(config);
    if let Err(err) = capture.run() {
        eprintln!("capture error: {err}");
    }
}
