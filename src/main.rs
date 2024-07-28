use clap::Command;

mod capture;
mod cmd;
mod conf;
pub mod core;
mod filter;

pub mod plugins;
pub mod route;
pub mod service;

mod layer;

#[tokio::main]
async fn main() {
    let root_cmd = Command::new("arkime-rust").subcommands([
        cmd::capture::capture(),
        cmd::config::config(),
        cmd::reload::reload(),
        cmd::stop::stop(),
        cmd::version::version()
    ]);
    let mut help_cmd = root_cmd.clone();
    let matches = root_cmd.get_matches();

    match matches.subcommand() {
        Some(("capture", capture_cmd)) => {},
        Some(("config", config_cmd)) => {},
        Some(("reload", reload_cmd)) => {},
        Some(("stop", stop_cmd)) => {},
        Some(("version", version_cmd)) => {
            cmd::version::version();
        },
        _ => help_cmd.print_help().unwrap()
    }
    conf::ArkimeConfig::init();
}
