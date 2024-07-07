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
        _ => help_cmd.print_help().unwrap()
    }
    conf::ArkimeConfig::init();
}
