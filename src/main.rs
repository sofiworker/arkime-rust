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

fn main() {
    let root_cmd = Command::new("arkime-rust").subcommands([
        cmd::capture::capture(),
        cmd::config::config(),
        cmd::reload::reload(),
        cmd::stop::stop(),
        cmd::version::version(),
    ]);
    let mut help_cmd = root_cmd.clone();
    let matches = root_cmd.get_matches();

    match matches.subcommand() {
        Some(("capture", sub)) => {
            let path = sub
                .get_one::<String>("config")
                .map(String::as_str)
                .unwrap_or("src/config.toml");
            cmd::capture::start_capture(path);
        }
        Some(("config", sub)) => {
            let path = sub
                .get_one::<String>("config")
                .map(String::as_str)
                .unwrap_or("src/config.toml");
            cmd::config::show_config(path);
        }
        Some(("version", _)) => {
            println!("{}", env!("CARGO_PKG_VERSION"));
        }
        Some(("reload", _)) | Some(("stop", _)) => {
            println!("not implemented yet")
        }
        _ => {
            let _ = help_cmd.print_help();
        }
    }
}
