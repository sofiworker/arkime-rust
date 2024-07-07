#![allow(deprecated)]
use std::collections::HashMap;
use serde_derive::{Deserialize, Serialize};
use config::{Config, File};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc::channel;
use std::sync::RwLock;
use std::thread;
use std::time::Duration;

const CONFIG_PATH :&str = "src/config.toml";

#[derive(Serialize, Deserialize, Debug)]
pub struct ArkimeConfig {
    net: NetConfig,
    service: ServiceConfig,
    log: LogConfig,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NetConfig {
    dynamic_interfaces: bool,
    bpf_filter: String,
    link_name: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServiceConfig {
    hostname: String,
    host: String,
    port: u32,
    socket_path: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LogConfig {
    level: String,
    output: String,
}

lazy_static::lazy_static! {
    static ref SETTINGS: RwLock<Config> = RwLock::new({
        let settings = Config::builder()
        .add_source(config::Environment::with_prefix("ARKIME-RUST").separator("_"))
        .add_source(File::with_name(CONFIG_PATH));
        settings.build().unwrap()
    });
}

fn watch() {
    thread::spawn(|| {
        let (tx, rx) = channel();

        let mut watcher: RecommendedWatcher = Watcher::new(
            tx,
            notify::Config::default().with_poll_interval(Duration::from_secs(1000)),
        )
            .unwrap();

        watcher
            .watch(
                Path::new(CONFIG_PATH),
                RecursiveMode::NonRecursive,
            )
            .unwrap();
        loop {
            match rx.recv() {
                Ok(Ok(Event {
                          kind: notify::event::EventKind::Modify(_),
                          ..
                      })) => {
                    println!(" * Settings.toml written; refreshing configuration ...");
                    SETTINGS.write().unwrap().refresh().unwrap();
                    show();
                }

                Err(e) => println!("watch error: {:?}", e),

                _ => {
                    // Ignore event
                }
            }
        }
    });
}

impl ArkimeConfig {

    pub fn init() {
        SETTINGS.read().unwrap();
        watch();
    }

    pub fn get_interface(self) -> Vec<String> {
        return self.net.link_name;
    }
}

fn show() {
    println!(
        " * Settings :: \n\x1b[31m{:?}\x1b[0m",
        SETTINGS
            .read()
            .unwrap()
            .clone()
            .try_deserialize::<HashMap<String, String>>()
            .unwrap()
    );
}