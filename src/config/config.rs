use serde_derive::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Config {
    net: NetConfig,
    service: ServiceConfig,
    log: LogConfig,
}

#[derive(Deserialize, Debug)]
pub struct NetConfig {
    bpf_filter: String,
    link_name: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct ServiceConfig {
    host: String,
    port: u32,
}

#[derive(Deserialize, Debug)]
pub struct LogConfig {
    level: String,
    output: String,
}
