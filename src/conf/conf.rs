use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};

const CONFIG_PATH: &str = "src/config.toml";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArkimeConfig {
    #[serde(default)]
    pub capture: CaptureConfig,
    #[serde(default)]
    pub net: NetConfig,
    #[serde(default)]
    pub service: ServiceConfig,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureBackend {
    Libpcap,
    Pfring,
    RawSocket,
    Dpdk,
    Ebpf,
}

impl Default for CaptureBackend {
    fn default() -> Self {
        Self::Libpcap
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    #[serde(default)]
    pub backend: CaptureBackend,
    #[serde(default = "default_enabled_backends")]
    pub enabled_backends: Vec<CaptureBackend>,
    #[serde(default)]
    pub snaplen: u32,
    #[serde(default = "default_promisc")]
    pub promisc: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            backend: CaptureBackend::Libpcap,
            enabled_backends: default_enabled_backends(),
            snaplen: 65535,
            promisc: true,
        }
    }
}

fn default_enabled_backends() -> Vec<CaptureBackend> {
    vec![
        CaptureBackend::Libpcap,
        CaptureBackend::Pfring,
        CaptureBackend::RawSocket,
    ]
}

fn default_promisc() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetConfig {
    #[serde(default = "default_dynamic_interfaces")]
    pub dynamic_interfaces: bool,
    #[serde(default)]
    pub bpf_filter: String,
    #[serde(default = "default_link_patterns")]
    pub link_patterns: Vec<String>,
}

fn default_dynamic_interfaces() -> bool {
    true
}

fn default_link_patterns() -> Vec<String> {
    vec!["*".to_string()]
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            dynamic_interfaces: default_dynamic_interfaces(),
            bpf_filter: String::new(),
            link_patterns: default_link_patterns(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    #[serde(default)]
    pub hostname: String,
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub socket_path: String,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8080
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            hostname: String::new(),
            host: default_host(),
            port: default_port(),
            socket_path: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_output")]
    pub output: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_output() -> String {
    "arkime-rust.log".to_string()
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            output: default_log_output(),
        }
    }
}

impl ArkimeConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let config = Config::builder()
            .add_source(File::with_name(CONFIG_PATH).required(false))
            .add_source(Environment::with_prefix("ARKIME_RUST").separator("__"))
            .build()?;

        config.try_deserialize::<Self>()
    }
}
