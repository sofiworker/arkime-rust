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
    pub session: SessionConfig,
    #[serde(default)]
    pub layer: LayerConfig,
    #[serde(default)]
    pub cluster: ClusterConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub index: IndexConfig,
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
    #[serde(default = "default_snaplen")]
    pub snaplen: u32,
    #[serde(default = "default_promisc")]
    pub promisc: bool,
    #[serde(default = "default_read_timeout_ms")]
    pub read_timeout_ms: u64,
    #[serde(default = "default_max_interface_threads")]
    pub max_interface_threads: usize,
    #[serde(default = "default_processing_threads")]
    pub processing_threads: usize,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            backend: CaptureBackend::Libpcap,
            enabled_backends: default_enabled_backends(),
            snaplen: default_snaplen(),
            promisc: default_promisc(),
            read_timeout_ms: default_read_timeout_ms(),
            max_interface_threads: default_max_interface_threads(),
            processing_threads: default_processing_threads(),
        }
    }
}

fn default_enabled_backends() -> Vec<CaptureBackend> {
    vec![
        CaptureBackend::Libpcap,
        CaptureBackend::Pfring,
        CaptureBackend::RawSocket,
        CaptureBackend::Dpdk,
        CaptureBackend::Ebpf,
    ]
}

fn default_snaplen() -> u32 {
    65535
}

fn default_promisc() -> bool {
    true
}

fn default_read_timeout_ms() -> u64 {
    50
}

fn default_max_interface_threads() -> usize {
    // 0 means "auto" (use CPU count).
    0
}

fn default_processing_threads() -> usize {
    // 0 means "auto" (use CPU count).
    0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetConfig {
    #[serde(default = "default_dynamic_interfaces")]
    pub dynamic_interfaces: bool,
    #[serde(default)]
    pub bpf_filter: String,
    #[serde(default = "default_link_patterns")]
    pub link_patterns: Vec<String>,
    #[serde(default = "default_discovery_interval_secs")]
    pub discovery_interval_secs: u64,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            dynamic_interfaces: default_dynamic_interfaces(),
            bpf_filter: String::new(),
            link_patterns: default_link_patterns(),
            discovery_interval_secs: default_discovery_interval_secs(),
        }
    }
}

fn default_dynamic_interfaces() -> bool {
    true
}

fn default_link_patterns() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_discovery_interval_secs() -> u64 {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    // TCP sessions are connection-oriented; we keep them longer by default.
    #[serde(default = "default_tcp_timeout_secs")]
    pub tcp_timeout_secs: u64,
    // UDP session lifetime is configurable. If 0, we'll try to read OS/kernel defaults
    // (Linux conntrack) and otherwise fall back to a reasonable default.
    #[serde(default = "default_udp_timeout_secs")]
    pub udp_timeout_secs: u64,
    #[serde(default = "default_session_max_entries")]
    pub max_entries: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            tcp_timeout_secs: default_tcp_timeout_secs(),
            udp_timeout_secs: default_udp_timeout_secs(),
            max_entries: default_session_max_entries(),
        }
    }
}

fn default_tcp_timeout_secs() -> u64 {
    300
}

fn default_udp_timeout_secs() -> u64 {
    0
}

fn default_session_max_entries() -> usize {
    1_000_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerConfig {
    #[serde(default)]
    pub plugins: Vec<String>,
}

impl Default for LayerConfig {
    fn default() -> Self {
        Self { plugins: vec![] }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClusterMode {
    Gossip,
    Raft,
}

impl Default for ClusterMode {
    fn default() -> Self {
        Self::Gossip
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: ClusterMode,
    #[serde(default = "default_cluster_node_id")]
    pub node_id: String,
    #[serde(default = "default_cluster_bind_addr")]
    pub bind_addr: String,
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default = "default_cluster_heartbeat_secs")]
    pub heartbeat_secs: u64,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: ClusterMode::Gossip,
            node_id: default_cluster_node_id(),
            bind_addr: default_cluster_bind_addr(),
            peers: vec![],
            heartbeat_secs: default_cluster_heartbeat_secs(),
        }
    }
}

fn default_cluster_node_id() -> String {
    // Stable default for local dev; production should set explicitly or via env.
    "node-1".to_string()
}

fn default_cluster_bind_addr() -> String {
    "0.0.0.0:17801".to_string()
}

fn default_cluster_heartbeat_secs() -> u64 {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StorageBackend {
    LocalFs,
    S3,
    Ceph,
}

impl Default for StorageBackend {
    fn default() -> Self {
        Self::LocalFs
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StorageFormat {
    Pcap,
    PcapNg,
}

impl Default for StorageFormat {
    fn default() -> Self {
        Self::Pcap
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default)]
    pub backend: StorageBackend,
    #[serde(default)]
    pub format: StorageFormat,
    #[serde(default = "default_storage_path")]
    pub local_path: String,
    #[serde(default = "default_bucket")]
    pub bucket: String,
    #[serde(default)]
    pub endpoint: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: StorageBackend::LocalFs,
            format: StorageFormat::Pcap,
            local_path: default_storage_path(),
            bucket: default_bucket(),
            endpoint: String::new(),
        }
    }
}

fn default_storage_path() -> String {
    "./data/pcap".to_string()
}

fn default_bucket() -> String {
    "arkime-rust-capture".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexConfig {
    #[serde(default = "default_index_enabled")]
    pub enabled: bool,
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            enabled: default_index_enabled(),
            max_entries: default_max_entries(),
        }
    }
}

fn default_index_enabled() -> bool {
    true
}

fn default_max_entries() -> usize {
    200_000
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

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8080
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_output")]
    pub output: String,
    #[serde(default = "default_log_rotate_max_size_mb")]
    pub rotate_max_size_mb: u64,
    #[serde(default = "default_log_rotate_keep_files")]
    pub rotate_keep_files: usize,
    #[serde(default = "default_log_compress")]
    pub compress: bool,
    #[serde(default = "default_log_stdout")]
    pub stdout: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            output: default_log_output(),
            rotate_max_size_mb: default_log_rotate_max_size_mb(),
            rotate_keep_files: default_log_rotate_keep_files(),
            compress: default_log_compress(),
            stdout: default_log_stdout(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_output() -> String {
    "arkime-rust.log".to_string()
}

fn default_log_rotate_max_size_mb() -> u64 {
    100
}

fn default_log_rotate_keep_files() -> usize {
    10
}

fn default_log_compress() -> bool {
    true
}

fn default_log_stdout() -> bool {
    true
}

impl ArkimeConfig {
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from_path(CONFIG_PATH)
    }

    pub fn load_from_path(config_path: &str) -> Result<Self, ConfigError> {
        let config = Config::builder()
            .add_source(File::with_name(config_path).required(false))
            .add_source(Environment::with_prefix("ARKIME_RUST").separator("__"))
            .build()?;

        config.try_deserialize::<Self>()
    }
}

