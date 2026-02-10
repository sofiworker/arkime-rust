use crate::conf::ArkimeConfig;
use clap::{Arg, Command};

pub fn cluster() -> Command {
    Command::new("cluster")
        .about("cluster metadata plane")
        .subcommand_required(true)
        .subcommands([
            Command::new("run")
                .about("run cluster gossip metadata node")
                .arg(
                    Arg::new("config")
                        .long("config")
                        .default_value("src/config.toml")
                        .help("config file path"),
                ),
            Command::new("dump")
                .about("dump local metadata (requires cluster enabled)")
                .arg(
                    Arg::new("config")
                        .long("config")
                        .default_value("src/config.toml")
                        .help("config file path"),
                ),
        ])
}

pub fn run_cluster(config_path: Option<&str>) {
    let cfg = match config_path {
        Some(path) => ArkimeConfig::load_from_path(path).expect("failed to load config"),
        None => ArkimeConfig::load().expect("failed to load config"),
    };

    if let Err(err) = crate::logging::init(&cfg.log) {
        eprintln!("init logging failed: {err}");
    }

    if !cfg.cluster.enabled {
        eprintln!("cluster.enabled=false");
        return;
    }

    if cfg.cluster.mode != crate::conf::ClusterMode::Gossip {
        eprintln!("cluster.mode is not gossip (only gossip is implemented currently)");
        return;
    }

    let bind = match crate::cluster::gossip::parse_socket_addr(&cfg.cluster.bind_addr) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("invalid cluster.bind_addr: {e}");
            return;
        }
    };

    let mut peers = Vec::new();
    for p in &cfg.cluster.peers {
        match crate::cluster::gossip::parse_socket_addr(p) {
            Ok(a) => peers.push(a),
            Err(e) => eprintln!("invalid cluster peer addr {p}: {e}"),
        }
    }

    let gc = crate::cluster::gossip::GossipCluster::new(crate::cluster::gossip::GossipConfig {
        node_id: cfg.cluster.node_id.clone(),
        bind_addr: bind,
        peers,
        heartbeat_secs: cfg.cluster.heartbeat_secs,
    });

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    let _ = rt.block_on(gc.run());
}

pub fn dump_cluster(config_path: Option<&str>) {
    let cfg = match config_path {
        Some(path) => ArkimeConfig::load_from_path(path).expect("failed to load config"),
        None => ArkimeConfig::load().expect("failed to load config"),
    };

    if !cfg.cluster.enabled {
        eprintln!("cluster.enabled=false");
        return;
    }

    // This is a placeholder until we expose a local admin API. For now, it's a no-op.
    eprintln!("cluster dump not implemented (needs local admin api or persisted store)");
}

