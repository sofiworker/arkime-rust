use crate::conf::LogConfig;
use std::io;
use std::path::PathBuf;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::fmt::writer::MakeWriterExt;

mod rotating;

pub fn init(cfg: &LogConfig) -> io::Result<()> {
    let level = parse_level(&cfg.level);

    let make_file = rotating::RotatingMakeWriter::new(
        PathBuf::from(&cfg.output),
        cfg.rotate_max_size_mb.saturating_mul(1024 * 1024),
        cfg.rotate_keep_files,
        cfg.compress,
    )?;

    let writer: BoxMakeWriter = if cfg.stdout {
        BoxMakeWriter::new(make_file.and(std::io::stdout))
    } else {
        BoxMakeWriter::new(make_file)
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_ansi(cfg.stdout)
        .with_writer(writer)
        .with_thread_ids(true)
        .with_thread_names(true)
        .try_init()
        .ok();

    Ok(())
}

fn parse_level(level: &str) -> LevelFilter {
    match level.to_ascii_lowercase().as_str() {
        "trace" => LevelFilter::TRACE,
        "debug" => LevelFilter::DEBUG,
        "info" => LevelFilter::INFO,
        "warn" | "warning" => LevelFilter::WARN,
        "error" => LevelFilter::ERROR,
        _ => LevelFilter::INFO,
    }
}

