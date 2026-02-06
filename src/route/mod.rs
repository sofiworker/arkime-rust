use crate::service::RuntimeStats;

pub fn render_stats(stats: RuntimeStats) -> String {
    stats.to_json()
}
