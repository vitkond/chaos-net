use aya::maps::{MapData, PerCpuHashMap};
use chaos_net_common::models::{RuleKey, RuleStats};

pub async fn log_drops(
    stats: PerCpuHashMap<MapData, RuleKey, RuleStats>,
) {
    let stats_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(
            std::time::Duration::from_secs(3)
        );

        loop {
            interval.tick().await;

            log::info!("===== Logging drops start... ======");
            for (_, rk_vals) in stats.iter().enumerate() {
                let (rule_key, values) = match rk_vals {
                    Ok((key, vals)) => (key, vals),
                    Err(e) => {
                        log::warn!("Failed to get rule key: {e}");
                        continue;
                    }
                };

                let total: u64 = values.iter().map(|s| s.total).sum();
                let dropped: u64 = values.iter().map(|s| s.dropped).sum();

                let loss = if total == 0 {
                    0.0
                } else {
                    dropped as f64 * 100.0 / total as f64
                };

                log::info!(
                    "rule_key={:?} total={} dropped={} loss={:.2}%",
                    rule_key,
                    total,
                    dropped,
                    loss
                );
            }
            log::info!("===== Logging drops end... ======");
        }
    });
    stats_task.await.unwrap();
}