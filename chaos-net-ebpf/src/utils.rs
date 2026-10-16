use aya_ebpf::helpers::generated::bpf_get_prandom_u32;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::programs::TcContext;
use aya_ebpf::maps::PerCpuHashMap;
use chaos_net_common::models::{RuleType, RuleKey, RuleStats};

pub fn unix_datetime(seconds: u64) -> (u64, u64, u64, u64, u64, u64) {
    let days = seconds / 86_400;
    let seconds_of_day = seconds % 86_400;
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;

    let shifted_days = days + 719_468;
    let era = shifted_days / 146_097;
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096)
            / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };

    (year, month, day, hour, minute, second)
}

fn apply_jitter(delay_ns: u64, jitter_ns: u64) -> u64 {
    if jitter_ns == 0 {
        return delay_ns;
    }

    let rnd = unsafe { bpf_get_prandom_u32() } as u64;

    let range = jitter_ns * 2 + 1;
    let offset = rnd % range;

    let min_delay = delay_ns.saturating_sub(jitter_ns);

    min_delay + offset
}

pub fn get_target(
    ctx: &TcContext, 
    delay_ns: u64, 
    jitter_ns: u64,
    clock_offset_ns: u64, 
    rule_type: RuleType
) -> u64 {
    let now = unsafe { bpf_ktime_get_ns() };
    let actual_delay_ns = apply_jitter(delay_ns, jitter_ns);
    let target = now + actual_delay_ns;
    let target_unix_ns = target + clock_offset_ns;
    let target_unix_seconds = target_unix_ns / 1_000_000_000;
    let millisecond = (target_unix_ns % 1_000_000_000) / 1_000_000;
    let (year, month, day, hour, minute, second) = unix_datetime(target_unix_seconds);
    aya_log_ebpf::info!(
        &ctx,
        "delay rule={} packet: target_utc={}-{}-{}T{}:{}:{}.{}Z delay_ms={}",
        <RuleType as Into<&'static str>>::into(rule_type),
        year,
        month,
        day,
        hour,
        minute,
        second,
        millisecond,
        actual_delay_ns / 1_000_000
    );
    target
}

pub fn should_drop(loss_percent: u32) -> bool {
    if loss_percent == 0 {
        return false;
    }

    let random = unsafe { bpf_get_prandom_u32() } % 100;

    random < loss_percent
}

pub fn update_stats(key: &RuleKey, dropped: bool, stats: &PerCpuHashMap<RuleKey, RuleStats>) {
    if let Some(ptr) = stats.get_ptr_mut(key) {
        unsafe {
            (*ptr).total += 1;

            if dropped {
                (*ptr).dropped += 1;
            }
        }
    }
}