use aya_log_ebpf::info;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::programs::TcContext;

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

pub fn get_target(ctx: &TcContext, delay_ns: u64, clock_offset_ns: u64) -> u64 {
    let now = unsafe { bpf_ktime_get_ns() };
    let target = now + delay_ns;
    let target_unix_ns = target + clock_offset_ns;
    let target_unix_seconds = target_unix_ns / 1_000_000_000;
    let millisecond = (target_unix_ns % 1_000_000_000) / 1_000_000;
    let (year, month, day, hour, minute, second) = unix_datetime(target_unix_seconds);
    info!(
        &ctx,
        "delay packet: target_utc={}-{}-{}T{}:{}:{}.{}Z delay_ms={}",
        year,
        month,
        day,
        hour,
        minute,
        second,
        millisecond,
        delay_ns / 1_000_000
    );
    target
}