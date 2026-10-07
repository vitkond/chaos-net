use aya_ebpf::programs::TcContext;
use chaos_net_common::models::{ChaosRule, RuleKey};
use aya_ebpf::maps::HashMap;

pub trait Processor {
    fn process(ctx: &TcContext,
        rules: &HashMap<RuleKey, ChaosRule>,
        clock_offset_ns: u64,
    ) -> Result<i32, i32>;
}