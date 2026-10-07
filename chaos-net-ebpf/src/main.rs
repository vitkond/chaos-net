#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{classifier, map},
    maps::{Array, HashMap},
    programs::TcContext
};
use chaos_net_common::models::{ChaosRule, RuleKey};
use chaos_net_ebpf::{contracts::Processor, outbound::OutboundProcessor, inbound::InboundProcessor};

#[map]
static RULES: HashMap<RuleKey, ChaosRule> =
    HashMap::with_max_entries(1024, 0);

#[map]
static CLOCK_OFFSET_NS: Array<u64> = Array::with_max_entries(1, 0);

#[classifier]
pub fn chaos_outbound(ctx: TcContext) -> i32 {
    match OutboundProcessor::process(
        &ctx, 
        &RULES, 
        CLOCK_OFFSET_NS.get(0).copied().unwrap_or(0)
    ) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[classifier]
pub fn chaos_inbound(ctx: TcContext) -> i32 {
    match InboundProcessor::process(
        &ctx, 
        &RULES, 
        CLOCK_OFFSET_NS.get(0).copied().unwrap_or(0)
    ) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }   
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
