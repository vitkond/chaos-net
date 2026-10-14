use crate::{contracts::Processor, utils};
use chaos_net_common::models::{RuleType, RuleKey, ChaosRule, RuleStats};
use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT}, helpers::generated::bpf_skb_set_tstamp,
    maps::PerCpuHashMap
};
use aya_log_ebpf::{debug, error};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

pub struct OutboundProcessor;

impl Processor for OutboundProcessor {
    fn process(
        ctx: &aya_ebpf::programs::TcContext, 
        rules: &aya_ebpf::maps::HashMap<RuleKey, ChaosRule>,
        stats: &PerCpuHashMap<RuleKey, RuleStats>,
        clock_offset_ns: u64,
    ) -> Result<i32, i32> {
        let eth: EthHdr = match ctx.load(0) {
            Ok(header) => header,
            Err(_) => {
                error!(&ctx, "failed to load Ethernet header");
                return Ok(TC_ACT_PIPE);
            }
        };
        if eth.ether_type() != Ok(EtherType::Ipv4) {
            debug!(&ctx, "skipping non-IPv4 packet");
            return Ok(TC_ACT_PIPE);
        }
        let ipv4: Ipv4Hdr = match ctx.load(EthHdr::LEN) {
            Ok(header) => header,
            Err(_) => {
                error!(&ctx, "failed to load IPv4 header");
                return Ok(TC_ACT_PIPE);
            }
        };
        let dst_ipv4 = u32::from_be_bytes(ipv4.dst_addr);
        if !matches!(ipv4.proto(), Ok(IpProto::Tcp)) {
            debug!(&ctx, "skipping non-TCP packet");
            return Ok(TC_ACT_PIPE);
        }

        let tcp_offset = EthHdr::LEN + ipv4.ihl() as usize;
        let tcp: TcpHdr = match ctx.load(tcp_offset) {
            Ok(header) => header,
            Err(_) => {
                error!(&ctx, "failed to load TCP header");
                return Ok(TC_ACT_PIPE);
            }
        };
        let dst_port = u16::from_be_bytes(tcp.dest);

        let rule_key = chaos_net_common::models::RuleKey::new(RuleType::Outbound, dst_ipv4, dst_port, IpProto::Tcp as u8);
        let chaos_rule = match unsafe { rules.get(&rule_key).copied() } {
            Some(rule) => rule,
            None => {
                debug!(&ctx, "no outbound chaos rule found for dst_ipv4={} dst_port={}", dst_ipv4, dst_port);
                return Ok(TC_ACT_PIPE);
            }
        };
        if utils::should_drop(chaos_rule.loss_percent) {
            debug!(&ctx, "dropping packet due to loss rule: dst_ipv4={} dst_port={} loss_percent={}", dst_ipv4, dst_port, chaos_rule.loss_percent);
            utils::update_stats(&rule_key, true, stats);
            return Ok(TC_ACT_SHOT);
        } else {
            utils::update_stats(&rule_key, false, stats);
        }
        let delay_ns = chaos_rule.delay_ns;
        let jitter_ns = chaos_rule.jitter_ns;
        if delay_ns > 0 {
            let target = utils::get_target(&ctx, delay_ns, jitter_ns, clock_offset_ns, RuleType::Outbound);
            unsafe { bpf_skb_set_tstamp(ctx.skb.skb, target, 1); }
        }
        Ok(TC_ACT_PIPE)
    }
}