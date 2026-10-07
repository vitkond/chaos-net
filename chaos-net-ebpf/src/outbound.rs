use crate::{contracts::Processor, utils};
use chaos_net_common::models::{RuleType, RuleKey, ChaosRule};
use aya_ebpf::{
    bindings::TC_ACT_PIPE, 
    helpers::generated::bpf_skb_set_tstamp
};
use aya_log_ebpf::info;
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
        clock_offset_ns: u64,
    ) -> Result<i32, i32> {
        let eth: EthHdr = match ctx.load(0) {
            Ok(header) => header,
            Err(_) => {
                info!(&ctx, "failed to load Ethernet header");
                return Ok(TC_ACT_PIPE);
            }
        };
        if eth.ether_type() != Ok(EtherType::Ipv4) {
            info!(&ctx, "skipping non-IPv4 packet");
            return Ok(TC_ACT_PIPE);
        }
        let ipv4: Ipv4Hdr = match ctx.load(EthHdr::LEN) {
            Ok(header) => header,
            Err(_) => {
                info!(&ctx, "failed to load IPv4 header");
                return Ok(TC_ACT_PIPE);
            }
        };
        let dst_ipv4 = u32::from_be_bytes(ipv4.dst_addr);
        if !matches!(ipv4.proto(), Ok(IpProto::Tcp)) {
            info!(&ctx, "skipping non-TCP packet");
            return Ok(TC_ACT_PIPE);
        }

        let tcp_offset = EthHdr::LEN + ipv4.ihl() as usize;
        let tcp: TcpHdr = match ctx.load(tcp_offset) {
            Ok(header) => header,
            Err(_) => {
                info!(&ctx, "failed to load TCP header");
                return Ok(TC_ACT_PIPE);
            }
        };
        let dst_port = u16::from_be_bytes(tcp.dest);

        let rule_key = chaos_net_common::models::RuleKey::new(RuleType::Outbound, dst_ipv4, dst_port, IpProto::Tcp as u8);
        let chaos_rule = match unsafe { rules.get(&rule_key).copied() } {
            Some(rule) => rule,
            None => {
                info!(&ctx, "no outbound chaos rule found for dst_ipv4={} dst_port={}", dst_ipv4, dst_port);
                return Ok(TC_ACT_PIPE);
            }
        };
        let delay_ns = chaos_rule.delay_ns;
        let target = utils::get_target(&ctx, delay_ns, clock_offset_ns);
        unsafe { bpf_skb_set_tstamp(ctx.skb.skb, target, 1); }
        Ok(TC_ACT_PIPE)
    }
}