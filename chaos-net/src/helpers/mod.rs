use chaos_net_common::models::{ChaosRule, RuleKey, RuleType};

pub fn parse_rule(rule: &str) -> anyhow::Result<(RuleKey, ChaosRule)> {
    let (rule_type, rule) = rule.split_once(' ').unwrap();
    let rule_type = match RuleType::from(rule_type) {
        RuleType::Inbound => RuleType::Inbound,
        RuleType::Outbound => RuleType::Outbound,
        RuleType::Unknown => anyhow::bail!("Unknown rule type"),
    };
    let (target, delay) = rule   
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("expected IP:PORT=DELAY_MS"))?;

    let socket: std::net::SocketAddrV4 = target.parse()?;
    let delay_ms: u64 = delay.parse()?;

    let key = RuleKey::new(
        rule_type,
        u32::from_be_bytes(socket.ip().octets()),
        socket.port(),
        libc::IPPROTO_TCP as u8,
    );

    let rule = ChaosRule {
        delay_ns: delay_ms * 1_000_000,
    };

    Ok((key, rule))
}