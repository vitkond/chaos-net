pub mod log_drops;
use chaos_net_common::models::{ChaosRule, ChaosRuleBuilder, RuleKey, RuleType};
use std::{
    fs::File, os::fd::AsRawFd,
};

static RULES_FORMAT: &str =
    "RULE_TYPE IP:PORT delay=MS loss=PERCENT jitter=MS";

pub fn parse_rule(rule: &str) -> anyhow::Result<(RuleKey, ChaosRule)> {
    let (rule_type, rule) = rule.split_once(' ')
    .ok_or_else(|| anyhow::anyhow!("expected {}", RULES_FORMAT))?;
    let rule_type = match RuleType::from(rule_type) {
        RuleType::Inbound => RuleType::Inbound,
        RuleType::Outbound => RuleType::Outbound,
        RuleType::Unknown => anyhow::bail!("Unknown rule type"),
    };
    let (target,  rules) = rule   
        .split_once(' ')
        .ok_or_else(|| anyhow::anyhow!("expected {}", RULES_FORMAT))?;

    let socket: std::net::SocketAddrV4 = target.parse()?;

    let rules = rules
        .split(' ')
        .collect::<Vec<_>>();
    
    let mut delay = 0;
    let mut loss = 0;
    let mut jitter = 0;
    
    for r in rules {
        if let Some((key, value)) = r.split_once('=') {
            match key {
                "delay" => {
                    delay = value.parse::<u64>()?;
                },
                "loss" => {
                    loss = value.parse::<u32>()?;
                },
                "jitter" => {
                    jitter = value.parse::<u64>()?;
                },
                _ => anyhow::bail!("unknown rule key: {}", key),
            }
        } else {
            anyhow::bail!("expected key=value format");
        }
    }

    let key = RuleKey::new(
        rule_type,
        u32::from_be_bytes(socket.ip().octets()),
        socket.port(),
        libc::IPPROTO_TCP as u8,
    );

    let rule = ChaosRuleBuilder::default()
        .delay_ns(delay * 1_000_000)
        .jitter_ns(jitter * 1_000_000)
        .loss_percent(loss)
        .build()
        .map_err(|e| 
            anyhow::anyhow!("failed to build ChaosRule: {}", e))?;

    Ok((key, rule))
}

fn ensure_fq(iface: &str) -> anyhow::Result<()> {
    use std::process::Command;

    let status = Command::new("tc")
        .args(["qdisc", "replace", "dev", iface, "root", "fq"])
        .status()?;

    if !status.success() {
        anyhow::bail!("failed to install fq on {iface}");
    }

    Ok(())
}

fn ensure_tbf(iface: &str, rate: &str, burst: &str, latency: &str) -> anyhow::Result<()> {
    use std::process::Command;

    let status = Command::new("tc")
        .args(["qdisc", "replace", "dev", iface, "root", "handle", "1:", "tbf", "rate", rate, "burst", burst, "latency", latency])
        .status()?;

    if !status.success() {
        anyhow::bail!("failed to install tbf on {iface} with rate {rate}, burst {burst}, latency {latency}");
    }

    let status = Command::new("tc")
        .args(["qdisc", "replace", "dev", iface, "parent", "1:1", "handle", "10:", "fq"])
        .status()?;

    if !status.success() {
        anyhow::bail!("failed to install fq under tbf on {iface}");
    }

    Ok(())
}

pub fn configure_qdisc(iface: &str, rate: Option<&str>) -> anyhow::Result<()> {
    match rate {
        Some(rate) => {
            ensure_tbf(iface, rate, "32kbit", "400ms")?;
        }

        None => {
            ensure_fq(iface)?;
        }
    }

    Ok(())
}

pub fn enter_netns(pid: u32) -> anyhow::Result<()> {
    let path = format!("/proc/{pid}/ns/net");
    let netns = File::open(&path)?;

    let ret = unsafe {
        libc::setns(netns.as_raw_fd(), libc::CLONE_NEWNET)
    };

    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(())
}

pub fn container_pid(name: &str) -> anyhow::Result<u32> {
    use std::process::Command;

    let output = Command::new("podman")
        .args([
            "inspect",
            "-f",
            "{{.State.Pid}}",
            name,
        ])
        .output()?;

    let stdout = String::from_utf8(output.stdout)?;
    let pid = stdout.trim().parse::<u32>()?;

    Ok(pid)
}

fn get_link_output(iface: &str) -> anyhow::Result<String> {
    let output = std::process::Command::new("ip")
        .args(["-o", "link", "show", "dev", iface])
        .output()?;

    if !output.status.success() {
        anyhow::bail!("failed to get link output for {iface}");
    }

    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout)
}

fn link_show() -> anyhow::Result<String> {
    let output = std::process::Command::new("ip")
        .args(["-o", "link", "show"])
        .output()?;

    if !output.status.success() {
        anyhow::bail!("failed to get link output for all interfaces");
    }

    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout)
}

pub fn switch_netns(netns: &File) -> anyhow::Result<()> {
    let ret = unsafe {
        libc::setns(netns.as_raw_fd(), libc::CLONE_NEWNET)
    };

    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(())
}   

pub fn input_iface_by_peer_index(peer_index: u32) -> anyhow::Result<String> {
    let lines = link_show()?;
    let lines = lines.lines().collect::<Vec<_>>();  

    let peer_index_str = format!("{peer_index}: ");

    let line = lines
    .into_iter()
    .find(|l| l.starts_with(&peer_index_str))
    .ok_or_else(|| anyhow::anyhow!("no input interface found"))?;

    let input: &str = line
        .split('@').next()
        .and_then(|s| s.strip_prefix(&peer_index_str))
        .ok_or_else(|| anyhow::anyhow!("input ifindex not found"))?;

    Ok(input.to_string())
}

pub fn peer_ifindex(iface: &str) -> anyhow::Result<u32> {

    let line = get_link_output(iface)?;

    // "2: eth0@if25: ..."
    let peer: &str = line
        .split('@')
        .nth(1)
        .and_then(|s| s.strip_prefix("if"))
        .and_then(|s| s.split(':').next())
        .ok_or_else(|| anyhow::anyhow!("peer ifindex not found"))?;

    Ok(peer.parse()?)
}

pub fn clock_ns(clock_id: libc::clockid_t) -> anyhow::Result<u64> {
    let mut timestamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(clock_id, &mut timestamp) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(timestamp.tv_sec as u64 * 1_000_000_000 + timestamp.tv_nsec as u64)
}