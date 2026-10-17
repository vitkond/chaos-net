mod helpers;

use std::fs::File;

use aya::{maps::{Array, HashMap, MapData, PerCpuHashMap, PerCpuValues}, programs::{SchedClassifier, TcAttachType, tc}};
use chaos_net_common::models::{ChaosRule, RuleKey, RuleStats};
use helpers::{parse_rule, enter_netns, container_pid, clock_ns};
use clap::Parser;
use log::info;
#[rustfmt::skip]
use log::warn;
use tokio::signal;
use helpers::log_drops;

use crate::helpers::{input_iface_by_peer_index, peer_ifindex, switch_netns};

#[derive(Debug, Parser)]
struct Opt {
    #[arg(short, long, default_value = "eth0")]
    iface: String,

    #[arg(long)]
    container: String,

    #[arg(long = "rule")]
    rules: Vec<String>,

    #[arg(long)]
    outbound_rate: Option<String>,

    #[arg(long)]
    inbound_rate: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let pid = container_pid(&opt.container)?;

    env_logger::init();

    info!("container pid: {pid}");

    let host_netns = File::open("/proc/self/ns/net")?;

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/chaos-net"
    )))?;

    /* Apply outbound settings */
    enter_netns(pid)?;
    info!("entered network namespace of container {pid}");

    let host_ifindex = peer_ifindex(&opt.iface)?;
    info!("host peer ifindex: {host_ifindex}");


    helpers::configure_qdisc(&opt.iface, opt.outbound_rate.as_deref())?;
    info!("qdisc configured on outbound container interface {}", opt.iface);

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("remove limit on locked memory failed, ret is: {ret}");
    }

    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);
    {
        let program: &mut SchedClassifier = ebpf.program_mut("chaos_outbound").unwrap().try_into()?;
        program.load()?;
    }
    let program_outbound: &mut SchedClassifier = ebpf.program_mut("chaos_outbound").unwrap().try_into()?;
    let outbound_link_id = program_outbound.attach(
        &opt.iface, TcAttachType::Egress)?;
    /* End of outbound settings */


    /* Apply inbound settings */
    switch_netns(&host_netns)?;
    let inbound_iface = input_iface_by_peer_index(host_ifindex)?;
    info!("inbound interface: {inbound_iface}");

    helpers::configure_qdisc(&inbound_iface, opt.inbound_rate.as_deref())?;
    info!("qdisc configured on inbound host interface {}", inbound_iface);

    let _ = tc::qdisc_add_clsact(&inbound_iface);
    {
        let program: &mut SchedClassifier = ebpf.program_mut("chaos_inbound").unwrap().try_into()?;
        program.load()?;
    }

    let program_inbound: &mut SchedClassifier = ebpf.program_mut("chaos_inbound").unwrap().try_into()?;
    let inbound_link_id = program_inbound.attach(&inbound_iface, TcAttachType::Egress)?;
    /* End of inbound settings */

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let nr_cpus = aya::util::nr_cpus().map_err(|(_, e)| e)?;

    let mut stats_map: PerCpuHashMap<MapData, RuleKey, RuleStats> =
        PerCpuHashMap::<_, RuleKey, RuleStats>::try_from(
            ebpf.take_map("STATS").unwrap()
        )?;
    
    let realtime_ns = clock_ns(libc::CLOCK_REALTIME)?;
    let monotonic_ns = clock_ns(libc::CLOCK_MONOTONIC)?;
    let clock_offset_ns = realtime_ns
        .checked_sub(monotonic_ns)
        .ok_or_else(|| anyhow::anyhow!("CLOCK_REALTIME precedes CLOCK_MONOTONIC"))?;
    let mut clock_offset_map =
        Array::<_, u64>::try_from(ebpf.map_mut("CLOCK_OFFSET_NS").unwrap())?;
    clock_offset_map.set(0, clock_offset_ns, 0)?;

    let mut chaos_rule_map =
            HashMap::<_, RuleKey, ChaosRule>::try_from(ebpf.map_mut("RULES").unwrap())?;
    for rule in &opt.rules {
        let (rule_key, chaos_rule) = parse_rule(rule)?;
        chaos_rule_map.insert(rule_key, chaos_rule, 0)?;
        
        let zero_stats = PerCpuValues::try_from(
            vec![RuleStats::default(); nr_cpus]
        )?;
        stats_map.insert(rule_key, zero_stats, 0)?;
    }

    tokio::spawn(log_drops::log_drops(stats_map));

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("\nExiting...");

    // 1. Host namespace — inbound
    {
        let program: &mut SchedClassifier =
            ebpf.program_mut("chaos_inbound").unwrap().try_into()?;

        program.detach(inbound_link_id)?;
    }

    helpers::remove_root_qdisc(&inbound_iface)?;

    // 2. Container namespace — outbound
    enter_netns(pid)?;

    {
        let program: &mut SchedClassifier =
            ebpf.program_mut("chaos_outbound").unwrap().try_into()?;

        program.detach(outbound_link_id)?;
    }

    helpers::remove_root_qdisc(&opt.iface)?;

    // 3. Back to host namespace
    switch_netns(&host_netns)?;

    Ok(())
}
