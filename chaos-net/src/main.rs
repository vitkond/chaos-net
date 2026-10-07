mod helpers;
use aya::{maps::{Array, HashMap}, programs::{SchedClassifier, TcAttachType, tc}};
use chaos_net_common::models::{ChaosRule, RuleKey};
use helpers::parse_rule;
use clap::Parser;
use log::info;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

use std::{
    fs::File, os::fd::AsRawFd,
};

#[derive(Debug, Parser)]
struct Opt {
    #[arg(short, long, default_value = "eth0")]
    iface: String,

    #[arg(long)]
    container: String,

    #[arg(long = "rule")]
    rules: Vec<String>,
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

fn enter_netns(pid: u32) -> anyhow::Result<()> {
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

fn container_pid(name: &str) -> anyhow::Result<u32> {
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

fn clock_ns(clock_id: libc::clockid_t) -> anyhow::Result<u64> {
    let mut timestamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(clock_id, &mut timestamp) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(timestamp.tv_sec as u64 * 1_000_000_000 + timestamp.tv_nsec as u64)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let pid = container_pid(&opt.container)?;

    env_logger::init();

    info!("container pid: {pid}");

    enter_netns(pid)?;

    info!("entered network namespace of container {pid}");

    ensure_fq(&opt.iface)?;
    info!("fq installed on {}", opt.iface);

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/chaos-net"
    )))?;
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
    let Opt { iface, .. } = opt;
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&iface);
    {
        let program: &mut SchedClassifier = ebpf.program_mut("chaos_outbound").unwrap().try_into()?;
        program.load()?;
    }

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
    }

    let program: &mut SchedClassifier = ebpf.program_mut("chaos_outbound").unwrap().try_into()?;
    program.attach(&iface, TcAttachType::Egress)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("\nExiting...");

    Ok(())
}
