# chaos-net

`chaos-net` is a Linux traffic-chaos prototype written in Rust with Aya/eBPF. It
attaches tc classifiers to both sides of a Podman container's veth pair and applies
rules to matching IPv4/TCP traffic.

The current implementation can:

- delay inbound and outbound packets;
- add random jitter to that delay;
- randomly drop a percentage of packets;
- independently limit inbound and outbound bandwidth with tc TBF;
- report per-rule packet and drop counts every three seconds.

Rules are held in eBPF maps and disappear when the process exits. The program
currently handles IPv4/TCP only and targets one running Podman container per process.

## Repository layout

| Path | Purpose |
| --- | --- |
| `chaos-net/` | Userspace CLI: finds the container, enters its network namespace, configures qdiscs, loads and attaches eBPF programs, and reports statistics. |
| `chaos-net-ebpf/` | `no_std` eBPF traffic-control classifiers for inbound and outbound traffic. |
| `chaos-net-common/` | Shared rule keys, rule values, types, and statistics structures. |
| `justfile` | Example development build-and-run command. |
| `Brewfile` | macOS packages used for cross-compilation. |

The userspace build script builds `chaos-net-ebpf` and embeds the object in the
`chaos-net` executable.

## Requirements

Building requires:

- stable Rust;
- nightly Rust with the `rust-src` component (used for the eBPF target);
- [`bpf-linker`](https://github.com/aya-rs/bpf-linker).

```shell
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

Running requires a Linux host with eBPF and traffic-control support, plus:

- a running Podman container;
- `podman`, `ip`, and `tc` in `PATH` (`ip` and `tc` normally come from
  `iproute2`);
- access to the container's network namespace;
- permission to load eBPF, change qdiscs, and attach tc programs.

macOS can build a Linux executable, but cannot run it natively because the runtime
uses Linux network namespaces, tc, and eBPF.

## Build

Building does **not** require root:

```shell
cargo build
```

For an optimized binary:

```shell
cargo build --release
```

## Run

The simplest development invocation uses `sudo` because execution performs
privileged kernel operations:

```shell
sudo env RUST_LOG=info ./target/debug/chaos-net \
  --container chaos-test \
  --iface eth0 \
  --outbound-rate 10mbit \
  --inbound-rate 5mbit \
  --rule "Outbound 10.88.0.1:8080 delay=100 jitter=30 loss=10" \
  --rule "Inbound 10.88.0.1:8080 delay=100 jitter=30 loss=10"
```

`just run` builds and runs that example. Replace the container, interface,
destination/source, and rule values for your environment. Press Ctrl-C to detach
the eBPF links and stop reporting.

### Bandwidth limits

Both rate options are optional and use rate strings accepted by `tc`, such as
`10mbit`:

| Option | Direction and interface |
| --- | --- |
| `--outbound-rate` | Traffic leaving the container through `--iface`. |
| `--inbound-rate` | Traffic entering the container through the host-side veth peer. |

For each direction with a rate set, the program installs a root TBF qdisc with
that rate, a fixed `burst` of `32kbit`, and `latency` of `400ms`, then attaches an
FQ qdisc beneath it. Without a rate, it installs a root FQ qdisc for that
direction. Rate limits apply to all traffic on the corresponding interface,
independently of the IPv4/TCP rules below.

### Rule format

```text
<Inbound|Outbound> <IPv4>:<port> delay=<ms> jitter=<ms> loss=<percent>
```

- `Outbound` matches the destination address and port.
- `Inbound` matches the source address and port.
- `delay`, `jitter`, and `loss` default to zero when omitted.
- `jitter` randomizes delay over approximately `delay - jitter` through
  `delay + jitter`; the lower bound saturates at zero.
- `loss` is an integer percentage. Use values from `0` through `100`.

## Permissions: is root required?

The process does not inherently need UID 0, but it cannot be fully unprivileged.
It needs Linux capabilities for four operations:

| Operation | Capability normally required |
| --- | --- |
| Enter the container network namespace and return to the host namespace | `CAP_SYS_ADMIN` |
| Replace qdiscs and attach tc classifiers | `CAP_NET_ADMIN` |
| Load and work with eBPF programs/maps on modern kernels | `CAP_BPF` and, depending on kernel/program type, `CAP_PERFMON` |
| Raise the locked-memory limit on older kernels | `CAP_SYS_RESOURCE` |

Using `sudo` is the most portable option. With the code as it currently stands,
putting file capabilities on `chaos-net` alone is **not enough**: the program runs
the external `tc` executable, and ordinary file capabilities are not automatically
inherited by that child process.

It is possible to avoid UID 0 by launching a fixed, root-owned release binary from
a system service with:

- `User=<dedicated-user>`;
- the capabilities above in both `AmbientCapabilities=` and
  `CapabilityBoundingSet=`;
- `NoNewPrivileges=false`, because ambient capabilities must cross the `tc`
  exec boundary;
- the correct Podman environment for that user.

This is still highly privileged—especially because of `CAP_SYS_ADMIN`—but it has
a narrower boundary than unrestricted root. Do not attach these capabilities to a
binary that an unprivileged user can replace. Older kernels that predate `CAP_BPF`
may require broader privileges.

A future implementation can avoid root more cleanly by replacing the `tc`
subprocess with an in-process netlink API and by moving namespace/qdisc/eBPF setup
into a small privileged helper. The current single-process implementation does not
offer a truly unprivileged execution mode.

Also note that `sudo ... chaos-net` invokes Podman as root, so it normally sees
root's containers, not containers created by rootless Podman under another user.
A capability-limited service running as that user, or explicit support for a
rootless Podman connection, is needed for that case.

### Networking side effects and cleanup

The program replaces the root qdisc on the container interface and its host peer
with FQ, or TBF with an FQ child when a rate is supplied, then adds `clsact`.
The attached classifier links are dropped when the program exits, but the qdisc
configuration, including bandwidth limits, can remain. Inspect the host peer with:

```shell
sudo tc qdisc show dev <interface>
```

Only remove a qdisc after confirming that nothing else relies on it:

```shell
sudo tc qdisc del dev <interface> clsact
sudo tc qdisc del dev <interface> root
```

To inspect or remove qdiscs on the container interface, run the same commands in
the container's network namespace, for example with
`sudo nsenter -t <container-pid> -n tc qdisc show dev eth0`.

## Cross-compile on macOS

Cross-compilation should work on both Intel and Apple Silicon Macs. Install LLVM
(the included `Brewfile` can be used with Homebrew), install the Rust target, and
choose the target architecture, for example `x86_64` or `aarch64`:

```shell
rustup target add ${ARCH}-unknown-linux-musl

cargo build --package chaos-net --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"rust-lld\"
```

The result is `target/${ARCH}-unknown-linux-musl/release/chaos-net`; copy it to a
compatible Linux host to run it.

## License

Except for the eBPF code, this project is available under either the [MIT license]
or the [Apache License 2.0], at your option. The eBPF code is available under either
the [MIT license] or the [GNU General Public License, Version 2], at your option.

[Apache License 2.0]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
