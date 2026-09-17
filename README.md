# voidGate

Multi-layer XDP shield for a single Linux VM. Silent unless the instance
is under attack.

Website: [https://lynch1981.github.io/VoidGate/](https://lynch1981.github.io/VoidGate/).
Source is [`docs/`](docs/). Enable once in the GitHub UI: Settings → Pages →
Deploy from a branch → `main` / `/docs`.

Watch the NIC idle, keep the VM reachable, cut attacker hosts, then
widen to `/24` or `/64` when the cluster is dense. There is no NetFlow,
sFlow, AF_PACKET, or AF_XDP. Packets are not redirected to userspace.
The XDP program either `XDP_PASS` or `XDP_DROP`. Userspace is the
control plane: it watches coarse rx rates, and only when the NIC is
flooded does it arm the gate, count sources, and install CIDRs into a
BPF LPM drop tree.

```
IDLE  ── wake_pps / wake_mbps ──► ACTIVE ── quiet clear_seconds ──► IDLE
         cfg.armed = 0                 cfg.armed = 1
         parse: no                     parse + LPM drop + counters
```

## Requirements

- Linux 5.8+ with BTF (`/sys/kernel/btf/vmlinux`)
- clang, llvm, libbpf, bpftool, libelf
- `CAP_BPF` + `CAP_NET_ADMIN` (root is fine)

On Ubuntu 24.04:

```
sudo apt install clang llvm libbpf-dev libelf-dev zlib1g-dev \
    linux-tools-generic make gcc
make
sudo ./tests/test_xdp
```

## Run

```
sudo ./voidgate -c configs/voidgate.conf -i eth0
sudo ./voidgatectl status
sudo ./voidgatectl drop 203.0.113.0/24
sudo ./voidgatectl disarm
```

Prometheus: `http://127.0.0.1:9105/metrics`

Edit `interface` in the config to the VM's public NIC. Do not point this
at a shared management-only interface you cannot afford to XDP-attach;
the idle path is `XDP_PASS`, but attach still requires driver/SKB XDP.

## How it decides

- **IDLE**: XDP increments `rx_pkts` / `rx_bytes` and passes. Userspace
  polls those counters. No drop tree, no per-source maps written.
- **ACTIVE**: XDP parses IPv4/IPv6, hard-passes NDP/SSH/DHCP, drops
  prefixes in `drop_v4`/`drop_v6`, counts local hosts and remote sources.
- Control plane inserts attacker `/32`/`/128` (and aggregates to
  `/24`/`/64` when dense). It will not install a prefix that covers the
  VM itself or the allow list.
- When the flood is gone for `clear_seconds` and the drop tree is empty,
  it disarms. Remote LRU maps are **not** wiped (no cheap BPF clear);
  rates are re-baselined on the next arm.

## Layout

```
src/bpf/voidgate.bpf.c   XDP program
src/bpf/voidgate.h       shared map/packet structs
src/voidgate.c           daemon
src/voidgatectl.c        voidgatectl
src/policy.c             IDLE/ACTIVE policy
src/maps.c               libbpf attach + LPM helpers
```
