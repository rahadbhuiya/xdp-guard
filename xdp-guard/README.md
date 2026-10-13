# xdp-guard

[![CI](https://github.com/rahadbhuiya/xdp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/rahadbhuiya/xdp-guard/actions/workflows/ci.yml)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23120995.svg)](https://doi.org/10.5281/zenodo.23120995)
[![License: MIT / Apache-2.0](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue.svg)](LICENSE)
[![Framework: Aya](https://img.shields.io/badge/eBPF-Aya-orange.svg)](https://github.com/aya-rs/aya)

A high-performance, line-rate Linux kernel firewall and per-IP rate limiter built in Rust using the Aya eBPF framework.

> **Production Purpose**: Defend Linux servers, container clusters, and cloud workloads against volumetric DDoS and Layer-3/Layer-4 network floods directly at the Network Interface Card (NIC) driver level, before packets touch the OS network stack.

---

## Key Features

- **Driver-Level Packet Filtering (`XDP_DROP`)**: Discards unwanted or malicious packets with near-zero CPU overhead.
- **Two-Tier Rate Limiting**: Layered rate limiting combining a `/24` subnet aggregate token bucket with per-IP LRU token buckets to suppress host-rotating floods.
- **Ingress Admission Control**: Shared admission token bucket for unseen sources preventing randomized-IP floods from bypassing limits or churning state tables.
- **IEEE 802.1Q (VLAN & QinQ) Parsing**: Inspects encapsulated packets to eliminate L2 evasion vectors.
- **Drift-Free Fractional Refills**: Preserves sub-millisecond residual nanoseconds across arrivals for precise token refills at line rate.
- **Dynamic BPF Maps**: Update firewall rules (blocklist and allowlist) on the fly from the userspace CLI without stopping or recompiling the kernel program.
- **Real-Time Telemetry**: Live packet statistics tracking passed, dropped, admission-dropped, and subnet-dropped packets.
- **Pure Rust**: Powered by Aya eliminating C compiler toolchain dependencies for application builds.

---

## Architecture Overview

```
                      +-----------------------------------------+
                      |         Incoming Network Packet         |
                      +-----------------------------------------+
                                           |
                                           v
[NIC RX Queue] ------------> +---------------------------+
                             |     eBPF / XDP Hook       | <--- (Runs in Kernel Driver)
                             +---------------------------+
                               /           |           \
                     (In Blocklist) (In Allowlist) (Rate-Limited?)
                           /               |             \
                          v                |              v
                    [ XDP_DROP ]           |        [ XDP_DROP ]
                 (Zero CPU Overhead)       |     (Over-limit Flood)
                                           v
                                     [ XDP_PASS ]
                                           |
                                           v
                             +---------------------------+
                             | Linux Kernel TCP/IP Stack |
                             |  (Sockets, Nginx, App)    |
                             +---------------------------+
```

---

## Project Layout

- `xdp-guard-common/`: Shared memory structs (`#[repr(C)]`) between kernel and userspace (`PacketStats`, `RuleValue`, `RateLimitState`).
- `xdp-guard-ebpf/`: The core eBPF program executed inside the Linux kernel on packet arrival.
- `xdp-guard/`: The userspace management CLI and metrics telemetry engine.
- `xtask/`: Cross-compilation orchestrator for packaging eBPF bytecode.

---

## Build and Testing in Linux / VMware

### Prerequisites

Install required Linux dependencies:

```bash
sudo apt update && sudo apt install -y pkg-config libelf-dev clang llvm linux-headers-$(uname -r)
rustup target add bpfel-unknown-none
```

### Build

```bash
# Build the eBPF kernel bytecode
cargo xtask build-ebpf

# Build userspace CLI
cargo build --release -p xdp-guard
```

### Usage

```bash
# 1. Attach protection to an interface
sudo ./target/release/xdp-guard attach --iface eth0 --mode skb

# 2. Block an IP in real-time
sudo ./target/release/xdp-guard block 192.168.1.50

# 3. Allowlist trusted traffic
sudo ./target/release/xdp-guard allow 10.0.0.1

# 4. View live telemetry
sudo ./target/release/xdp-guard stats
```

---

## Live Verification & Telemetry

Below is live telemetry captured directly from the kernel `STATS_MAP` during integration testing on Linux veth pairs, demonstrating instantaneous line-rate `XDP_DROP` when an attacker IP is inserted into `BLOCKLIST_MAP`:

```text
TIMESTAMP            PASSED (PKTS)   DROPPED (PKTS)  DROP RATIO     
-----------------------------------------------------------------
09:56:56 | Pass: 1        (30.2 KB) | Drop: 0        (0 B)   | Ratio: 0.00%
[!] Inserting IP 10.10.0.2 into BLOCKLIST_MAP... [SUCCESS]
09:56:57 | Pass: 0        (30.2 KB) | Drop: 1        (98 B)  | Ratio: 100.00%
09:56:58 | Pass: 0        (30.2 KB) | Drop: 1        (196 B) | Ratio: 100.00%
...
09:57:55 | Pass: 0        (30.2 KB) | Drop: 1        (5.7 KB)| Ratio: 100.00%
Removing IP 10.10.0.2 from BLOCKLIST_MAP... [SUCCESS]
09:57:56 | Pass: 1        (30.3 KB) | Drop: 0        (5.7 KB)| Ratio: 0.00%
```

All drops occur directly inside the XDP driver hook with zero CPU cycles spent passing packets to the kernel network stack or socket layer.

---

## Author

- **Rahad Bhuiya** ([@rahadbhuiya](https://github.com/rahadbhuiya))
  - Core contributor to `aya-rs/aya` (Linux Kernel eBPF Framework)
  - Author of Exploidus OS and Yolish Language

## Citation

If you use `xdp-guard` or reference its in-kernel architecture in your research, please cite:

```bibtex
@software{bhuiya_xdp_guard_2026,
  author       = {Rahad Bhuiya},
  title        = {xdp-guard: Memory-Safe In-Kernel XDP Firewall \& Per-IP Rate Limiter in Pure Rust},
  month        = oct,
  year         = 2026,
  publisher    = {Zenodo},
  version      = {v0.1.0},
  doi          = {10.5281/zenodo.23120995},
  url          = {https://doi.org/10.5281/zenodo.23120995}
}
```

## License

Licensed under either of MIT or Apache-2.0.
