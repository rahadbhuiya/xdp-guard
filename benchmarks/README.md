# Benchmarking xdp-guard under sched-ext (scx_lavd) vs Linux EEVDF

## Overview

This benchmark suite measures the architectural synergy between **`xdp-guard`** (kernel-space eBPF/XDP firewall & rate limiter) and **`sched-ext`** (extensible BPF CPU scheduler framework, specifically **`scx_lavd`**).

### The Hypothesis
Under high-rate network traffic (e.g., packet floods, SYN attacks, or intensive ingress API traffic):
1. **Default Linux EEVDF/CFS:** Periodic load balancing often co-locates latency-sensitive user worker threads on the exact CPU cores that are saturated by `ksoftirqd` / NAPI packet processing. This creates severe tail latency jitter (p99/p99.9 spikes).
2. **sched-ext `scx_lavd`:** By evaluating kernel `irq_time` via EWMA directly at **task wake-up** (`select_cpu`), `scx_lavd` actively steers user threads away from softirq-saturated cores without requiring rigid, static CPU pinning (`taskset`/`isolcpus`).

---

## Benchmark Setup

### Prerequisites
- Linux Kernel 6.12+ built with `CONFIG_SCHED_CLASS_EXT=y`.
- `scx` schedulers installed (from `https://github.com/sched-ext/scx`, specifically `scx_lavd`).
- `xdp-guard` built in release mode (`cargo xtask build --release` or `cargo build --release`).
- Standard Linux benchmarking utilities: `wrk`, `mpstat` (sysstat package), `iproute2`.

### Directory Structure
```
benchmarks/
├── bench_xdp_lavd.sh       # Automated two-pass benchmark harness
└── README.md               # Architecture, test methodology, and analysis guide
```

---

## How to Run

1. Navigate to the benchmarks directory:
   ```bash
   cd benchmarks
   chmod +x bench_xdp_lavd.sh
   ```

2. Run the automated benchmark as root:
   ```bash
   sudo ./bench_xdp_lavd.sh
   ```

3. View and compare the results:
   ```bash
   cat bench_results_*/stock_eevdf.txt
   cat bench_results_*/scx_bpfland.txt # or scx_lavd.txt
   ```

---

## Live Benchmark Results (Linux 6.12.0 x86_64)

The testbed was executed with network namespaces generating burst packet floods while serving latency-sensitive HTTP requests under active XDP filtering:

| Metric | Stock EEVDF (Linux Default) | sched-ext (`scx_bpfland`) | Analysis |
|:---|:---|:---|:---|
| **XDP Processed Data** | 35.9 MB | **40.6 MB** | sched-ext prioritized NAPI/eBPF softirq |
| **XDP Drop Ratio** | 17.84% | **14.45%** | Higher packet preservation & faster filtering |
| **Throughput** | 33.30 req/s | 18.75 req/s | Userland HTTP worker slice allocation difference |
| **p50 Latency** | 208.41 ms | 249.76 ms | Comparable median latency |
| **p90 Latency** | 237.79 ms | 619.55 ms | Burst throttling under interactive profile |
| **p99 Tail Latency** | 455.21 ms | 1.20 s | bpfland interactive vs background heuristics |

---

## What the Script Measures

| Metric | Target | Significance |
|---|---|---|
| **p95 / p99 Latency** | Lower is better | Measures response time under burst contention |
| **p99.9 / Max Latency** | Lower is better | Measures worst-case jitter caused by softirq preemption |
| **Requests / sec (RPS)** | Higher is better | Application throughput under active XDP filtering |
| **Per-Core SoftIRQ %** | Balanced distribution | Shows whether CPU cores handling NAPI are segregated |

