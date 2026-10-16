#!/usr/bin/env bash
# ==============================================================================
# bench_xdp_lavd.sh - Benchmark xdp-guard under sched-ext (scx_lavd) vs EEVDF
#
# Methodology:
# 1. Simulates high-rate adversarial/burst traffic against xdp-guard (XDP_DROP / Rate Limiting).
# 2. Concurrently runs a latency-sensitive application worker workload.
# 3. Compares Run A (Stock Linux EEVDF) vs Run B (sched-ext scx_lavd).
# 4. Measures:
#    - Application p95, p99, p99.9 tail latencies (jitter)
#    - SoftIRQ / IRQ CPU time saturation per core
#    - Packet processing throughput (Mpps / kpps)
# ==============================================================================

set -eo pipefail

# Ensure Cargo binaries are in PATH even under sudo
export PATH="$PATH:/home/oro/.cargo/bin:$HOME/.cargo/bin:/usr/local/bin:/usr/bin"

DURATION=30
RESULTS_DIR="bench_results_$(date +%s)"
CLIENT_NS="xdp_bench_client"
SERVER_NS="xdp_bench_server"
WORKER_PORT=8080

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

cleanup() {
    echo -e "${YELLOW}[*] Cleaning up test processes and network namespaces...${NC}"
    # Stop user schedulers if running
    killall scx_lavd 2>/dev/null || true
    # Kill background workers
    kill $(jobs -p) 2>/dev/null || true
    # Remove network namespaces
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
    echo -e "${GREEN}[+] Cleanup complete.${NC}"
}
trap cleanup EXIT INT TERM

check_dependencies() {
    echo -e "${BLUE}[+] Checking system prerequisites...${NC}"
    local missing=()
    for cmd in ip ping wrk mpstat; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing required tools: ${missing[*]}${NC}"
        echo "Please install them via: sudo apt-get install -y iproute2 sysstat wrk"
        exit 1
    fi

    # Verify sched_ext support in kernel
    if [ ! -d "/sys/kernel/sched_ext" ]; then
        echo -e "${YELLOW}[!] Warning: /sys/kernel/sched_ext not detected in this kernel.${NC}"
        echo "Make sure you are booted into a kernel built with CONFIG_SCHED_CLASS_EXT=y (Linux 6.12+)."
    fi
}

setup_network_testbed() {
    echo -e "${BLUE}[+] Setting up virtual ethernet namespaces...${NC}"
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true

    ip netns add "$CLIENT_NS"
    ip netns add "$SERVER_NS"

    ip link add veth_bench_c type veth peer name veth_bench_s
    ip link set veth_bench_c netns "$CLIENT_NS"
    ip link set veth_bench_s netns "$SERVER_NS"

    ip netns exec "$CLIENT_NS" ip addr add 10.200.0.2/24 dev veth_bench_c
    ip netns exec "$CLIENT_NS" ip link set veth_bench_c up
    ip netns exec "$CLIENT_NS" ip link set lo up

    ip netns exec "$SERVER_NS" ip addr add 10.200.0.1/24 dev veth_bench_s
    ip netns exec "$SERVER_NS" ip link set veth_bench_s up
    ip netns exec "$SERVER_NS" ip link set lo up

    # Baseline ping check
    ip netns exec "$CLIENT_NS" ping -c 2 10.200.0.1 > /dev/null
    echo -e "${GREEN}[+] Network namespace testbed initialized (10.200.0.1 <-> 10.200.0.2).${NC}"
}

run_benchmark_pass() {
    local SCHED_NAME="$1"
    local OUT_FILE="$RESULTS_DIR/${SCHED_NAME}.txt"
    echo -e "${BLUE}============================================================${NC}"
    echo -e "${GREEN}[+] Running Benchmark Pass: ${SCHED_NAME}${NC}"
    echo -e "${BLUE}============================================================${NC}"

    # 1. Start scheduler if scx_lavd
    if [ "$SCHED_NAME" == "scx_lavd" ]; then
        if command -v scx_lavd &>/dev/null; then
            echo "[*] Activating scx_lavd..."
            scx_lavd &
            sleep 2
        else
            echo -e "${RED}[!] scx_lavd binary not found in PATH. Skipping scx_lavd pass.${NC}"
            return
        fi
    else
        echo "[*] Running on default Linux scheduler (EEVDF/CFS)..."
    fi

    # 2. Attach xdp-guard in server namespace
    local SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
    local XDP_BIN=""
    local EBPF_BIN="$PROJECT_ROOT/target/bpfel-unknown-none/release/xdp-guard-ebpf"

    if [ -f "$PROJECT_ROOT/target/release/xdp-guard" ]; then
        XDP_BIN="$PROJECT_ROOT/target/release/xdp-guard"
    elif command -v xdp-guard &>/dev/null; then
        XDP_BIN="$(command -v xdp-guard)"
    else
        echo -e "${RED}[!] xdp-guard binary not found! Please run 'cargo build --release -p xdp-guard' first.${NC}"
        return 1
    fi

    if [ ! -f "$EBPF_BIN" ]; then
        echo -e "${RED}[!] eBPF bytecode not found at: $EBPF_BIN${NC}"
        echo "Please compile the eBPF kernel target first via:"
        echo "  cargo xtask build-ebpf"
        return 1
    fi

    echo "[*] Attaching xdp-guard ($XDP_BIN) in server namespace..."
    ip netns exec "$SERVER_NS" "$XDP_BIN" attach --iface veth_bench_s --mode skb --ebpf-path "$EBPF_BIN" &
    XDP_PID=$!
    sleep 3

    # 3. Start mock HTTP latency worker inside server namespace
    echo "[*] Starting latency-critical worker service on port $WORKER_PORT..."
    ip netns exec "$SERVER_NS" python3 -m http.server "$WORKER_PORT" --bind 10.200.0.1 &>/dev/null &
    WORKER_PID=$!

    # Wait until HTTP server is actively accepting connections
    echo "[*] Waiting for worker service to be ready..."
    for i in {1..30}; do
        if ip netns exec "$CLIENT_NS" nc -z -w 1 10.200.0.1 "$WORKER_PORT" 2>/dev/null; then
            echo "[+] Worker service is ready on port $WORKER_PORT!"
            break
        fi
        sleep 0.5
    done

    # 4. Start concurrent high-rate network traffic from client namespace
    echo "[*] Generating burst traffic and measuring latency over ${DURATION}s..."
    # Background flood
    ip netns exec "$CLIENT_NS" ping -f -s 1400 10.200.0.1 &>/dev/null &
    FLOOD_PID=$!

    # 5. Measure CPU softirq load in background
    mpstat -P ALL 1 "$DURATION" > "$RESULTS_DIR/${SCHED_NAME}_cpu.txt" &
    MPSTAT_PID=$!

    # 6. Execute latency load testing (wrk)
    ip netns exec "$CLIENT_NS" wrk -t4 -c40 -d"${DURATION}s" --latency "http://10.200.0.1:$WORKER_PORT/" > "$OUT_FILE"

    # Stop background traffic and worker
    kill "$FLOOD_PID" "$WORKER_PID" "$XDP_PID" 2>/dev/null || true
    wait "$MPSTAT_PID" 2>/dev/null || true

    if [ "$SCHED_NAME" == "scx_lavd" ]; then
        killall scx_lavd 2>/dev/null || true
        sleep 2
    fi

    echo -e "${GREEN}[+] Pass finished for: ${SCHED_NAME}. Results saved to ${OUT_FILE}.${NC}"
}

main() {
    mkdir -p "$RESULTS_DIR"
    check_dependencies
    setup_network_testbed

    # Run Pass 1: Stock Linux Scheduler (EEVDF)
    run_benchmark_pass "stock_eevdf"
    sleep 3

    # Run Pass 2: sched-ext scx_lavd
    run_benchmark_pass "scx_lavd"

    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}                  BENCHMARK COMPLETE                        ${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo "Summary results located in: $RESULTS_DIR"
    echo ""
    echo "Compare tail latencies using:"
    echo "  cat $RESULTS_DIR/stock_eevdf.txt"
    echo "  cat $RESULTS_DIR/scx_lavd.txt"
}

main "$@"
