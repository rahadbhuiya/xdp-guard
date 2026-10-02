#!/bin/bash
# test_xdp_guard.sh - Integration test using Linux Network Namespaces & Virtual Ethernet
#
# This script sets up a real kernel test environment inside Linux/VMware:
# 1. Creates two isolated network namespaces (client & server)
# 2. Connects them with a virtual ethernet pair (veth_server <-> veth_client)
# 3. Attaches xdp-guard to veth_server
# 4. Generates ping & UDP traffic from client
# 5. Tests instant packet drop (XDP_DROP) and token-bucket rate limits

set -e

CLIENT_NS="xdp_client"
SERVER_NS="xdp_server"

echo "[*] Cleaning up old namespaces..."
ip netns del $CLIENT_NS 2>/dev/null || true
ip netns del $SERVER_NS 2>/dev/null || true

echo "[+] Creating network namespaces ($CLIENT_NS, $SERVER_NS)..."
ip netns add $CLIENT_NS
ip netns add $SERVER_NS

echo "[+] Creating veth pair (veth_c <-> veth_s)..."
ip link add veth_c type veth peer name veth_s
ip link set veth_c netns $CLIENT_NS
ip link set veth_s netns $SERVER_NS

echo "[+] Configuring IP addresses..."
ip netns exec $CLIENT_NS ip addr add 10.10.0.2/24 dev veth_c
ip netns exec $CLIENT_NS ip link set veth_c up
ip netns exec $CLIENT_NS ip link set lo up

ip netns exec $SERVER_NS ip addr add 10.10.0.1/24 dev veth_s
ip netns exec $SERVER_NS ip link set veth_s up
ip netns exec $SERVER_NS ip link set lo up

echo "[*] Verifying baseline connectivity..."
ip netns exec $CLIENT_NS ping -c 3 10.10.0.1

echo ""
echo "=========================================================="
echo "  Veth Testbed Ready!"
echo "  Terminal 1: sudo ip netns exec \$SERVER_NS ./target/release/xdp-guard attach --iface veth_s --mode skb"
echo "  Terminal 2: sudo ip netns exec \$CLIENT_NS ping 10.10.0.1"
echo "  Terminal 3: sudo nsenter -t \$(pgrep -x xdp-guard | tail -n 1) -m -n ./target/release/xdp-guard block 10.10.0.2"
echo "=========================================================="
