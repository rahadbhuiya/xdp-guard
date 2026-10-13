#!/bin/sh
set -e

# xdp-guard installer
# Installs pre-compiled xdp-guard binary and systemd service on Linux

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "${BLUE}=== xdp-guard Linux Kernel eBPF Firewall Installer ===${NC}"

# Check root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "${RED}Error: xdp-guard must be installed as root to interact with Linux BPF subsystem.${NC}"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        TARGET="x86_64-unknown-linux-gnu"
        ;;
    aarch64|arm64)
        TARGET="aarch64-unknown-linux-gnu"
        ;;
    *)
        echo "${RED}Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

# Check Cargo / Rust availability
if command -v cargo >/dev/null 2>&1; then
    echo "${GREEN}[*] Rust toolchain detected. Installing via cargo...${NC}"
    cargo install xdp-guard --locked
    INSTALL_DIR="/usr/local/bin"
    cp "$(which xdp-guard 2>/dev/null || echo "$HOME/.cargo/bin/xdp-guard")" "$INSTALL_DIR/xdp-guard"
else
    echo "${BLUE}[*] Fetching latest release binary from GitHub...${NC}"
    LATEST_URL="https://github.com/rahadbhuiya/xdp-guard/releases/latest/download/xdp-guard-${TARGET}.tar.gz"
    TMP_DIR=$(mktemp -d)
    
    if curl -sSLf "$LATEST_URL" -o "$TMP_DIR/xdp-guard.tar.gz" 2>/dev/null; then
        tar -xzf "$TMP_DIR/xdp-guard.tar.gz" -C "$TMP_DIR"
        install -m 755 "$TMP_DIR/xdp-guard" /usr/local/bin/xdp-guard
        rm -rf "$TMP_DIR"
    else
        echo "${RED}Binary download failed. Please ensure Rust is installed or download from releases page.${NC}"
        exit 1
    fi
fi

chmod +x /usr/local/bin/xdp-guard
echo "${GREEN}[+] xdp-guard installed successfully at /usr/local/bin/xdp-guard${NC}"
echo ""
echo "Quick Start:"
echo "  xdp-guard attach -i eth0"
echo "  xdp-guard block -i 198.51.100.24"
echo "  xdp-guard stats"
