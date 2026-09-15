#!/usr/bin/env bash
# ==============================================================================
# AEGS v6 "Titan" Global Edition -- Carrier-Grade Server Installer
# Automated dependencies, kernel sysctl tuning (10Gbps), and systemd service
# ==============================================================================
set -euo pipefail

readonly C_RESET='\033[0m'
readonly C_BOLD='\033[1m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_CYAN='\033[0;36m'
readonly C_RED='\033[0;31m'
readonly C_WHITE='\033[1;37m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${C_RED}[ERROR] This script must be run as root. Please run with sudo:${C_RESET}"
    echo "  curl -fsSL https://raw.githubusercontent.com/XDGOOD/AEGS-Global-/main/install.sh | sudo bash"
    exit 1
fi

echo -e "${C_CYAN}${C_BOLD}"
cat << "EOF"
========================================================================
   ___    ______ _____ ____         ______ __       __            __
  /   |  / ____// ___// __ \ _    / ____// /____  / /_  ____ _   / /
 / /| | / __/  / / _ / / / /| |  / / __ / // __ \/ __ \/ __ `/  / / 
/ ___ |/ /___ / /_/ // /_/ / | | / /_/ // // /_/ / /_/ / /_/ /  /_/  
/_/  |_/_____/ \____(_)____/  |_| \____//_/ \____/_.___/\__,_/  (_)   
  🌐 AEGS Global Enterprise Edition -- 10+ Gbps Target Architecture
========================================================================
EOF
echo -e "${C_RESET}"

INSTALL_DIR="/opt/aegs-global"
REPO_URL="https://github.com/XDGOOD/AEGS-Global-.git"

# 1. Install build dependencies
echo -e "${C_CYAN}[1/6] Installing build dependencies (CMake, GCC/G++, OpenSSL, SQLite3)...${C_RESET}"
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq build-essential cmake pkg-config libssl-dev libsqlite3-dev git
elif command -v dnf >/dev/null 2>&1; then
    dnf groupinstall -y "Development Tools"
    dnf install -y cmake pkgconf openssl-devel sqlite-devel git
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm base-devel cmake pkgconf openssl sqlite git
elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache build-base cmake pkgconf openssl-dev sqlite-dev linux-headers git
fi

# 2. Clone or locate repository
if [[ -f "./server.cpp" && -f "./CMakeLists.txt" ]]; then
    SOURCE_DIR="$(pwd)"
    echo -e "${C_GREEN}[✓] Using local repository at ${SOURCE_DIR}${C_RESET}"
elif [[ -d "${INSTALL_DIR}/.git" ]]; then
    SOURCE_DIR="${INSTALL_DIR}"
    echo -e "${C_CYAN}[i] Updating existing installation at ${SOURCE_DIR}...${C_RESET}"
    git -C "${SOURCE_DIR}" pull origin main || true
else
    echo -e "${C_CYAN}[2/6] Cloning AEGS Global repository into ${INSTALL_DIR}...${C_RESET}"
    mkdir -p "${INSTALL_DIR}"
    git clone "${REPO_URL}" "${INSTALL_DIR}"
    SOURCE_DIR="${INSTALL_DIR}"
fi

# 3. High-Performance Carrier-Grade Compilation
echo -e "${C_CYAN}[3/6] Compiling AEGS Global Release Binaries with CMake (-O3)...${C_RESET}"
mkdir -p "${SOURCE_DIR}/build"
cmake -S "${SOURCE_DIR}" -B "${SOURCE_DIR}/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "${SOURCE_DIR}/build" -j"$(nproc)"

# 4. Linux Kernel High-Throughput & Low-Latency Tuning
echo -e "${C_CYAN}[4/6] Applying 10Gbps Linux Kernel UDP & Buffer Tuning...${C_RESET}"
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/99-aegs-global.conf << "SYSCTL"
net.ipv4.ip_forward = 1
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432
net.core.netdev_max_backlog = 100000
net.core.somaxconn = 65535
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
SYSCTL
sysctl -p /etc/sysctl.d/99-aegs-global.conf >/dev/null 2>&1 || true

# 5. Setup systemd service
echo -e "${C_CYAN}[5/6] Creating systemd service (aegs-global.service)...${C_RESET}"
mkdir -p /app/data
cat > /etc/systemd/system/aegs-global.service << SYSTEMD
[Unit]
Description=AEGS Global Carrier-Grade UDP Tunnel Server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/app
ExecStart=${SOURCE_DIR}/build/aegs_server
Restart=always
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW

[Install]
WantedBy=multi-user.target
SYSTEMD

systemctl daemon-reload
systemctl enable aegs-global.service
systemctl restart aegs-global.service

# 6. Global CLI link
ln -sf "${SOURCE_DIR}/build/aegs_server" /usr/local/bin/aegs-server 2>/dev/null || true
ln -sf "${SOURCE_DIR}/build/bench_hotpath" /usr/local/bin/aegs-bench 2>/dev/null || true

PUBLIC_IP=$(curl -4s https://ifconfig.me 2>/dev/null || ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' || echo "YOUR_SERVER_IP")

echo ""
echo -e "${C_GREEN}${C_BOLD}========================================================================${C_RESET}"
echo -e "${C_GREEN}${C_BOLD}    🎉 AEGS GLOBAL ENTERPRISE УСПЕШНО УСТАНОВЛЕН И ЗАПУЩЕН!             ${C_RESET}"
echo -e "${C_GREEN}${C_BOLD}========================================================================${C_RESET}"
echo ""
echo -e "${C_WHITE}${C_BOLD}📍 Серверные параметры:${C_RESET}"
echo -e "   • Публичный IP:       ${C_CYAN}${PUBLIC_IP}${C_RESET}"
echo -e "   • UDP Порт:           ${C_CYAN}50001${C_RESET}"
echo -e "   • Служба:             ${C_CYAN}systemctl status aegs-global${C_RESET}"
echo -e "   • Логи службы:        ${C_CYAN}journalctl -u aegs-global -f${C_RESET}"
echo -e "   • Тест hotpath:       ${C_YELLOW}aegs-bench${C_RESET}"
echo ""
echo -e "${C_BOLD}========================================================================${C_RESET}"
