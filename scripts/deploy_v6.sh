#!/usr/bin/env bash
# ==============================================================================
# AEGS v6 Titan — 1-Click Server Auto-Deployer (Ubuntu / Debian / Linux)
# High-Speed Stealth Protocol Server with RFC 9000 QUIC Mimicry & Anti-DDoS
# ==============================================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "=================================================================="
echo "          AEGS v6 TITAN — SERVER AUTO-DEPLOYER (1-CLICK)          "
echo "        Ultra High-Speed (300-900+ Mbps) & Anti-DPI Stealth       "
echo "=================================================================="
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERROR] Please run this script as root (sudo bash deploy_v6.sh)${NC}"
  exit 1
fi

# Detect WAN Interface and Server Public IP
WAN_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $5; exit}')
if [ -z "$WAN_IF" ]; then
  WAN_IF=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;exit}' | tr -d ' ')
fi
SERVER_IP=$(curl -s https://api.ipify.org || curl -s https://ifconfig.me || ip route get 1.1.1.1 | awk '{print $7; exit}')

echo -e "${GREEN}[1/6] Detected Server IP:${NC} ${BOLD}${SERVER_IP}${NC} (Interface: ${WAN_IF})"

# Install dependencies
echo -e "${GREEN}[2/6] Installing build dependencies and network tools...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq build-essential cmake libssl-dev iptables ufw curl qrencode >/dev/null 2>&1 || true

# Kernel network tuning (BBR and UDP buffer sizes for 900+ Mbps)
echo -e "${GREEN}[3/6] Applying high-speed BBR and UDP buffer sysctl optimizations...${NC}"
cat << 'EOF' > /etc/sysctl.d/99-aegs-titan.conf
# AEGS Titan High-Throughput Kernel Settings
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432
net.core.netdev_max_backlog = 100000
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF
sysctl -p /etc/sysctl.d/99-aegs-titan.conf >/dev/null 2>&1 || true

# Generate random secure credentials
RAND_TOKEN=$(openssl rand -hex 16)
AEGS_PORT=50001
AEGS_PORT_COUNT=8
INSTALL_DIR="/opt/aegs"
mkdir -p "${INSTALL_DIR}"

# Clone or compile AEGS Server
echo -e "${GREEN}[4/6] Compiling AEGS v6 Titan optimized native binary...${NC}"
cd "${INSTALL_DIR}"
if [ ! -f "server.cpp" ]; then
  curl -sSL "https://raw.githubusercontent.com/XDGOOD/AEGS-Global-/main/server.cpp" -o server.cpp
  curl -sSL "https://raw.githubusercontent.com/XDGOOD/AEGS-Global-/main/session.h" -o session.h
  curl -sSL "https://raw.githubusercontent.com/XDGOOD/AEGS-Global-/main/handshake.h" -o handshake.h
  curl -sSL "https://raw.githubusercontent.com/XDGOOD/AEGS-Global-/main/packet_scratch.h" -o packet_scratch.h
  curl -sSL "https://raw.githubusercontent.com/XDGOOD/AEGS-Global-/main/protocol_mimicry.h" -o protocol_mimicry.h
  curl -sSL "https://raw.githubusercontent.com/XDGOOD/AEGS-Global-/main/protocol_mimicry.cpp" -o protocol_mimicry.cpp
fi

# Build binary
g++ -O3 -flto -march=native -std=c++17 server.cpp protocol_mimicry.cpp -o aegs_server -lssl -lcrypto -lpthread || \
g++ -O2 -std=c++17 server.cpp protocol_mimicry.cpp -o aegs_server -lssl -lcrypto -lpthread

# Configure Firewall & NAT
echo -e "${GREEN}[5/6] Setting up iptables NAT forwarding...${NC}"
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "${WAN_IF}" -j MASQUERADE
iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp --dport ${AEGS_PORT}:$((AEGS_PORT + AEGS_PORT_COUNT - 1)) -j ACCEPT

# Create Systemd Service
echo -e "${GREEN}[6/6] Creating systemd service (aegs-server.service)...${NC}"
cat << EOF > /etc/systemd/system/aegs-server.service
[Unit]
Description=AEGS v6 Titan High-Speed Stealth VPN Server
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/aegs_server ${AEGS_PORT} ${AEGS_PORT_COUNT} ${RAND_TOKEN}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable aegs-server.service >/dev/null 2>&1
systemctl restart aegs-server.service

# Generate AEGS URI & Config
AEGS_JSON="{\"v\":6,\"name\":\"My VPS Server\",\"ip\":\"${SERVER_IP}\",\"p\":${AEGS_PORT},\"pc\":${AEGS_PORT_COUNT},\"t\":\"${RAND_TOKEN}\",\"k\":\"client_key_01\",\"m\":1,\"st\":1,\"dns\":\"1.1.1.1, 8.8.8.8\"}"
AEGS_B64=$(echo -n "${AEGS_JSON}" | base64 | tr -d '\n=' | tr '/+' '_-')
AEGS_URI="aegs://${AEGS_B64}"

echo -e "${GREEN}${BOLD}"
echo "=================================================================="
echo "          AEGS v6 TITAN УСПЕШНО РАЗВЕРНУТ И ЗАПУЩЕН!              "
echo "=================================================================="
echo -e "${NC}"
echo -e "${BOLD}IP Сервера:${NC}        ${SERVER_IP}"
echo -e "${BOLD}Порты:${NC}             ${AEGS_PORT} - $((AEGS_PORT + AEGS_PORT_COUNT - 1)) (UDP)"
echo -e "${BOLD}Секретный Токен:${NC}   ${RAND_TOKEN}"
echo -e "${BOLD}Маскировка:${NC}        RFC 9000 QUIC Camouflage (Анти-ТСПУ)"
echo -e "${BOLD}Статус службы:${NC}     Активна (systemctl status aegs-server)"
echo ""
echo -e "${CYAN}${BOLD}🔗 КЛЮЧ ПОДКЛЮЧЕНИЯ ДЛЯ ПРИЛОЖЕНИЙ (ПК И ТЕЛЕФОН):${NC}"
echo -e "${YELLOW}${AEGS_URI}${NC}"
echo ""
echo -e "${CYAN}${BOLD}📱 QR-КОД ДЛЯ СКАНИРОВАНИЯ В ПРИЛОЖЕНИИ AEGS:${NC}"
qrencode -t ANSIUTF8 "${AEGS_URI}" 2>/dev/null || echo "(Установите qrencode для отображения QR в терминале)"
echo ""
echo "Скопируйте ключ aegs://... выше и вставьте его в приложение AEGS на ПК или телефоне!"
