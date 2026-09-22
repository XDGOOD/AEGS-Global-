#!/usr/bin/env bash
# ==============================================================================
# AEGS Titan v6.5 -- Turnkey Carrier-Grade Server Setup Script
# Automatically prepares Ubuntu/Debian VPS for AEGS High-Speed Stealth Protocol
# ==============================================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[-] Этот скрипт необходимо запускать с правами root (sudo)."
    exit 1
fi

echo "=========================================================="
echo "   🚀 НАСТРОЙКА СЕРВЕРА AEGS TITAN PROTOCOL v6.5"
echo "=========================================================="

# 1. Обновление пакетов и установка зависимостей
echo "[1/5] Установка системных зависимостей..."
apt-get update -qq
apt-get install -y -qq build-essential cmake libssl-dev libsqlite3-dev iptables iproute2 curl git python3 python3-pip

# 2. Настройка сетевого ядра (BBR, буферы UDP, форвардинг пакетов)
echo "[2/5] Оптимизация ядра Linux (10G sysctl, BBR, UDP Buffers)..."
cat > /etc/sysctl.d/99-aegs-titan.conf << "EOF"
net.ipv4.ip_forward = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432
net.core.netdev_max_backlog = 100000
net.core.somaxconn = 65535
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
EOF
sysctl -p /etc/sysctl.d/99-aegs-titan.conf >/dev/null 2>&1 || true

# 3. Настройка NAT в iptables для туннеля (10.8.0.0/24)
echo "[3/5] Настройка правил NAT iptables..."
PUB_IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $5}' | head -n1 || echo "eth0")
iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "$PUB_IFACE" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$PUB_IFACE" -j MASQUERADE

# Сохранение iptables
apt-get install -y -qq iptables-persistent 2>/dev/null || true
netfilter-persistent save >/dev/null 2>&1 || true

# 4. Сборка C++ сервера AEGS
echo "[4/5] Компиляция C++ ядра AEGS Titan (Release -O3)..."
WORKDIR="/opt/aegs-global"
if [[ ! -d "$WORKDIR" ]]; then
    mkdir -p "$WORKDIR"
    git clone https://github.com/XDGOOD/AEGS-Global-.git "$WORKDIR"
fi

cd "$WORKDIR"
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j$(nproc)

# Создание каталогов для базы данных
mkdir -p /app/data
mkdir -p /opt/aegs-global/data

# 5. Создание службы systemd
echo "[5/5] Регистрация службы aegs-titan.service..."
cat > /etc/systemd/system/aegs-titan.service << EOF
[Unit]
Description=AEGS Titan Carrier-Grade Stealth Server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/aegs-global
ExecStart=/opt/aegs-global/build/aegs_server
Restart=always
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable aegs-titan.service
systemctl restart aegs-titan.service

PUBLIC_IP=$(curl -4s https://ifconfig.me 2>/dev/null || ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' || echo "UNKNOWN_IP")

echo ""
echo "=========================================================="
echo "   ✅ СЕРВЕР AEGS TITAN УСПЕШНО НАСТРОЕН И ЗАПУЩЕН!"
echo "=========================================================="
echo "IP адрес сервера: $PUBLIC_IP"
echo "UDP Порт:        50001"
echo "Статус службы:   systemctl status aegs-titan"
echo "Логи:            journalctl -u aegs-titan -f"
echo "=========================================================="
