#!/usr/bin/env bash
# ==============================================================================
# AEGS-Global Carrier-Grade Host Network Tuning (300-900+ Mbps / 10 Gbps)
# Applies high-throughput kernel network buffer, queue, and congestion parameters
# ==============================================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This script must be run as root (sudo ./optimize_sysctl.sh)"
   exit 1
fi

echo "===================================================================="
echo "    AEGS-Global: Applying Carrier-Grade Host Network Tuning         "
echo "===================================================================="

CONF_FILE="/etc/sysctl.d/99-aegs-speed.conf"

cat <<'EOF' > "$CONF_FILE"
# ----------------------------------------------------------------------
# AEGS-Global High-Speed Buffer & Socket Scaling (300-900+ Mbps)
# ----------------------------------------------------------------------
# Maximum socket receive & send buffer sizes (64 MB)
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864

# Default socket receive & send buffer sizes (32 MB)
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432

# Max packets in kernel network queue awaiting delivery to userspace
net.core.netdev_max_backlog = 100000

# Max pending socket connection requests
net.core.somaxconn = 65535

# UDP buffer memory limits (min, default, max in pages)
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# TCP window size scaling & fast open
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fastopen = 3

# TCP buffer scaling (min: 4KB, default: 87KB, max: 64MB)
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864

# Prefer BBR congestion control if available
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

sysctl -p "$CONF_FILE" 2>/dev/null || sysctl --system

echo ""
echo "[SUCCESS] Carrier-grade network tuning applied successfully."
echo "[INFO] Tuned parameters written to $CONF_FILE."
echo "===================================================================="
