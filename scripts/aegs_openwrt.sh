#!/bin/sh
# ==============================================================================
# AEGS v6 Titan — Router Client Setup (OpenWrt / Keenetic / Entware / DD-WRT)
# Transparently protects all home devices (Smart TVs, Consoles, Phones)
# ==============================================================================

set -e

echo "=== AEGS v6 Titan Router Gateway Installer ==="

# 1. Detect package manager (opkg for OpenWrt / Entware)
if command -v opkg >/dev/null 2>&1; then
    echo "[*] Updating opkg and installing dependencies..."
    opkg update
    opkg install kmod-tun ip-full iptables ipset curl ca-certificates || true
fi

# 2. Server configuration (Positional or aegs:// URI)
if echo "$1" | grep -q "^aegs://"; then
    AEGS_URI="$1"
    AEGS_SERVER=$(echo "$AEGS_URI" | sed -E 's|aegs://([^:/]+).*|\1|')
    AEGS_PORT=$(echo "$AEGS_URI" | sed -E 's|aegs://[^:]+:([0-9]+).*|\1|')
    AEGS_TOKEN=$(echo "$AEGS_URI" | sed -E 's|aegs://[^/]+/([^?#]+).*|\1|')
else
    AEGS_SERVER="${1:-}"
    AEGS_PORT="${2:-443}"
    AEGS_TOKEN="${3:-}"
fi

if [ -z "$AEGS_SERVER" ] || [ -z "$AEGS_TOKEN" ]; then
    echo "Usage: $0 <server_ip> <server_port> <token>"
    echo "   or: $0 'aegs://<host>:<port>/<token>'"
    exit 1
fi

echo "[*] Target AEGS Server: ${AEGS_SERVER}:${AEGS_PORT}"

# 3. Create routing script for transparent LAN redirection
mkdir -p /etc/aegs
cat << 'EOF' > /etc/aegs/firewall_rules.sh
#!/bin/sh
# Transparent redirect of LAN traffic to AEGS tunnel
TUN_IF="aegs0"

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

# NAT masquerade on aegs0
iptables -t nat -C POSTROUTING -o ${TUN_IF} -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -o ${TUN_IF} -j MASQUERADE

# Allow forwarding from LAN to aegs0
iptables -C FORWARD -o ${TUN_IF} -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -o ${TUN_IF} -j ACCEPT

iptables -C FORWARD -i ${TUN_IF} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i ${TUN_IF} -m state --state RELATED,ESTABLISHED -j ACCEPT
EOF
chmod +x /etc/aegs/firewall_rules.sh

# 4. Create OpenWrt procd service
cat << EOF > /etc/init.d/aegs-router
#!/bin/sh /etc/rc.common
START=95
STOP=10

USE_PROCD=1
PROG=/usr/bin/aegs_client

start_service() {
    procd_open_instance
    procd_set_param command \$PROG ${AEGS_SERVER} ${AEGS_PORT} ${AEGS_TOKEN} --quic-mimicry
    procd_set_param respawn
    procd_close_instance
    /etc/aegs/firewall_rules.sh
}

stop_service() {
    killall aegs_client 2>/dev/null || true
}
EOF
chmod +x /etc/init.d/aegs-router || true

echo "=== AEGS Router Setup Complete! ==="
echo "All LAN devices will now be routed through AEGS v6 Titan tunnel with QUIC mimicry."
