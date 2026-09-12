#!/usr/bin/env bash
# ==============================================================================
# 🏠 AEGS v4 "Pantheon" (Home & Family Edition) -- 1-Click Server Installer
# One command to install, configure firewall, start background service, and
# generate client profiles for all family devices and home routers.
# ==============================================================================
set -euo pipefail

# --- Color Scheme ---
readonly C_RESET='\033[0m'
readonly C_BOLD='\033[1m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_CYAN='\033[0;36m'
readonly C_RED='\033[0;31m'
readonly C_WHITE='\033[1;37m'
readonly C_BG_BLUE='\033[44m'

# Check root privileges
if [[ $EUID -ne 0 ]]; then
    echo -e "${C_RED}[ERROR] This script must be run as root. Please run with sudo:${C_RESET}"
    echo "  curl -fsSL https://raw.githubusercontent.com/XDGOOD/net-packet-handler/main/install.sh | sudo bash"
    exit 1
fi

echo -e "${C_CYAN}${C_BOLD}"
cat << "EOF"
========================================================================
   ___    ______ _____ ____         __  __                      
  /   |  / ____// ___// __ \ _   __/ / / /___  ____ ___  ___    
 / /| | / __/  / / _ / / / /| | / / /_/ / __ \/ __ `__ \/ _ \   
/ ___ |/ /___ / /_/ // /_/ / | |/ / __  / /_/ / / / / / /  __/   
/_/  |_/_____/ \____(_)____/  |___/_/ /_/\____/_/ /_/ /_/\___/    
  🏠 Home & Family Edition -- 1-Click Zero-Config Server Setup
========================================================================
EOF
echo -e "${C_RESET}"

INSTALL_DIR="/opt/aegs"
REPO_URL="https://github.com/XDGOOD/net-packet-handler.git"

# 1. Clone or locate repository
if [[ -f "./server.cpp" && -f "./CMakeLists.txt" ]]; then
    SOURCE_DIR="$(pwd)"
    echo -e "${C_GREEN}[✓] Using local repository at ${SOURCE_DIR}${C_RESET}"
elif [[ -d "${INSTALL_DIR}/.git" ]]; then
    SOURCE_DIR="${INSTALL_DIR}"
    echo -e "${C_CYAN}[i] Updating existing installation at ${SOURCE_DIR}...${C_RESET}"
    git -C "${SOURCE_DIR}" pull origin main || true
else
    echo -e "${C_CYAN}[1/6] Cloning AEGS Home Edition repository into ${INSTALL_DIR}...${C_RESET}"
    mkdir -p "${INSTALL_DIR}"
    if command -v git >/dev/null 2>&1; then
        git clone "${REPO_URL}" "${INSTALL_DIR}"
    else
        # Install git first
        if command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y git
        elif command -v dnf >/dev/null 2>&1; then dnf install -y git
        elif command -v yum >/dev/null 2>&1; then yum install -y git
        elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm git
        elif command -v apk >/dev/null 2>&1; then apk add git
        fi
        git clone "${REPO_URL}" "${INSTALL_DIR}"
    fi
    SOURCE_DIR="${INSTALL_DIR}"
fi

# 2. Run manage.sh installer
echo -e "${C_CYAN}[2/6] Installing build dependencies and compiling server...${C_RESET}"
bash "${SOURCE_DIR}/scripts/manage.sh" install --systemd

# 3. Enable IP forwarding
echo -e "${C_CYAN}[3/6] Enabling Kernel IP Forwarding...${C_RESET}"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
mkdir -p /etc/sysctl.d
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-aegs.conf

# 4. Configure NAT firewall rule for VPN subnet 10.8.0.0/24
echo -e "${C_CYAN}[4/6] Setting up NAT masquerade for client internet traffic...${C_RESET}"
WAN_IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $5}' || echo "")
if [[ -n "$WAN_IFACE" ]]; then
    iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$WAN_IFACE" -j MASQUERADE
    echo -e "${C_GREEN}[✓] NAT forwarding active on interface: ${WAN_IFACE}${C_RESET}"
fi

# 5. Create symlink for global CLI command 'aegs'
ln -sf "${SOURCE_DIR}/scripts/manage.sh" /usr/local/bin/aegs
chmod +x /usr/local/bin/aegs

# 6. Generate first client profile if none exists
echo -e "${C_CYAN}[5/6] Creating default family client profile...${C_RESET}"
FIRST_USER="home_client"
mkdir -p /app/data/clients

# Add user if not already present
aegs add-user "$FIRST_USER" >/dev/null 2>&1 || true

PUBLIC_IP=$(aegs status 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || echo "YOUR_SERVER_IP")
USER_TOKEN=$(sqlite3 /app/data/aegis.db "SELECT aegis_token FROM users WHERE aegis_key_id = (SELECT aegis_key_id FROM users LIMIT 1);" 2>/dev/null || echo "")

# Write clean client configuration file
CONFIG_PATH="/app/data/clients/${FIRST_USER}.conf"
cat > "$CONFIG_PATH" << EOF
# AEGS Pantheon Client Configuration
[Server]
Host = ${PUBLIC_IP}
Port = 50001

[Auth]
User = ${FIRST_USER}
Token = ${USER_TOKEN}

[Tunnel]
MTU = 1400
SemanticPadding = true
EOF
chmod 600 "$CONFIG_PATH"

echo -e "${C_CYAN}[6/6] Generating friendly connection guides for all devices...${C_RESET}"
echo ""
echo -e "${C_GREEN}${C_BOLD}========================================================================${C_RESET}"
echo -e "${C_GREEN}${C_BOLD}       🎉 УСТАНОВКА УСПЕШНО ЗАВЕРШЕНА! СЕРВЕР РАБОТАЕТ В ФОНЕ!         ${C_RESET}"
echo -e "${C_GREEN}${C_BOLD}========================================================================${C_RESET}"
echo ""
echo -e "${C_WHITE}${C_BOLD}📍 Данные вашего сервера:${C_RESET}"
echo -e "   • Публичный IP:   ${C_CYAN}${PUBLIC_IP}${C_RESET}"
echo -e "   • UDP Порт:       ${C_CYAN}50001${C_RESET}"
echo -e "   • Первый клиент:  ${C_CYAN}${FIRST_USER}${C_RESET}"
echo -e "   • Секретный токен:${C_YELLOW} ${USER_TOKEN}${C_RESET}"
echo -e "   • Файл конфига:   ${C_WHITE}${CONFIG_PATH}${C_RESET}"
echo ""
echo -e "${C_BOLD}------------------------------------------------------------------------${C_RESET}"
echo -e "${C_BOLD}📱 КАК ПОДКЛЮЧИТЬ УСТРОЙСТВА (ВЫБЕРИТЕ ВАШЕ УСТРОЙСТВО):${C_RESET}"
echo -e "${C_BOLD}------------------------------------------------------------------------${C_RESET}"
echo ""
echo -e "${C_CYAN}${C_BOLD}💻 1. Windows (1 команда в PowerShell):${C_RESET}"
echo -e "   Откройте PowerShell от имени Администратора и вставьте:"
echo -e "   ${C_YELLOW}irm https://raw.githubusercontent.com/XDGOOD/net-packet-handler/main/scripts/setup_client.ps1 | iex${C_RESET}"
echo -e "   (Скрипт спросит IP: ${PUBLIC_IP} и токен, и сразу запустит туннель)"
echo ""
echo -e "${C_CYAN}${C_BOLD}🍏 2. macOS / Linux (1 команда в Терминале):${C_RESET}"
echo -e "   ${C_YELLOW}curl -fsSL https://raw.githubusercontent.com/XDGOOD/net-packet-handler/main/scripts/setup_client.sh | bash -s -- connect ${PUBLIC_IP} 50001 \"${USER_TOKEN}\"${C_RESET}"
echo ""
echo -e "${C_CYAN}${C_BOLD}📡 3. Роутер для дома (OpenWrt / Keenetic) — весь Wi-Fi в туннеле:${C_RESET}"
echo -e "   Чтобы компьютеры, телевизор и телефоны дома работали через туннель без настроек,"
echo -e "   зайдите по SSH на ваш роутер с OpenWrt и вставьте:"
echo -e "   ${C_YELLOW}wget -O - https://raw.githubusercontent.com/XDGOOD/net-packet-handler/main/scripts/router_setup.sh | sh -s -- ${PUBLIC_IP} 50001 \"${USER_TOKEN}\"${C_RESET}"
echo ""
echo -e "${C_BOLD}------------------------------------------------------------------------${C_RESET}"
echo -e "${C_BOLD}⚙️ Управление сервером (вводите прямо в консоли):${C_RESET}"
echo -e "   • ${C_CYAN}aegs add-user <имя>${C_RESET}     — добавить профиль для друга или родственника"
echo -e "   • ${C_CYAN}aegs list-users${C_RESET}        — посмотреть всех пользователей"
echo -e "   • ${C_CYAN}aegs remove-user <имя>${C_RESET}  — удалить доступ"
echo -e "   • ${C_CYAN}aegs status${C_RESET}            — проверить статус сервера и IP"
echo -e "   • ${C_CYAN}aegs logs${C_RESET}              — смотреть логи подключений в реальном времени"
echo -e "${C_BOLD}========================================================================${C_RESET}"
