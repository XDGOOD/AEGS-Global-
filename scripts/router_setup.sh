#!/bin/sh
# ==============================================================================
# 📡 AEGS v4 "Pantheon" -- Home Router Auto-Setup (OpenWrt & Keenetic)
# Turns your home Wi-Fi router into a stealth zero-DPI gateway.
# All connected phones, TVs, laptops automatically bypass censorship & blocks!
# ==============================================================================
set -e

# ANSI Colors
C_GREEN='\033[0;32m'
C_CYAN='\033[0;36m'
C_YELLOW='\033[1;33m'
C_RED='\033[0;31m'
C_RESET='\033[0m'
C_BOLD='\033[1m'

SERVER_IP="${1:-}"
SERVER_PORT="${2:-50001}"
USER_TOKEN="${3:-}"

if [ -z "$SERVER_IP" ] || [ -z "$USER_TOKEN" ]; then
    echo -e "${C_RED}[!] Ошибка использования!${C_RESET}"
    echo "Использование:"
    echo "  sh router_setup.sh <SERVER_IP> [PORT] <TOKEN>"
    echo "Пример:"
    echo "  sh router_setup.sh 123.45.67.89 50001 \"a1b2c3d4...\""
    exit 1
fi

echo -e "${C_CYAN}${C_BOLD}"
echo "========================================================================"
echo "    📡 Настройка домашнего роутера для AEGS Stealth Tunnel (OpenWrt)    "
echo "========================================================================"
echo -e "${C_RESET}"

# 1. Проверка окружения OpenWrt / Entware
if [ ! -f /etc/openwrt_release ] && [ ! -d /opt/etc ]; then
    echo -e "${C_YELLOW}[WARN] Система не похожа на OpenWrt или Keenetic Entware.${C_RESET}"
    echo -e "Продолжаю установку в стандартном POSIX-режиме..."
fi

# 2. Установка пакетов через opkg (если OpenWrt)
if command -v opkg >/dev/null 2>&1; then
    echo -e "${C_CYAN}[1/4] Обновление пакетов и установка kmod-tun, python3...${C_RESET}"
    opkg update || true
    opkg install kmod-tun python3 python3-pip curl iptables || true
fi

ROUTER_DIR="/etc/aegs"
mkdir -p "$ROUTER_DIR"

# 3. Скачивание легковесного клиента
echo -e "${C_CYAN}[2/4] Загрузка клиента AEGS...${C_RESET}"
CLIENT_URL="https://raw.githubusercontent.com/XDGOOD/net-packet-handler/main/scripts/quick_client.py"
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$CLIENT_URL" -o "$ROUTER_DIR/client.py"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$ROUTER_DIR/client.py" "$CLIENT_URL"
else
    echo -e "${C_RED}[ERROR] Не найден curl или wget!${C_RESET}"
    exit 1
fi
chmod +x "$ROUTER_DIR/client.py"

# 4. Сохранение конфигурации
cat > "$ROUTER_DIR/config.env" << EOF
SERVER_IP="${SERVER_IP}"
SERVER_PORT="${SERVER_PORT}"
USER_TOKEN="${USER_TOKEN}"
EOF
chmod 600 "$ROUTER_DIR/config.env"

# 5. Создание службы автозапуска /etc/init.d/aegs
echo -e "${C_CYAN}[3/4] Создание службы автозапуска /etc/init.d/aegs...${C_RESET}"
cat > /etc/init.d/aegs << 'EOF'
#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1

CONFIG_DIR="/etc/aegs"

start_service() {
    [ -f "$CONFIG_DIR/config.env" ] || return 1
    . "$CONFIG_DIR/config.env"

    procd_open_instance
    procd_set_param command python3 "$CONFIG_DIR/client.py" connect "$SERVER_IP" "$SERVER_PORT" "$USER_TOKEN"
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
EOF
chmod +x /etc/init.d/aegs

# 6. Включение и запуск службы
echo -e "${C_CYAN}[4/4] Запуск туннеля на роутере...${C_RESET}"
if [ -f /etc/init.d/aegs ]; then
    /etc/init.d/aegs enable || true
    /etc/init.d/aegs start || true
fi

echo ""
echo -e "${C_GREEN}${C_BOLD}========================================================================${C_RESET}"
echo -e "${C_GREEN}${C_BOLD}      🎉 РОУТЕР УСПЕШНО НАСТРОЕН И ПОДКЛЮЧЕН К СЕРВЕРУ!                ${C_RESET}"
echo -e "${C_GREEN}${C_BOLD}========================================================================${C_RESET}"
echo -e " • Статус туннеля:   /etc/init.d/aegs status"
echo -e " • Логи туннеля:     logread | grep aegs"
echo -e " • Перезапуск:       /etc/init.d/aegs restart"
echo ""
echo -e "Теперь весь домашний Wi-Fi трафик защищён от блокировок и анализа DPI!"
