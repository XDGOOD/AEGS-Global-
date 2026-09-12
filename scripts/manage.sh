#!/usr/bin/env bash
# ==============================================================================
# 🛡️ AEGS v2 Protocol - Linux Server Manager & 1-Click Installer
# High-Performance UDP Obfuscation Tunnel & Multi-User Management CLI
# ==============================================================================
set -euo pipefail

# --- Color Definitions ---
readonly C_RESET='\033[0m'
readonly C_BOLD='\033[1m'
readonly C_DIM='\033[2m'
readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_BLUE='\033[0;34m'
readonly C_PURPLE='\033[0;35m'
readonly C_CYAN='\033[0;36m'
readonly C_WHITE='\033[1;37m'
readonly C_BG_BLUE='\033[44m'

# --- Project Paths & Configurations ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

DATA_DIR="/app/data"
DB_PATH="${DATA_DIR}/aegis.db"
BACKUP_DIR="${DATA_DIR}/backups"
BIN_DIR="/usr/local/bin"
SERVER_BIN="${BIN_DIR}/aegs-server"
CLIENT_BIN="${BIN_DIR}/aegs-client"
SERVICE_NAME="aegis-server"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
DOCKER_CONTAINER_NAME="aegis_server"
DOCKER_IMAGE_NAME="aegis-server:latest"
DEFAULT_UDP_PORT=50001
DEFAULT_WG_PORT=51820

# --- Logging Helpers ---
log_info()    { echo -e "${C_CYAN}[INFO]${C_RESET} $*"; }
log_success() { echo -e "${C_GREEN}[✓]${C_RESET} ${C_BOLD}$*${C_RESET}"; }
log_warn()    { echo -e "${C_YELLOW}[WARN]${C_RESET} $*"; }
log_error()   { echo -e "${C_RED}[ERROR]${C_RESET} $*" >&2; }
log_fatal()   { echo -e "${C_RED}[FATAL]${C_RESET} ${C_BOLD}$*${C_RESET}" >&2; exit 1; }

banner() {
    echo -e "${C_CYAN}${C_BOLD}"
    cat << "EOF"
    ___    ______ _____ ____         ___ 
   /   |  / ____// ___// __ \ _   __|__ \
  / /| | / __/  / / _ / / / /| | / /__/ /
 / ___ |/ /___ / /_/ // /_/ / | |/ // __/ 
/_/  |_/_____/ \____(_)____/  |___//____/ 
  🛡️  Zero-DPI Stream Masking & Multi-User Manager
EOF
    echo -e "${C_RESET}"
}

# --- Privilege & System Checks ---
require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_fatal "This command requires root privileges. Please run with sudo or as root: sudo $0 $*"
    fi
}

detect_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman"
    elif command -v apk >/dev/null 2>&1; then
        echo "apk"
    else
        echo "unknown"
    fi
}

# --- Public IP Resolver ---
get_public_ip() {
    local ip=""
    local ip_services=(
        "https://api.ipify.org"
        "https://ifconfig.me/ip"
        "https://icanhazip.com"
        "https://ipinfo.io/ip"
        "https://checkip.amazonaws.com"
    )
    for service in "${ip_services[@]}"; do
        ip=$(curl -s4m 3 "$service" 2>/dev/null | tr -d '[:space:]' || true)
        if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    # Fallback to local default route IP
    ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | tr -d '[:space:]' || true)
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return 0
    fi
    echo "127.0.0.1"
}

# --- Cryptographic Helpers ---
# Generates 32 bytes (64 hex characters) of cryptographically secure random token
generate_token() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
    fi
}

# KeyID: First 8 bytes (16 hex chars) of SHA-256(token)
compute_key_id() {
    local token="$1"
    if command -v openssl >/dev/null 2>&1; then
        printf "%s" "$token" | openssl dgst -sha256 -r | awk '{print substr($1, 1, 16)}'
    elif command -v sha256sum >/dev/null 2>&1; then
        printf "%s" "$token" | sha256sum | awk '{print substr($1, 1, 16)}'
    else
        log_fatal "Neither 'openssl' nor 'sha256sum' found to calculate KeyID."
    fi
}

# --- Database Management ---
init_database() {
    mkdir -p "${DATA_DIR}"
    mkdir -p "${BACKUP_DIR}"
    chmod 700 "${DATA_DIR}"

    if ! command -v sqlite3 >/dev/null 2>&1; then
        log_fatal "sqlite3 CLI is not installed. Please install sqlite3 first."
    fi

    log_info "Initializing SQLite database schema at ${DB_PATH}..."
    sqlite3 "${DB_PATH}" << 'EOF'
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    aegis_key_id TEXT NOT NULL,
    aegis_token TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_users_key_id ON users(aegis_key_id);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
EOF
    chmod 600 "${DB_PATH}"
    log_success "Database schema verified."
}

# --- Dependency Installer ---
install_dependencies() {
    local pm
    pm=$(detect_package_manager)
    log_info "Detected package manager: ${C_BOLD}${pm}${C_RESET}"

    case "$pm" in
        apt)
            log_info "Updating apt packages and installing build dependencies..."
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y
            apt-get install -y --no-install-recommends \
                build-essential \
                cmake \
                pkg-config \
                libssl-dev \
                libsqlite3-dev \
                sqlite3 \
                curl \
                iproute2 \
                iptables \
                ca-certificates
            ;;
        dnf|yum)
            log_info "Installing dependencies via ${pm}..."
            $pm install -y \
                gcc \
                gcc-c++ \
                make \
                cmake \
                pkgconfig \
                openssl-devel \
                sqlite-devel \
                sqlite \
                curl \
                iproute \
                iptables \
                ca-certificates
            ;;
        pacman)
            log_info "Installing dependencies via pacman..."
            pacman -Sy --noconfirm \
                base-devel \
                cmake \
                openssl \
                sqlite \
                curl \
                iproute2 \
                iptables
            ;;
        apk)
            log_info "Installing dependencies via apk..."
            apk update
            apk add --no-cache \
                build-base \
                cmake \
                openssl-dev \
                sqlite-dev \
                sqlite \
                curl \
                iproute2 \
                iptables
            ;;
        *)
            log_warn "Unknown package manager. Ensure g++ (C++17), OpenSSL 3.0+, SQLite3, and CMake are installed."
            ;;
    esac
    log_success "Dependencies installed."
}

# --- Compiler ---
compile_binaries() {
    log_info "Compiling AEGS Pantheon server and client binaries..."
    
    if command -v cmake >/dev/null 2>&1; then
        mkdir -p "${ROOT_DIR}/build"
        cmake -B "${ROOT_DIR}/build" -S "${ROOT_DIR}" -DCMAKE_BUILD_TYPE=Release
        cmake --build "${ROOT_DIR}/build" -j"$(nproc 2>/dev/null || echo 2)"
        cp "${ROOT_DIR}/build/aegis_server" "${SERVER_BIN}"
        if [[ -f "${ROOT_DIR}/build/aegis_client" ]]; then
            cp "${ROOT_DIR}/build/aegis_client" "${CLIENT_BIN}"
        fi
    else
        local core_sources=(
            "${ROOT_DIR}/tun_interface.cpp"
            "${ROOT_DIR}/ip_router.cpp"
            "${ROOT_DIR}/handshake.cpp"
            "${ROOT_DIR}/ip_pool.cpp"
            "${ROOT_DIR}/nat_manager.cpp"
            "${ROOT_DIR}/port_hopper.cpp"
            "${ROOT_DIR}/protocol_mimicry.cpp"
            "${ROOT_DIR}/traffic_shaper.cpp"
            "${ROOT_DIR}/chaff_engine.cpp"
            "${ROOT_DIR}/illusion_prebypass.cpp"
            "${ROOT_DIR}/blackhole_responder.cpp"
            "${ROOT_DIR}/network_security.cpp"
        )
        g++ -O3 -std=c++17 -Wall -Wextra \
            -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pie -Wl,-z,relro,-z,now \
            "${ROOT_DIR}/server.cpp" "${core_sources[@]}" -o "${SERVER_BIN}" \
            -lssl -lcrypto -lsqlite3 -lpthread

        if [[ -f "${ROOT_DIR}/client.cpp" ]]; then
            g++ -O3 -std=c++17 -Wall -Wextra \
                -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pie -Wl,-z,relro,-z,now \
                "${ROOT_DIR}/client.cpp" "${core_sources[@]}" -o "${CLIENT_BIN}" \
                -lssl -lcrypto -lpthread
        fi
    fi
    chmod 755 "${SERVER_BIN}"
    chmod 755 "${CLIENT_BIN}" 2>/dev/null || true
    log_success "Binaries compiled successfully -> ${SERVER_BIN}"
}

# --- Service Management (Systemd & Docker) ---
setup_systemd_service() {
    log_info "Configuring systemd service '${SERVICE_NAME}'..."

    cat > "${SERVICE_FILE}" << EOF
[Unit]
Description=AEGS v2 Obfuscated UDP Tunnel Server
Documentation=https://github.com/XDGOOD/net-packet-handler
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${SERVER_BIN}
WorkingDirectory=/app
Restart=always
RestartSec=3s
LimitNOFILE=65535
LimitNPROC=65535
StandardOutput=journal
StandardError=journal

# Security hardening
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "${SERVICE_FILE}"
    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"
    systemctl restart "${SERVICE_NAME}"
    log_success "Systemd service ${SERVICE_NAME} enabled and started."
}

setup_docker_service() {
    if ! command -v docker >/dev/null 2>&1; then
        log_fatal "Docker is not installed on this system. Please install Docker or use systemd mode."
    fi

    log_info "Building Docker image ${DOCKER_IMAGE_NAME} from Dockerfile.aegis..."
    docker build -f "${ROOT_DIR}/Dockerfile.aegis" -t "${DOCKER_IMAGE_NAME}" "${ROOT_DIR}"

    log_info "Deploying Docker container ${DOCKER_CONTAINER_NAME}..."
    docker stop "${DOCKER_CONTAINER_NAME}" 2>/dev/null || true
    docker rm "${DOCKER_CONTAINER_NAME}" 2>/dev/null || true

    docker run -d \
        --name "${DOCKER_CONTAINER_NAME}" \
        --restart unless-stopped \
        -p ${DEFAULT_UDP_PORT}:${DEFAULT_UDP_PORT}/udp \
        -v "${DATA_DIR}":/app/data \
        "${DOCKER_IMAGE_NAME}"

    log_success "Docker container ${DOCKER_CONTAINER_NAME} running."
}

configure_firewall() {
    local port="${1:-$DEFAULT_UDP_PORT}"
    log_info "Configuring firewall for UDP port ${port}..."

    if command -v ufw >/dev/null 2>&1 && ufw status | grep -qw "active"; then
        ufw allow "${port}/udp" comment "AEGS v2 Obfuscated Port" || true
        log_success "UFW rule added: ${port}/udp allowed"
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port="${port}/udp" || true
        firewall-cmd --reload || true
        log_success "Firewalld rule added: ${port}/udp allowed"
    elif command -v iptables >/dev/null 2>&1; then
        if ! iptables -C INPUT -p udp --dport "${port}" -j ACCEPT 2>/dev/null; then
            iptables -A INPUT -p udp --dport "${port}" -j ACCEPT
            log_success "iptables rule added: UDP port ${port} accepted"
        fi
    else
        log_warn "No active firewall detected (UFW/firewalld). Ensure UDP port ${port} is open in your cloud VPS security groups."
    fi
}

restart_server() {
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        log_info "Restarting systemd service ${SERVICE_NAME}..."
        systemctl restart "${SERVICE_NAME}"
        log_success "Systemd service restarted."
    elif command -v docker >/dev/null 2>&1 && docker ps --filter "name=${DOCKER_CONTAINER_NAME}" --filter "status=running" | grep -q "${DOCKER_CONTAINER_NAME}"; then
        log_info "Restarting Docker container ${DOCKER_CONTAINER_NAME}..."
        docker restart "${DOCKER_CONTAINER_NAME}"
        log_success "Docker container restarted."
    else
        log_warn "Server is not currently running under systemd or Docker."
    fi
}

# --- CLI Action: 1-Click Install ---
cmd_install() {
    require_root
    banner

    local deploy_mode="systemd"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --docker) deploy_mode="docker"; shift ;;
            --systemd) deploy_mode="systemd"; shift ;;
            --port) DEFAULT_UDP_PORT="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    echo -e "${C_BOLD}🚀 Starting 1-Click Automated Installation (${deploy_mode} mode)...${C_RESET}\n"

    install_dependencies
    init_database
    configure_firewall "${DEFAULT_UDP_PORT}"

    if [[ "$deploy_mode" == "docker" ]]; then
        setup_docker_service
    else
        compile_binaries
        setup_systemd_service
    fi

    # Check if we have at least one user, if not create default initial user
    local user_count
    user_count=$(sqlite3 "${DB_PATH}" "SELECT count(*) FROM users;")
    if [[ "$user_count" -eq 0 ]]; then
        echo ""
        log_info "No users found in database. Generating initial client access credentials..."
        cmd_add_user "admin"
    else
        restart_server
        log_success "Server running with ${user_count} existing user(s)."
    fi

    echo ""
    echo -e "${C_GREEN}${C_BOLD}========================================================================${C_RESET}"
    echo -e "${C_GREEN}${C_BOLD}🎉 AEGS v2 SERVER INSTALLATION COMPLETED SUCCESSFULLY!${C_RESET}"
    echo -e "${C_GREEN}${C_BOLD}========================================================================${C_RESET}"
    echo -e "  • Public IP:    ${C_WHITE}$(get_public_ip)${C_RESET}"
    echo -e "  • Port:         ${C_WHITE}${DEFAULT_UDP_PORT}/UDP${C_RESET}"
    echo -e "  • Database:     ${C_WHITE}${DB_PATH}${C_RESET}"
    echo -e "  • Deploy Mode:  ${C_WHITE}${deploy_mode}${C_RESET}"
    echo -e "  • Service:      ${C_WHITE}${SERVICE_NAME}${C_RESET}"
    echo ""
    echo -e "Manage clients anytime with: ${C_CYAN}./manage.sh add-user <username>${C_RESET}"
    echo -e "View active clients with:   ${C_CYAN}./manage.sh list-users${C_RESET}"
}

# --- CLI Action: Add User ---
cmd_add_user() {
    require_root
    local username="${1:-}"
    local custom_token="${2:-}"

    if [[ -z "$username" ]]; then
        echo -e "${C_RED}Error: Username is required.${C_RESET}"
        echo -e "Usage: $0 add-user <username> [token]"
        exit 1
    fi

    # Sanitize username
    if [[ ! "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        log_fatal "Invalid username '${username}'. Use only alphanumeric characters, underscores, and dashes."
    fi

    if [[ ! -f "$DB_PATH" ]]; then
        init_database
    fi

    # Check if user already exists
    local exists
    exists=$(sqlite3 "${DB_PATH}" "SELECT count(*) FROM users WHERE username = '${username}';")
    if [[ "$exists" -gt 0 ]]; then
        log_fatal "User '${username}' already exists. Use './manage.sh show-user ${username}' to view configuration or remove with './manage.sh remove-user ${username}'."
    fi

    local token
    if [[ -n "$custom_token" ]]; then
        token="$custom_token"
    else
        token=$(generate_token)
    fi

    local key_id
    key_id=$(compute_key_id "$token")

    # Insert into database
    sqlite3 "${DB_PATH}" << EOF
INSERT INTO users (username, aegis_key_id, aegis_token)
VALUES ('${username}', '${key_id}', '${token}');
EOF

    log_success "User '${username}' registered in SQLite database!"

    # Refresh server in-memory sessions
    restart_server

    local server_ip
    server_ip=$(get_public_ip)

    echo ""
    echo -e "${C_CYAN}${C_BOLD}========================================================================${C_RESET}"
    echo -e "${C_WHITE}${C_BOLD} 🔑 CLIENT CREDENTIALS & LAUNCH CONFIGURATION: ${C_YELLOW}${username}${C_RESET}"
    echo -e "${C_CYAN}${C_BOLD}========================================================================${C_RESET}"
    echo -e "  ${C_BOLD}Username:${C_RESET}       ${C_WHITE}${username}${C_RESET}"
    echo -e "  ${C_BOLD}Key ID (Hex):${C_RESET}   ${C_CYAN}${key_id}${C_RESET}"
    echo -e "  ${C_BOLD}Secret Token:${C_RESET}   ${C_GREEN}${token}${C_RESET}"
    echo -e "  ${C_BOLD}Server Address:${C_RESET} ${C_WHITE}${server_ip}:${DEFAULT_UDP_PORT}${C_RESET}"
    echo -e "  ${C_BOLD}Local WG Port:${C_RESET}  ${C_WHITE}51821${C_RESET} (Client listens locally for WireGuard)"
    echo -e "${C_CYAN}------------------------------------------------------------------------${C_RESET}"
    echo -e "${C_YELLOW}${C_BOLD}🚀 Option 1: Fast Launch on Client (Automated Scripts)${C_RESET}"
    echo -e "  ${C_BOLD}Linux/macOS:${C_RESET}"
    echo -e "    ${C_WHITE}./setup_client.sh --server ${server_ip} --token ${token}${C_RESET}"
    echo ""
    echo -e "  ${C_BOLD}Windows PowerShell:${C_RESET}"
    echo -e "    ${C_WHITE}.\\setup_client.ps1 -Server \"${server_ip}\" -Token \"${token}\"${C_RESET}"
    echo ""
    echo -e "  ${C_BOLD}Cross-Platform Python:${C_RESET}"
    echo -e "    ${C_WHITE}python quick_client.py run --server ${server_ip} --token ${token}${C_RESET}"
    echo -e "${C_CYAN}------------------------------------------------------------------------${C_RESET}"
    echo -e "${C_YELLOW}${C_BOLD}💻 Option 2: Direct Binary Execution${C_RESET}"
    echo -e "    ${C_WHITE}./aegs-client --server ${server_ip} --token ${token} --port 51821${C_RESET}"
    echo -e "${C_CYAN}------------------------------------------------------------------------${C_RESET}"
    echo -e "${C_YELLOW}${C_BOLD}🛡️ Option 3: WireGuard Client Interface Setup (.conf)${C_RESET}"
    echo -e "  In your WireGuard client profile on PC/Phone, change only the [Peer] Endpoint:"
    echo -e "    ${C_BOLD}[Peer]${C_RESET}"
    echo -e "    ${C_BOLD}Endpoint = 127.0.0.1:51821${C_RESET}"
    echo -e "    ${C_DIM}(All raw WireGuard traffic is now masked and immune to DPI blocks!)${C_RESET}"
    echo -e "${C_CYAN}========================================================================${C_RESET}"
    echo ""
}

# --- CLI Action: List Users ---
cmd_list_users() {
    require_root
    banner

    if [[ ! -f "$DB_PATH" ]]; then
        log_fatal "Database not found at ${DB_PATH}. Run '$0 install' first."
    fi

    local count
    count=$(sqlite3 "${DB_PATH}" "SELECT count(*) FROM users;")

    echo -e "${C_WHITE}${C_BOLD}📋 Registered AEGS v2 Users [Total: ${count}]${C_RESET}\n"

    if [[ "$count" -eq 0 ]]; then
        echo -e "${C_YELLOW}No users found in database.${C_RESET}"
        echo -e "Add a new user with: ${C_CYAN}$0 add-user <username>${C_RESET}"
        return 0
    fi

    # Output formatted table
    printf "${C_BOLD}%-5s | %-16s | %-18s | %-34s | %-20s${C_RESET}\n" "ID" "USERNAME" "KEY ID" "SECRET TOKEN (PREVIEW)" "CREATED AT"
    echo "------+------------------+--------------------+------------------------------------+--------------------"

    sqlite3 -separator '|' "${DB_PATH}" "SELECT id, username, aegis_key_id, aegis_token, created_at FROM users ORDER BY id ASC;" | while IFS='|' read -r uid uname ukid utok udate; do
        local masked_tok="${utok:0:16}...${utok: -8}"
        printf "%-5s | %-16s | %-18s | %-34s | %-20s\n" "$uid" "$uname" "$ukid" "$masked_tok" "$udate"
    done
    echo ""
}

# --- CLI Action: Show User Configuration ---
cmd_show_user() {
    require_root
    local username="${1:-}"
    if [[ -z "$username" ]]; then
        log_fatal "Usage: $0 show-user <username>"
    fi

    if [[ ! -f "$DB_PATH" ]]; then
        log_fatal "Database not found at ${DB_PATH}."
    fi

    local row
    row=$(sqlite3 -separator '|' "${DB_PATH}" "SELECT aegis_key_id, aegis_token, created_at FROM users WHERE username = '${username}';")
    if [[ -z "$row" ]]; then
        log_fatal "User '${username}' not found in database."
    fi

    local key_id token created_at
    IFS='|' read -r key_id token created_at <<< "$row"

    local server_ip
    server_ip=$(get_public_ip)

    echo ""
    echo -e "${C_CYAN}${C_BOLD}========================================================================${C_RESET}"
    echo -e "${C_WHITE}${C_BOLD} 🔑 USER DETAILS: ${C_YELLOW}${username}${C_RESET}"
    echo -e "${C_CYAN}${C_BOLD}========================================================================${C_RESET}"
    echo -e "  ${C_BOLD}Username:${C_RESET}       ${C_WHITE}${username}${C_RESET}"
    echo -e "  ${C_BOLD}Key ID (Hex):${C_RESET}   ${C_CYAN}${key_id}${C_RESET}"
    echo -e "  ${C_BOLD}Secret Token:${C_RESET}   ${C_GREEN}${token}${C_RESET}"
    echo -e "  ${C_BOLD}Server:${C_RESET}         ${C_WHITE}${server_ip}:${DEFAULT_UDP_PORT}${C_RESET}"
    echo -e "  ${C_BOLD}Created At:${C_RESET}     ${C_DIM}${created_at}${C_RESET}"
    echo -e "${C_CYAN}------------------------------------------------------------------------${C_RESET}"
    echo -e "${C_YELLOW}${C_BOLD}Client Launch Command:${C_RESET}"
    echo -e "  ${C_WHITE}./aegs-client --server ${server_ip} --token ${token} --port 51821${C_RESET}"
    echo -e "${C_CYAN}========================================================================${C_RESET}"
    echo ""
}

# --- CLI Action: Remove User ---
cmd_remove_user() {
    require_root
    local username="${1:-}"
    local force="${2:-}"

    if [[ -z "$username" ]]; then
        log_fatal "Usage: $0 remove-user <username> [--force]"
    fi

    if [[ ! -f "$DB_PATH" ]]; then
        log_fatal "Database not found at ${DB_PATH}."
    fi

    local exists
    exists=$(sqlite3 "${DB_PATH}" "SELECT count(*) FROM users WHERE username = '${username}';")
    if [[ "$exists" -eq 0 ]]; then
        log_fatal "User '${username}' does not exist."
    fi

    if [[ "$force" != "--force" && "$force" != "-y" ]]; then
        echo -en "${C_YELLOW}Are you sure you want to delete user '${username}'? [y/N]: ${C_RESET}"
        read -r confirm
        if [[ ! "$confirm" =~ ^[yY]([eE][sS])?$ ]]; then
            log_info "Operation cancelled."
            return 0
        fi
    fi

    sqlite3 "${DB_PATH}" "DELETE FROM users WHERE username = '${username}';"
    log_success "User '${username}' removed from SQLite database."

    # Refresh server in-memory sessions
    restart_server
}

# --- CLI Action: Status ---
cmd_status() {
    banner
    echo -e "${C_WHITE}${C_BOLD}📊 AEGS v2 Server System Status${C_RESET}\n"

    local srv_status="Stopped"
    local srv_color="${C_RED}"

    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        srv_status="Active (Systemd Service: ${SERVICE_NAME})"
        srv_color="${C_GREEN}"
    elif command -v docker >/dev/null 2>&1 && docker ps --filter "name=${DOCKER_CONTAINER_NAME}" --filter "status=running" | grep -q "${DOCKER_CONTAINER_NAME}"; then
        srv_status="Active (Docker Container: ${DOCKER_CONTAINER_NAME})"
        srv_color="${C_GREEN}"
    fi

    echo -e "  • Status:        ${srv_color}${srv_status}${C_RESET}"
    echo -e "  • Public IP:     ${C_WHITE}$(get_public_ip)${C_RESET}"
    echo -e "  • Obfuscated UDP:${C_WHITE}${DEFAULT_UDP_PORT}${C_RESET}"
    echo -e "  • WG Backend:    ${C_WHITE}127.0.0.1:${DEFAULT_WG_PORT}${C_RESET}"
    echo -e "  • Database:      ${C_WHITE}${DB_PATH}${C_RESET}"

    if [[ -f "$DB_PATH" ]]; then
        local user_count
        user_count=$(sqlite3 "${DB_PATH}" "SELECT count(*) FROM users;" 2>/dev/null || echo "0")
        echo -e "  • Active Users:  ${C_CYAN}${user_count}${C_RESET}"
    fi

    echo ""
    if command -v ss >/dev/null 2>&1; then
        echo -e "${C_BOLD}Listening UDP Sockets:${C_RESET}"
        ss -unlp | grep -E "${DEFAULT_UDP_PORT}|${SERVICE_NAME}|aegs" || echo -e "${C_DIM}No sockets matching port ${DEFAULT_UDP_PORT}${C_RESET}"
    fi
    echo ""
}

# --- CLI Action: Logs ---
cmd_logs() {
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        journalctl -u "${SERVICE_NAME}" -f -n 50
    elif command -v docker >/dev/null 2>&1 && docker ps -a | grep -q "${DOCKER_CONTAINER_NAME}"; then
        docker logs -f --tail 50 "${DOCKER_CONTAINER_NAME}"
    else
        log_warn "Service is not running. Showing last journalctl logs if available:"
        journalctl -u "${SERVICE_NAME}" -n 50 || true
    fi
}

# --- CLI Action: Backup & Restore ---
cmd_backup() {
    require_root
    mkdir -p "${BACKUP_DIR}"
    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    local backup_file="${BACKUP_DIR}/aegis_${ts}.db"
    
    if [[ ! -f "$DB_PATH" ]]; then
        log_fatal "No database found at ${DB_PATH} to backup."
    fi

    sqlite3 "${DB_PATH}" ".backup '${backup_file}'"
    chmod 600 "${backup_file}"
    log_success "Database backup created: ${backup_file}"
}

cmd_restore() {
    require_root
    local backup_file="${1:-}"
    if [[ -z "$backup_file" || ! -f "$backup_file" ]]; then
        log_fatal "Usage: $0 restore <path_to_backup.db>"
    fi

    log_info "Restoring database from ${backup_file}..."
    cmd_backup # auto safety backup before overwriting
    cp "$backup_file" "$DB_PATH"
    chmod 600 "$DB_PATH"
    restart_server
    log_success "Database restored successfully and server restarted."
}

# --- CLI Help & Router ---
show_help() {
    banner
    cat << EOF
Usage: $0 <command> [arguments...]

${C_BOLD}SERVER MANAGEMENT & INSTALLATION:${C_RESET}
  ${C_CYAN}install${C_RESET} [--systemd|--docker] [--port <udp_port>]
      Installs build dependencies, compiles server, initializes SQLite DB,
      configures firewall, sets up & starts background service.

  ${C_CYAN}status${C_RESET}
      Displays server status, listening UDP port, public IP, and active users count.

  ${C_CYAN}restart${C_RESET}
      Restarts the background systemd service or Docker container.

  ${C_CYAN}logs${C_RESET}
      Tails live server runtime logs.

${C_BOLD}CLIENT CREDENTIALS MANAGEMENT:${C_RESET}
  ${C_CYAN}add-user <username> [token]${C_RESET}
      Generates a 256-bit high-entropy secret token, computes 64-bit KeyID,
      stores client in database, and outputs ready-to-run client commands.

  ${C_CYAN}list-users${C_RESET}
      Lists all registered client credentials and KeyIDs in an ASCII table.

  ${C_CYAN}show-user <username>${C_RESET}
      Displays existing user credentials, KeyID, and ready-to-copy client commands.

  ${C_CYAN}remove-user <username> [--force]${C_RESET}
      Revokes access by removing the user from SQLite DB and reloading the server.

${C_BOLD}BACKUP & MAINTENANCE:${C_RESET}
  ${C_CYAN}backup${C_RESET}
      Creates a timestamped snapshot of the SQLite database.

  ${C_CYAN}restore <file.db>${C_RESET}
      Restores database from a previous snapshot.

  ${C_CYAN}help${C_RESET}
      Displays this help menu.

${C_BOLD}EXAMPLES:${C_RESET}
  sudo ./manage.sh install
  sudo ./manage.sh add-user alice
  sudo ./manage.sh list-users
  sudo ./manage.sh show-user alice
  sudo ./manage.sh remove-user alice --force
  sudo ./manage.sh status
EOF
}

# --- Main Entry Point ---
main() {
    local cmd="${1:-help}"
    shift || true

    case "$cmd" in
        install)     cmd_install "$@" ;;
        add-user)    cmd_add_user "$@" ;;
        list-users)  cmd_list_users "$@" ;;
        show-user)   cmd_show_user "$@" ;;
        remove-user) cmd_remove_user "$@" ;;
        status)      cmd_status "$@" ;;
        restart)     restart_server "$@" ;;
        logs)        cmd_logs "$@" ;;
        backup)      cmd_backup "$@" ;;
        restore)     cmd_restore "$@" ;;
        help|--help|-h) show_help ;;
        *)
            log_error "Unknown command: ${cmd}"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
