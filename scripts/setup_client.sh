#!/usr/bin/env bash
# ==============================================================================
# 🛡️ AEGS v2 Protocol - Linux & macOS Client Setup & Launcher
# Automated Client Proxy for Obfuscated WireGuard / UDP Tunnels
# ==============================================================================
set -euo pipefail

# --- Colors ---
readonly C_RESET='\033[0m'
readonly C_BOLD='\033[1m'
readonly C_DIM='\033[2m'
readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_CYAN='\033[0;36m'
readonly C_WHITE='\033[1;37m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

CONFIG_DIR="${HOME}/.config/aegis"
CONFIG_FILE="${CONFIG_DIR}/client.env"
PID_FILE="${CONFIG_DIR}/client.pid"
LOG_FILE="${CONFIG_DIR}/client.log"

DEFAULT_LOCAL_PORT=51821
DEFAULT_SERVER_PORT=50001

log_info()    { echo -e "${C_CYAN}[INFO]${C_RESET} $*"; }
log_success() { echo -e "${C_GREEN}[✓]${C_RESET} ${C_BOLD}$*${C_RESET}"; }
log_warn()    { echo -e "${C_YELLOW}[WARN]${C_RESET} $*"; }
log_error()   { echo -e "${C_RED}[ERROR]${C_RESET} $*" >&2; }
log_fatal()   { echo -e "${C_RED}[FATAL]${C_RESET} ${C_BOLD}$*${C_RESET}" >&2; exit 1; }

banner() {
    echo -e "${C_CYAN}${C_BOLD}"
    cat << "EOF"
    ___    ______ _____ ____         ________  _            __ 
   /   |  / ____// ___// __ \ _   __/ ____/ / (_)__  ____  / /_
  / /| | / __/  / / _ / / / /| | / / /   / / / / _ \/ __ \/ __/
 / ___ |/ /___ / /_/ // /_/ / | |/ / /___/ / / /  __/ / / / /_  
/_/  |_/_____/ \____(_)____/  |___/\____/_/_/_/\___/_/ /_/\__/  
  🛡️  Zero-DPI Client Proxy Launcher (WireGuard 127.0.0.1:51821)
EOF
    echo -e "${C_RESET}"
}

find_or_build_client_binary() {
    local candidate_paths=(
        "${SCRIPT_DIR}/aegs-client"
        "${SCRIPT_DIR}/client"
        "${ROOT_DIR}/aegs-client"
        "${ROOT_DIR}/client"
        "${ROOT_DIR}/aegis_client"
        "/usr/local/bin/aegs-client"
        "/usr/local/bin/aegis_client"
    )

    for bin in "${candidate_paths[@]}"; do
        if [[ -x "$bin" ]]; then
            echo "$bin"
            return 0
        fi
    done

    # Try looking in PATH
    if command -v aegs-client >/dev/null 2>&1; then
        command -v aegs-client
        return 0
    fi
    if command -v aegis_client >/dev/null 2>&1; then
        command -v aegis_client
        return 0
    fi

    # Not found -> Attempt auto-compile if client.cpp is available
    local client_src="${ROOT_DIR}/client.cpp"
    if [[ -f "$client_src" ]]; then
        log_info "Client binary not found. Compiling ${client_src}..."
        if ! command -v g++ >/dev/null 2>&1 && ! command -v clang++ >/dev/null 2>&1; then
            log_fatal "C++ compiler (g++ / clang++) not found. Please install build-essential / libssl-dev."
        fi

        local compiler="g++"
        command -v g++ >/dev/null 2>&1 || compiler="clang++"

        local out_bin="${ROOT_DIR}/aegs-client"
        $compiler -O3 -std=c++17 "$client_src" -o "$out_bin" -lssl -lcrypto -lpthread
        chmod +x "$out_bin"
        log_success "Compiled -> ${out_bin}"
        echo "$out_bin"
        return 0
    fi

    log_fatal "Could not find 'aegs-client' binary or 'client.cpp' source."
}

save_config() {
    local server="$1"
    local token="$2"
    local port="$3"

    mkdir -p "${CONFIG_DIR}"
    cat > "${CONFIG_FILE}" << EOF
# AEGS v2 Client Configuration
AEGS_SERVER="${server}"
AEGS_TOKEN="${token}"
AEGS_PORT="${port}"
EOF
    chmod 600 "${CONFIG_FILE}"
    log_success "Saved configuration to ${CONFIG_FILE}"
}

load_config() {
    if [[ -f "${CONFIG_FILE}" ]]; then
        # shellcheck disable=SC1090
        source "${CONFIG_FILE}"
    fi
}

generate_wireguard_sample() {
    local local_port="${1:-$DEFAULT_LOCAL_PORT}"
    local sample_path="${ROOT_DIR}/wg0-aegis.conf"

    cat > "${sample_path}" << EOF
# ==============================================================================
# WireGuard Client Configuration with AEGS v2 Masking
# ==============================================================================
[Interface]
# Replace with your assigned WireGuard client private key and IP
PrivateKey = YOUR_CLIENT_PRIVATE_KEY_HERE
Address = 10.8.0.2/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
# Replace with your server's WireGuard public key
PublicKey = YOUR_SERVER_WIREGUARD_PUBLIC_KEY_HERE
# CRITICAL: Point Endpoint to local AEGS obfuscator proxy port!
Endpoint = 127.0.0.1:${local_port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    log_success "Sample WireGuard profile created at: ${sample_path}"
}

cmd_stop() {
    if [[ -f "${PID_FILE}" ]]; then
        local pid
        pid=$(cat "${PID_FILE}")
        if kill -0 "$pid" 2>/dev/null; then
            log_info "Stopping AEGS client (PID: $pid)..."
            kill "$pid" 2>/dev/null || true
            sleep 1
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
            fi
            log_success "AEGS client stopped."
        else
            log_warn "Process $pid was not running."
        fi
        rm -f "${PID_FILE}"
    else
        # Try finding by process name
        pkill -f "aegs-client" || pkill -f "aegis_client" || true
        log_info "No active PID file found. Cleaned up any matching processes."
    fi
}

cmd_status() {
    banner
    echo -e "${C_WHITE}${C_BOLD}📊 Local AEGS Client Status${C_RESET}\n"

    if [[ -f "${PID_FILE}" ]]; then
        local pid
        pid=$(cat "${PID_FILE}")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "  • Status:     ${C_GREEN}Running${C_RESET} (PID: ${pid})"
            if [[ -f "${CONFIG_FILE}" ]]; then
                load_config
                echo -e "  • Server:     ${C_WHITE}${AEGS_SERVER:-unknown}${C_RESET}"
                echo -e "  • Local Port: ${C_WHITE}${AEGS_PORT:-51821}${C_RESET}"
            fi
            echo -e "  • Log File:   ${C_DIM}${LOG_FILE}${C_RESET}"
            return 0
        fi
    fi

    echo -e "  • Status: ${C_RED}Stopped${C_RESET}"
    if [[ -f "${CONFIG_FILE}" ]]; then
        load_config
        echo -e "  • Last Saved Server: ${C_WHITE}${AEGS_SERVER:-none}${C_RESET}"
    fi
}

show_help() {
    banner
    cat << EOF
Usage: $0 [options]

${C_BOLD}OPTIONS:${C_RESET}
  ${C_CYAN}-s, --server <HOST/IP>${C_RESET}   Remote AEGS v2 server IP or domain
  ${C_CYAN}-t, --token <TOKEN>${C_RESET}      User secret authentication token
  ${C_CYAN}-p, --port <PORT>${C_RESET}        Local UDP port for WireGuard connection (default: 51821)
  ${C_CYAN}--kill-switch${C_RESET}            Block all traffic on external interfaces if tunnel drops
  ${C_CYAN}--dns-protect${C_RESET}            Block plaintext DNS (port 53) on external interfaces
  ${C_CYAN}-d, --daemon${C_RESET}             Run in background as a daemon
  ${C_CYAN}--stop${C_RESET}                   Stop running client background instance
  ${C_CYAN}--status${C_RESET}                 Check client running status
  ${C_CYAN}--gen-wg${C_RESET}                 Generate sample WireGuard client config (.conf)
  ${C_CYAN}-h, --help${C_RESET}               Show this help message

${C_BOLD}EXAMPLES:${C_RESET}
  # Interactive setup wizard:
  ./setup_client.sh

  # Foreground run:
  ./setup_client.sh --server 198.51.100.1 --token a1b2c3d4e5f6...

  # Run in background daemon:
  ./setup_client.sh --server 198.51.100.1 --token a1b2c3d4e5f6... --daemon

  # Stop background client:
  ./setup_client.sh --stop
EOF
}

main() {
    local server=""
    local token=""
    local port="$DEFAULT_LOCAL_PORT"
    local daemon_mode=false
    local gen_wg_only=false
    local kill_switch=false
    local dns_protect=false

    load_config

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -s|--server) server="$2"; shift 2 ;;
            -t|--token)  token="$2"; shift 2 ;;
            -p|--port)   port="$2"; shift 2 ;;
            --kill-switch) kill_switch=true; shift ;;
            --dns-protect) dns_protect=true; shift ;;
            -d|--daemon|--background) daemon_mode=true; shift ;;
            --stop)      cmd_stop; exit 0 ;;
            --status)    cmd_status; exit 0 ;;
            --gen-wg)    gen_wg_only=true; shift ;;
            -h|--help)   show_help; exit 0 ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    if $gen_wg_only; then
        generate_wireguard_sample "$port"
        exit 0
    fi

    # Interactive Wizard if parameters missing
    if [[ -z "$server" || -z "$token" ]]; then
        banner
        echo -e "${C_WHITE}${C_BOLD}🚀 AEGS v2 Client Setup Wizard${C_RESET}\n"

        if [[ -z "$server" ]]; then
            local default_srv="${AEGS_SERVER:-}"
            if [[ -n "$default_srv" ]]; then
                read -rp "Enter Server IP or Hostname [${default_srv}]: " input_server
                server="${input_server:-$default_srv}"
            else
                read -rp "Enter Server IP or Hostname: " server
            fi
        fi

        if [[ -z "$token" ]]; then
            local default_tok="${AEGS_TOKEN:-}"
            if [[ -n "$default_tok" ]]; then
                read -rp "Enter Secret Token [saved token]: " input_token
                token="${input_token:-$default_tok}"
            else
                read -rp "Enter Secret Token: " token
            fi
        fi

        if [[ -z "$server" || -z "$token" ]]; then
            log_fatal "Server address and token are required."
        fi
    fi

    save_config "$server" "$token" "$port"
    generate_wireguard_sample "$port"

    local client_bin
    client_bin=$(find_or_build_client_binary)

    echo ""
    echo -e "${C_CYAN}${C_BOLD}========================================================================${C_RESET}"
    echo -e "${C_GREEN}${C_BOLD}🛡️ LAUNCHING AEGS v2 CLIENT PROXY${C_RESET}"
    echo -e "${C_CYAN}========================================================================${C_RESET}"
    echo -e "  • Remote Server: ${C_WHITE}${server}:${DEFAULT_SERVER_PORT}${C_RESET}"
    echo -e "  • Local WG Port: ${C_WHITE}127.0.0.1:${port}${C_RESET}"
    echo -e "  • Client Binary: ${C_WHITE}${client_bin}${C_RESET}"
    echo -e "${C_CYAN}------------------------------------------------------------------------${C_RESET}"
    echo -e "${C_YELLOW}Point your WireGuard client's [Peer] Endpoint to:${C_RESET} ${C_BOLD}127.0.0.1:${port}${C_RESET}"
    echo -e "${C_CYAN}========================================================================${C_RESET}\n"

    local extra_args=()
    if $kill_switch; then extra_args+=("--kill-switch"); fi
    if $dns_protect; then extra_args+=("--dns-protect"); fi

    if $daemon_mode; then
        mkdir -p "${CONFIG_DIR}"
        cmd_stop 2>/dev/null || true
        nohup "$client_bin" --server "$server" --token "$token" --port "$port" "${extra_args[@]}" > "${LOG_FILE}" 2>&1 &
        local pid=$!
        echo "$pid" > "${PID_FILE}"
        log_success "AEGS client is running in background (PID: $pid)"
        log_info "Logs: tail -f ${LOG_FILE}"
        log_info "Stop with: ./setup_client.sh --stop"
    else
        log_info "Starting client proxy in foreground (Press Ctrl+C to stop)..."
        exec "$client_bin" --server "$server" --token "$token" --port "$port" "${extra_args[@]}"
    fi
}

main "$@"
