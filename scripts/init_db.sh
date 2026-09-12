#!/usr/bin/env bash
# =============================================================================
# AEGS Protocol v2 - SQLite Database Initialization & User Management Script
# =============================================================================
# Initializes SQLite database 'aegis.db' with schema:
#   CREATE TABLE IF NOT EXISTS users (
#       aegis_key_id TEXT PRIMARY KEY,
#       aegis_token TEXT NOT NULL,
#       created_at DATETIME DEFAULT CURRENT_TIMESTAMP
#   );
#
# Generates or imports credentials for clients.
# 'aegis_key_id' is the 16-hex character (8 bytes) SHA-256 prefix of 'aegis_token'.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DATA_DIR="${DATA_DIR:-${ROOT_DIR}/data}"
DB_PATH="${DB_PATH:-${DATA_DIR}/aegis.db}"
AEGIS_UID=10001
AEGIS_GID=10001

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

usage() {
    cat <<EOF
${BOLD}Usage:${NC} $0 [OPTIONS]

${BOLD}Options:${NC}
  -t, --token <TOKEN>    Use a specific token instead of generating a random one
  -d, --db <PATH>        Path to SQLite database file (default: data/aegis.db)
  -l, --list             List all registered users in the database
  -h, --help             Show this help message

${BOLD}Examples:${NC}
  $0                     # Initialize DB and generate a random test client token
  $0 -t my_secret_token  # Register user with custom token 'my_secret_token'
  $0 -l                  # List all existing users
EOF
}

# Parse command line options
SPECIFIED_TOKEN=""
ACTION_LIST=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--token)
            SPECIFIED_TOKEN="$2"
            shift 2
            ;;
        -d|--db)
            DB_PATH="$2"
            DATA_DIR="$(dirname "$DB_PATH")"
            shift 2
            ;;
        -l|--list)
            ACTION_LIST=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            exit 1
            ;;
    esac
done

# Ensure data directory exists
mkdir -p "$DATA_DIR"

# Helper: Execute SQL command safely across multiple host environments
# (tries native sqlite3 -> python3 -> dockerized alpine sqlite3)
exec_sql() {
    local sql_query="$1"
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "$DB_PATH" "$sql_query"
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c "
import sqlite3, sys
conn = sqlite3.connect('${DB_PATH}')
cursor = conn.cursor()
cursor.executescript('''${sql_query}''')
conn.commit()
conn.close()
"
    elif command -v docker >/dev/null 2>&1; then
        docker run --rm -v "${DATA_DIR}:/data" alpine:3.20 sh -c \
            "apk add --no-cache sqlite >/dev/null 2>&1 && sqlite3 /data/$(basename "$DB_PATH") \"${sql_query}\""
    else
        echo -e "${RED}Error: Neither sqlite3 CLI, python3, nor docker is available to execute SQLite query.${NC}" >&2
        exit 1
    fi
}

query_sql() {
    local sql_query="$1"
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 -header -column "$DB_PATH" "$sql_query"
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c "
import sqlite3
conn = sqlite3.connect('${DB_PATH}')
cursor = conn.cursor()
cursor.execute('''${sql_query}''')
rows = cursor.fetchall()
col_names = [description[0] for description in cursor.description]
print('\t'.join(col_names))
print('-' * 60)
for row in rows:
    print('\t'.join(str(v) for v in row))
conn.close()
"
    elif command -v docker >/dev/null 2>&1; then
        docker run --rm -v "${DATA_DIR}:/data" alpine:3.20 sh -c \
            "apk add --no-cache sqlite >/dev/null 2>&1 && sqlite3 -header -column /data/$(basename "$DB_PATH") \"${sql_query}\""
    fi
}

# Helper: Compute 16-hex key_id (first 8 bytes of SHA256 of token)
compute_key_id() {
    local token="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        echo -n "$token" | sha256sum | awk '{print substr($1, 1, 16)}'
    elif command -v openssl >/dev/null 2>&1; then
        echo -n "$token" | openssl dgst -sha256 | awk '{print substr($NF, 1, 16)}'
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c "import hashlib; print(hashlib.sha256('${token}'.encode('utf-8')).hexdigest()[:16])"
    else
        echo -e "${RED}Error: No hashing tool found (sha256sum/openssl/python3).${NC}" >&2
        exit 1
    fi
}

# 1. Initialize SQLite table schema
echo -e "${CYAN}[1/4] Ensuring SQLite database schema at ${DB_PATH}...${NC}"
exec_sql "
CREATE TABLE IF NOT EXISTS users (
    aegis_key_id TEXT PRIMARY KEY,
    aegis_token TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_users_key_id ON users(aegis_key_id);
"

# Handle --list option
if [ "$ACTION_LIST" = true ]; then
    echo -e "${GREEN}Registered Users in ${DB_PATH}:${NC}"
    query_sql "SELECT aegis_key_id, aegis_token, created_at FROM users ORDER BY created_at DESC;"
    exit 0
fi

# 2. Generate or set token
echo -e "${CYAN}[2/4] Generating client credentials...${NC}"
if [ -n "$SPECIFIED_TOKEN" ]; then
    TOKEN="$SPECIFIED_TOKEN"
else
    if command -v openssl >/dev/null 2>&1; then
        TOKEN=$(openssl rand -hex 32)
    elif [ -r /dev/urandom ]; then
        TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    else
        TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    fi
fi

# 3. Compute key ID (8 bytes = 16 hex chars)
KEY_ID=$(compute_key_id "$TOKEN")

# 4. Insert user into database
echo -e "${CYAN}[3/4] Registering user in database...${NC}"
# Escape single quotes in token
ESCAPED_TOKEN="${TOKEN//\'/\'\'}"
exec_sql "INSERT OR REPLACE INTO users (aegis_key_id, aegis_token) VALUES ('${KEY_ID}', '${ESCAPED_TOKEN}');"

# 5. Fix permissions for non-root container user (UID/GID 10001)
echo -e "${CYAN}[4/4] Setting file permissions for container user aegis (${AEGIS_UID}:${AEGIS_GID})...${NC}"
chmod 775 "$DATA_DIR" || true
chmod 664 "$DB_PATH" || true
if [ "$(id -u)" -eq 0 ]; then
    chown -R "${AEGIS_UID}:${AEGIS_GID}" "$DATA_DIR" 2>/dev/null || true
fi

echo ""
echo -e "${GREEN}=================================================================${NC}"
echo -e "${BOLD}🎉 AEGS Protocol v2 Client Credentials Successfully Generated!${NC}"
echo -e "${GREEN}=================================================================${NC}"
echo -e "  ${BOLD}Database Path:${NC}     ${DB_PATH}"
echo -e "  ${BOLD}AEGS Key ID:${NC}       ${YELLOW}${KEY_ID}${NC}"
echo -e "  ${BOLD}AEGS Token:${NC}        ${GREEN}${TOKEN}${NC}"
echo -e "${GREEN}=================================================================${NC}"
echo ""
echo -e "${BOLD}🚀 Client Quickstart Command:${NC}"
echo -e "Run the following command on your client machine to start the obfuscated tunnel:"
echo ""
echo -e "  ${CYAN}./aegs-client --server <YOUR_SERVER_IP> --token ${TOKEN} --port 51821${NC}"
echo ""
echo -e "${BOLD}📡 WireGuard Client Configuration (${CYAN}wg0.conf${BOLD}):${NC}"
echo -e "Point your WireGuard client's ${YELLOW}Endpoint${NC} to local proxy port ${YELLOW}127.0.0.1:51821${NC}:"
echo ""
cat <<EOF
  [Interface]
  PrivateKey = <CLIENT_PRIVATE_KEY>
  Address = 10.13.13.2/32
  DNS = 1.1.1.1

  [Peer]
  PublicKey = <WIREGUARD_SERVER_PUBLIC_KEY>
  Endpoint = 127.0.0.1:51821
  AllowedIPs = 0.0.0.0/0, ::/0
  PersistentKeepalive = 25
EOF
echo ""
echo -e "${GREEN}Deployment complete! You can now start services with:${NC} ${BOLD}docker compose up -d${NC}"
