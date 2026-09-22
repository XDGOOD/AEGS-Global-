#!/usr/bin/env bash
# ==============================================================================
# 🛡️ AEGS Titan Telegram Bot Launcher (Linux / macOS)
# ==============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${ROOT_DIR}"

if [[ -z "${BOT_TOKEN:-}" ]]; then
    echo "----------------------------------------------------------------------"
    echo "⚠️  Переменная BOT_TOKEN не задана."
    echo "Введите токен бота от @BotFather:"
    read -r input_token
    export BOT_TOKEN="${input_token}"
fi

python3 -m tools.telegram_bot.bot
