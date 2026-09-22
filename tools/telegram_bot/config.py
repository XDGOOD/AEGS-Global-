"""
AEGS Titan Telegram Bot - Configuration Module
"""

import os

# --- Telegram Bot Settings ---
BOT_TOKEN = os.getenv("BOT_TOKEN", "8988683377:AAGlu7emVUqm_khSQFpZWruFWSBqd0QBc-U")

# Primary Admin Usernames (Strictly only @Balbes_ls has admin access)
ADMIN_USERNAMES = ["balbes_ls"]

# Primary Admin IDs (8537965095 is @balbes_ls user ID)
ADMIN_IDS = [8537965095]

ADMIN_IDS_RAW = os.getenv("ADMIN_IDS", "")
for x in ADMIN_IDS_RAW.split(","):
    if x.strip().isdigit() and int(x.strip()) not in ADMIN_IDS:
        ADMIN_IDS.append(int(x.strip()))

# --- AEGS VPN Server Settings ---
SERVER_IP = os.getenv("AEGS_SERVER_IP", "31.76.9.86")
SERVER_PORT = int(os.getenv("AEGS_SERVER_PORT", "50001"))
SERVER_NAME = os.getenv("AEGS_SERVER_NAME", "AEGS Netherlands-01")

# Paths
AEGIS_DB_PATH = os.getenv("AEGIS_DB_PATH", "/app/data/aegis.db")
if not os.path.exists(os.path.dirname(AEGIS_DB_PATH)) and os.path.exists("./data"):
    AEGIS_DB_PATH = "./data/aegis.db"
elif not os.path.exists(os.path.dirname(AEGIS_DB_PATH)):
    AEGIS_DB_PATH = "tools/telegram_bot/data/aegis.db"

BOT_DB_PATH = os.getenv("BOT_DB_PATH", "tools/telegram_bot/data/bot_billing.db")

os.makedirs(os.path.dirname(BOT_DB_PATH), exist_ok=True)
os.makedirs(os.path.dirname(AEGIS_DB_PATH), exist_ok=True)

# Device Limit per Subscription
MAX_DEVICES_PER_KEY = 4

# --- Subscription Plans & Pricing (RUB) ---
# Strictly only 1 single plan: 1 month for 100 RUB (per owner request)
PLANS = {
    "1_month": {
        "id": "1_month",
        "name": "1 месяц (30 дней)",
        "days": 30,
        "price_rub": 100,
        "description": "30 дней, до 4 устройств одновременно (макс. 4 шт), Anti-DPI QUIC Mimicry, до 940 Мбит/с"
    }
}

ENABLE_FREE_TRIAL = False
TRIAL_DAYS = 0

SUPPORT_USERNAME = "Balbes_ls"
NEWS_CHANNEL = os.getenv("NEWS_CHANNEL", "AEGS_Official")
APK_DOWNLOAD_URL = "https://github.com/XDGOOD/AEGS-Global-/releases/download/v6.0-titan/AEGS-v6.0-titan.apk"
GITHUB_REPO_URL = "https://github.com/XDGOOD/AEGS-Global-"
AEGS_GLOBAL_URL = "https://github.com/XDGOOD/AEGS-Global-"
