"""
AEGS Titan - Cryptographic Token & Server Database Synchronization Engine
"""

import os
import sqlite3
import hashlib
import secrets
import logging
from . import config

logger = logging.getLogger('aegs_sync')

def generate_token() -> str:
    """Generates a 256-bit (64 hex characters) cryptographic pre-shared secret token."""
    return secrets.token_hex(32)

def compute_key_id(token: str) -> str:
    """Computes KeyID: first 8 bytes (16 hex chars) of SHA-256(token)."""
    return hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]

def init_aegis_server_db():
    """Ensures AEGS server database exists with correct table structure."""
    os.makedirs(os.path.dirname(config.AEGIS_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(config.AEGIS_DB_PATH)
    try:
        with conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                aegis_key_id TEXT NOT NULL,
                aegis_token TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_key_id ON users(aegis_key_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    finally:
        conn.close()

def sync_add_user_to_server(username: str, key_id: str, token: str) -> bool:
    """
    Adds or updates active user in the AEGS C++ Server database.
    Allows immediate authentication on the VPN server.
    """
    init_aegis_server_db()
    conn = sqlite3.connect(config.AEGIS_DB_PATH)
    try:
        with conn:
            conn.execute("""
            INSERT INTO users (username, aegis_key_id, aegis_token)
            VALUES (?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                aegis_key_id = excluded.aegis_key_id,
                aegis_token = excluded.aegis_token;
            """, (username, key_id, token))
        logger.info(f"User {username} (KeyID: {key_id}) synchronized to AEGS server DB")
        try:
            import subprocess
            subprocess.run(["systemctl", "try-restart", "aegs-server.service"], timeout=2)
        except Exception:
            pass
        return True
    except Exception as e:
        logger.error(f"Failed to sync user {username} to server DB: {e}")
        return False
    finally:
        conn.close()

def sync_remove_user_from_server(key_id: str) -> bool:
    """
    Removes user from AEGS server database upon subscription expiration.
    The server will immediately reject subsequent packets and handshakes.
    """
    init_aegis_server_db()
    conn = sqlite3.connect(config.AEGIS_DB_PATH)
    try:
        with conn:
            conn.execute("DELETE FROM users WHERE aegis_key_id = ?;", (key_id,))
        logger.info(f"KeyID {key_id} removed from AEGS server DB (expired/suspended)")
        try:
            import subprocess
            subprocess.run(["systemctl", "try-restart", "aegs-server.service"], timeout=2)
        except Exception:
            pass
        return True
    except Exception as e:
        logger.error(f"Failed to remove KeyID {key_id} from server DB: {e}")
        return False
    finally:
        conn.close()

def make_subscription_uri(token: str, name: str = "AEGS_Titan") -> str:
    """
    Builds the standard AEGS subscription URI format for 1-click import in Android & Desktop apps:
    aegs://<HOST>:<PORT>/<TOKEN>?name=<NAME>
    """
    return f"aegs://{config.SERVER_IP}:{config.SERVER_PORT}/{token}?name={name}"

def make_quick_command(token: str) -> str:
    """Generates quick terminal connection command for Linux / macOS."""
    return f"./aegis_client {config.SERVER_IP} {config.SERVER_PORT} {token}"
