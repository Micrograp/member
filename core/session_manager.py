"""
core/session_manager.py — Core Telegram Session Engine & SQLite Storage

Manages Telegram session files, SQLite database persistence (data/accounts.db),
proxy configuration, and Telethon error recovery.
"""

import os
import sys
import json
import sqlite3
import asyncio
from datetime import date, datetime
from typing import List, Dict, Optional, Any

from dotenv import load_dotenv
from telethon import TelegramClient, errors

load_dotenv()

# Determine project root directory dynamically (copy-login root)
CORE_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(CORE_DIR)

DATA_DIR     = os.path.join(BASE_DIR, "data")
SESSIONS_DIR = os.path.join(BASE_DIR, "sessions")
DB_FILE      = os.path.join(DATA_DIR, "accounts.db")
ACCS_JSON    = os.path.join(DATA_DIR, "accounts.json")

os.makedirs(DATA_DIR,     exist_ok=True)
os.makedirs(SESSIONS_DIR, exist_ok=True)

DEFAULT_DAILY_LIMIT = 30   # safe adds per account per day


# ─────────────────────────────────────────────────────────────────────────────
#  Database Setup & Migration
# ─────────────────────────────────────────────────────────────────────────────

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create accounts table if it does not exist and migrate legacy JSON data."""
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                phone TEXT UNIQUE NOT NULL,
                session_file TEXT UNIQUE NOT NULL,
                display_name TEXT DEFAULT '',
                status TEXT DEFAULT 'active',
                daily_adds INTEGER DEFAULT 0,
                daily_limit INTEGER DEFAULT 30,
                total_adds INTEGER DEFAULT 0,
                last_active TEXT DEFAULT NULL,
                last_reset_date TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                proxy_type TEXT DEFAULT NULL,
                proxy_host TEXT DEFAULT NULL,
                proxy_port INTEGER DEFAULT NULL,
                proxy_user TEXT DEFAULT NULL,
                proxy_pass TEXT DEFAULT NULL,
                two_fa_pass TEXT DEFAULT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        try:
            conn.execute("ALTER TABLE accounts ADD COLUMN two_fa_pass TEXT DEFAULT NULL")
        except sqlite3.OperationalError:
            pass
        conn.commit()

    migrate_json_if_needed()


def migrate_json_if_needed():
    """Migrate legacy accounts.json to accounts.db if accounts.db is empty."""
    if not os.path.exists(ACCS_JSON):
        return

    try:
        with open(ACCS_JSON, "r", encoding="utf-8") as f:
            legacy_data = json.load(f)
        if not legacy_data or not isinstance(legacy_data, list):
            return
    except Exception:
        return

    with get_db_connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
        if count == 0:
            for acc in legacy_data:
                conn.execute("""
                    INSERT OR IGNORE INTO accounts (
                        id, label, phone, session_file, display_name, status,
                        daily_adds, daily_limit, total_adds, last_active,
                        last_reset_date, notes, proxy_type, proxy_host, proxy_port,
                        proxy_user, proxy_pass
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    acc.get("id"),
                    acc.get("label", f"Worker {acc.get('id', 1)}"),
                    acc.get("phone", ""),
                    acc.get("session_file", ""),
                    acc.get("display_name", ""),
                    acc.get("status", "active"),
                    acc.get("daily_adds", 0),
                    acc.get("daily_limit", DEFAULT_DAILY_LIMIT),
                    acc.get("total_adds", 0),
                    acc.get("last_active", None),
                    acc.get("last_reset_date", today_str()),
                    acc.get("notes", ""),
                    acc.get("proxy_type"),
                    acc.get("proxy_host"),
                    acc.get("proxy_port"),
                    acc.get("proxy_user"),
                    acc.get("proxy_pass")
                ))
            conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers & Proxy Configuration
# ─────────────────────────────────────────────────────────────────────────────

def today_str() -> str:
    return date.today().isoformat()


def status_icon(status: str) -> str:
    return {
        "active":    "🟢",
        "limited":   "🟡",
        "banned":    "🔴",
        "expired":   "❌",
        "needs_2fa": "🔑",
        "unknown":   "⚪",
        "error":     "❌",
    }.get(status, "⚪")


def get_proxy_config(acc: Dict[str, Any]) -> Optional[dict]:
    """Returns Telethon-compatible proxy dictionary or None."""
    p_type = (acc.get("proxy_type") or "").strip().lower()
    p_host = (acc.get("proxy_host") or "").strip()
    p_port = acc.get("proxy_port")

    if not (p_type and p_host and p_port):
        return None

    try:
        p_port = int(p_port)
    except (ValueError, TypeError):
        return None

    proxy_dict = {
        "proxy_type": p_type,
        "addr": p_host,
        "port": p_port,
        "rdns": True
    }
    if acc.get("proxy_user"):
        proxy_dict["username"] = str(acc.get("proxy_user")).strip()
    if acc.get("proxy_pass"):
        proxy_dict["password"] = str(acc.get("proxy_pass")).strip()

    return proxy_dict


def create_telegram_client(sess_path: str, api_id: int, api_hash: str, acc: Optional[Dict[str, Any]] = None) -> TelegramClient:
    """Create a Telethon TelegramClient configured with proxy if available."""
    proxy = get_proxy_config(acc) if acc else None
    if proxy:
        return TelegramClient(sess_path, api_id, api_hash, proxy=proxy)
    return TelegramClient(sess_path, api_id, api_hash)


def handle_telethon_error(session_file: str, err: Exception) -> str:
    """Classifies Telethon exceptions and updates account status in database."""
    sess = session_file.lstrip("+").strip()

    if isinstance(err, errors.FloodWaitError):
        msg = f"FloodWait ({err.seconds}s required)"
        update_account_status(sess, "limited", notes=f"FloodWait {err.seconds}s")
        return f"🟡 LIMITED: {msg}"

    elif isinstance(err, (errors.UserDeactivatedError, errors.UserDeactivatedBanError, errors.PhoneNumberBannedError)):
        msg = "Account Banned/Deactivated by Telegram"
        update_account_status(sess, "banned", notes=msg)
        return f"🔴 BANNED: {msg}"

    elif isinstance(err, (errors.AuthKeyUnregisteredError, errors.SessionRevokedError, errors.AuthKeyInvalidError)):
        msg = "Session Expired or Revoked"
        update_account_status(sess, "expired", notes=msg)
        return f"❌ EXPIRED: {msg}"

    elif isinstance(err, errors.SessionPasswordNeededError):
        msg = "2FA Password Required"
        update_account_status(sess, "needs_2fa", notes=msg)
        return f"🔑 2FA REQUIRED: {msg}"

    elif isinstance(err, errors.PeerFloodError):
        msg = "PeerFlood Limit (Account Restricted)"
        update_account_status(sess, "limited", notes=msg)
        return f"🟡 LIMITED: {msg}"

    else:
        msg = str(err)
        update_account_status(sess, "error", notes=msg)
        return f"❌ ERROR: {msg}"


# ─────────────────────────────────────────────────────────────────────────────
#  Database Persistence API
# ─────────────────────────────────────────────────────────────────────────────

def load_accounts() -> List[dict]:
    init_db()
    with get_db_connection() as conn:
        rows = conn.execute("SELECT * FROM accounts ORDER BY id ASC").fetchall()
        return [dict(row) for row in rows]


def update_account_status(session_file: str, status: str, notes: str = ""):
    sess = session_file.lstrip("+").strip()
    with get_db_connection() as conn:
        if notes:
            conn.execute("UPDATE accounts SET status = ?, notes = ? WHERE session_file = ?", (status, notes, sess))
        else:
            conn.execute("UPDATE accounts SET status = ? WHERE session_file = ?", (status, sess))
        conn.commit()


def reset_daily_if_needed(accounts: Optional[List[dict]] = None) -> List[dict]:
    """Reset daily_adds counter for accounts whose last_reset_date != today."""
    today = today_str()
    init_db()
    with get_db_connection() as conn:
        conn.execute("""
            UPDATE accounts
            SET daily_adds = 0,
                last_reset_date = ?,
                status = CASE WHEN status = 'limited' THEN 'active' ELSE status END
            WHERE last_reset_date != ? OR last_reset_date IS NULL
        """, (today, today))
        conn.commit()
    return load_accounts()
