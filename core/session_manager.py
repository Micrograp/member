"""
core/session_manager.py — Core Telegram Session Engine & MongoDB Storage

Manages Telegram sessions as StringSessions stored in MongoDB Atlas,
proxy configuration, and Telethon error recovery.

All data persists in the cloud — immune to Render's ephemeral filesystem.
"""

import os
import sys
import json
from datetime import date, datetime
from typing import List, Dict, Optional, Any

from dotenv import load_dotenv
from telethon import TelegramClient, errors
from telethon.sessions import StringSession
from pymongo import MongoClient

load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
#  MongoDB Connection
# ─────────────────────────────────────────────────────────────────────────────

MONGO_URI = os.getenv("MONGO_URI", "")
if not MONGO_URI:
    print("[FATAL] MONGO_URI not set in .env — cannot connect to database.")
    sys.exit(1)

_mongo_client = MongoClient(MONGO_URI)
_db = _mongo_client[os.getenv("MONGO_DB_NAME", "teleboost")]
accounts_col = _db["accounts"]
counters_col = _db["counters"]

# Create indexes for fast lookups
accounts_col.create_index("phone", unique=True, sparse=True)
accounts_col.create_index("session_file", unique=True, sparse=True)
accounts_col.create_index("account_id", unique=True)

DEFAULT_DAILY_LIMIT = 30   # safe adds per account per day


# ─────────────────────────────────────────────────────────────────────────────
#  Auto-Increment ID Helper (replaces SQLite AUTOINCREMENT)
# ─────────────────────────────────────────────────────────────────────────────

def _next_id() -> int:
    """Get next auto-increment ID for accounts collection."""
    result = counters_col.find_one_and_update(
        {"_id": "account_id"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=True
    )
    return result["seq"]


# ─────────────────────────────────────────────────────────────────────────────
#  Database Setup (replaces init_db / migrate_json)
# ─────────────────────────────────────────────────────────────────────────────

def init_db():
    """No-op for MongoDB — collections are auto-created. Kept for API compat."""
    pass


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


def create_telegram_client(
    session_string: str,
    api_id: int,
    api_hash: str,
    acc: Optional[Dict[str, Any]] = None
) -> TelegramClient:
    """
    Create a TelegramClient using StringSession (cloud-safe).
    
    Spoofs legitimate Desktop device parameters (device_model, system_version, app_version)
    to prevent Telegram's anti-fraud algorithm from detecting a headless Linux/datacenter bot.
    """
    proxy = get_proxy_config(acc) if acc else None
    
    # Check for global proxy in environment if no account-specific proxy is configured
    if not proxy:
        g_type = os.getenv("GLOBAL_PROXY_TYPE", "").strip().lower()
        g_host = os.getenv("GLOBAL_PROXY_HOST", "").strip()
        g_port = os.getenv("GLOBAL_PROXY_PORT", "").strip()
        if g_type and g_host and g_port:
            try:
                proxy = {
                    "proxy_type": g_type,
                    "addr": g_host,
                    "port": int(g_port),
                    "rdns": True
                }
                if os.getenv("GLOBAL_PROXY_USER"):
                    proxy["username"] = os.getenv("GLOBAL_PROXY_USER").strip()
                if os.getenv("GLOBAL_PROXY_PASS"):
                    proxy["password"] = os.getenv("GLOBAL_PROXY_PASS").strip()
            except Exception:
                proxy = None

    ss = StringSession(session_string)
    
    client_kwargs = {
        "device_model": "Desktop",
        "system_version": "Windows 11",
        "app_version": "5.6.3 x64",
        "lang_code": "en",
        "system_lang_code": "en"
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    return TelegramClient(ss, api_id, api_hash, **client_kwargs)


def save_session_string(session_file: str, session_string: str):
    """Save a Telethon StringSession string to MongoDB for the given account."""
    accounts_col.update_one(
        {"session_file": session_file},
        {"$set": {"session_string": session_string}},
    )


def get_session_string(session_file: str) -> str:
    """Retrieve the saved StringSession string from MongoDB. Returns '' if not found."""
    doc = accounts_col.find_one({"session_file": session_file}, {"session_string": 1})
    if doc and doc.get("session_string"):
        return doc["session_string"]
    return ""


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
#  Database Persistence API (MongoDB)
# ─────────────────────────────────────────────────────────────────────────────

def load_accounts() -> List[dict]:
    """Load all accounts from MongoDB, sorted by account_id."""
    docs = accounts_col.find({}, {"_id": 0}).sort("account_id", 1)
    results = []
    for doc in docs:
        # Map MongoDB fields to the dict keys the rest of the app expects
        doc["id"] = doc.get("account_id", 0)
        results.append(doc)
    return results


def get_account_by_id(account_id: int) -> Optional[dict]:
    """Fetch a single account by its numeric ID."""
    doc = accounts_col.find_one({"account_id": account_id}, {"_id": 0})
    if doc:
        doc["id"] = doc.get("account_id", 0)
    return doc


def get_account_by_phone_or_session(phone: str, session_file: str) -> Optional[dict]:
    """Look up account by phone or session_file name."""
    doc = accounts_col.find_one(
        {"$or": [{"phone": phone}, {"session_file": session_file}]},
        {"_id": 0}
    )
    if doc:
        doc["id"] = doc.get("account_id", 0)
    return doc


def upsert_account(
    phone: str,
    session_file: str,
    label: str = "",
    display_name: str = "",
    status: str = "active",
    two_fa_pass: Optional[str] = None,
    session_string: str = "",
):
    """Insert or update an account document in MongoDB."""
    update_fields = {
        "label": label,
        "display_name": display_name,
        "status": status,
        "last_reset_date": today_str(),
    }
    if session_string:
        update_fields["session_string"] = session_string
    if two_fa_pass is not None:
        update_fields["two_fa_pass"] = two_fa_pass

    result = accounts_col.update_one(
        {"phone": phone},
        {
            "$set": update_fields,
            "$setOnInsert": {
                "account_id": _next_id(),
                "phone": phone,
                "session_file": session_file,
                "daily_adds": 0,
                "daily_limit": DEFAULT_DAILY_LIMIT,
                "total_adds": 0,
                "last_active": None,
                "notes": "",
                "proxy_type": None,
                "proxy_host": None,
                "proxy_port": None,
                "proxy_user": None,
                "proxy_pass": None,
                "created_at": datetime.utcnow().isoformat(),
            }
        },
        upsert=True
    )
    return result


def delete_account(account_id: int):
    """Delete an account from MongoDB by its numeric ID."""
    accounts_col.delete_one({"account_id": account_id})


def update_account_status(session_file: str, status: str, notes: str = ""):
    """Update status (and optionally notes) for an account identified by session_file."""
    sess = session_file.lstrip("+").strip()
    update = {"status": status}
    if notes:
        update["notes"] = notes
    accounts_col.update_one({"session_file": sess}, {"$set": update})


def reset_daily_if_needed(accounts: Optional[List[dict]] = None) -> List[dict]:
    """Reset daily_adds counter for accounts whose last_reset_date != today."""
    today = today_str()
    accounts_col.update_many(
        {"$or": [
            {"last_reset_date": {"$ne": today}},
            {"last_reset_date": None},
            {"last_reset_date": {"$exists": False}},
        ]},
        {"$set": {
            "daily_adds": 0,
            "last_reset_date": today,
        }}
    )
    # Also reset 'limited' → 'active' for those accounts
    accounts_col.update_many(
        {"status": "limited", "last_reset_date": today},
        {"$set": {"status": "active"}}
    )
    return load_accounts()
