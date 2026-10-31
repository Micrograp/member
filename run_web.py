"""
run_web.py — 1-Click Launcher for Telegram Session Store Web Application

Run this script to launch the Web UI locally on http://127.0.0.1:5000
"""
import os
import sys
import uvicorn

# Ensure core package is in Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    print(f"[*] Starting Telegram Session Web App on http://{host}:{port}")
    uvicorn.run("app:app", host=host, port=port, reload=True)
