"""
NetWatcher - Authentication.
Passwords are hashed with PBKDF2-HMAC-SHA256 (stdlib only, no extra deps).
Sessions are opaque random tokens stored server-side with an expiry, passed
back by the client as a Bearer token (Authorization header).
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Header, HTTPException

from backend.database import db_cursor

SESSION_LIFETIME_HOURS = 12
PBKDF2_ITERATIONS = 200_000


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS
    ).hex()
    return digest, salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    candidate, _ = hash_password(password, salt)
    return secrets.compare_digest(candidate, password_hash)


def create_session(username: str, role: str) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=SESSION_LIFETIME_HOURS)).isoformat()
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO sessions (token, username, role, expires_at) VALUES (?, ?, ?, ?)",
            (token, username, role, expires_at),
        )
    return token


def _get_session(token: str):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM sessions WHERE token = ?", (token,))
        row = cur.fetchone()
    if not row:
        return None
    expires_at = datetime.fromisoformat(row["expires_at"])
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires_at:
        with db_cursor() as cur:
            cur.execute("DELETE FROM sessions WHERE token = ?", (token,))
        return None
    return row


def require_user(authorization: str = Header(default="")):
    """FastAPI dependency: validates Bearer token, returns session row."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    token = authorization.removeprefix("Bearer ").strip()
    session = _get_session(token)
    if not session:
        raise HTTPException(status_code=401, detail="Session invalid or expired")
    return session


def require_admin(session=None):
    """Call after require_user; raises if role isn't admin."""
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return session


def log_action(username: str, action: str, detail: str = ""):
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO audit_log (username, action, detail) VALUES (?, ?, ?)",
            (username, action, detail),
        )
