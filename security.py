"""Secure sessions (random bearer tokens stored as SHA-256 hashes), login lockout and password rules."""
import hashlib
import re
import secrets
from functools import wraps

from flask import g, jsonify, request

import config
from database import connect


def fail(message, code=400, **extra):
    body = {"ok": False, "error": message}
    body.update(extra)
    return jsonify(body), code


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def password_problem(password: str):
    """Return an error message if the password is too weak, else None."""
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Password must contain at least one letter and one number."
    return None


def create_session(db, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    db.execute("INSERT INTO sessions(user_id, token_hash, expires_at) VALUES(?,?,datetime('now', ?))",
               (user_id, hash_token(token), f"+{config.SESSION_DAYS} days"))
    return token


def revoke_all_sessions(db, user_id: int):
    db.execute("UPDATE sessions SET revoked=1 WHERE user_id=?", (user_id,))


def _token_from_request():
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return ""


def current_user():
    token = _token_from_request()
    if not token:
        return None
    with connect() as db:
        row = db.execute("""SELECT u.id, u.name, u.email, u.phone, u.role, s.id AS session_id
                            FROM sessions s JOIN users u ON u.id = s.user_id
                            WHERE s.token_hash=? AND s.revoked=0 AND s.expires_at > datetime('now')""",
                         (hash_token(token),)).fetchone()
        if row:
            db.execute("UPDATE sessions SET last_used_at=CURRENT_TIMESTAMP WHERE id=?", (row["session_id"],))
    return dict(row) if row else None


def require_auth(*roles):
    """Decorator: the request must carry a valid 'Authorization: Bearer <token>' header.
    If roles are given, the signed-in user must have one of them."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return fail("Your session has expired. Please sign in again.", 401, session_expired=True)
            if roles and user["role"] not in roles:
                names = {"citizen": "Citizen", "authority": "Municipal Authority", "worker": "Repair Worker"}
                return fail(f"{' or '.join(names[r] for r in roles)} access is required.", 403)
            g.user = user
            return view(*args, **kwargs)
        return wrapper
    return decorator
