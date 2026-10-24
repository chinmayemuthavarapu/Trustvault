"""Authentication plumbing: server-side sessions, CSRF, role checks.

Session cookie: 256-bit random token, HttpOnly, SameSite=Strict, Secure in
production. The database stores only SHA-256(token). Every request re-reads
the session row AND the user row, so disabling a user, changing their
password, logging them out or expiring the session takes effect on the next
request with nothing cached anywhere.
"""
import hashlib
import hmac
import secrets
from functools import wraps
from urllib.parse import urlsplit

from flask import abort, current_app, g, request

from . import audit
from .db import get_db, iso_in, now_iso, transaction

COOKIE = "tv_session"


def cookie_name() -> str:
    """With HTTPS the cookie gets the __Host- prefix: browsers then refuse it unless it is
    Secure, has Path=/ and no Domain, so a sibling subdomain cannot plant or overwrite it."""
    return "__Host-" + COOKIE if current_app.config["TV"].COOKIE_SECURE else COOKIE
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(conn, user_id: str) -> tuple[str, str]:
    """Must be called inside a transaction. Returns (token, csrf_token)."""
    cfg = current_app.config["TV"]
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = now_iso()
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, last_seen_at, expires_at, ip, user_agent)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (_hash(token), user_id, csrf, now, now, iso_in(cfg.SESSION_ABSOLUTE_SECONDS),
         request.remote_addr, (request.headers.get("User-Agent") or "")[:300]),
    )
    return token, csrf


def set_cookie(response, token: str) -> None:
    cfg = current_app.config["TV"]
    response.set_cookie(cookie_name(), token, httponly=True, secure=cfg.COOKIE_SECURE, samesite="Strict",
                        path="/", max_age=cfg.SESSION_ABSOLUTE_SECONDS)


def clear_cookie(response) -> None:
    cfg = current_app.config["TV"]
    response.set_cookie(cookie_name(), "", httponly=True, secure=cfg.COOKIE_SECURE, samesite="Strict",
                        path="/", max_age=0, expires=0)


def current_token_hash() -> str | None:
    token = request.cookies.get(cookie_name())
    return _hash(token) if token else None


def load_user() -> None:
    """before_request: populate g.user / g.session from the cookie, or leave them None."""
    g.user = None
    g.session = None
    token = request.cookies.get(cookie_name())
    if not token or len(token) > 100:
        return
    conn = get_db()
    row = conn.execute(
        "SELECT s.token_hash, s.csrf_token, s.last_seen_at, s.expires_at,"
        "       u.id, u.username, u.display_name, u.role, u.active, u.must_change_password"
        " FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
        (_hash(token),),
    ).fetchone()
    if row is None:
        return
    cfg = current_app.config["TV"]
    now = now_iso()
    idle_cutoff = iso_in(-cfg.SESSION_IDLE_SECONDS)
    if row["expires_at"] <= now or row["last_seen_at"] <= idle_cutoff or not row["active"]:
        with transaction(conn):
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
        return
    # Refresh idle timer at most once a minute to avoid a write per request.
    if row["last_seen_at"] <= iso_in(-60):
        with transaction(conn):
            conn.execute("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", (now, row["token_hash"]))
    g.session = {"token_hash": row["token_hash"], "csrf_token": row["csrf_token"]}
    g.user = {k: row[k] for k in ("id", "username", "display_name", "role", "must_change_password")}


def check_csrf() -> None:
    """before_request: state-changing requests from a logged-in browser must carry
    the per-session CSRF token in a header (which a cross-site form cannot set),
    on top of SameSite=Strict cookies."""
    if request.method in SAFE_METHODS or g.get("session") is None:
        return
    sent = request.headers.get(CSRF_HEADER, "")
    if not sent or not hmac.compare_digest(sent, g.session["csrf_token"]):
        audit.record_standalone("security.csrf_rejected", "denied",
                                details={"path": request.path[:200], "method": request.method})
        abort(403, description="Missing or invalid CSRF token.")
    origin = request.headers.get("Origin")
    if origin and urlsplit(origin).netloc.lower() != request.host.lower():
        audit.record_standalone("security.origin_rejected", "denied",
                                details={"path": request.path[:200], "origin": origin[:200]})
        abort(403, description="Cross-origin request refused.")


def login_required(*roles, allow_password_change=False):
    """Decorator: require a session; optionally restrict to roles.
    Accounts flagged must_change_password can only reach password-change endpoints."""
    def wrap(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            user = g.get("user")
            if user is None:
                abort(401)
            if user["must_change_password"] and not allow_password_change:
                abort(403, description="You must change your password before continuing.")
            if roles and user["role"] not in roles:
                audit.record_standalone("security.role_denied", "denied",
                                        details={"path": request.path[:200], "required": list(roles)})
                abort(403, description="Your role does not allow this.")
            return fn(*args, **kwargs)
        return inner
    return wrap


def revoke_user_sessions(conn, user_id: str, except_token_hash: str | None = None) -> int:
    """Must be called inside a transaction."""
    if except_token_hash:
        cur = conn.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (user_id, except_token_hash))
    else:
        cur = conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    return cur.rowcount
