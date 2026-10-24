"""Login, logout, current user, password change."""
from flask import Blueprint, abort, current_app, g, jsonify, make_response, request

from . import audit
from .db import get_db, iso_in, now_iso, transaction
from .request_helpers import json_body
from .passwords import DUMMY_HASH, hash_password, password_problems, verify_password
from .sessions import (clear_cookie, create_session, current_token_hash, login_required,
                       revoke_user_sessions, set_cookie)

bp = Blueprint("auth", __name__, url_prefix="/api/auth")

GENERIC_LOGIN_ERROR = "Username or password is incorrect."


def _user_json(u, csrf=None):
    out = {"id": u["id"], "username": u["username"], "display_name": u["display_name"],
           "role": u["role"], "must_change_password": bool(u["must_change_password"])}
    if csrf:
        out["csrf_token"] = csrf
    return out


def _locked_out(conn, username: str, ip: str) -> bool:
    cfg = current_app.config["TV"]
    since = iso_in(-cfg.LOGIN_WINDOW_SECONDS)
    by_user = conn.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE username = ? AND success = 0 AND ts > ?"
        " AND ts > COALESCE((SELECT MAX(ts) FROM login_attempts WHERE username = ? AND success = 1), '')",
        (username, since, username)).fetchone()[0]
    by_ip = conn.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND success = 0 AND ts > ?", (ip, since)).fetchone()[0]
    return by_user >= cfg.LOGIN_MAX_FAILURES_PER_USER or by_ip >= cfg.LOGIN_MAX_FAILURES_PER_IP


@bp.post("/login")
def login():
    data = json_body({"username", "password"}, {"username", "password"})
    username, password = data["username"], data["password"]
    if not isinstance(username, str) or not isinstance(password, str) or len(username) > 64 or len(password) > 256:
        abort(400, description=GENERIC_LOGIN_ERROR)
    username = username.strip()
    conn = get_db()
    ip = request.remote_addr

    if _locked_out(conn, username, ip):
        audit.record_standalone("auth.login", "denied", details={"username": username[:64], "reason": "locked out"})
        abort(429, description="Too many failed attempts. Wait 15 minutes and try again.")

    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    # Always run the hash, even for unknown users, so timing does not reveal valid usernames.
    ok = verify_password(password, user["password_hash"] if user else DUMMY_HASH)
    ok = ok and user is not None and bool(user["active"])

    with transaction(conn):
        conn.execute("INSERT INTO login_attempts (username, ip, ts, success) VALUES (?, ?, ?, ?)",
                     (username, ip, now_iso(), 1 if ok else 0))
        if not ok:
            reason = "unknown user" if user is None else ("account disabled" if not user["active"] else "bad password")
            audit.record(conn, "auth.login", "denied", actor=None, target=user,
                         details={"username": username[:64], "reason": reason})
        else:
            # Session fixation defence: always a fresh token; drop any token the client brought.
            old = current_token_hash()
            if old:
                conn.execute("DELETE FROM sessions WHERE token_hash = ?", (old,))
            token, csrf = create_session(conn, user["id"])
            audit.record(conn, "auth.login", "allowed", actor=user)
    if not ok:
        abort(401, description=GENERIC_LOGIN_ERROR)
    resp = make_response(jsonify(_user_json(user, csrf)))
    set_cookie(resp, token)
    return resp


@bp.post("/logout")
def logout():
    conn = get_db()
    token_hash = current_token_hash()
    if token_hash:
        with transaction(conn):
            cur = conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            if cur.rowcount and g.get("user"):
                audit.record(conn, "auth.logout", "allowed")
    resp = make_response(jsonify({"ok": True}))
    clear_cookie(resp)
    return resp


@bp.get("/me")
@login_required(allow_password_change=True)
def me():
    return jsonify(_user_json(g.user, g.session["csrf_token"]))


@bp.post("/change-password")
@login_required(allow_password_change=True)
def change_password():
    data = json_body({"current_password", "new_password"}, {"current_password", "new_password"})
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (g.user["id"],)).fetchone()
    if not isinstance(data["current_password"], str) or not verify_password(data["current_password"], user["password_hash"]):
        audit.record_standalone("auth.password_change", "denied", details={"reason": "wrong current password"})
        abort(403, description="Your current password is incorrect.")
    new = data["new_password"]
    problems = password_problems(new, user["username"])
    if not problems and new == data["current_password"]:
        problems = ["Choose a password different from your current one."]
    if problems:
        abort(400, description=" ".join(problems))
    with transaction(conn):
        conn.execute("UPDATE users SET password_hash = ?, must_change_password = 0, password_changed_at = ? WHERE id = ?",
                     (hash_password(new), now_iso(), user["id"]))
        # Every other session for this account ends now (e.g. a stolen one).
        ended = revoke_user_sessions(conn, user["id"], except_token_hash=g.session["token_hash"])
        audit.record(conn, "auth.password_change", "allowed", details={"other_sessions_ended": ended})
    updated = dict(g.user, must_change_password=0)
    return jsonify(_user_json(updated, g.session["csrf_token"]))
