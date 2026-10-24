"""Administrator routes: people, audit trail, integrity check, alerts.

Administrators manage accounts and watch activity. They have NO implicit
access to document contents: authz.decide() never looks at role.
"""
import re
import secrets
from datetime import timedelta

from flask import Blueprint, abort, current_app, g, jsonify, request

from . import audit
from .db import get_db, iso, iso_in, new_id, now_iso, transaction, utcnow
from .request_helpers import int_arg, json_body
from .passwords import hash_password
from .routes_documents import _like, _parse_date
from .sessions import login_required, revoke_user_sessions

bp = Blueprint("admin", __name__, url_prefix="/api/admin")

_USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
ROLES = ("admin", "owner", "viewer")


def _user_json(r):
    return {k: r[k] for k in ("id", "username", "display_name", "role", "created_at")} | {
        "active": bool(r["active"]), "must_change_password": bool(r["must_change_password"]),
        "sessions": r["sessions"], "documents": r["documents"]}


def _users(conn, where="1=1", params=()):
    return conn.execute(
        "SELECT u.*, (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id) AS sessions,"
        " (SELECT COUNT(*) FROM documents d WHERE d.owner_id = u.id AND d.purged_at IS NULL) AS documents"
        f" FROM users u WHERE {where} ORDER BY u.role, u.display_name", params).fetchall()


@bp.get("/users")
@login_required("admin")
def list_users():
    return jsonify({"items": [_user_json(r) for r in _users(get_db())]})


@bp.post("/users")
@login_required("admin")
def create_user():
    data = json_body({"username", "display_name", "role"}, {"username", "display_name", "role"})
    username = str(data["username"]).strip().lower()
    if not _USERNAME.match(username):
        abort(400, description="Usernames are 3-32 characters: lowercase letters, digits, dot, dash, underscore.")
    display = str(data["display_name"]).strip()
    if not 1 <= len(display) <= 80:
        abort(400, description="Display name must be 1-80 characters.")
    if data["role"] not in ROLES:
        abort(400, description="Role must be admin, owner or viewer.")
    conn = get_db()
    if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        abort(409, description="That username is taken.")
    temp = secrets.token_urlsafe(12)
    uid = new_id()
    with transaction(conn):
        conn.execute("INSERT INTO users (id, username, display_name, role, password_hash, active, must_change_password,"
                     " created_at, password_changed_at) VALUES (?,?,?,?,?,1,1,?,?)",
                     (uid, username, display, data["role"], hash_password(temp), now_iso(), now_iso()))
        audit.record(conn, "admin.user_create", "allowed", target={"id": uid, "username": username},
                     details={"role": data["role"]})
    # The temporary password is shown once to the admin and must be changed at first login.
    return jsonify({"user": _user_json(_users(conn, "u.id = ?", (uid,))[0]), "temporary_password": temp}), 201


@bp.patch("/users/<user_id>")
@login_required("admin")
def update_user(user_id):
    data = json_body({"role", "active", "display_name"})
    conn = get_db()
    target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        abort(404)
    changes = {}
    if "role" in data:
        if data["role"] not in ROLES:
            abort(400, description="Role must be admin, owner or viewer.")
        changes["role"] = data["role"]
    if "active" in data:
        if not isinstance(data["active"], bool):
            abort(400, description="active must be true or false.")
        changes["active"] = 1 if data["active"] else 0
    if "display_name" in data:
        name = str(data["display_name"]).strip()
        if not 1 <= len(name) <= 80:
            abort(400, description="Display name must be 1-80 characters.")
        changes["display_name"] = name
    changes = {k: v for k, v in changes.items() if v != target[k]}
    if target["id"] == g.user["id"] and ("role" in changes or changes.get("active") == 0):
        abort(400, description="You cannot change your own role or disable yourself.")
    if target["role"] == "admin" and ("role" in changes or changes.get("active") == 0):
        admins = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1").fetchone()[0]
        if admins <= 1:
            abort(400, description="At least one active administrator must remain.")
    if not changes:
        return jsonify(_user_json(_users(conn, "u.id = ?", (user_id,))[0]))
    with transaction(conn):
        sets = ", ".join(f"{k} = ?" for k in changes)  # keys from the allowlist above
        conn.execute(f"UPDATE users SET {sets} WHERE id = ?", [*changes.values(), user_id])
        ended = 0
        if changes.get("active") == 0 or "role" in changes:
            ended = revoke_user_sessions(conn, user_id)
        audit.record(conn, "admin.user_update", "allowed", target=target,
                     details={"changes": {k: {"from": target[k], "to": v} for k, v in changes.items()},
                              "sessions_ended": ended})
    return jsonify(_user_json(_users(conn, "u.id = ?", (user_id,))[0]))


@bp.post("/users/<user_id>/revoke-sessions")
@login_required("admin")
def revoke_sessions(user_id):
    conn = get_db()
    target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        abort(404)
    with transaction(conn):
        ended = revoke_user_sessions(conn, user_id)
        audit.record(conn, "admin.sessions_revoked", "allowed", target=target, details={"sessions_ended": ended})
    return jsonify({"sessions_ended": ended})


# ---------------------------------------------------------------- audit

@bp.get("/audit")
@login_required("admin")
def audit_list():
    where, params = ["1=1"], []
    action = request.args.get("action")
    if action:
        where.append("action LIKE ? ESCAPE '\\'")
        params.append(action.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")[:60] + "%")
    if request.args.get("outcome"):
        if request.args["outcome"] not in ("allowed", "denied", "error"):
            abort(400, description="outcome must be allowed, denied or error.")
        where.append("outcome = ?")
        params.append(request.args["outcome"])
    if request.args.get("actor"):
        where.append("actor_username LIKE ? ESCAPE '\\'")
        params.append(_like(request.args["actor"][:64]))
    if request.args.get("document"):
        where.append("(document_title LIKE ? ESCAPE '\\' OR document_id = ?)")
        params += [_like(request.args["document"][:100]), request.args["document"][:64]]
    if request.args.get("from"):
        where.append("ts >= ?")
        params.append(iso(_parse_date(request.args["from"], "from")))
    if request.args.get("to"):
        where.append("ts < ?")
        params.append(iso(_parse_date(request.args["to"], "to") + timedelta(days=1)))
    page = int_arg("page", 1, 1, 100_000)
    size = int_arg("page_size", 50, 1, 200)
    conn = get_db()
    clause = " AND ".join(where)
    total = conn.execute(f"SELECT COUNT(*) FROM audit_log WHERE {clause}", params).fetchone()[0]
    rows = conn.execute(f"SELECT * FROM audit_log WHERE {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                        [*params, size, (page - 1) * size]).fetchall()
    return jsonify({"total": total, "page": page, "page_size": size, "items": [dict(r) for r in rows]})


@bp.get("/audit/verify")
@login_required("admin")
def audit_verify():
    conn = get_db()
    result = audit.verify_chain(conn, current_app.config["TV"].AUDIT_KEY)
    with transaction(conn):
        audit.record(conn, "admin.audit_verified", "allowed" if result["intact"] else "error", details=result)
    return jsonify(result)


# ---------------------------------------------------------------- alerts and summary

def _alerts(conn):
    day, hour = iso_in(-86400), iso_in(-3600)
    alerts = []

    def add(kind, severity, title, detail, actor=None):
        alerts.append({"kind": kind, "severity": severity, "title": title, "detail": detail, "actor": actor})

    for r in conn.execute(
            "SELECT actor_username, COUNT(*) n, COUNT(DISTINCT COALESCE(document_id, details)) docs FROM audit_log"
            " WHERE outcome = 'denied' AND action LIKE 'document.%' AND actor_id IS NOT NULL AND ts > ?"
            " GROUP BY actor_id HAVING n >= 5 ORDER BY n DESC", (day,)):
        add("probing", "high", f"{r['actor_username']} was refused {r['n']} times in 24 hours",
            f"Attempts against {r['docs']} different targets. Repeated refusals usually mean someone is trying ids "
            "or links they were not given.", r["actor_username"])
    for r in conn.execute(
            "SELECT actor_username, COUNT(*) n, COUNT(DISTINCT document_id) docs FROM audit_log"
            " WHERE action = 'document.download' AND outcome = 'allowed' AND ts > ? GROUP BY actor_id HAVING n >= 15",
            (hour,)):
        add("bulk_download", "high", f"{r['actor_username']} downloaded {r['n']} files in the last hour",
            f"{r['docs']} different documents. Bulk downloading is the usual shape of data being taken out.",
            r["actor_username"])
    for r in conn.execute(
            "SELECT json_extract(details, '$.username') AS u, COUNT(*) n FROM audit_log"
            " WHERE action = 'auth.login' AND outcome = 'denied' AND ts > ? GROUP BY u HAVING n >= 5", (hour,)):
        add("login_failures", "medium", f"{r['n']} failed sign-ins for '{r['u']}' in the last hour",
            "Possible password guessing. The account locks itself after repeated failures.")
    for r in conn.execute(
            "SELECT ip, COUNT(*) n, COUNT(DISTINCT json_extract(details, '$.username')) users FROM audit_log"
            " WHERE action = 'auth.login' AND outcome = 'denied' AND ts > ? GROUP BY ip HAVING users >= 3",
            (hour,)):
        add("spraying", "high", f"{r['users']} different usernames tried from {r['ip']}",
            f"{r['n']} failed sign-ins in the last hour from one address: looks like password spraying.")
    for r in conn.execute(
            "SELECT actor_username, COUNT(*) n FROM audit_log WHERE action IN ('permission.grant','permission.change')"
            " AND ts > ? GROUP BY actor_id HAVING n >= 10", (hour,)):
        add("mass_sharing", "medium", f"{r['actor_username']} changed access {r['n']} times in the last hour",
            "Unusually wide sharing in a short time.", r["actor_username"])
    n = conn.execute("SELECT COUNT(*) FROM audit_log WHERE action LIKE 'security.%' AND ts > ?", (day,)).fetchone()[0]
    if n:
        add("forged_requests", "medium", f"{n} forged or cross-site requests refused in 24 hours",
            "Requests without a valid CSRF token or from another origin, or role-restricted endpoints called "
            "by the wrong role.")
    n = conn.execute("SELECT COUNT(*) FROM audit_log WHERE outcome = 'error' AND action = 'document.download'"
                     " AND ts > ?", (day,)).fetchone()[0]
    if n:
        add("integrity", "high", f"{n} files failed their integrity check",
            "Stored ciphertext did not decrypt. Someone may have altered files on disk.")
    return alerts


@bp.get("/alerts")
@login_required("admin")
def alerts():
    return jsonify({"items": _alerts(get_db())})


@bp.get("/summary")
@login_required("admin")
def summary():
    conn = get_db()
    day = iso_in(-86400)

    def count(sql, *p):
        return conn.execute(sql, p).fetchone()[0]

    stats = {
        "users": count("SELECT COUNT(*) FROM users WHERE active = 1"),
        "documents": count("SELECT COUNT(*) FROM documents WHERE purged_at IS NULL AND deleted_at IS NULL"),
        "downloads_24h": count("SELECT COUNT(*) FROM audit_log WHERE action='document.download' AND outcome='allowed'"
                               " AND ts > ?", day),
        "refusals_24h": count("SELECT COUNT(*) FROM audit_log WHERE outcome='denied' AND ts > ?", day),
        "permission_changes_24h": count("SELECT COUNT(*) FROM audit_log WHERE action LIKE 'permission.%' AND ts > ?", day),
        "audit_entries": count("SELECT COUNT(*) FROM audit_log"),
    }
    hours = []
    start = utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(hours=23)
    for i in range(24):
        a, b = iso(start + timedelta(hours=i)), iso(start + timedelta(hours=i + 1))
        hours.append({
            "hour": a,
            "allowed": count("SELECT COUNT(*) FROM audit_log WHERE outcome='allowed' AND ts >= ? AND ts < ?", a, b),
            "denied": count("SELECT COUNT(*) FROM audit_log WHERE outcome='denied' AND ts >= ? AND ts < ?", a, b),
        })
    return jsonify({"stats": stats, "hourly": hours, "alerts": _alerts(conn), "generated_at": now_iso()})
