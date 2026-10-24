"""Document routes. Each route that names a document calls authz.require()
as its first data access. Read that function before reading these."""
import hashlib
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from flask import Blueprint, Response, abort, current_app, g, jsonify, request

from . import audit, storage
from .authz import ACCESSIBLE_SQL, Action, require
from .db import get_db, iso, new_id, now_iso, transaction
from .request_helpers import int_arg, json_body
from .sessions import login_required
from .validation import ALLOWED, UploadRejected, clean_text, detect_and_validate

bp = Blueprint("documents", __name__, url_prefix="/api")

_ID = re.compile(r"^[0-9a-f]{32}$")


def _cfg():
    return current_app.config["TV"]


def _like(term: str) -> str:
    """Escape LIKE wildcards so a search for '%' does not match everything."""
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _parse_date(value: str, field: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        abort(400, description=f"{field} must be a date like 2026-10-24.")


def _doc_json(row, permission=None):
    out = {
        "id": row["id"], "title": row["title"], "category": row["category"],
        "description": row["description"], "created_at": row["created_at"], "updated_at": row["updated_at"],
        "owner": {"username": row["owner_username"], "display_name": row["owner_name"]},
        "in_trash": bool(row["deleted_at"]), "deleted_at": row["deleted_at"],
        "my_permission": permission or row["my_permission"],
    }
    if row["current_version_id"]:
        out["current_version"] = {
            "id": row["current_version_id"], "version_no": row["version_no"],
            "filename": row["original_filename"], "file_type": row["file_type"], "size_bytes": row["size_bytes"],
        }
    return out


_DOC_SELECT = """
    SELECT d.*, u.username AS owner_username, u.display_name AS owner_name,
           v.version_no, v.original_filename, v.file_type, v.size_bytes,
           CASE WHEN d.owner_id = :me THEN 'owner' ELSE (
               SELECT g.permission FROM grants g WHERE g.document_id = d.id AND g.user_id = :me
                 AND (g.expires_at IS NULL OR g.expires_at > :now)) END AS my_permission
    FROM documents d
    JOIN users u ON u.id = d.owner_id
    LEFT JOIN document_versions v ON v.id = d.current_version_id
"""


def _load_doc_view(doc_id):
    me = g.user["id"]
    return get_db().execute(_DOC_SELECT + " WHERE d.id = :id", {"me": me, "now": now_iso(), "id": doc_id}).fetchone()


def _read_upload():
    f = request.files.get("file")
    if f is None or not f.filename:
        abort(400, description="Choose a file to upload.")
    data = f.read(_cfg().MAX_UPLOAD_BYTES + 1)
    try:
        name, file_type = detect_and_validate(f.filename, data, _cfg().MAX_UPLOAD_BYTES)
    except UploadRejected as e:
        audit.record_standalone("document.upload", "denied",
                                details={"reason": str(e), "filename": (f.filename or "")[:200], "size": len(data)})
        abort(400, description=str(e))
    return name, file_type, data


def _add_version(conn, doc_id, name, file_type, data, version_no):
    """Encrypt to disk, then record the version row (caller holds the transaction)."""
    version_id = new_id()
    blob_name, wrapped = storage.store(_cfg().BLOB_DIR, _cfg().MASTER_KEY, doc_id, version_id, data)
    try:
        conn.execute(
            "INSERT INTO document_versions (id, document_id, version_no, original_filename, file_type, size_bytes,"
            " sha256, blob_name, wrapped_key, uploaded_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (version_id, doc_id, version_no, name, file_type, len(data), hashlib.sha256(data).hexdigest(),
             blob_name, wrapped, g.user["id"], now_iso()))
    except Exception:
        storage.destroy(_cfg().BLOB_DIR, blob_name)
        raise
    return version_id, blob_name


# ---------------------------------------------------------------- meta

@bp.get("/meta")
@login_required()
def meta():
    return jsonify({"categories": _cfg().CATEGORIES, "max_upload_bytes": _cfg().MAX_UPLOAD_BYTES,
                    "allowed_extensions": sorted(ALLOWED)})


# ---------------------------------------------------------------- list / search

@bp.get("/documents")
@login_required()
def list_documents():
    me = g.user["id"]
    params = {"me": me, "now": now_iso()}
    where = [ACCESSIBLE_SQL, "d.deleted_at IS NULL"]

    scope = request.args.get("scope", "all")
    if scope == "mine":
        where.append("d.owner_id = :me")
    elif scope == "shared":
        where.append("d.owner_id != :me")
    elif scope != "all":
        abort(400, description="scope must be all, mine or shared.")

    q = (request.args.get("q") or "").strip()[:100]
    if q:
        where.append("(d.title LIKE :q ESCAPE '\\' OR d.description LIKE :q ESCAPE '\\'"
                     " OR v.original_filename LIKE :q ESCAPE '\\')")
        params["q"] = _like(q)
    owner = (request.args.get("owner") or "").strip()[:64]
    if owner:
        where.append("(u.username LIKE :owner ESCAPE '\\' OR u.display_name LIKE :owner ESCAPE '\\')")
        params["owner"] = _like(owner)
    category = request.args.get("category")
    if category:
        if category not in _cfg().CATEGORIES:
            abort(400, description="Unknown category.")
        where.append("d.category = :category")
        params["category"] = category
    if request.args.get("from"):
        where.append("d.created_at >= :from_ts")
        params["from_ts"] = iso(_parse_date(request.args["from"], "from"))
    if request.args.get("to"):
        where.append("d.created_at < :to_ts")
        params["to_ts"] = iso(_parse_date(request.args["to"], "to") + timedelta(days=1))

    sort = {"updated": "d.updated_at DESC", "created": "d.created_at DESC",
            "title": "d.title COLLATE NOCASE ASC"}.get(request.args.get("sort", "updated"))
    if sort is None:
        abort(400, description="sort must be updated, created or title.")
    page = int_arg("page", 1, 1, 10_000)
    size = int_arg("page_size", 25, 1, 100)

    conn = get_db()
    base = _DOC_SELECT + " WHERE " + " AND ".join(f"({w})" for w in where)
    total = conn.execute(f"SELECT COUNT(*) FROM ({base})", params).fetchone()[0]
    rows = conn.execute(f"{base} ORDER BY {sort} LIMIT :lim OFFSET :off",
                        dict(params, lim=size, off=(page - 1) * size)).fetchall()
    return jsonify({"total": total, "page": page, "page_size": size, "items": [_doc_json(r) for r in rows]})


@bp.get("/documents/trash")
@login_required()
def list_trash():
    rows = get_db().execute(
        _DOC_SELECT + " WHERE d.owner_id = :me AND d.deleted_at IS NOT NULL AND d.purged_at IS NULL"
        " ORDER BY d.deleted_at DESC", {"me": g.user["id"], "now": now_iso()}).fetchall()
    retention = _cfg().TRASH_RETENTION_DAYS
    return jsonify({"retention_days": retention, "items": [_doc_json(r) for r in rows]})


# ---------------------------------------------------------------- create / read / update

@bp.post("/documents")
@login_required("owner")
def upload_document():
    try:
        title = clean_text(request.form.get("title"), "Title", 200, required=True)
        description = clean_text(request.form.get("description"), "Description", 2000)
    except UploadRejected as e:
        abort(400, description=str(e))
    category = request.form.get("category")
    if category not in _cfg().CATEGORIES:
        abort(400, description="Choose a category from the list.")
    unknown = set(request.form) - {"title", "description", "category"}
    if unknown:
        abort(400, description=f"Unknown field(s): {', '.join(sorted(unknown))}.")
    name, file_type, data = _read_upload()

    conn = get_db()
    doc_id = new_id()
    now = now_iso()
    with transaction(conn):
        conn.execute(
            "INSERT INTO documents (id, owner_id, title, category, description, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?)", (doc_id, g.user["id"], title, category, description, now, now))
        version_id, blob = _add_version(conn, doc_id, name, file_type, data, 1)
        try:
            conn.execute("UPDATE documents SET current_version_id = ? WHERE id = ?", (version_id, doc_id))
            audit.record(conn, "document.upload", "allowed", document={"id": doc_id, "title": title},
                         details={"version": 1, "filename": name, "file_type": file_type, "size": len(data),
                                  "sha256": hashlib.sha256(data).hexdigest(), "category": category})
        except Exception:
            storage.destroy(_cfg().BLOB_DIR, blob)
            raise
    return jsonify(_doc_json(_load_doc_view(doc_id))), 201


@bp.get("/documents/<doc_id>")
@login_required()
def get_document(doc_id):
    doc, permission = require(g.user, doc_id, Action.VIEW)
    conn = get_db()
    versions = conn.execute(
        "SELECT v.id, v.version_no, v.original_filename, v.file_type, v.size_bytes, v.sha256, v.created_at,"
        " u.username AS uploaded_by FROM document_versions v JOIN users u ON u.id = v.uploaded_by"
        " WHERE v.document_id = ? ORDER BY v.version_no DESC", (doc["id"],)).fetchall()
    with transaction(conn):
        audit.record(conn, "document.view", "allowed", document=doc)
    out = _doc_json(_load_doc_view(doc["id"]), permission)
    out["versions"] = [dict(v) for v in versions]
    return jsonify(out)


@bp.patch("/documents/<doc_id>")
@login_required()
def update_document(doc_id):
    doc, _ = require(g.user, doc_id, Action.EDIT)
    data = json_body({"title", "category", "description"})
    changes = {}
    try:
        if "title" in data:
            changes["title"] = clean_text(data["title"], "Title", 200, required=True)
        if "description" in data:
            changes["description"] = clean_text(data["description"], "Description", 2000)
    except UploadRejected as e:
        abort(400, description=str(e))
    if "category" in data:
        if data["category"] not in _cfg().CATEGORIES:
            abort(400, description="Choose a category from the list.")
        changes["category"] = data["category"]
    changes = {k: v for k, v in changes.items() if v != doc[k]}
    if not changes:
        return jsonify(_doc_json(_load_doc_view(doc["id"])))
    conn = get_db()
    with transaction(conn):
        sets = ", ".join(f"{k} = ?" for k in changes)  # keys come from the fixed allowlist above
        conn.execute(f"UPDATE documents SET {sets}, updated_at = ? WHERE id = ?",
                     [*changes.values(), now_iso(), doc["id"]])
        audit.record(conn, "document.update", "allowed", document=doc,
                     details={k: {"from": doc[k], "to": v} for k, v in changes.items()})
    return jsonify(_doc_json(_load_doc_view(doc["id"])))


@bp.post("/documents/<doc_id>/versions")
@login_required()
def upload_version(doc_id):
    doc, _ = require(g.user, doc_id, Action.EDIT)
    if set(request.form):
        abort(400, description="Only a file is expected.")
    name, file_type, data = _read_upload()
    conn = get_db()
    with transaction(conn):
        n = conn.execute("SELECT COALESCE(MAX(version_no), 0) + 1 FROM document_versions WHERE document_id = ?",
                         (doc["id"],)).fetchone()[0]
        version_id, blob = _add_version(conn, doc["id"], name, file_type, data, n)
        try:
            conn.execute("UPDATE documents SET current_version_id = ?, updated_at = ? WHERE id = ?",
                         (version_id, now_iso(), doc["id"]))
            audit.record(conn, "document.new_version", "allowed", document=doc,
                         details={"version": n, "filename": name, "file_type": file_type, "size": len(data),
                                  "sha256": hashlib.sha256(data).hexdigest()})
        except Exception:
            storage.destroy(_cfg().BLOB_DIR, blob)
            raise
    return jsonify(_doc_json(_load_doc_view(doc["id"]))), 201


# ---------------------------------------------------------------- download

@bp.get("/documents/<doc_id>/download")
@login_required()
def download(doc_id):
    # >>> The authorisation decision for downloads is this line. <<<
    doc, _ = require(g.user, doc_id, Action.DOWNLOAD)
    if not current_app.extensions["tv_limiter"].hit(f"dl:{g.user['id']}", _cfg().DOWNLOADS_PER_MINUTE):
        audit.record_standalone("document.download", "denied", document=doc, details={"reason": "rate limited"})
        abort(429, description="Too many downloads. Wait a minute and try again.")
    conn = get_db()
    version_id = request.args.get("version") or doc["current_version_id"]
    if not isinstance(version_id, str) or not _ID.match(version_id):
        abort(404)
    # The version must belong to THIS document. Without the document_id condition,
    # a read grant on one document would unlock any version id of any other.
    v = conn.execute("SELECT * FROM document_versions WHERE id = ? AND document_id = ?",
                     (version_id, doc["id"])).fetchone()
    if v is None:
        audit.record_standalone("document.download", "denied", document=doc,
                                details={"reason": "version not in this document", "version": version_id})
        abort(404)
    try:
        data = storage.load(_cfg().BLOB_DIR, _cfg().MASTER_KEY, doc["id"], v["id"], v["blob_name"], v["wrapped_key"])
    except storage.StorageError:
        audit.record_standalone("document.download", "error", document=doc,
                                details={"reason": "blob failed integrity check", "version": v["version_no"]})
        abort(500, description="This file failed its integrity check and was not served.")
    # Audit is written BEFORE any byte leaves. If the audit write fails, nothing is served.
    with transaction(conn):
        audit.record(conn, "document.download", "allowed", document=doc,
                     details={"version": v["version_no"], "filename": v["original_filename"], "sha256": v["sha256"]})
    fallback = re.sub(r"[^A-Za-z0-9._-]", "_", v["original_filename"])[:150] or "download"
    return Response(data, headers={
        "Content-Type": "application/octet-stream",
        "Content-Disposition": f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(v['original_filename'])}",
        "Content-Length": str(len(data)),
        "Cache-Control": "no-store, private",
        "Content-Security-Policy": "sandbox; default-src 'none'",
        "X-Download-Options": "noopen",
    })


# ---------------------------------------------------------------- delete / restore / purge

@bp.delete("/documents/<doc_id>")
@login_required()
def delete_document(doc_id):
    doc, _ = require(g.user, doc_id, Action.DELETE)
    conn = get_db()
    with transaction(conn):
        conn.execute("UPDATE documents SET deleted_at = ?, deleted_by = ? WHERE id = ?",
                     (now_iso(), g.user["id"], doc["id"]))
        audit.record(conn, "document.delete", "allowed", document=doc, details={"mode": "moved to trash"})
    return jsonify({"ok": True})


@bp.post("/documents/<doc_id>/restore")
@login_required()
def restore_document(doc_id):
    doc, _ = require(g.user, doc_id, Action.RESTORE)
    conn = get_db()
    with transaction(conn):
        conn.execute("UPDATE documents SET deleted_at = NULL, deleted_by = NULL, updated_at = ? WHERE id = ?",
                     (now_iso(), doc["id"]))
        audit.record(conn, "document.restore", "allowed", document=doc)
    return jsonify(_doc_json(_load_doc_view(doc["id"])))


def purge(conn, doc, reason: str):
    """Destroy content permanently. Caller has authorised and holds no transaction."""
    blobs = [r["blob_name"] for r in conn.execute(
        "SELECT blob_name FROM document_versions WHERE document_id = ?", (doc["id"],))]
    with transaction(conn):
        conn.execute("UPDATE documents SET purged_at = ? WHERE id = ?", (now_iso(), doc["id"]))
        conn.execute("DELETE FROM grants WHERE document_id = ?", (doc["id"],))
        audit.record(conn, "document.purge", "allowed", document=doc,
                     details={"reason": reason, "versions_destroyed": len(blobs)})
    for b in blobs:
        storage.destroy(_cfg().BLOB_DIR, b)


@bp.post("/documents/<doc_id>/purge")
@login_required()
def purge_document(doc_id):
    doc, _ = require(g.user, doc_id, Action.PURGE)
    purge(get_db(), doc, "owner purged from trash")
    return jsonify({"ok": True})


# ---------------------------------------------------------------- sharing

def _grant_json(r):
    return {"id": r["id"], "permission": r["permission"], "created_at": r["created_at"],
            "expires_at": r["expires_at"], "expired": bool(r["expires_at"] and r["expires_at"] <= now_iso()),
            "user": {"username": r["username"], "display_name": r["display_name"]},
            "granted_by": r["granted_by_username"]}


def _grants(conn, doc_id):
    return conn.execute(
        "SELECT g.*, u.username, u.display_name, gb.username AS granted_by_username FROM grants g"
        " JOIN users u ON u.id = g.user_id JOIN users gb ON gb.id = g.granted_by"
        " WHERE g.document_id = ? ORDER BY u.display_name", (doc_id,)).fetchall()


@bp.get("/documents/<doc_id>/grants")
@login_required()
def list_grants(doc_id):
    doc, _ = require(g.user, doc_id, Action.SHARE)
    return jsonify({"items": [_grant_json(r) for r in _grants(get_db(), doc["id"])]})


def _parse_expiry(value):
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        abort(400, description="expires_at must be a date.")
    try:
        if len(value) == 10:
            dt = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc) + timedelta(days=1)
        else:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
    except ValueError:
        abort(400, description="expires_at must be a date like 2026-12-31.")
    if dt <= datetime.now(timezone.utc):
        abort(400, description="The expiry date must be in the future.")
    return iso(dt)


@bp.post("/documents/<doc_id>/grants")
@login_required()
def add_grant(doc_id):
    doc, _ = require(g.user, doc_id, Action.SHARE)
    data = json_body({"username", "permission", "expires_at", "suggestion_id"}, {"username", "permission"})
    if data["permission"] not in ("read", "edit"):
        abort(400, description="permission must be read or edit.")
    if not isinstance(data["username"], str):
        abort(400, description="username must be text.")
    expires_at = _parse_expiry(data.get("expires_at"))
    conn = get_db()
    target = conn.execute("SELECT id, username, display_name, active FROM users WHERE username = ?",
                          (data["username"].strip(),)).fetchone()
    if target is None or not target["active"]:
        abort(400, description="No active user with that username.")
    if target["id"] == doc["owner_id"]:
        abort(400, description="The owner already has full access.")

    suggestion = None
    if data.get("suggestion_id"):
        suggestion = conn.execute(
            "SELECT * FROM suggestions WHERE id = ? AND document_id = ? AND suggested_user_id = ? AND status = 'shown'",
            (data["suggestion_id"], doc["id"], target["id"])).fetchone()
        if suggestion is None:
            abort(400, description="That suggestion does not apply to this person and document.")

    with transaction(conn):
        existing = conn.execute("SELECT * FROM grants WHERE document_id = ? AND user_id = ?",
                                (doc["id"], target["id"])).fetchone()
        if existing:
            conn.execute("UPDATE grants SET permission = ?, expires_at = ?, granted_by = ?, created_at = ? WHERE id = ?",
                         (data["permission"], expires_at, g.user["id"], now_iso(), existing["id"]))
            action = "permission.change"
            details = {"from": existing["permission"], "to": data["permission"],
                       "expires_from": existing["expires_at"], "expires_to": expires_at}
        else:
            conn.execute("INSERT INTO grants (id, document_id, user_id, permission, granted_by, created_at, expires_at)"
                         " VALUES (?,?,?,?,?,?,?)",
                         (new_id(), doc["id"], target["id"], data["permission"], g.user["id"], now_iso(), expires_at))
            action = "permission.grant"
            details = {"permission": data["permission"], "expires_at": expires_at}
        if suggestion:
            conn.execute("UPDATE suggestions SET status = 'accepted', decided_at = ? WHERE id = ?",
                         (now_iso(), suggestion["id"]))
            details["from_suggestion"] = {"id": suggestion["id"], "suggested_permission": suggestion["permission"],
                                          "reason": suggestion["reason"], "confirmed_by_owner": True}
        audit.record(conn, action, "allowed", document=doc, target=target, details=details)
    return jsonify({"items": [_grant_json(r) for r in _grants(conn, doc["id"])]}), 201


@bp.delete("/documents/<doc_id>/grants/<grant_id>")
@login_required()
def revoke_grant(doc_id, grant_id):
    doc, _ = require(g.user, doc_id, Action.SHARE)
    conn = get_db()
    # The grant must belong to THIS document; otherwise an owner of document A
    # could delete grants on document B by guessing ids.
    grant = conn.execute("SELECT g.*, u.username FROM grants g JOIN users u ON u.id = g.user_id"
                         " WHERE g.id = ? AND g.document_id = ?", (grant_id, doc["id"])).fetchone()
    if grant is None:
        audit.record_standalone("permission.revoke", "denied", document=doc,
                                details={"reason": "grant not on this document", "grant_id": str(grant_id)[:64]})
        abort(404)
    with transaction(conn):
        conn.execute("DELETE FROM grants WHERE id = ?", (grant["id"],))
        audit.record(conn, "permission.revoke", "allowed", document=doc,
                     target={"id": grant["user_id"], "username": grant["username"]},
                     details={"permission": grant["permission"], "effect": "immediate; next request is refused"})
    return jsonify({"items": [_grant_json(r) for r in _grants(conn, doc["id"])]})


# ---------------------------------------------------------------- access suggestions

@bp.get("/documents/<doc_id>/suggestions")
@login_required()
def suggestions(doc_id):
    """Suggest who might need this document, from the owner's own past sharing.
    Read-only: nothing is granted here. The owner must confirm through add_grant,
    which records the suggestion and the decision together in the audit trail."""
    doc, _ = require(g.user, doc_id, Action.SHARE)
    conn = get_db()
    rows = conn.execute(
        """
        SELECT u.id, u.username, u.display_name,
               SUM(CASE WHEN d.category = :cat THEN 3 ELSE 1 END) AS score,
               SUM(CASE WHEN d.category = :cat THEN 1 ELSE 0 END) AS same_cat,
               COUNT(*) AS total,
               SUM(CASE WHEN g.permission = 'edit' THEN 1 ELSE 0 END) AS edits
        FROM grants g
        JOIN documents d ON d.id = g.document_id
        JOIN users u ON u.id = g.user_id
        WHERE d.owner_id = :owner AND d.id != :doc AND d.purged_at IS NULL AND u.active = 1
          AND u.id != :owner
          AND u.id NOT IN (SELECT user_id FROM grants WHERE document_id = :doc)
          AND u.id NOT IN (SELECT suggested_user_id FROM suggestions WHERE document_id = :doc AND status = 'dismissed')
        GROUP BY u.id ORDER BY score DESC, u.display_name LIMIT 5
        """, {"cat": doc["category"], "owner": doc["owner_id"], "doc": doc["id"]}).fetchall()
    items, new_items = [], []
    with transaction(conn):
        for r in rows:
            reason = (f"Has access to {r['same_cat']} of your other {doc['category']} documents"
                      if r["same_cat"] else f"Has access to {r['total']} of your other documents")
            permission = "edit" if r["edits"] * 2 > r["total"] else "read"
            existing = conn.execute("SELECT id FROM suggestions WHERE document_id = ? AND suggested_user_id = ?"
                                    " AND status = 'shown'", (doc["id"], r["id"])).fetchone()
            sid = existing["id"] if existing else new_id()
            if not existing:
                conn.execute("INSERT INTO suggestions (id, document_id, owner_id, suggested_user_id, permission,"
                             " reason, status, created_at) VALUES (?,?,?,?,?,?, 'shown', ?)",
                             (sid, doc["id"], g.user["id"], r["id"], permission, reason, now_iso()))
            item = {"id": sid, "permission": permission, "reason": reason,
                    "user": {"username": r["username"], "display_name": r["display_name"]}}
            items.append(item)
            if not existing:
                new_items.append(item)
        if new_items:
            # Recorded once, when a suggestion is first made, not on every page view.
            audit.record(conn, "suggestion.shown", "allowed", document=doc,
                         details={"suggested": [{"username": i["user"]["username"], "permission": i["permission"],
                                                 "reason": i["reason"], "suggestion_id": i["id"]} for i in new_items]})
    return jsonify({"items": items})


@bp.post("/documents/<doc_id>/suggestions/<sid>/dismiss")
@login_required()
def dismiss_suggestion(doc_id, sid):
    doc, _ = require(g.user, doc_id, Action.SHARE)
    conn = get_db()
    s = conn.execute("SELECT s.*, u.username FROM suggestions s JOIN users u ON u.id = s.suggested_user_id"
                     " WHERE s.id = ? AND s.document_id = ? AND s.status = 'shown'", (sid, doc["id"])).fetchone()
    if s is None:
        abort(404)
    with transaction(conn):
        conn.execute("UPDATE suggestions SET status = 'dismissed', decided_at = ? WHERE id = ?", (now_iso(), s["id"]))
        audit.record(conn, "suggestion.dismissed", "allowed", document=doc,
                     target={"id": s["suggested_user_id"], "username": s["username"]},
                     details={"suggested_permission": s["permission"], "reason": s["reason"]})
    return jsonify({"ok": True})


# ---------------------------------------------------------------- per-document activity (owner)

@bp.get("/documents/<doc_id>/activity")
@login_required()
def document_activity(doc_id):
    doc, _ = require(g.user, doc_id, Action.SHARE)
    rows = get_db().execute(
        "SELECT id, ts, actor_username, action, outcome, target_username, details FROM audit_log"
        " WHERE document_id = ? ORDER BY id DESC LIMIT 200", (doc["id"],)).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})


# ---------------------------------------------------------------- people picker

@bp.get("/users/lookup")
@login_required()
def user_lookup():
    """Find colleagues to share with. Only for people who can share (owners), and
    returns at most 8 matches for a 2+ character query, to limit directory scraping."""
    conn = get_db()
    can_share = g.user["role"] == "owner" or conn.execute(
        "SELECT 1 FROM documents WHERE owner_id = ? AND purged_at IS NULL LIMIT 1", (g.user["id"],)).fetchone()
    if not can_share:
        abort(403, description="Only document owners can look up people.")
    q = (request.args.get("q") or "").strip()[:64]
    if len(q) < 2:
        return jsonify({"items": []})
    rows = conn.execute(
        "SELECT username, display_name FROM users WHERE active = 1 AND id != ?"
        " AND (username LIKE ? ESCAPE '\\' OR display_name LIKE ? ESCAPE '\\') ORDER BY display_name LIMIT 8",
        (g.user["id"], _like(q), _like(q))).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})
