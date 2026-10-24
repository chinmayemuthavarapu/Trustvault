"""THE document authorisation decision.

Every route that touches a document calls `require()` before doing anything
else. There is no second code path that reads documents, versions, grants or
blobs for a specific document without going through it. (Listing/search is
the one place that filters many documents in SQL; it uses the same rules,
expressed as `ACCESSIBLE_SQL` below, and tests/test_authz_matrix.py checks
the two agree for every user and every document.)

Rules, in order:
  1. The document id must be well-formed and the document must exist and not
     be purged.
  2. Owner of the document:
       live document   -> VIEW, DOWNLOAD, EDIT, SHARE, DELETE
       in the trash    -> VIEW, RESTORE, PURGE
  3. Anyone else needs a grant row for (document, user) that has not expired,
     and the document must not be in the trash:
       read  -> VIEW, DOWNLOAD
       edit  -> VIEW, DOWNLOAD, EDIT
     Grantees never SHARE, DELETE, RESTORE or PURGE.
  4. Everything else is refused. Role (admin/owner/viewer) grants NOTHING on
     its own: an administrator has no implicit access to documents.

Refusals are audited. If the caller has no visible access at all, they get
404 (indistinguishable from "does not exist"); if they can see the document
but not perform this action, they get 403.
"""
import re
from enum import Enum

from flask import abort

from . import audit
from .db import get_db, now_iso

_DOC_ID = re.compile(r"^[0-9a-f]{32}$")


class Action(str, Enum):
    VIEW = "view"
    DOWNLOAD = "download"
    EDIT = "edit"
    SHARE = "share"
    DELETE = "delete"
    RESTORE = "restore"
    PURGE = "purge"


OWNER_LIVE = {Action.VIEW, Action.DOWNLOAD, Action.EDIT, Action.SHARE, Action.DELETE}
OWNER_TRASH = {Action.VIEW, Action.RESTORE, Action.PURGE}
GRANT_ACTIONS = {
    "read": {Action.VIEW, Action.DOWNLOAD},
    "edit": {Action.VIEW, Action.DOWNLOAD, Action.EDIT},
}

# SQL form of rules 2-3 for VIEW, used for listing/search. Parameters: (:me, :now).
ACCESSIBLE_SQL = """
    d.purged_at IS NULL AND (
        d.owner_id = :me
        OR (d.deleted_at IS NULL AND EXISTS (
            SELECT 1 FROM grants g
            WHERE g.document_id = d.id AND g.user_id = :me
              AND (g.expires_at IS NULL OR g.expires_at > :now)))
    )
"""


class Decision:
    __slots__ = ("allowed", "document", "permission", "visible", "reason")

    def __init__(self, allowed, document, permission, visible, reason):
        self.allowed = allowed
        self.document = document          # sqlite Row or None
        self.permission = permission      # 'owner' | 'edit' | 'read' | None
        self.visible = visible            # may the caller know this document exists?
        self.reason = reason


def active_grant(conn, document_id: str, user_id: str):
    return conn.execute(
        "SELECT * FROM grants WHERE document_id = ? AND user_id = ? "
        "AND (expires_at IS NULL OR expires_at > ?)",
        (document_id, user_id, now_iso()),
    ).fetchone()


def decide(conn, user, document_id, action: Action) -> Decision:
    if user is None:
        return Decision(False, None, None, False, "not authenticated")
    if not isinstance(document_id, str) or not _DOC_ID.match(document_id):
        return Decision(False, None, None, False, "malformed document id")
    doc = conn.execute(
        "SELECT * FROM documents WHERE id = ? AND purged_at IS NULL", (document_id,)
    ).fetchone()
    if doc is None:
        return Decision(False, None, None, False, "no such document")

    if doc["owner_id"] == user["id"]:
        allowed_actions = OWNER_TRASH if doc["deleted_at"] else OWNER_LIVE
        ok = action in allowed_actions
        return Decision(ok, doc, "owner", True, "owner" if ok else f"owner cannot {action.value} in this state")

    if doc["deleted_at"]:
        return Decision(False, doc, None, False, "document is in the owner's trash")

    grant = active_grant(conn, document_id, user["id"])
    if grant is None:
        return Decision(False, doc, None, False, "no grant")
    ok = action in GRANT_ACTIONS[grant["permission"]]
    return Decision(ok, doc, grant["permission"], True,
                    f"{grant['permission']} grant" if ok else f"{grant['permission']} grant does not allow {action.value}")


def require(user, document_id, action: Action):
    """Return the document row if allowed; otherwise audit the refusal and abort."""
    conn = get_db()
    d = decide(conn, user, document_id, action)
    if d.allowed:
        return d.document, d.permission
    audit.record_standalone(
        f"document.{action.value}", "denied",
        actor=user,
        # Record which document was targeted even when the caller may not see it;
        # the audit log is admin-only, so this leaks nothing to the caller.
        document=d.document if d.document is not None else None,
        details={"reason": d.reason, "requested_id": str(document_id)[:64]},
    )
    abort(403 if d.visible else 404)
