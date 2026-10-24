"""Tamper-evident audit trail.

Each row carries:
    hash = HMAC-SHA256(TV_AUDIT_KEY, prev_hash || canonical_json(row fields incl. id))

What this gives us, layer by layer:
  1. Database triggers reject UPDATE and DELETE on audit_log (schema.sql), so
     the application itself, or an injected statement, cannot rewrite history.
  2. Someone with raw file access can drop the triggers and edit rows. The
     chain then breaks at the edited row, and because the hash is keyed with
     TV_AUDIT_KEY (held in the environment, not the database), they cannot
     recompute a valid chain from the database alone.
  3. Cutting rows off the END of the chain leaves a valid shorter chain. To
     catch that, every row is also written as a JSON line to stdout, which the
     hosting platform ships to its own log store outside the database, and the
     admin "verify" view reports the head hash and count so they can be
     recorded elsewhere. Truncation shows up as a head that went backwards.

Writes happen inside the caller's BEGIN IMMEDIATE transaction, so the read of
the previous hash and the insert are serialised: no two rows share a parent.
For actions that change data, the audit row is in the SAME transaction as the
change: either both happen or neither does.
"""
import hashlib
import hmac
import json
import sys

from flask import current_app, g, has_request_context, request

from .db import get_db, now_iso, transaction

GENESIS = "0" * 64

_FIELDS = ("id", "ts", "actor_id", "actor_username", "action", "outcome", "document_id",
           "document_title", "target_user_id", "target_username", "ip", "user_agent", "details")


def _canonical(row: dict) -> bytes:
    return json.dumps([row.get(f) for f in _FIELDS], separators=(",", ":"),
                      ensure_ascii=False).encode()


def compute_hash(key: bytes, prev_hash: str, row: dict) -> str:
    return hmac.new(key, prev_hash.encode() + b"|" + _canonical(row), hashlib.sha256).hexdigest()


def _request_meta():
    if not has_request_context():
        return None, None
    return request.remote_addr, (request.headers.get("User-Agent") or "")[:300]


def record(conn, action: str, outcome: str = "allowed", *, actor=None, document=None,
           target=None, details: dict | None = None) -> dict:
    """Append one audit row. MUST be called inside db.transaction()."""
    if not conn.in_transaction:
        raise RuntimeError("audit.record must run inside a transaction")
    if actor is None and has_request_context():
        actor = g.get("user")
    ip, ua = _request_meta()
    last = conn.execute("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = last["hash"] if last else GENESIS
    row = {
        "id": (last["id"] + 1) if last else 1,
        "ts": now_iso(),
        "actor_id": actor["id"] if actor else None,
        "actor_username": actor["username"] if actor else None,
        "action": action,
        "outcome": outcome,
        "document_id": document["id"] if document else None,
        "document_title": document["title"] if document else None,
        "target_user_id": target["id"] if target else None,
        "target_username": target["username"] if target else None,
        "ip": ip,
        "user_agent": ua,
        "details": json.dumps(details or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
    }
    cfg = current_app.config["TV"]
    row["prev_hash"] = prev_hash
    row["hash"] = compute_hash(cfg.AUDIT_KEY, prev_hash, row)
    cols = list(_FIELDS) + ["prev_hash", "hash"]
    conn.execute(
        f"INSERT INTO audit_log ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})",
        [row[c] for c in cols],
    )
    if cfg.AUDIT_STDOUT:
        # Off-database copy for the hosting platform's log store (see module docstring).
        print("AUDIT " + json.dumps(row, separators=(",", ":")), file=sys.stdout, flush=True)
    return row


def record_standalone(action: str, outcome: str, **kwargs) -> dict:
    """For events with no surrounding data change, chiefly refusals."""
    conn = get_db()
    with transaction(conn):
        return record(conn, action, outcome, **kwargs)


def verify_chain(conn, key: bytes) -> dict:
    prev = GENESIS
    expected_id = 1
    count = 0
    for r in conn.execute("SELECT * FROM audit_log ORDER BY id"):
        row = dict(r)
        problem = None
        if row["id"] != expected_id:
            problem = f"gap in sequence: expected id {expected_id}, found {row['id']}"
        elif row["prev_hash"] != prev:
            problem = "prev_hash does not match the previous row"
        elif not hmac.compare_digest(row["hash"], compute_hash(key, prev, row)):
            problem = "row contents do not match its hash"
        if problem:
            return {"intact": False, "checked": count, "broken_at_id": row["id"], "problem": problem}
        prev = row["hash"]
        expected_id += 1
        count += 1
    return {"intact": True, "checked": count, "head_id": expected_id - 1, "head_hash": prev}
