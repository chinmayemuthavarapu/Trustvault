-- TrustVault schema (SQLite). Applied idempotently at startup by app/db.py.
-- All IDs are random 128-bit hex strings (uuid4().hex): not guessable, not sequential.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id                    TEXT PRIMARY KEY,
    username              TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name          TEXT NOT NULL,
    role                  TEXT NOT NULL CHECK (role IN ('admin', 'owner', 'viewer')),
    password_hash         TEXT NOT NULL,
    active                INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    must_change_password  INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0, 1)),
    created_at            TEXT NOT NULL,
    password_changed_at   TEXT NOT NULL
);

-- Server-side sessions. Only the SHA-256 of the cookie token is stored, so a
-- database leak does not hand out live sessions. Deleting a row ends the session
-- on the very next request: that is how revocation is "immediate".
CREATE TABLE IF NOT EXISTS sessions (
    token_hash    TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token    TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    ip            TEXT,
    user_agent    TEXT
);
CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS documents (
    id                  TEXT PRIMARY KEY,
    owner_id            TEXT NOT NULL REFERENCES users(id),
    title               TEXT NOT NULL,
    category            TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    current_version_id  TEXT,
    deleted_at          TEXT,          -- in trash (owner can restore)
    deleted_by          TEXT,
    purged_at           TEXT           -- content destroyed; row kept so audit references resolve
);
CREATE INDEX IF NOT EXISTS ix_documents_owner ON documents(owner_id);

CREATE TABLE IF NOT EXISTS document_versions (
    id                 TEXT PRIMARY KEY,
    document_id        TEXT NOT NULL REFERENCES documents(id),
    version_no         INTEGER NOT NULL,
    original_filename  TEXT NOT NULL,
    file_type          TEXT NOT NULL,   -- detected from content, never from the client
    size_bytes         INTEGER NOT NULL,
    sha256             TEXT NOT NULL,   -- of the plaintext
    blob_name          TEXT NOT NULL UNIQUE,
    wrapped_key        BLOB NOT NULL,   -- per-file key, encrypted with the master key
    uploaded_by        TEXT NOT NULL REFERENCES users(id),
    created_at         TEXT NOT NULL,
    UNIQUE (document_id, version_no)
);

-- One row per (document, person). Absence of a row means no access.
CREATE TABLE IF NOT EXISTS grants (
    id           TEXT PRIMARY KEY,
    document_id  TEXT NOT NULL REFERENCES documents(id),
    user_id      TEXT NOT NULL REFERENCES users(id),
    permission   TEXT NOT NULL CHECK (permission IN ('read', 'edit')),
    granted_by   TEXT NOT NULL REFERENCES users(id),
    created_at   TEXT NOT NULL,
    expires_at   TEXT,
    UNIQUE (document_id, user_id)
);
CREATE INDEX IF NOT EXISTS ix_grants_user ON grants(user_id);

-- Access suggestions shown to owners. Never applied automatically.
CREATE TABLE IF NOT EXISTS suggestions (
    id                 TEXT PRIMARY KEY,
    document_id        TEXT NOT NULL REFERENCES documents(id),
    owner_id           TEXT NOT NULL REFERENCES users(id),
    suggested_user_id  TEXT NOT NULL REFERENCES users(id),
    permission         TEXT NOT NULL CHECK (permission IN ('read', 'edit')),
    reason             TEXT NOT NULL,
    status             TEXT NOT NULL CHECK (status IN ('shown', 'accepted', 'dismissed')),
    created_at         TEXT NOT NULL,
    decided_at         TEXT
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT NOT NULL COLLATE NOCASE,
    ip        TEXT,
    ts        TEXT NOT NULL,
    success   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_login_attempts_user_ts ON login_attempts(username, ts);

-- Append-only, hash-chained audit trail. See app/audit.py.
CREATE TABLE IF NOT EXISTS audit_log (
    id               INTEGER PRIMARY KEY,
    ts               TEXT NOT NULL,
    actor_id         TEXT,
    actor_username   TEXT,
    action           TEXT NOT NULL,
    outcome          TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied', 'error')),
    document_id      TEXT,
    document_title   TEXT,
    target_user_id   TEXT,
    target_username  TEXT,
    ip               TEXT,
    user_agent       TEXT,
    details          TEXT NOT NULL DEFAULT '{}',
    prev_hash        TEXT NOT NULL,
    hash             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS ix_audit_doc ON audit_log(document_id);
CREATE INDEX IF NOT EXISTS ix_audit_actor ON audit_log(actor_id);

-- The application can only INSERT into the audit log. Any UPDATE or DELETE,
-- through the app or through a stray SQL statement, aborts.
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
