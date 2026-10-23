# TrustVault — Design

## 1. Stack and why

| Layer | Choice | Why I can defend it |
|---|---|---|
| API | Python 3.12, FastAPI, Pydantic v2 (`extra="forbid"`) | Explicit per-route dependencies make the authz call visible on every endpoint; strict schemas block mass assignment |
| DB | PostgreSQL 16 via psycopg 3, hand-written SQL, plain `.sql` migrations | Every access rule is a visible SQL predicate I can point at; no ORM can quietly add a query that skips it. Row-Level Security as a second lock; real GRANT/REVOKE to make audit append-only |
| Files | Encrypted blobs in Postgres (`bytea`, ≤ 25 MB), behind a `BlobStore` interface | No public bucket, no presigned URL, no disk path to guess; one transaction covers file + metadata + audit |
| Auth | Server-side sessions, opaque token in `HttpOnly; Secure; SameSite=Strict` cookie, Argon2id passwords | A session row can be deleted, so revocation is immediate. JWTs cannot be un-issued |
| Frontend | React 18, Vite, TypeScript, Tailwind, served by the API from the **same origin** | Same origin means no CORS to misconfigure and SameSite cookies just work. No router or data library: fewer dependencies to audit |
| Tests | pytest + FastAPI TestClient against a fresh real Postgres database per run | RLS, grants, triggers and the real `tv_app` role are exercised, not mocked |
| Deploy | Single Docker image on Render + Render Postgres (`render.yaml`), or `docker compose up` | One URL, one origin, reproducible from a clean clone |

## 2. Roles

| Capability | Admin | Owner | Viewer |
|---|---|---|---|
| Upload documents | ✗ | ✓ | ✗ |
| Read/download a document | only if granted | own + granted | granted only |
| Edit (new version, rename, re-categorise) | only if granted edit | own + edit grants | edit grants |
| Delete / restore / purge | ✗ | own only | ✗ |
| Grant / revoke access | ✗ (see below) | own only | ✗ |
| Create / deactivate users, reset passwords | ✓ | ✗ | ✗ |
| Transfer ownership (e.g. leaver) | ✓ (audited) | ✗ | ✗ |
| View full audit, alerts, chain verification | ✓ | own documents' audit only | ✗ |

**Admins cannot read document content by default.** They run the system, not the documents. An admin who needs a document must be granted it by the owner, or transfer ownership, which is loud in the audit. This is a separation-of-duties choice I can defend in interview: a compromised admin account is not a skeleton key.

No self-registration. Users are created by an admin. An admin may not own documents: promotion to admin is refused until their documents are transferred, and documents cannot be transferred to an admin. Otherwise "admins can't read content" would have an exception.

## 3. Permission model

Per-document grants to named users. Deliberately **no folders and no inheritance**: inheritance is where "access to one file became access to forty" comes from. Organisation is by `category` and `tags`, which carry no permissions.

```
documents(id uuid, owner_id, title, category, tags[], current_version_id,
          created_at, deleted_at, purge_after)
document_versions(id uuid, document_id, version_no, blob_id, size, sha256,
                  mime_detected, original_filename, uploaded_by, created_at)
grants(id, document_id, grantee_id, level enum('read','edit'),
       granted_by, created_at, expires_at null, revoked_at null)
```

Effective access = owner, OR an active grant (`revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`), AND document not deleted, AND user active. `edit` implies `read`. Only the owner changes grants; editors cannot re-share.

### Where the decision is made

One function, `authz.require(db, user, document_id, action)`, called as a FastAPI dependency on every document route. It runs **one SQL query** that loads the document *through* the access predicate, so there is no "load, then check" gap:

```sql
SELECT d.* FROM documents d
WHERE d.id = :doc_id AND d.deleted_at IS NULL
  AND (d.owner_id = :uid OR EXISTS (
        SELECT 1 FROM grants g WHERE g.document_id = d.id AND g.grantee_id = :uid
          AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > now())
          AND g.level = ANY(:levels_satisfying_action)))
```

No row → **404**, whether the document doesn't exist or you weren't granted it (no existence oracle). The refusal is written to the audit log before the response.

List and search use the same predicate as a SQL `WHERE`, never a post-filter in Python, so counts and pagination can't leak.

Nested resources (`/documents/{doc}/versions/{ver}`) look up the version with `WHERE id = :ver AND document_id = :doc` after the document check — a valid document ID must not unlock another document's version.

### Defence in depth: Postgres RLS

Each request sets `SET LOCAL app.user_id = ...` in its transaction. RLS policies on `documents`, `document_versions`, `blobs` and `grants` enforce the same predicate. The app connects as `tv_app`, which is not the table owner and cannot bypass RLS.

Test consequence: if the judges delete an app-level check, RLS would still block access and the tests would still pass, which looks like the tests test nothing. So the suite runs **twice**: once with RLS on (system behaviour) and once with RLS disabled (`TV_TEST_RLS=off`), which proves the application layer alone holds. CI runs both.

## 4. Revocation — what "immediately" means

- Every request re-evaluates grants against the DB. Nothing caches permissions.
- No presigned URLs, no download tokens, no share links that outlive a grant. Every byte goes through the authz query.
- Deactivating a user deletes all their session rows in the same transaction.
- Downloads send `Cache-Control: no-store, private` so no browser or proxy serves a copy later.
- Cost: one indexed query per request, and no CDN offload of files. Accepted.
- Edge accepted: a download stream that has already started when a grant is revoked runs to completion (files ≤ 25 MB, seconds). Documented in THREATS.md.

## 5. File storage and upload validation

- Each file encrypted with AES-256-GCM using a per-file data key; the data key is wrapped with a master key from env (`TV_MASTER_KEY`). A DB dump alone does not yield documents.
- Original filename is metadata only, never a path. Blob IDs are UUIDs.
- Validation: size ≤ 25 MB (enforced while streaming, not after), extension allowlist (pdf, docx, xlsx, pptx, png, jpg, txt, csv), magic-byte sniff must match the extension, filename normalised (NFKC, strip control and bidi characters, length cap).
- Served with `Content-Disposition: attachment; filename*=UTF-8''…`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox`. Nothing uploaded is ever rendered inline on the app origin.
- SHA-256 stored per version so a download can be proven identical to what was uploaded.

## 6. Audit trail

`audit_log(id bigserial, at, actor_id, action, outcome('allowed','denied'), document_id, target_user_id, ip, user_agent, details jsonb, prev_hash, hash)`

Logged: login success/failure, upload, download, view metadata, edit, new version, delete, restore, purge, grant, revoke, ownership transfer, user create/deactivate, **every denial**, AI suggestion shown, AI suggestion accepted/rejected.

What stops quiet alteration:
1. **Privileges**: `tv_app` has `INSERT, SELECT` on `audit_log` only. `UPDATE, DELETE, TRUNCATE` revoked; a trigger raises on update/delete as a second layer. No API endpoint deletes or edits audit rows.
2. **Hash chain**: `hash = sha256(prev_hash || canonical_json(row))`. Inserts take a transaction-scoped advisory lock so the chain is linear. Editing or deleting any row breaks every hash after it.
3. **Anchoring**: every hour and on demand, the head hash and row count are HMAC-signed and written outside the DB (a second store / emitted to logs). Truncating the tail and recomputing the chain no longer matches the last anchor.
4. **Verification**: admin page "Verify chain" recomputes and reports the first broken row.
5. **Fail closed**: the audit insert is in the same transaction as the action. If audit fails, the download/grant does not happen.

Accepted: someone with the Postgres superuser password (the host provider, me) could rewrite rows and the chain; anchoring limits that to the window since the last anchor.

## 7. Admin view

- Activity feed with filters (actor, document, action, outcome, date).
- Permission changes timeline.
- Alerts ("worth noticing"): ≥ 10 denials by one user in 10 minutes; a user downloading > 20 documents in an hour; grants to > 10 people on one document; access within 5 minutes of a grant being revoked (attempted use after revocation); failed-login bursts; any ownership transfer; chain verification failure.
- Users: create, deactivate (kills sessions), reset password, transfer ownership of a leaver's documents.

## 8. AI access suggestions (optional, behind `TV_AI_ENABLED`)

On the share dialog, "Suggest people" sends **metadata only** (title, category, tags, and who the owner already shares that category with) to an LLM, which returns user IDs + reasons. The server intersects the result with real active users and shows them as unticked suggestions. The model has no tool or endpoint that writes grants; the owner clicks Grant, which goes through the normal grant endpoint. Both `ai_suggestion_shown` and the owner's decision are audited. Document content is never sent to the model.

## 9. Features — built vs. deliberately not built

**Built:** login/logout, upload (drag-and-drop), versions, rename/re-categorise, soft delete with 30-day trash + restore, purge, per-document read/edit grants with optional expiry, revoke, search (title, owner, category, tag, date range), document activity tab, admin dashboard, audit explorer, chain verification, user management, ownership transfer, AI suggestions.

**Not built, on purpose:**
- Folders / inheritance — the main source of over-sharing.
- Groups — membership changes silently widen access; would need its own audit and revocation semantics.
- External share links — a bearer link is access without identity; it undermines "prove who reached it". Would add later as invite-only guest accounts.
- Inline preview — rendering untrusted files on the app origin is an XSS vector; would add later on a separate sandboxed origin.
- Email-based password reset — admin reset only; no email infrastructure to secure.
- Malware scanning (ClamAV) — out of scope for a week; noted in THREATS.md.

## 10. API (who may call each endpoint)

| Method | Path | Allowed |
|---|---|---|
| POST | /api/auth/login | anyone (rate limited) |
| POST | /api/auth/logout | authenticated |
| GET | /api/auth/me | authenticated |
| GET | /api/documents | authenticated — returns only owned + granted |
| GET | /api/documents/categories | authenticated — categories of visible docs |
| POST | /api/documents | owner role |
| GET | /api/documents/{id} | owner of doc, read/edit grantee |
| PATCH | /api/documents/{id} | owner of doc, edit grantee |
| DELETE | /api/documents/{id} | owner of doc |
| POST | /api/documents/{id}/restore | owner of doc |
| DELETE | /api/documents/{id}/purge | owner of doc, only if already in trash |
| GET | /api/documents/{id}/versions | owner, read/edit grantee |
| POST | /api/documents/{id}/versions | owner, edit grantee |
| GET | /api/documents/{id}/versions/{vid}/download | owner, read/edit grantee (version must belong to doc) |
| GET | /api/documents/{id}/grants | owner of doc |
| POST | /api/documents/{id}/grants | owner of doc |
| DELETE | /api/documents/{id}/grants/{gid} | owner of doc |
| GET | /api/documents/{id}/activity | owner of doc |
| POST | /api/documents/{id}/suggestions | owner of doc |
| POST | /api/documents/{id}/suggestions/dismiss | owner of doc |
| GET | /api/users/lookup?q= | owner role (returns id + display name only, min 2 chars) |
| GET/POST/PATCH | /api/admin/users… | admin |
| GET | /api/admin/documents | admin (metadata only) |
| GET | /api/admin/stats | admin |
| POST | /api/admin/documents/{id}/transfer | admin |
| GET | /api/admin/audit, /api/admin/alerts | admin |
| POST | /api/admin/audit/verify | admin |

A test enumerates `app.routes` and fails if any route is missing from the authorization matrix, so a new endpoint can't ship untested.

## 11. Implementation notes (what changed from the first draft)

- **SQLAlchemy/Alembic were dropped for psycopg + SQL files.** The access predicate is one SQL string in `app/authz.py`. With an ORM, a convenience query could load a document by id without passing through it; here every document query is visibly written against `visible_clause()` or `require()`.
- **Refusals are audited without being rolled back.** `db.tx()` catches `Denied`, rolls back the request's transaction, then commits the `access_denied` row in a fresh transaction on the same connection. Using a second connection risked a deadlock on the chain lock and exhausting the pool.
- **The audit append is a SECURITY DEFINER function.** `tv_app` has no INSERT on `audit_log`, so the app cannot write a row with a forged `prev_hash`.
- **RLS policy helpers are SECURITY DEFINER.** `documents` and `grants` policies refer to each other, which recurses infinitely with plain subqueries. The helpers only answer yes/no about the current `app.user_id`.
- **Blobs have no DELETE privilege for the app.** A policy-based delete of "unreferenced" blobs cannot tell "unreferenced" from "referenced by a version I can't see". Garbage collection is a definer function.
- **The owner database URL never reaches the web process** (`app/boot.py`).
- **Demo mode** protects seed accounts and re-seeds on every boot, because reviewers share them.
