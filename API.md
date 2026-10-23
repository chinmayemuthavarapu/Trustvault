# TrustVault API

Base path `/api`. JSON in and out, except uploads (multipart) and downloads (file bytes).

## Conventions

- **Authentication:** session cookie set by `POST /api/auth/login`. It is `HttpOnly`, `SameSite=Strict`, and in production `Secure` with the `__Host-` prefix.
- **CSRF:** every `POST`, `PATCH` and `DELETE` (except login) must send `X-CSRF-Token`. The token is returned by login and `GET /api/auth/me`.
- **Errors:**
  - `401` not signed in.
  - `403` your *role* can't do this.
  - `404` no such document **or** you have no access. The two are deliberately identical.
  - `413` body too large.
  - `422` invalid input.
  - `429` rate limited.
- **Audit:** every call to a document route is recorded, allowed or refused. Refusals are recorded even though the response is a 404.

Who may call each endpoint, in terms of the document involved:

| Shorthand | Meaning |
|---|---|
| **owner** | the document's owner |
| **editor** | a live `edit` grant |
| **reader** | a live `read` grant |

A grant is *live* when it is not revoked and not expired. Documents in the trash are reachable only by their owner, and only through restore and purge. Admins get no implicit access to any document.

## Auth

| Method | Path | Who | Notes |
|---|---|---|---|
| POST | `/auth/login` | anyone | `{email, password}` → `{user, csrf_token}`. JSON only. 20/5 min per IP, 10/5 min per account, back-off after 5 failures |
| POST | `/auth/logout` | signed in | Deletes the session row |
| GET | `/auth/me` | signed in | `{user, csrf_token}` |

## Documents

| Method | Path | Who | Notes |
|---|---|---|---|
| GET | `/documents` | signed in | Only documents you own or have a live grant on. Query: `q, owner, category, tag, from, to` (dates), `scope=all\|mine\|shared\|trash`, `sort=updated_at\|created_at\|title\|category`, `order`, `page`, `page_size≤100`. `total` is scoped too |
| GET | `/documents/categories` | signed in | Categories of documents you can see |
| POST | `/documents` | role **owner** | Multipart: `file`, `title`, `category`, `tags` (comma-separated), `description`. ≤ 25 MB; pdf, docx, xlsx, pptx, png, jpg, txt, csv; content must match the extension. You become the owner |
| GET | `/documents/{id}` | owner, editor, reader | Metadata plus current version. Audited as `document_view` |
| PATCH | `/documents/{id}` | owner, editor | `{title?, category?, tags?, description?}`; any other field → 422 |
| DELETE | `/documents/{id}` | owner | Moves to the trash; grantees lose access at once. Purged automatically after 30 days |
| POST | `/documents/{id}/restore` | owner, document in trash | |
| DELETE | `/documents/{id}/purge` | owner, document in trash | Destroys every version. The audit record is kept |
| GET | `/documents/{id}/versions` | owner, editor, reader | |
| POST | `/documents/{id}/versions` | owner, editor | Multipart `file` |
| GET | `/documents/{id}/versions/{vid}/download` | owner, editor, reader | `vid` must belong to `id`. Response is `attachment`, `no-store`, `nosniff`, `CSP: sandbox`. Audited with version and SHA-256. 60 downloads / 10 min per user |

## Sharing

| Method | Path | Who | Notes |
|---|---|---|---|
| GET | `/documents/{id}/grants` | owner | Active, expired and revoked, with status |
| POST | `/documents/{id}/grants` | owner | `{grantee_id, level: read\|edit, expires_at?, via_suggestion?}`. Replaces any live grant for that person. Grantee must be active and not the owner. Expiry: future, ≤ 1 year |
| DELETE | `/documents/{id}/grants/{gid}` | owner | Effective on the grantee's next request. Returns `revoked` or `already_revoked` |
| GET | `/documents/{id}/activity` | owner | The document's custody record (last 200 audit entries, refusals included) |
| POST | `/documents/{id}/suggestions` | owner | Suggested people with reasons. Creates no access. Audited |
| POST | `/documents/{id}/suggestions/dismiss` | owner | `{user_ids: [...]}`. Audited |
| GET | `/users/lookup?q=` | role **owner** | ≥ 2 characters; ≤ 10 active people; id, name, email |

## Administration (role **admin**)

| Method | Path | Notes |
|---|---|---|
| GET | `/admin/users` | All accounts |
| POST | `/admin/users` | `{email, display_name, role, password≥12}` |
| PATCH | `/admin/users/{id}` | `{display_name?, role?, is_active?, password?}`. Deactivation, role change and password reset end all of that person's sessions. You cannot change your own role or deactivate yourself. In demo mode seed accounts are protected |
| GET | `/admin/documents` | Metadata only (title, owner, number of live grants). Admins have no route to content |
| POST | `/admin/documents/{id}/transfer` | `{new_owner_id}` (an active document owner) |
| GET | `/admin/audit` | Filters: `actor, action, outcome, document_id, from, to, category=all\|access\|permissions\|auth\|admin`, paging |
| POST | `/admin/audit/verify` | Recomputes the hash chain, checks signed checkpoints, then signs a new one |
| GET | `/admin/alerts` | Refusal bursts, attempts after revocation, bulk downloads, failed-login bursts, wide sharing, transfers, account changes, integrity failure |
| GET | `/admin/stats` | Totals and a 14-day series |

## Other

| Method | Path | Who |
|---|---|---|
| GET | `/health` | anyone (returns `{"status":"ok"}`, no data) |
| GET | `/openapi.json` | signed in |

`backend/tests/test_matrix.py` holds this table as code: every route against seven kinds of caller. The test `test_every_route_in_matrix` fails if a route is added without an entry.
