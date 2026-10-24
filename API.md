# TrustVault API

JSON over HTTPS, same origin as the web app. All routes are under `/api`.

**Authentication.** `POST /api/auth/login` sets an `HttpOnly`, `Secure`, `SameSite=Strict` session cookie and returns a `csrf_token`. Every request that is not `GET` must send that value in the `X-CSRF-Token` header (this includes `login` and `logout` while a session is live). Requests from another `Origin` are refused.

**Errors.** `{"error": "<message for a person>"}` with:
`400` invalid input · `401` not signed in · `403` signed in but not allowed (only when you can already see the document, or the route is role-restricted) · `404` not found **or not yours** (deliberately identical) · `409` conflict · `413` too large · `429` rate-limited or locked out.

**Who may call.** "Signed in" means any active account that is not waiting to change a temporary password. Document rules come from `app/authz.py`; the role column of the account never grants document access by itself.

| Document permission | view | download | edit details / new version | share (grants, suggestions, activity) | trash | restore / purge |
|---|---|---|---|---|---|---|
| Owner (live document) | ✓ | ✓ | ✓ | ✓ | ✓ | – |
| Owner (in trash) | ✓ | – | – | – | – | ✓ |
| Edit grant | ✓ | ✓ | ✓ | – | – | – |
| Read grant | ✓ | ✓ | – | – | – | – |
| Anyone else, including admins | – | – | – | – | – | – |

Grants with an `expires_at` in the past count as absent. Grants on a trashed document are suspended until it is restored.

---

## Auth

| Method & path | Who | Body | Notes |
|---|---|---|---|
| `POST /api/auth/login` | Anyone | `{username, password}` | Returns the user and `csrf_token`. Same error for unknown user, wrong password, disabled account. 8 failures per username or 30 per IP in 15 min → 429. |
| `POST /api/auth/logout` | Anyone | – | Deletes the session server-side. |
| `GET /api/auth/me` | Signed in (incl. must-change-password) | – | Current user and `csrf_token`. |
| `POST /api/auth/change-password` | Signed in (incl. must-change-password) | `{current_password, new_password}` | 12+ characters, not common, not containing the username. Ends all **other** sessions. |

## Documents

| Method & path | Who | Body / query | Notes |
|---|---|---|---|
| `GET /api/meta` | Signed in | – | Categories, upload limit, allowed extensions. |
| `GET /api/documents` | Signed in | `q`, `owner`, `category`, `from`, `to` (YYYY-MM-DD, upload date), `scope` (`all`/`mine`/`shared`), `sort` (`updated`/`created`/`title`), `page`, `page_size` (≤100) | Returns only documents you can view. `total` counts only those. |
| `GET /api/documents/trash` | Signed in | – | Your own trashed documents only. |
| `POST /api/documents` | Role **owner** | multipart: `file`, `title`, `category`, `description` | File type detected from content; see THREATS.md §D. You become the owner. Private until shared. |
| `GET /api/documents/{id}` | view | – | Metadata, `my_permission`, all versions. Audited (`document.view`). |
| `PATCH /api/documents/{id}` | edit | `{title?, category?, description?}` | Unknown fields → 400. |
| `POST /api/documents/{id}/versions` | edit | multipart: `file` | Adds version n+1; earlier versions kept. |
| `GET /api/documents/{id}/download[?version={versionId}]` | download | – | `application/octet-stream`, attachment, `no-store`, CSP sandbox. The version must belong to this document. Audited before the first byte. 40/min per user. |
| `DELETE /api/documents/{id}` | owner (live) | – | Moves to trash; grantees lose access until restored. |
| `POST /api/documents/{id}/restore` | owner (in trash) | – | Earlier grants apply again. |
| `POST /api/documents/{id}/purge` | owner (in trash) | – | Destroys every version's encrypted file and all grants. Audit history is kept. Also runs automatically 30 days after trashing. |

## Sharing

| Method & path | Who | Body | Notes |
|---|---|---|---|
| `GET /api/documents/{id}/grants` | owner | – | Everyone with access, level, expiry, who granted. |
| `POST /api/documents/{id}/grants` | owner | `{username, permission: "read"\|"edit", expires_at?: "YYYY-MM-DD", suggestion_id?}` | Creates or changes a grant (upsert). Target must be an active account other than the owner. Expiry date is inclusive and must be in the future. `suggestion_id` records that the owner accepted a suggestion. |
| `DELETE /api/documents/{id}/grants/{grantId}` | owner | – | Grant must belong to this document. Effective on the grantee's next request. |
| `GET /api/documents/{id}/suggestions` | owner | – | Up to 5 people, from the owner's own sharing history. **Read-only: never grants access.** First appearance of each suggestion is audited. |
| `POST /api/documents/{id}/suggestions/{sid}/dismiss` | owner | – | Not suggested again for this document. |
| `GET /api/documents/{id}/activity` | owner | – | Audit entries for this document (no IPs). |
| `GET /api/users/lookup?q=` | Role owner, or anyone who owns a document | – | ≥2 characters, ≤8 active people. |

## Administration (role **admin** only)

Administrators manage accounts and watch activity. They cannot open, download or share documents.

| Method & path | Body / query | Notes |
|---|---|---|
| `GET /api/admin/users` | – | All accounts with session and document counts. |
| `POST /api/admin/users` | `{username, display_name, role}` | Returns a one-time `temporary_password`; the person must change it at first sign-in. |
| `PATCH /api/admin/users/{userId}` | `{role?, active?, display_name?}` | Disabling or changing role ends all that person's sessions. Cannot change own role or disable self; one active admin must remain. |
| `POST /api/admin/users/{userId}/revoke-sessions` | – | Signs the person out everywhere now. |
| `GET /api/admin/audit` | `action` (prefix, e.g. `permission.`), `outcome` (`allowed`/`denied`/`error`), `actor`, `document` (title or id), `from`, `to`, `page`, `page_size` (≤200) | Full entries including `prev_hash` and `hash`. |
| `GET /api/admin/audit/verify` | – | Recomputes the HMAC chain. `{intact, checked, head_id, head_hash}` or `{intact: false, broken_at_id, problem}`. The verification itself is audited. |
| `GET /api/admin/alerts` | – | Repeated refusals, bulk downloads, login failures, password spraying, mass sharing, forged requests, integrity failures. |
| `GET /api/admin/summary` | – | 24-hour counts, hourly allowed/refused series, alerts. |

## Other

| Method & path | Who | Notes |
|---|---|---|
| `GET /` and `/static/*` | Anyone | The single-page app. |
| `GET /healthz` | Anyone | `{"ok": true}` for the platform health check. |

## Audit event names

`auth.login`, `auth.logout`, `auth.password_change` · `document.upload`, `document.view`, `document.download`, `document.update`, `document.new_version`, `document.delete`, `document.restore`, `document.purge`, `document.access` (unauthenticated), and `document.<action>` for refusals · `permission.grant`, `permission.change`, `permission.revoke` · `suggestion.shown`, `suggestion.dismissed` · `admin.user_create`, `admin.user_update`, `admin.sessions_revoked`, `admin.audit_verified` · `security.csrf_rejected`, `security.origin_rejected`, `security.role_denied`.
