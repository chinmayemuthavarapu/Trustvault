# THREATS.md

How TrustVault could be broken, what stops each attack, and what I knowingly left open.

**Status key.** **Closed**: the attack does not work, and a test proves it. **Mitigated**: harder, detected, or limited, but not impossible. **Accepted**: I know about it and chose not to fix it, with the reason.

**How to check my claims.** Every Closed entry names the test that proves it. `python scripts/mutation_check.py` deletes each security check in turn (every `authz.require()` call, every rule inside `authz.decide()`, CSRF, session, audit, storage and upload checks) and runs the suite. A check whose removal leaves the tests green is a hole in the tests; the latest result is at the end of this file.

**Where the decision is made.** Every route that names a document calls `authz.require(user, doc_id, action)` before it touches anything else. That function (in `app/authz.py`) is the only place that decides document access. Role never grants document access: an administrator gets nothing on a document unless its owner shares it.

---

## A. Reaching a document you were not given

| ID | Attack | What stops it | Status | Proof |
|---|---|---|---|---|
| T01 | **IDOR.** Take a document id (from a shared link, a colleague's screen, the audit log, or by guessing) and call any route with it: view, download, edit, new version, delete, restore, purge, list grants, add a grant, suggestions, activity. | Every route calls `authz.require()` first. No grant row for (document, you) means refused, whatever the route. Ids are random 128-bit values, so guessing is also hopeless, but nothing depends on that. | Closed | `test_access_control.StrangerCannotReachDocument` (one test per route, as another owner, a viewer and an admin) |
| T02 | **Search and listing leak.** Search for a title, filter by another owner, page through results, read `total`, to learn what exists. | Listing filters in SQL with `ACCESSIBLE_SQL`, the same rules as `decide()`. `total` counts only what you can open. A test compares the SQL rule against `decide()` for every user and every document, so the two cannot drift apart. | Closed | `test_search_matrix` (whole matrix, owner filter, title search, count) |
| T03 | **Read grant used to write.** Someone with view access edits details, uploads a version, deletes, or opens the sharing panel. | Grant levels map to fixed action sets: read = view + download; edit = + edit. | Closed | `GrantLevels.test_read_grant_can_view_and_download_only` |
| T04 | **Edit grant used to share or delete.** An editor grants themselves or a friend access, or deletes the document. | Only the owner can SHARE or DELETE. Editors are refused with 403. | Closed | `GrantLevels.test_edit_grant_can_edit_but_not_share_or_delete` |
| T09 | **Version id from another document.** I can read document A. I pass `?version=<id of a version of B>` to A's download route, hoping the check is on A and the file comes from B. | The version lookup is `WHERE id = ? AND document_id = ?` against the document that was just authorised. | Closed | `GrantIntegrity.test_cannot_download_other_documents_version_via_granted_doc` |
| T10 | **Grant id from another document.** As owner of my document, call `DELETE /api/documents/<mine>/grants/<grant on someone else's document>`. | The grant must belong to the authorised document. Refusal is audited. | Closed | `GrantIntegrity.test_cannot_revoke_grant_of_another_document_via_own_doc` |
| T11 | **Suggestion id replay.** Use a suggestion made for document A to justify a grant on document C. | A suggestion is accepted only for its own document, its own person, and only while still `shown`. | Closed | `GrantIntegrity.test_suggestion_from_other_document_cannot_be_used` |
| T12 | **Administrator reads documents.** An admin, or an attacker with an admin account, opens or shares a document. | `decide()` never looks at role. Admins see metadata and the audit trail, not contents. | Closed | `AdminHasNoDocumentAccess` |
| T13 | **Role bypass.** A viewer uploads; a non-admin calls `/api/admin/*`; a viewer scrapes the people directory. | `login_required(roles)` on each route. The people lookup is for document owners only. | Closed | `Roles.*` |
| T14 | **Mass assignment.** Send `owner_id`, `granted_by`, `role` or `password_hash` in a request body or upload form. | Every body is checked against an allowlist of fields; unknown fields are rejected with 400, not ignored. | Closed | `Hardening.test_mass_assignment_rejected`, `AdminSafety.test_user_patch_rejects_unknown_fields`, `UploadValidation.test_unknown_form_fields_rejected` |
| T23 | **Existence oracle.** Tell "exists but not yours" from "does not exist" by status code or message. | Both return the identical 404. 403 is used only when you can already see the document. Malformed ids also get 404. | Closed | `Enumeration.*` |
| T25 | **No session at all.** Call any route without a cookie, or with a forged one. | 401 everywhere. Anonymous attempts on document routes are audited. | Closed | `Unauthenticated.*` |
| T26 | **SQL injection / wildcard abuse** in search, owner filter, sort and paging. | Parameterised SQL only. `%` and `_` are escaped so they match literally. `sort` is a fixed allowlist. Paging is clamped. | Closed | `SearchMatrix.test_wildcards_and_injection_are_literal` |
| T07 | **Trash as a side door.** The owner moves a document to the trash; a grantee keeps opening it. | A trashed document is unreachable for everyone except its owner, who can only view, restore or purge it, and cannot download from the trash. | Closed | `TrashAndPurge.test_trashed_document_unreachable_by_grantee_until_restored` |
| T08 | **Purge leaves something behind.** After permanent deletion, the metadata, grants or encrypted file are still reachable. | Purge deletes the blobs and the grants and marks the row purged; `decide()` treats purged as non-existent. The audit history stays, by design. | Closed | `TrashAndPurge.test_purge_destroys_content_and_grants` |
| T22 | **Path traversal** through the static file route or a crafted file name. | Static files are served with Werkzeug's `safe_join`. Stored files are named by random hex from the server; the user's file name is display-only and never part of a path. | Closed | `Hardening.test_static_path_traversal`, `UploadValidation.test_filename_is_cleaned` |
| T28 | **Granting to the wrong target.** Grant to yourself as owner, to a disabled account, to a non-existent user, or with an invented permission like `owner`. | All refused with 400. | Closed | `GrantIntegrity.test_grant_to_unknown_inactive_or_owner` |

## B. Taking access away

"Immediately" in TrustVault means: **the next request after the change is refused.** Nothing that grants access is ever cached or handed out. There are no signed URLs, no bearer download links and no access tokens with a lifetime. The browser holds one opaque session cookie; every request looks up the session row, the user row (active?) and the grant row (exists? expired?) in the database. The cost is a few indexed SQLite lookups per request, which I chose over any token that would outlive a revocation.

| ID | Attack | What stops it | Status | Proof |
|---|---|---|---|---|
| T05 | **Keep using access after it is revoked**, from a tab that is already signed in. | Grant lookup on every request. Revocation is a row delete. | Closed | `Revocation.test_revoke_is_immediate_for_existing_session` |
| T05b | **Downgrade not applied.** Edit is reduced to read but the person keeps editing. | Same: permission read on every request. | Closed | `Revocation.test_downgrade_edit_to_read_is_immediate` |
| T06 | **Expired grant still works.** | Expiry is checked in the SQL of every decision and every listing. No background job to forget. | Closed | `Revocation.test_expired_grant_is_refused` |
| T15 | **Disabled employee keeps their session**, or someone who left the company still has a browser signed in. | Disabling deletes all their sessions in the same transaction, and every request re-checks `users.active` as well, so even a surviving session row is refused. Role changes also end sessions. | Closed | `Revocation.test_disabling_user_kills_their_session_now`, `SessionLifecycle.test_inactive_user_session_refused_even_if_row_survives`, `SessionLifecycle.test_role_change_ends_sessions` |
| T15b | **Stolen session after password change.** | Changing password ends every other session for that account. | Closed | `SessionLifecycle.test_password_change_ends_other_sessions` |
| T15c | **Replay a cookie after logout.** | Logout deletes the session row server-side; the old cookie value is now worthless. | Closed | `SessionLifecycle.test_logout_invalidates_the_token_server_side` |
| T15d | **Previous person's session on a shared computer** survives the next sign-in. | Signing in on a browser deletes the session that browser already held. | Closed | `SessionLifecycle.test_signing_in_as_someone_else_ends_the_previous_session` |
| T40 | **A download already in flight** when access is revoked. | The authorisation decision is made at the start of the request. A download that has already started finishes (files are at most 20 MB, so this is under a second). | Accepted | The window is one HTTP response. |
| T41 | **Copies already downloaded.** Revocation cannot reach a file on someone's laptop. | Nothing in a web app can. The audit trail records exactly which version (with its SHA-256) each person took, which is what you need afterwards. | Accepted | Watermarking per downloader is listed under future work. |
| T42 | **Write that races a revocation.** `require()` runs, then the write transaction starts; a revocation committed in between is not seen by that one request. | The window is milliseconds and only affects one request. | Accepted | Fix would be to re-check inside the write transaction. |
| T43 | **Restoring a document restores its old grants.** An owner trashes a document to "unshare" it, then restores it and is surprised that people can open it again. | Intentional: trash is undo, not a sharing tool. The UI says so when restoring and the restore is audited. | Accepted (design) | |

## C. Sessions, sign-in and forged requests

| ID | Attack | What stops it | Status | Proof |
|---|---|---|---|---|
| T16 | **CSRF.** A malicious page makes the signed-in browser grant access, delete, or revoke. | Session cookie is `SameSite=Strict`. In addition, every state-changing request needs a per-session CSRF token in a header (a cross-site form cannot set headers), and a mismatched `Origin` is refused. Refusals are audited. | Closed | `Csrf.*` |
| T16b | **Login CSRF / session swap** while a session is live. | The login endpoint also requires the live session's CSRF token. | Closed | `SessionLifecycle.test_signing_in_as_someone_else_ends_the_previous_session` |
| T17 | **Password guessing** against one account. | 8 failures in 15 minutes locks that username (the lock applies to the username string, so it does not reveal whether the account exists). Lockout state is in the database, so it survives restarts. | Closed | `BruteForce.test_lockout_after_repeated_failures` |
| T17b | **Password spraying** (one password, many usernames, one address). | 30 failures per IP per 15 minutes; the admin overview flags three or more usernames tried from one address. | Mitigated | Behind a proxy this needs `TV_TRUSTED_PROXIES` set correctly (see T35). |
| T17c | **Username enumeration** by error message or timing. | Same message and status for unknown user, wrong password and disabled account. Unknown users still run a full scrypt comparison against a dummy hash. | Closed | `BruteForce.test_same_error_for_unknown_user_and_wrong_password` |
| T18 | **Lockout as a weapon.** Someone deliberately fails 8 times to lock a colleague out for 15 minutes. | It is time-limited and visible in the admin overview. | Accepted | The trade-off against brute force. A CAPTCHA or per-device trust would fix it. |
| T19 | **Session theft by XSS.** | The cookie is `HttpOnly`. The UI never uses `innerHTML` with data (all text goes through `textContent`), and the CSP forbids inline script and third-party origins (`script-src 'self'`). | Closed | `Hardening.test_security_headers`; code review of `static/app.js` |
| T20 | **Session fixation.** Plant a token in the victim's browser before they sign in. | Sign-in always issues a new random token. Only SHA-256 of tokens is stored, so a database leak gives no usable sessions. | Closed | `SessionLifecycle.test_login_rotates_token`, `test_token_stored_hashed` |
| T20b | **Cookie tossing.** A page on a sibling subdomain sets a `tv_session` cookie for the parent domain to fix or shadow the real one. | Over HTTPS the cookie is named `__Host-tv_session`; browsers only accept that name when it is `Secure`, `Path=/` and has no `Domain`, so no other host can set it. | Closed | `SessionLifecycle.test_https_cookie_is_host_prefixed_and_secure` |
| T21 | **Idle or abandoned sessions.** | 30-minute idle timeout and 8-hour absolute lifetime, checked server-side. | Closed | `SessionLifecycle.test_expired_session_refused` |
| T27 | **Temporary password left in use.** Admin-created accounts are used without ever setting a real password. | Accounts flagged `must_change_password` can do nothing except change it. Password policy: 12+ characters, not common, not containing the username. | Closed | `PasswordRules.*` |
| T29 | **Admin locks everyone out**: disables or demotes themselves, or the last administrator. | Refused. | Closed | `AdminSafety.test_cannot_disable_or_demote_self` |
| T30 | **Clickjacking**: the UI framed on another site to trick a click on "Give access". | `frame-ancestors 'none'` and `X-Frame-Options: DENY`. | Closed | `Hardening.test_security_headers` |
| T31 | **CORS abuse.** Another origin reads API responses with the user's cookie. | No CORS headers are ever sent, so browsers refuse cross-origin reads. | Closed | `Hardening.test_security_headers` |
| T44 | **No account recovery.** A user who forgets their password has to ask an administrator for a new account. | I did not build admin password resets on purpose: an admin who can set a user's password can sign in as them and read their documents, which would break T12. | Accepted (design) | The right fix is a reset link sent to the user's verified email, so the admin never knows the secret. |
| T45 | **No MFA.** A phished password is enough to sign in. | Not built. Lockout, alerting and short sessions limit the damage. | Accepted | First thing to add with more time (TOTP or WebAuthn). |

## D. What gets uploaded and how it comes back

| ID | Attack | What stops it | Status | Proof |
|---|---|---|---|---|
| T32 | **Stored XSS through an uploaded file.** Upload `report.html` or `logo.svg` and get a colleague to open it on the TrustVault origin, where it can act as them. | HTML, SVG and script types are not accepted at all. Every download is `application/octet-stream`, `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox`, so nothing is ever rendered on our origin even if a file slipped through. | Closed | `UploadValidation.test_rejects_disallowed_extensions`, `SafeDownloads.test_download_cannot_render_in_browser` |
| T33 | **Type spoofing.** An executable renamed `invoice.pdf`, a PDF renamed `.docx`. | The type is decided from the file's bytes (magic numbers, OOXML structure) and must agree with the extension. The client's `Content-Type` is ignored. | Closed | `UploadValidation.test_rejects_content_that_does_not_match_extension` |
| T34 | **Active content in "safe" formats**: PDF with JavaScript or launch actions, Word files with macros or ActiveX. | PDFs containing `/JavaScript`, `/JS`, `/Launch`, `/OpenAction`, `/AA`, `/EmbeddedFile`, `/RichMedia` or `/XFA` are refused. OOXML containing `vbaProject.bin` or ActiveX parts is refused; macro-enabled extensions (`.docm`) are not on the list. | Mitigated | `UploadValidation.test_rejects_active_pdf`, `test_rejects_macros`. A byte search can be evaded with compressed object streams; real assurance needs a sandboxed parser or AV scan (not built). |
| T36 | **Zip bomb** inside an Office file. | Limits on entry count, total uncompressed size (200 MB) and compression ratio (100:1). Path-traversal entry names are refused. | Closed | `UploadValidation.test_rejects_zip_bomb` |
| T37 | **Header injection or spoofing through the file name**: CR/LF, path separators, right-to-left override (`invoice‮fdp.exe`). | Control and bidi characters are stripped, paths are cut to the base name, and the download header uses an ASCII fallback plus RFC 5987 encoding. | Closed | `UploadValidation.test_filename_is_cleaned`, `test_clean_filename_strips_header_injection` |
| T38 | **Oversized uploads** to fill the disk or memory. | 20 MB limit enforced by Flask before the body is read into the app. | Mitigated | Total storage per user is not capped (see T52). |
| T39 | **Browser or proxy cache** keeps a copy that outlives revocation or sign-out. | `Cache-Control: no-store, private` on every API response and download. | Closed | `SafeDownloads.test_download_cannot_render_in_browser`, `Hardening.test_security_headers` |
| T46 | **Malicious new version** from an editor (replaces a contract with a doctored one). | Editors are trusted to change content by definition. Every version is kept and downloadable, and each upload is audited with its SHA-256. | Accepted (design) | |

## E. Files at rest

| ID | Attack | What stops it | Status | Proof |
|---|---|---|---|---|
| T47 | **Stolen disk or backup** of the blob directory. | Every file version is encrypted with AES-256-GCM under its own random key; that key is itself encrypted with the master key, which lives only in the `TV_MASTER_KEY` environment variable, never on the data volume. | Closed | `EncryptedStorage.test_files_on_disk_are_ciphertext` |
| T48 | **Tampered file on disk.** Someone edits ciphertext to corrupt or alter a document. | GCM authentication fails and the file is not served at all (500, never partial data). The failure is audited and raised as an admin alert. | Closed | `EncryptedStorage.test_tampered_blob_is_not_served` |
| T49 | **Blob swap.** Someone with write access to the volume or database copies a secret file (and even its wrapped key) over a file they are allowed to read. | Both encryption layers bind the document id and version id as associated data, so a blob moved to another document will not decrypt. | Closed | `test_swapped_blob_fails`, `test_moving_ciphertext_and_wrapped_key_between_documents_fails` |
| T50 | **Metadata at rest.** Titles, descriptions, file names and the audit log are plaintext in SQLite. A database copy reveals what documents exist and who shared what. | Accepted for this scope. Contents are what is protected. | Accepted | Field-level encryption of titles would break search. |
| T51 | **Someone with the server's environment** (master key + data volume) reads everything. | Nothing in-app can stop the operator of the host. | Accepted | Production answer: master key in a KMS/HSM, so decrypting requires an audited KMS call. |

## F. The audit trail

The brief asks: what stops the audit trail being quietly altered? Four layers, each catching what the one before cannot.

1. **The application can only add.** There is no code path that updates or deletes audit rows, and SQLite triggers (`audit_no_update`, `audit_no_delete`) abort any `UPDATE` or `DELETE` on `audit_log`, so even an SQL injection could not rewrite history.
2. **Edits are detectable.** Each row stores `hash = HMAC-SHA256(TV_AUDIT_KEY, prev_hash || row)`, including its sequence number. Change, delete or reorder a row and verification fails at that row. The key is not in the database, so someone holding the database file cannot recompute a valid chain.
3. **Truncation is detectable.** Cutting rows off the end leaves a valid but shorter chain. So every row is also written as a JSON line to stdout (`TV_AUDIT_STDOUT=1`), which the host keeps in its own log store, out of reach of the database; and "Verify" reports the head hash and entry count for the administrator to record elsewhere. A head that moved backwards is evidence of truncation.
4. **Audit before effect.** For data changes, the audit row is written in the same transaction as the change: both happen or neither does. For downloads, the audit row is committed before the first byte is sent; if the audit write fails, the file is not served.

| ID | Attack | What stops it | Status | Proof |
|---|---|---|---|---|
| T53 | **Edit or delete audit rows through the app or SQL.** | Triggers. | Closed | `AuditTrail.test_update_and_delete_blocked_by_database` |
| T54 | **Drop the triggers and edit a row** (file-level access to the database). | HMAC chain breaks at the edited row. | Closed (detected) | `test_edit_with_triggers_dropped_is_detected`, `test_deleting_a_middle_row_is_detected` |
| T55 | **Edit and re-hash the whole chain** without the audit key. | Verification uses the real key; a guessed key produces a chain that does not verify. | Closed (detected) | `test_rehashing_without_the_key_is_detected` |
| T56 | **Truncate the tail.** | Off-database copy in the platform log + recorded head hash. | Mitigated | Depends on the operator recording the head or keeping platform logs; automatic anchoring to WORM storage (e.g. S3 Object Lock) is future work. |
| T57 | **Attacker with BOTH the database and `TV_AUDIT_KEY`** rewrites history and re-hashes. | Only the off-database stdout copy would disagree. | Accepted | Same boundary as T51. |
| T58 | **Refused attempts not recorded**, so probing leaves no trace. | Every refusal from `require()` (with the reason and the requested id), every failed sign-in, CSRF/origin rejection, role refusal, upload rejection and anonymous document request is recorded. | Closed | `StrangerCannotReachDocument.test_refusals_are_audited`, `Csrf.test_state_change_without_token_refused` |
| T59 | **Log injection**: a crafted username or file name forges a fake line in the audit view or platform log. | Details are stored as JSON; stdout lines are JSON-encoded; the admin UI renders with `textContent`. | Closed | Code review; `UploadValidation.test_filename_is_cleaned` |
| T60 | **Flooding the audit log** with refused requests to bury something or fill the disk. | Rate limits (240 requests/min per user or IP, 40 downloads/min). Floods themselves raise the "probing" alert. | Mitigated | No audit retention policy yet; the log grows forever by design (it is evidence). |
| T61 | **Spoofed IP in the audit trail** via `X-Forwarded-For`. | Forwarded headers are only trusted for the configured number of proxy hops (`TV_TRUSTED_PROXIES`). | Mitigated | Must be set to match the real deployment (see T35). |

## G. AI-assisted sharing

| ID | Risk | What stops it | Status | Proof |
|---|---|---|---|---|
| T62 | **The assistant widens access on its own.** | The suggestions endpoint is read-only. A suggestion becomes access only when the owner presses Add and confirms, which calls the ordinary grant endpoint. The suggestion (with its reason) and the owner's decision are recorded together in the grant's audit entry. | Closed | `Suggestions.test_suggestion_never_grants_and_acceptance_is_recorded` |
| T63 | **Suggestions leak information.** A suggestion reveals who has access to other documents. | Suggestions are computed only from the requesting owner's own documents and shown only to that owner. | Closed | Code: `routes_documents.suggestions` (`WHERE d.owner_id = :owner`) |
| T64 | **A plausible but wrong suggestion gets rubber-stamped.** (In the seed data, Victor is suggested for "Salary bands 2026" because he can see other HR documents. He must not.) | The confirmation dialog states exactly what the person will be able to do; dismissed suggestions are not repeated. | Accepted | This is the human-in-the-loop risk the brief describes; the audit makes it attributable. |
| T65 | **Sending confidential metadata to a third-party model.** | The recommender is deliberately a local rule over the owner's own sharing history. No document data leaves the server. | Closed (design) | |

## H. Platform and operations

| ID | Risk | What stops it | Status |
|---|---|---|---|
| T35 | **Misconfigured proxy trust.** With `TV_TRUSTED_PROXIES` too low, every user shares the proxy's IP (rate limits hit everyone, audit IPs are useless); too high, clients can forge their IP. | Documented in DEPLOY section of README; set to 1 in `render.yaml` and `fly.toml`. | Mitigated |
| T66 | **Missing keys in production** silently falling back to defaults. | With `TV_ENV=production` the app refuses to start without both keys, refuses identical keys, and refuses insecure cookies. | Closed |
| T67 | **Error messages leak internals.** | Generic JSON errors; stack traces only in server logs. | Closed (`Hardening.test_errors_do_not_leak_internals`) |
| T68 | **Supply chain.** | Three Python dependencies (Flask, cryptography, gunicorn); the frontend has zero dependencies and no build step. | Mitigated: versions are range-pinned, not hash-pinned. |
| T69 | **Single instance.** One process, SQLite on one volume: no horizontal scaling; the in-memory rate limiter resets on restart. | Chosen for a single-tenant demo. Every auth decision reads the database, so moving to Postgres + Redis changes no security logic. | Accepted |
| T70 | **Directory scraping by owners.** The people picker reveals usernames and names of active colleagues. | Owners only, 2+ characters, 8 results, rate-limited. | Accepted (a company directory is not secret here) |
| T71 | **Display-name impersonation.** Two accounts both called "Olivia Park". | Usernames are unique and restricted to `[a-z0-9._-]`; the UI shows `@username` next to every name in sharing. | Mitigated |
| T52 | **Storage exhaustion** by a legitimate owner uploading many large files. | Per-file size limit and request rate limit only. | Accepted |
| T72 | **Disabled owner's documents.** If an owner leaves, nobody can manage sharing on their documents (existing grants keep working). | Ownership transfer not built: an admin who can transfer ownership to themselves could read anything (breaks T12). Would need two-person approval. | Accepted |
| T73 | **Audit volume of metadata to admins.** Admins see document titles and who accessed them, though not contents. | Deliberate: that is the oversight role. | Accepted (design) |

---

## Mutation check result

Last full run of `python scripts/mutation_check.py` on commit `7074d93`, 2026-10-24 (each line removes one check and runs all tests). Earlier runs found five checks the tests did not cover; see PROMPTS.md entry 2.

```
OK  authz: grant expiry ignored                             CAUGHT  by test_access_control.Revocation.test_expired_grant_is_refused
OK  authz: grantee can reach trashed documents              CAUGHT  by test_access_control.TrashAndPurge.test_trashed_document_unreachable_by_grantee_until_restored
OK  authz: owner state check ignored                        CAUGHT  by test_access_control.TrashAndPurge.test_purge_destroys_content_and_grants
OK  authz: grant level ignored                              CAUGHT  by test_access_control.GrantLevels.test_edit_grant_can_edit_but_not_share_or_delete
OK  authz: read grant allows edit                           CAUGHT  by test_access_control.GrantLevels.test_read_grant_can_view_and_download_only
OK  authz: edit grant allows share                          CAUGHT  by test_access_control.GrantLevels.test_edit_grant_can_edit_but_not_share_or_delete
OK  authz: no grant row treated as read                     CAUGHT  by test_access_control.AdminHasNoDocumentAccess.test_admin_cannot_read_change_or_share
OK  authz: purged documents reachable                       CAUGHT  by test_access_control.TrashAndPurge.test_purge_destroys_content_and_grants
OK  list: expiry ignored in listing SQL                     CAUGHT  by test_access_control.Revocation.test_expired_grant_is_refused
OK  list: trashed shared docs listed                        CAUGHT  by test_search_matrix.SearchMatrix.test_accessible_sql_alone_matches_authz
OK  list: access filter removed                             CAUGHT  by test_access_control.AdminHasNoDocumentAccess.test_admin_cannot_read_change_or_share
OK  trash: other owners' trash listed                       CAUGHT  by test_access_control.TrashAndPurge.test_trashed_document_unreachable_by_grantee_until_restored
OK  download: version not tied to document                  CAUGHT  by test_access_control.GrantIntegrity.test_cannot_download_other_documents_version_via_granted_doc
OK  revoke: grant not tied to document                      CAUGHT  by test_access_control.GrantIntegrity.test_cannot_revoke_grant_of_another_document_via_own_doc
OK  grant: suggestion not tied to document                  CAUGHT  by test_access_control.GrantIntegrity.test_suggestion_from_other_document_cannot_be_used
OK  grant: owner can grant to self/inactive                 CAUGHT  by test_access_control.GrantIntegrity.test_grant_to_unknown_inactive_or_owner
OK  roles: viewer can upload                                CAUGHT  by test_access_control.Roles.test_viewer_cannot_upload
OK  roles: role check in decorator removed                  CAUGHT  by test_access_control.Roles.test_non_admins_cannot_use_admin_api
OK  roles: anyone can look up people                        CAUGHT  by test_access_control.Roles.test_viewer_cannot_look_up_directory
OK  session: disabled user keeps session                    CAUGHT  by test_sessions.SessionLifecycle.test_inactive_user_session_refused_even_if_row_survives
OK  session: idle timeout ignored                           CAUGHT  by test_sessions.SessionLifecycle.test_expired_session_refused
OK  session: logout does not delete server-side             CAUGHT  by test_sessions.SessionLifecycle.test_logout_invalidates_the_token_server_side
OK  session: password change keeps other sessions           CAUGHT  by test_sessions.SessionLifecycle.test_password_change_ends_other_sessions
OK  session: disabling user keeps sessions                  CAUGHT  by test_sessions.SessionLifecycle.test_role_change_ends_sessions
OK  session: must-change-password not enforced              CAUGHT  by test_sessions.PasswordRules.test_must_change_password_gates_everything
OK  session: login does not rotate token                    CAUGHT  by test_sessions.SessionLifecycle.test_signing_in_as_someone_else_ends_the_previous_session
OK  session: cookie not __Host- prefixed over HTTPS         CAUGHT  by test_sessions.SessionLifecycle.test_https_cookie_is_host_prefixed_and_secure
OK  csrf: token check removed                               CAUGHT  by test_sessions.Csrf.test_grant_via_csrf_refused
OK  csrf: origin check removed                              CAUGHT  by test_sessions.Csrf.test_cross_origin_refused
OK  login: lockout removed                                  CAUGHT  by test_sessions.BruteForce.test_lockout_after_repeated_failures
OK  admin: can disable/demote self                          CAUGHT  by test_sessions.AdminSafety.test_cannot_disable_or_demote_self
OK  audit: download not recorded                            CAUGHT  by test_audit.AuditTrail.test_edit_with_triggers_dropped_is_detected
OK  audit: refusals not recorded                            CAUGHT  by test_access_control.StrangerCannotReachDocument.test_refusals_are_audited
OK  audit: verify skips hash check                          CAUGHT  by test_audit.AuditTrail.test_edit_with_triggers_dropped_is_detected
OK  audit: append-only triggers removed                     CAUGHT  by test_audit.AuditTrail.test_update_and_delete_blocked_by_database
OK  storage: document binding (AAD) removed                 CAUGHT  by test_uploads_and_storage.EncryptedStorage.test_moving_ciphertext_and_wrapped_key_between_documents_fails
OK  upload: PDF active-content check removed                CAUGHT  by test_uploads_and_storage.UploadValidation.test_rejects_active_pdf
OK  upload: magic-byte check removed                        CAUGHT  by test_uploads_and_storage.UploadValidation.test_rejects_content_that_does_not_match_extension
OK  upload: extension allowlist removed                     CAUGHT  by test_uploads_and_storage.UploadValidation.test_rejects_disallowed_extensions
OK  upload: filename not cleaned                            CAUGHT  by test_uploads_and_storage.UploadValidation.test_clean_filename_strips_header_injection
OK  download: served inline                                 CAUGHT  by test_uploads_and_storage.SafeDownloads.test_download_cannot_render_in_browser
OK  search: LIKE wildcards not escaped                      CAUGHT  by test_search_matrix.SearchMatrix.test_wildcards_and_injection_are_literal
OK  route get_document: authz.require() removed             CAUGHT  by test_access_control.AdminHasNoDocumentAccess.test_other_owner_role_gives_nothing
OK  route update_document: authz.require() removed          CAUGHT  by test_access_control.GrantLevels.test_read_grant_can_view_and_download_only
OK  route upload_version: authz.require() removed           CAUGHT  by test_access_control.GrantLevels.test_read_grant_can_view_and_download_only
OK  route download: authz.require() removed                 CAUGHT  by test_access_control.AdminHasNoDocumentAccess.test_admin_cannot_read_change_or_share
OK  route delete_document: authz.require() removed          CAUGHT  by test_access_control.GrantLevels.test_edit_grant_can_edit_but_not_share_or_delete
OK  route restore_document: authz.require() removed         CAUGHT  by test_access_control.StrangerCannotReachDocument.test_restore_and_purge
OK  route purge_document: authz.require() removed           CAUGHT  by test_access_control.StrangerCannotReachDocument.test_restore_and_purge
OK  route list_grants: authz.require() removed              CAUGHT  by test_access_control.GrantLevels.test_edit_grant_can_edit_but_not_share_or_delete
OK  route add_grant: authz.require() removed                CAUGHT  by test_access_control.AdminHasNoDocumentAccess.test_admin_cannot_read_change_or_share
OK  route revoke_grant: authz.require() removed             CAUGHT  by test_access_control.StrangerCannotReachDocument.test_grantee_cannot_revoke_others
OK  route suggestions: authz.require() removed              CAUGHT  by test_access_control.StrangerCannotReachDocument.test_suggestions_and_activity
OK  route dismiss_suggestion: authz.require() removed       CAUGHT  by test_access_control.StrangerCannotReachDocument.test_dismiss_someone_elses_suggestion
OK  route document_activity: authz.require() removed        CAUGHT  by test_access_control.StrangerCannotReachDocument.test_suggestions_and_activity

55/55 mutations caught by the tests.
```
