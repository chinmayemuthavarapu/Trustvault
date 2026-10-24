# Standing context for AI tools working on TrustVault

Paste this (or reference the file) at the start of every session.

## What this is
TrustVault: a document-sharing service judged on whether the wrong person can reach a document.
Stack: Flask + SQLite (stdlib `sqlite3`, raw parameterised SQL), `cryptography` (AES-GCM), vanilla JS
frontend with no build step. One process (gunicorn, 1 worker, threads).

## Non-negotiables
1. The server decides every time. Every route that names a document calls
   `authz.require(g.user, doc_id, Action.X)` as its FIRST data access. No exceptions, no "the UI hides it".
2. Role grants nothing on documents. Admins have no implicit access.
3. Any id that arrives alongside a document id (version, grant, suggestion) must be looked up
   `WHERE id = ? AND document_id = <the authorised document>`.
4. Revocation is immediate: never cache a permission, never issue a token or URL that grants access
   on its own. Sessions are server-side rows checked on every request.
5. Every refusal is audited. Every data change writes its audit row in the SAME transaction.
   Downloads are audited before the first byte is sent.
6. The audit log is append-only (DB triggers) and HMAC-chained. Never add code that UPDATEs or DELETEs it.
7. Unknown request fields are rejected (400), not ignored.

## Rules for generated code
- No `innerHTML`, `outerHTML`, `insertAdjacentHTML` or inline event handlers in the frontend. Use `h()` / `put()`.
- No new dependency (Python or JS) without asking me first.
- No SQL built from user input; ORDER BY only from a fixed allowlist.
- Every new route needs: a stranger test, a wrong-permission test, and an entry in API.md.
- Every new security check needs a line in scripts/mutation_check.py, and that mutation must be CAUGHT.
- If you are unsure whether something is safe, say so instead of guessing.
