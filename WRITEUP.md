# TrustVault: write-up

## What I built

A document-sharing service for one company, with three roles (administrator, document owner, viewer):

- upload with content-based validation, categories, descriptions, full version history;
- per-document sharing with named people at two levels (view, edit), optional expiry dates, immediate revocation;
- search by name, owner, category and upload date, returning only what you can open;
- trash with restore, permanent purge, and automatic purge after 30 days;
- files encrypted at rest with a per-file key, bound to their document so they cannot be swapped;
- an append-only, HMAC-chained audit trail of every view, download, upload, change, deletion, permission change and **refusal**, with in-app verification;
- an admin view: 24-hour activity, refusals, alerts for probing, bulk downloads, password guessing and spraying, mass sharing, forged requests and integrity failures; account management;
- a per-document record for owners ("who opened my document?");
- sharing suggestions for owners that never change access on their own;
- 106 security tests, and a mutation checker that proves they fail when a check is removed.

## My permission model, in my own words

A document belongs to exactly one owner. Nobody else can do anything with it unless there is a **grant row** naming them and that document. A grant says "read" (open and download) or "edit" (also change details and upload versions), and may have an end date. That's the whole model. There are no folders, groups, inheritance, public links or "anyone in the company" settings, because each of those is a way for a grant meant for one file to reach forty.

Roles decide what *kind of work* you do, not *which documents* you reach. Owners can upload and share their own documents. Viewers can only use what is shared with them. Administrators manage people and watch the record, and get **no** access to documents. An admin who could read everything would make every admin account the most valuable thing to steal, and would make "who could have seen this?" impossible to answer.

The decision lives in one function, `authz.decide()`, and every document route calls `authz.require()` as its first data access. When someone downloads a file, the decision is the first line of `download()` in `app/routes_documents.py`. If that line were removed, anyone signed in could download any document whose id they know: ids are random, but they appear in URLs, in shared screens and in the audit log, so this would be a real leak. Fourteen tests fail when that one line is removed, starting with `StrangerCannotReachDocument.test_download`. The mutation checker does exactly that removal on every run.

Listing and search are the one place where many documents are filtered at once. They use the same rules written as SQL (`ACCESSIBLE_SQL`), and a test compares the SQL against `decide()` for every user and every document so they cannot drift apart.

## What "taking access away immediately" means here

The next request is refused. Nothing that grants access is cached or handed out: no signed URLs, no download tokens, no JWTs. The browser holds one random session cookie; each request looks up the session, whether the account is still active, and the grant. Revoking deletes a row; disabling an account deletes all its sessions and is also re-checked on every request; changing a password ends every other session.

The cost: a few indexed database lookups per request, no stateless scaling, and download links you can't paste into another tool. I think that is the right trade for this product. What it cannot do: claw back a copy that was already downloaded. The audit trail records which version (and its SHA-256) each person took, which is what you need afterwards.

## How the audit trail is protected

Triggers in the database refuse any update or delete, so the application (or an injection) can only add. Each entry is chained to the previous one with an HMAC whose key is not in the database, so editing, deleting or reordering an entry, even with the triggers removed, breaks verification at that entry. Truncating the end is caught by an off-database copy (every entry goes to the platform log) and by the head hash the admin records outside the system. Data changes and their audit entries commit together; downloads are recorded before the first byte leaves, and are not served if recording fails.

## What I deliberately did not build, and why

- **Groups, folders, inheritance, "share with everyone".** Each is a way access spreads beyond the file it was meant for. A smaller model that holds beats a richer one with a hole.
- **Public or external share links.** A bearer link is access that can be forwarded and cannot be tied to a person. External partners would get a viewer account instead, ideally with an expiry. With more time: invited external accounts restricted to the documents shared with them, with a mandatory expiry.
- **Admin password reset and ownership transfer.** Both let an administrator become someone who can read documents. Recovery should be a link sent to the user's own verified email; transfer should need a second approver.
- **An LLM inside the product.** Sending document titles and sharing patterns to a third-party model is itself a disclosure. The suggestion feature uses a local rule over the owner's own sharing history; the confirm-and-audit flow around it would stay the same if a model were plugged in later.
- **In-browser preview.** Rendering untrusted files on our origin is the most common way document systems get stored XSS. Everything downloads as an attachment.
- **MFA.** Not built for time. It is the first thing I would add.

## Where AI was wrong

Details and fix commits are in [PROMPTS.md](PROMPTS.md). The ones that mattered for security:

- The generated test suite looked complete and was green, but the mutation checker showed four security checks could be deleted without any test failing. The worst: removing the authorisation check from **revoking a grant** would have let any signed-in user remove other people's access to documents they cannot even see. Every one is now covered.
- A failing session test pushed towards exempting the login endpoint from CSRF. The code was right and the test was wrong; exempting it would have allowed login CSRF.
- The audit trail was written on every page view for suggestions, burying real events.
- The admin activity log showed refused downloads as "downloaded". The stored record was right; the screen said the opposite, which in an incident report would be evidence against an innocent person. Found by an end-to-end browser test.
- The suggested gunicorn command trusted forwarded headers from anyone, which would let clients forge their IP in the audit log.

## What is unfinished

- MFA; account recovery by email; external-partner accounts.
- Automatic anchoring of the audit head to write-once storage (today the admin records it by hand, and the platform log keeps a copy).
- Per-download watermarking.
- Real malware scanning and a proper PDF parser (active-content detection is a byte search, which compressed object streams can evade; see T34).
- Postgres and multiple instances. The security logic would not change: every decision already reads the database.
- Dependencies are range-pinned, not hash-pinned.
- Audit retention: the log grows forever.
