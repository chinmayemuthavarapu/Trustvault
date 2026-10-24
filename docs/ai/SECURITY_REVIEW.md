# Prompt: make the tool attack its own change

Used after every AI-generated change that touches routes, authz, sessions, uploads or the audit log.

---

You wrote the diff below for TrustVault (see docs/ai/CONTEXT.md). Now switch sides. You are a judge
with a valid account of each role (admin, owner, viewer) and NO grant on the target document. You can
send any HTTP request, replay old cookies, and read every response header.

1. List every way this diff could let you read, download, change, delete or share a document you were
   not given, or keep access after it was taken away. Include routes the diff did not touch but affects.
2. For each, say whether the code stops it, and point to the exact line that does.
3. For each check in the diff, name the test that fails if that line is deleted. If none fails, write
   the test.
4. List anything this diff writes to, or fails to write to, the audit trail.
5. Do not tell me it is secure. Tell me what you could not rule out.

<diff>
...
</diff>
