# Five-minute demo script

Two browser windows side by side: **left** signed in as `olivia` (owner), **right** as `victor` (viewer). A third tab for `admin`.

| Time | Do | Say |
|---|---|---|
| 0:00 | Sign-in page. | "TrustVault: the wrong person cannot reach a document, and every attempt is on the record." |
| 0:20 | Right (victor): document list shows two items. | "Victor only sees what was shared with him. Search is filtered by the same rule as every download." |
| 0:40 | Right: paste the URL of olivia's *Salary bands 2026* (copy the id from the left window). | "Knowing the id doesn't help. Same 404 as a document that doesn't exist, and the attempt is recorded." |
| 1:10 | Left (olivia): upload `board-minutes.txt`. | "New documents are private. Type is checked from the bytes, not the name; files are encrypted at rest." |
| 1:40 | Left: point at **Suggested people**. Victor is suggested. | "The assistant suggests from Olivia's own sharing history. It cannot grant anything. Watch what happens if I accept." Press Add → confirmation dialog → Give access. |
| 2:10 | Right: open it, download. | "Allowed, and recorded with the exact version and its SHA-256." |
| 2:30 | Left: Remove Victor. Right: click Download again **without reloading**. | "Revocation is the next request. No token, no link, nothing cached that outlives it." Show the refusal. |
| 3:00 | Left: scroll to **Record for this document**. | "Olivia can see exactly who reached her document, including the refused attempts." |
| 3:20 | Admin tab: Overview → **Verify now**. | "Every audit entry is HMAC-chained to the one before; the database refuses edits and deletes." |
| 3:40 | Terminal: `sqlite3 data/trustvault.db "DELETE FROM audit_log WHERE id=5"` → error. Then drop the trigger, edit a row, press Verify again → **Chain broken at entry N**. | "Even with file access, tampering shows." |
| 4:20 | Terminal: `python scripts/mutation_check.py download`. | "The judges will delete an authorisation check. This does it to every check; the tests catch every one." |
| 4:45 | Admin: People → disable Victor; right window clicks anything → signed out. | "Disabling someone ends their sessions everywhere, immediately." |
| 5:00 | End. | |
