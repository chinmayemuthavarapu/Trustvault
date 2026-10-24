"""Remove one security check at a time and confirm the test suite notices.

The judges will delete an authorisation check and run the tests. This script
does that to ourselves, for every check we know about:

    python scripts/mutation_check.py            # all mutations
    python scripts/mutation_check.py download   # only mutations whose name contains "download"

Each mutation is applied to a throwaway copy of the repository, the full test
suite runs with --failfast, and the result is reported as CAUGHT (a test
failed, good) or SURVIVED (all tests still passed: a gap in the tests).
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BYPASS = 'doc, _ = (get_db().execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone(), "owner")'


_REQUIRE = r"doc, \w+ = require\(g\.user, doc_id, Action\.\w+\)"


def require_calls():
    """One mutation per authz.require() call in the document routes (located again at run time)."""
    path = "app/routes_documents.py"
    src = open(os.path.join(ROOT, path)).read()
    out = []
    for n, m in enumerate(re.finditer(_REQUIRE, src)):
        fn = re.findall(r"\ndef (\w+)\(", src[:m.start()])[-1]
        out.append((f"route {fn}: authz.require() removed", path, None, BYPASS, n))
    return out


MUTATIONS = [
    # authz.decide rules
    ("authz: grant expiry ignored", "app/authz.py",
     '"AND (expires_at IS NULL OR expires_at > ?)"', '"AND (? IS NOT NULL)"'),
    ("authz: grantee can reach trashed documents", "app/authz.py",
     '    if doc["deleted_at"]:\n        return Decision(False, doc, None, False, "document is in the owner\'s trash")\n', ""),
    ("authz: owner state check ignored", "app/authz.py",
     'allowed_actions = OWNER_TRASH if doc["deleted_at"] else OWNER_LIVE', "allowed_actions = OWNER_TRASH | OWNER_LIVE"),
    ("authz: grant level ignored", "app/authz.py",
     'ok = action in GRANT_ACTIONS[grant["permission"]]', "ok = True"),
    ("authz: read grant allows edit", "app/authz.py",
     '"read": {Action.VIEW, Action.DOWNLOAD},', '"read": {Action.VIEW, Action.DOWNLOAD, Action.EDIT},'),
    ("authz: edit grant allows share", "app/authz.py",
     '"edit": {Action.VIEW, Action.DOWNLOAD, Action.EDIT},', '"edit": {Action.VIEW, Action.DOWNLOAD, Action.EDIT, Action.SHARE},'),
    ("authz: no grant row treated as read", "app/authz.py",
     '    if grant is None:\n        return Decision(False, doc, None, False, "no grant")\n',
     '    if grant is None:\n        grant = {"permission": "read"}\n'),
    ("authz: purged documents reachable", "app/authz.py",
     '"SELECT * FROM documents WHERE id = ? AND purged_at IS NULL"', '"SELECT * FROM documents WHERE id = ?"'),
    ("list: expiry ignored in listing SQL", "app/authz.py",
     "              AND (g.expires_at IS NULL OR g.expires_at > :now)))", "              AND :now IS NOT NULL))"),
    ("list: trashed shared docs listed", "app/authz.py",
     "OR (d.deleted_at IS NULL AND EXISTS (", "OR (1=1 AND EXISTS ("),
    ("list: access filter removed", "app/routes_documents.py",
     'where = [ACCESSIBLE_SQL, "d.deleted_at IS NULL"]', 'where = ["1=1", "d.deleted_at IS NULL"]'),
    ("trash: other owners' trash listed", "app/routes_documents.py",
     "WHERE d.owner_id = :me AND d.deleted_at IS NOT NULL", "WHERE d.deleted_at IS NOT NULL"),
    # ids that must belong to the authorised document
    ("download: version not tied to document", "app/routes_documents.py",
     '"SELECT * FROM document_versions WHERE id = ? AND document_id = ?"',
     '"SELECT * FROM document_versions WHERE id = ? AND ? IS NOT NULL"'),
    ("revoke: grant not tied to document", "app/routes_documents.py",
     '" WHERE g.id = ? AND g.document_id = ?"', '" WHERE g.id = ? AND ? IS NOT NULL"'),
    ("grant: suggestion not tied to document", "app/routes_documents.py",
     '"SELECT * FROM suggestions WHERE id = ? AND document_id = ? AND',
     '"SELECT * FROM suggestions WHERE id = ? AND ? IS NOT NULL AND'),
    ("grant: owner can grant to self/inactive", "app/routes_documents.py",
     'if target is None or not target["active"]:', "if target is None:"),
    # roles
    ("roles: viewer can upload", "app/routes_documents.py",
     '@login_required("owner")\ndef upload_document', "@login_required()\ndef upload_document"),
    ("roles: role check in decorator removed", "app/sessions.py",
     'if roles and user["role"] not in roles:', "if False:"),
    ("roles: anyone can look up people", "app/routes_documents.py",
     'can_share = g.user["role"] == "owner" or', "can_share = True or"),
    # sessions
    ("session: disabled user keeps session", "app/sessions.py",
     ' or not row["active"]:', ":"),
    ("session: idle timeout ignored", "app/sessions.py",
     ' or row["last_seen_at"] <= idle_cutoff', ""),
    ("session: logout does not delete server-side", "app/routes_auth.py",
     'cur = conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))',
     'cur = conn.execute("SELECT 1 WHERE ? IS NOT NULL", (token_hash,))'),
    ("session: password change keeps other sessions", "app/routes_auth.py",
     'ended = revoke_user_sessions(conn, user["id"], except_token_hash=g.session["token_hash"])', "ended = 0"),
    ("session: disabling user keeps sessions", "app/routes_admin.py",
     "            ended = revoke_user_sessions(conn, user_id)\n        audit.record(conn, \"admin.user_update\"",
     "            ended = 0\n        audit.record(conn, \"admin.user_update\""),
    ("session: must-change-password not enforced", "app/sessions.py",
     'if user["must_change_password"] and not allow_password_change:', "if False:"),
    ("session: login does not rotate token", "app/routes_auth.py",
     "            if old:\n                conn.execute(\"DELETE FROM sessions WHERE token_hash = ?\", (old,))\n", ""),
    ("session: cookie not __Host- prefixed over HTTPS", "app/sessions.py",
     'return "__Host-" + COOKIE if', "return COOKIE if"),
    ("csrf: token check removed", "app/sessions.py",
     'if not sent or not hmac.compare_digest(sent, g.session["csrf_token"]):', "if False:"),
    ("csrf: origin check removed", "app/sessions.py",
     "if origin and urlsplit(origin).netloc.lower() != request.host.lower():", "if False:"),
    ("login: lockout removed", "app/routes_auth.py", "if _locked_out(conn, username, ip):", "if False:"),
    ("admin: can disable/demote self", "app/routes_admin.py",
     'if target["id"] == g.user["id"] and', "if False and"),
    # audit
    ("audit: download not recorded", "app/routes_documents.py",
     'audit.record(conn, "document.download", "allowed", document=doc,', 'dict(conn=conn, document=doc,'),
    ("audit: refusals not recorded", "app/authz.py",
     "    audit.record_standalone(\n        f\"document.{action.value}\", \"denied\",", "    dict(\n        x=1,"),
    ("audit: verify skips hash check", "app/audit.py",
     'elif not hmac.compare_digest(row["hash"], compute_hash(key, prev, row)):', "elif False:"),
    ("audit: append-only triggers removed", "app/schema.sql",
     "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;", "BEGIN SELECT 1; END;"),
    # storage and uploads
    ("storage: document binding (AAD) removed", "app/storage.py",
     'return f"trustvault:{document_id}:{version_id}".encode()', 'return b"trustvault"'),
    ("upload: PDF active-content check removed", "app/validation.py",
     "        m = _PDF_ACTIVE.search(data)\n", "        m = None\n"),
    ("upload: magic-byte check removed", "app/validation.py",
     '        if not data.startswith(b"%PDF-"):', "        if False:"),
    ("upload: extension allowlist removed", "app/validation.py",
     "    if ext not in ALLOWED:\n", "    if False:\n"),
    ("upload: filename not cleaned", "app/validation.py",
     'name = name.replace("\\\\", "/").rsplit("/", 1)[-1]', "pass"),
    ("download: served inline", "app/routes_documents.py",
     '"Content-Disposition": f"attachment;', '"Content-Disposition": f"inline;'),
    ("search: LIKE wildcards not escaped", "app/routes_documents.py",
     'return "%" + term.replace("\\\\", "\\\\\\\\").replace("%", "\\\\%").replace("_", "\\\\_") + "%"',
     'return "%" + term + "%"'),
]


def run(name, path, old, new, at=None):
    tmp = tempfile.mkdtemp(prefix="tvmut-")
    try:
        shutil.copytree(ROOT, os.path.join(tmp, "repo"), ignore=shutil.ignore_patterns("data", ".git", "__pycache__"))
        repo = os.path.join(tmp, "repo")
        target = os.path.join(repo, path)
        src = open(target).read()
        if at is not None:  # the n-th authz.require() call
            m = list(re.finditer(_REQUIRE, src))[at]
            mutated = src[:m.start()] + new + src[m.end():]
        else:
            if src.count(old) < 1:
                return "BROKEN (pattern not found: update this script)"
            mutated = src.replace(old, new)
        open(target, "w").write(mutated)
        env = dict(os.environ, TV_DATA_DIR=os.path.join(tmp, "data"))
        r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-f", "-q"],
                           cwd=repo, env=env, capture_output=True, text=True, timeout=900)
        if r.returncode == 0:
            return "SURVIVED"
        failed = re.search(r"(?:FAIL|ERROR): (\S+) \((\S+)\)", r.stderr)
        return "CAUGHT" + (f"  by {failed.group(2)}.{failed.group(1)}" if failed else "")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    flt = sys.argv[1] if len(sys.argv) > 1 else ""
    muts = [m + (None,) for m in MUTATIONS] + require_calls()
    muts = [m for m in muts if flt in m[0]]
    survived = 0
    for name, path, old, new, at in muts:
        result = run(name, path, old, new, at)
        survived += not result.startswith("CAUGHT")
        print(f"{'OK  ' if result.startswith('CAUGHT') else '!!  '}{name:55s} {result}", flush=True)
    print(f"\n{len(muts) - survived}/{len(muts)} mutations caught by the tests.")
    sys.exit(1 if survived else 0)


if __name__ == "__main__":
    main()
