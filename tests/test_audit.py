"""T20/T34 and the misc hardening checks (T14/T22/T31/T32/T33)."""
import json
import sqlite3

from app import audit
from app.db import connect
from tests.helpers import TVTestCase


class AuditTrail(TVTestCase):
    def setUp(self):
        super().setUp()
        self.doc = self.make_doc("alice", title="Evidence")
        g = self.grant(self.doc["id"], "carol")
        self.as_("carol").get(f"/api/documents/{self.doc['id']}/download")
        self.as_("bob").get(f"/api/documents/{self.doc['id']}/download")
        self.as_("alice").delete(f"/api/documents/{self.doc['id']}/grants/{g['id']}")

    def verify(self):
        return self.as_("admin").get("/api/admin/audit/verify").get_json()

    def test_every_required_event_recorded(self):
        actions = {(r["action"], r["outcome"], r["actor_username"]) for r in self.audit_rows()}
        for expected in [("document.upload", "allowed", "alice"), ("permission.grant", "allowed", "alice"),
                         ("document.download", "allowed", "carol"), ("document.download", "denied", "bob"),
                         ("permission.revoke", "allowed", "alice")]:
            self.assertIn(expected, actions)

    def test_chain_intact(self):
        self.assertTrue(self.verify()["intact"])

    def test_update_and_delete_blocked_by_database(self):
        conn = connect(self.cfg.DATABASE)
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("UPDATE audit_log SET actor_username = 'someone-else' WHERE action = 'document.download'")
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM audit_log WHERE outcome = 'denied'")
        conn.close()

    def _tamper(self, sql):
        conn = connect(self.cfg.DATABASE)
        conn.execute("DROP TRIGGER audit_no_update")
        conn.execute("DROP TRIGGER audit_no_delete")
        conn.execute(sql)
        conn.close()

    def test_edit_with_triggers_dropped_is_detected(self):
        self._tamper("UPDATE audit_log SET actor_username = 'mallory' WHERE action = 'document.download'"
                     " AND outcome = 'allowed'")
        result = self.verify()
        self.assertFalse(result["intact"])
        self.assertIn("hash", result["problem"])

    def test_deleting_a_middle_row_is_detected(self):
        self._tamper("DELETE FROM audit_log WHERE action = 'document.download' AND outcome = 'denied'")
        self.assertFalse(self.verify()["intact"])

    def test_rehashing_without_the_key_is_detected(self):
        """An attacker with the DB but not TV_AUDIT_KEY recomputes the chain with a guessed key."""
        conn = connect(self.cfg.DATABASE)
        conn.execute("DROP TRIGGER audit_no_update")
        prev = audit.GENESIS
        for r in conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall():
            row = dict(r)
            if row["action"] == "document.download" and row["outcome"] == "denied":
                row["actor_username"] = "someone-else"
            h = audit.compute_hash(b"\x00" * 32, prev, row)
            conn.execute("UPDATE audit_log SET actor_username=?, prev_hash=?, hash=? WHERE id=?",
                         (row["actor_username"], prev, h, row["id"]))
            prev = h
        conn.close()
        self.assertFalse(self.verify()["intact"])

    def test_admin_audit_view_and_filters(self):
        a = self.as_("admin")
        denied = a.get("/api/admin/audit?outcome=denied").get_json()["items"]
        self.assertTrue(all(r["outcome"] == "denied" for r in denied))
        perms = a.get("/api/admin/audit?action=permission.").get_json()["items"]
        self.assertEqual({r["action"] for r in perms}, {"permission.grant", "permission.revoke"})
        self.assertEqual(a.get("/api/admin/audit?outcome=maybe").status_code, 400)

    def test_owner_sees_activity_on_own_document(self):
        items = self.as_("alice").get(f"/api/documents/{self.doc['id']}/activity").get_json()["items"]
        self.assertIn("carol", {i["actor_username"] for i in items})

    def test_alert_for_probing(self):
        bob = self.as_("bob")
        for _ in range(6):
            bob.get(f"/api/documents/{self.doc['id']}/download")
        kinds = {a["kind"] for a in self.as_("admin").get("/api/admin/alerts").get_json()["items"]}
        self.assertIn("probing", kinds)


class Suggestions(TVTestCase):
    """T34: the assistant suggests; only the owner grants; both are audited."""

    def test_suggestion_never_grants_and_acceptance_is_recorded(self):
        d1 = self.make_doc("alice", title="HR one", category="HR")
        d2 = self.make_doc("alice", title="HR two", category="HR")
        self.grant(d1["id"], "carol", "read")
        items = self.as_("alice").get(f"/api/documents/{d2['id']}/suggestions").get_json()["items"]
        self.assertEqual([i["user"]["username"] for i in items], ["carol"])
        self.assertEqual(self.as_("carol").get(f"/api/documents/{d2['id']}").status_code, 404)
        self.assertTrue(self.audit_rows("suggestion.shown"))
        r = self.as_("alice").post(f"/api/documents/{d2['id']}/grants",
                                   json={"username": "carol", "permission": "read", "suggestion_id": items[0]["id"]})
        self.assertEqual(r.status_code, 201)
        row = self.audit_rows("permission.grant")[-1]
        self.assertTrue(json.loads(row["details"])["from_suggestion"]["confirmed_by_owner"])

    def test_dismissed_suggestion_not_repeated(self):
        d1 = self.make_doc("alice", title="One")
        d2 = self.make_doc("alice", title="Two")
        self.grant(d1["id"], "carol")
        s = self.as_("alice").get(f"/api/documents/{d2['id']}/suggestions").get_json()["items"][0]
        self.as_("alice").post(f"/api/documents/{d2['id']}/suggestions/{s['id']}/dismiss")
        self.assertEqual(self.as_("alice").get(f"/api/documents/{d2['id']}/suggestions").get_json()["items"], [])


class Hardening(TVTestCase):
    def test_security_headers(self):
        r = self.as_("alice").get("/api/documents")
        for h in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"):
            self.assertIn(h, r.headers)
        self.assertIn("no-store", r.headers["Cache-Control"])
        self.assertNotIn("Access-Control-Allow-Origin", r.headers)
        self.assertIn("frame-ancestors 'none'", self.app.test_client().get("/").headers["Content-Security-Policy"])

    def test_mass_assignment_rejected(self):
        d = self.make_doc("alice")
        r = self.as_("alice").patch(f"/api/documents/{d['id']}", json={"title": "x", "owner_id": self.ids["bob"]})
        self.assertEqual(r.status_code, 400)
        r = self.as_("alice").post(f"/api/documents/{d['id']}/grants",
                                   json={"username": "carol", "permission": "read", "granted_by": self.ids["bob"]})
        self.assertEqual(r.status_code, 400)

    def test_static_path_traversal(self):
        c = self.app.test_client()
        for url in ("/static/../app/config.py", "/static/..%2fapp%2fconfig.py", "/static/%2e%2e/data/trustvault.db"):
            r = c.get(url)
            self.assertIn(r.status_code, (400, 404), url)
            self.assertNotIn(b"MASTER_KEY", r.get_data())

    def test_download_rate_limit(self):
        d = self.make_doc("alice")
        codes = [self.as_("alice").get(f"/api/documents/{d['id']}/download").status_code
                 for _ in range(self.cfg.DOWNLOADS_PER_MINUTE + 1)]
        self.assertEqual(codes[-1], 429)

    def test_errors_do_not_leak_internals(self):
        r = self.as_("alice").post("/api/documents/" + "a" * 32 + "/grants", data="not json",
                                   content_type="application/json")
        self.assertNotIn(b"Traceback", r.get_data())
