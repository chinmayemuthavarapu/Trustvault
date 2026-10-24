"""T02/T26/T30: listing and search never reveal documents the caller cannot open,
and the SQL filter used for listing agrees with authz.decide() for every
(user, document) pair."""
from app.authz import ACCESSIBLE_SQL, Action, decide
from app.db import now_iso
from app.db import connect
from tests.helpers import TVTestCase


class SearchMatrix(TVTestCase):
    def setUp(self):
        super().setUp()
        self.docs = {
            "a_private": self.make_doc("alice", title="Alpha private", category="HR"),
            "a_read": self.make_doc("alice", title="Alpha read carol", category="Finance"),
            "a_edit": self.make_doc("alice", title="Alpha edit dave", category="Legal"),
            "a_expired": self.make_doc("alice", title="Alpha expired", category="HR"),
            "a_trash": self.make_doc("alice", title="Alpha trashed", category="HR"),
            "b_private": self.make_doc("bob", title="Bravo private", category="HR"),
            "b_read": self.make_doc("bob", title="Bravo read carol", category="Audit"),
        }
        self.grant(self.docs["a_read"]["id"], "carol", "read")
        self.grant(self.docs["a_edit"]["id"], "dave", "edit")
        self.grant(self.docs["a_expired"]["id"], "carol", "read")
        self.expire_grant_now(self.docs["a_expired"]["id"], "carol")
        self.grant(self.docs["a_trash"]["id"], "carol", "read")
        self.as_("alice").delete(f"/api/documents/{self.docs['a_trash']['id']}")
        self.grant(self.docs["b_read"]["id"], "carol", "read", owner="bob")

    def listed(self, who, query=""):
        r = self.as_(who).get("/api/documents?page_size=100" + query)
        self.assertEqual(r.status_code, 200, r.get_json())
        return {d["id"] for d in r.get_json()["items"]}

    def test_list_matches_authz_for_every_user_and_document(self):
        conn = connect(self.cfg.DATABASE)
        for username in self.ids:
            user = {"id": self.ids[username], "username": username}
            listed = self.listed(username)
            for key, doc in self.docs.items():
                d = decide(conn, user, doc["id"], Action.VIEW)
                expected = d.allowed and not d.document["deleted_at"]
                self.assertEqual(doc["id"] in listed, expected, f"{username} / {key}")
        conn.close()

    def test_accessible_sql_alone_matches_authz(self):
        """The SQL rule itself, without the extra filters list_documents adds on top."""
        conn = connect(self.cfg.DATABASE)
        for username, uid in self.ids.items():
            rows = conn.execute(f"SELECT d.id FROM documents d WHERE {ACCESSIBLE_SQL}",
                                {"me": uid, "now": now_iso()}).fetchall()
            got = {r[0] for r in rows}
            for key, doc in self.docs.items():
                d = decide(conn, {"id": uid, "username": username}, doc["id"], Action.VIEW)
                self.assertEqual(doc["id"] in got, d.allowed, f"{username} / {key}")
        conn.close()

    def test_carol_sees_exactly_her_grants(self):
        self.assertEqual(self.listed("carol"), {self.docs["a_read"]["id"], self.docs["b_read"]["id"]})

    def test_search_by_owner_does_not_reveal_owners_other_documents(self):
        self.assertEqual(self.listed("carol", "&owner=alice"), {self.docs["a_read"]["id"]})
        self.assertEqual(self.listed("carol", "&owner=bob"), {self.docs["b_read"]["id"]})

    def test_search_by_title_does_not_match_inaccessible(self):
        self.assertEqual(self.listed("carol", "&q=private"), set())
        self.assertEqual(self.listed("carol", "&q=Alpha"), {self.docs["a_read"]["id"]})

    def test_category_and_date_filters(self):
        self.assertEqual(self.listed("carol", "&category=Audit"), {self.docs["b_read"]["id"]})
        self.assertEqual(self.listed("carol", "&from=2000-01-01&to=2099-01-01"),
                         {self.docs["a_read"]["id"], self.docs["b_read"]["id"]})
        self.assertEqual(self.listed("carol", "&to=2000-01-01"), set())
        self.assertEqual(self.as_("carol").get("/api/documents?from=yesterday").status_code, 400)
        self.assertEqual(self.as_("carol").get("/api/documents?category=Secret").status_code, 400)

    def test_wildcards_and_injection_are_literal(self):
        self.assertEqual(self.listed("carol", "&q=%25"), set())     # '%'
        self.assertEqual(self.listed("carol", "&q=_"), set())
        self.assertEqual(self.listed("carol", "&q=' OR 1=1 --"), set())
        self.assertEqual(self.listed("carol", "&owner=%25"), set())
        self.assertEqual(self.as_("carol").get("/api/documents?sort=title;DROP TABLE users").status_code, 400)

    def test_total_count_does_not_leak(self):
        r = self.as_("carol").get("/api/documents?page_size=1").get_json()
        self.assertEqual(r["total"], 2)

    def test_trash_lists_only_own(self):
        self.assertEqual([d["id"] for d in self.as_("alice").get("/api/documents/trash").get_json()["items"]],
                         [self.docs["a_trash"]["id"]])
        for who in ("bob", "carol", "admin"):
            self.assertEqual(self.as_(who).get("/api/documents/trash").get_json()["items"], [])

    def test_scope_filters(self):
        self.assertEqual(self.listed("alice", "&scope=shared"), set())
        self.assertEqual(len(self.listed("alice", "&scope=mine")), 4)
