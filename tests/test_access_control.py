"""One user cannot reach another user's documents, through any endpoint.

Each test names the THREATS.md entry it covers. Removing any single
authz.require() call, or any rule inside authz.decide(), fails at least one
test here (verified with scripts/mutation_check.py).
"""
import io

from tests.helpers import TVTestCase, pdf_bytes

SECRET = b"TOP-SECRET-PAYLOAD-7f3a"


class StrangerCannotReachDocument(TVTestCase):
    """T01: a signed-in user with no grant, trying every route by document id."""

    def setUp(self):
        super().setUp()
        self.doc = self.make_doc("alice", title="Alice private", data=pdf_bytes("x") + SECRET)
        self.id = self.doc["id"]

    def assert_refused(self, resp, who="bob"):
        self.assertEqual(resp.status_code, 404, resp.get_data(as_text=True))
        self.assertNotIn(SECRET, resp.get_data())
        self.assertNotIn(b"Alice private", resp.get_data())

    def test_view_metadata(self):
        for who in ("bob", "carol", "admin"):
            self.assert_refused(self.as_(who).get(f"/api/documents/{self.id}"))

    def test_download(self):
        for who in ("bob", "carol", "admin"):
            self.assert_refused(self.as_(who).get(f"/api/documents/{self.id}/download"))

    def test_download_specific_version(self):
        v = self.as_("alice").get(f"/api/documents/{self.id}").get_json()["versions"][0]["id"]
        self.assert_refused(self.as_("bob").get(f"/api/documents/{self.id}/download?version={v}"))

    def test_edit_metadata(self):
        self.assert_refused(self.as_("bob").patch(f"/api/documents/{self.id}", json={"title": "pwned"}))
        self.assertEqual(self.as_("alice").get(f"/api/documents/{self.id}").get_json()["title"], "Alice private")

    def test_upload_new_version(self):
        r = self.as_("bob").post(f"/api/documents/{self.id}/versions",
                                 data={"file": (io.BytesIO(pdf_bytes("evil")), "evil.pdf")},
                                 content_type="multipart/form-data")
        self.assert_refused(r)
        self.assertEqual(len(self.as_("alice").get(f"/api/documents/{self.id}").get_json()["versions"]), 1)

    def test_delete(self):
        self.assert_refused(self.as_("bob").delete(f"/api/documents/{self.id}"))
        self.assertFalse(self.as_("alice").get(f"/api/documents/{self.id}").get_json()["in_trash"])

    def test_restore_and_purge(self):
        self.as_("alice").delete(f"/api/documents/{self.id}")
        self.assert_refused(self.as_("bob").post(f"/api/documents/{self.id}/restore"))
        self.assert_refused(self.as_("bob").post(f"/api/documents/{self.id}/purge"))
        self.assertTrue(self.as_("alice").get(f"/api/documents/{self.id}").get_json()["in_trash"])

    def test_list_grants(self):
        self.assert_refused(self.as_("bob").get(f"/api/documents/{self.id}/grants"))

    def test_grant_self_access(self):
        r = self.as_("bob").post(f"/api/documents/{self.id}/grants", json={"username": "bob", "permission": "edit"})
        self.assert_refused(r)
        self.assert_refused(self.as_("bob").get(f"/api/documents/{self.id}/download"))

    def test_revoke_someone_elses_grant(self):
        g = self.grant(self.id, "carol", "read")
        for who in ("bob", "dave", "admin"):
            self.assert_refused(self.as_(who).delete(f"/api/documents/{self.id}/grants/{g['id']}"))
        self.assertEqual(self.as_("carol").get(f"/api/documents/{self.id}").status_code, 200)

    def test_grantee_cannot_revoke_others(self):
        g = self.grant(self.id, "carol", "read")
        self.grant(self.id, "dave", "edit")
        r = self.as_("dave").delete(f"/api/documents/{self.id}/grants/{g['id']}")
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.as_("carol").get(f"/api/documents/{self.id}").status_code, 200)

    def test_dismiss_someone_elses_suggestion(self):
        other = self.make_doc("alice", title="Other")
        self.grant(other["id"], "carol")
        s = self.as_("alice").get(f"/api/documents/{self.id}/suggestions").get_json()["items"][0]
        self.assert_refused(self.as_("bob").post(f"/api/documents/{self.id}/suggestions/{s['id']}/dismiss"))
        self.assertEqual(len(self.as_("alice").get(f"/api/documents/{self.id}/suggestions").get_json()["items"]), 1)

    def test_suggestions_and_activity(self):
        self.assert_refused(self.as_("bob").get(f"/api/documents/{self.id}/suggestions"))
        self.assert_refused(self.as_("bob").get(f"/api/documents/{self.id}/activity"))

    def test_refusals_are_audited(self):
        """T20: refused attempts are evidence."""
        self.as_("bob").get(f"/api/documents/{self.id}/download")
        rows = self.audit_rows("document.download", "denied")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["actor_username"], "bob")
        self.assertEqual(rows[0]["document_id"], self.id)


class Enumeration(TVTestCase):
    """T23: refused and non-existent look the same; malformed ids are handled."""

    def test_not_granted_equals_not_found(self):
        doc = self.make_doc("alice")
        a = self.as_("bob").get(f"/api/documents/{doc['id']}")
        b = self.as_("bob").get(f"/api/documents/{'0' * 32}")
        self.assertEqual((a.status_code, a.get_json()), (b.status_code, b.get_json()))

    def test_malformed_ids(self):
        for bad in ("..%2f..%2fetc%2fpasswd", "1 OR 1=1", "%27", "A" * 40, "x"):
            r = self.as_("bob").get(f"/api/documents/{bad}/download")
            self.assertEqual(r.status_code, 404, bad)


class Unauthenticated(TVTestCase):
    """T25: no session, no access, and the attempt is recorded."""

    def test_every_route_requires_login(self):
        doc = self.make_doc("alice")
        c = self.app.test_client()
        d = doc["id"]
        for method, url in [("get", "/api/documents"), ("get", f"/api/documents/{d}"),
                            ("get", f"/api/documents/{d}/download"), ("get", f"/api/documents/{d}/grants"),
                            ("get", "/api/documents/trash"), ("get", "/api/admin/audit"),
                            ("get", "/api/admin/users"), ("get", "/api/users/lookup?q=al"),
                            ("delete", f"/api/documents/{d}"), ("post", f"/api/documents/{d}/grants")]:
            r = getattr(c, method)(url)
            self.assertEqual(r.status_code, 401, url)
        self.assertTrue(self.audit_rows("document.access", "denied"))

    def test_forged_cookie(self):
        c = self.app.test_client()
        c.set_cookie("tv_session", "forged-token-value")
        self.assertEqual(c.get("/api/documents").status_code, 401)


class GrantLevels(TVTestCase):
    """T03/T04: each grant level allows exactly its actions."""

    def setUp(self):
        super().setUp()
        self.doc = self.make_doc("alice", title="Shared")
        self.id = self.doc["id"]

    def test_read_grant_can_view_and_download_only(self):
        self.grant(self.id, "carol", "read")
        c = self.as_("carol")
        self.assertEqual(c.get(f"/api/documents/{self.id}").status_code, 200)
        self.assertEqual(c.get(f"/api/documents/{self.id}/download").status_code, 200)
        self.assertEqual(c.patch(f"/api/documents/{self.id}", json={"title": "x"}).status_code, 403)
        r = c.post(f"/api/documents/{self.id}/versions", data={"file": (io.BytesIO(pdf_bytes()), "v.pdf")},
                   content_type="multipart/form-data")
        self.assertEqual(r.status_code, 403)
        self.assertEqual(c.delete(f"/api/documents/{self.id}").status_code, 403)
        self.assertEqual(c.get(f"/api/documents/{self.id}/grants").status_code, 403)
        self.assertEqual(c.post(f"/api/documents/{self.id}/grants",
                                json={"username": "dave", "permission": "read"}).status_code, 403)

    def test_edit_grant_can_edit_but_not_share_or_delete(self):
        self.grant(self.id, "carol", "edit")
        c = self.as_("carol")
        self.assertEqual(c.patch(f"/api/documents/{self.id}", json={"title": "Renamed"}).status_code, 200)
        r = c.post(f"/api/documents/{self.id}/versions", data={"file": (io.BytesIO(pdf_bytes("v2")), "v2.pdf")},
                   content_type="multipart/form-data")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(c.delete(f"/api/documents/{self.id}").status_code, 403)
        self.assertEqual(c.get(f"/api/documents/{self.id}/grants").status_code, 403)
        self.assertEqual(c.post(f"/api/documents/{self.id}/grants",
                                json={"username": "dave", "permission": "read"}).status_code, 403)
        self.assertEqual(c.post(f"/api/documents/{self.id}/grants",
                                json={"username": "carol", "permission": "edit"}).status_code, 403)
        self.assertEqual(self.as_("dave").get(f"/api/documents/{self.id}").status_code, 404)

    def test_grant_on_one_document_gives_nothing_on_another(self):
        other = self.make_doc("alice", title="Other")
        self.grant(self.id, "carol", "edit")
        self.assertEqual(self.as_("carol").get(f"/api/documents/{other['id']}/download").status_code, 404)


class Revocation(TVTestCase):
    """T05/T06: taking access away works on the very next request."""

    def setUp(self):
        super().setUp()
        self.doc = self.make_doc("alice")
        self.id = self.doc["id"]

    def test_revoke_is_immediate_for_existing_session(self):
        g = self.grant(self.id, "carol", "read")
        c = self.as_("carol")
        self.assertEqual(c.get(f"/api/documents/{self.id}/download").status_code, 200)
        r = self.as_("alice").delete(f"/api/documents/{self.id}/grants/{g['id']}")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(c.get(f"/api/documents/{self.id}/download").status_code, 404)
        self.assertEqual(c.get(f"/api/documents/{self.id}").status_code, 404)
        self.assertNotIn(self.id, [d["id"] for d in c.get("/api/documents").get_json()["items"]])
        self.assertTrue(self.audit_rows("permission.revoke", "allowed"))

    def test_downgrade_edit_to_read_is_immediate(self):
        self.grant(self.id, "carol", "edit")
        self.grant(self.id, "carol", "read")
        self.assertEqual(self.as_("carol").patch(f"/api/documents/{self.id}", json={"title": "x"}).status_code, 403)

    def test_expired_grant_is_refused(self):
        self.grant(self.id, "carol", "read", expires_at="2099-01-01")
        self.assertEqual(self.as_("carol").get(f"/api/documents/{self.id}/download").status_code, 200)
        self.expire_grant_now(self.id, "carol")
        self.assertEqual(self.as_("carol").get(f"/api/documents/{self.id}/download").status_code, 404)
        self.assertEqual(self.as_("carol").get("/api/documents").get_json()["total"], 0)

    def test_expiry_in_the_past_rejected(self):
        r = self.as_("alice").post(f"/api/documents/{self.id}/grants",
                                   json={"username": "carol", "permission": "read", "expires_at": "2001-01-01"})
        self.assertEqual(r.status_code, 400)

    def test_disabling_user_kills_their_session_now(self):
        """T15"""
        self.grant(self.id, "carol", "read")
        c = self.as_("carol")
        self.assertEqual(c.get(f"/api/documents/{self.id}/download").status_code, 200)
        r = self.as_("admin").patch(f"/api/admin/users/{self.ids['carol']}", json={"active": False})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(c.get(f"/api/documents/{self.id}/download").status_code, 401)
        self.assertEqual(Client_login_status(self.app, "carol"), 401)

    def test_admin_revoke_sessions(self):
        c = self.as_("carol")
        self.as_("admin").post(f"/api/admin/users/{self.ids['carol']}/revoke-sessions")
        self.assertEqual(c.get("/api/documents").status_code, 401)


def Client_login_status(app, username):
    from tests.helpers import Client
    return Client(app).login(username).status_code


class GrantIntegrity(TVTestCase):
    """T10/T11/T28: ids from one document cannot be used through another."""

    def test_cannot_revoke_grant_of_another_document_via_own_doc(self):
        alice_doc = self.make_doc("alice")
        bob_doc = self.make_doc("bob", title="Bob's")
        g = self.grant(alice_doc["id"], "carol", "read", owner="alice")
        r = self.as_("bob").delete(f"/api/documents/{bob_doc['id']}/grants/{g['id']}")
        self.assertEqual(r.status_code, 404)
        self.assertEqual(self.as_("carol").get(f"/api/documents/{alice_doc['id']}").status_code, 200)

    def test_cannot_download_other_documents_version_via_granted_doc(self):
        """T09"""
        mine = self.make_doc("alice", title="Shared with carol")
        secret = self.make_doc("bob", title="Bob secret", data=pdf_bytes() + SECRET)
        self.grant(mine["id"], "carol", "read")
        secret_v = self.as_("bob").get(f"/api/documents/{secret['id']}").get_json()["versions"][0]["id"]
        r = self.as_("carol").get(f"/api/documents/{mine['id']}/download?version={secret_v}")
        self.assertEqual(r.status_code, 404)
        self.assertNotIn(SECRET, r.get_data())

    def test_grant_to_unknown_inactive_or_owner(self):
        d = self.make_doc("alice")
        a = self.as_("alice")
        self.assertEqual(a.post(f"/api/documents/{d['id']}/grants", json={"username": "nobody", "permission": "read"}).status_code, 400)
        self.assertEqual(a.post(f"/api/documents/{d['id']}/grants", json={"username": "alice", "permission": "read"}).status_code, 400)
        self.assertEqual(a.post(f"/api/documents/{d['id']}/grants", json={"username": "carol", "permission": "owner"}).status_code, 400)
        self.as_("admin").patch(f"/api/admin/users/{self.ids['dave']}", json={"active": False})
        self.assertEqual(a.post(f"/api/documents/{d['id']}/grants", json={"username": "dave", "permission": "read"}).status_code, 400)

    def test_suggestion_from_other_document_cannot_be_used(self):
        d1 = self.make_doc("alice", title="One")
        d2 = self.make_doc("alice", title="Two")
        d3 = self.make_doc("alice", title="Three")
        self.grant(d1["id"], "carol")
        s = self.as_("alice").get(f"/api/documents/{d2['id']}/suggestions").get_json()["items"]
        self.assertEqual(s[0]["user"]["username"], "carol")
        r = self.as_("alice").post(f"/api/documents/{d3['id']}/grants",
                                   json={"username": "carol", "permission": "read", "suggestion_id": s[0]["id"]})
        self.assertEqual(r.status_code, 400)


class TrashAndPurge(TVTestCase):
    """T07/T08"""

    def test_trashed_document_unreachable_by_grantee_until_restored(self):
        d = self.make_doc("alice")
        self.grant(d["id"], "carol", "edit")
        self.as_("alice").delete(f"/api/documents/{d['id']}")
        c = self.as_("carol")
        self.assertEqual(c.get(f"/api/documents/{d['id']}/download").status_code, 404)
        self.assertEqual(c.patch(f"/api/documents/{d['id']}", json={"title": "x"}).status_code, 404)
        self.assertEqual(c.get("/api/documents").get_json()["total"], 0)
        self.assertEqual(c.get("/api/documents/trash").get_json()["items"], [])
        # Owner can still see it in the trash but not download from there.
        self.assertEqual(self.as_("alice").get(f"/api/documents/{d['id']}/download").status_code, 403)
        self.as_("alice").post(f"/api/documents/{d['id']}/restore")
        self.assertEqual(c.get(f"/api/documents/{d['id']}/download").status_code, 200)

    def test_purge_destroys_content_and_grants(self):
        d = self.make_doc("alice")
        self.grant(d["id"], "carol")
        a = self.as_("alice")
        self.assertEqual(a.post(f"/api/documents/{d['id']}/purge").status_code, 403)  # must be in trash first
        a.delete(f"/api/documents/{d['id']}")
        self.assertEqual(a.post(f"/api/documents/{d['id']}/purge").status_code, 200)
        self.assertEqual(a.get(f"/api/documents/{d['id']}").status_code, 404)
        conn = self.db()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM grants").fetchone()[0], 0)
        conn.close()
        import os
        self.assertEqual(os.listdir(self.cfg.BLOB_DIR), [])


class AdminHasNoDocumentAccess(TVTestCase):
    """T12: role alone grants nothing on documents."""

    def test_admin_cannot_read_change_or_share(self):
        d = self.make_doc("alice")
        a = self.as_("admin")
        self.assertEqual(a.get(f"/api/documents/{d['id']}/download").status_code, 404)
        self.assertEqual(a.post(f"/api/documents/{d['id']}/grants",
                                json={"username": "admin", "permission": "read"}).status_code, 404)
        self.assertEqual(a.get("/api/documents").get_json()["total"], 0)

    def test_other_owner_role_gives_nothing(self):
        d = self.make_doc("alice")
        self.assertEqual(self.as_("bob").get("/api/documents").get_json()["total"], 0)
        self.assertEqual(self.as_("bob").get(f"/api/documents/{d['id']}").status_code, 404)


class Roles(TVTestCase):
    """T13"""

    def test_viewer_cannot_upload(self):
        r = self.as_("carol").upload()
        self.assertEqual(r.status_code, 403)

    def test_non_admins_cannot_use_admin_api(self):
        for who in ("alice", "carol"):
            c = self.as_(who)
            for url in ("/api/admin/users", "/api/admin/audit", "/api/admin/audit/verify", "/api/admin/alerts",
                        "/api/admin/summary"):
                self.assertEqual(c.get(url).status_code, 403, (who, url))
            self.assertEqual(c.post("/api/admin/users", json={"username": "evil", "display_name": "E",
                                                               "role": "admin"}).status_code, 403)
            self.assertEqual(c.patch(f"/api/admin/users/{self.ids[who]}", json={"role": "admin"}).status_code, 403)

    def test_viewer_cannot_look_up_directory(self):
        self.assertEqual(self.as_("carol").get("/api/users/lookup?q=al").status_code, 403)
