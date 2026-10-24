"""T15/T16/T17/T27/T29: sessions, CSRF, brute force, password rules, admin safety."""
from app.db import connect
from tests.helpers import PASSWORD, Client, TVTestCase


class SessionLifecycle(TVTestCase):
    def test_logout_invalidates_the_token_server_side(self):
        c = self.as_("carol")
        token = c.c.get_cookie("tv_session").value
        c.post("/api/auth/logout")
        replay = self.app.test_client()
        replay.set_cookie("tv_session", token)
        self.assertEqual(replay.get("/api/documents").status_code, 401)

    def test_token_stored_hashed(self):
        c = self.as_("carol")
        token = c.c.get_cookie("tv_session").value
        conn = connect(self.cfg.DATABASE)
        hashes = [r[0] for r in conn.execute("SELECT token_hash FROM sessions")]
        conn.close()
        self.assertNotIn(token, hashes)

    def test_cookie_flags(self):
        r = Client(self.app).login("carol")
        cookie = r.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_https_cookie_is_host_prefixed_and_secure(self):
        """T20b: over HTTPS the cookie is __Host- prefixed, so a sibling subdomain cannot set it."""
        self.cfg.COOKIE_SECURE = True
        c = self.app.test_client()
        r = c.post("/api/auth/login", json={"username": "carol", "password": PASSWORD}, base_url="https://localhost")
        cookie = r.headers["Set-Cookie"]
        self.assertTrue(cookie.startswith("__Host-tv_session="))
        self.assertIn("Secure", cookie)
        self.assertIn("Strict-Transport-Security", r.headers)
        self.assertEqual(c.get("/api/documents", base_url="https://localhost").status_code, 200)

    def test_login_rotates_token(self):
        """Session fixation: a token planted before login is not the one used after."""
        c = self.app.test_client()
        c.set_cookie("tv_session", "attacker-chosen")
        c.post("/api/auth/login", json={"username": "carol", "password": PASSWORD})
        self.assertNotEqual(c.get_cookie("tv_session").value, "attacker-chosen")

    def test_signing_in_as_someone_else_ends_the_previous_session(self):
        """On a shared computer, the previous person's session must not stay alive."""
        c = self.app.test_client()
        csrf = c.post("/api/auth/login", json={"username": "alice", "password": PASSWORD}).get_json()["csrf_token"]
        old = c.get_cookie("tv_session").value
        # While a session is live, even the login form needs that session's CSRF token.
        self.assertEqual(c.post("/api/auth/login", json={"username": "bob", "password": PASSWORD}).status_code, 403)
        r = c.post("/api/auth/login", json={"username": "bob", "password": PASSWORD}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r.status_code, 200)
        replay = self.app.test_client()
        replay.set_cookie("tv_session", old)
        self.assertEqual(replay.get("/api/documents").status_code, 401)

    def test_password_change_ends_other_sessions(self):
        phone = Client(self.app)
        phone.login("carol")
        laptop = self.as_("carol")
        r = laptop.post("/api/auth/change-password",
                        json={"current_password": PASSWORD, "new_password": "a-brand-new-passphrase"})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(phone.get("/api/documents").status_code, 401)
        self.assertEqual(laptop.get("/api/documents").status_code, 200)

    def test_expired_session_refused(self):
        c = self.as_("carol")
        conn = connect(self.cfg.DATABASE)
        conn.execute("UPDATE sessions SET last_seen_at = '2000-01-01T00:00:00.000000Z'")
        conn.close()
        self.assertEqual(c.get("/api/documents").status_code, 401)

    def test_inactive_user_session_refused_even_if_row_survives(self):
        """Defence in depth: the session check re-reads users.active on every request."""
        c = self.as_("carol")
        conn = connect(self.cfg.DATABASE)
        conn.execute("UPDATE users SET active = 0 WHERE username = 'carol'")
        conn.close()
        self.assertEqual(c.get("/api/documents").status_code, 401)

    def test_role_change_ends_sessions(self):
        c = self.as_("alice")
        self.as_("admin").patch(f"/api/admin/users/{self.ids['alice']}", json={"role": "viewer"})
        self.assertEqual(c.get("/api/documents").status_code, 401)
        c2 = Client(self.app)
        c2.login("alice")
        self.assertEqual(c2.upload().status_code, 403)


class Csrf(TVTestCase):
    def test_state_change_without_token_refused(self):
        d = self.make_doc("alice")
        c = self.as_("alice")
        r = c.c.delete(f"/api/documents/{d['id']}")  # raw client: no header
        self.assertEqual(r.status_code, 403)
        r = c.c.delete(f"/api/documents/{d['id']}", headers={"X-CSRF-Token": "wrong"})
        self.assertEqual(r.status_code, 403)
        self.assertFalse(c.get(f"/api/documents/{d['id']}").get_json()["in_trash"])
        self.assertTrue(self.audit_rows("security.csrf_rejected", "denied"))

    def test_token_of_another_session_refused(self):
        d = self.make_doc("alice")
        other = self.as_("bob").csrf
        r = self.as_("alice").c.delete(f"/api/documents/{d['id']}", headers={"X-CSRF-Token": other})
        self.assertEqual(r.status_code, 403)

    def test_cross_origin_refused(self):
        d = self.make_doc("alice")
        r = self.as_("alice").delete(f"/api/documents/{d['id']}", headers={"Origin": "https://evil.example"})
        self.assertEqual(r.status_code, 403)

    def test_grant_via_csrf_refused(self):
        d = self.make_doc("alice")
        r = self.as_("alice").c.post(f"/api/documents/{d['id']}/grants",
                                     json={"username": "carol", "permission": "edit"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.as_("carol").get(f"/api/documents/{d['id']}").status_code, 404)


class BruteForce(TVTestCase):
    def test_same_error_for_unknown_user_and_wrong_password(self):
        a = Client(self.app).login("carol", "wrong-password-123")
        b = Client(self.app).login("nobody-here", "wrong-password-123")
        self.assertEqual((a.status_code, a.get_json()), (b.status_code, b.get_json()))

    def test_lockout_after_repeated_failures(self):
        for _ in range(self.cfg.LOGIN_MAX_FAILURES_PER_USER):
            Client(self.app).login("carol", "wrong-password-123")
        r = Client(self.app).login("carol")  # correct password, still locked
        self.assertEqual(r.status_code, 429)
        self.assertTrue(self.audit_rows("auth.login", "denied"))

    def test_disabled_account_cannot_log_in(self):
        self.as_("admin").patch(f"/api/admin/users/{self.ids['carol']}", json={"active": False})
        self.assertEqual(Client(self.app).login("carol").status_code, 401)


class PasswordRules(TVTestCase):
    def test_must_change_password_gates_everything(self):
        r = self.as_("admin").post("/api/admin/users", json={"username": "newbie", "display_name": "New",
                                                             "role": "owner"})
        temp = r.get_json()["temporary_password"]
        c = Client(self.app)
        self.assertEqual(c.login("newbie", temp).status_code, 200)
        self.assertEqual(c.get("/api/documents").status_code, 403)
        self.assertEqual(c.upload().status_code, 403)
        self.assertEqual(c.post("/api/auth/change-password",
                                json={"current_password": temp, "new_password": "short"}).status_code, 400)
        self.assertEqual(c.post("/api/auth/change-password",
                                json={"current_password": temp, "new_password": "newbie-is-my-name!"}).status_code, 400)
        self.assertEqual(c.post("/api/auth/change-password",
                                json={"current_password": temp, "new_password": "plenty-long-phrase"}).status_code, 200)
        self.assertEqual(c.get("/api/documents").status_code, 200)

    def test_wrong_current_password(self):
        r = self.as_("carol").post("/api/auth/change-password",
                                   json={"current_password": "nope-nope-nope", "new_password": "plenty-long-phrase"})
        self.assertEqual(r.status_code, 403)


class AdminSafety(TVTestCase):
    USERS = TVTestCase.USERS + [("admin2", "admin")]

    def test_cannot_disable_or_demote_self(self):
        # A second admin exists, so only the self-protection rule can refuse this.
        a = self.as_("admin")
        self.assertEqual(a.patch(f"/api/admin/users/{self.ids['admin']}", json={"active": False}).status_code, 400)
        self.assertEqual(a.patch(f"/api/admin/users/{self.ids['admin']}", json={"role": "viewer"}).status_code, 400)

    def test_user_patch_rejects_unknown_fields(self):
        r = self.as_("admin").patch(f"/api/admin/users/{self.ids['carol']}", json={"password_hash": "x"})
        self.assertEqual(r.status_code, 400)

    def test_admin_actions_audited(self):
        self.as_("admin").patch(f"/api/admin/users/{self.ids['carol']}", json={"role": "owner"})
        self.assertTrue(self.audit_rows("admin.user_update", "allowed"))
