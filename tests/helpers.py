"""Test fixtures. Each test gets a brand-new data directory, database and keys.

Run:  python -m unittest discover -s tests -v     (or: pytest)
"""
import io
import os
import shutil
import tempfile
import unittest
import zipfile

from app import create_app
from app.config import Config
from app.db import connect, iso_in, new_id, now_iso
from app.passwords import hash_password

PASSWORD = "correct-horse-battery-staple"
_HASH = hash_password(PASSWORD)  # computed once; scrypt is deliberately slow


def pdf_bytes(text="hello"):
    return (b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n% " + text.encode() + b"\n%%EOF\n")


def ooxml_bytes(kind="docx", extra: dict | None = None):
    folder = {"docx": "word/", "xlsx": "xl/", "pptx": "ppt/"}[kind]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr(folder + "document.xml", "<doc>hi</doc>")
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return buf.getvalue()


class Client:
    """Wraps Flask's test client: keeps the session cookie and adds the CSRF header."""

    def __init__(self, app, username=None):
        self.c = app.test_client()
        self.csrf = None
        self.username = username

    def login(self, username, password=PASSWORD):
        r = self.c.post("/api/auth/login", json={"username": username, "password": password})
        if r.status_code == 200:
            self.csrf = r.get_json()["csrf_token"]
            self.username = username
        return r

    def _h(self, headers):
        h = dict(headers or {})
        if self.csrf and "X-CSRF-Token" not in h:
            h["X-CSRF-Token"] = self.csrf
        return h

    def get(self, url, **kw):
        return self.c.get(url, **kw)

    def post(self, url, headers=None, **kw):
        return self.c.post(url, headers=self._h(headers), **kw)

    def patch(self, url, headers=None, **kw):
        return self.c.patch(url, headers=self._h(headers), **kw)

    def delete(self, url, headers=None, **kw):
        return self.c.delete(url, headers=self._h(headers), **kw)

    def upload(self, title="Doc", filename="a.pdf", data=None, category="HR", description=""):
        data = pdf_bytes(title) if data is None else data
        return self.post("/api/documents", data={"title": title, "category": category, "description": description,
                                                 "file": (io.BytesIO(data), filename)},
                         content_type="multipart/form-data")


class TVTestCase(unittest.TestCase):
    USERS = [("admin", "admin"), ("alice", "owner"), ("bob", "owner"), ("carol", "viewer"), ("dave", "viewer")]

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tvtest-")
        self.cfg = Config(DATA_DIR=self.tmp)
        self.cfg.TESTING = True
        self.app = create_app(self.cfg)
        self.ids = {}
        conn = connect(self.cfg.DATABASE)
        for username, role in self.USERS:
            uid = new_id()
            conn.execute("INSERT INTO users (id, username, display_name, role, password_hash, active,"
                         " must_change_password, created_at, password_changed_at) VALUES (?,?,?,?,?,1,0,?,?)",
                         (uid, username, username.title(), role, _HASH, now_iso(), now_iso()))
            self.ids[username] = uid
        conn.close()
        self._clients = {}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- helpers ---------------------------------------------------------
    def as_(self, username) -> Client:
        if username not in self._clients:
            c = Client(self.app)
            r = c.login(username)
            assert r.status_code == 200, r.get_json()
            self._clients[username] = c
        return self._clients[username]

    def db(self):
        return connect(self.cfg.DATABASE)

    def make_doc(self, owner="alice", title="Secret plan", filename="plan.pdf", data=None, category="HR"):
        r = self.as_(owner).upload(title=title, filename=filename, data=data, category=category)
        assert r.status_code == 201, r.get_json()
        return r.get_json()

    def grant(self, doc_id, username, permission="read", owner="alice", expires_at=None):
        body = {"username": username, "permission": permission}
        if expires_at:
            body["expires_at"] = expires_at
        r = self.as_(owner).post(f"/api/documents/{doc_id}/grants", json=body)
        assert r.status_code == 201, r.get_json()
        return [gr for gr in r.get_json()["items"] if gr["user"]["username"] == username][0]

    def audit_rows(self, action=None, outcome=None):
        conn = self.db()
        sql, p = "SELECT * FROM audit_log WHERE 1=1", []
        if action:
            sql += " AND action = ?"
            p.append(action)
        if outcome:
            sql += " AND outcome = ?"
            p.append(outcome)
        rows = [dict(r) for r in conn.execute(sql + " ORDER BY id", p)]
        conn.close()
        return rows

    def expire_grant_now(self, doc_id, username):
        conn = self.db()
        conn.execute("UPDATE grants SET expires_at = ? WHERE document_id = ? AND user_id = ?",
                     (iso_in(-1), doc_id, self.ids[username]))
        conn.close()
