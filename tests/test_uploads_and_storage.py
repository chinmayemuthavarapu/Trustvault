"""T18/T19/T21/T24: what gets in, how it is stored, how it comes out."""
import os

from app.db import connect
from tests.helpers import TVTestCase, ooxml_bytes, pdf_bytes


class UploadValidation(TVTestCase):
    def up(self, filename, data, **kw):
        return self.as_("alice").upload(filename=filename, data=data, **kw)

    def test_accepts_valid_types(self):
        for name, data in [("a.pdf", pdf_bytes()), ("a.docx", ooxml_bytes("docx")), ("a.xlsx", ooxml_bytes("xlsx")),
                           ("a.txt", b"hello"), ("a.csv", b"a,b\n1,2"), ("a.png", b"\x89PNG\r\n\x1a\n" + b"0" * 20)]:
            self.assertEqual(self.up(name, data).status_code, 201, name)

    def test_rejects_disallowed_extensions(self):
        for name in ("evil.html", "evil.svg", "evil.exe", "evil.js", "noext", "evil.docm", "evil.pdf.exe"):
            r = self.up(name, b"<script>alert(1)</script>")
            self.assertEqual(r.status_code, 400, name)

    def test_rejects_content_that_does_not_match_extension(self):
        self.assertEqual(self.up("renamed.pdf", b"MZ\x90\x00 executable").status_code, 400)
        self.assertEqual(self.up("fake.docx", pdf_bytes()).status_code, 400)
        self.assertEqual(self.up("zip.docx", ooxml_bytes("xlsx")).status_code, 400)
        self.assertEqual(self.up("img.png", b"<svg onload=alert(1)>").status_code, 400)

    def test_rejects_active_pdf(self):
        r = self.up("js.pdf", b"%PDF-1.4\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>")
        self.assertEqual(r.status_code, 400)
        self.assertIn("active content", r.get_json()["error"])

    def test_rejects_macros(self):
        r = self.up("macro.docx", ooxml_bytes("docx", {"word/vbaProject.bin": b"\x00" * 10}))
        self.assertEqual(r.status_code, 400)

    def test_rejects_zip_bomb(self):
        r = self.up("bomb.docx", ooxml_bytes("docx", {"word/big.xml": "A" * 5_000_000}))
        self.assertEqual(r.status_code, 400)

    def test_rejects_binary_text_and_empty(self):
        self.assertEqual(self.up("a.txt", b"abc\x00def").status_code, 400)
        self.assertEqual(self.up("a.txt", b"\xff\xfe\xfa").status_code, 400)
        self.assertEqual(self.up("a.pdf", b"").status_code, 400)

    def test_rejects_oversize(self):
        big = pdf_bytes() + b"0" * (self.cfg.MAX_UPLOAD_BYTES + 10)
        self.assertIn(self.up("big.pdf", big).status_code, (400, 413))

    def test_filename_is_cleaned(self):
        # CR/LF cannot travel inside a multipart filename; clean_filename is tested for them directly below.
        r = self.up("../../etc/pass\u202ewd\tX-Evil: 1.pdf", pdf_bytes())
        self.assertEqual(r.status_code, 201, r.get_json())
        name = r.get_json()["current_version"]["filename"]
        for bad in ("/", "..", "\r", "\n", "\u202e"):
            self.assertNotIn(bad, name)
        d = self.as_("alice").get(f"/api/documents/{r.get_json()['id']}/download")
        self.assertNotIn("X-Evil", d.headers)

    def test_clean_filename_strips_header_injection(self):
        from app.validation import clean_filename
        self.assertEqual(clean_filename("a\r\nX-Evil: 1.pdf"), "aX-Evil: 1.pdf")
        self.assertEqual(clean_filename("..\\..\\boot.ini.pdf"), "boot.ini.pdf")

    def test_validation_failures_audited(self):
        self.up("evil.exe", b"MZ")
        self.assertTrue(self.audit_rows("document.upload", "denied"))

    def test_unknown_form_fields_rejected(self):
        r = self.as_("alice").post("/api/documents", data={"title": "x", "category": "HR", "owner_id": self.ids["bob"]},
                                   content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)

    def test_bad_category_and_title(self):
        self.assertEqual(self.up("a.pdf", pdf_bytes(), category="Secret").status_code, 400)
        self.assertEqual(self.as_("alice").upload(title="", filename="a.pdf").status_code, 400)


class SafeDownloads(TVTestCase):
    def test_download_cannot_render_in_browser(self):
        d = self.make_doc("alice", filename="page.txt", data=b"<html><script>alert(1)</script></html>")
        r = self.as_("alice").get(f"/api/documents/{d['id']}/download")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["Content-Type"], "application/octet-stream")
        self.assertTrue(r.headers["Content-Disposition"].startswith("attachment"))
        self.assertIn("sandbox", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("no-store", r.headers["Cache-Control"])

    def test_download_is_audited_with_version_and_hash(self):
        d = self.make_doc("alice")
        self.as_("alice").get(f"/api/documents/{d['id']}/download")
        row = self.audit_rows("document.download", "allowed")[-1]
        self.assertIn("sha256", row["details"])
        self.assertEqual(row["actor_username"], "alice")

    def test_versions_download_by_number(self):
        d = self.make_doc("alice", data=pdf_bytes("one"))
        self.as_("alice").post(f"/api/documents/{d['id']}/versions",
                               data={"file": (__import__("io").BytesIO(pdf_bytes("two")), "v2.pdf")},
                               content_type="multipart/form-data")
        versions = self.as_("alice").get(f"/api/documents/{d['id']}").get_json()["versions"]
        self.assertEqual([v["version_no"] for v in versions], [2, 1])
        old = self.as_("alice").get(f"/api/documents/{d['id']}/download?version={versions[1]['id']}")
        self.assertIn(b"one", old.get_data())


class EncryptedStorage(TVTestCase):
    def test_files_on_disk_are_ciphertext(self):
        marker = b"PLAINTEXT-MARKER-91c2"
        self.make_doc("alice", data=pdf_bytes() + marker)
        for name in os.listdir(self.cfg.BLOB_DIR):
            with open(os.path.join(self.cfg.BLOB_DIR, name), "rb") as f:
                self.assertNotIn(marker, f.read())

    def _blob(self, doc_id):
        conn = connect(self.cfg.DATABASE)
        r = conn.execute("SELECT blob_name FROM document_versions WHERE document_id = ?", (doc_id,)).fetchone()
        conn.close()
        return os.path.join(self.cfg.BLOB_DIR, r[0])

    def test_tampered_blob_is_not_served(self):
        d = self.make_doc("alice")
        path = self._blob(d["id"])
        with open(path, "r+b") as f:
            f.seek(20)
            f.write(b"\x00\x01\x02")
        r = self.as_("alice").get(f"/api/documents/{d['id']}/download")
        self.assertEqual(r.status_code, 500)
        self.assertTrue(self.audit_rows("document.download", "error"))

    def test_swapped_blob_fails(self):
        """Copying a secret blob over a file I can read must not give me the secret."""
        secret = self.make_doc("bob", data=pdf_bytes() + b"BOB-SECRET")
        mine = self.make_doc("alice")
        self.grant(mine["id"], "carol")
        with open(self._blob(secret["id"]), "rb") as src, open(self._blob(mine["id"]), "wb") as dst:
            dst.write(src.read())
        r = self.as_("carol").get(f"/api/documents/{mine['id']}/download")
        self.assertEqual(r.status_code, 500)
        self.assertNotIn(b"BOB-SECRET", r.get_data())

    def test_moving_ciphertext_and_wrapped_key_between_documents_fails(self):
        """Someone with database write access points my version row at Bob's blob AND Bob's
        wrapped key. The associated data binds both to Bob's document id, so it will not decrypt."""
        secret = self.make_doc("bob", data=pdf_bytes() + b"BOB-SECRET")
        mine = self.make_doc("alice")
        conn = connect(self.cfg.DATABASE)
        src = conn.execute("SELECT blob_name, wrapped_key FROM document_versions WHERE document_id = ?",
                           (secret["id"],)).fetchone()
        conn.execute("UPDATE document_versions SET blob_name = 'x' || blob_name WHERE document_id = ?", (secret["id"],))
        conn.execute("UPDATE document_versions SET blob_name = ?, wrapped_key = ? WHERE document_id = ?",
                     (src["blob_name"], src["wrapped_key"], mine["id"]))
        conn.close()
        r = self.as_("alice").get(f"/api/documents/{mine['id']}/download")
        self.assertEqual(r.status_code, 500)
        self.assertNotIn(b"BOB-SECRET", r.get_data())

