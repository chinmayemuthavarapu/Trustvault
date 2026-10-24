"""Seed demo data: one account per role plus documents and grants that exercise
every rule (read, edit, expired, trashed, private).

    python -m scripts.seed            # seed if the database has no users
    python -m scripts.seed --reset    # wipe data directory first (DESTROYS DATA)

Demo passwords can be overridden with TV_SEED_PASSWORD_<USERNAME> env vars.
"""
import hashlib
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import g  # noqa: E402

from app import audit, create_app, storage  # noqa: E402
from app.config import Config  # noqa: E402
from app.db import connect, iso_in, new_id, now_iso, transaction  # noqa: E402
from app.passwords import hash_password  # noqa: E402

USERS = [
    # username, display name, role, default demo password
    ("admin", "Avery Admin", "admin", "Granite-Harbor-71"),
    ("olivia", "Olivia Park", "owner", "Copper-Lantern-42"),
    ("oscar", "Oscar Mendes", "owner", "Velvet-Orchard-58"),
    ("victor", "Victor Shah", "viewer", "Silent-Meadow-36"),
    ("vera", "Vera Ibrahim", "viewer", "Amber-Compass-29"),
]


def make_pdf(lines: list[str]) -> bytes:
    """A small, valid, single-page PDF with no active content."""
    def esc(s):
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    text = "BT /F1 12 Tf 72 740 Td 16 TL " + " ".join(f"({esc(line)}) Tj T*" for line in lines) + " ET"
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(text) + text.encode("latin-1") + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


DOCS = [
    # owner, title, category, filename, content, description
    ("olivia", "Offer letter: Victor Shah", "HR", "offer-letter-victor-shah.pdf",
     make_pdf(["TrustVault demo - Offer letter", "Candidate: Victor Shah", "Base salary: 128,000 USD",
               "Start date: 2026-11-02", "CONFIDENTIAL"]), "Signed offer letter. Shared with the candidate only."),
    ("olivia", "Salary bands 2026", "HR", "salary-bands-2026.csv",
     b"level,min,max\nL3,98000,121000\nL4,118000,146000\nL5,140000,178000\n", "Private to HR. Not shared with anyone."),
    ("olivia", "Employee handbook", "HR", "employee-handbook.md",
     b"# Employee handbook\n\nWorking hours, leave policy and the code of conduct.\n", "Shared with all staff."),
    ("olivia", "Contractor NDA template", "Legal", "contractor-nda.txt",
     b"MUTUAL NON-DISCLOSURE AGREEMENT\n\nThe parties agree to keep confidential information confidential.\n",
     "Vera can edit until the end of the year."),
    ("oscar", "Q3 budget", "Finance", "q3-budget.csv",
     b"line,amount\nPayroll,410000\nCloud,38000\nTravel,12000\n", "Vera maintains this."),
    ("oscar", "Audit findings FY25", "Audit", "audit-findings-fy25.pdf",
     make_pdf(["TrustVault demo - Audit findings FY25", "Finding 1: access reviews late", "RESTRICTED"]),
     "Victor's access expired; he can no longer open it."),
    ("oscar", "Vendor contract: Northwind", "Contracts", "northwind-msa.pdf",
     make_pdf(["Master services agreement", "Customer: Northwind Traders", "Term: 24 months"]),
     "Private to Oscar."),
    ("oscar", "Old forecast", "Finance", "old-forecast.csv", b"quarter,revenue\nQ1,1.2m\n", "In the trash."),
]

GRANTS = [
    # doc title, username, permission, expires (seconds from now, None = never; negative = already expired)
    ("Offer letter: Victor Shah", "victor", "read", None),
    ("Employee handbook", "victor", "read", None),
    ("Employee handbook", "vera", "read", None),
    ("Contractor NDA template", "vera", "edit", 60 * 86400),
    ("Q3 budget", "vera", "edit", None),
    ("Audit findings FY25", "victor", "read", -86400),
]


def seed(cfg: Config) -> bool:
    app = create_app(cfg)
    conn = connect(cfg.DATABASE)
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        print("Database already has users; not seeding. Use --reset to start over.")
        return False
    users = {}
    with app.test_request_context("/seed"):
        g.db = conn
        g.user = None
        with transaction(conn):
            for username, display, role, default_pw in USERS:
                pw = os.environ.get(f"TV_SEED_PASSWORD_{username.upper()}", default_pw)
                uid = new_id()
                conn.execute("INSERT INTO users (id, username, display_name, role, password_hash, active,"
                             " must_change_password, created_at, password_changed_at) VALUES (?,?,?,?,?,1,0,?,?)",
                             (uid, username, display, role, hash_password(pw), now_iso(), now_iso()))
                users[username] = {"id": uid, "username": username}
                audit.record(conn, "admin.user_create", "allowed", actor=None,
                             target=users[username], details={"role": role, "source": "seed"})
        docs = {}
        for owner, title, category, filename, content, desc in DOCS:
            did, vid = new_id(), new_id()
            blob, wrapped = storage.store(cfg.BLOB_DIR, cfg.MASTER_KEY, did, vid, content)
            with transaction(conn):
                now = now_iso()
                conn.execute("INSERT INTO documents (id, owner_id, title, category, description, created_at,"
                             " updated_at) VALUES (?,?,?,?,?,?,?)", (did, users[owner]["id"], title, category, desc,
                                                                     now, now))
                file_type = {"pdf": "pdf", "csv": "text", "md": "text", "txt": "text"}[filename.rsplit(".", 1)[1]]
                conn.execute("INSERT INTO document_versions (id, document_id, version_no, original_filename,"
                             " file_type, size_bytes, sha256, blob_name, wrapped_key, uploaded_by, created_at)"
                             " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                             (vid, did, 1, filename, file_type, len(content), hashlib.sha256(content).hexdigest(),
                              blob, wrapped, users[owner]["id"], now))
                conn.execute("UPDATE documents SET current_version_id = ? WHERE id = ?", (vid, did))
                audit.record(conn, "document.upload", "allowed", actor=users[owner],
                             document={"id": did, "title": title},
                             details={"version": 1, "filename": filename, "source": "seed"})
            docs[title] = {"id": did, "title": title, "owner": owner}
        with transaction(conn):
            for title, username, perm, expires in GRANTS:
                d = docs[title]
                exp = iso_in(expires) if expires is not None else None
                conn.execute("INSERT INTO grants (id, document_id, user_id, permission, granted_by, created_at,"
                             " expires_at) VALUES (?,?,?,?,?,?,?)",
                             (new_id(), d["id"], users[username]["id"], perm, users[d["owner"]]["id"], now_iso(), exp))
                audit.record(conn, "permission.grant", "allowed", actor=users[d["owner"]], document=d,
                             target=users[username], details={"permission": perm, "expires_at": exp,
                                                              "source": "seed"})
            old = docs["Old forecast"]
            conn.execute("UPDATE documents SET deleted_at = ?, deleted_by = ? WHERE id = ?",
                         (now_iso(), users["oscar"]["id"], old["id"]))
            audit.record(conn, "document.delete", "allowed", actor=users["oscar"], document=old,
                         details={"mode": "moved to trash", "source": "seed"})
        g.pop("db", None)
    conn.close()
    print(f"Seeded {len(USERS)} users and {len(DOCS)} documents into {cfg.DATA_DIR}")
    return True


if __name__ == "__main__":
    if "--reset" in sys.argv:
        # Wipe BEFORE loading config, so development keys are regenerated consistently.
        data_dir = os.environ.get("TV_DATA_DIR", os.path.abspath("data"))
        if os.path.isdir(data_dir):
            shutil.rmtree(data_dir)
    seed(Config())
