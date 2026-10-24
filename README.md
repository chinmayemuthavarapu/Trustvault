# TrustVault

Confidential document sharing where the wrong person cannot reach a document, and where you can prove who did.

- **Live:** `https://<your-deployment>` ← replace after deploying
- **Threat model:** [THREATS.md](THREATS.md) · **API and who may call each endpoint:** [API.md](API.md) · **Write-up:** [WRITEUP.md](WRITEUP.md) · **AI log:** [PROMPTS.md](PROMPTS.md)

## Demo accounts (seed data)

| Role | Username | Password | What to try |
|---|---|---|---|
| Administrator | `admin` | `Granite-Harbor-71` | Overview, activity log, verify the audit chain, disable a person. Cannot open any document. |
| Document owner | `olivia` | `Copper-Lantern-42` | Owns HR/Legal documents. Share, revoke, set expiry, accept or dismiss suggestions. |
| Document owner | `oscar` | `Velvet-Orchard-58` | Owns Finance/Audit/Contracts. Has one document in the trash. |
| Viewer | `victor` | `Silent-Meadow-36` | Can view the offer letter and handbook. His access to "Audit findings FY25" has **expired**. |
| Viewer | `vera` | `Amber-Compass-29` | Can **edit** "Q3 budget" and "Contractor NDA template" (expires in 60 days). |

Things that are seeded on purpose: a private document per owner, an expired grant, an edit grant with an expiry, and a trashed document whose grantee can no longer see it.

## Roles

| | Administrator | Document owner | Viewer |
|---|---|---|---|
| Upload documents | – | ✓ (becomes owner) | – |
| Open/download a document | only if shared with them | own + shared with them | only if shared with them |
| Edit / new version | if given edit | own + if given edit | if given edit |
| Share, revoke, delete, restore | – | own documents only | – |
| Manage accounts, see audit trail and alerts | ✓ | – | – |

## Run locally (from a clean clone)

**Quickest:** `pip install -r requirements.txt`, then `python run.py` (or open `run.py` in VS Code and press ▶). It seeds demo data on first run and prints the URL and accounts.

**Step by step:**

Needs Python 3.11+.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m scripts.seed --reset        # creates ./data with demo accounts and documents
flask --app wsgi run --port 8000      # http://localhost:8000
```

**Windows / VS Code:** open the `trustvault` folder (the one containing `wsgi.py`), select the venv interpreter, and use the Run and Debug configurations in `.vscode/launch.json` ("seed demo data", then "run server"). Don't press Run on individual files inside `app/`; they are package modules, not scripts. In PowerShell activate the venv with `.venv\Scripts\Activate.ps1`.

Locally, development keys are generated into `./data` and cookies are not `Secure` (plain http). Never use these settings in production.

## Tests

```bash
python -m unittest discover -s tests -t . -v     # or: pytest
python scripts/mutation_check.py                 # deletes each security check in turn; every one must be CAUGHT
python scripts/e2e_browser.py                    # optional, needs Playwright: share → download → revoke in a real browser
```

Each test names the THREATS.md entry it covers. The mutation check is how I know the tests test something: it removes every `authz.require()` call and every rule in `authz.decide()`, plus session, CSRF, audit, storage and upload checks, and runs the suite against each.

## Deploy

The app is one container with a persistent volume at `/data`. It **must** run as a single instance (SQLite has one writer; the rate limiter is in memory).

1. Generate two **different** keys and keep them somewhere safe. Losing `TV_MASTER_KEY` makes every stored file unreadable.
   ```bash
   python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"   # TV_MASTER_KEY
   python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"   # TV_AUDIT_KEY
   ```
2. **Render:** New → Blueprint → this repo (`render.yaml`). Set `TV_MASTER_KEY` and `TV_AUDIT_KEY` in the dashboard. A persistent disk needs a paid instance.
   **Fly.io:** see the comments at the top of `fly.toml`.
   **Any Docker host:** `docker build -t trustvault . && docker run -p 8000:8000 -v tvdata:/data -e TV_MASTER_KEY=... -e TV_AUDIT_KEY=... -e TV_TRUSTED_PROXIES=1 -e TV_SEED_ON_START=1 trustvault` behind an HTTPS proxy.
3. Open `/healthz`, then sign in as `admin` and press **Verify now** on the overview.

| Variable | Default | Meaning |
|---|---|---|
| `TV_ENV` | `development` | `production` refuses to start without keys or with insecure cookies. |
| `TV_MASTER_KEY` | dev: generated | 32 bytes base64. Wraps every file's encryption key. |
| `TV_AUDIT_KEY` | dev: generated | 32 bytes base64. Keys the audit hash chain. Must differ from the master key. |
| `TV_DATA_DIR` | `./data` (`/data` in Docker) | Database and encrypted blobs. |
| `TV_TRUSTED_PROXIES` | `0` | Number of reverse proxies in front of the app. Set to `1` on Render/Fly. Wrong values break rate limiting and audit IPs (THREATS T35). |
| `TV_COOKIE_SECURE` | `1` in production | Only `0` for plain-http local runs. |
| `TV_AUDIT_STDOUT` | `1` in production | Also write each audit entry to stdout so the platform keeps an off-database copy. |
| `TV_SEED_ON_START` | `0` | Seed demo data if the database has no users. |
| `TV_SEED_PASSWORD_<USERNAME>` | – | Override a demo password at seed time. |

**Operating it.** Record the head hash shown by **Verify now** somewhere outside TrustVault (a ticket, an email to yourself) from time to time; a later head that is shorter, or a broken chain, is evidence of tampering. Back up `/data` and the two keys separately.

## Layout

```
app/
  authz.py            the authorisation decision (read this first)
  routes_documents.py documents, versions, downloads, sharing, suggestions
  routes_auth.py      sign-in, sign-out, password change
  routes_admin.py     accounts, audit trail, verification, alerts
  sessions.py         server-side sessions, CSRF, role checks
  audit.py            append-only HMAC-chained audit trail
  storage.py          AES-GCM envelope encryption of files
  validation.py       upload validation
  schema.sql          database schema and append-only triggers
static/               the web app (no build step, no dependencies)
tests/                security tests, mapped to THREATS.md
scripts/seed.py       demo data
scripts/mutation_check.py
docs/ai/              reusable AI context and review prompts
```
