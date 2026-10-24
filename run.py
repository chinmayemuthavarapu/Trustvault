"""Start TrustVault locally. Open this file in VS Code and press Run (▶),
or run:  python run.py

First run: creates ./data with demo accounts and documents.
Then open http://127.0.0.1:8000 in your browser. Stop with Ctrl+C.
Production uses gunicorn (see Dockerfile), not this file.
"""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
sys.path.insert(0, ROOT)

missing = []
for mod in ("flask", "cryptography"):
    try:
        __import__(mod)
    except ImportError:
        missing.append(mod)
if missing:
    print(f"Missing packages: {', '.join(missing)}")
    print(f'Install them with:  "{sys.executable}" -m pip install -r requirements.txt')
    sys.exit(1)

from app.config import Config  # noqa: E402
from scripts.seed import USERS, seed  # noqa: E402

cfg = Config()
if not os.path.exists(cfg.DATABASE):
    print("First run: creating demo data in", cfg.DATA_DIR)
    seed(cfg)

from app import create_app  # noqa: E402

app = create_app(cfg)
print("\nTrustVault is running at  http://127.0.0.1:8000")
print("Demo accounts:")
for username, _, role, password in USERS:
    print(f"  {role:7s}  {username:7s}  {password}")
print("Press Ctrl+C to stop.\n")
app.run(host="127.0.0.1", port=8000, debug=False, use_reloader=False)
