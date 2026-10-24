"""Runtime configuration, read from environment variables.

In production the app refuses to start without real keys, so a forgotten
environment variable can never silently fall back to a known default.
"""
import base64
import os
import secrets


class ConfigError(RuntimeError):
    pass


def _key_from_env(name: str, production: bool, data_dir: str) -> bytes:
    raw = os.environ.get(name)
    if not raw:
        if production:
            raise ConfigError(f"{name} must be set in production (32 random bytes, base64)")
        # Development only: a random key kept in the data directory so local data
        # survives restarts. Production keys never touch the disk next to the data.
        os.makedirs(data_dir, mode=0o700, exist_ok=True)
        path = os.path.join(data_dir, f".dev-{name.lower()}")
        if not os.path.exists(path):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(base64.b64encode(secrets.token_bytes(32)).decode())
        with open(path) as f:
            raw = f.read().strip()
    key = base64.b64decode(raw)
    if len(key) != 32:
        raise ConfigError(f"{name} must decode to exactly 32 bytes")
    return key


class Config:
    CATEGORIES = ["Contracts", "HR", "Finance", "Legal", "Engineering", "Audit", "Other"]

    MAX_UPLOAD_BYTES = 20 * 1024 * 1024
    SESSION_IDLE_SECONDS = 30 * 60
    SESSION_ABSOLUTE_SECONDS = 8 * 60 * 60
    TRASH_RETENTION_DAYS = 30

    LOGIN_MAX_FAILURES_PER_USER = 8     # within the window below
    LOGIN_MAX_FAILURES_PER_IP = 30
    LOGIN_WINDOW_SECONDS = 15 * 60

    API_REQUESTS_PER_MINUTE = 240       # per user (or per IP when anonymous)
    DOWNLOADS_PER_MINUTE = 40           # per user

    def __init__(self, **overrides):
        self.ENV = os.environ.get("TV_ENV", "development")
        production = self.ENV == "production"
        self.DATA_DIR = os.environ.get("TV_DATA_DIR", os.path.abspath("data"))
        self.DATABASE = os.path.join(self.DATA_DIR, "trustvault.db")
        self.BLOB_DIR = os.path.join(self.DATA_DIR, "blobs")
        self.DATA_DIR = overrides.pop("DATA_DIR", self.DATA_DIR)
        self.DATABASE = os.path.join(self.DATA_DIR, "trustvault.db")
        self.BLOB_DIR = os.path.join(self.DATA_DIR, "blobs")
        self.MASTER_KEY = _key_from_env("TV_MASTER_KEY", production, self.DATA_DIR)
        self.AUDIT_KEY = _key_from_env("TV_AUDIT_KEY", production, self.DATA_DIR)
        if self.MASTER_KEY == self.AUDIT_KEY:
            raise ConfigError("TV_MASTER_KEY and TV_AUDIT_KEY must be different keys")
        # Secure cookies need HTTPS. Only switched off for local http development.
        self.COOKIE_SECURE = os.environ.get("TV_COOKIE_SECURE", "1" if production else "0") == "1"
        # Number of reverse proxies in front of the app whose X-Forwarded-For we trust.
        self.TRUSTED_PROXIES = int(os.environ.get("TV_TRUSTED_PROXIES", "0"))
        self.AUDIT_STDOUT = os.environ.get("TV_AUDIT_STDOUT", "1" if production else "0") == "1"
        self.TESTING = False
        for k, v in overrides.items():
            setattr(self, k, v)
        if production and not self.COOKIE_SECURE:
            raise ConfigError("TV_COOKIE_SECURE cannot be disabled in production")
