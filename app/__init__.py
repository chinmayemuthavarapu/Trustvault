"""TrustVault application factory."""
import os

from flask import Flask, abort, g, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from . import audit
from .config import Config
from .db import close_db, connect, init_db, iso_in, transaction
from .ratelimit import RateLimiter
from .sessions import check_csrf, load_user

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


def create_app(config: Config | None = None) -> Flask:
    cfg = config or Config()
    app = Flask(__name__, static_folder=None)
    app.config["TV"] = cfg
    app.config["MAX_CONTENT_LENGTH"] = cfg.MAX_UPLOAD_BYTES + 64 * 1024
    app.config["JSON_SORT_KEYS"] = False
    app.config["TESTING"] = cfg.TESTING
    app.extensions["tv_limiter"] = RateLimiter()

    if cfg.TRUSTED_PROXIES:
        # Only trust X-Forwarded-* from the number of proxies we actually run behind;
        # otherwise a client could forge its IP into the audit trail and dodge rate limits.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=cfg.TRUSTED_PROXIES, x_proto=cfg.TRUSTED_PROXIES)

    os.makedirs(cfg.DATA_DIR, mode=0o700, exist_ok=True)
    os.makedirs(cfg.BLOB_DIR, mode=0o700, exist_ok=True)
    init_db(cfg.DATABASE)

    from .routes_admin import bp as admin_bp
    from .routes_auth import bp as auth_bp
    from .routes_documents import bp as docs_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(docs_bp)
    app.register_blueprint(admin_bp)
    app.teardown_appcontext(close_db)

    @app.before_request
    def _before():
        if not request.path.startswith("/api/"):
            return
        load_user()
        key = f"u:{g.user['id']}" if g.get("user") else f"ip:{request.remote_addr}"
        if not app.extensions["tv_limiter"].hit(key, cfg.API_REQUESTS_PER_MINUTE):
            abort(429, description="Too many requests. Slow down and try again in a minute.")
        check_csrf()

    @app.after_request
    def _headers(resp):
        h = resp.headers
        h.setdefault("Content-Security-Policy", CSP)
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        if cfg.COOKIE_SECURE:
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.path.startswith("/api/"):
            h["Cache-Control"] = "no-store, private"
        h.pop("Server", None)
        return resp

    @app.errorhandler(HTTPException)
    def _http_error(e):
        if e.code == 401 and request.path.startswith("/api/documents"):
            # Refused attempts are evidence too, including anonymous ones.
            try:
                audit.record_standalone("document.access", "denied",
                                        details={"reason": "not signed in", "path": request.path[:200],
                                                 "method": request.method})
            except Exception:
                pass
        messages = {401: "Sign in to continue.", 404: "Not found.", 405: "Method not allowed.",
                    413: "The upload is too large."}
        desc = e.description if e.description and e.description != type(e).description else messages.get(e.code, e.name)
        return jsonify({"error": desc}), e.code

    @app.errorhandler(Exception)
    def _unhandled(e):
        app.logger.exception("Unhandled error")
        return jsonify({"error": "Something went wrong on the server. The action was not completed."}), 500

    @app.get("/")
    def index():
        resp = send_from_directory(STATIC_DIR, "index.html")
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    @app.get("/static/<path:name>")
    def static_files(name):
        resp = send_from_directory(STATIC_DIR, name)  # safe_join inside: no traversal
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    @app.get("/healthz")
    def health():
        return jsonify({"ok": True})

    _retention_sweep(app)
    return app


def _retention_sweep(app):
    """Permanently destroy documents that have been in the trash past retention.
    Runs at startup; a scheduled job would be the production version (see THREATS.md)."""
    cfg = app.config["TV"]
    from .routes_documents import purge
    with app.test_request_context("/internal/retention"):
        conn = connect(cfg.DATABASE)
        g.db = conn
        g.user = None
        cutoff = iso_in(-cfg.TRASH_RETENTION_DAYS * 86400)
        rows = conn.execute("SELECT * FROM documents WHERE deleted_at IS NOT NULL AND purged_at IS NULL"
                            " AND deleted_at < ?", (cutoff,)).fetchall()
        for doc in rows:
            purge(conn, doc, f"retention: in trash more than {cfg.TRASH_RETENTION_DAYS} days")
        g.pop("db", None)
        conn.close()
