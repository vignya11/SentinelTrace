"""SentinelTrace application factory."""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from flask import Flask, g, jsonify, render_template, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

from . import db as dbm
from . import security
from .config import load_config

__version__ = "1.0.0"


def create_app(overrides: dict | None = None) -> Flask:
    cfg = load_config(overrides)
    app = Flask(__name__)
    app.config.update(cfg)
    app.config.update(SESSION_COOKIE_NAME="st_session", SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_SECURE=cfg["SESSION_COOKIE_SECURE"], JSON_AS_ASCII=True)
    if not logging.getLogger().handlers:
        logging.basicConfig(level=logging.INFO, format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}')
    for p in (Path(cfg["DATABASE"]).parent, cfg["EVIDENCE_DIR"], cfg["OUTBOX_DIR"]):
        Path(p).mkdir(parents=True, exist_ok=True)
    if cfg["TRUSTED_PROXY_COUNT"]:
        n = cfg["TRUSTED_PROXY_COUNT"]
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)
    conn = dbm.connect(cfg["DATABASE"])
    dbm.migrate(conn, cfg["ENV"])
    conn.close()
    security.reset_rate_limits()

    app.teardown_appcontext(dbm.close_db)

    @app.before_request
    def _gate():
        security.load_user()
        if g.user and g.user["must_change_password"] and request.endpoint not in (
                "auth.account", "auth.change_password", "auth.logout", "static"):
            from flask import redirect, url_for
            return redirect(url_for("auth.account"))
        if request.path.startswith("/api/") and request.endpoint != "api.ingest":
            key = f"api:{g.user['id'] if g.user else request.remote_addr}"
            if not security.rate_ok(key, cfg["API_RATE_PER_MIN"]):
                return security.api_error(429, "rate_limited", "Too many requests.")
        if not security.csrf_ok():
            if security.is_api_request():
                return security.api_error(400, "csrf_failed", "Missing or invalid CSRF token.")
            return render_template("error.html", code=400, title="Request rejected",
                                   message="Your form session expired or was invalid. Go back, refresh the page and try again."), 400

    @app.after_request
    def _headers(resp):
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                                   "connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        if cfg["ENV"] == "production" and cfg["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    def _err(code, title, message):
        def handler(e):
            if security.is_api_request():
                return security.api_error(code, title.lower().replace(" ", "_"), message)
            return render_template("error.html", code=code, title=title, message=message), code
        return handler

    for code, title, msg in ((400, "Bad request", "The request could not be understood."),
                             (403, "Access denied", "Your role does not allow this action."),
                             (404, "Not found", "That page or record does not exist, or you cannot access it."),
                             (405, "Method not allowed", "This action is not supported here."),
                             (413, "Request too large", "The request body is too large."),
                             (429, "Too many requests", "Slow down and try again shortly.")):
        app.register_error_handler(code, _err(code, title, msg))

    @app.errorhandler(500)
    def _500(e):
        logging.getLogger("sentineltrace").exception("unhandled error")  # details to log only, never to the client
        return _err(500, "Server error", "Something went wrong. The error was logged.")(e)

    from . import auth, web, api
    app.register_blueprint(auth.bp)
    app.register_blueprint(web.bp)
    app.register_blueprint(api.bp)

    @app.template_filter("ts")
    def _ts(v):
        return (v or "")[:19].replace("T", " ") + " UTC" if v else "-"

    @app.template_filter("short")
    def _short(v):
        return (v[:10] + "…" + v[-6:]) if v and len(v) > 18 else (v or "")

    app.jinja_env.globals.update(
        csrf_token=security.csrf_token, can=security.can,
        page_url=lambda n: request.path + "?" + "&".join(f"{k}={v}" for k, v in {**request.args.to_dict(), "page": n}.items()))

    @app.context_processor
    def _ctx():
        return {"user": g.get("user"), "env": cfg["ENV"], "version": __version__}

    return app
