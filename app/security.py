"""Sessions, CSRF, RBAC, throttling, password policy, TOTP, in-process rate limiting."""
from __future__ import annotations

import base64
import hmac
import secrets
import struct
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta
from functools import wraps

from flask import abort, current_app, g, jsonify, redirect, request, session, url_for
from werkzeug.security import generate_password_hash

from .db import get_db
from .util import iso, parse_ts, sha256_hex, utcnow, utcnow_dt

ROLE_PERMS = {"analyst": {"dashboard.view", "events.view", "alerts.view", "integrity.view"}}
ROLE_PERMS["investigator"] = ROLE_PERMS["analyst"] | {
    "alerts.ack", "integrity.verify", "cases.manage", "evidence.view", "evidence.export"}
ROLE_PERMS["admin"] = ROLE_PERMS["investigator"] | {
    "users.manage", "settings.manage", "audit.view", "simulator.run", "integrity.checkpoint"}

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
DUMMY_HASH = generate_password_hash("dummy-password-for-constant-time-checks")
COMMON = {"password1234", "123456789012", "qwertyuiop12", "administrator", "letmein12345",
          "password12345", "welcome12345", "changeme1234", "iloveyou1234", "sentineltrace"}


def can(perm: str) -> bool:
    return bool(g.get("user")) and perm in ROLE_PERMS.get(g.user["role"], ())


def is_api_request() -> bool:
    return request.path.startswith(("/api/", "/stream/"))


def api_error(status: int, code: str, message: str):
    resp = jsonify({"error": {"code": code, "message": message}})
    resp.status_code = status
    return resp


# ---- CSRF -----------------------------------------------------------------
def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def csrf_ok() -> bool:
    if request.method in SAFE_METHODS or request.endpoint == "api.ingest":
        return True
    expected = session.get("csrf", "")
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    return bool(expected) and hmac.compare_digest(sent, expected)


# ---- server-side sessions ---------------------------------------------------
def load_user() -> None:
    g.user = None
    sid = session.get("sid")
    if not sid:
        return
    db, cfg, now = get_db(), current_app.config, utcnow_dt()
    h = sha256_hex(sid.encode())
    row = db.execute("SELECT * FROM sessions WHERE sid_hash=?", (h,)).fetchone()
    if row:
        idle = parse_ts(row["last_seen"]) + timedelta(minutes=cfg["SESSION_IDLE_MINUTES"])
        if now > idle or now > parse_ts(row["expires_at"]):
            db.execute("DELETE FROM sessions WHERE sid_hash=?", (h,))
            row = None
    user = db.execute("SELECT * FROM users WHERE id=? AND status='active'", (row["user_id"],)).fetchone() if row else None
    if not user:
        session.pop("sid", None)
        return
    g.user, g.sid_hash = user, h
    if (now - parse_ts(row["last_seen"])).total_seconds() > 60:
        db.execute("UPDATE sessions SET last_seen=? WHERE sid_hash=?", (iso(now), h))


def start_session(db, user_id: int, ip: str, ua: str) -> None:
    """Rotate: drop the old server-side session, clear the cookie state, issue a fresh sid + CSRF token."""
    old = session.get("sid")
    if old:
        db.execute("DELETE FROM sessions WHERE sid_hash=?", (sha256_hex(old.encode()),))
    session.clear()
    sid, now = secrets.token_urlsafe(32), utcnow_dt()
    db.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?,?)", (
        sha256_hex(sid.encode()), user_id, iso(now), iso(now),
        iso(now + timedelta(hours=current_app.config["SESSION_ABSOLUTE_HOURS"])), ip, ua[:300]))
    session["sid"] = sid
    csrf_token()


def end_session(db) -> None:
    sid = session.get("sid")
    if sid:
        db.execute("DELETE FROM sessions WHERE sid_hash=?", (sha256_hex(sid.encode()),))
    session.clear()


# ---- decorators --------------------------------------------------------------
def requires(perm: str | None = None):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not g.user:
                if is_api_request():
                    return api_error(401, "unauthenticated", "Authentication required.")
                return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))
            if perm and not can(perm):
                if is_api_request():
                    return api_error(403, "forbidden", "You do not have permission for this action.")
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


# ---- rate limiting (per process; use a shared store for multi-worker deployments) ----
_hits: dict = defaultdict(deque)
_lock = threading.Lock()


def rate_ok(key: str, limit: int, window: int = 60) -> bool:
    now = time.monotonic()
    with _lock:
        if len(_hits) > 20000:
            _hits.clear()
        dq = _hits[key]
        while dq and dq[0] < now - window:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True


def reset_rate_limits() -> None:
    with _lock:
        _hits.clear()


# ---- login throttling with progressive backoff ------------------------------
def blocked(db, key: str, threshold: int, base_minutes: int) -> bool:
    now = utcnow_dt()
    rows = db.execute("SELECT ts FROM login_attempts WHERE key=? AND ts>=? ORDER BY ts DESC",
                      (key, iso(now - timedelta(hours=24)))).fetchall()
    if len(rows) < threshold:
        return False
    strikes = min(len(rows) - threshold, 10)
    minutes = min(base_minutes * (2 ** strikes), 1440)
    return now < parse_ts(rows[0]["ts"]) + timedelta(minutes=minutes)


def note_failure(db, *keys: str) -> None:
    now = utcnow()
    for k in keys:
        db.execute("INSERT INTO login_attempts(key,ts) VALUES(?,?)", (k, now))
    db.execute("DELETE FROM login_attempts WHERE ts<?", (iso(utcnow_dt() - timedelta(days=2)),))


def clear_failures(db, key: str) -> None:
    db.execute("DELETE FROM login_attempts WHERE key=?", (key,))


# ---- password policy ----------------------------------------------------------
def validate_password(pw: str, username: str = "") -> list[str]:
    errs, minlen = [], current_app.config["PASSWORD_MIN_LENGTH"]
    if len(pw) < minlen:
        errs.append(f"Use at least {minlen} characters.")
    if len(pw) > 128:
        errs.append("Use at most 128 characters.")
    if username and len(username) >= 3 and username.lower() in pw.lower():
        errs.append("Do not include your username.")
    if pw.lower() in COMMON or len(set(pw)) < 5:
        errs.append("That password is too common or too repetitive.")
    return errs


# ---- TOTP (RFC 6238, SHA-1, 30 s step) ----------------------------------------
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def totp_code(secret: str, step: int, digits: int = 6) -> str:
    h = hmac.new(base64.b32decode(secret, casefold=True), struct.pack(">Q", step), "sha1").digest()
    o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


def totp_verify(secret: str, code: str, last_step: int) -> int | None:
    """Accept +/-1 step of drift; reject replay of an already-used step."""
    now = int(time.time() // 30)
    code = (code or "").strip()
    for s in (now - 1, now, now + 1):
        if s > last_step and hmac.compare_digest(totp_code(secret, s), code):
            return s
    return None
