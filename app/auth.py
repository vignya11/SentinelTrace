"""Authentication: login (+TOTP), logout, registration, recovery, password change, MFA enrolment."""
from __future__ import annotations

import re
import secrets
import sqlite3
from datetime import timedelta
from pathlib import Path

from flask import (Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from . import security as sec
from .db import get_db
from .services import audit, client_ip, create_user, record_event
from .util import clean_text, iso, safe_next, sha256_hex, utcnow, utcnow_dt

bp = Blueprint("auth", __name__)
GENERIC = "Invalid credentials, or too many attempts. Try again later."
USER_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")


def _norm(u: str) -> str:
    return clean_text(u, 64).lower()


def _finish_login(db, user, mfa: bool):
    sec.start_session(db, user["id"], client_ip(), request.headers.get("User-Agent", ""))
    sec.clear_failures(db, f"u:{user['username']}")
    db.execute("UPDATE users SET last_login_at=? WHERE id=?", (utcnow(), user["id"]))
    record_event(db, "login_success", "success", user["username"], user["id"], {"mfa": mfa})
    if user["must_change_password"]:
        flash("Set a new password to continue.", "warn")
        return redirect(url_for("auth.account"))
    return redirect(safe_next(request.args.get("next")) or url_for("main.dashboard"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("main.dashboard"))
    if request.method == "GET":
        return render_template("login.html")
    db, cfg = get_db(), current_app.config
    uname, pw, ip = _norm(request.form.get("username", "")), request.form.get("password", "")[:256], client_ip()
    if sec.blocked(db, f"u:{uname}", cfg["LOCKOUT_THRESHOLD"], cfg["LOCKOUT_BASE_MINUTES"]) or \
       sec.blocked(db, f"ip:{ip}", cfg["IP_THROTTLE_THRESHOLD"], cfg["LOCKOUT_BASE_MINUTES"]):
        recent = db.execute("SELECT 1 FROM auth_events WHERE username=? AND event_type='login_throttled' AND ts>?",
                            (uname, iso(utcnow_dt() - timedelta(seconds=60)))).fetchone()
        if not recent:  # avoid letting an attacker flood the evidence chain
            record_event(db, "login_throttled", "blocked", uname, None, {"reason": "lockout_active"})
        flash(GENERIC, "error")
        return render_template("login.html"), 429
    user = db.execute("SELECT * FROM users WHERE username=?", (uname,)).fetchone()
    ok = check_password_hash(user["password_hash"] if user else sec.DUMMY_HASH, pw)  # constant-ish time
    if not (user and ok and user["status"] == "active"):
        sec.note_failure(db, f"u:{uname}", f"ip:{ip}")
        reason = "unknown_user" if not user else ("disabled" if user["status"] != "active" else "bad_password")
        record_event(db, "login_failure", "failure", uname, user["id"] if user else None, {"reason": reason})
        flash(GENERIC, "error")
        return render_template("login.html"), 401
    if user["totp_enabled"]:
        session.clear()
        session["mfa_uid"], session["mfa_exp"] = user["id"], iso(utcnow_dt() + timedelta(minutes=5))
        return redirect(url_for("auth.login_mfa", next=safe_next(request.args.get("next")) or ""))
    return _finish_login(db, user, mfa=False)


@bp.route("/login/mfa", methods=["GET", "POST"])
def login_mfa():
    if g.user:
        return redirect(url_for("main.dashboard"))
    db, cfg = get_db(), current_app.config
    uid, exp = session.get("mfa_uid"), session.get("mfa_exp")
    if not uid or not exp or iso(utcnow_dt()) > exp:
        session.clear()
        return redirect(url_for("auth.login"))
    if request.method == "GET":
        return render_template("mfa.html")
    user = db.execute("SELECT * FROM users WHERE id=? AND status='active'", (uid,)).fetchone()
    key = f"m:{uid}"
    if not user or sec.blocked(db, key, 5, cfg["LOCKOUT_BASE_MINUTES"]):
        flash(GENERIC, "error")
        return render_template("mfa.html"), 429
    step = sec.totp_verify(user["totp_secret"] or "", request.form.get("code", ""), user["totp_last_step"])
    if step is None:
        sec.note_failure(db, key, f"ip:{client_ip()}")
        record_event(db, "mfa_failure", "failure", user["username"], user["id"], {"reason": "bad_code"})
        flash("That code was not accepted.", "error")
        return render_template("mfa.html"), 401
    db.execute("UPDATE users SET totp_last_step=? WHERE id=?", (step, uid))
    sec.clear_failures(db, key)
    return _finish_login(db, user, mfa=True)


@bp.post("/logout")
@sec.requires()
def logout():
    record_event(get_db(), "logout", "info", g.user["username"], g.user["id"])
    sec.end_session(get_db())
    flash("You have been signed out.", "ok")
    return redirect(url_for("auth.login"))


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("main.dashboard"))
    cfg, db = current_app.config, get_db()
    if not cfg["REGISTRATION_ENABLED"]:
        return render_template("register.html", disabled=True)
    if request.method == "POST":
        u, e, pw = _norm(request.form.get("username", "")), clean_text(request.form.get("email", ""), 255).lower(), request.form.get("password", "")
        errs = sec.validate_password(pw, u)
        if not USER_RE.match(u):
            errs.append("Username: 3-32 characters, letters, digits, . _ -")
        if not EMAIL_RE.match(e):
            errs.append("Enter a valid email address.")
        if not errs:
            try:
                uid = create_user(db, u, e, pw, "analyst")  # least privilege by default
                record_event(db, "account_created", "success", u, uid, {"via": "self_registration"})
                flash("Account created. You can sign in now.", "ok")
                return redirect(url_for("auth.login"))
            except sqlite3.IntegrityError:
                errs.append("Those details cannot be used. Try different ones.")
        for m in errs:
            flash(m, "error")
        return render_template("register.html", disabled=False), 400
    return render_template("register.html", disabled=False)


@bp.route("/forgot", methods=["GET", "POST"])
def forgot():
    if g.user:
        return redirect(url_for("main.dashboard"))
    cfg, db = current_app.config, get_db()
    enabled = cfg["RECOVERY_ADAPTER"] == "file"
    if request.method == "POST" and enabled and sec.rate_ok(f"forgot:{client_ip()}", 5, 600):
        ident = clean_text(request.form.get("identifier", ""), 255).lower()
        u = db.execute("SELECT * FROM users WHERE (username=? OR email=?) AND status='active'", (ident, ident)).fetchone()
        if u:
            token = secrets.token_urlsafe(32)
            db.execute("INSERT INTO password_resets VALUES(?,?,?,0)", (sha256_hex(token.encode()), u["id"], iso(utcnow_dt() + timedelta(minutes=30))))
            out = Path(cfg["OUTBOX_DIR"]); out.mkdir(parents=True, exist_ok=True)
            (out / f"reset-{u['username']}-{utcnow_dt():%Y%m%dT%H%M%S}.txt").write_text(
                f"DEVELOPMENT RECOVERY ADAPTER (file outbox, no email sent)\nUser: {u['username']}\n"
                f"Link (valid 30 min): {request.host_url}reset/{token}\n")
            record_event(db, "password_reset_requested", "info", u["username"], u["id"])
    if request.method == "POST":
        flash("If that account exists and recovery is enabled, reset instructions have been issued.", "ok")
    return render_template("forgot.html", enabled=enabled)


@bp.route("/reset/<token>", methods=["GET", "POST"])
def reset(token):
    if g.user:
        return redirect(url_for("main.dashboard"))
    db = get_db()
    h = sha256_hex(token.encode())
    row = db.execute("SELECT * FROM password_resets WHERE token_hash=? AND used=0 AND expires_at>?", (h, utcnow())).fetchone()
    if not row:
        return render_template("error.html", code=400, title="Link invalid", message="This reset link is invalid, used or expired."), 400
    if request.method == "POST":
        user = db.execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone()
        pw = request.form.get("password", "")
        errs = sec.validate_password(pw, user["username"])
        if errs:
            for m in errs:
                flash(m, "error")
            return render_template("reset.html"), 400
        db.execute("UPDATE users SET password_hash=?, must_change_password=0, updated_at=? WHERE id=?",
                   (generate_password_hash(pw), utcnow(), user["id"]))
        db.execute("UPDATE password_resets SET used=1 WHERE token_hash=?", (h,))
        db.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
        sec.clear_failures(db, f"u:{user['username']}")
        record_event(db, "password_reset_completed", "success", user["username"], user["id"])
        flash("Password updated. Sign in with the new password.", "ok")
        return redirect(url_for("auth.login"))
    return render_template("reset.html")


@bp.get("/account")
@sec.requires()
def account():
    return render_template("account.html", secret=session.get("pending_totp"))


@bp.post("/account/password")
@sec.requires()
def change_password():
    db, u = get_db(), g.user
    cur, new = request.form.get("current_password", ""), request.form.get("new_password", "")
    errs = sec.validate_password(new, u["username"])
    if not check_password_hash(u["password_hash"], cur):
        errs.insert(0, "Current password is incorrect.")
    if errs:
        for m in errs:
            flash(m, "error")
        return redirect(url_for("auth.account"))
    db.execute("UPDATE users SET password_hash=?, must_change_password=0, updated_at=? WHERE id=?",
               (generate_password_hash(new), utcnow(), u["id"]))
    db.execute("DELETE FROM sessions WHERE user_id=?", (u["id"],))  # invalidate every session, incl. this one
    session.clear()
    sec.start_session(db, u["id"], client_ip(), request.headers.get("User-Agent", ""))
    record_event(db, "password_change", "success", u["username"], u["id"])
    flash("Password changed. Other sessions were signed out.", "ok")
    return redirect(url_for("auth.account"))


@bp.post("/account/mfa/start")
@sec.requires()
def mfa_start():
    if g.user["totp_enabled"]:
        return redirect(url_for("auth.account"))
    secret = sec.new_totp_secret()
    get_db().execute("UPDATE users SET totp_secret=?, totp_last_step=0 WHERE id=?", (secret, g.user["id"]))
    session["pending_totp"] = secret
    return redirect(url_for("auth.account"))


@bp.post("/account/mfa/confirm")
@sec.requires()
def mfa_confirm():
    db, u = get_db(), g.user
    step = sec.totp_verify(u["totp_secret"] or "", request.form.get("code", ""), 0)
    if step is None:
        flash("That code was not accepted. Check your authenticator's clock and try again.", "error")
        return redirect(url_for("auth.account"))
    db.execute("UPDATE users SET totp_enabled=1, totp_last_step=? WHERE id=?", (step, u["id"]))
    session.pop("pending_totp", None)
    record_event(db, "mfa_enabled", "success", u["username"], u["id"])
    flash("Two-factor authentication is on.", "ok")
    return redirect(url_for("auth.account"))


@bp.post("/account/mfa/disable")
@sec.requires()
def mfa_disable():
    db, u = get_db(), g.user
    if not check_password_hash(u["password_hash"], request.form.get("current_password", "")):
        flash("Current password is incorrect.", "error")
        return redirect(url_for("auth.account"))
    db.execute("UPDATE users SET totp_enabled=0, totp_secret=NULL WHERE id=?", (u["id"],))
    record_event(db, "mfa_disabled", "info", u["username"], u["id"])
    flash("Two-factor authentication is off.", "warn")
    return redirect(url_for("auth.account"))
