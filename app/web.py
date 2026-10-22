"""Server-rendered pages. Every route enforces RBAC server-side; every object lookup is ownership-checked."""
from __future__ import annotations

import json
import re
import secrets
import sqlite3
from pathlib import Path

from flask import (Blueprint, abort, current_app, flash, g, redirect, render_template, request, send_file, url_for)

from . import alerts as alerts_mod
from . import evidence as ev_mod
from . import security as sec
from .chain import create_checkpoint, verify_chain, verify_linked
from .db import get_db
from .services import (AUDIT_FIELDS, audit, correlate, create_user, dashboard_metrics, get_setting, next_case_ref,
                       query_events, record_event, set_setting, simulate, parse_filters, event_public)
from .util import clean_text, sha256_hex, utcnow

bp = Blueprint("main", __name__)
UUID_RE = re.compile(r"^[0-9a-f-]{36}$")
SEVERITIES = ("low", "medium", "high", "critical")
CASE_STATES = ("open", "in_review", "closed")


def _chain():
    return current_app.config["CHAIN_ID"]


def _case_or_404(db, ref):
    c = db.execute("SELECT * FROM cases WHERE ref=?", (ref,)).fetchone()
    if not c or (g.user["role"] != "admin" and c["owner_id"] != g.user["id"]):
        abort(404)  # 404 not 403: do not reveal that the object exists
    return c


def _evidence_or_404(db, ref):
    e = db.execute("SELECT e.*, u.username creator FROM evidence e JOIN users u ON u.id=e.created_by WHERE ref=?", (ref,)).fetchone()
    if not e:
        abort(404)
    if g.user["role"] != "admin" and e["created_by"] != g.user["id"]:
        owned = e["case_id"] and db.execute("SELECT 1 FROM cases WHERE id=? AND owner_id=?", (e["case_id"], g.user["id"])).fetchone()
        if not owned:
            abort(404)
    return e


def _my_cases(db):
    if g.user["role"] == "admin":
        return db.execute("SELECT * FROM cases ORDER BY id DESC").fetchall()
    return db.execute("SELECT * FROM cases WHERE owner_id=? ORDER BY id DESC", (g.user["id"],)).fetchall()


@bp.get("/")
def landing():
    return render_template("landing.html")


@bp.get("/dashboard")
@sec.requires("dashboard.view")
def dashboard():
    db = get_db()
    m = dashboard_metrics(db)
    recent = db.execute("SELECT * FROM auth_events WHERE chain_id=? ORDER BY id DESC LIMIT 12", (_chain(),)).fetchall()
    alerts = db.execute("SELECT * FROM alerts WHERE chain_id=? AND status='open' ORDER BY id DESC LIMIT 5", (_chain(),)).fetchall()
    return render_template("dashboard.html", m=m, recent=recent, alerts=alerts, last_id=recent[0]["id"] if recent else 0)


@bp.get("/events")
@sec.requires("events.view")
def events():
    res = query_events(get_db(), request.args)
    for e in res["errors"]:
        flash(e, "error")
    types = [r[0] for r in get_db().execute("SELECT DISTINCT event_type FROM auth_events WHERE chain_id=? ORDER BY 1", (_chain(),))]
    return render_template("events.html", res=res, types=types, f=request.args)


@bp.get("/events/<event_id>")
@sec.requires("events.view")
def event_detail(event_id):
    db = get_db()
    r = db.execute("SELECT * FROM auth_events WHERE event_id=?", (event_id,)).fetchone() if UUID_RE.match(event_id) else None
    if not r:
        abort(404)
    cases = db.execute("SELECT c.ref, c.title FROM case_events ce JOIN cases c ON c.id=ce.case_id WHERE ce.event_id=?" +
                       ("" if g.user["role"] == "admin" else " AND c.owner_id=?"),
                       (event_id,) if g.user["role"] == "admin" else (event_id, g.user["id"])).fetchall()
    return render_template("event_detail.html", e=r, meta=json.loads(r["metadata"]), cases=cases,
                           my_cases=_my_cases(db) if sec.can("cases.manage") else [])


@bp.post("/events/<event_id>/to-case")
@sec.requires("cases.manage")
def event_to_case(event_id):
    db = get_db()
    case = _case_or_404(db, request.form.get("case_ref", ""))
    flash(f"Linked {_add_events(db, case, [event_id])} event(s) to {case['ref']}.", "ok")
    return redirect(url_for("main.case_detail", ref=case["ref"]))


# ---- integrity ---------------------------------------------------------------------------
@bp.get("/integrity")
@sec.requires("integrity.view")
def integrity():
    db, cfg = get_db(), current_app.config
    run = db.execute("SELECT * FROM integrity_runs WHERE chain_id=? ORDER BY id DESC LIMIT 1", (_chain(),)).fetchone()
    cps = db.execute("SELECT * FROM checkpoints WHERE chain_id=? ORDER BY id DESC LIMIT 10", (_chain(),)).fetchall()
    tail = db.execute("SELECT chain_seq, record_hash, prev_hash, event_type, ts FROM auth_events WHERE chain_id=? ORDER BY chain_seq DESC LIMIT 4", (_chain(),)).fetchall()
    return render_template("integrity.html", run=run, findings=json.loads(run["findings"]) if run else [],
                           warnings=json.loads(run["warnings"]) if run else [], cps=cps, tail=tail,
                           key_set=bool(cfg["CHECKPOINT_KEY"]), ext_set=bool(cfg["CHECKPOINT_EXTERNAL_PATH"]))


def run_verification(db, user_id):
    cfg = current_app.config
    r = verify_chain(db, _chain(), cfg["CHECKPOINT_KEY"], cfg["CHECKPOINT_EXTERNAL_PATH"])
    db.execute("INSERT INTO integrity_runs(ts,chain_id,records_checked,ok,findings,warnings,run_by) VALUES(?,?,?,?,?,?,?)",
               (r["verified_at"], _chain(), r["records_checked"], int(r["ok"]), json.dumps(r["findings"]), json.dumps(r["warnings"]), user_id))
    audit(db, "integrity.verify", _chain(), f"checked={r['records_checked']} ok={r['ok']} findings={len(r['findings'])}")
    return r


@bp.post("/integrity/verify")
@sec.requires("integrity.verify")
def integrity_verify():
    r = run_verification(get_db(), g.user["id"])
    flash(f"Verified {r['records_checked']} records: " + ("no findings." if r["ok"] else f"{len(r['findings'])} finding(s)."), "ok" if r["ok"] else "error")
    return redirect(url_for("main.integrity"))


@bp.post("/integrity/checkpoint")
@sec.requires("integrity.checkpoint")
def integrity_checkpoint():
    cfg, db = current_app.config, get_db()
    try:
        cp = create_checkpoint(db, _chain(), cfg["CHECKPOINT_KEY"], cfg["CHECKPOINT_EXTERNAL_PATH"], g.user["id"])
        audit(db, "integrity.checkpoint", _chain(), f"seq={cp['chain_seq']} signed={cp['signed']}")
        flash(f"Checkpoint recorded at sequence {cp['chain_seq']}.", "ok")
    except ValueError as e:
        flash(str(e), "error")
    return redirect(url_for("main.integrity"))


# ---- alerts ----------------------------------------------------------------------------
@bp.get("/alerts")
@sec.requires("alerts.view")
def alerts():
    db, st = get_db(), request.args.get("status", "open")
    where, p = "chain_id=?", [_chain()]
    if st in ("open", "acknowledged", "dismissed"):
        where += " AND status=?"; p.append(st)
    sev = request.args.get("severity", "")
    if sev in ("low", "medium", "high"):
        where += " AND severity=?"; p.append(sev)
    rows = db.execute(f"SELECT * FROM alerts WHERE {where} ORDER BY id DESC LIMIT 200", p).fetchall()
    return render_template("alerts.html", rows=rows, status=st, rules=alerts_mod.get_rules(db))


@bp.get("/alerts/<int:aid>")
@sec.requires("alerts.view")
def alert_detail(aid):
    db = get_db()
    a = db.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone() or abort(404)
    ids = json.loads(a["evidence"])
    evs = db.execute(f"SELECT * FROM auth_events WHERE event_id IN ({','.join('?' * len(ids))}) ORDER BY id", ids).fetchall() if ids else []
    return render_template("alert_detail.html", a=a, evs=evs, rules=alerts_mod.get_rules(db),
                           my_cases=_my_cases(db) if sec.can("cases.manage") else [])


@bp.post("/alerts/<int:aid>/status")
@sec.requires("alerts.ack")
def alert_status(aid):
    db, st = get_db(), request.form.get("status")
    if st not in ("acknowledged", "dismissed", "open"):
        abort(400)
    if not db.execute("SELECT 1 FROM alerts WHERE id=?", (aid,)).fetchone():
        abort(404)
    db.execute("UPDATE alerts SET status=?, handled_by=?, handled_at=? WHERE id=?", (st, g.user["id"], utcnow(), aid))
    audit(db, "alert.status", f"alert:{aid}", st)
    return redirect(url_for("main.alert_detail", aid=aid))


def _add_events(db, case, event_ids):
    n = 0
    for eid in event_ids:
        if UUID_RE.match(eid) and db.execute("SELECT 1 FROM auth_events WHERE event_id=?", (eid,)).fetchone():
            try:
                db.execute("INSERT INTO case_events(case_id,event_id,added_by,added_at) VALUES(?,?,?,?)", (case["id"], eid, g.user["id"], utcnow()))
                n += 1
            except sqlite3.IntegrityError:
                pass  # already linked
    db.execute("UPDATE cases SET updated_at=? WHERE id=?", (utcnow(), case["id"]))
    return n


@bp.post("/alerts/<int:aid>/to-case")
@sec.requires("cases.manage")
def alert_to_case(aid):
    db = get_db()
    a = db.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone() or abort(404)
    case = _case_or_404(db, request.form.get("case_ref", ""))
    n = _add_events(db, case, json.loads(a["evidence"]))
    flash(f"Linked {n} event(s) to {case['ref']}. Original records are unchanged.", "ok")
    return redirect(url_for("main.case_detail", ref=case["ref"]))


# ---- cases -------------------------------------------------------------------------------
@bp.route("/cases", methods=["GET", "POST"])
@sec.requires("cases.manage")
def cases():
    db = get_db()
    if request.method == "POST":
        title, sev = clean_text(request.form.get("title", ""), 160), request.form.get("severity", "")
        if len(title) < 3 or sev not in SEVERITIES:
            flash("Enter a title (3+ characters) and a severity.", "error")
            return redirect(url_for("main.cases"))
        ref, now = next_case_ref(db), utcnow()
        db.execute("INSERT INTO cases(ref,title,status,severity,owner_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", (ref, title, "open", sev, g.user["id"], now, now))
        audit(db, "case.create", ref, title)
        return redirect(url_for("main.case_detail", ref=ref))
    rows = db.execute("SELECT c.*, u.username owner, (SELECT COUNT(*) FROM case_events WHERE case_id=c.id) n_events FROM cases c "
                      "JOIN users u ON u.id=c.owner_id" + ("" if g.user["role"] == "admin" else " WHERE c.owner_id=?") + " ORDER BY c.id DESC",
                      () if g.user["role"] == "admin" else (g.user["id"],)).fetchall()
    return render_template("cases.html", rows=rows)


@bp.get("/cases/<ref>")
@sec.requires("cases.manage")
def case_detail(ref):
    db = get_db()
    c = _case_or_404(db, ref)
    evs = db.execute("SELECT e.* FROM case_events ce JOIN auth_events e ON e.event_id=ce.event_id WHERE ce.case_id=? ORDER BY e.ts", (c["id"],)).fetchall()
    notes = db.execute("SELECT n.*, u.username author FROM case_notes n JOIN users u ON u.id=n.author_id WHERE case_id=? ORDER BY n.id", (c["id"],)).fetchall()
    timeline = sorted([{"ts": e["ts"], "kind": "event", "text": f"{e['event_type']} ({e['outcome']}) {e['username'] or '-'} from {e['source_ip']}", "id": e["event_id"]} for e in evs] +
                      [{"ts": n["created_at"], "kind": n["kind"], "text": f"{n['author']}: {n['body']}", "id": None} for n in notes], key=lambda x: x["ts"])
    arts = db.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id DESC", (c["id"],)).fetchall()
    owner = db.execute("SELECT username FROM users WHERE id=?", (c["owner_id"],)).fetchone()["username"]
    return render_template("case_detail.html", c=c, evs=evs, notes=notes, timeline=timeline, arts=arts, owner=owner,
                           corr=correlate(db, [e["event_id"] for e in evs]), states=CASE_STATES)


@bp.post("/cases/<ref>/notes")
@sec.requires("cases.manage")
def case_note(ref):
    db = get_db(); c = _case_or_404(db, ref)
    kind, body = request.form.get("kind", ""), clean_text(request.form.get("body", ""), 4000)
    if kind not in ("note", "hypothesis", "finding") or not body:
        flash("Choose a type and write some text.", "error")
    else:
        db.execute("INSERT INTO case_notes(case_id,author_id,kind,body,created_at) VALUES(?,?,?,?,?)", (c["id"], g.user["id"], kind, body, utcnow()))
        db.execute("UPDATE cases SET updated_at=? WHERE id=?", (utcnow(), c["id"]))
    return redirect(url_for("main.case_detail", ref=ref))


@bp.post("/cases/<ref>/events")
@sec.requires("cases.manage")
def case_events(ref):
    db = get_db(); c = _case_or_404(db, ref)
    ids = [x.strip().lower() for x in re.split(r"[\s,]+", request.form.get("event_ids", "")) if x.strip()][:200]
    flash(f"Linked {_add_events(db, c, ids)} event(s). Unknown or duplicate IDs were skipped.", "ok")
    return redirect(url_for("main.case_detail", ref=ref))


@bp.post("/cases/<ref>/status")
@sec.requires("cases.manage")
def case_status(ref):
    db = get_db(); c = _case_or_404(db, ref)
    st = request.form.get("status")
    if st not in CASE_STATES:
        abort(400)
    db.execute("UPDATE cases SET status=?, updated_at=? WHERE id=?", (st, utcnow(), c["id"]))
    audit(db, "case.status", ref, st)
    return redirect(url_for("main.case_detail", ref=ref))


@bp.post("/cases/<ref>/report")
@sec.requires("evidence.export")
def case_report(ref):
    db = get_db(); c = _case_or_404(db, ref)
    notes = db.execute("SELECT n.kind, n.body, n.created_at, u.username author FROM case_notes n JOIN users u ON u.id=n.author_id WHERE case_id=? ORDER BY n.id", (c["id"],)).fetchall()
    ids = [r[0] for r in db.execute("SELECT event_id FROM case_events WHERE case_id=?", (c["id"],))]
    if not ids:
        flash("Link at least one event before exporting a report.", "error")
        return redirect(url_for("main.case_detail", ref=ref))
    where = f"chain_id=? AND event_id IN ({','.join('?' * len(ids))})"
    try:
        er = ev_mod.create_export(db, g.user, "pdf", where, [_chain()] + ids, {"case": ref}, case=c, notes=[dict(n) for n in notes], kind="case_report")
    except ValueError as e:
        flash(str(e), "error"); return redirect(url_for("main.case_detail", ref=ref))
    audit(db, "evidence.export", er, f"case report for {ref}")
    return redirect(url_for("main.evidence_detail", ref=er))


# ---- evidence --------------------------------------------------------------------------------
@bp.get("/evidence")
@sec.requires("evidence.view")
def evidence():
    db = get_db()
    q = "SELECT e.*, u.username creator FROM evidence e JOIN users u ON u.id=e.created_by"
    rows = db.execute(q + " ORDER BY e.id DESC LIMIT 200").fetchall() if g.user["role"] == "admin" else db.execute(
        q + " WHERE e.created_by=? OR e.case_id IN (SELECT id FROM cases WHERE owner_id=?) ORDER BY e.id DESC LIMIT 200", (g.user["id"], g.user["id"])).fetchall()
    types = [r[0] for r in db.execute("SELECT DISTINCT event_type FROM auth_events WHERE chain_id=? ORDER BY 1", (_chain(),))]
    return render_template("evidence.html", rows=rows, types=types, cases=_my_cases(db))


@bp.post("/evidence/export")
@sec.requires("evidence.export")
def evidence_export():
    db, fmt = get_db(), request.form.get("format", "json")
    if fmt not in ("json", "csv", "pdf"):
        abort(400)
    sql, params, f, errs = parse_filters(request.form)
    if errs:
        for e in errs:
            flash(e, "error")
        return redirect(url_for("main.evidence"))
    case = _case_or_404(db, request.form["case_ref"]) if request.form.get("case_ref") else None
    try:
        ref = ev_mod.create_export(db, g.user, fmt, sql, params, f, case=case)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("main.evidence"))
    audit(db, "evidence.export", ref, f"{fmt} filters={json.dumps(f, sort_keys=True)}")
    flash("Evidence snapshot created and hashed.", "ok")
    return redirect(url_for("main.evidence_detail", ref=ref))


@bp.get("/evidence/<ref>")
@sec.requires("evidence.view")
def evidence_detail(ref):
    db = get_db(); e = _evidence_or_404(db, ref)
    rows = db.execute("SELECT * FROM custody WHERE evidence_id=? ORDER BY id", (e["id"],)).fetchall()
    findings = verify_linked(rows, fields=ev_mod.CUSTODY_FIELDS)
    return render_template("evidence_detail.html", e=e, rows=rows, findings=findings, filters=json.loads(e["filters"]))


@bp.get("/evidence/<ref>/download")
@sec.requires("evidence.export")
def evidence_download(ref):
    db = get_db(); e = _evidence_or_404(db, ref)
    if ev_mod.file_digest(e) != e["sha256"]:
        ev_mod.custody_add(db, e["id"], "accessed", "Download REFUSED: file digest does not match recorded SHA-256")
        audit(db, "evidence.download_refused", ref, "digest mismatch")
        return render_template("error.html", code=409, title="Integrity check failed",
                               message="The stored file no longer matches its recorded SHA-256 digest, so it was not served."), 409
    ev_mod.custody_add(db, e["id"], "downloaded", f"Downloaded by {g.user['username']} from {request.remote_addr}")
    audit(db, "evidence.download", ref)
    return send_file(Path(current_app.config["EVIDENCE_DIR"]) / e["filename"], mimetype=e["media_type"], as_attachment=True, download_name=e["filename"])


@bp.post("/evidence/<ref>/custody")
@sec.requires("evidence.export")
def custody_note(ref):
    db = get_db(); e = _evidence_or_404(db, ref)
    action, detail = request.form.get("action", ""), clean_text(request.form.get("detail", ""), 500)
    if action not in ("transferred", "note") or len(detail) < 3:
        flash("Choose transfer or note and describe it (who, to whom, why).", "error")
    else:
        ev_mod.custody_add(db, e["id"], action, detail)
        audit(db, "evidence.custody", ref, action)
    return redirect(url_for("main.evidence_detail", ref=ref))


@bp.post("/evidence/<ref>/verify")
@sec.requires("evidence.export")
def evidence_verify(ref):
    db = get_db(); e = _evidence_or_404(db, ref)
    d = ev_mod.file_digest(e)
    ok = d == e["sha256"]
    ev_mod.custody_add(db, e["id"], "verified", "Digest MATCHES recorded SHA-256" if ok else f"Digest MISMATCH (found {d or 'file missing'})")
    flash("Digest matches the recorded SHA-256." if ok else "DIGEST MISMATCH - treat this artifact as compromised.", "ok" if ok else "error")
    return redirect(url_for("main.evidence_detail", ref=ref))


# ---- users -----------------------------------------------------------------------------------
def _active_admins(db):
    return db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND status='active'").fetchone()[0]


@bp.get("/users")
@sec.requires("users.manage")
def users():
    return render_template("users.html", rows=get_db().execute("SELECT * FROM users ORDER BY id").fetchall())


@bp.post("/users/create")
@sec.requires("users.manage")
def user_create():
    db = get_db()
    u, e, role = clean_text(request.form.get("username", ""), 32).lower(), clean_text(request.form.get("email", ""), 255).lower(), request.form.get("role")
    if not re.match(r"^[a-z0-9_.-]{3,32}$", u) or "@" not in e or role not in ("admin", "investigator", "analyst"):
        flash("Check the username, email and role.", "error")
        return redirect(url_for("main.users"))
    temp = secrets.token_urlsafe(14)
    try:
        create_user(db, u, e, temp, role, must_change=True)
    except sqlite3.IntegrityError:
        flash("Username or email already exists.", "error")
        return redirect(url_for("main.users"))
    audit(db, "user.create", u, f"role={role}")
    flash(f"User created. One-time temporary password (shown once, must be changed at first sign-in): {temp}", "warn")
    return redirect(url_for("main.users"))


def _target_user(db, uid):
    return db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() or abort(404)


@bp.post("/users/<int:uid>/role")
@sec.requires("users.manage")
def user_role(uid):
    db, t, role = get_db(), None, request.form.get("role")
    t = _target_user(db, uid)
    if role not in ("admin", "investigator", "analyst"):
        abort(400)
    if t["id"] == g.user["id"]:
        flash("You cannot change your own role.", "error")
    elif t["role"] == "admin" and role != "admin" and _active_admins(db) <= 1:
        flash("At least one active admin must remain.", "error")
    else:
        db.execute("UPDATE users SET role=?, updated_at=? WHERE id=?", (role, utcnow(), uid))
        db.execute("DELETE FROM sessions WHERE user_id=?", (uid,))  # force re-auth with new privileges
        audit(db, "user.role", t["username"], f"{t['role']} -> {role}")
    return redirect(url_for("main.users"))


@bp.post("/users/<int:uid>/status")
@sec.requires("users.manage")
def user_status(uid):
    db, st = get_db(), request.form.get("status")
    t = _target_user(db, uid)
    if st not in ("active", "disabled"):
        abort(400)
    if t["id"] == g.user["id"]:
        flash("You cannot disable your own account.", "error")
    elif t["role"] == "admin" and st == "disabled" and _active_admins(db) <= 1:
        flash("At least one active admin must remain.", "error")
    else:
        db.execute("UPDATE users SET status=?, updated_at=? WHERE id=?", (st, utcnow(), uid))
        if st == "disabled":
            db.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        audit(db, "user.status", t["username"], st)
    return redirect(url_for("main.users"))


@bp.post("/users/<int:uid>/unlock")
@sec.requires("users.manage")
def user_unlock(uid):
    db = get_db(); t = _target_user(db, uid)
    sec.clear_failures(db, f"u:{t['username']}"); sec.clear_failures(db, f"m:{t['id']}")
    audit(db, "user.unlock", t["username"])
    flash("Lockout cleared.", "ok")
    return redirect(url_for("main.users"))


# ---- settings / audit / simulator ------------------------------------------------------------------------
@bp.route("/settings", methods=["GET", "POST"])
@sec.requires("settings.manage")
def settings():
    db, cfg = get_db(), current_app.config
    if request.method == "POST":
        rules, errs = alerts_mod.get_rules(db), []
        for name, r in rules.items():
            for k, v in r.items():
                if k in ("label", "severity"):
                    continue
                raw = request.form.get(f"{name}.{k}")
                if raw is None:
                    continue
                try:
                    val = int(raw)
                    lim = (0, 23) if k.endswith("hour") else (1, 1440)
                    if not lim[0] <= val <= lim[1]:
                        raise ValueError
                    r[k] = val
                except ValueError:
                    errs.append(f"{r['label']}: {k} must be a whole number {lim[0]}-{lim[1]}.")
        if errs:
            for e in errs:
                flash(e, "error")
        else:
            set_setting(db, "rules", {n: {k: v for k, v in r.items() if k != "label"} for n, r in rules.items()})
            audit(db, "settings.rules", "rules", "detection thresholds updated")
            flash("Detection thresholds saved. They apply to new events only.", "ok")
        return redirect(url_for("main.settings"))
    health = {"database": db.execute("SELECT COUNT(*) FROM auth_events").fetchone()[0],
              "evidence_dir_writable": Path(cfg["EVIDENCE_DIR"]).is_dir()}
    return render_template("settings.html", rules=alerts_mod.get_rules(db), cfg=cfg, health=health,
                           audit_ok=not verify_linked(db.execute("SELECT * FROM audit ORDER BY id").fetchall(), fields=AUDIT_FIELDS))


@bp.get("/audit")
@sec.requires("audit.view")
def audit_view():
    db = get_db()
    page = max(1, int(request.args.get("page", 1))) if request.args.get("page", "1").isdigit() else 1
    act = clean_text(request.args.get("action", ""), 40)
    where, p = ("WHERE action LIKE ?", [act + "%"]) if act else ("", [])
    total = db.execute(f"SELECT COUNT(*) FROM audit {where}", p).fetchone()[0]
    rows = db.execute(f"SELECT * FROM audit {where} ORDER BY id DESC LIMIT 50 OFFSET ?", p + [(page - 1) * 50]).fetchall()
    res = {"page": page, "pages": max(1, -(-total // 50)), "total": total}
    return render_template("audit.html", rows=rows, res=res, act=act)


@bp.post("/simulator/run")
@sec.requires("simulator.run")
def simulator_run():
    if not current_app.config["SIMULATOR_ENABLED"]:
        flash("The simulator is disabled in this environment.", "error")
        return redirect(url_for("main.dashboard"))
    mode = "burst" if request.form.get("mode") == "burst" else "normal"
    n = simulate(get_db(), mode, 10)
    audit(get_db(), "simulator.run", mode, f"{n} synthetic events")
    flash(f"Generated {n} SYNTHETIC events (labelled, hash-chained, flagged synthetic).", "ok")
    return redirect(url_for("main.dashboard"))
