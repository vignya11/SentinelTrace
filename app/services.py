"""Business logic shared by web pages and the JSON API. All data comes from the database."""
from __future__ import annotations

import json
import logging
import random
import re
from datetime import datetime, timedelta

from flask import current_app, g, has_request_context, request
from werkzeug.security import generate_password_hash

from . import alerts as alerts_mod
from .chain import append_event, linked_hash, EVENT_TYPES
from .util import clean_text, escape_like, hours_ago, iso, parse_ts, utcnow, utcnow_dt

log = logging.getLogger("sentineltrace")
OUTCOME_LIST = ("success", "failure", "blocked", "info")


def client_ip() -> str:
    return request.remote_addr or "unknown" if has_request_context() else "unknown"


# ---- users ---------------------------------------------------------------------------
def create_user(db, username, email, password, role, must_change=False) -> int:
    now = utcnow()
    cur = db.execute(
        "INSERT INTO users(username,email,password_hash,role,must_change_password,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
        (username.strip().lower(), email.strip().lower(), generate_password_hash(password), role, int(must_change), now, now))
    return cur.lastrowid


# ---- audit (append-only, hash-linked) -----------------------------------------------------
def audit(db, action, target="", detail="", actor=None):
    actor = actor or (g.get("user") if has_request_context() else None)
    name = actor["username"] if actor else "system"
    payload = {"ts": utcnow(), "actor_name": name, "action": action, "target": clean_text(target, 120),
               "detail": clean_text(detail, 500), "ip": client_ip()}
    db.execute("BEGIN IMMEDIATE")
    try:
        last = db.execute("SELECT entry_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev = last["entry_hash"] if last else "0" * 64
        db.execute("INSERT INTO audit(ts,actor_id,actor_name,action,target,detail,ip,prev_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?,?)",
                   (payload["ts"], actor["id"] if actor else None, name, action, payload["target"], payload["detail"],
                    payload["ip"], prev, linked_hash(prev, payload)))
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise


AUDIT_FIELDS = ("ts", "actor_name", "action", "target", "detail", "ip")


# ---- events ----------------------------------------------------------------------------
def record_event(db, event_type, outcome, username="", user_id=None, metadata=None, synthetic=False,
                 ts=None, source_ip=None, user_agent=None):
    cfg = current_app.config
    if source_ip is None:
        source_ip = client_ip()
    if user_agent is None:
        user_agent = request.headers.get("User-Agent", "") if has_request_context() else ""
    ev = append_event(db, chain_id=cfg["CHAIN_ID"], event_type=event_type, outcome=outcome, username=username,
                      user_id=user_id, source_ip=source_ip, user_agent=user_agent, metadata=metadata,
                      synthetic=synthetic, ts=ts)
    try:
        alerts_mod.evaluate_event(db, ev)
    except Exception:  # detection must never break authentication
        log.exception("alert evaluation failed")
    return ev


def parse_filters(args) -> tuple[str, list, dict, list]:
    """Build a parameterized WHERE clause from allow-listed filters. Returns (sql, params, filters, errors)."""
    where, params, f, errs = ["chain_id=?"], [current_app.config["CHAIN_ID"]], {}, []
    q = clean_text(args.get("q", ""), 100)
    if q:
        like = f"%{escape_like(q)}%"
        where.append("(username LIKE ? ESCAPE '\\' OR source_ip LIKE ? ESCAPE '\\' OR user_agent LIKE ? ESCAPE '\\' OR event_id LIKE ? ESCAPE '\\')")
        params += [like] * 4; f["q"] = q
    et = args.get("event_type", "")
    if et:
        if et in EVENT_TYPES:
            where.append("event_type=?"); params.append(et); f["event_type"] = et
        else:
            errs.append("Unknown event type.")
    oc = args.get("outcome", "")
    if oc:
        if oc in OUTCOME_LIST:
            where.append("outcome=?"); params.append(oc); f["outcome"] = oc
        else:
            errs.append("Unknown outcome.")
    un = clean_text(args.get("username", ""), 64).lower()
    if un:
        where.append("username=?"); params.append(un); f["username"] = un
    ip = clean_text(args.get("ip", ""), 45)
    if ip:
        where.append("source_ip=?"); params.append(ip); f["ip"] = ip
    for key, op in (("date_from", ">="), ("date_to", "<")):
        v = args.get(key, "")
        if v:
            try:
                d = datetime.strptime(v, "%Y-%m-%d")
                if key == "date_to":
                    d += timedelta(days=1)
                where.append(f"ts{op}?"); params.append(d.strftime("%Y-%m-%dT00:00:00.000000Z")); f[key] = v
            except ValueError:
                errs.append(f"{key.replace('_', ' ').capitalize()} must be YYYY-MM-DD.")
    syn = args.get("synthetic", "")
    if syn in ("0", "1"):
        where.append("synthetic=?"); params.append(int(syn)); f["synthetic"] = syn
    after = args.get("after_id", "")
    if after:
        if after.isdigit():
            where.append("id>?"); params.append(int(after))
        else:
            errs.append("after_id must be an integer.")
    return " AND ".join(where), params, f, errs


def query_events(db, args, default_per=25, max_per=100):
    sql, params, f, errs = parse_filters(args)
    try:
        page = max(1, int(args.get("page", 1)))
        per = min(max_per, max(1, int(args.get("per_page", default_per))))
    except ValueError:
        page, per = 1, default_per
        errs.append("page and per_page must be integers.")
    total = db.execute(f"SELECT COUNT(*) FROM auth_events WHERE {sql}", params).fetchone()[0]
    order = "ASC" if args.get("after_id") else "DESC"
    rows = db.execute(f"SELECT * FROM auth_events WHERE {sql} ORDER BY id {order} LIMIT ? OFFSET ?",
                      params + [per, (page - 1) * per]).fetchall()
    return {"rows": rows, "total": total, "page": page, "per_page": per,
            "pages": max(1, -(-total // per)), "filters": f, "errors": errs}


def event_public(r) -> dict:
    return {"id": r["id"], "event_id": r["event_id"], "ts": r["ts"], "event_type": r["event_type"],
            "outcome": r["outcome"], "username": r["username"], "source_ip": r["source_ip"],
            "user_agent": r["user_agent"], "synthetic": bool(r["synthetic"]), "chain_seq": r["chain_seq"],
            "record_hash": r["record_hash"], "prev_hash": r["prev_hash"], "metadata": json.loads(r["metadata"])}


def dashboard_metrics(db) -> dict:
    chain, since = current_app.config["CHAIN_ID"], hours_ago(24)
    def one(sql, *p):
        return db.execute(sql, p).fetchone()[0] or 0
    total = one("SELECT COUNT(*) FROM auth_events WHERE chain_id=?", chain)
    s24 = one("SELECT COUNT(*) FROM auth_events WHERE chain_id=? AND event_type='login_success' AND ts>=?", chain, since)
    f24 = one("SELECT COUNT(*) FROM auth_events WHERE chain_id=? AND event_type='login_failure' AND ts>=?", chain, since)
    buckets = {}
    now = utcnow_dt().replace(minute=0, second=0, microsecond=0)
    for i in range(23, -1, -1):
        buckets[iso(now - timedelta(hours=i))[:13]] = {"hour": iso(now - timedelta(hours=i))[:13], "success": 0, "failure": 0}
    for r in db.execute("SELECT substr(ts,1,13) h, event_type t, COUNT(*) c FROM auth_events WHERE chain_id=? AND ts>=? "
                        "AND event_type IN ('login_success','login_failure') GROUP BY h,t", (chain, iso(now - timedelta(hours=23)))):
        if r["h"] in buckets:
            buckets[r["h"]]["success" if r["t"] == "login_success" else "failure"] = r["c"]
    top = [dict(r) for r in db.execute(
        "SELECT source_ip ip, COUNT(*) failures, COUNT(DISTINCT username) accounts FROM auth_events WHERE chain_id=? AND "
        "event_type='login_failure' AND ts>=? GROUP BY source_ip ORDER BY failures DESC LIMIT 5", (chain, since))]
    run = db.execute("SELECT * FROM integrity_runs WHERE chain_id=? ORDER BY id DESC LIMIT 1", (chain,)).fetchone()
    head = db.execute("SELECT chain_seq, record_hash, ts FROM auth_events WHERE chain_id=? ORDER BY chain_seq DESC LIMIT 1", (chain,)).fetchone()
    return {
        "generated_at": utcnow(), "total_events": total, "logins_success_24h": s24, "logins_failed_24h": f24,
        "failure_rate_24h": round(100 * f24 / (s24 + f24), 1) if (s24 + f24) else None,
        "open_alerts": one("SELECT COUNT(*) FROM alerts WHERE chain_id=? AND status='open'", chain),
        "synthetic_events": one("SELECT COUNT(*) FROM auth_events WHERE chain_id=? AND synthetic=1", chain),
        "hourly": list(buckets.values()), "top_sources": top,
        "integrity": {"last_run": run["ts"], "ok": bool(run["ok"]), "records_checked": run["records_checked"]} if run else None,
        "chain_head": {"seq": head["chain_seq"], "hash": head["record_hash"], "ts": head["ts"]} if head else None,
        "last_event_ts": head["ts"] if head else None,
    }


def correlate(db, event_ids: list[str]) -> list[dict]:
    """For case events, summarise related activity across ALL events by shared IP / username."""
    if not event_ids:
        return []
    ph = ",".join("?" * len(event_ids))
    rows = db.execute(f"SELECT DISTINCT username, source_ip FROM auth_events WHERE event_id IN ({ph})", event_ids).fetchall()
    out, seen = [], set()
    for kind, col in (("source_ip", "source_ip"), ("username", "username")):
        for v in sorted({r[col] for r in rows if r[col] and r[col] != "unknown"}):
            if (kind, v) in seen:
                continue
            seen.add((kind, v))
            s = db.execute(f"SELECT COUNT(*) n, SUM(event_type='login_failure') f, SUM(event_type='login_success') s, "
                           f"MIN(ts) first, MAX(ts) last FROM auth_events WHERE {col}=?", (v,)).fetchone()
            out.append({"kind": kind.replace("_", " "), "value": v, "total": s["n"], "failures": s["f"] or 0,
                        "successes": s["s"] or 0, "first": s["first"], "last": s["last"]})
    return out


def next_case_ref(db) -> str:
    n = db.execute("SELECT COALESCE(MAX(id),0)+1 FROM cases").fetchone()[0]
    return f"CASE-{utcnow_dt().year}-{n:04d}"


def get_setting(db, key, default=None):
    r = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return json.loads(r["value"]) if r else default


def set_setting(db, key, value):
    db.execute("INSERT INTO settings VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
               (key, json.dumps(value), utcnow()))


# ---- synthetic simulator (clearly labelled, demo/dev only) ----------------------------------------
SIM_USERS = ["synthetic.alice", "synthetic.bob", "synthetic.carol", "synthetic.dave", "synthetic.erin"]
SIM_IPS = ["192.0.2.10", "192.0.2.24", "198.51.100.7", "198.51.100.88", "203.0.113.5", "203.0.113.99"]  # RFC 5737 documentation ranges
SIM_UA = "SENTINELTRACE-SIMULATOR/1.0 (synthetic)"


def simulate(db, mode="normal", n=10, rng=None) -> int:
    rng, made = rng or random.Random(), 0
    meta = {"source": "simulator", "synthetic": True}
    def add(t, o, u, ip, extra=None):
        record_event(db, t, o, username=u, source_ip=ip, user_agent=SIM_UA, metadata={**meta, **(extra or {})}, synthetic=True)
    if mode == "burst":
        ip, victim = rng.choice(SIM_IPS), rng.choice(SIM_USERS)
        for _ in range(max(6, n)):
            add("login_failure", "failure", victim, ip, {"reason": "bad_password"})
            made += 1
    else:
        for _ in range(n):
            u, ip = rng.choice(SIM_USERS), rng.choice(SIM_IPS[:3])
            if rng.random() < 0.8:
                add("login_success", "success", u, ip)
            else:
                add("login_failure", "failure", u, ip, {"reason": "bad_password"})
            made += 1
    return made
