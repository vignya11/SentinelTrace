"""Versioned JSON API (/api/v1), SSE live stream, and token-authenticated ingestion."""
from __future__ import annotations

import hmac
import json
import time
from datetime import timedelta

from flask import Blueprint, Response, current_app, g, jsonify, request, stream_with_context

from . import db as dbm
from . import evidence as ev_mod
from . import security as sec
from .db import get_db
from .services import (audit, dashboard_metrics, event_public, parse_filters, query_events, record_event)
from .util import iso, parse_ts, utcnow, utcnow_dt

bp = Blueprint("api", __name__)
_streams: dict[int, int] = {}


def _page(items, res, key):
    return jsonify({key: items, "pagination": {"page": res["page"], "per_page": res["per_page"], "total": res["total"], "pages": res["pages"]}})


@bp.get("/api/v1/health")
def health():
    try:
        get_db().execute("SELECT 1").fetchone()
        return jsonify({"status": "ok", "time": utcnow()})
    except Exception:
        return sec.api_error(503, "unavailable", "Database unavailable.")


@bp.get("/api/v1/dashboard/metrics")
@sec.requires("dashboard.view")
def metrics():
    return jsonify(dashboard_metrics(get_db()))


@bp.get("/api/v1/events")
@sec.requires("events.view")
def events():
    res = query_events(get_db(), request.args)
    if res["errors"]:
        return sec.api_error(400, "invalid_parameters", " ".join(res["errors"]))
    return _page([event_public(r) for r in res["rows"]], res, "events")


@bp.post("/api/v1/integrity/verify")
@sec.requires("integrity.verify")
def verify():
    from .web import run_verification
    return jsonify(run_verification(get_db(), g.user["id"]))


@bp.get("/api/v1/alerts")
@sec.requires("alerts.view")
def alerts():
    db, status = get_db(), request.args.get("status", "open")
    where, p = "chain_id=?", [current_app.config["CHAIN_ID"]]
    if status in ("open", "acknowledged", "dismissed"):
        where += " AND status=?"; p.append(status)
    rows = db.execute(f"SELECT * FROM alerts WHERE {where} ORDER BY id DESC LIMIT 200", p).fetchall()
    return jsonify({"alerts": [{**dict(r), "evidence": json.loads(r["evidence"])} for r in rows]})


@bp.get("/api/v1/cases")
@sec.requires("cases.manage")
def cases():
    db = get_db()
    q = "SELECT ref,title,status,severity,created_at,updated_at FROM cases"
    rows = db.execute(q + " ORDER BY id DESC").fetchall() if g.user["role"] == "admin" else db.execute(q + " WHERE owner_id=? ORDER BY id DESC", (g.user["id"],)).fetchall()
    return jsonify({"cases": [dict(r) for r in rows]})


@bp.get("/api/v1/cases/<ref>")
@sec.requires("cases.manage")
def case(ref):
    db = get_db()
    c = db.execute("SELECT * FROM cases WHERE ref=?", (ref,)).fetchone()
    if not c or (g.user["role"] != "admin" and c["owner_id"] != g.user["id"]):
        return sec.api_error(404, "not_found", "Case not found.")
    ids = [r[0] for r in db.execute("SELECT event_id FROM case_events WHERE case_id=?", (c["id"],))]
    return jsonify({"case": {k: c[k] for k in ("ref", "title", "status", "severity", "created_at", "updated_at")}, "event_ids": ids})


@bp.post("/api/v1/evidence/exports")
@sec.requires("evidence.export")
def export():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return sec.api_error(400, "invalid_json", "JSON object body required.")
    fmt = body.get("format", "json")
    if fmt not in ("json", "csv", "pdf"):
        return sec.api_error(400, "invalid_format", "format must be json, csv or pdf.")
    flt = body.get("filters", {})
    if not isinstance(flt, dict):
        return sec.api_error(400, "invalid_filters", "filters must be an object.")
    sql, params, f, errs = parse_filters({k: str(v) for k, v in flt.items()})
    if errs:
        return sec.api_error(400, "invalid_filters", " ".join(errs))
    db = get_db()
    try:
        ref = ev_mod.create_export(db, g.user, fmt, sql, params, f)
    except ValueError as e:
        return sec.api_error(422, "export_failed", str(e))
    audit(db, "evidence.export", ref, f"api {fmt}")
    r = db.execute("SELECT ref,fmt,sha256,size_bytes,record_count,created_at FROM evidence WHERE ref=?", (ref,)).fetchone()
    return jsonify({"evidence": dict(r)}), 201


@bp.get("/api/v1/evidence/<ref>")
@sec.requires("evidence.view")
def evidence_get(ref):
    from .web import _evidence_or_404
    from flask import abort
    try:
        e = _evidence_or_404(get_db(), ref)
    except Exception:
        return sec.api_error(404, "not_found", "Evidence not found.")
    return jsonify({"evidence": {k: e[k] for k in ("ref", "kind", "fmt", "sha256", "size_bytes", "record_count", "created_at", "chain_head_seq", "chain_head_hash")}})


# ---- ingestion (explicitly configured, token authenticated, rate limited) -------------------------------
@bp.post("/api/v1/ingest")
def ingest():
    cfg = current_app.config
    token = cfg["INGEST_TOKEN"]
    auth = request.headers.get("Authorization", "")
    if not token:
        return sec.api_error(503, "ingest_disabled", "Ingestion is not configured on this server.")
    if not auth.startswith("Bearer ") or not hmac.compare_digest(auth[7:], token):
        sec.rate_ok(f"ingest-bad:{request.remote_addr}", 1000)
        return sec.api_error(401, "unauthenticated", "Invalid or missing bearer token.")
    if not sec.rate_ok("ingest", cfg["INGEST_RATE_PER_MIN"]):
        return sec.api_error(429, "rate_limited", "Ingest rate limit exceeded.")
    body = request.get_json(silent=True)
    items = body.get("events") if isinstance(body, dict) else None
    if not isinstance(items, list) or not 1 <= len(items) <= 100:
        return sec.api_error(400, "invalid_payload", "Body must be {\"events\": [1..100 items]}.")
    from .chain import EVENT_TYPES, OUTCOMES
    clean, now = [], utcnow_dt()
    for i, it in enumerate(items):
        if not isinstance(it, dict) or it.get("event_type") not in EVENT_TYPES or it.get("outcome") not in OUTCOMES:
            return sec.api_error(422, "invalid_event", f"events[{i}]: bad event_type or outcome.")
        ts = it.get("timestamp")
        if ts:
            try:
                if parse_ts(ts) > now + timedelta(minutes=5):
                    raise ValueError
            except ValueError:
                return sec.api_error(422, "invalid_event", f"events[{i}]: timestamp must be UTC 'YYYY-MM-DDTHH:MM:SS.ffffffZ' and not in the future.")
        meta = it.get("metadata") if isinstance(it.get("metadata"), dict) else {}
        clean.append((it, ts, {**meta, "ingested": True}))
    db, ids = get_db(), []
    for it, ts, meta in clean:
        ev = record_event(db, it["event_type"], it["outcome"], str(it.get("username", "")), None, meta, False, ts,
                          str(it.get("source_ip", "")), str(it.get("user_agent", "")))
        ids.append(ev["event_id"])
    return jsonify({"accepted": len(ids), "event_ids": ids}), 202


# ---- SSE live stream ------------------------------------------------------------------------------------------
@bp.get("/stream/events")
@sec.requires("events.view")
def stream():
    cfg, uid = current_app.config, g.user["id"]
    if _streams.get(uid, 0) >= cfg["MAX_STREAMS_PER_USER"]:
        return sec.api_error(429, "too_many_streams", "Too many open streams.")
    last = request.headers.get("Last-Event-ID") or request.args.get("last_id", "")
    path, chain, ttl, poll = cfg["DATABASE"], cfg["CHAIN_ID"], cfg["STREAM_MAX_SECONDS"], cfg["STREAM_POLL_SECONDS"]
    conn0 = get_db()
    start = int(last) if last.isdigit() else (conn0.execute("SELECT COALESCE(MAX(id),0) FROM auth_events WHERE chain_id=?", (chain,)).fetchone()[0])
    _streams[uid] = _streams.get(uid, 0) + 1

    def gen():
        conn, cur, end, quiet = dbm.connect(path), start, time.time() + ttl, 0
        try:
            yield "retry: 3000\n\n"
            while time.time() < end:
                rows = conn.execute("SELECT * FROM auth_events WHERE chain_id=? AND id>? ORDER BY id LIMIT 50", (chain, cur)).fetchall()
                for r in rows:
                    cur = r["id"]
                    d = {k: r[k] for k in ("id", "event_id", "ts", "event_type", "outcome", "username", "source_ip", "synthetic")}
                    yield f"id: {cur}\nevent: auth_event\ndata: {json.dumps(d)}\n\n"
                quiet = 0 if rows else quiet + 1
                if quiet and quiet % 8 == 0:
                    yield ": keepalive\n\n"
                time.sleep(poll)
        finally:
            conn.close()
            _streams[uid] = max(0, _streams.get(uid, 1) - 1)

    return Response(stream_with_context(gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
