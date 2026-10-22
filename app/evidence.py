"""Evidence acquisition: immutable export snapshots with SHA-256 digests and chain-of-custody."""
from __future__ import annotations

import csv
import io
import json
import os
import secrets
import stat
from pathlib import Path

from flask import current_app, g

from .chain import linked_hash, verify_chain
from .services import event_public
from .util import sha256_hex, utcnow, utcnow_dt

MEDIA = {"json": "application/json", "csv": "text/csv", "pdf": "application/pdf"}
CSV_COLS = ["id", "event_id", "chain_seq", "ts", "event_type", "outcome", "username", "source_ip", "user_agent",
            "synthetic", "metadata", "prev_hash", "record_hash"]
CUSTODY_FIELDS = ("evidence_id", "action", "actor_name", "ts", "detail")
HANDOFF_NOTE = ("Evidence handling: this artifact is a point-in-time snapshot. Verify its SHA-256 digest before relying on it, "
                "keep the original database and checkpoints, and record every transfer in the chain of custody. "
                "Hash-chain verification shows consistency, not authenticity or legal admissibility.")


def _csv_safe(v):
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s  # spreadsheet formula-injection guard


def build_json(manifest, records) -> bytes:
    return json.dumps({"manifest": manifest, "records": records}, indent=2, sort_keys=True).encode("utf-8")


def build_csv(records) -> bytes:
    buf = io.StringIO(newline="")
    w = csv.writer(buf)
    w.writerow(CSV_COLS)
    for r in records:
        w.writerow([_csv_safe(json.dumps(r[c], sort_keys=True) if c == "metadata" else r[c]) for c in CSV_COLS])
    return buf.getvalue().encode("utf-8")


def build_pdf(manifest, records, case=None, notes=(), timeline=()) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    st, out = getSampleStyleSheet(), io.BytesIO()
    doc = SimpleDocTemplate(out, pagesize=landscape(A4), title="SentinelTrace report", leftMargin=28, rightMargin=28)
    esc = lambda s: str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    el = [Paragraph("SentinelTrace - " + ("Case report " + esc(case["ref"]) if case else "Evidence export"), st["Title"])]
    if manifest["includes_synthetic"]:
        el.append(Paragraph("<b>CONTAINS SYNTHETIC DEMO DATA</b>", st["Normal"]))
    for k in ("exported_at", "exported_by", "record_count", "chain_head_seq", "chain_head_hash", "filters"):
        el.append(Paragraph(f"<b>{k}</b>: {esc(manifest.get(k))}", st["Normal"]))
    if case:
        el += [Spacer(1, 8), Paragraph(esc(f"{case['title']} - severity {case['severity']}, status {case['status']}"), st["Heading2"])]
        for n in notes:
            el.append(Paragraph(esc(f"[{n['created_at']}] {n['kind'].upper()} ({n['author']}): {n['body']}"), st["Normal"]))
    el += [Spacer(1, 8), Paragraph("Events (UTC)", st["Heading2"])]
    data = [["Seq", "Timestamp", "Type", "Outcome", "User", "Source IP", "Record hash"]]
    data += [[r["chain_seq"], r["ts"], r["event_type"], r["outcome"], esc(r["username"]), r["source_ip"], r["record_hash"][:16] + "..."]
             for r in records[:500]]
    t = Table(data, repeatRows=1)
    t.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 7), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14213d")),
                           ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), 0.25, colors.grey)]))
    el += [t]
    if len(records) > 500:
        el.append(Paragraph(f"Showing first 500 of {len(records)} records; export JSON for the full set.", st["Normal"]))
    el += [Spacer(1, 10), Paragraph(esc(HANDOFF_NOTE), st["Italic"])]
    doc.build(el)
    return out.getvalue()


def custody_add(db, evidence_id, action, detail, actor=None):
    actor = actor or g.user
    ts, name = utcnow(), actor["username"] if actor else "system"
    payload = {"evidence_id": evidence_id, "action": action, "actor_name": name, "ts": ts, "detail": detail[:500]}
    db.execute("BEGIN IMMEDIATE")
    try:
        last = db.execute("SELECT entry_hash FROM custody WHERE evidence_id=? ORDER BY id DESC LIMIT 1", (evidence_id,)).fetchone()
        prev = last["entry_hash"] if last else "0" * 64
        db.execute("INSERT INTO custody(evidence_id,action,actor_id,actor_name,ts,detail,prev_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?)",
                   (evidence_id, action, actor["id"] if actor else None, name, ts, payload["detail"], prev, linked_hash(prev, payload)))
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise


def create_export(db, user, fmt, where_sql, params, filters, case=None, notes=(), kind="events_export"):
    """Snapshot matching events to a write-once file; record digest, manifest data and first custody entry."""
    cfg = current_app.config
    n = db.execute(f"SELECT COUNT(*) FROM auth_events WHERE {where_sql}", params).fetchone()[0]
    if n == 0:
        raise ValueError("No records match the selected filters.")
    if n > cfg["MAX_EXPORT_RECORDS"]:
        raise ValueError(f"Too many records ({n}); narrow the filters (limit {cfg['MAX_EXPORT_RECORDS']}).")
    records = [event_public(r) for r in db.execute(f"SELECT * FROM auth_events WHERE {where_sql} ORDER BY chain_seq", params)]
    head = db.execute("SELECT chain_seq, record_hash FROM auth_events WHERE chain_id=? ORDER BY chain_seq DESC LIMIT 1", (cfg["CHAIN_ID"],)).fetchone()
    ver = verify_chain(db, cfg["CHAIN_ID"], cfg["CHECKPOINT_KEY"], cfg["CHECKPOINT_EXTERNAL_PATH"])
    now = utcnow()
    manifest = {"tool": "SentinelTrace", "exported_at": now, "exported_by": user["username"], "record_count": n,
                "filters": filters, "chain_id": cfg["CHAIN_ID"], "chain_head_seq": head["chain_seq"],
                "chain_head_hash": head["record_hash"], "chain_verified_at_export": ver["ok"],
                "includes_synthetic": any(r["synthetic"] for r in records), "handling_note": HANDOFF_NOTE}
    data = (build_json(manifest, records) if fmt == "json" else build_csv(records) if fmt == "csv"
            else build_pdf(manifest, records, case, notes))
    ref = f"EV-{utcnow_dt():%Y%m%d}-{secrets.token_hex(3).upper()}"
    fname = f"{ref}.{fmt}"
    d = Path(cfg["EVIDENCE_DIR"]); d.mkdir(parents=True, exist_ok=True)
    path = d / fname
    with open(path, "xb") as fh:  # 'x': never overwrite an existing artifact
        fh.write(data)
    os.chmod(path, stat.S_IREAD)
    digest = sha256_hex(data)
    db.execute("BEGIN IMMEDIATE")
    try:
        cur = db.execute(
            "INSERT INTO evidence(ref,case_id,kind,fmt,filename,media_type,size_bytes,sha256,record_count,filters,chain_head_seq,"
            "chain_head_hash,includes_synthetic,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ref, case["id"] if case else None, kind, fmt, fname, MEDIA[fmt], len(data), digest, n, json.dumps(filters, sort_keys=True),
             head["chain_seq"], head["record_hash"], int(manifest["includes_synthetic"]), user["id"], now))
        eid = cur.lastrowid
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    custody_add(db, eid, "acquired", f"Exported {n} records as {fmt.upper()}; sha256={digest}", user)
    return ref


def file_digest(row) -> str | None:
    p = Path(current_app.config["EVIDENCE_DIR"]) / row["filename"]
    return sha256_hex(p.read_bytes()) if p.is_file() else None
