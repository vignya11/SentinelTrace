"""Transparent, configurable detection rules. Alerts are indicators requiring investigation, not proof."""
from __future__ import annotations

import json
from datetime import timedelta

from .util import iso, parse_ts, utcnow

DEFAULT_RULES = {
    "failures_per_account": {"label": "Repeated failures on one account", "threshold": 5, "window_min": 10, "severity": "medium"},
    "source_burst": {"label": "Failure burst from one source IP", "threshold": 10, "window_min": 5, "severity": "medium"},
    "success_after_failures": {"label": "Success after repeated failures", "threshold": 3, "window_min": 10, "severity": "high"},
    "many_accounts_one_source": {"label": "Many accounts targeted from one source", "threshold": 4, "window_min": 10, "severity": "high"},
    "unusual_hour": {"label": "Login outside baseline hours (UTC)", "start_hour": 6, "end_hour": 20, "window_min": 60, "severity": "low"},
    "new_ip_or_device": {"label": "New IP address or user agent for account", "min_history": 3, "window_min": 60, "severity": "low"},
}
DISCLAIMER = "This is an indicator requiring investigation, not proof of compromise."


def get_rules(db) -> dict:
    rules = {k: dict(v) for k, v in DEFAULT_RULES.items()}
    row = db.execute("SELECT value FROM settings WHERE key='rules'").fetchone()
    if row:
        for k, v in json.loads(row["value"]).items():
            if k in rules:
                rules[k].update({a: b for a, b in v.items() if a in rules[k] and a != "label"})
    return rules


def _emit(db, ev, rule, severity, subject, ws, we, ids, text):
    if db.execute("SELECT 1 FROM alerts WHERE chain_id=? AND rule=? AND subject=? AND window_end>=?",
                  (ev["chain_id"], rule, subject, ws)).fetchone():
        return None  # an alert for this rule+subject is already active in this window
    cur = db.execute(
        "INSERT OR IGNORE INTO alerts(chain_id,rule,severity,subject,trigger_event_id,window_start,window_end,evidence,"
        "explanation,dedupe_key,synthetic,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (ev["chain_id"], rule, severity, subject, ev["event_id"], ws, we, json.dumps(ids[:50]),
         f"{text} {DISCLAIMER}", f"{rule}|{subject}|{ev['event_id']}", ev["synthetic"], utcnow()))
    return cur.lastrowid


def evaluate_event(db, ev) -> list:
    """Evaluate rules relative to the event's own timestamp (works for live and back-filled data)."""
    rules, made = get_rules(db), []
    we, user, ip, chain = ev["ts"], ev["username"], ev["source_ip"], ev["chain_id"]

    def win(rule):
        return iso(parse_ts(we) - timedelta(minutes=rules[rule]["window_min"]))

    if ev["event_type"] == "login_failure":
        if user:
            r = rules["failures_per_account"]; ws = win("failures_per_account")
            ids = [x[0] for x in db.execute(
                "SELECT event_id FROM auth_events WHERE chain_id=? AND event_type='login_failure' AND username=? AND ts>? AND ts<=? ORDER BY ts",
                (chain, user, ws, we))]
            if len(ids) >= r["threshold"]:
                made.append(_emit(db, ev, "failures_per_account", r["severity"], user, ws, we, ids,
                    f"{len(ids)} failed logins for account '{user}' between {ws} and {we} UTC (rule: {r['threshold']} within {r['window_min']} min)."))
        if ip != "unknown":
            r = rules["source_burst"]; ws = win("source_burst")
            ids = [x[0] for x in db.execute(
                "SELECT event_id FROM auth_events WHERE chain_id=? AND event_type='login_failure' AND source_ip=? AND ts>? AND ts<=? ORDER BY ts",
                (chain, ip, ws, we))]
            if len(ids) >= r["threshold"]:
                made.append(_emit(db, ev, "source_burst", r["severity"], ip, ws, we, ids,
                    f"{len(ids)} failed logins from {ip} between {ws} and {we} UTC (rule: {r['threshold']} within {r['window_min']} min)."))
            r = rules["many_accounts_one_source"]; ws = win("many_accounts_one_source")
            rows = db.execute(
                "SELECT event_id, username FROM auth_events WHERE chain_id=? AND event_type='login_failure' AND source_ip=? AND ts>? AND ts<=? ORDER BY ts",
                (chain, ip, ws, we)).fetchall()
            names = {x["username"] for x in rows if x["username"]}
            if len(names) >= r["threshold"]:
                made.append(_emit(db, ev, "many_accounts_one_source", r["severity"], ip, ws, we, [x["event_id"] for x in rows],
                    f"{len(names)} distinct accounts had failed logins from {ip} between {ws} and {we} UTC (rule: {r['threshold']} accounts within {r['window_min']} min)."))
    elif ev["event_type"] == "login_success" and user:
        r = rules["success_after_failures"]; ws = win("success_after_failures")
        ids = [x[0] for x in db.execute(
            "SELECT event_id FROM auth_events WHERE chain_id=? AND event_type='login_failure' AND username=? AND ts>? AND ts<?",
            (chain, user, ws, we))]
        if len(ids) >= r["threshold"]:
            made.append(_emit(db, ev, "success_after_failures", r["severity"], user, ws, we, ids + [ev["event_id"]],
                f"Successful login for '{user}' at {we} UTC followed {len(ids)} failures in the preceding {r['window_min']} min (rule: {r['threshold']})."))
        r = rules["unusual_hour"]; h = parse_ts(we).hour; s, e = r["start_hour"], r["end_hour"]
        inside = (s <= h < e) if s < e else (h >= s or h < e)
        if not inside:
            ws = win("unusual_hour")
            made.append(_emit(db, ev, "unusual_hour", r["severity"], user, ws, we, [ev["event_id"]],
                f"Successful login for '{user}' at {we} UTC (hour {h:02d}) is outside the configured baseline {s:02d}:00-{e:02d}:00 UTC."))
        r = rules["new_ip_or_device"]
        prior = db.execute(
            "SELECT source_ip, user_agent FROM auth_events WHERE chain_id=? AND event_type='login_success' AND username=? AND ts<?",
            (chain, user, we)).fetchall()
        if len(prior) >= r["min_history"]:
            new = []
            if ip not in {p["source_ip"] for p in prior}:
                new.append(f"IP {ip}")
            if ev["user_agent"] and ev["user_agent"] not in {p["user_agent"] for p in prior}:
                new.append("user agent")
            if new:
                ws = win("new_ip_or_device")
                made.append(_emit(db, ev, "new_ip_or_device", r["severity"], user, ws, we, [ev["event_id"]],
                    f"Login for '{user}' used a previously unseen {' and '.join(new)} ({len(prior)} earlier successful logins observed)."))
    return [m for m in made if m]
