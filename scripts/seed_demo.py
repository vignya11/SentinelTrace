"""Seed a SEPARATE demo database with clearly labelled SYNTHETIC data.

Refuses to run unless SENTINEL_ENV=demo, so real databases are never touched.
  PowerShell:  $env:SENTINEL_ENV="demo"; python scripts/seed_demo.py --reset
Credentials are generated randomly and printed ONCE; they are not stored anywhere.
"""
import os
import random
import secrets
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
if os.environ.get("SENTINEL_ENV") != "demo":
    sys.exit("Refusing to seed: set SENTINEL_ENV=demo first (demo data must never enter a real database).")

from app import create_app  # noqa: E402
from app.chain import create_checkpoint  # noqa: E402
from app.db import connect  # noqa: E402
from app.services import audit, create_user, next_case_ref, record_event  # noqa: E402
from app.util import iso, utcnow, utcnow_dt  # noqa: E402

cfg_path = Path(os.environ.get("SENTINEL_DB", ""))
if "--reset" in sys.argv:
    from app.config import load_config
    p = Path(load_config()["DATABASE"])
    if "demo" not in p.name:
        sys.exit("Refusing to delete a database whose name does not contain 'demo'.")
    for suffix in ("", "-wal", "-shm"):
        Path(str(p) + suffix).unlink(missing_ok=True)

app = create_app()
rng = random.Random(1337)
IPS = ["192.0.2.%d" % i for i in (10, 11, 25, 40)]  # RFC 5737 documentation ranges: not real hosts
ATTACKERS = ["203.0.113.45", "198.51.100.23"]
UA = "SENTINELTRACE-DEMO/1.0 (synthetic)"
STAFF = ["demo.alice", "demo.bob", "demo.carol", "demo.dan", "demo.erin"]

with app.app_context():
    db = connect(app.config["DATABASE"])
    if db.execute("SELECT COUNT(*) FROM auth_events").fetchone()[0]:
        sys.exit("Demo database already has events. Re-run with --reset.")
    creds = {}
    for name, role in (("demo_admin", "admin"), ("demo_investigator", "investigator"), ("demo_analyst", "analyst")):
        pw = secrets.token_urlsafe(15)
        creds[name] = pw
        create_user(db, name, f"{name}@example.invalid", pw, role)
    now = utcnow_dt()

    def ev(minutes_ago, typ, outcome, user, ip, **meta):
        record_event(db, typ, outcome, user, None, {"synthetic": True, "source": "seed_demo", **meta}, True,
                     iso(now - timedelta(minutes=minutes_ago)), ip, UA)

    timeline = []  # (minutes_ago, kind, user, ip)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)

    def workday(day):  # a random minute between 08:00 and 17:00 UTC, `day` days ago (independent of the current clock)
        return (now - (midnight - timedelta(days=day) + timedelta(minutes=rng.randint(8 * 60, 17 * 60)))).total_seconds() / 60

    for day in range(7, 0, -1):
        for u in STAFF:
            ip = IPS[STAFF.index(u) % len(IPS)]
            for _ in range(rng.randint(2, 4)):
                timeline.append((workday(day), "ok", u, ip))
            if rng.random() < 0.5:
                timeline.append((workday(day), "fail", u, ip))
    # scripted, clearly synthetic scenarios (all relative to "now")
    for i in range(14):  # brute-force burst + success: password guessing against one account
        timeline.append((95 - i, "fail", "demo.alice", ATTACKERS[0]))
    timeline.append((78, "ok", "demo.alice", ATTACKERS[0]))
    for i, u in enumerate(["demo.bob", "demo.carol", "demo.dan", "demo.erin", "admin", "root"]):  # spraying
        timeline.append((40 - i, "fail", u, ATTACKERS[1]))
    timeline.append((20, "ok", "demo.bob", IPS[0]))  # one 'usual-hours' login to keep baseline stats
    for m, kind, u, ip in sorted(timeline, key=lambda x: -x[0]):
        if kind == "ok":
            ev(m, "login_success", "success", u, ip)
        else:
            ev(m, "login_failure", "failure", u, ip, reason="bad_password")
    cp = create_checkpoint(db, "main", app.config["CHECKPOINT_KEY"], app.config["CHECKPOINT_EXTERNAL_PATH"], None)
    uid = db.execute("SELECT id FROM users WHERE username='demo_investigator'").fetchone()["id"]
    ref, t = next_case_ref(db), utcnow()
    db.execute("INSERT INTO cases(ref,title,status,severity,owner_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
               (ref, "Synthetic: password guessing against demo.alice", "open", "high", uid, t, t))
    cid = db.execute("SELECT id FROM cases WHERE ref=?", (ref,)).fetchone()["id"]
    for r in db.execute("SELECT event_id FROM auth_events WHERE username='demo.alice' AND source_ip=? ORDER BY id", (ATTACKERS[0],)).fetchall():
        db.execute("INSERT INTO case_events(case_id,event_id,added_by,added_at) VALUES(?,?,?,?)", (cid, r[0], uid, t))
    db.execute("INSERT INTO case_notes(case_id,author_id,kind,body,created_at) VALUES(?,?,?,?,?)",
               (cid, uid, "hypothesis", "SYNTHETIC SCENARIO: repeated failures followed by a success from one address may indicate password guessing. Needs verification.", t))
    audit(db, "demo.seed", "demo", "seeded synthetic dataset")
    n = db.execute("SELECT COUNT(*) FROM auth_events").fetchone()[0]
    a = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    print(f"Seeded {n} SYNTHETIC events, {a} alerts, 1 case, checkpoint at seq {cp['chain_seq']}.")
    print(f"Database: {app.config['DATABASE']}\n\nDemo sign-in details (shown once, not stored):")
    for k, v in creds.items():
        print(f"  {k:18} {v}")
