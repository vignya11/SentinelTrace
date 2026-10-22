"""SQLite access layer: parameterized queries only, explicit transactions, append-only triggers."""
from __future__ import annotations

import sqlite3

from flask import current_app, g

from .util import utcnow

APPEND_ONLY = ("auth_events", "checkpoints", "case_notes", "evidence", "custody", "audit")

SCHEMA_V1 = """
CREATE TABLE users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK(length(username) BETWEEN 3 AND 64),
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','investigator','analyst')),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
  must_change_password INTEGER NOT NULL DEFAULT 0,
  totp_secret TEXT, totp_enabled INTEGER NOT NULL DEFAULT 0, totp_last_step INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_login_at TEXT);
CREATE TABLE sessions(
  sid_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL, last_seen TEXT NOT NULL, expires_at TEXT NOT NULL, ip TEXT, user_agent TEXT);
CREATE INDEX ix_sessions_user ON sessions(user_id);
CREATE TABLE login_attempts(id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL, ts TEXT NOT NULL);
CREATE INDEX ix_attempts ON login_attempts(key, ts);
CREATE TABLE password_resets(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  expires_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE auth_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE, chain_id TEXT NOT NULL, chain_seq INTEGER NOT NULL,
  ts TEXT NOT NULL, user_id INTEGER REFERENCES users(id), username TEXT NOT NULL DEFAULT '',
  event_type TEXT NOT NULL, outcome TEXT NOT NULL CHECK(outcome IN ('success','failure','blocked','info')),
  source_ip TEXT NOT NULL DEFAULT 'unknown', user_agent TEXT NOT NULL DEFAULT '',
  metadata TEXT NOT NULL DEFAULT '{}', synthetic INTEGER NOT NULL DEFAULT 0 CHECK(synthetic IN (0,1)),
  prev_hash TEXT NOT NULL, record_hash TEXT NOT NULL UNIQUE, schema_version INTEGER NOT NULL,
  UNIQUE(chain_id, chain_seq));
CREATE INDEX ix_ev_ts ON auth_events(ts);
CREATE INDEX ix_ev_user ON auth_events(username, ts);
CREATE INDEX ix_ev_ip ON auth_events(source_ip, ts);
CREATE INDEX ix_ev_type ON auth_events(event_type, ts);
CREATE TABLE checkpoints(
  id INTEGER PRIMARY KEY AUTOINCREMENT, chain_id TEXT NOT NULL, chain_seq INTEGER NOT NULL,
  head_hash TEXT NOT NULL, created_at TEXT NOT NULL, digest TEXT NOT NULL, hmac TEXT,
  external_ref TEXT, created_by INTEGER REFERENCES users(id));
CREATE TABLE integrity_runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, chain_id TEXT NOT NULL,
  records_checked INTEGER NOT NULL, ok INTEGER NOT NULL, findings TEXT NOT NULL, warnings TEXT NOT NULL,
  run_by INTEGER REFERENCES users(id));
CREATE TABLE cases(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT NOT NULL UNIQUE, title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','in_review','closed')),
  severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
  owner_id INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX ix_cases_owner ON cases(owner_id);
CREATE TABLE case_notes(
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL REFERENCES cases(id),
  author_id INTEGER NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL CHECK(kind IN ('note','hypothesis','finding')), body TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE case_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL REFERENCES cases(id),
  event_id TEXT NOT NULL REFERENCES auth_events(event_id), added_by INTEGER NOT NULL REFERENCES users(id),
  added_at TEXT NOT NULL, UNIQUE(case_id, event_id));
CREATE TABLE alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, chain_id TEXT NOT NULL, rule TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('low','medium','high')), subject TEXT NOT NULL,
  trigger_event_id TEXT NOT NULL, window_start TEXT NOT NULL, window_end TEXT NOT NULL,
  evidence TEXT NOT NULL, explanation TEXT NOT NULL, dedupe_key TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','acknowledged','dismissed')),
  synthetic INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, handled_by INTEGER, handled_at TEXT);
CREATE INDEX ix_alerts ON alerts(status, created_at);
CREATE TABLE evidence(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT NOT NULL UNIQUE, case_id INTEGER REFERENCES cases(id),
  kind TEXT NOT NULL CHECK(kind IN ('events_export','case_report')), fmt TEXT NOT NULL CHECK(fmt IN ('json','csv','pdf')),
  filename TEXT NOT NULL, media_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL,
  record_count INTEGER NOT NULL, filters TEXT NOT NULL, chain_head_seq INTEGER, chain_head_hash TEXT,
  includes_synthetic INTEGER NOT NULL DEFAULT 0, created_by INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL);
CREATE TABLE custody(
  id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_id INTEGER NOT NULL REFERENCES evidence(id),
  action TEXT NOT NULL CHECK(action IN ('acquired','accessed','downloaded','transferred','verified','note')),
  actor_id INTEGER REFERENCES users(id), actor_name TEXT NOT NULL, ts TEXT NOT NULL, detail TEXT NOT NULL,
  prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
CREATE INDEX ix_custody ON custody(evidence_id, id);
CREATE TABLE audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor_id INTEGER, actor_name TEXT NOT NULL,
  action TEXT NOT NULL, target TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '',
  prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
"""


def _triggers() -> str:
    out = []
    for t in APPEND_ONLY:
        for op in ("UPDATE", "DELETE"):
            out.append(
                f"CREATE TRIGGER {t}_no_{op.lower()} BEFORE {op} ON {t} "
                f"BEGIN SELECT RAISE(ABORT, '{t} is append-only'); END;"
            )
    return "\n".join(out)


MIGRATIONS = [(1, SCHEMA_V1 + _triggers())]


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=15, isolation_level=None)  # autocommit; BEGIN is explicit
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def _split(sql: str) -> list[str]:
    """Split on ';' keeping CREATE TRIGGER ... END; bodies intact."""
    stmts, buf = [], ""
    for line in sql.splitlines():
        buf += line + "\n"
        s = buf.strip()
        if s.endswith(";") and (not s.upper().startswith("CREATE TRIGGER") or s.upper().endswith("END;")):
            stmts.append(s)
            buf = ""
    return stmts


def migrate(conn: sqlite3.Connection, env: str = "development") -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
    done = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
    for version, sql in MIGRATIONS:
        if version in done:
            continue
        conn.execute("BEGIN IMMEDIATE")
        try:
            for stmt in _split(sql):
                conn.execute(stmt)
            conn.execute("INSERT INTO schema_migrations VALUES(?,?)", (version, utcnow()))
            if version == 1:
                conn.execute("INSERT INTO settings VALUES('environment',?,?)", (env, utcnow()))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_exc=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()
