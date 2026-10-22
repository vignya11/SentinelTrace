# SentinelTrace — Tamper-Evident Authentication & Digital Forensics Platform

Flask + SQLite application that records authentication events in a SHA-256 hash chain, verifies it read-only,
raises rule-based suspicious-activity indicators, and packages evidence (JSON/CSV/PDF) with digests and a
hash-linked chain of custody.

> **Status: working, tested core (75 automated tests executed and passing — see `TESTING.md`).**
> Read `docs/PRODUCTION_READINESS.md` and `THREAT_MODEL.md` before putting it in front of a customer.

## What is implemented
Landing page · login/logout · optional TOTP 2FA · password change · recovery adapter (dev file outbox) · overview dashboard ·
event explorer (server-side filters + pagination) · integrity verification + checkpoints · six detection rules (configurable) ·
investigations (notes/hypotheses/findings, UTC timeline, correlation) · evidence export (JSON/CSV/PDF) with SHA-256 ·
chain-of-custody · user/role admin · settings & health · admin audit trail · live SSE stream with polling fallback ·
token-authenticated ingest API · Linux/Windows log adapters · labelled synthetic simulator and demo seeder · `/api/v1` JSON API.

## Deviations from the brief (honest list)
| Brief | What was built | Why |
|---|---|---|
| SQLAlchemy + Alembic | `sqlite3` with parameterized queries, a versioned migration runner (`app/db.py`), DB-level append-only triggers | The build sandbox had no network, so SQLAlchemy/Flask-WTF/pytest/PyOTP could not be installed and therefore could not be tested. |
| Flask-WTF CSRF | Own session-bound CSRF tokens (constant-time compare), tested | same |
| PyOTP | RFC 6238 TOTP implemented in stdlib, verified against the RFC test vector | same |
| pytest | `unittest` (pytest also collects these tests) | same |
| Chart.js / Lucide | Hand-written SVG chart and icon sprite served from `/static` | Keeps a strict CSP (`script-src 'self'`, no inline) and works offline |
| PostgreSQL support | **Not implemented.** SQLite only (WAL mode) | Not testable here |
| Docker | **Not provided** | Cannot be built/tested here; not shipping untested images |
| OpenAPI | Written API reference in `docs/API.md` | — |
| Retention enforcement | Policy value shown only; **no purge job** | Evidence is append-only by design |
| Argon2id | Werkzeug scrypt | Argon2 library not installable here |
| TOTP QR code | Manual key entry only | No QR library available |

## Windows 10/11 + VS Code setup (PowerShell)
```powershell
cd sentineltrace
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
pip install -r requirements.txt
```
In VS Code: *Ctrl+Shift+P → Python: Select Interpreter → .venv*.

### A. Demo (separate database, synthetic data)
```powershell
$env:SENTINEL_ENV="demo"
python scripts/seed_demo.py --reset     # prints three random demo logins ONCE
python run.py                           # http://127.0.0.1:5000
```
Database: `instance\sentineltrace_demo.db`. Everything in it is flagged synthetic; the UI shows a banner. Use *Simulate* buttons on the dashboard (admin) to add labelled synthetic events live.

### B. Real use (development machine)
```powershell
$env:SENTINEL_ENV="development"
python scripts/create_admin.py          # prompts for credentials (hidden input)
python run.py
```
Database: `instance\sentineltrace.db`. The seeder **refuses** to run unless `SENTINEL_ENV=demo`.

### C. Production-style start
```powershell
$env:SENTINEL_ENV="production"
$env:SENTINEL_SECRET_KEY="<64 hex chars>"
$env:SENTINEL_CHECKPOINT_KEY="<another random secret>"
$env:SENTINEL_CHECKPOINT_EXTERNAL="E:\anchors\checkpoints.jsonl"   # different disk/host
$env:SENTINEL_TRUSTED_PROXIES="1"                                  # if behind a TLS-terminating proxy
waitress-serve --listen=127.0.0.1:8000 wsgi:app
```
Terminate TLS at a reverse proxy (IIS ARR, nginx, Caddy). See `docs/PRODUCTION_READINESS.md`.

## Tests
```powershell
python -m unittest discover -s tests -t . -v      # or: pytest
```
Tests use temporary databases and never touch `instance\`.

## Tools
* `python scripts/verify_chain.py --db instance\sentineltrace.db --external E:\anchors\checkpoints.jsonl` — read-only verification (exit 0/1).
* `python scripts/ingest_file.py --kind linux --file auth.log --url https://host` — pushes an explicitly chosen source (needs `SENTINEL_INGEST_TOKEN`).

## Roles
| Role | Can |
|---|---|
| analyst | view dashboard, events, alerts, integrity results |
| investigator | + acknowledge alerts, run verification, manage **own** cases, export/download **own** evidence |
| admin | + users, settings, audit trail, checkpoints, simulator, all cases/evidence |

## Backup / restore
Stop the app, copy `instance\*.db` (+ `-wal`/`-shm` if present) **and** `instance\evidence\`, **and** the external checkpoint file, to separate storage. Restore by copying back, then run `verify_chain.py`. Keep the checkpoint key in a secret manager, not in the backup of the database.
