# Architecture

```
 Browser ──HTTPS──▶ reverse proxy (TLS) ──▶ waitress ──▶ Flask app (create_app)
                                                         │
   auth.py  web.py  api.py ──▶ services.py ──▶ chain.py   (hash chain, checkpoints, verification)
                       │             │        alerts.py   (rule engine)
                       │             └──────▶ evidence.py (snapshots, digests, custody)
                       ▼
                 SQLite (WAL)  ◀── scripts/ (seed_demo, create_admin, verify_chain, ingest_file)
                       ▲
   External sources ──▶ POST /api/v1/ingest (bearer token) ◀── adapters.py (Linux sshd, Windows 4624/4625/4634)
   Checkpoint anchor ─▶ external JSONL file + HMAC key (outside DB)
```

## Data flow: a login
1. `POST /login` → CSRF check → throttle check → password verify (constant-time dummy for unknown users).
2. `services.record_event` → `chain.append_event`: inside `BEGIN IMMEDIATE`, read chain head, build record, `record_hash = SHA256(canonical JSON of fields + prev_hash)`, insert.
3. `alerts.evaluate_event` runs the rules for that event (windows are relative to the event's own timestamp); alerts are de-duplicated per rule+subject while an earlier alert's window is still active.
4. Dashboard/API read aggregates directly from `auth_events`; `GET /stream/events` (SSE) polls the table for new ids and pushes them; the browser reconnects automatically (`Last-Event-ID`) or falls back to polling `/api/v1/events?after_id=`.

## Record format (schema v1)
Hashed fields: `schema_version, chain_id, chain_seq, event_id, ts, user_id, username, event_type, outcome, source_ip, user_agent, metadata, synthetic, prev_hash` — serialized as sorted-key, whitespace-free ASCII JSON. Genesis `prev_hash = SHA256("SENTINELTRACE-GENESIS:" + chain_id)`.

## Verification (read-only)
Walk records in insertion order and check: sequence continuity (`missing_sequence`, `reordered_or_duplicate`), previous-hash link (`broken_link`), recomputed digest (`record_modified`); then check every database and external checkpoint (`checkpoint_mismatch`, `truncation`, `checkpoint_signature_invalid`, `checkpoint_digest_invalid`). Findings carry sequence and event id. Nothing is written or repaired; checkpoints refuse to anchor a chain that already fails.

## Checkpoints & key handling
`message = chain_id|seq|head_hash|created_at`; stored with `SHA256(message)` and, if `SENTINEL_CHECKPOINT_KEY` is set, `HMAC-SHA256(key, message)`. If `SENTINEL_CHECKPOINT_EXTERNAL` is set, each checkpoint is also appended (fsync) to that file. **Rotation:** create a checkpoint, archive the old key and external file with their date range, set the new key, create a new checkpoint; verify old ranges with the old key (`SENTINEL_CHECKPOINT_KEY=<old> python scripts/verify_chain.py ...`). A mixed-key history currently reports `checkpoint_signature_invalid` for old checkpoints under the new key — expected until multi-key verification is added.

## Schema (tables)
`users, sessions, login_attempts, password_resets, auth_events*, checkpoints*, integrity_runs, cases, case_notes*, case_events, alerts, evidence*, custody*, audit*, settings, schema_migrations` (`*` = append-only triggers). `custody` and `audit` are additionally hash-linked.
