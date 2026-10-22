# API v1

Auth: browser session cookie. State-changing calls need header `X-CSRF-Token` (value of `<meta name="csrf">`). Ingest uses `Authorization: Bearer <SENTINEL_INGEST_TOKEN>` and no cookie/CSRF.
Errors: `{"error":{"code":"...","message":"..."}}` with 400/401/403/404/422/429/503. Lists: `{"<items>":[...],"pagination":{page,per_page,total,pages}}` (`per_page` ≤ 100).

| Method & path | Permission | Notes |
|---|---|---|
| GET `/api/v1/health` | none | `{"status","time"}` only |
| GET `/api/v1/dashboard/metrics` | dashboard.view | totals, 24 h success/failure, hourly buckets, top sources, open alerts, integrity, chain head |
| GET `/api/v1/events` | events.view | filters: `q, event_type, outcome, username, ip, date_from, date_to (YYYY-MM-DD UTC), synthetic (0/1), after_id, page, per_page` |
| POST `/api/v1/integrity/verify` | integrity.verify | read-only; stores a run; returns findings/warnings |
| GET `/api/v1/alerts?status=open` | alerts.view | includes explanation and evidence event ids |
| GET `/api/v1/cases`, `/api/v1/cases/<ref>` | cases.manage | own cases (all for admin); others → 404 |
| POST `/api/v1/evidence/exports` | evidence.export | `{"format":"json|csv|pdf","filters":{...}}` → 201 `{"evidence":{ref,fmt,sha256,size_bytes,record_count,created_at}}` |
| GET `/api/v1/evidence/<ref>` | evidence.view | metadata only |
| POST `/api/v1/ingest` | bearer token | `{"events":[{"event_type","outcome","username","source_ip","user_agent","timestamp?","metadata?"}]}` 1–100 items → 202 `{"accepted","event_ids"}`; atomic validation; disabled (503) without a token; rate limited |
| GET `/stream/events` | events.view | SSE: `id:` = row id, `event: auth_event`; connections last ≤55 s and the browser reconnects with `Last-Event-ID`; max 3 per user |

Event types: `login_success, login_failure, login_throttled, logout, password_change, password_reset_requested, password_reset_completed, mfa_enabled, mfa_disabled, mfa_failure, account_created, session_event`. Outcomes: `success, failure, blocked, info`.
