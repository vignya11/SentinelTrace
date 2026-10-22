# Testing

Run: `python -m unittest discover -s tests -t . -v` (also works with `pytest`). Tests build temporary databases under the OS temp folder.

## Result actually obtained
**75 tests, 0 failures, 0 errors** — run in the build sandbox (Linux, Python 3.12.3, Flask 3.1.3). Full output: `docs/test_run_output.txt`.

| Module | Tests | Covers |
|---|---|---|
| `test_auth` | 16 | valid/invalid login, generic errors, hash/plaintext never in responses/audit/events, session rotation (fixation), logout revocation, cookie flags, CSRF rejection, throttling + backoff + unlock, password policy, registration default-off, password-change session kill, forced change, TOTP flow + replay, recovery adapter, security headers |
| `test_rbac` | 9 | unauthenticated access, analyst/investigator limits, case & evidence IDOR, admin guard rails, session revocation on role change, audit append-only |
| `test_chain` | 16 | valid chain, empty chain, modified record, broken link (even with recomputed hash), deleted/reordered records, tail deletion (undetectable w/o checkpoint; detected with), full-chain rewrite vs external checkpoint + HMAC, wrong key, verification read-only, refusing to anchor tampered chain, triggers, persistence across restart, metadata sanitization, API/page findings |
| `test_alerts` | 10 | each rule's threshold/window, dedupe, configurability, live-login alerts, status workflow, alert→case link with originals untouched |
| `test_api` | 9 | health, pagination, filters (incl. LIKE-escape & injection strings), metrics derived from DB, ingest auth/validation/rate-limit/disabled, SSE authorization + resume, error shape, API rate limit |
| `test_evidence` | 8 | JSON digest + per-record re-hash, CSV injection guard, PDF, validation, API export, download custody, tampered-file refusal, custody linking/append-only/tamper display, case report workflow |
| `test_misc` | 5 | RFC 6238 vector, Linux/Windows adapters, redirect guard, production config |

## Also executed manually (not part of the suite)
* Seeded the demo DB (142 synthetic events → 7 alerts), started the real server, signed in over HTTP, fetched all 10 admin pages (200), the metrics API, and the SSE stream.
* Headless Chromium (Playwright) drove the UI and captured `docs/screenshots/*`; **no console or CSP errors** were reported.

## Not tested
Windows, waitress/gunicorn, HTTPS/proxy deployment, browsers other than Chromium, load/concurrency, accessibility audit beyond semantic markup and contrast choices, penetration testing, multi-worker rate limiting.
