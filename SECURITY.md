# Security

## Implemented and tested controls
* Passwords: scrypt (Werkzeug), 12–128 chars, blocklist, no username; constant-time dummy hash for unknown users; never logged.
* Sessions: random 256-bit id, only its SHA-256 stored server-side; rotation on login/password change; idle (30 min) + absolute (8 h) expiry; logout and password/role change revoke sessions; cookie `HttpOnly`, `SameSite=Lax`, `Secure` in production.
* CSRF on every state-changing request (form field or `X-CSRF-Token`), constant-time comparison.
* Throttling: per-account and per-IP, progressive backoff (15 min doubling, max 24 h); identical generic responses for known and unknown users.
* TOTP 2FA with replay protection (a code step can be used once).
* RBAC enforced server-side on every route; object-level ownership checks (non-owners get 404) for cases/evidence.
* Append-only SQLite triggers on events, checkpoints, case notes, evidence, custody, audit (defence in depth against application bugs).
* Strict CSP (no inline script/style), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `no-store`.
* SQL: parameterized only; filter fields allow-listed; LIKE wildcards escaped.
* CSV formula-injection guard; evidence written write-once (`xb`) and made read-only; digest re-checked before every download.
* Errors never expose stack traces; health endpoint reveals nothing sensitive.

## Known weaknesses — read these
1. **TOTP secrets are stored in the database in clear (base32).** Anyone with DB read access can clone second factors. Needs envelope encryption with an external key.
2. **Rate limiting and SSE stream counters are per-process memory.** With several workers limits multiply; use a shared store or a reverse-proxy limiter.
3. **Hash chain ≠ tamper-proof.** See `THREAT_MODEL.md`.
4. Triggers and file permissions do not stop an attacker with DB/file-system administrator rights.
5. SQLite is single-writer; heavy ingest will serialize writes.
6. No email adapter; recovery is disabled by default and the `file` adapter is for development only.
7. Not independently pen-tested. Not tested on Windows or against waitress in the build sandbox.

Report vulnerabilities privately to the maintainer; do not open public issues containing exploit details.
