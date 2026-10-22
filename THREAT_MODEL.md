# Threat model

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| 1 | Insider edits a record via SQL | Hash mismatch → `record_modified` | Detected only when verification runs |
| 2 | Insider deletes/reorders middle records | Sequence + link checks | Detected on verification |
| 3 | Insider deletes the **newest** records | Checkpoints (DB + external) → `truncation` | **Undetectable if no checkpoint exists after those records** (UI warns) |
| 4 | Attacker rewrites the **entire** chain and recomputes hashes | External checkpoint file + HMAC key held outside the DB | **Not detected** if attacker also controls the external file and the key, or no anchor is configured |
| 5 | Attacker with DB admin drops triggers | Triggers are only defence-in-depth | Triggers do not stop DB admins; rely on #1–#4 detection |
| 6 | Credential stuffing / brute force | Throttle + backoff, generic errors, optional TOTP | Distributed attacks across many IPs/accounts are slowed, not prevented |
| 7 | Session theft | HttpOnly/Secure/SameSite, server-side revoke, rotation, idle timeout | XSS-free assumption relies on strict CSP |
| 8 | CSRF / clickjacking | Tokens, SameSite, `frame-ancestors 'none'` | — |
| 9 | IDOR on cases/evidence | Ownership checks (404) | — |
| 10 | Tampered evidence file | Digest checked before download; custody logs refusals | Attacker who edits file **and** DB row needs DB admin (see #5); custody chain exposes edits to custody rows |
| 11 | Log forging through ingest | Token auth, validation, rate limit, source marked `ingested` | A leaked ingest token lets an attacker add false events (they remain attributable as ingested) |
| 12 | Spreadsheet formula injection in CSV | Leading `' ` escape | CSV is no longer byte-identical to source values; JSON is the canonical export |
| 13 | Host compromise | Out of scope | Full compromise defeats all in-app controls |

**What a verified result means:** records are internally consistent and (if anchored) consistent with checkpoints. It does **not** prove the events were genuine, complete, correctly timestamped (clock is the server's, or the source's for ingested events), or legally admissible. Detections are leads, not proof of compromise.
**Out of scope:** OS-level log collection without explicit authorization, geolocation/threat-intel (none used), multi-tenant isolation, high-availability.
