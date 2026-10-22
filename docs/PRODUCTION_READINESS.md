# Production-readiness checklist

Legend: ✅ done & tested · ⚠️ done, needs operator action · ❌ not done

- ✅ Secure defaults: registration off, simulator off, recovery off, ingest off, secure cookies in production, secret required in production
- ✅ RBAC, CSRF, throttling, TOTP, strict CSP, append-only triggers, evidence digests, custody chain
- ⚠️ **TLS**: terminate HTTPS at a reverse proxy, redirect HTTP→HTTPS, set `SENTINEL_TRUSTED_PROXIES`, keep HSTS
- ⚠️ **Anchoring**: set `SENTINEL_CHECKPOINT_KEY` + `SENTINEL_CHECKPOINT_EXTERNAL` (different disk/host/WORM); schedule a checkpoint (e.g. hourly) and a `verify_chain.py` run with alerting on exit code 1
- ⚠️ **Secrets**: environment/secret manager only; rotate on schedule (see ARCHITECTURE.md)
- ⚠️ **Permissions**: run as a dedicated low-privilege account; only that account can write `instance\`; evidence folder not web-served
- ⚠️ **Backups**: DB + evidence + external checkpoints, off-host, restore-tested; log retention policy decided by the customer (the app never purges)
- ⚠️ **Monitoring**: watch process, disk space, `/api/v1/health`, failed verification runs, structured JSON logs on stdout
- ⚠️ **Incident response**: on any integrity finding — preserve DB copy + WAL, do not repair, compare against external checkpoints, record in a case
- ❌ PostgreSQL, Docker image, email adapter, TOTP secret encryption, shared rate-limit store, HA, SSO/SAML, automated retention
- ❌ Independent penetration test and Windows/waitress validation — **required before customer hand-over**
