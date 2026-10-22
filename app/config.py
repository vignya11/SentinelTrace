"""Configuration. Secrets come from the environment, never from the repo or database."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INSTANCE = ROOT / "instance"


def _bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _dev_secret() -> str:
    INSTANCE.mkdir(exist_ok=True)
    p = INSTANCE / ".dev_secret_key"  # gitignored; development only
    if not p.exists():
        p.write_text(secrets.token_hex(32))
    return p.read_text().strip()


def load_config(overrides: dict | None = None) -> dict:
    env = os.environ.get("SENTINEL_ENV", "development").lower()
    if env not in {"development", "demo", "production", "testing"}:
        raise RuntimeError("SENTINEL_ENV must be development, demo, production or testing")
    default_db = INSTANCE / ("sentineltrace_demo.db" if env == "demo" else "sentineltrace.db")
    cfg = {
        "ENV": env,
        "SECRET_KEY": os.environ.get("SENTINEL_SECRET_KEY") or ("" if env == "production" else _dev_secret()),
        "DATABASE": os.environ.get("SENTINEL_DB", str(default_db)),
        "EVIDENCE_DIR": os.environ.get("SENTINEL_EVIDENCE_DIR", str(INSTANCE / "evidence")),
        "OUTBOX_DIR": os.environ.get("SENTINEL_OUTBOX_DIR", str(INSTANCE / "outbox")),
        "CHECKPOINT_KEY": os.environ.get("SENTINEL_CHECKPOINT_KEY", ""),
        "CHECKPOINT_EXTERNAL_PATH": os.environ.get("SENTINEL_CHECKPOINT_EXTERNAL", ""),
        "INGEST_TOKEN": os.environ.get("SENTINEL_INGEST_TOKEN", ""),
        "REGISTRATION_ENABLED": _bool("SENTINEL_REGISTRATION", False),
        "SIMULATOR_ENABLED": _bool("SENTINEL_SIMULATOR", env == "demo"),
        "RECOVERY_ADAPTER": os.environ.get("SENTINEL_RECOVERY", "none"),  # none | file
        "TRUSTED_PROXY_COUNT": _int("SENTINEL_TRUSTED_PROXIES", 0),
        "SESSION_COOKIE_SECURE": _bool("SENTINEL_COOKIE_SECURE", env == "production"),
        "SESSION_IDLE_MINUTES": _int("SENTINEL_IDLE_MINUTES", 30),
        "SESSION_ABSOLUTE_HOURS": _int("SENTINEL_ABSOLUTE_HOURS", 8),
        "LOCKOUT_THRESHOLD": _int("SENTINEL_LOCKOUT_THRESHOLD", 5),
        "LOCKOUT_BASE_MINUTES": _int("SENTINEL_LOCKOUT_MINUTES", 15),
        "IP_THROTTLE_THRESHOLD": _int("SENTINEL_IP_THRESHOLD", 30),
        "API_RATE_PER_MIN": _int("SENTINEL_API_RATE", 240),
        "INGEST_RATE_PER_MIN": _int("SENTINEL_INGEST_RATE", 120),
        "STREAM_MAX_SECONDS": _int("SENTINEL_STREAM_SECONDS", 55),
        "STREAM_POLL_SECONDS": float(os.environ.get("SENTINEL_STREAM_POLL", 2)),
        "MAX_STREAMS_PER_USER": 3,
        "CHAIN_ID": "main",
        "MAX_CONTENT_LENGTH": 1_000_000,
        "PASSWORD_MIN_LENGTH": 12,
        "RETENTION_DAYS": _int("SENTINEL_RETENTION_DAYS", 365),
        "MAX_EXPORT_RECORDS": 50_000,
    }
    if overrides:
        cfg.update(overrides)
    if cfg["ENV"] == "production" and len(cfg["SECRET_KEY"]) < 32:
        raise RuntimeError("SENTINEL_SECRET_KEY (>=32 chars) is required in production")
    return cfg
