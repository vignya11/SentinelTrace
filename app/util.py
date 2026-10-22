"""Small shared helpers: UTC time, hashing, canonical JSON, input cleaning."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

TS_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def utcnow_dt() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(TS_FMT)


def utcnow() -> str:
    return iso(utcnow_dt())


def parse_ts(s: str) -> datetime:
    return datetime.strptime(s, TS_FMT).replace(tzinfo=timezone.utc)


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def canonical(obj) -> bytes:
    """Deterministic JSON: sorted keys, no whitespace, ASCII only."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def clean_text(value, limit: int = 200) -> str:
    return _CTRL.sub("", str(value if value is not None else "")).strip()[:limit]


def escape_like(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def safe_next(target: str | None) -> str | None:
    """Only allow same-site relative redirects."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return None


def hours_ago(h: float) -> str:
    return iso(utcnow_dt() - timedelta(hours=h))
