"""Tamper-evident hash chain for authentication events.

Each record commits (SHA-256 over canonical JSON) to its own fields AND the previous record's hash.
Genesis is explicit and per-chain. Verification is strictly read-only.

LIMITS (see THREAT_MODEL.md): an attacker who can rewrite the whole chain and recompute hashes is only
caught by an independent anchor (HMAC-signed checkpoint with an out-of-database key and/or an external
checkpoint file). Without a checkpoint, deletion of the newest records cannot be detected.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import uuid

from .util import canonical, clean_text, parse_ts, sha256_hex, utcnow

SCHEMA_VERSION = 1
EVENT_TYPES = {
    "login_success", "login_failure", "login_throttled", "logout", "password_change",
    "password_reset_requested", "password_reset_completed", "mfa_enabled", "mfa_disabled",
    "mfa_failure", "account_created", "session_event",
}
OUTCOMES = {"success", "failure", "blocked", "info"}
HASHED_FIELDS = (
    "schema_version", "chain_id", "chain_seq", "event_id", "ts", "user_id", "username", "event_type",
    "outcome", "source_ip", "user_agent", "metadata", "synthetic", "prev_hash",
)
_SENSITIVE = re.compile(r"pass|secret|token|otp|cookie|session|auth|key|credential|pwd", re.I)


def genesis_hash(chain_id: str) -> str:
    return sha256_hex(f"SENTINELTRACE-GENESIS:{chain_id}".encode())


def compute_hash(rec) -> str:
    return sha256_hex(canonical({k: rec[k] for k in HASHED_FIELDS}))


def safe_metadata(meta) -> str:
    """Canonical JSON string; drops sensitive-looking keys, flattens values, bounds size."""
    out = {}
    for k, v in list((meta or {}).items())[:20]:
        k = clean_text(k, 40)
        if not k or _SENSITIVE.search(k):
            continue
        out[k] = v if isinstance(v, (bool, int, float)) or v is None else clean_text(v, 200)
    return canonical(out).decode()


def normalize_ip(ip) -> str:
    try:
        return ipaddress.ip_address(str(ip).strip()).compressed
    except ValueError:
        return "unknown"


def append_event(db, *, chain_id, event_type, outcome, username="", user_id=None, source_ip=None,
                 user_agent="", metadata=None, synthetic=False, ts=None) -> dict:
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown event_type {event_type!r}")
    if outcome not in OUTCOMES:
        raise ValueError(f"unknown outcome {outcome!r}")
    meta = safe_metadata(metadata)
    db.execute("BEGIN IMMEDIATE")
    try:
        last = db.execute(
            "SELECT chain_seq, record_hash FROM auth_events WHERE chain_id=? ORDER BY chain_seq DESC LIMIT 1",
            (chain_id,)).fetchone()
        rec = {
            "schema_version": SCHEMA_VERSION, "chain_id": chain_id,
            "chain_seq": (last["chain_seq"] + 1) if last else 1,
            "event_id": str(uuid.uuid4()), "ts": ts or utcnow(), "user_id": user_id,
            "username": clean_text(username, 64).lower(), "event_type": event_type, "outcome": outcome,
            "source_ip": normalize_ip(source_ip), "user_agent": clean_text(user_agent, 300),
            "metadata": meta, "synthetic": 1 if synthetic else 0,
            "prev_hash": last["record_hash"] if last else genesis_hash(chain_id),
        }
        rec["record_hash"] = compute_hash(rec)
        cur = db.execute(
            "INSERT INTO auth_events(event_id,chain_id,chain_seq,ts,user_id,username,event_type,outcome,source_ip,"
            "user_agent,metadata,synthetic,prev_hash,record_hash,schema_version) VALUES"
            "(:event_id,:chain_id,:chain_seq,:ts,:user_id,:username,:event_type,:outcome,:source_ip,"
            ":user_agent,:metadata,:synthetic,:prev_hash,:record_hash,:schema_version)", rec)
        rec["id"] = cur.lastrowid
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    return rec


def linked_hash(prev: str, payload: dict) -> str:
    """Hash for generic append-only linked tables (custody, audit)."""
    return sha256_hex(canonical({"prev": prev, "payload": payload}))


def checkpoint_message(chain_id, seq, head_hash, created_at) -> str:
    return f"{chain_id}|{seq}|{head_hash}|{created_at}"


def _mac(key: str, msg: str) -> str:
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()


def read_external(path: str) -> list[dict]:
    if not path or not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    out.append({"_corrupt": line[:80]})
    return out


def create_checkpoint(db, chain_id, key="", external_path="", user_id=None):
    """Anchor the current chain head. Refuses to anchor a chain that already fails verification."""
    res = verify_chain(db, chain_id, key, external_path)
    if not res["ok"]:
        raise ValueError("chain fails verification; refusing to anchor a tampered state")
    if res["head_seq"] == 0:
        raise ValueError("chain is empty; nothing to anchor")
    ts = utcnow()
    msg = checkpoint_message(chain_id, res["head_seq"], res["head_hash"], ts)
    digest, mac = sha256_hex(msg.encode()), (_mac(key, msg) if key else None)
    ref = None
    if external_path:
        os.makedirs(os.path.dirname(os.path.abspath(external_path)), exist_ok=True)
        entry = {"chain_id": chain_id, "chain_seq": res["head_seq"], "head_hash": res["head_hash"],
                 "created_at": ts, "digest": digest, "hmac": mac}
        with open(external_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        ref = os.path.basename(external_path)
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute("INSERT INTO checkpoints(chain_id,chain_seq,head_hash,created_at,digest,hmac,external_ref,created_by)"
                   " VALUES(?,?,?,?,?,?,?,?)", (chain_id, res["head_seq"], res["head_hash"], ts, digest, mac, ref, user_id))
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    return {"chain_seq": res["head_seq"], "head_hash": res["head_hash"], "created_at": ts, "signed": bool(mac)}


def verify_chain(db, chain_id, key="", external_path="") -> dict:
    """READ-ONLY verification. Never modifies or repairs records."""
    findings, warnings = [], []
    exp_seq, exp_prev, checked = 1, genesis_hash(chain_id), 0
    head_seq, head_hash = 0, genesis_hash(chain_id)
    by_seq = {}
    cur = db.execute("SELECT * FROM auth_events WHERE chain_id=? ORDER BY id", (chain_id,))
    for r in cur:
        checked += 1
        eid = r["event_id"]
        if r["chain_seq"] != exp_seq:
            kind = "missing_sequence" if r["chain_seq"] > exp_seq else "reordered_or_duplicate"
            findings.append({"type": kind, "seq": r["chain_seq"], "event_id": eid,
                             "detail": f"expected sequence {exp_seq}, found {r['chain_seq']}"})
        if r["prev_hash"] != exp_prev:
            findings.append({"type": "broken_link", "seq": r["chain_seq"], "event_id": eid,
                             "detail": "previous-hash does not match the preceding record's hash"})
        if compute_hash(r) != r["record_hash"]:
            findings.append({"type": "record_modified", "seq": r["chain_seq"], "event_id": eid,
                             "detail": "stored hash does not match the record's contents"})
        exp_seq, exp_prev = r["chain_seq"] + 1, r["record_hash"]
        head_seq, head_hash = r["chain_seq"], r["record_hash"]
        by_seq[r["chain_seq"]] = r["record_hash"]

    def check_anchor(src, cp):
        if "_corrupt" in cp:
            findings.append({"type": "external_checkpoint_corrupt", "seq": None, "event_id": None,
                             "detail": f"{src}: unreadable line"})
            return
        msg = checkpoint_message(cp["chain_id"], cp["chain_seq"], cp["head_hash"], cp["created_at"])
        if cp.get("hmac"):
            if key:
                if not hmac.compare_digest(_mac(key, msg), cp["hmac"]):
                    findings.append({"type": "checkpoint_signature_invalid", "seq": cp["chain_seq"], "event_id": None,
                                     "detail": f"{src}: HMAC does not verify with the configured key"})
                    return
            else:
                warnings.append(f"{src} checkpoint at seq {cp['chain_seq']} is signed but no key is configured; signature not verified")
        if sha256_hex(msg.encode()) != cp.get("digest"):
            findings.append({"type": "checkpoint_digest_invalid", "seq": cp["chain_seq"], "event_id": None,
                             "detail": f"{src}: checkpoint digest mismatch"})
            return
        if cp["chain_seq"] > head_seq:
            findings.append({"type": "truncation", "seq": cp["chain_seq"], "event_id": None,
                             "detail": f"{src}: checkpoint anchors seq {cp['chain_seq']} but chain ends at {head_seq}"})
        elif by_seq.get(cp["chain_seq"]) != cp["head_hash"]:
            findings.append({"type": "checkpoint_mismatch", "seq": cp["chain_seq"], "event_id": None,
                             "detail": f"{src}: record at seq {cp['chain_seq']} no longer matches the anchored hash"})

    cps = [dict(c) for c in db.execute("SELECT * FROM checkpoints WHERE chain_id=? ORDER BY id", (chain_id,))]
    for cp in cps:
        check_anchor("database", cp)
    ext = [c for c in read_external(external_path) if c.get("chain_id", chain_id) == chain_id]
    for cp in ext:
        check_anchor("external", cp)
    if not cps and not ext:
        warnings.append("No checkpoint exists: removal of the newest records, or a full chain rewrite, would be undetectable.")
    elif not ext:
        warnings.append("No external checkpoint configured: an attacker with database write access could also alter database checkpoints.")
    if cps and not key:
        warnings.append("No checkpoint HMAC key configured: checkpoints are not authenticated.")
    return {"chain_id": chain_id, "records_checked": checked, "ok": not findings, "findings": findings,
            "warnings": warnings, "head_seq": head_seq, "head_hash": head_hash,
            "checkpoints_checked": len(cps) + len(ext), "verified_at": utcnow()}


def verify_linked(rows, genesis="0" * 64, fields=()) -> list[dict]:
    """Verify a list of rows from a linked table (custody/audit). Returns findings."""
    prev, out = genesis, []
    for r in rows:
        payload = {k: r[k] for k in fields}
        if r["prev_hash"] != prev:
            out.append({"type": "broken_link", "id": r["id"]})
        if linked_hash(r["prev_hash"], payload) != r["entry_hash"]:
            out.append({"type": "entry_modified", "id": r["id"]})
        prev = r["entry_hash"]
    return out


__all__ = ["append_event", "verify_chain", "create_checkpoint", "parse_ts"]
