"""Log-source adapters. They only NORMALIZE records; nothing is ingested unless an operator explicitly
configures an authorized source and pushes it to the ingest API (see scripts/ingest_file.py)."""
from __future__ import annotations

import re
from datetime import datetime, timezone

_SSH = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s\S+\ssshd\[\d+\]:\s(?P<res>Accepted|Failed)\s\S+\sfor\s(?:invalid user\s)?"
    r"(?P<user>\S+)\sfrom\s(?P<ip>[0-9a-fA-F:.]+)")


def parse_linux_auth_line(line: str, year: int | None = None) -> dict | None:
    """Parse an sshd 'Accepted/Failed ... for USER from IP' syslog line into an ingest record."""
    m = _SSH.match(line.strip())
    if not m:
        return None
    year = year or datetime.now(timezone.utc).year
    ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    ok = m["res"] == "Accepted"
    return {"event_type": "login_success" if ok else "login_failure", "outcome": "success" if ok else "failure",
            "username": m["user"], "source_ip": m["ip"], "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "metadata": {"source": "linux-sshd"}}


def parse_windows_event(ev: dict) -> dict | None:
    """Map a Windows Security event (dict with EventID, TargetUserName, IpAddress, TimeCreated) to an ingest record."""
    kinds = {4624: ("login_success", "success"), 4625: ("login_failure", "failure"), 4634: ("logout", "info")}
    k = kinds.get(int(ev.get("EventID", 0)))
    if not k:
        return None
    ts = str(ev.get("TimeCreated", "")).replace("Z", "").split(".")[0]
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return {"event_type": k[0], "outcome": k[1], "username": str(ev.get("TargetUserName", "")),
            "source_ip": str(ev.get("IpAddress", "")), "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "metadata": {"source": "windows-security", "event_id": int(ev["EventID"]),
                         "logon_type": str(ev.get("LogonType", ""))}}
