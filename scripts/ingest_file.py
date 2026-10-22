"""Push events from an EXPLICITLY CHOSEN, AUTHORIZED log source to the SentinelTrace ingest API.
Nothing is read automatically. You must pass the file, the server URL and set SENTINEL_INGEST_TOKEN.
  linux:   python scripts/ingest_file.py --kind linux   --file /var/log/auth.log --url https://host
  windows: python scripts/ingest_file.py --kind windows --file events.jsonl     --url https://host
(windows input: one JSON object per line exported from the Security log, e.g. via Get-WinEvent | ConvertTo-Json)"""
import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.adapters import parse_linux_auth_line, parse_windows_event  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--kind", choices=["linux", "windows"], required=True)
ap.add_argument("--file", required=True)
ap.add_argument("--url", required=True)
a = ap.parse_args()
token = os.environ.get("SENTINEL_INGEST_TOKEN")
if not token:
    sys.exit("Set SENTINEL_INGEST_TOKEN to the server's ingest token.")
batch = []
for line in open(a.file, encoding="utf-8", errors="replace"):
    rec = parse_linux_auth_line(line) if a.kind == "linux" else (parse_windows_event(json.loads(line)) if line.strip() else None)
    if rec:
        batch.append(rec)
sent = 0
for i in range(0, len(batch), 100):
    req = urllib.request.Request(a.url.rstrip("/") + "/api/v1/ingest", data=json.dumps({"events": batch[i:i + 100]}).encode(),
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        sent += json.loads(r.read())["accepted"]
print(f"Ingested {sent} of {len(batch)} parsed records.")
