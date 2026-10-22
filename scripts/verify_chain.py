"""Read-only chain verification from the command line. Exit code 0 = no findings, 1 = findings, 2 = error.
  python scripts/verify_chain.py --db instance/sentineltrace.db [--external path/to/checkpoints.jsonl]
Set SENTINEL_CHECKPOINT_KEY in the environment to verify checkpoint HMACs."""
import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.chain import verify_chain  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--db", required=True)
ap.add_argument("--chain", default="main")
ap.add_argument("--external", default="")
a = ap.parse_args()
conn = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)  # opened read-only
conn.row_factory = sqlite3.Row
res = verify_chain(conn, a.chain, os.environ.get("SENTINEL_CHECKPOINT_KEY", ""), a.external)
print(json.dumps(res, indent=2))
sys.exit(0 if res["ok"] else 1)
