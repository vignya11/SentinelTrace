import csv
import hashlib
import io
import json
import os
import sqlite3

from app.chain import compute_hash, verify_linked
from app.evidence import CUSTODY_FIELDS
from .helpers import Base


class EvidenceTests(Base):
    def export(self, c, **data):
        d = {"format": "json"}; d.update(data)
        r = self.post("/evidence/export", d, client=c); self.assertEqual(r.status_code, 302, r.get_data(True)[:300])
        return r.headers["Location"].rsplit("/", 1)[1]

    def path(self, ref, fmt="json"):
        return os.path.join(self.app.config["EVIDENCE_DIR"], f"{ref}.{fmt}")

    def test_json_export_digest_manifest_and_record_hashes(self):
        self.events(12, username="zed"); c = self.as_user("ivy", "investigator")
        ref = self.export(c, username="zed")
        data = self.read(self.path(ref))
        row = self.db().execute("SELECT * FROM evidence WHERE ref=?", (ref,)).fetchone()
        self.assertEqual(hashlib.sha256(data).hexdigest(), row["sha256"]); self.assertEqual(len(data), row["size_bytes"])
        doc = json.loads(data); m = doc["manifest"]
        self.assertEqual((m["record_count"], m["exported_by"], m["filters"]), (12, "ivy", {"username": "zed"}))
        self.assertEqual(len(doc["records"]), 12); self.assertEqual(row["record_count"], 12)
        for r in doc["records"]:  # every exported record can be independently re-hashed
            rec = dict(r); rec.update(chain_id="main", user_id=None, schema_version=1, metadata=json.dumps(r["metadata"], sort_keys=True, separators=(",", ":")), synthetic=int(r["synthetic"]))
            self.assertEqual(compute_hash(rec), r["record_hash"])
        self.assertEqual(self.count("SELECT COUNT(*) FROM auth_events WHERE username='zed'"), 12)  # source preserved
        self.assertEqual(self.count("SELECT COUNT(*) FROM audit WHERE action='evidence.export'"), 1)
        self.assertEqual(os.stat(self.path(ref)).st_mode & 0o222, 0)  # snapshot is read-only on disk

    def test_csv_export_and_formula_injection_guard(self):
        self.events(3, username="=cmd|calc"); c = self.as_user("ivy", "investigator")
        ref = self.export(c, format="csv", username="=cmd|calc")
        rows = list(csv.reader(io.StringIO(self.read(self.path(ref, "csv"), "r", encoding="utf-8"))))
        self.assertEqual(len(rows), 4); col = rows[0].index("username")
        self.assertTrue(all(r[col] == "'=cmd|calc" for r in rows[1:]))

    def test_pdf_export(self):
        self.events(5); c = self.as_user("ivy", "investigator"); ref = self.export(c, format="pdf")
        data = self.read(self.path(ref, "pdf")); self.assertTrue(data.startswith(b"%PDF"))
        self.assertEqual(hashlib.sha256(data).hexdigest(), self.db().execute("SELECT sha256 FROM evidence").fetchone()[0])

    def test_export_validation(self):
        c = self.as_user("ivy", "investigator")
        r = self.post("/evidence/export", {"format": "json", "username": "nobody"}, client=c); self.assertEqual(r.status_code, 302)
        self.assertEqual(self.count("SELECT COUNT(*) FROM evidence"), 0)
        self.assertEqual(self.post("/evidence/export", {"format": "exe"}, client=c).status_code, 400)
        self.assertEqual(self.post("/evidence/export", {"format": "json", "date_from": "garbage"}, client=c).status_code, 302)
        self.assertEqual(self.count("SELECT COUNT(*) FROM evidence"), 0)

    def test_api_export_returns_digest(self):
        self.events(4); c = self.as_user("ivy", "investigator")
        r = c.post("/api/v1/evidence/exports", json={"format": "json", "filters": {"username": "user0"}}, headers={"X-CSRF-Token": self.token(c)})
        self.assertEqual(r.status_code, 201); e = r.get_json()["evidence"]
        self.assertEqual(hashlib.sha256(self.read(self.path(e["ref"]))).hexdigest(), e["sha256"])
        bad = c.post("/api/v1/evidence/exports", json={"format": "zip"}, headers={"X-CSRF-Token": self.token(c)}); self.assertEqual(bad.status_code, 400)

    def test_download_logs_custody_and_audit(self):
        self.events(3); c = self.as_user("ivy", "investigator"); ref = self.export(c)
        r = c.get(f"/evidence/{ref}/download"); self.assertEqual(r.status_code, 200)
        self.assertIn("attachment", r.headers["Content-Disposition"]); self.assertEqual(hashlib.sha256(r.data).hexdigest(), self.db().execute("SELECT sha256 FROM evidence").fetchone()[0])
        acts = [x[0] for x in self.db().execute("SELECT action FROM custody ORDER BY id")]
        self.assertEqual(acts, ["acquired", "downloaded"]); self.assertEqual(self.count("SELECT COUNT(*) FROM audit WHERE action='evidence.download'"), 1)

    def test_tampered_artifact_is_refused_and_logged(self):
        self.events(3); c = self.as_user("ivy", "investigator"); ref = self.export(c)
        p = self.path(ref); os.chmod(p, 0o644)
        with open(p, "ab") as fh:
            fh.write(b"\n tampered")
        r = c.get(f"/evidence/{ref}/download"); self.assertEqual(r.status_code, 409); self.assertNotIn(b"tampered", r.data)
        self.post(f"/evidence/{ref}/verify", client=c)
        details = [x[0] for x in self.db().execute("SELECT detail FROM custody ORDER BY id")]
        self.assertTrue(any("REFUSED" in d for d in details)); self.assertTrue(any("MISMATCH" in d for d in details))
        self.assertIn("MISMATCH", c.get(f"/evidence/{ref}").get_data(True))

    def test_custody_entries_append_only_and_hash_linked(self):
        self.events(3); c = self.as_user("ivy", "investigator"); ref = self.export(c)
        self.post(f"/evidence/{ref}/custody", {"action": "transferred", "detail": "ivy to legal counsel for review"}, client=c)
        self.post(f"/evidence/{ref}/custody", {"action": "delete", "detail": "attempt"}, client=c)  # not an allowed action
        conn = self.db(); rows = conn.execute("SELECT * FROM custody ORDER BY id").fetchall()
        self.assertEqual(len(rows), 2); self.assertEqual(verify_linked(rows, fields=CUSTODY_FIELDS), [])
        for sql in ("UPDATE custody SET detail='x'", "DELETE FROM custody", "UPDATE evidence SET sha256='x'", "DELETE FROM evidence"):
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(sql)
        conn.close()
        self.assertIn("Custody chain verified", c.get(f"/evidence/{ref}").get_data(True))
        self.raw("custody", "UPDATE custody SET detail='rewritten history' WHERE id=1")  # privileged attacker edits custody
        self.assertIn("Custody chain verification FAILED", c.get(f"/evidence/{ref}").get_data(True))

    def test_case_report_and_forensic_workflow(self):
        evs = self.events(6, username="victim"); c = self.as_user("ivy", "investigator")
        ref = self.post("/cases", {"title": "Suspicious logins", "severity": "high"}, client=c).headers["Location"].rsplit("/", 1)[1]
        self.assertEqual(self.post(f"/cases/{ref}/report", client=c).status_code, 302)
        self.assertEqual(self.count("SELECT COUNT(*) FROM evidence"), 0)  # no events linked yet
        ids = " ".join(e["event_id"] for e in evs[:4]) + " not-a-real-id " + evs[0]["event_id"]
        self.post(f"/cases/{ref}/events", {"event_ids": ids}, client=c)
        self.assertEqual(self.count("SELECT COUNT(*) FROM case_events"), 4)  # unknown + duplicate skipped
        self.post(f"/cases/{ref}/notes", {"kind": "hypothesis", "body": "Shared account used from several hosts"}, client=c)
        self.post(f"/cases/{ref}/notes", {"kind": "finding", "body": "Four logins in one minute"}, client=c)
        page = c.get(f"/cases/{ref}").get_data(True)
        self.assertIn("Shared account used", page); self.assertIn("Correlation across all events", page); self.assertIn("victim", page)
        r = self.post(f"/cases/{ref}/report", client=c); self.assertEqual(r.status_code, 302)
        row = self.db().execute("SELECT * FROM evidence").fetchone(); self.assertEqual((row["kind"], row["fmt"], row["record_count"]), ("case_report", "pdf", 4))
        self.assertEqual(self.count("SELECT COUNT(*) FROM auth_events WHERE username='victim'"), 6)
        import sqlite3
        with self.assertRaises(sqlite3.IntegrityError):
            self.db().execute("UPDATE case_notes SET body='edited'")  # analyst notes cannot be rewritten
