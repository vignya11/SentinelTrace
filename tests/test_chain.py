import json
import sqlite3

from app.chain import compute_hash, create_checkpoint, verify_chain, genesis_hash
from .helpers import Base

KEY = "unit-test-checkpoint-key"


class ChainTests(Base):
    def verify(self, key="", ext=""):
        c = self.db(); r = verify_chain(c, "main", key, ext); c.close(); return r

    def types(self, r):
        return {f["type"] for f in r["findings"]}

    def test_valid_chain_and_genesis(self):
        self.events(10); r = self.verify()
        self.assertTrue(r["ok"]); self.assertEqual(r["records_checked"], 10); self.assertEqual(r["head_seq"], 10)
        self.assertEqual(self.count("SELECT COUNT(*) FROM auth_events WHERE prev_hash=?", genesis_hash("main")), 1)

    def test_empty_chain_ok(self):
        self.assertTrue(self.verify()["ok"])

    def test_modified_record_detected(self):
        self.events(8); self.raw("auth_events", "UPDATE auth_events SET username='mallory' WHERE chain_seq=4")
        r = self.verify(); self.assertFalse(r["ok"])
        f = [x for x in r["findings"] if x["type"] == "record_modified"]
        self.assertEqual([x["seq"] for x in f], [4])

    def test_broken_previous_hash_link_detected_even_with_recomputed_hash(self):
        self.events(8); conn = self.db()
        row = dict(conn.execute("SELECT * FROM auth_events WHERE chain_seq=5").fetchone())
        row["prev_hash"] = "f" * 64; new = compute_hash(row); conn.close()
        self.raw("auth_events", ("UPDATE auth_events SET prev_hash=?, record_hash=? WHERE chain_seq=5", ("f" * 64, new)))
        r = self.verify(); self.assertFalse(r["ok"])
        self.assertIn("broken_link", self.types(r))  # seq 5's own link, plus seq 6 no longer links to the new hash

    def test_deleted_middle_record_detected(self):
        self.events(8); self.raw("auth_events", "DELETE FROM auth_events WHERE chain_seq=5")
        r = self.verify(); self.assertFalse(r["ok"]); self.assertIn("missing_sequence", self.types(r)); self.assertIn("broken_link", self.types(r))

    def test_reordered_records_detected(self):
        self.events(8)
        self.raw("auth_events", "UPDATE auth_events SET id=1000 WHERE id=3", "UPDATE auth_events SET id=3 WHERE id=4", "UPDATE auth_events SET id=4 WHERE id=1000")
        r = self.verify(); self.assertFalse(r["ok"]); self.assertTrue(self.types(r) & {"reordered_or_duplicate", "missing_sequence", "broken_link"})

    def test_tail_deletion_undetectable_without_checkpoint_but_warned(self):
        self.events(8); self.raw("auth_events", "DELETE FROM auth_events WHERE chain_seq>6")
        r = self.verify(); self.assertTrue(r["ok"])  # documented limitation
        self.assertTrue(any("undetectable" in w for w in r["warnings"]))

    def test_tail_deletion_detected_with_checkpoint(self):
        self.events(8); c = self.db(); create_checkpoint(c, "main", KEY, "", None); c.close()
        self.raw("auth_events", "DELETE FROM auth_events WHERE chain_seq>6")
        self.assertIn("truncation", self.types(self.verify(KEY)))

    def test_full_rewrite_caught_by_external_checkpoint_and_hmac(self):
        self.events(8); ext = f"{self.tmp}/anchor/checkpoints.jsonl"
        c = self.db(); create_checkpoint(c, "main", KEY, ext, None); c.close()
        self.assertTrue(self.verify(KEY, ext)["ok"])
        # attacker rewrites record 3 and re-links/rehashes EVERYTHING after it, and fixes the database checkpoint too
        conn = self.db()
        for t in ("auth_events", "checkpoints"):
            for op in ("update", "delete"):
                conn.execute(f"DROP TRIGGER IF EXISTS {t}_no_{op}")
        rows = [dict(r) for r in conn.execute("SELECT * FROM auth_events ORDER BY chain_seq")]
        prev = genesis_hash("main")
        for r in rows:
            if r["chain_seq"] == 3:
                r["username"] = "forged"
            r["prev_hash"] = prev; r["record_hash"] = compute_hash(r); prev = r["record_hash"]
            conn.execute("UPDATE auth_events SET username=?, prev_hash=?, record_hash=? WHERE chain_seq=?", (r["username"], r["prev_hash"], r["record_hash"], r["chain_seq"]))
        from app.util import sha256_hex
        from app.chain import checkpoint_message
        cp = dict(conn.execute("SELECT * FROM checkpoints").fetchone())
        conn.execute("UPDATE checkpoints SET head_hash=?, digest=? WHERE id=?", (prev, sha256_hex(checkpoint_message("main", cp["chain_seq"], prev, cp["created_at"]).encode()), cp["id"]))
        conn.close()
        no_anchor = self.verify()  # internally consistent: a bare hash chain is fooled
        self.assertTrue(no_anchor["ok"] or "checkpoint_signature_invalid" in self.types(no_anchor))
        r = self.verify(KEY, ext); self.assertFalse(r["ok"])
        self.assertIn("checkpoint_mismatch", self.types(r))              # external file still holds the original head
        self.assertIn("checkpoint_signature_invalid", self.types(r))     # forged database checkpoint cannot carry a valid HMAC

    def test_wrong_key_flags_signature(self):
        self.events(4); c = self.db(); create_checkpoint(c, "main", KEY, "", None); c.close()
        self.assertIn("checkpoint_signature_invalid", self.types(self.verify("different-key")))

    def test_verification_is_read_only(self):
        self.events(6); self.raw("auth_events", "UPDATE auth_events SET username='x' WHERE chain_seq=2")
        snap = lambda: [tuple(r) for r in self.db().execute("SELECT * FROM auth_events ORDER BY id")]
        before = snap(); self.verify(); self.verify()
        self.assertEqual(before, snap())  # tampered record is reported, never repaired

    def test_checkpoint_refuses_tampered_chain(self):
        self.events(5); self.raw("auth_events", "UPDATE auth_events SET username='x' WHERE chain_seq=2")
        c = self.db()
        with self.assertRaises(ValueError):
            create_checkpoint(c, "main", KEY, "", None)
        c.close()

    def test_append_only_triggers_block_normal_writes(self):
        self.events(3); c = self.db(); create_checkpoint(c, "main", "", "", None)
        for sql in ("UPDATE auth_events SET username='x'", "DELETE FROM auth_events", "UPDATE checkpoints SET digest='x'"):
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute(sql)
        c.close()

    def test_events_persist_across_app_restart(self):
        self.user("alice"); self.login("alice")
        n = self.count("SELECT COUNT(*) FROM auth_events"); self.assertGreaterEqual(n, 1)
        self.make_app()  # new application instance over the same database file
        self.assertEqual(self.count("SELECT COUNT(*) FROM auth_events"), n)
        self.assertTrue(self.verify()["ok"])
        self.login("alice", "wrong-password-123")  # chain continues correctly after restart
        r = self.verify(); self.assertTrue(r["ok"]); self.assertEqual(r["records_checked"], n + 1)

    def test_sensitive_metadata_dropped_and_unknown_types_rejected(self):
        from app.chain import append_event
        c = self.db()
        rec = append_event(c, chain_id="main", event_type="login_failure", outcome="failure", username="a",
                           metadata={"password": "hunter2", "session_cookie": "abc", "otp": "123456", "api_token": "t", "reason": "bad"})
        self.assertEqual(json.loads(rec["metadata"]), {"reason": "bad"})
        with self.assertRaises(ValueError):
            append_event(c, chain_id="main", event_type="nope", outcome="success")
        c.close()

    def test_integrity_page_and_api_report_findings(self):
        self.events(6); self.raw("auth_events", "UPDATE auth_events SET username='x' WHERE chain_seq=3")
        c = self.as_user("ivy", "investigator")
        r = c.post("/api/v1/integrity/verify", headers={"X-CSRF-Token": self.token(c)}); j = r.get_json()
        self.assertEqual(r.status_code, 200); self.assertFalse(j["ok"]); self.assertEqual(j["findings"][0]["type"], "record_modified")
        self.assertIn("record modified", c.get("/integrity").get_data(True))
        self.assertEqual(self.count("SELECT COUNT(*) FROM integrity_runs WHERE ok=0"), 1)
