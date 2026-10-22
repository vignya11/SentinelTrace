import json

from .helpers import Base


class RbacTests(Base):
    def test_unauthenticated(self):
        r = self.client.get("/dashboard"); self.assertEqual(r.status_code, 302); self.assertIn("/login", r.headers["Location"])
        for url in ("/api/v1/events", "/api/v1/dashboard/metrics", "/api/v1/alerts", "/api/v1/cases", "/stream/events"):
            r = self.client.get(url); self.assertEqual(r.status_code, 401, url); self.assertEqual(r.get_json()["error"]["code"], "unauthenticated")

    def test_analyst_is_read_only(self):
        c = self.as_user("ann", "analyst")
        for url in ("/events", "/alerts", "/integrity", "/dashboard"):
            self.assertEqual(c.get(url).status_code, 200, url)
        for url in ("/cases", "/evidence", "/users", "/settings", "/audit"):
            self.assertEqual(c.get(url).status_code, 403, url)
        self.assertEqual(self.post("/integrity/verify", client=c).status_code, 403)
        self.assertEqual(self.post("/evidence/export", {"format": "json"}, client=c).status_code, 403)
        self.assertEqual(self.post("/simulator/run", client=c).status_code, 403)
        self.assertEqual(self.post("/integrity/checkpoint", client=c).status_code, 403)
        r = c.post("/api/v1/evidence/exports", json={"format": "json"}, headers={"X-CSRF-Token": self.token(c)})
        self.assertEqual(r.status_code, 403)

    def test_investigator_cannot_administer(self):
        self.events(3); c = self.as_user("ivy", "investigator")
        for url in ("/users", "/settings", "/audit"):
            self.assertEqual(c.get(url).status_code, 403, url)
        self.assertEqual(c.get("/cases").status_code, 200)
        self.assertEqual(self.post("/integrity/checkpoint", client=c).status_code, 403)
        self.assertEqual(self.post("/users/create", {"username": "evil", "email": "e@x.co", "role": "admin"}, client=c).status_code, 403)

    def test_case_idor(self):
        a, b, adm = self.as_user("ivy", "investigator"), self.as_user("ian", "investigator"), self.as_user("boss", "admin")
        r = self.post("/cases", {"title": "Case of ivy", "severity": "high"}, client=a)
        ref = r.headers["Location"].rsplit("/", 1)[1]
        self.assertEqual(a.get(f"/cases/{ref}").status_code, 200)
        self.assertEqual(adm.get(f"/cases/{ref}").status_code, 200)
        self.assertEqual(b.get(f"/cases/{ref}").status_code, 404)
        for sub in ("notes", "events", "status", "report"):
            self.assertEqual(self.post(f"/cases/{ref}/{sub}", {"kind": "note", "body": "x", "status": "closed", "event_ids": ""}, client=b).status_code, 404, sub)
        self.assertEqual(b.get(f"/api/v1/cases/{ref}").status_code, 404)
        self.assertNotIn(ref, b.get("/cases").get_data(True))

    def test_evidence_idor_and_download(self):
        self.events(4)
        a, b = self.as_user("ivy", "investigator"), self.as_user("ian", "investigator")
        r = self.post("/evidence/export", {"format": "json"}, client=a); ref = r.headers["Location"].rsplit("/", 1)[1]
        self.assertEqual(a.get(f"/evidence/{ref}").status_code, 200)
        for url in (f"/evidence/{ref}", f"/evidence/{ref}/download", f"/api/v1/evidence/{ref}"):
            self.assertEqual(b.get(url).status_code, 404, url)
        self.assertEqual(self.post(f"/evidence/{ref}/verify", client=b).status_code, 404)
        self.assertEqual(self.post(f"/evidence/{ref}/custody", {"action": "note", "detail": "hack"}, client=b).status_code, 404)

    def test_admin_safety_guards(self):
        adm = self.as_user("boss", "admin"); self.user("ann", "analyst")
        me = self.count("SELECT id FROM users WHERE username='boss'"); ann = self.count("SELECT id FROM users WHERE username='ann'")
        self.post(f"/users/{me}/role", {"role": "analyst"}, client=adm)
        self.assertEqual(self.count("SELECT role='admin' FROM users WHERE id=?", me), 1)  # cannot demote self / last admin
        self.post(f"/users/{me}/status", {"status": "disabled"}, client=adm)
        self.assertEqual(self.count("SELECT status='active' FROM users WHERE id=?", me), 1)
        self.post(f"/users/{ann}/role", {"role": "bogus"}, client=adm)
        self.assertEqual(self.count("SELECT COUNT(*) FROM users WHERE id=? AND role='analyst'", ann), 1)
        self.assertGreaterEqual(self.count("SELECT COUNT(*) FROM audit"), 0)

    def test_role_change_revokes_sessions_and_is_audited(self):
        adm = self.as_user("boss", "admin"); inv = self.as_user("ivy", "investigator")
        uid = self.count("SELECT id FROM users WHERE username='ivy'")
        self.post(f"/users/{uid}/role", {"role": "analyst"}, client=adm)
        self.assertEqual(inv.get("/dashboard").status_code, 302)  # must re-authenticate
        self.assertEqual(self.count("SELECT COUNT(*) FROM audit WHERE action='user.role'"), 1)

    def test_create_user_flow_temp_password(self):
        adm = self.as_user("boss", "admin")
        r = self.post("/users/create", {"username": "newhire", "email": "n@example.test", "role": "analyst"}, client=adm)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.count("SELECT must_change_password FROM users WHERE username='newhire'"), 1)
        self.assertEqual(self.count("SELECT COUNT(*) FROM audit WHERE action='user.create'"), 1)

    def test_audit_trail_is_append_only(self):
        adm = self.as_user("boss", "admin")
        self.post("/integrity/verify", client=adm)
        conn = self.db()
        import sqlite3
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("UPDATE audit SET detail='x'")
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM audit")
        conn.close()
