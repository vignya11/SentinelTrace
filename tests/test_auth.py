import re
import time
import sqlite3

from app import security as sec
from app.util import sha256_hex
from .helpers import PW, Base


class AuthTests(Base):
    def test_valid_login_and_event_recorded(self):
        self.user("alice")
        r = self.login("alice")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(self.count("SELECT COUNT(*) FROM auth_events WHERE event_type='login_success' AND username='alice'"), 1)

    def test_invalid_login_is_generic_and_recorded(self):
        self.user("alice")
        r1 = self.login("alice", "wrong-password-123")
        r2 = self.login("nobody", "wrong-password-123")
        self.assertEqual((r1.status_code, r2.status_code), (401, 401))
        msg = lambda r: re.search(r'class="flash error"[^>]*>([^<]+)<', r.get_data(True)).group(1)
        self.assertEqual(msg(r1), msg(r2))  # no user enumeration
        self.assertEqual(self.count("SELECT COUNT(*) FROM auth_events WHERE event_type='login_failure'"), 2)

    def test_password_hash_and_plaintext_never_exposed(self):
        self.user("root", "admin"); c = self.app.test_client(); self.login("root", client=c)
        self.login("root", "wrong-secret-XYZ-1")  # failure path
        conn = self.db(); h = conn.execute("SELECT password_hash FROM users").fetchone()[0]; conn.close()
        for url in ("/dashboard", "/events", "/users", "/audit", "/settings", "/integrity", "/account", "/api/v1/events"):
            body = c.get(url).get_data(True)
            self.assertNotIn(h, body, url); self.assertNotIn(PW, body, url)
        conn = self.db()
        blob = " ".join(str(tuple(r)) for t in ("auth_events", "audit") for r in conn.execute(f"SELECT * FROM {t}"))
        conn.close()
        for needle in (h, PW, "wrong-secret-XYZ-1", "scrypt:"):
            self.assertNotIn(needle, blob)

    def test_session_rotation_on_login_prevents_fixation(self):
        self.user("alice")
        self.client.get("/login")
        with self.client.session_transaction() as s:
            s["sid"] = "attacker-fixed-sid"
        self.login("alice")
        with self.client.session_transaction() as s:
            self.assertNotEqual(s["sid"], "attacker-fixed-sid")
            new = s["sid"]
        self.assertEqual(self.count("SELECT COUNT(*) FROM sessions WHERE sid_hash=?", sha256_hex(b"attacker-fixed-sid")), 0)
        self.assertEqual(self.count("SELECT COUNT(*) FROM sessions WHERE sid_hash=?", sha256_hex(new.encode())), 1)

    def test_logout_invalidates_server_side_session(self):
        self.user("alice"); self.login("alice")
        cookie = self.client.get_cookie("st_session").value
        stolen = self.app.test_client(); stolen.set_cookie("st_session", cookie)
        self.assertEqual(stolen.get("/dashboard").status_code, 200)
        self.assertEqual(self.post("/logout").status_code, 302)
        self.assertEqual(stolen.get("/dashboard").status_code, 302)  # replayed cookie is dead
        self.assertEqual(self.count("SELECT COUNT(*) FROM sessions"), 0)

    def test_cookie_flags(self):
        self.user("alice"); r = self.login("alice")
        sc = r.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", sc); self.assertIn("SameSite=Lax", sc)

    def test_csrf_rejected(self):
        self.user("alice")
        self.assertEqual(self.client.post("/login", data={"username": "alice", "password": PW}).status_code, 400)
        self.assertEqual(self.client.post("/login", data={"username": "alice", "password": PW, "csrf_token": "bad"}).status_code, 400)
        self.login("alice")
        self.assertEqual(self.client.post("/logout").status_code, 400)
        r = self.client.post("/api/v1/integrity/verify")  # session-authenticated API write without CSRF header
        self.assertEqual((r.status_code, r.get_json()["error"]["code"]), (400, "csrf_failed"))

    def test_login_throttling_and_backoff(self):
        self.user("alice")
        for _ in range(5):
            self.assertEqual(self.login("alice", "wrong-password-123").status_code, 401)
        self.assertEqual(self.login("alice", PW).status_code, 429)  # correct password is refused while locked
        self.assertEqual(self.login("ghost", PW).status_code, 401)  # unknown account is not treated differently
        for _ in range(5):
            self.login("ghost", "x" * 12)
        self.assertEqual(self.login("ghost", PW).status_code, 429)  # ...and is throttled the same way
        self.assertGreaterEqual(self.count("SELECT COUNT(*) FROM auth_events WHERE event_type='login_throttled'"), 1)

    def test_admin_can_unlock(self):
        self.user("alice"); adm = self.as_user("boss", "admin")
        for _ in range(5):
            self.login("alice", "wrong-password-123")
        self.assertEqual(self.login("alice").status_code, 429)
        uid = self.count("SELECT id FROM users WHERE username='alice'")
        self.assertEqual(self.post(f"/users/{uid}/unlock", client=adm).status_code, 302)
        self.assertEqual(self.login("alice").status_code, 302)

    def test_password_policy(self):
        with self.app.test_request_context():
            self.assertTrue(sec.validate_password("short1"))
            self.assertTrue(sec.validate_password("alicealicealice", "alice"))
            self.assertTrue(sec.validate_password("aaaaaaaaaaaaaaaa"))
            self.assertFalse(sec.validate_password("Correct-Horse-Battery-9", "alice"))

    def test_registration_disabled_by_default_and_least_privilege_when_enabled(self):
        self.assertIn("turned off", self.client.get("/register").get_data(True))
        self.assertEqual(self.post("/register", {"username": "x", "email": "a@b.co", "password": PW}).status_code, 200)
        self.make_app(REGISTRATION_ENABLED=True)
        r = self.post("/register", {"username": "newbie", "email": "n@example.test", "password": PW})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.count("SELECT COUNT(*) FROM users WHERE username='newbie' AND role='analyst'"), 1)

    def test_password_change_rotates_session_and_kills_others(self):
        self.user("alice"); self.login("alice")
        other = self.app.test_client(); self.login("alice", client=other)
        with self.client.session_transaction() as s:
            before = s["sid"]
        new = "Another-Strong-Pass-77"
        self.post("/account/password", {"current_password": PW, "new_password": new})
        with self.client.session_transaction() as s:
            self.assertNotEqual(s["sid"], before)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(other.get("/dashboard").status_code, 302)
        self.post("/logout"); self.assertEqual(self.login("alice", PW).status_code, 401)
        self.assertEqual(self.login("alice", new).status_code, 302)

    def test_must_change_password_forces_account_page(self):
        conn = self.db()
        from app.services import create_user
        create_user(conn, "temp", "t@example.test", PW, "analyst", must_change=True); conn.close()
        self.login("temp")
        r = self.client.get("/dashboard"); self.assertEqual(r.status_code, 302); self.assertIn("/account", r.headers["Location"])

    def test_mfa_flow_wrong_code_and_replay(self):
        self.user("alice"); self.login("alice")
        self.post("/account/mfa/start")
        conn = self.db(); secret = conn.execute("SELECT totp_secret FROM users").fetchone()[0]; conn.close()
        now = int(time.time() // 30)
        self.assertEqual(self.post("/account/mfa/confirm", {"code": "000000"}).status_code, 302)
        self.assertEqual(self.count("SELECT totp_enabled FROM users"), 0)  # wrong code does not enable
        self.post("/account/mfa/confirm", {"code": sec.totp_code(secret, now)})
        self.assertEqual(self.count("SELECT totp_enabled FROM users"), 1)
        self.post("/logout")
        r = self.login("alice"); self.assertEqual(r.status_code, 302); self.assertIn("/login/mfa", r.headers["Location"])
        self.assertEqual(self.client.get("/dashboard").status_code, 302)  # password alone is not enough
        self.assertEqual(self.post("/login/mfa", {"code": "123456"}).status_code, 401)
        good = sec.totp_code(secret, now + 1)
        self.assertEqual(self.post("/login/mfa", {"code": good}).status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.post("/logout"); self.login("alice")
        self.assertEqual(self.post("/login/mfa", {"code": good}).status_code, 401)  # replay rejected

    def test_recovery_disabled_by_default_and_file_adapter_single_use(self):
        self.user("alice")
        self.post("/forgot", {"identifier": "alice"})
        self.assertEqual(len(__import__("os").listdir(self.app.config["OUTBOX_DIR"])), 0)
        self.make_app(RECOVERY_ADAPTER="file")
        self.login("alice"); other = self.app.test_client(); self.login("alice", client=other)
        self.client = self.app.test_client()
        self.post("/forgot", {"identifier": "alice"})
        import os
        files = os.listdir(self.app.config["OUTBOX_DIR"]); self.assertEqual(len(files), 1)
        token = re.search(r"/reset/(\S+)", self.read(os.path.join(self.app.config["OUTBOX_DIR"], files[0]), "r")).group(1)
        self.assertEqual(self.client.get(f"/reset/{token}").status_code, 200)
        self.assertEqual(self.post(f"/reset/{token}", {"password": "Brand-New-Passphrase-5"}).status_code, 302)
        self.assertEqual(self.client.get(f"/reset/{token}").status_code, 400)  # single use
        self.assertEqual(other.get("/dashboard").status_code, 302)  # old sessions revoked

    def test_security_headers(self):
        h = self.client.get("/").headers
        self.assertIn("default-src 'self'", h["Content-Security-Policy"]); self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertNotIn("unsafe-inline", h["Content-Security-Policy"])
