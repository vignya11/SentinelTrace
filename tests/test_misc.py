import os
import unittest
from unittest import mock

from app.adapters import parse_linux_auth_line, parse_windows_event
from app.security import totp_code
from app.util import safe_next
from app.config import load_config


class MiscTests(unittest.TestCase):
    def test_totp_rfc6238_vector(self):
        # RFC 6238 Appendix B, SHA-1, T=59s -> step 1 -> 94287082 (8 digits); 6-digit form is the last 6 digits
        self.assertEqual(totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1, 8), "94287082")
        self.assertEqual(totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1, 6), "287082")

    def test_linux_adapter(self):
        ok = parse_linux_auth_line("Mar 10 12:00:01 host sshd[123]: Accepted password for alice from 192.0.2.7 port 22 ssh2", 2026)
        bad = parse_linux_auth_line("Mar 10 12:00:05 host sshd[124]: Failed password for invalid user admin from 203.0.113.9 port 55 ssh2", 2026)
        self.assertEqual((ok["event_type"], ok["username"], ok["source_ip"]), ("login_success", "alice", "192.0.2.7"))
        self.assertEqual((bad["event_type"], bad["username"], bad["timestamp"]), ("login_failure", "admin", "2026-03-10T12:00:05.000000Z"))
        self.assertIsNone(parse_linux_auth_line("Mar 10 12:00:05 host cron[1]: job done"))

    def test_windows_adapter(self):
        r = parse_windows_event({"EventID": 4625, "TargetUserName": "bob", "IpAddress": "198.51.100.4", "TimeCreated": "2026-03-10T12:00:00Z", "LogonType": 3})
        self.assertEqual((r["event_type"], r["outcome"], r["username"]), ("login_failure", "failure", "bob"))
        self.assertIsNone(parse_windows_event({"EventID": 9999, "TimeCreated": "2026-03-10T12:00:00Z"}))
        self.assertIsNone(parse_windows_event({"EventID": 4624, "TimeCreated": "garbage"}))

    def test_open_redirect_guard(self):
        self.assertEqual(safe_next("/events?x=1"), "/events?x=1")
        for bad in ("//evil.example", "https://evil.example", "\\\\evil", "javascript:alert(1)", None, ""):
            self.assertIsNone(safe_next(bad))

    def test_production_requires_strong_secret(self):
        with mock.patch.dict(os.environ, {"SENTINEL_ENV": "production", "SENTINEL_SECRET_KEY": ""}):
            with self.assertRaises(RuntimeError):
                load_config()
        with mock.patch.dict(os.environ, {"SENTINEL_ENV": "production", "SENTINEL_SECRET_KEY": "s" * 40}):
            c = load_config(); self.assertTrue(c["SESSION_COOKIE_SECURE"]); self.assertFalse(c["SIMULATOR_ENABLED"]); self.assertFalse(c["REGISTRATION_ENABLED"])
