from datetime import timedelta

from app.services import record_event
from app.util import iso, parse_ts, utcnow_dt
from .helpers import Base

T0 = parse_ts("2026-03-10T12:00:00.000000Z")  # fixed, inside baseline hours


class AlertTests(Base):
    def add(self, kind, user, ip, minutes, ua="ua-1"):
        with self.app.app_context():
            c = self.db()
            record_event(c, "login_failure" if kind == "f" else "login_success", "failure" if kind == "f" else "success",
                         user, None, {}, False, iso(T0 + timedelta(minutes=minutes)), ip, ua)
            c.close()

    def alerts(self, rule=None):
        c = self.db()
        rows = [dict(r) for r in c.execute("SELECT * FROM alerts" + (" WHERE rule=?" if rule else ""), (rule,) if rule else ())]
        c.close(); return rows

    def test_repeated_failures_threshold(self):
        for i in range(4):
            self.add("f", "alice", "192.0.2.1", i)
        self.assertEqual(self.alerts("failures_per_account"), [])
        self.add("f", "alice", "192.0.2.1", 4)
        a = self.alerts("failures_per_account"); self.assertEqual(len(a), 1)
        self.assertIn("indicator requiring investigation", a[0]["explanation"]); self.assertEqual(a[0]["subject"], "alice")
        self.assertIn("5 failed logins", a[0]["explanation"])

    def test_failures_outside_window_do_not_count(self):
        for i in range(5):
            self.add("f", "alice", "192.0.2.1", i * 4)  # 0,4,8,12,16 minutes: never 5 inside 10 min
        self.assertEqual(self.alerts("failures_per_account"), [])

    def test_no_duplicate_alerts_for_ongoing_burst(self):
        for i in range(9):
            self.add("f", "alice", "192.0.2.1", i * 0.5)
        self.assertEqual(len(self.alerts("failures_per_account")), 1)

    def test_source_burst_and_many_accounts(self):
        for i in range(10):
            self.add("f", f"user{i % 5}", "203.0.113.9", i * 0.2)
        self.assertEqual(len(self.alerts("source_burst")), 1)
        self.assertEqual(len(self.alerts("many_accounts_one_source")), 1)
        import json
        ev = json.loads(self.alerts("source_burst")[0]["evidence"]); self.assertEqual(len(ev), 10)

    def test_success_after_failures(self):
        for i in range(3):
            self.add("f", "bob", "198.51.100.2", i)
        self.add("s", "bob", "198.51.100.2", 4)
        a = self.alerts("success_after_failures"); self.assertEqual(len(a), 1); self.assertEqual(a[0]["severity"], "high")

    def test_unusual_hour_relative_to_baseline(self):
        self.add("s", "carol", "192.0.2.5", 0)  # 12:00 UTC: inside baseline
        self.assertEqual(self.alerts("unusual_hour"), [])
        self.add("s", "carol", "192.0.2.5", 15 * 60)  # 03:00 UTC next day
        self.assertEqual(len(self.alerts("unusual_hour")), 1)

    def test_new_ip_or_device(self):
        for i in range(3):
            self.add("s", "dave", "192.0.2.7", i * 90)
        self.add("s", "dave", "192.0.2.7", 300); self.assertEqual(self.alerts("new_ip_or_device"), [])
        self.add("s", "dave", "203.0.113.200", 400)
        a = self.alerts("new_ip_or_device"); self.assertEqual(len(a), 1); self.assertIn("203.0.113.200", a[0]["explanation"])

    def test_thresholds_are_configurable(self):
        adm = self.as_user("boss", "admin")
        data = {"failures_per_account.threshold": "3", "failures_per_account.window_min": "10"}
        self.post("/settings", data, client=adm)
        for i in range(3):
            self.add("f", "erin", "192.0.2.3", i)
        self.assertEqual(len(self.alerts("failures_per_account")), 1)
        r = self.post("/settings", {"failures_per_account.threshold": "0"}, client=adm)  # invalid value rejected
        self.assertEqual(self.alerts("failures_per_account")[0]["rule"], "failures_per_account")

    def test_live_events_create_alerts_via_login_failures(self):
        self.user("alice")
        for _ in range(5):
            self.login("alice", "wrong-password-123")
        self.assertEqual(len(self.alerts("failures_per_account")), 1)

    def test_alert_status_workflow_and_case_link(self):
        for i in range(5):
            self.add("f", "alice", "192.0.2.1", i)
        inv = self.as_user("ivy", "investigator"); ana = self.as_user("ann", "analyst")
        aid = self.alerts()[0]["id"]
        self.assertEqual(self.post(f"/alerts/{aid}/status", {"status": "acknowledged"}, client=ana).status_code, 403)
        self.post(f"/alerts/{aid}/status", {"status": "acknowledged"}, client=inv)
        self.assertEqual(self.count("SELECT COUNT(*) FROM alerts WHERE status='acknowledged'"), 1)
        ref = self.post("/cases", {"title": "From alert", "severity": "medium"}, client=inv).headers["Location"].rsplit("/", 1)[1]
        self.post(f"/alerts/{aid}/to-case", {"case_ref": ref}, client=inv)
        self.assertGreaterEqual(self.count("SELECT COUNT(*) FROM case_events"), 5)
        self.assertEqual(self.count("SELECT COUNT(*) FROM auth_events WHERE username='alice'"), 5)  # originals untouched
