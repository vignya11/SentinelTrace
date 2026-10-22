import json

from app.chain import verify_chain
from .helpers import Base


class ApiTests(Base):
    def test_health_reveals_nothing_sensitive(self):
        r = self.client.get("/api/v1/health"); self.assertEqual(r.status_code, 200)
        body = r.get_data(True); self.assertEqual(set(r.get_json()), {"status", "time"})
        for s in ("SECRET", "ingest-token", "sqlite", self.tmp):
            self.assertNotIn(s, body)

    def test_pagination(self):
        self.events(60); c = self.as_user("ann")
        j = c.get("/api/v1/events?per_page=25").get_json()
        self.assertEqual((len(j["events"]), j["pagination"]["total"], j["pagination"]["pages"]), (25, 61, 3))  # +1 login event
        self.assertEqual(len(c.get("/api/v1/events?per_page=25&page=3").get_json()["events"]), 11)
        self.assertEqual(len(c.get("/api/v1/events?per_page=5000").get_json()["events"]), 61)
        self.assertEqual(c.get("/api/v1/events?per_page=5000").get_json()["pagination"]["per_page"], 100)
        ids = [e["id"] for e in j["events"]]; self.assertEqual(ids, sorted(ids, reverse=True))

    def test_filters(self):
        self.events(6, username="zed", ip="198.51.100.9"); self.events(4, username="amy", ip="192.0.2.77", event_type="login_failure")
        c = self.as_user("ann")
        g = lambda q: c.get("/api/v1/events?" + q).get_json()["pagination"]["total"]
        self.assertEqual(g("username=zed"), 6); self.assertEqual(g("ip=192.0.2.77"), 4); self.assertEqual(g("event_type=login_failure"), 4)
        self.assertEqual(g("q=198.51"), 6); self.assertEqual(g("q=%25"), 0)  # LIKE wildcards are escaped
        self.assertEqual(g("date_from=2999-01-01"), 0); self.assertEqual(g("date_to=2000-01-01"), 0)
        self.assertGreater(g("date_from=2000-01-01&date_to=2999-01-01"), 0)
        self.assertEqual(g("username=zed&event_type=login_failure"), 0)
        r = c.get("/api/v1/events?date_from=not-a-date"); self.assertEqual((r.status_code, r.get_json()["error"]["code"]), (400, "invalid_parameters"))
        self.assertEqual(c.get("/api/v1/events?event_type=bogus").status_code, 400)
        self.assertEqual(c.get("/api/v1/events?username=' OR 1=1 --").get_json()["pagination"]["total"], 0)  # injection is just a string

    def test_events_page_filters_render(self):
        self.events(30); c = self.as_user("ann")
        self.assertIn("31 matching records", c.get("/events").get_data(True))
        self.assertIn("Page 2 of 2", c.get("/events?page=2").get_data(True))
        self.assertIn("No events match", c.get("/events?username=nobody").get_data(True))

    def test_metrics_are_derived_from_database(self):
        c = self.as_user("ann")
        m0 = c.get("/api/v1/dashboard/metrics").get_json(); self.assertEqual(m0["logins_failed_24h"], 0); self.assertEqual(m0["failure_rate_24h"], 0.0)
        with self.app.app_context():  # empty database: rate is undefined, not a fake 0
            from app.services import dashboard_metrics
            conn = self.db(); conn.execute("PRAGMA foreign_keys=OFF")
            import sqlite3
            empty = sqlite3.connect(":memory:"); empty.row_factory = sqlite3.Row
            from app.db import migrate; migrate(empty)
            self.assertIsNone(dashboard_metrics(empty)["failure_rate_24h"]); self.assertEqual(dashboard_metrics(empty)["total_events"], 0)
            conn.close()
        self.assertEqual(len(m0["hourly"]), 24)
        for _ in range(3):
            self.login("ann", "wrong-password-123", client=self.app.test_client())
        self.events(2, event_type="login_success")
        m = c.get("/api/v1/dashboard/metrics").get_json()
        self.assertEqual(m["logins_failed_24h"], 3); self.assertEqual(m["logins_success_24h"], 3)  # own login + 2
        self.assertEqual(m["failure_rate_24h"], 50.0); self.assertEqual(sum(h["failure"] for h in m["hourly"]), 3)
        self.assertEqual(m["total_events"], self.count("SELECT COUNT(*) FROM auth_events"))
        self.assertEqual(m["top_sources"][0]["failures"], 3)

    def test_ingest_auth_validation_and_chain(self):
        ev = {"events": [{"event_type": "login_failure", "outcome": "failure", "username": "Remote.User", "source_ip": "203.0.113.4",
                          "metadata": {"source": "linux-sshd", "password": "leak"}}]}
        h = {"Authorization": "Bearer ingest-token-for-tests"}
        self.assertEqual(self.client.post("/api/v1/ingest", json=ev).status_code, 401)
        self.assertEqual(self.client.post("/api/v1/ingest", json=ev, headers={"Authorization": "Bearer wrong"}).status_code, 401)
        r = self.client.post("/api/v1/ingest", json=ev, headers=h)  # no CSRF needed: token authenticated, no session
        self.assertEqual((r.status_code, r.get_json()["accepted"]), (202, 1))
        c = self.db(); row = c.execute("SELECT * FROM auth_events").fetchone()
        self.assertEqual((row["username"], row["source_ip"]), ("remote.user", "203.0.113.4"))
        self.assertNotIn("leak", row["metadata"]); self.assertIn('"ingested":true', row["metadata"]); c.close()
        self.assertTrue(self.db() and verify_chain(self.db(), "main")["ok"])
        for bad in ({"events": []}, {"events": [{"event_type": "x", "outcome": "success"}]}, {"nope": 1}, {"events": [{"event_type": "login_success", "outcome": "success", "timestamp": "2999-01-01T00:00:00.000000Z"}]}):
            self.assertIn(self.client.post("/api/v1/ingest", json=bad, headers=h).status_code, (400, 422))
        self.assertEqual(self.count("SELECT COUNT(*) FROM auth_events"), 1)  # invalid batches stored nothing

    def test_ingest_disabled_without_token_and_rate_limited(self):
        self.make_app(INGEST_TOKEN="")
        self.assertEqual(self.client.post("/api/v1/ingest", json={"events": []}).status_code, 503)
        self.make_app(INGEST_RATE_PER_MIN=3)
        ok = {"events": [{"event_type": "login_success", "outcome": "success", "username": "a"}]}
        codes = [self.client.post("/api/v1/ingest", json=ok, headers={"Authorization": "Bearer ingest-token-for-tests"}).status_code for _ in range(5)]
        self.assertEqual(codes, [202, 202, 202, 429, 429])

    def test_stream_requires_auth_and_emits_events(self):
        self.events(3)
        self.assertEqual(self.client.get("/stream/events").status_code, 401)
        c = self.as_user("ann")
        r = c.get("/stream/events?last_id=0")
        self.assertEqual(r.status_code, 200); self.assertTrue(r.mimetype == "text/event-stream")
        body = r.get_data(True)
        self.assertIn("retry: 3000", body); self.assertIn("event: auth_event", body); self.assertGreaterEqual(body.count("\nid: ") + body.startswith("id: "), 3)
        first = json.loads(body.split("data: ", 1)[1].split("\n", 1)[0]); self.assertNotIn("record_hash", first); self.assertIn("event_id", first)
        r2 = c.get("/stream/events", headers={"Last-Event-ID": "999999"})  # resume point beyond head: nothing replayed
        self.assertNotIn("event: auth_event", r2.get_data(True))

    def test_errors_are_consistent_and_hide_internals(self):
        @self.app.route("/boom")  # registered before the first request
        def boom():
            raise RuntimeError("secret-internal-detail")
        c = self.as_user("ann")
        r = c.get("/api/v1/cases"); self.assertEqual((r.status_code, r.get_json()["error"]["code"]), (403, "forbidden"))
        self.assertEqual(c.get("/api/v1/nope").status_code, 404)
        body = c.get("/boom").get_data(True); self.assertNotIn("secret-internal-detail", body); self.assertNotIn("Traceback", body)

    def test_api_rate_limit(self):
        self.make_app(API_RATE_PER_MIN=5); c = self.as_user("ann")
        codes = [c.get("/api/v1/alerts").status_code for _ in range(8)]
        self.assertIn(429, codes)
