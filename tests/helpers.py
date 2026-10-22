import json
import shutil
import tempfile
import unittest

from app import create_app
from app.chain import append_event
from app.db import connect
from app.security import reset_rate_limits
from app.services import create_user

PW = "Correct-Horse-Battery-9"


class Base(unittest.TestCase):
    cfg: dict = {}

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="st_test_")  # temporary DB: the real database is never touched
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.make_app()

    def make_app(self, **over):
        c = {"ENV": "testing", "SECRET_KEY": "t" * 48, "DATABASE": f"{self.tmp}/t.db", "EVIDENCE_DIR": f"{self.tmp}/ev",
             "OUTBOX_DIR": f"{self.tmp}/ob", "STREAM_MAX_SECONDS": 1, "STREAM_POLL_SECONDS": 0.1,
             "INGEST_TOKEN": "ingest-token-for-tests", "CHECKPOINT_KEY": "", "CHECKPOINT_EXTERNAL_PATH": ""}
        c.update(self.cfg); c.update(over)
        self.app = create_app(c)
        self.client = self.app.test_client()
        reset_rate_limits()

    def db(self):
        return connect(self.app.config["DATABASE"])

    def user(self, name, role="analyst", pw=PW):
        conn = self.db(); uid = create_user(conn, name, f"{name}@example.test", pw, role); conn.close(); return uid

    def token(self, c=None):
        c = c or self.client
        with c.session_transaction() as s:
            t = s.get("csrf")
        if not t:
            c.get("/login")
            with c.session_transaction() as s:
                t = s["csrf"]
        return t

    def post(self, url, data=None, client=None, **kw):
        c = client or self.client
        d = dict(data or {}); d["csrf_token"] = self.token(c)
        return c.post(url, data=d, **kw)

    def login(self, name, pw=PW, client=None):
        return self.post("/login", {"username": name, "password": pw}, client)

    def as_user(self, name, role="analyst"):
        self.user(name, role)
        c = self.app.test_client()
        r = self.login(name, client=c)
        assert r.status_code == 302, r.status_code
        return c

    def events(self, n=10, **kw):
        conn = self.db(); out = []
        for i in range(n):
            out.append(append_event(conn, chain_id="main", event_type=kw.get("event_type", "login_success"), outcome="success",
                                    username=kw.get("username", f"user{i % 3}"), source_ip=kw.get("ip", f"192.0.2.{i % 5 + 1}"),
                                    user_agent="test", metadata={"i": i}))
        conn.close(); return out

    def raw(self, table, *stmts):
        """Simulate a privileged attacker: drop the append-only triggers, then run raw SQL."""
        conn = self.db()
        for op in ("update", "delete"):
            conn.execute(f"DROP TRIGGER IF EXISTS {table}_no_{op}")
        for s in stmts:
            conn.execute(*s) if isinstance(s, tuple) else conn.execute(s)
        conn.close()

    @staticmethod
    def read(path, mode="rb", **kw):
        with open(path, mode, **kw) as fh:
            return fh.read()

    def count(self, sql, *p):
        conn = self.db(); n = conn.execute(sql, p).fetchone()[0]; conn.close(); return n
