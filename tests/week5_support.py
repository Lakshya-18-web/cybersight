"""Shared helpers for the Week 5 tests (not a test module).

Everything is offline and uses the fake model. PostgreSQL tests are OPT-IN exactly as in Week 4 (WEEK4_TEST_PG=1 and the PG* variables): each test class clones a migrated scratch database
(Week 4 migrations, then Week 5 migrations) and drops it afterwards; an existing database is never touched.
"""
import copy
import os
import uuid

from tests import week4_support as W4
from week4.db import drivers, migrate as w4_migrate
from week4.db.fake import MemoryRepository
from week5 import fixtures, intake, jobs, queues, settings as settings_module
from week5 import worker as worker_module
from week5.db import migrate as w5_migrate
from week5.runner import GraphRunner
from week5 import models
from week4 import policy as policy_module

pg_enabled = W4.pg_enabled


class PgHarness5(W4.PgHarness):
    """Template = Week 4 migrations + Week 5 migrations. A separate template from the Week 4 harness."""
    template = None

    @classmethod
    def ensure_template(cls):
        if cls.template is None:
            admin = W4.driver_for("postgres")
            name = "w5_tpl_" + uuid.uuid4().hex[:12]
            admin.run_script('CREATE DATABASE "%s"' % name)
            driver = W4.driver_for(name)
            w4_migrate.apply(driver, say=lambda *_: None)
            w5_migrate.apply(driver, say=lambda *_: None)
            cls.template = name
            import atexit
            atexit.register(cls.drop_template)
        return cls.template

    @classmethod
    def new_database(cls):
        tpl = cls.ensure_template()
        name = "w5_t_" + uuid.uuid4().hex[:12]
        W4.driver_for("postgres").run_script('CREATE DATABASE "%s" TEMPLATE "%s"' % (name, tpl))
        return name


def test_settings(**over):
    """Settings for tests: instrumented engine (no LangGraph needed), fixture flow store is injected by the Rig, short timeouts."""
    base = dict(engine="instrumented", flow_store="none", job_timeout_seconds=5.0, lease_seconds=60, retry_backoff_seconds=(0.0, 0.0, 0.0), poll_interval_seconds=0.05, rate_limit_per_minute=0,
                max_queue_depth=100)
    base.update(over)
    return settings_module.Settings(**base)


def submit(store, alert, submitter="analyst1", memory="off", client_key=None, alert_set="synthetic", max_attempts=3, **kw):
    """Validate an alert and submit it the way the API does. -> the store's submit result."""
    clean = intake.validate_alert(copy.deepcopy(alert))
    return store.submit(clean, alert_set, memory, submitter, intake.idempotency_key(submitter, client_key, clean, memory), intake.payload_sha256(clean, memory), max_attempts, **kw)


class Clock:
    """A settable clock (seconds, float) for worker timing in tests."""

    def __init__(self, start=1000.0):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


class Rig:
    """A complete in-process backend: job store, case repository, fake model, worker, queue, dispatcher. All in memory unless a store/repo is passed."""

    def __init__(self, settings=None, store=None, repo=None, provider=None, queue=None, timeout_mode="thread", sensor=False, threat_intel=None, **settings_over):
        self.settings = settings or test_settings(**settings_over)
        self.store = store or jobs.MemoryJobStore()
        self.repo = repo or MemoryRepository()
        self.provider = provider or models.FakeModel()
        self.runner = GraphRunner(self.settings, policy_module.load_policy(None), __import__("tools").build_registry(flow_store=fixtures.flow_store()), self.provider, threat_intel=threat_intel)
        if sensor:          # sensor events, notes, feedback and search live in the Week 5 repository layer; the worker reads and writes through the same object
            from week5 import repo5
            self.repo = repo5.wrap(self.repo)
            self.runner.attach_repository(self.repo)
        self.queue = queue if queue is not None else queues.PostgresQueue(self.store)
        self.logs = []
        self.dispatcher = queues.Dispatcher(self.store, self.queue, self.settings, log=lambda e, **k: self.logs.append((e, k)))
        self.worker = worker_module.Worker(self.settings, self.store, self.repo, self.runner, self.dispatcher, worker_id="w-test", timeout_mode=timeout_mode,
                                           log=lambda e, **k: self.logs.append((e, k)), sleep=lambda s: None)

    def submit(self, index=0, **kw):
        res = submit(self.store, fixtures.make_alert(index), max_attempts=kw.pop("max_attempts", self.settings.max_attempts), **kw)
        if self.dispatcher is not None and res["outcome"] == "created":
            self.dispatcher.dispatch(res["job_id"])
        return res

    def events(self, name):
        return [k for e, k in self.logs if e == name]


# ---------------------------------------------------------------------------- API rig
TOKENS = {"alice": "A" * 40, "bob": "B" * 40, "carol": "C" * 40, "root": "R" * 40, "erin": "E" * 40, "ghost": "G" * 40}


class ApiRig(Rig):
    """Rig + Api5 with token authentication. Analysts: alice approver, bob analyst, carol viewer, root admin, erin approver (inactive); ghost has a token but no analyst record."""

    def __init__(self, clock=None, **kw):
        from week4.api import auth
        from week5.api.api5 import Api5
        super().__init__(**kw)
        W4.seed_analysts(self.repo)
        hashes = {a: auth.hash_token(t) for a, t in TOKENS.items()}
        self.clock = clock or Clock()
        self.api = Api5(self.repo, auth.AuthConfig("token", hashes), self.store, self.dispatcher, self.settings, clock=self.clock)

    def call(self, name, who="bob", body=None, raw=None, headers=None, query=None, path=None, content_type="application/json", token=None):
        h = dict(headers or {})
        if who is not None:
            h["Authorization"] = "Bearer " + (token or TOKENS[who])
        if content_type and (body is not None or raw is not None):
            h["Content-Type"] = content_type
        if raw is None and body is not None:
            import json
            raw = json.dumps(body).encode("utf-8")
        return self.api.dispatch(name, h, query, path, body, raw)

    def post_alert(self, index=0, who="bob", **kw):
        memory = kw.pop("memory", None)
        body = {"alert": fixtures.make_alert(index)}
        if memory:
            body["memory"] = memory
        return self.call("submit_alert", who, body=body, **kw)


# ---------------------------------------------------------------------------- minimal stdlib HTTP front for Api5 (tests only)
class HttpStub:
    """Serves an Api5 over real HTTP on 127.0.0.1 using only the standard library, so the load tester's HTTP client can be exercised without FastAPI. It is a TEST DOUBLE of the web layer
    (it maps method+path to Api5.dispatch the same way week5.api.app5 does); it is not shipped as a server and does not test FastAPI."""

    def __init__(self, api, max_body=16384):
        import http.server
        import json
        import re
        import threading
        from week4.api import routes as w4
        from week5.api import routes5
        table = [(r.method, re.compile("^" + re.sub(r"{(\w+)}", r"(?P<\1>[^/]+)", r.path) + "$"), r.name) for r in list(w4.ROUTES) + list(routes5.ROUTES5)]

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self, method):
                path = self.path.split("?")[0]
                for m, rx, name in table:
                    hit = rx.match(path) if m == method else None
                    if hit:
                        raw = None
                        if method == "POST":
                            length = int(self.headers.get("Content-Length") or 0)
                            if length > max_body:
                                return self._send(413, {"error": {"code": "too_large"}}, {})
                            raw = self.rfile.read(length)
                        try:
                            body = json.loads(raw) if raw else None
                        except ValueError:
                            body = None
                        import urllib.parse
                        query = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).items()}
                        res = api.dispatch(name, dict(self.headers), query, hit.groupdict(), body, raw)
                        return self._send(res.status, res.body, res.headers)
                self._send(404, {"error": {"code": "not_found"}}, {})

            def _send(self, status, body, headers):
                data = json.dumps(body, default=str).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._do("GET")

            def do_POST(self):
                self._do("POST")
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.server.server_address[1]

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
