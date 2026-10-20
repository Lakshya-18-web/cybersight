"""A fresh, isolated, in-memory Week 5 backend for one payload: the real Api5, worker, graph runner and guard, with a SCRIPTED model that returns exactly the reply the payload defines and records every
prompt it is sent. Nothing touches a network, a database, a key or real data."""
import json
import secrets

from week4 import policy as policy_module
from week4.api import auth
from week4.db.fake import MemoryRepository

from week5 import fixtures, jobs, models, queues, settings as settings_module
from week5 import worker as worker_module
from week5.api.api5 import Api5
from week5.runner import GraphRunner

KNOWN_SECRET = "w5-canary-known-secret-0123456789"       # planted: configured as a server secret the guard must never let out
ANALYSTS = {"alice": "approver", "bob": "analyst", "mallory": "analyst", "carol": "viewer", "root": "admin"}


class ScriptedClient:
    def __init__(self, reply_text, prompts):
        self.reply_text, self.prompts = reply_text, prompts

    def generate(self, prompt):
        self.prompts.append(prompt)
        import gemini_client
        return gemini_client.CallRecord(text=self.reply_text, finish_reason="STOP", block_reason=None, prompt_tokens=None, output_tokens=None, thinking_tokens=None, total_tokens=None)


class ScriptedModel(models.FakeModel):
    """A model that does what the payload says. fake = True (so nothing is invented about tokens)."""
    name = "FAKE:scripted-worst-case"

    def __init__(self, default_reply=models.VALID_BENIGN):
        super().__init__()
        self.default_reply, self.replies, self.prompts = default_reply, {}, []

    def caller(self, spec, alert_id):
        return models.JobCaller(ScriptedClient(self.replies.get(alert_id, self.default_reply), self.prompts), gate=None, sleep=lambda s: None)


class InjectionStack:
    def __init__(self, rate_limit_per_minute=0, rate_burst=30, max_body_bytes=16384, alias_ids=True):
        self.settings = settings_module.Settings(engine="instrumented", flow_store="none", job_timeout_seconds=30.0, lease_seconds=60, retry_backoff_seconds=(0.0, 0.0, 0.0), max_attempts=3,
                                                 max_queue_depth=1000, rate_limit_per_minute=rate_limit_per_minute, rate_burst=rate_burst, max_body_bytes=max_body_bytes, alias_ids=alias_ids)
        self.store = jobs.MemoryJobStore()
        self.repo = MemoryRepository()
        self.tokens = {}
        hashes = {}
        for who, role in ANALYSTS.items():
            self.repo.upsert_analyst(who, role)
            self.tokens[who] = secrets.token_urlsafe(32)
            hashes[who] = auth.hash_token(self.tokens[who])
        self.model = ScriptedModel()
        registry = __import__("tools").build_registry(flow_store=fixtures.flow_store())
        self.runner = GraphRunner(self.settings, policy_module.load_policy(None), registry, self.model, guard_secrets=(KNOWN_SECRET,))
        self.queue = queues.PostgresQueue(self.store)
        self.logs = []
        self.dispatcher = queues.Dispatcher(self.store, self.queue, self.settings, log=lambda e, **k: self.logs.append((e, k)))
        self.api = Api5(self.repo, auth.AuthConfig("token", hashes), self.store, self.dispatcher, self.settings, log=lambda *a: self.logs.append(("api", {"args": [str(x) for x in a]})))
        self.worker = worker_module.Worker(self.settings, self.store, self.repo, self.runner, self.dispatcher, worker_id="inj-worker", timeout_mode="thread",
                                           log=lambda e, **k: self.logs.append((e, k)), sleep=lambda s: None)
        self.responses = []         # every (name, status, body) returned by the API, in order

    # ---- calling the API
    def call(self, name, who="bob", raw=None, body=None, headers=None, path=None, query=None, content_type="application/json", token=None):
        h = dict(headers or {})
        if who is not None:
            h["Authorization"] = "Bearer " + (token if token is not None else self.tokens[who])
        if content_type and (raw is not None or body is not None):
            h["Content-Type"] = content_type
        if raw is None and body is not None:
            raw = json.dumps(body, allow_nan=False).encode("utf-8")
        r = self.api.dispatch(name, h, query, path, body, raw)
        self.responses.append((name, r.status, r.body))
        return r

    def drain(self, limit=50):
        n = 0
        while n < limit and self.worker.run_once() is not None:
            n += 1
        return n

    # ---- what an attacker or operator could observe
    def observable_texts(self):
        out = [json.dumps([(n, s, b) for n, s, b in self.responses], default=str, ensure_ascii=False)]
        listing = self.store.list_jobs(limit=200)["items"]
        out.append(json.dumps(listing, default=str, ensure_ascii=False))
        for j in listing:
            out.append(json.dumps(self.store.events(j["job_id"]), default=str, ensure_ascii=False))
        for c in self.repo.list_cases(limit=200)["items"]:
            cid = c["case_id"]
            out.append(json.dumps(self.repo.get_case(cid), default=str, ensure_ascii=False))
            out.append(json.dumps(self.repo.case_evidence(cid), default=str, ensure_ascii=False))
            out.append(json.dumps(self.repo.case_history(cid), default=str, ensure_ascii=False))
        out.append(json.dumps(self.store.security_events, default=str, ensure_ascii=False))
        out.append(json.dumps(self.logs, default=str, ensure_ascii=False))
        out.append(json.dumps(self.repo.audit_events, default=str, ensure_ascii=False))
        return out

    def cases(self):
        return [self.repo.get_case(c["case_id"]) for c in self.repo.list_cases(limit=200)["items"]]
