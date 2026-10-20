"""An in-process Week 5 stack for the load tester: the real Api5, the real job store contract (in memory), the real worker and graph runner (instrumented engine), and the FAKE model with a
SIMULATED delay. Nothing here touches the network, a database, a key or real data. Results from it measure this software's own overhead plus the delay you choose, not Gemini and not your hardware's
capacity: threads in one Python process share one interpreter lock.
"""
import hashlib
import secrets
import threading
import time

from week4 import policy as policy_module
from week4.api import auth
from week4.db.fake import MemoryRepository

from week5 import fixtures, jobs, models, queues, settings as settings_module
from week5 import worker as worker_module
from week5.api.api5 import Api5
from week5.runner import GraphRunner

LOADTEST_ANALYST = "loadtester"


def parse_mix(text):
    """'unavailable=0.1,malformed=0.05' -> {'unavailable': 0.1, 'malformed': 0.05}. Raises ValueError for an unknown scenario or a total above 1."""
    mix = {}
    for part in [p.strip() for p in (text or "").split(",") if p.strip()]:
        name, sep, value = part.partition("=")
        name = name.strip()
        if not sep or name not in models.SCENARIOS or name in ("ok_benign", "ok_attack", "ok_benign_slow"):
            raise ValueError("a failure mix entry looks like scenario=fraction, scenario one of: " + ", ".join(s for s in models.SCENARIOS if not s.startswith("ok_")))
        frac = float(value)
        if not 0 <= frac <= 1:
            raise ValueError("a fraction must be between 0 and 1")
        mix[name] = frac
    if sum(mix.values()) > 1.0 + 1e-9:
        raise ValueError("the failure fractions add up to more than 1")
    return mix


def scenario_table(alert_ids, mix, seed):
    """Deterministic alert_id -> scenario for the failure mix (alerts not in the table get the default canned reply)."""
    table, edges, total = {}, [], 0.0
    for name, frac in sorted(mix.items()):
        total += frac
        edges.append((total, name))
    for aid in alert_ids:
        u = int(hashlib.sha256(("%s:%s" % (seed, aid)).encode("utf-8")).hexdigest()[:8], 16) / float(16 ** 8)
        for edge, name in edges:
            if u < edge:
                table[aid] = name
                break
    return table


class SimulatedLatencyModel(models.FakeModel):
    """FakeModel whose delay is base +- jitter, deterministic per alert id. The delay is SIMULATED and is reported as such."""

    def __init__(self, scenarios=None, base_delay=0.05, jitter=0.0, seed=0, sleep=time.sleep):
        super().__init__(scenarios, base_delay, sleep)
        self.base_delay, self.jitter, self.seed = float(base_delay), float(jitter), seed

    def _delay(self, alert_id):
        if self.jitter <= 0:
            return self.base_delay
        u = int(hashlib.sha256(("d%s:%s" % (self.seed, alert_id)).encode("utf-8")).hexdigest()[:8], 16) / float(16 ** 8)
        return max(0.0, self.base_delay + (2 * u - 1) * self.jitter)

    def caller(self, spec, alert_id):
        scenario = self.scenario_for(alert_id)
        if scenario not in models.SCENARIOS:
            raise ValueError("unknown fake scenario")
        return models.JobCaller(models.FakeClient(scenario, self._delay(alert_id), self.sleep), gate=None, sleep=lambda s: None)


class InProcessBackend:
    def __init__(self, workers=2, model_delay=0.05, jitter=0.0, max_attempts=3, job_timeout=30.0, backoff=(0.05, 0.1, 0.2), queue_depth=100000, api_rate_per_minute=0, api_burst=30,
                 scenarios=None, seed=0, poll=0.005, max_body_bytes=16384):
        self.worker_count, self.poll = int(workers), poll
        self.settings = settings_module.Settings(engine="instrumented", flow_store="none", job_timeout_seconds=float(job_timeout), lease_seconds=max(60, int(job_timeout) + 30),
                                                 retry_backoff_seconds=tuple(backoff), max_attempts=int(max_attempts), max_queue_depth=int(queue_depth), rate_limit_per_minute=int(api_rate_per_minute),
                                                 rate_burst=int(api_burst), poll_interval_seconds=poll, max_body_bytes=max_body_bytes)
        self.store = jobs.MemoryJobStore()
        self.repo = MemoryRepository()
        self.repo.upsert_analyst(LOADTEST_ANALYST, "analyst")
        self.token = secrets.token_urlsafe(32)
        self.model = SimulatedLatencyModel(scenarios, model_delay, jitter, seed)
        registry = __import__("tools").build_registry(flow_store=fixtures.flow_store())
        self.runner = GraphRunner(self.settings, policy_module.load_policy(None), registry, self.model)
        self.queue = queues.PostgresQueue(self.store)
        self.dispatcher = queues.Dispatcher(self.store, self.queue, self.settings)
        self.api = Api5(self.repo, auth.AuthConfig("token", {LOADTEST_ANALYST: auth.hash_token(self.token)}), self.store, self.dispatcher, self.settings)
        self.workers = []
        self.threads = []

    def start(self):
        for i in range(self.worker_count):
            w = worker_module.Worker(self.settings, self.store, self.repo, self.runner, self.dispatcher, worker_id="lt-worker-%d" % i, timeout_mode="thread", log=lambda *a, **k: None)
            t = threading.Thread(target=w.run_forever, kwargs={"maintenance_every": 1.0}, daemon=True, name="lt-worker-%d" % i)
            self.workers.append(w)
            self.threads.append(t)
            t.start()

    def stop(self):
        for w in self.workers:
            w.stop.set()
        for t in self.threads:
            t.join(timeout=5)

    def describe(self):
        return {"workers": self.worker_count, "model": "FAKE:canned (simulated latency)", "simulated_model_delay_s": self.model.base_delay, "simulated_model_jitter_s": self.model.jitter,
                "engine": "instrumented", "queue": "in-memory job store polled by worker threads", "max_attempts": self.settings.max_attempts, "job_timeout_s": self.settings.job_timeout_seconds,
                "retry_backoff_s": list(self.settings.retry_backoff_seconds), "api_rate_limit_per_minute": self.settings.rate_limit_per_minute, "worker_poll_s": self.poll}
