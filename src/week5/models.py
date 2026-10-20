"""Model providers for the worker. The model call is the only network call a job makes.

  FakeModel     deterministic, offline, free. Replies are canned: they are NOT verdicts, they only exercise the plumbing. It reports NO token counts (the fields stay None), so no usage or cost is ever
                invented for a fake run. Scenarios let tests and the load tester script success, malformed replies, outages, permanent refusals and slowness. A fake run is flagged in every case it creates.
  GeminiModel   the real thing, through the project's gemini_client. It refuses to be built unless live calls were allowed explicitly (WEEK5_ALLOW_LIVE_MODEL=1 AND WEEK5_MODEL_MODE=gemini), and it reads
                the key from the environment only at the moment of the call (llm_config.get_api_key). The key is never stored on a settings object, a job, a log line or an error message.

Both return a JobCaller per job: a function  prompt text -> reply text  (what the Week 3/4 verdict nodes expect) with transport retries and a calls-per-minute gate, and a record of every call.
"""
import hashlib
import threading
import time

import gemini_client

from . import errors

GENERATION_SEED = 42            # the Week 2 value (run_baseline_dev.GENERATION_SEED); a test checks they agree
TRANSPORT_RETRIES = 4           # the Week 2 values (run_baseline_dev.TRANSPORT_RETRIES / BACKOFF_SECONDS)
BACKOFF_SECONDS = (4, 8, 16, 32)

VALID_BENIGN = '{"is_malicious": false, "attack_type": "BENIGN", "mitre_technique": "NONE", "severity": "none", "evidence": "FAKE canned reply for plumbing tests."}'
VALID_ATTACK = '{"is_malicious": true, "attack_type": "PortScan", "mitre_technique": "T1046", "severity": "medium", "evidence": "FAKE canned reply for plumbing tests."}'
MALFORMED = "this is not json"
SCENARIOS = ("ok_benign", "ok_attack", "malformed", "malformed_then_ok", "transient_then_ok", "unavailable", "permanent", "crash", "ok_benign_slow")


class RateGate:
    """At most calls_per_minute model calls, shared by every job in this process. Thread-safe."""

    def __init__(self, calls_per_minute, clock=time.monotonic, sleep=time.sleep):
        self.gap = 60.0 / float(calls_per_minute)
        self.clock, self.sleep = clock, sleep
        self.last = None
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            now = self.clock()
            if self.last is not None:
                pause = self.gap - (now - self.last)
                if pause > 0:
                    self.sleep(pause)
                    now = self.clock()
            self.last = now


class JobCaller:
    """prompt -> reply text, for one job. Retries transport errors with the Week 2 back-off; raises errors.ModelUnavailable when they run out and lets a permanent refusal through."""

    def __init__(self, client, gate=None, sleep=time.sleep, clock=time.monotonic):
        self.client, self.gate, self.sleep, self.clock = client, gate, sleep, clock
        self.calls = []

    def __call__(self, prompt):
        transport_errors = 0
        for attempt in range(TRANSPORT_RETRIES + 1):
            if self.gate is not None:
                self.gate.wait()
            started = self.clock()
            try:
                record = self.client.generate(prompt)
            except gemini_client.TransientModelError:
                transport_errors += 1
                if attempt == TRANSPORT_RETRIES:
                    self.calls.append({"outcome": "transport_failed", "latency_seconds": self.clock() - started, "prompt_tokens": None, "output_tokens": None, "thinking_tokens": None, "total_tokens": None})
                    raise errors.ModelUnavailable("the model call failed %d times" % (attempt + 1))
                self.sleep(BACKOFF_SECONDS[min(attempt, len(BACKOFF_SECONDS) - 1)])
                continue
            except gemini_client.PermanentModelError:
                self.calls.append({"outcome": "permanent_error", "latency_seconds": self.clock() - started, "prompt_tokens": None, "output_tokens": None, "thinking_tokens": None, "total_tokens": None})
                raise
            self.calls.append({"outcome": "reply", "latency_seconds": self.clock() - started, "transport_errors": transport_errors, "prompt_tokens": record.prompt_tokens,
                               "output_tokens": record.output_tokens, "thinking_tokens": record.thinking_tokens, "total_tokens": record.total_tokens})
            return record.text
        raise errors.ModelUnavailable("no reply")

    def usage(self, fake=False):
        """Token and call totals. Fields a provider did not report are None, never zero, and `available` says whether real token counts exist."""
        calls = [c for c in self.calls if c["outcome"] == "reply"]

        def total(name):
            values = [c[name] for c in calls if c.get(name) is not None]
            return sum(values) if values and len(values) == len(calls) else None
        out = {"model_calls": len(self.calls), "model_seconds": round(sum(c["latency_seconds"] for c in self.calls), 6), "prompt_tokens": total("prompt_tokens"),
               "output_tokens": total("output_tokens"), "thinking_tokens": total("thinking_tokens"), "total_tokens": total("total_tokens")}
        out["tokens_available"] = out["total_tokens"] is not None
        out["tokens_note"] = ("a fake model reports no token counts" if fake else (None if out["tokens_available"] else "the provider did not report token counts for every call"))
        return out


class FakeClient:
    """A scripted stand-in for GeminiClient. scenario_for(alert_id) -> one of SCENARIOS; delay_seconds simulates model latency (the load tester labels it as simulated)."""

    def __init__(self, scenario, delay_seconds=0.0, sleep=time.sleep):
        self.scenario, self.delay, self.sleep = scenario, float(delay_seconds), sleep
        self.n = 0

    def _record(self, text):
        return gemini_client.CallRecord(text=text, finish_reason="STOP", block_reason=None, prompt_tokens=None, output_tokens=None, thinking_tokens=None, total_tokens=None)

    def generate(self, prompt):
        self.n += 1
        if self.delay > 0 or self.scenario == "ok_benign_slow":
            self.sleep(self.delay if self.delay > 0 else 0.2)
        s = self.scenario
        if s in ("ok_benign", "ok_benign_slow"):
            return self._record(VALID_BENIGN)
        if s == "ok_attack":
            return self._record(VALID_ATTACK)
        if s == "malformed":
            return self._record(MALFORMED)
        if s == "malformed_then_ok":
            return self._record(MALFORMED if self.n == 1 else VALID_ATTACK)
        if s == "transient_then_ok":
            if self.n == 1:
                raise gemini_client.TransientModelError("fake transient error", 503)
            return self._record(VALID_BENIGN)
        if s == "unavailable":
            raise gemini_client.TransientModelError("fake transient error", 503)
        if s == "permanent":
            raise gemini_client.PermanentModelError("fake permanent error", 400)
        if s == "crash":
            raise RuntimeError("fake model crash")
        raise ValueError("unknown fake scenario " + str(s))


def default_scenario(alert_id):
    """Deterministic and independent of the alert's content: the parity of a hash of its id. Half the alerts get the canned attack reply, half the canned benign one."""
    return "ok_attack" if int(hashlib.sha256(str(alert_id).encode("utf-8")).hexdigest(), 16) % 2 == 0 else "ok_benign"


class FakeModel:
    name = "FAKE:canned"
    fake = True

    def __init__(self, scenario_for=None, delay_seconds=0.0, sleep=time.sleep, clock=time.monotonic):
        if isinstance(scenario_for, dict):
            table = dict(scenario_for)
            scenario_for = lambda alert_id: table.get(alert_id, default_scenario(alert_id))  # noqa: E731
        self.scenario_for = scenario_for or default_scenario
        self.delay, self.sleep, self.clock = delay_seconds, sleep, clock

    def caller(self, spec, alert_id):
        scenario = self.scenario_for(alert_id)
        if scenario not in SCENARIOS:
            raise ValueError("unknown fake scenario")
        return JobCaller(FakeClient(scenario, self.delay, self.sleep), gate=None, sleep=lambda s: None, clock=self.clock)


class GeminiModel:
    fake = False

    def __init__(self, settings, env=None, sleep=time.sleep, clock=time.monotonic, client_factory=None):
        if settings.model_mode != "gemini" or not settings.allow_live_model:
            raise PermissionError("live Gemini calls need WEEK5_MODEL_MODE=gemini and WEEK5_ALLOW_LIVE_MODEL=1 (set deliberately; they cost money)")
        import llm_config
        self._llm = llm_config
        self.settings, self.sleep, self.clock = settings, sleep, clock
        self.name = llm_config.models()["small"]
        self.gate = RateGate(settings.model_rpm, clock=clock, sleep=sleep)
        self._clients = {}
        self._factory = client_factory
        self._lock = threading.Lock()

    def _client(self, spec):
        with self._lock:
            if spec.version not in self._clients:
                if self._factory is not None:
                    self._clients[spec.version] = self._factory(self.name, spec)
                else:
                    self._clients[spec.version] = gemini_client.GeminiClient(self.name, spec.system_prompt, self._llm.TEMPERATURE, self._llm.MAX_OUTPUT_TOKENS, GENERATION_SEED,
                                                                              api_key=self._llm.get_api_key(), timeout_seconds=self._llm.REQUEST_TIMEOUT_SECONDS)
            return self._clients[spec.version]

    def caller(self, spec, alert_id):
        return JobCaller(self._client(spec), gate=self.gate, sleep=self.sleep, clock=self.clock)
