"""Week 2 Day 5: optional, metadata-only LangSmith tracing.

Off by default. The runner only uses this module when you pass --langsmith. When tracing is off the runner gets a
NullTracer, which does nothing at all (no import of the langsmith package, no network).

What may be sent (an allowlist, enforced by sanitize() on every payload):
  run name, alert id, prompt version, prompt hash, model, session, attempt number, number of model calls, latency,
  token counts, finish reason, parse status, error code, and the dev-set marker.
What is never sent: alert or flow values, the prompt text, the model's reply, error details (they can quote the reply),
labels, the MITRE answer key, anything from the frozen set. A payload with any other key, a nested value, or a long or
JSON-looking string is refused (TracingPayloadError), so a mistake here fails closed.

Configuration is from the environment only. Nothing is hard-coded and no key is ever written to disk:
  LANGSMITH_API_KEY   required when --langsmith is used
  LANGSMITH_PROJECT   optional, default "soc-triage-week2"
  LANGSMITH_ENDPOINT  optional, for a non-default server

Tracing can never change a run. The runner wraps every tracing call, so an error here is counted and printed and the run
carries on. The local raw_responses.jsonl and results.jsonl stay the source of truth.

The langsmith package is imported only inside make_client(), so importing this module needs nothing installed.
"""
import os
import uuid
import datetime

DEFAULT_PROJECT = "soc-triage-week2"
MAX_STRING_CHARS = 128

# Every key a payload may carry. Anything else is refused.
ALLOWED_KEYS = frozenset([
    "run_name", "alert_id", "prompt_version", "prompt_sha256", "model", "session", "set",
    "attempt", "model_calls", "latency_seconds", "prompt_tokens", "output_tokens", "thinking_tokens", "total_tokens",
    "finish_reason", "parse_status", "error_code", "status", "malformed_first_try", "attempts",
])


class TracingPayloadError(ValueError):
    pass


class TracingConfigError(Exception):
    pass


def sanitize(payload):
    """Return a copy of payload if it is metadata only; raise TracingPayloadError otherwise."""
    if not isinstance(payload, dict):
        raise TracingPayloadError("a tracing payload must be a dict")
    clean = {}
    for key, value in payload.items():
        if key not in ALLOWED_KEYS:
            raise TracingPayloadError("tracing key '" + str(key) + "' is not on the metadata allowlist")
        if value is None or isinstance(value, (bool, int, float)):
            clean[key] = value
        elif isinstance(value, str):
            if len(value) > MAX_STRING_CHARS or "{" in value or "\n" in value:
                raise TracingPayloadError("tracing value for '" + key + "' looks like content, not metadata")
            clean[key] = value
        else:
            raise TracingPayloadError("tracing value for '" + key + "' must be a plain string, number, bool or None")
    return clean


def parse_status_of(error_code):
    return "valid" if error_code is None else str(error_code)


def alert_payload(base, record):
    """Run-level metadata plus the result of one alert. Reads only counts, ids and status fields from the record."""
    payload = dict(base)
    payload.update({
        "alert_id": record.get("alert_id"),
        "session": record.get("session"),
        "status": record.get("status"),
        "error_code": record.get("error_code"),
        "attempts": record.get("attempts"),
        "model_calls": record.get("model_calls"),
        "malformed_first_try": record.get("malformed_first_try"),
        "latency_seconds": record.get("latency_seconds"),
        "prompt_tokens": record.get("prompt_tokens"),
        "output_tokens": record.get("output_tokens"),
        "thinking_tokens": record.get("thinking_tokens"),
        "total_tokens": record.get("total_tokens"),
        "parse_status": record.get("status"),
    })
    return sanitize(payload)


def attempt_payloads(base, record, calls):
    """One payload per model call: attempt number, latency, tokens, finish reason, parse status, error code."""
    log = record.get("attempt_log") or []
    out = []
    for i, call in enumerate(calls):
        code = log[i].get("error_code") if i < len(log) else None
        payload = dict(base)
        payload.update({
            "alert_id": record.get("alert_id"),
            "session": record.get("session"),
            "attempt": i + 1,
            "latency_seconds": call.get("latency_seconds"),
            "prompt_tokens": call.get("prompt_tokens"),
            "output_tokens": call.get("output_tokens"),
            "thinking_tokens": call.get("thinking_tokens"),
            "total_tokens": call.get("total_tokens"),
            "finish_reason": call.get("finish_reason"),
            "parse_status": parse_status_of(code),
            "error_code": code,
        })
        out.append(sanitize(payload))
    return out


class NullTracer:
    """Tracing off: no behavior at all."""
    enabled = False
    errors = 0

    def record_alert(self, record, calls):
        return None

    def close(self):
        return None

    def describe(self):
        return {"enabled": False}


class LangSmithTracer:
    """Sends metadata-only runs to LangSmith through a client object with create_run().

    The client is passed in, so tests use a fake one and nothing here needs the network.
    """
    enabled = True

    def __init__(self, client, project, run_name, prompt_version, prompt_sha256, model, now=None):
        self.client = client
        self.project = project
        self.errors = 0
        self.sent = 0
        self.base = sanitize({"run_name": run_name, "prompt_version": prompt_version, "prompt_sha256": prompt_sha256,
                              "model": model, "set": "dev"})
        self.now = now or (lambda: datetime.datetime.now(datetime.timezone.utc))

    def record_alert(self, record, calls):
        end = self.now()
        parent_payload = alert_payload(self.base, record)
        children = attempt_payloads(self.base, record, calls)
        total = float(record.get("latency_seconds") or 0.0)
        parent_id = uuid.uuid4()
        self.client.create_run(
            id=parent_id, name="triage_alert", run_type="chain", project_name=self.project,
            inputs={"alert_id": parent_payload["alert_id"], "prompt_version": parent_payload["prompt_version"]},
            outputs={"status": parent_payload["status"], "error_code": parent_payload["error_code"]},
            extra={"metadata": parent_payload}, tags=["week2", "dev", self.base["prompt_version"]],
            start_time=end - datetime.timedelta(seconds=total), end_time=end)
        cursor = end - datetime.timedelta(seconds=total)
        for child in children:
            seconds = float(child.get("latency_seconds") or 0.0)
            stop = cursor + datetime.timedelta(seconds=seconds)
            self.client.create_run(
                id=uuid.uuid4(), parent_run_id=parent_id, name="model_call", run_type="llm", project_name=self.project,
                inputs={"alert_id": child["alert_id"], "attempt": child["attempt"]},
                outputs={"parse_status": child["parse_status"], "error_code": child["error_code"]},
                extra={"metadata": child}, tags=["week2", "dev", self.base["prompt_version"]],
                start_time=cursor, end_time=stop)
            cursor = stop
            self.sent += 1
        self.sent += 1

    def close(self):
        flush = getattr(self.client, "flush", None)
        if callable(flush):
            flush()

    def describe(self):
        return {"enabled": True, "project": self.project, "payload_policy": "metadata_only", "runs_sent": self.sent, "errors": self.errors}


def make_client(environ=None):
    """Create the real LangSmith client from the environment. The only place the langsmith package is imported."""
    environ = os.environ if environ is None else environ
    key = environ.get("LANGSMITH_API_KEY")
    if not key:
        raise TracingConfigError("--langsmith needs LANGSMITH_API_KEY in the environment. Tracing stays off until it is set.")
    try:
        from langsmith import Client
    except ImportError:
        raise TracingConfigError("--langsmith needs the langsmith package: pip install langsmith")
    kwargs = {"api_key": key}
    endpoint = environ.get("LANGSMITH_ENDPOINT")
    if endpoint:
        kwargs["api_url"] = endpoint
    return Client(**kwargs)


def project_name(environ=None):
    environ = os.environ if environ is None else environ
    return environ.get("LANGSMITH_PROJECT") or DEFAULT_PROJECT


def create_tracer(enabled, run_name, prompt_version, prompt_sha256, model, client=None, environ=None):
    """NullTracer when disabled. When enabled, a LangSmithTracer on the given client or on a new real client."""
    if not enabled:
        return NullTracer()
    if client is None:
        client = make_client(environ)
    return LangSmithTracer(client, project_name(environ), run_name, prompt_version, prompt_sha256, model)
