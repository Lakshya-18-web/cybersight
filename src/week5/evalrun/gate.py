"""The protected-data gate. FAIL CLOSED: anything missing, malformed, expired, mismatched or unexpected means "denied".

The frozen evaluation set is opened only by open_frozen(), and open_frozen() opens it only when ALL of these hold:
  1. SOC_FROZEN_UNLOCK has the Week 1 value (the existing eval_io.py guard, kept) AND
  2. WEEK5_FINAL_EVAL_AUTH names an authorisation file (JSON, schema week5-final-eval-authorization-v1) that
       - carries the exact authorisation statement,
       - names who authorised it (authorized_by) and when (authorized_at), and has not expired (expires_at, at most 7 days after authorized_at),
       - is bound to ONE plan by that plan's SHA-256 (editing the plan invalidates the authorisation),
       - lists the exact run keys it permits (for example "full_system/run1"),
       - says set = "frozen",
  3. the run key has not been opened before (an append-only ledger, final_eval_ledger.jsonl, next to the plan) and
  4. the caller passed acknowledged=True (the CLI flag --i-understand-this-opens-the-frozen-set).
The ledger line is written and flushed BEFORE any protected file is read, so a crash cannot leave an unrecorded look at the data.
eval_io (the only module that knows the frozen paths) is imported inside open_frozen() only, never at import time and never for the dev or fixture sets.
Nothing in this package computes a path to a frozen file itself.
"""
import datetime
import json
import os

from . import data as data_module

SCHEMA_AUTH = "week5-final-eval-authorization-v1"
STATEMENT = "I authorise opening the frozen evaluation set for exactly the runs listed in this file."
ENV_AUTH = "WEEK5_FINAL_EVAL_AUTH"
ENV_UNLOCK = "SOC_FROZEN_UNLOCK"
UNLOCK_VALUE = "week1-day6"            # eval_io's value (config.FROZEN_UNLOCK_VALUE); a test checks they agree
MAX_VALID_DAYS = 7
MAX_AUTH_BYTES = 65536
LEDGER_NAME = "final_eval_ledger.jsonl"
AUTH_KEYS = {"schema", "statement", "authorized_by", "authorized_at", "expires_at", "plan_sha256", "set", "allowed_runs"}


class GateDenied(Exception):
    def __init__(self, reasons):
        self.reasons = list(reasons)
        super().__init__("the protected-set gate is closed: " + "; ".join(self.reasons))


def _parse_time(text):
    if not isinstance(text, str):
        raise ValueError("not a string")
    return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def read_ledger(path):
    if not os.path.isfile(path):
        return []
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def decide(plan, plan_sha256, run_key, env=None, now=None, acknowledged=False, ledger_path=None):
    """-> list of reasons the gate is closed. An empty list means open. Never raises."""
    reasons = []
    try:
        env = os.environ if env is None else env
        now = now or _utcnow()
        if plan.get("set") != "frozen":
            return ["the plan is not a frozen-set plan (set=%r): the gate guards only the frozen set" % plan.get("set")]
        if env.get(ENV_UNLOCK) != UNLOCK_VALUE:
            reasons.append(ENV_UNLOCK + " is not set to the documented value")
        if not acknowledged:
            reasons.append("the acknowledgement flag was not given")
        path = env.get(ENV_AUTH)
        if not path:
            reasons.append(ENV_AUTH + " is not set (no authorisation file)")
            return reasons
        if not os.path.isfile(path):
            return reasons + ["the authorisation file does not exist"]
        if os.path.getsize(path) > MAX_AUTH_BYTES:
            return reasons + ["the authorisation file is too large"]
        with open(path, "r", encoding="utf-8") as fh:
            auth = json.load(fh)
        if not isinstance(auth, dict) or set(auth) != AUTH_KEYS:
            return reasons + ["the authorisation file does not have exactly the required fields"]
        if auth["schema"] != SCHEMA_AUTH:
            reasons.append("wrong authorisation schema")
        if auth["statement"] != STATEMENT:
            reasons.append("the authorisation statement is not the required sentence")
        if not isinstance(auth["authorized_by"], str) or len(auth["authorized_by"].strip()) < 3:
            reasons.append("authorized_by is empty")
        try:
            given, expires = _parse_time(auth["authorized_at"]), _parse_time(auth["expires_at"])
            if given > now:
                reasons.append("authorized_at is in the future")
            if now >= expires:
                reasons.append("the authorisation has expired")
            if expires - given > datetime.timedelta(days=MAX_VALID_DAYS) or expires <= given:
                reasons.append("the authorisation window must be positive and at most %d days" % MAX_VALID_DAYS)
        except ValueError:
            reasons.append("authorized_at / expires_at must look like 2026-10-20T09:30:00Z")
        if auth["set"] != "frozen":
            reasons.append("the authorisation is not for the frozen set")
        if auth["plan_sha256"] != plan_sha256:
            reasons.append("the authorisation was made for a different plan (hash mismatch)")
        if not isinstance(auth["allowed_runs"], list) or run_key not in auth["allowed_runs"]:
            reasons.append("run %s is not listed in allowed_runs" % run_key)
        if ledger_path is None:
            reasons.append("no ledger location was given")
        elif any(row.get("run_key") == run_key and row.get("plan_sha256") == plan_sha256 for row in read_ledger(ledger_path)):
            reasons.append("run %s already opened the frozen set once; a repeat needs a new plan and a new authorisation" % run_key)
        return reasons
    except Exception as error:      # unreadable, malformed, anything: closed
        return reasons + ["the gate could not be evaluated (%s)" % type(error).__name__]


def open_frozen(plan, plan_sha256, run_key, ledger_path, env=None, now=None, acknowledged=False, loader=None):
    """-> EvalData for the frozen set, or raises GateDenied. `loader` exists for tests (an object with load_alerts / load_flow_store / load_labels); production uses eval_io."""
    reasons = decide(plan, plan_sha256, run_key, env, now, acknowledged, ledger_path)
    if reasons:
        raise GateDenied(reasons)
    stamp = (now or _utcnow()).strftime("%Y-%m-%dT%H:%M:%SZ")
    os.makedirs(os.path.dirname(os.path.abspath(ledger_path)), exist_ok=True)
    line = json.dumps({"opened_at": stamp, "run_key": run_key, "plan_sha256": plan_sha256, "set": "frozen"}, sort_keys=True)
    with open(ledger_path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(line + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    if loader is None:
        import eval_io as loader        # the ONLY place the real loader is imported
    reason = "week5 final evaluation " + run_key
    alerts = loader.load_alerts("frozen", reason)
    labels = loader.load_labels("frozen", reason)
    flows = loader.load_flow_store("frozen", reason)
    return data_module.EvalData("frozen", alerts, labels, flows)
