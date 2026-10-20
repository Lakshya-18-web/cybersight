"""Collect ONE recorded run of ONE configuration. Sequential on purpose (concurrency would make latencies and rate-limit effects irreproducible); see docs/WEEK5_FINAL_EVALUATION.md.

Layout, write-once:   <out_root>/<plan_id>/<config>/run<k>/
   config_snapshot.json  the plan, the configuration and the code/version facts this run used
   run_meta.json         unique run id, timings, input hashes, status "complete"
   results.jsonl         one record per alert (schema week5-evalrun-record-v1; the Week 2 results.jsonl keys, plus routing for the full system)
   errors.jsonl          one line per alert that did not end with a valid verdict, classified (parse_failure | model_unavailable | system_error)
   run.sha256            SHA-256 of the four files above
The run is written to run<k>.partial/ and renamed only when complete, so a crash leaves a visible partial folder that validate.py reports, never a half-written "finished" run.
Existing run folders are never overwritten. Prompts and raw model replies are NOT stored (the protected set's alert content must not be copied into result files); prompt hashes are.

Reused project code: Week 2 prompt builder (prompt_registry), baseline record builder (run_baseline_dev.process_alert) and parser; Week 3/4 graph, guard and policy through week5.runner.GraphRunner.execute (the same code a deployed worker runs).
"""
import datetime
import hashlib
import json
import os
import platform
import time
import uuid

import pandas as pd

from . import SCHEMA_RECORD, SCHEMA_RUN_META
from .data import canonical
from .plan import plan_sha256

FILES = ("config_snapshot.json", "run_meta.json", "results.jsonl", "errors.jsonl")
NONDETERMINISM = ("Model replies can differ between runs even at temperature 0 and a fixed seed (provider-side non-determinism).",
                  "Latency depends on provider load, network and the calls-per-minute gate, not only on the system.",
                  "Runs are sequential; no concurrency effects are introduced by this tool.")


class CollectError(Exception):
    pass


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path, obj):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True, default=str)
        fh.write("\n")


def jsonable(value):
    return json.loads(json.dumps(value, default=lambda o: o.item() if hasattr(o, "item") else (list(o) if isinstance(o, (set, tuple)) else str(o))))


# ---------------------------------------------------------------------------------------------- baseline caller (the Week 2 RecordingCaller minus the raw-response file)
class BaselineCaller:
    """prompt -> reply text. Records each call (tokens, latency, finish reason, reply) in .calls, exactly the fields run_baseline_dev.process_alert reads."""

    def __init__(self, client, clock=time.perf_counter):
        self.client, self.clock = client, clock
        self.alert_id, self.calls = None, []

    def start(self, alert_id):
        self.alert_id, self.calls = alert_id, []

    def __call__(self, prompt):
        import gemini_client
        import run_baseline_dev as rb
        for attempt in range(rb.TRANSPORT_RETRIES + 1):
            started = self.clock()
            try:
                record = self.client.generate(prompt)
            except gemini_client.TransientModelError as error:
                if attempt == rb.TRANSPORT_RETRIES:
                    raise rb.ModelUnavailable("the model call failed %d times: %s" % (attempt + 1, error))
                time.sleep(rb.BACKOFF_SECONDS[min(attempt, len(rb.BACKOFF_SECONDS) - 1)])
                continue
            self.calls.append({"reply": record.text, "finish_reason": record.finish_reason, "block_reason": record.block_reason, "prompt_tokens": record.prompt_tokens,
                               "output_tokens": record.output_tokens, "thinking_tokens": record.thinking_tokens, "total_tokens": record.total_tokens,
                               "latency_seconds": round(self.clock() - started, 3)})
            return record.text
        raise rb.ModelUnavailable("no reply")


# ---------------------------------------------------------------------------------------------- per-configuration record builders
def failure_kind(record):
    if record["status"] == "ok":
        return "none"
    if record["status"] == "parse_failed":
        return "parse_failure"
    return "model_unavailable" if record.get("error_code") in ("model_unavailable", "model_exception") else "system_error"


def raw_detector_records(plan, data):
    for _, row in data.alerts.iterrows():
        yield {"alert_id": row["alert_id"], "status": "ok", "verdict": {"is_malicious": True, "attack_type": None, "mitre_technique": None, "severity": None, "evidence": None},
               "error_code": None, "error_detail": None, "attempts": 0, "model_calls": 0, "malformed_first_try": None, "attempt_log": [], "repairs": [], "prompt_tokens": None,
               "output_tokens": None, "thinking_tokens": None, "total_tokens": None, "latency_seconds": None, "finish_reasons": [], "detector_score": float(row["detector_score"]),
               "wall_seconds": 0.0, "note": "raw detector: malicious for every alert by definition; it gives no attack type or technique"}


def baseline_records(plan, data, client, say=None):
    import prompt_registry
    import run_baseline_dev as rb
    spec = prompt_registry.get_prompt(plan["configs"]["single_llm_baseline"]["prompt_version"])
    flows = data.flows.copy()
    flows["timestamp"] = pd.to_datetime(flows["timestamp"])
    caller = BaselineCaller(client)
    for _, row in data.alerts.iterrows():
        started = time.perf_counter()
        _model_input, prompt = prompt_registry.build_prompt_for_row(spec, row, flows)
        record = rb.process_alert(row["alert_id"], prompt, caller, "week5-eval", plan["model"]["parse_retries"])
        record = {k: v for k, v in record.items() if k not in ("session",)}
        if isinstance(record.get("verdict"), dict):
            record["verdict"] = dict(record["verdict"], evidence=None)           # the model's free text is not stored in result files
        record["wall_seconds"] = round(time.perf_counter() - started, 4)
        yield record


def full_system_records(plan, data, runner, memory_enabled, say=None):
    from agents import state as S
    flows = data.flows
    for _, row in data.alerts.iterrows():
        started = time.perf_counter()
        alert = S.alert_record(row, flows)
        record = {"alert_id": alert["alert_id"], "status": "model_error", "verdict": None, "error_code": None, "error_detail": None, "attempts": 0, "model_calls": 0, "malformed_first_try": None,
                  "attempt_log": [], "repairs": [], "prompt_tokens": None, "output_tokens": None, "thinking_tokens": None, "total_tokens": None, "latency_seconds": None, "finish_reasons": [],
                  "routing": None, "proposed_actions": [], "guard_signals": [], "graph_status": None}
        try:
            ex = runner.execute(alert, memory_enabled, 1, 1)           # one attempt: an unreachable model is RECORDED as model_error, never retried silently
        except Exception as error:      # a failure of the system itself is recorded as such, never turned into a verdict
            record["error_code"] = "system_exception"
            record["error_detail"] = "the system raised " + type(error).__name__
            record["wall_seconds"] = round(time.perf_counter() - started, 4)
            yield record
            continue
        v = ex.verdict or {}
        calls = ex.caller.calls
        usage = ex.caller.usage(fake=bool(runner.provider.fake))
        record.update(status=v.get("status") or "model_error", error_code=v.get("error_code"), error_detail=(v.get("error_detail") or None), attempt_log=v.get("attempt_log") or [],
                      repairs=v.get("repairs") or [], attempts=len(calls), model_calls=usage["model_calls"], prompt_tokens=usage["prompt_tokens"], output_tokens=usage["output_tokens"],
                      thinking_tokens=usage["thinking_tokens"], total_tokens=usage["total_tokens"], latency_seconds=round(usage["model_seconds"], 4), finish_reasons=[],
                      graph_status=ex.state.get("status"), prompt_version=v.get("prompt_version"), prompt_sha256=v.get("agent_prompt_sha256"), guard_signals=sorted({s.code for s in ex.signals}),
                      routing={k: ex.routed["routing"][k] for k in ("decision", "risk_level", "reasons", "policy_sha256")}, proposed_actions=jsonable(ex.routed.get("actions") or []))
        if record["status"] == "ok" and isinstance(v.get("verdict"), dict):
            record["verdict"] = {k: v["verdict"].get(k) for k in ("is_malicious", "attack_type", "mitre_technique", "severity", "evidence")}
            record["verdict"]["evidence"] = None            # the free text is not stored in result files
        elif record["status"] == "ok":
            record["status"], record["error_code"] = "model_error", "no_verdict_in_state"
        if record["attempt_log"]:
            record["malformed_first_try"] = record["attempt_log"][0].get("error_code") is not None
        record["wall_seconds"] = round(time.perf_counter() - started, 4)
        yield record


# ---------------------------------------------------------------------------------------------- what was ACTUALLY used (not what the plan says)
def observed_identity(config_name, client, provider):
    """The model name and generation settings read from the client / provider objects themselves. validate.py compares them with the plan, so a run cannot claim a model it did not use."""
    if config_name == "single_llm_baseline":
        cfg = getattr(client, "config", None) or {}
        return {"model": getattr(client, "model", None), "temperature": cfg.get("temperature"), "max_output_tokens": cfg.get("max_output_tokens"), "seed": cfg.get("seed")}
    if config_name == "full_system":
        view = getattr(provider, "observed_settings", None)
        llm = getattr(provider, "_llm", None)
        if view is None and llm is not None:
            from week5 import models
            view = {"temperature": getattr(llm, "TEMPERATURE", None), "max_output_tokens": getattr(llm, "MAX_OUTPUT_TOKENS", None), "seed": models.GENERATION_SEED}
        view = view or {}
        return {"model": getattr(provider, "name", None), "temperature": view.get("temperature"), "max_output_tokens": view.get("max_output_tokens"), "seed": view.get("seed")}
    return None


# ---------------------------------------------------------------------------------------------- one run
def make_runner(plan, data, provider, memory_store=None, memory_error=None):
    import tools
    from week4 import policy as policy_module
    from week5 import settings as settings_module
    from week5.runner import GraphRunner
    full = plan["configs"]["full_system"]
    settings = settings_module.Settings(engine=full["engine"], model_mode="fake" if plan["model"]["fake"] else "gemini", allow_live_model=not plan["model"]["fake"], alias_ids=bool(full["alias_ids"]),
                                        flow_store="none", memory_dir="" if memory_store is None else "set-by-caller")
    registry = tools.build_registry(flow_store=tools.FlowStore(data.flows))
    return GraphRunner(settings, policy_module.load_policy(None), registry, provider, memory_store, memory_error)


def collect_run(plan, config_name, run_index, data, out_root, client=None, provider=None, memory_store=None, memory_error=None, say=None):
    """Record one run. `client` (baseline: .generate(prompt)) or `provider` (full system: a week5.models provider) are supplied by the caller; the CLI builds fakes unless a live run was authorised.
    -> the run directory. Raises CollectError when the run already exists or the inputs do not match the plan."""
    if data.set_name != plan["set"]:
        raise CollectError("the data set (%s) is not the plan's set (%s)" % (data.set_name, plan["set"]))
    if config_name not in plan["configs"] or not 1 <= run_index <= plan["runs_per_config"]:
        raise CollectError("no such run in the plan")
    base = os.path.join(out_root, plan["plan_id"], config_name)
    final, partial = os.path.join(base, "run%d" % run_index), os.path.join(base, "run%d.partial" % run_index)
    if os.path.exists(final) or os.path.exists(partial):
        raise CollectError("run%d of %s already exists (%s); runs are write-once" % (run_index, config_name, "complete" if os.path.exists(final) else "partial"))
    cfg = plan["configs"][config_name]
    if config_name == "single_llm_baseline" and client is None:
        raise CollectError("the baseline needs a model client")
    if config_name == "full_system" and provider is None:
        raise CollectError("the full system needs a model provider")
    fake = bool(plan["model"]["fake"]) if cfg["uses_model"] else False
    os.makedirs(partial)
    started_utc, t0 = utc_now(), time.perf_counter()
    if config_name == "raw_detector":
        records = raw_detector_records(plan, data)
    elif config_name == "single_llm_baseline":
        records = baseline_records(plan, data, client, say)
    else:
        records = full_system_records(plan, data, make_runner(plan, data, provider, memory_store, memory_error), cfg["memory"] == "on", say)
    results_path, errors_path = os.path.join(partial, "results.jsonl"), os.path.join(partial, "errors.jsonl")
    count = 0
    with open(results_path, "w", encoding="utf-8", newline="\n") as rf, open(errors_path, "w", encoding="utf-8", newline="\n") as ef:
        for rec in records:
            rec = jsonable(rec)
            rec["schema"], rec["failure_kind"] = SCHEMA_RECORD, failure_kind(rec)
            rf.write(json.dumps(rec, sort_keys=True) + "\n")
            rf.flush()
            if rec["failure_kind"] != "none":
                ef.write(json.dumps({"alert_id": rec["alert_id"], "failure_kind": rec["failure_kind"], "status": rec["status"], "error_code": rec.get("error_code"),
                                     "error_detail": (rec.get("error_detail") or "")[:200]}, sort_keys=True) + "\n")
            count += 1
    wall = time.perf_counter() - t0
    snapshot = {"plan": plan, "plan_sha256": plan_sha256(plan), "config": config_name, "config_settings": cfg, "model": plan["model"] if cfg["uses_model"] else None,
                "python": platform.python_version(), "pandas": pd.__version__}
    write_json(os.path.join(partial, "config_snapshot.json"), snapshot)
    meta = {"schema": SCHEMA_RUN_META, "run_id": "%s-%s-r%d-%s" % (plan["plan_id"], config_name, run_index, uuid.uuid4().hex[:8]), "plan_id": plan["plan_id"], "plan_sha256": plan_sha256(plan),
            "config": config_name, "run_index": run_index, "set": data.set_name, "fake_model": fake, "model": plan["model"] if cfg["uses_model"] else None, "observed": observed_identity(config_name, client, provider),
            "started_utc": started_utc, "finished_utc": utc_now(), "wall_seconds": round(wall, 4), "alerts_expected": int(len(data.alerts)), "alerts_recorded": count, "concurrency": 1,
            "inputs": data.hashes(), "threshold": plan["threshold"], "status": "complete", "nondeterminism": list(NONDETERMINISM)}
    write_json(os.path.join(partial, "run_meta.json"), meta)
    with open(os.path.join(partial, "run.sha256"), "w", encoding="ascii", newline="\n") as fh:
        for name in FILES:
            fh.write("%s  %s\n" % (sha256_file(os.path.join(partial, name)), name))
    os.rename(partial, final)
    return final
