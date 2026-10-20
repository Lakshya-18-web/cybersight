"""Validate a set of recorded runs BEFORE any comparison is made. Detects: missing runs, partial output, tampered or truncated files, schema mismatches, duplicate or missing alerts, runs of a different plan,
different inputs / label definitions / model / settings / threshold / policy between the runs being compared, a fake run mixed with real ones, and a raw detector that is not deterministic.
Every problem is listed with a code; a comparison is produced only when there is no problem (report.py prints "NOT COMPARABLE" with the list otherwise). Nothing is repaired or dropped silently."""
import json
import os

from . import CONFIGS, SCHEMA_RECORD, SCHEMA_RUN_META
from .collect import FILES, sha256_file
from .data import canonical
from .plan import plan_sha256, run_key, validate_plan

RECORD_KEYS = {"alert_id", "status", "verdict", "error_code", "attempts", "model_calls", "attempt_log", "latency_seconds", "failure_kind", "schema", "wall_seconds"}
STATUSES = ("ok", "parse_failed", "model_error")
FAILURE_KINDS = ("none", "parse_failure", "model_unavailable", "system_error")
VERDICT_KEYS = {"is_malicious", "attack_type", "mitre_technique", "severity"}


class LoadedRun:
    def __init__(self, key, config, index, path):
        self.key, self.config, self.index, self.path = key, config, index, path
        self.meta = self.snapshot = None
        self.records, self.errors = [], []
        self.status = "missing"


def _problem(problems, code, key, detail):
    problems.append({"code": code, "run": key, "detail": detail})


def _read_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _read_jsonl(path):
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    raise ValueError("line %d is not valid JSON" % n)
    return rows


def load_run(plan, root, config, index, problems):
    key = run_key(config, index)
    base = os.path.join(root, plan["plan_id"], config)
    path, partial = os.path.join(base, "run%d" % index), os.path.join(base, "run%d.partial" % index)
    run = LoadedRun(key, config, index, path)
    if os.path.isdir(partial):
        run.status = "partial"
        _problem(problems, "PARTIAL_RUN", key, "an unfinished run folder exists (%s): the run did not complete" % os.path.basename(partial))
    if not os.path.isdir(path):
        if run.status != "partial":
            _problem(problems, "MISSING_RUN", key, "no recorded run")
        return run
    run.status = "invalid"
    try:
        for name in FILES + ("run.sha256",):
            if not os.path.isfile(os.path.join(path, name)):
                _problem(problems, "MISSING_FILE", key, name)
                return run
        listed = {}
        with open(os.path.join(path, "run.sha256"), "r", encoding="ascii") as fh:
            for line in fh:
                digest, _, name = line.strip().partition("  ")
                listed[name] = digest
        for name in FILES:
            if listed.get(name) != sha256_file(os.path.join(path, name)):
                _problem(problems, "HASH_MISMATCH", key, "%s does not match run.sha256 (changed or truncated after the run)" % name)
                return run
        run.meta, run.snapshot = _read_json(os.path.join(path, "run_meta.json")), _read_json(os.path.join(path, "config_snapshot.json"))
        run.records, run.errors = _read_jsonl(os.path.join(path, "results.jsonl")), _read_jsonl(os.path.join(path, "errors.jsonl"))
    except (OSError, ValueError) as error:
        _problem(problems, "UNREADABLE", key, str(error)[:120])
        return run
    run.status = "loaded"
    return run


def _check_run(plan, run, problems):
    m, key = run.meta, run.key
    if m.get("schema") != SCHEMA_RUN_META:
        _problem(problems, "BAD_SCHEMA", key, "run_meta.json has the wrong schema")
    if m.get("status") != "complete":
        _problem(problems, "NOT_COMPLETE", key, "run_meta status is %r" % m.get("status"))
    if m.get("plan_sha256") != plan_sha256(plan):
        _problem(problems, "PLAN_MISMATCH", key, "the run was made under a different plan")
    if m.get("set") != plan["set"] or m.get("config") != run.config or m.get("run_index") != run.index:
        _problem(problems, "META_MISMATCH", key, "set / config / run index in run_meta.json do not match the folder")
    if run.snapshot.get("config_settings") != plan["configs"][run.config] or run.snapshot.get("plan_sha256") != plan_sha256(plan):
        _problem(problems, "CONFIG_MISMATCH", key, "the configuration snapshot differs from the plan")
    uses_model = plan["configs"][run.config]["uses_model"]
    if (m.get("model") or None) != (plan["model"] if uses_model else None):
        _problem(problems, "MODEL_MISMATCH", key, "the model or generation settings differ from the plan")
    if uses_model:
        obs, want = m.get("observed") or {}, plan["model"]
        wrong = [k for k, plan_key in (("model", "name"), ("temperature", "temperature"), ("max_output_tokens", "max_output_tokens"), ("seed", "seed")) if obs.get(k) != want[plan_key]]
        if wrong:
            _problem(problems, "OBSERVED_MODEL_MISMATCH", key, "the client actually used differs from the plan in: " + ", ".join(wrong))
    if uses_model and bool(m.get("fake_model")) != bool(plan["model"]["fake"]):
        _problem(problems, "FAKE_MISMATCH", key, "fake_model=%s but the plan says fake=%s" % (m.get("fake_model"), plan["model"]["fake"]))
    if m.get("threshold") != plan["threshold"]:
        _problem(problems, "THRESHOLD_MISMATCH", key, "detector threshold differs from the plan")
    if m.get("alerts_recorded") != len(run.records) or m.get("alerts_expected") != len(run.records):
        _problem(problems, "COUNT_MISMATCH", key, "run_meta says %s recorded / %s expected, results.jsonl has %d" % (m.get("alerts_recorded"), m.get("alerts_expected"), len(run.records)))
    seen = set()
    for rec in run.records:
        missing = RECORD_KEYS - set(rec)
        if missing or rec.get("schema") != SCHEMA_RECORD:
            _problem(problems, "RECORD_SCHEMA", key, "record %s: missing %s" % (rec.get("alert_id"), ",".join(sorted(missing)) or "schema"))
            break
        if rec["status"] not in STATUSES or rec["failure_kind"] not in FAILURE_KINDS or (rec["status"] == "ok") != (rec["failure_kind"] == "none"):
            _problem(problems, "RECORD_SCHEMA", key, "record %s has an inconsistent status / failure_kind" % rec["alert_id"])
            break
        if rec["status"] == "ok" and (not isinstance(rec["verdict"], dict) or not VERDICT_KEYS <= set(rec["verdict"])):
            _problem(problems, "RECORD_SCHEMA", key, "record %s is ok but has no complete verdict" % rec["alert_id"])
            break
        if rec["status"] != "ok" and rec["verdict"] is not None:
            _problem(problems, "RECORD_SCHEMA", key, "record %s has a verdict although it did not succeed" % rec["alert_id"])
            break
        if rec["alert_id"] in seen:
            _problem(problems, "DUPLICATE_ALERT", key, "alert %s appears twice" % rec["alert_id"])
            break
        seen.add(rec["alert_id"])
    if len(run.errors) != sum(1 for r in run.records if r.get("failure_kind") != "none"):
        _problem(problems, "ERRORS_MISMATCH", key, "errors.jsonl does not list exactly the non-ok records")
    if run.config == "full_system":
        for rec in run.records:
            routing = rec.get("routing")
            if routing is not None and routing.get("policy_sha256") != plan["configs"]["full_system"].get("policy_sha256"):
                _problem(problems, "POLICY_MISMATCH", key, "alert %s was routed with a different risk policy than the plan's" % rec["alert_id"])
                break


def validate_runs(plan, root, data=None):
    """-> {"valid": bool, "problems": [...], "runs": {key: LoadedRun}}. `data` (EvalData) is optional; with it the runs are also checked against the actual input records and labels."""
    problems = []
    for p in validate_plan(plan):
        _problem(problems, "BAD_PLAN", None, p)
    runs = {}
    for config in CONFIGS:
        for i in range(1, plan["runs_per_config"] + 1):
            run = load_run(plan, root, config, i, problems)
            runs[run.key] = run
            if run.status == "loaded":
                _check_run(plan, run, problems)
        base = os.path.join(root, plan["plan_id"], config)
        if os.path.isdir(base):
            expected = {"run%d" % i for i in range(1, plan["runs_per_config"] + 1)}
            for name in sorted(os.listdir(base)):
                if name not in expected and name.replace(".partial", "") not in expected:
                    _problem(problems, "UNEXPECTED_RUN", "%s/%s" % (config, name), "a folder that is not one of the planned runs")
    loaded = [r for r in runs.values() if r.status == "loaded"]
    ids = list(data.alerts["alert_id"]) if data is not None else (None if not loaded else [r["alert_id"] for r in loaded[0].records])
    ids_set = set(ids) if ids is not None else None
    for run in loaded:
        got = [r["alert_id"] for r in run.records]
        if ids is not None and got != ids:
            code = "ALERT_SET_MISMATCH" if set(got) != ids_set else "ALERT_ORDER_MISMATCH"
            _problem(problems, code, run.key, "the run's alert ids are not the evaluation set's (%d recorded, %d expected)" % (len(got), len(ids)))
    if data is not None:
        expected_inputs = data.hashes()
        for run in loaded:
            if run.meta.get("inputs") != expected_inputs:
                _problem(problems, "INPUT_MISMATCH", run.key, "the recorded input hashes (alerts, labels, flows) differ from the data supplied now")
    inputs = {canonical(r.meta.get("inputs")) for r in loaded}
    if len(inputs) > 1:
        _problem(problems, "INPUT_MISMATCH", None, "the runs were made on different input records or label definitions")
    run_ids = [r.meta.get("run_id") for r in loaded]
    if len(set(run_ids)) != len(run_ids):
        _problem(problems, "DUPLICATE_RUN_ID", None, "two runs share a run id")
    raw = [r for r in loaded if r.config == "raw_detector"]
    if len(raw) > 1 and len({canonical([{k: v for k, v in rec.items() if k != "wall_seconds"} for rec in r.records]) for r in raw}) > 1:
        _problem(problems, "RAW_NOT_DETERMINISTIC", None, "the raw detector runs differ from each other; a deterministic rule must give identical results")
    fakes = {bool(r.meta.get("fake_model")) for r in loaded if plan["configs"][r.config]["uses_model"]}
    if len(fakes) > 1:
        _problem(problems, "FAKE_MIXED", None, "a fake-model run is mixed with a real-model run")
    if plan["set"] != "fixture" and any(r.meta.get("fake_model") for r in loaded):
        _problem(problems, "FAKE_ON_REAL_SET", None, "a fake-model run exists for a %s plan" % plan["set"])
    return {"valid": not problems, "problems": problems, "runs": runs}
