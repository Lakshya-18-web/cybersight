"""Labelled evaluation of the SENSOR pipeline on the synthetic scenario set (week5.evalrun.sensor_scenarios), offline and reproducible.

    python -m week5.evalrun.sensor_suite --out DIR [--profiles oracle,lazy_benign,noisy] [--seed N]

For every model profile the whole path runs in process: EVE events -> ingestion -> stored evidence -> analysis agents -> risk policy -> evidence policy -> case. Then five decision-makers are compared on the
same alerts (positive = "do not close"):
    sensor_passthrough       every alert is escalated (no triage; the Week 2 "raw detector" idea)
    sensor_severity_rule     Suricata severity 1 or 2 is flagged; 3 is closed. No model.
    model_only               the verdict alone: malicious -> flagged, benign -> closed; a missing verdict is flagged (fail closed)
    model_plus_risk_policy   verdict + the Week 4 risk policy, before the evidence policy (positive = escalate or needs_review)
    full_pipeline            the stored case routing: verdict + risk policy + evidence policy (deterministic veto) (positive = escalate or needs_review)
    *_escalate_only          the same two, but only the top-priority queue (escalate) counts as flagged: a PRIORITY view. Sensor alerts are never auto-closed (no detector score), so the
                             closed/not-closed view cannot separate attacks from benign traffic for them; the queue the case lands in is what carries the information.

HONESTY NOTES (repeated in the report): the model is a SCRIPTED FAKE whose behaviour is a stated assumption; the traffic is synthetic; no real Suricata, Gemini or AbuseIPDB is involved. The numbers show what
the deterministic layers add or cannot add under an assumed model; they are not detection accuracy. Tokens and cost do not exist for a fake model and are reported as unavailable. Real-model performance needs
a real run (python -m week5.evalrun plan/collect/score on the dev set) and is NOT in this report.
"""
import argparse
import hashlib
import json
import os
import platform
import sys
import time

import week5
from week4 import policy as w4_policy
from week4.db.fake import MemoryRepository
from week5 import evidence_policy, ingest5, jobs, models, queues, repo5, settings as settings_module, worker as worker_module
from week5.runner import GraphRunner

from . import sensor_scenarios as SC

SCHEMA = "week5-sensor-eval-v1"
PROFILES = ("oracle", "noisy", "lazy_benign")
CONFIGS = ("sensor_passthrough", "sensor_severity_rule", "model_only", "model_plus_risk_policy", "full_pipeline", "model_plus_risk_policy_escalate_only", "full_pipeline_escalate_only")
ACTOR = "evaluator"
SENSOR = "eval-sensor-1"
BATCH = 400
CAUTION = {"auto_close": 0, "needs_review": 1, "escalate": 2}


class ScriptedClient(models.FakeClient):
    def __init__(self, reply_for, failing=()):
        super().__init__("ok_benign")
        self.reply_for, self.failing = reply_for, set(failing)

    def generate(self, prompt):
        self.n += 1
        raise_for = self.alert_id in self.failing
        if raise_for:
            raise models.gemini_client.TransientModelError("scripted provider outage", 503)
        return self._record(json.dumps(self.reply_for(self.alert_id)))


class ScriptedModel(models.FakeModel):
    name = "FAKE:scripted-eval"

    def __init__(self, reply_for, failing=()):
        super().__init__()
        self.reply_for, self.failing = reply_for, failing

    def caller(self, spec, alert_id):
        client = ScriptedClient(self.reply_for, self.failing)
        client.alert_id = alert_id
        return models.JobCaller(client, gate=None, sleep=lambda s: None)


def _stack(provider):
    settings = settings_module.Settings(engine="instrumented", flow_store="none", job_timeout_seconds=30.0, lease_seconds=120, retry_backoff_seconds=(0.0, 0.0, 0.0), max_attempts=3,
                                        poll_interval_seconds=0.01, rate_limit_per_minute=0, max_queue_depth=100000)
    store = jobs.MemoryJobStore()
    repo = repo5.wrap(MemoryRepository())
    repo.upsert_analyst(ACTOR, "analyst")
    registry = __import__("tools").build_registry(flow_store=__import__("week5.fixtures", fromlist=["x"]).flow_store())
    runner = GraphRunner(settings, w4_policy.load_policy(None), registry, provider).attach_repository(repo)
    queue = queues.PostgresQueue(store)
    dispatcher = queues.Dispatcher(store, queue, settings)
    worker = worker_module.Worker(settings, store, repo, runner, dispatcher, worker_id="eval-worker", timeout_mode="thread", log=lambda *a, **k: None)
    return settings, store, repo, dispatcher, worker, runner


def _percentile(values, q):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * q
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def run_profile(scenarios, profile, failing_fraction=0.0, seed=0):
    """-> {"records": [...], "ops": {...}}. One fresh stack per call."""
    by_alert = {}
    failing = set()

    def reply_for(alert_id):
        return SC.model_reply(by_alert[alert_id]["family"], profile, alert_id)

    provider = ScriptedModel(reply_for, failing)
    settings, store, repo, dispatcher, worker, runner = _stack(provider)
    alert_ids = []
    flat = []
    for s in scenarios:
        flat.extend(s["events"])
    started = time.perf_counter()
    for i in range(0, len(flat), BATCH):
        res = ingest5.ingest(repo, store, dispatcher, settings, ACTOR, SENSOR, flat[i:i + BATCH], "off", True)
        if res["outcome"] != "ok" or res["rejected"]:
            raise RuntimeError("the scenario batch was not accepted: %s" % json.dumps({k: res[k] for k in ("outcome", "rejected")}, default=str)[:300])
        alert_ids.extend(a["alert_id"] for a in res["alerts"])
    ingest_seconds = time.perf_counter() - started
    if len(alert_ids) != len(scenarios):
        raise RuntimeError("expected one alert per scenario, got %d for %d" % (len(alert_ids), len(scenarios)))
    for s, aid in zip(scenarios, alert_ids):
        by_alert[aid] = s
    if failing_fraction > 0:
        for aid in alert_ids:
            u = int(hashlib.sha256(("fail:%s:%s" % (seed, aid)).encode("utf-8")).hexdigest()[:8], 16) / float(16 ** 8)
            if u < failing_fraction:
                failing.add(aid)
    started = time.perf_counter()
    runs = 0
    while worker.run_once() is not None:
        runs += 1
        if runs > 20 * len(alert_ids):
            raise RuntimeError("the worker did not drain the queue")
    drain_seconds = time.perf_counter() - started
    records = []
    for s, aid in zip(scenarios, alert_ids):
        job = next(j for j in store.jobs.values() if j["alert_id"] == aid) if hasattr(store, "jobs") else None
        case = repo.get_case(job["case_id"]) if job and job.get("case_id") else None
        rec = {"scenario": s["scenario"], "family": s["family"], "label": s["label"], "true_class": s["true_class"], "suricata_severity": s["suricata_severity"], "alert_id": aid,
               "job_status": job["status"] if job else "missing", "attempts": job["attempts"] if job else None, "wall_seconds": ((job or {}).get("timings") or {}).get("wall_seconds"),
               "case": None}
        if case:
            wk = case["provenance"].get("week5") or {}
            v = case.get("verdict") or {}
            rec["case"] = {"decision": case["routing"]["decision"], "risk_level": case["routing"]["risk_level"], "decision_before_evidence": (wk.get("evidence_policy") or {}).get("decision_before"),
                           "evidence_rules": (wk.get("evidence_policy") or {}).get("fired"), "verdict_status": v.get("status"), "is_malicious": v.get("is_malicious"), "attack_type": v.get("attack_type"),
                           "proposed_actions": len(case.get("actions") or []), "approved_or_executed_actions": sum(1 for a in case.get("actions") or [] if a.get("state") not in ("pending",))}
        records.append(rec)
    walls = [r["wall_seconds"] for r in records if r["wall_seconds"] is not None]
    ops = {"alerts": len(records), "ingest_seconds": round(ingest_seconds, 4), "drain_seconds": round(drain_seconds, 4),
           "throughput_alerts_per_second": round(len(records) / drain_seconds, 2) if drain_seconds > 0 else None, "latency_median_s": _percentile(walls, 0.5), "latency_p95_s": _percentile(walls, 0.95),
           "jobs_succeeded": sum(1 for r in records if r["job_status"] == "succeeded"), "jobs_failed": sum(1 for r in records if r["job_status"] != "succeeded"),
           "job_failure_rate": (sum(1 for r in records if r["job_status"] != "succeeded") / len(records)) if records else None,
           "alerts_retried": sum(1 for r in records if (r["attempts"] or 0) > 1), "attempts_total": sum(r["attempts"] or 0 for r in records),
           "model_errors_stored_as_needs_review": sum(1 for r in records if r["case"] and r["case"]["verdict_status"] == "model_error"),
           "tokens": {"available": False, "reason": "a scripted fake model reports no token counts"}, "cost": {"available": False, "reason": "no tokens and no verified pricing configuration; no price is assumed"},
           "simulated": True, "note": "latency and throughput measure this software on this machine with an instant fake model; they say nothing about Gemini or production hardware"}
    return {"records": records, "ops": ops, "injected_provider_failures": len(failing)}


def decisions(rec):
    """Per configuration: True when the alert is flagged (not closed)."""
    c = rec["case"]
    out = {"sensor_passthrough": True, "sensor_severity_rule": rec["suricata_severity"] <= 2}
    if c is None:
        out.update(model_only=True, model_plus_risk_policy=True, full_pipeline=True, model_plus_risk_policy_escalate_only=True, full_pipeline_escalate_only=True)
        return out
    out["model_only"] = True if c["is_malicious"] is None else bool(c["is_malicious"])
    before = c["decision_before_evidence"] or c["decision"]
    out["model_plus_risk_policy"] = before != "auto_close"
    out["full_pipeline"] = c["decision"] != "auto_close"
    out["model_plus_risk_policy_escalate_only"] = before == "escalate"          # priority view: only the top queue counts as "flagged"; needs_review counts as not flagged
    out["full_pipeline_escalate_only"] = c["decision"] == "escalate"
    return out


def confusion(records, config):
    tp = fp = fn = tn = 0
    missed, fp_ids = [], []
    for r in records:
        flagged, attack = decisions(r)[config], r["label"] == "attack"
        if attack and flagged:
            tp += 1
        elif attack:
            fn += 1
            missed.append(r["scenario"])
        elif flagged:
            fp += 1
            fp_ids.append(r["scenario"])
        else:
            tn += 1
    div = lambda a, b: (a / b) if b else None          # noqa: E731
    p, rc = div(tp, tp + fp), div(tp, tp + fn)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": p, "recall": rc, "f1": (2 * p * rc / (p + rc)) if p and rc else (0.0 if p is not None and rc is not None else None),
            "specificity": div(tn, tn + fp), "false_positive_rate": div(fp, fp + tn), "false_negative_rate": div(fn, fn + tp), "flagged_rate": div(tp + fp, tp + fp + fn + tn),
            "incorrect_closures_of_attacks": fn, "missed_attack_scenarios": missed, "benign_flagged_count": fp}


def per_class(records, config):
    out = {}
    for r in records:
        c = out.setdefault(r["true_class"], {"support": 0, "flagged": 0, "closed": 0, "label": r["label"]})
        c["support"] += 1
        c["flagged" if decisions(r)[config] else "closed"] += 1
    for c in out.values():
        c["recall" if c["label"] == "attack" else "specificity"] = (c["flagged"] if c["label"] == "attack" else c["closed"]) / c["support"]
    return out


def per_family(records, config):
    out = {}
    for r in records:
        c = out.setdefault(r["family"], {"label": r["label"], "support": 0, "flagged": 0})
        c["support"] += 1
        c["flagged"] += 1 if decisions(r)[config] else 0
    return out


def invariants(records):
    """Properties that must hold on EVERY run regardless of the model; a violation is a defect, not a result."""
    problems = []
    for r in records:
        c = r["case"]
        if c is None:
            continue
        if r["label"] == "attack" and c["decision"] == "auto_close":
            problems.append("attack auto-closed: " + r["scenario"])
        if c["decision"] == "auto_close":
            problems.append("a sensor alert (no detector score) was auto-closed: " + r["scenario"])
        if CAUTION[c["decision"]] < CAUTION[c["decision_before_evidence"] or c["decision"]]:
            problems.append("the evidence policy lowered caution: " + r["scenario"])
        if c["approved_or_executed_actions"]:
            problems.append("an action left the pending state without a human: " + r["scenario"])
    return problems


def run(out_dir, profiles=PROFILES, per_family_counts=None, failure_fraction=0.2, seed=0, now=None):
    scenarios = SC.build(per_family_counts)
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) if now is None else now
    risk = w4_policy.load_policy(None)
    ev = evidence_policy.load()
    result = {"schema": SCHEMA, "generated_utc": started, "synthetic": True, "fake_model": True, "real_traffic": False, "real_performance": "NOT MEASURED",
              "set": {"id": SC.SET_ID, "scenarios": len(scenarios), "attacks": sum(1 for s in scenarios if s["label"] == "attack"), "benign": sum(1 for s in scenarios if s["label"] == "benign"),
                      "families": {f: sum(1 for s in scenarios if s["family"] == f) for f in SC.FAMILIES}, "sha256": SC.sha256(scenarios), "label_source": "by construction (family decides the label)"},
              "versions": {"week5": week5.VERSION, "risk_policy": risk.version, "risk_policy_sha256": risk.sha256, "evidence_policy": ev.version, "evidence_policy_sha256": ev.sha256, "python": platform.python_version()},
              "profiles": {}, "provider_failure": None, "invariant_violations": [], "limits": LIMITS}
    for profile in profiles:
        res = run_profile(scenarios, profile, 0.0, seed)
        bad = invariants(res["records"])
        result["invariant_violations"].extend("%s: %s" % (profile, b) for b in bad)
        result["profiles"][profile] = {"assumption": ASSUMPTIONS[profile], "ops": res["ops"], "configs": {c: confusion(res["records"], c) for c in CONFIGS},
                                       "per_class": {c: per_class(res["records"], c) for c in ("model_only", "full_pipeline", "full_pipeline_escalate_only")}, "per_family": {c: per_family(res["records"], c) for c in ("model_only", "full_pipeline", "full_pipeline_escalate_only")},
                                       "records": res["records"]}
    if failure_fraction:
        res = run_profile(scenarios, "oracle", failure_fraction, seed)
        bad = invariants(res["records"])
        result["invariant_violations"].extend("provider_failure: " + b for b in bad)
        attacks_in_failed = [r["scenario"] for r in res["records"] if r["label"] == "attack" and r["case"] and r["case"]["verdict_status"] == "model_error"]
        result["provider_failure"] = {"injected_failure_fraction": failure_fraction, "alerts_with_injected_outage": res["injected_provider_failures"], "ops": res["ops"],
                                      "attacks_hit_by_outage": attacks_in_failed, "attacks_hit_and_closed": [r["scenario"] for r in res["records"] if r["scenario"] in attacks_in_failed and r["case"]["decision"] == "auto_close"],
                                      "all_outage_cases_routed_to_review": all(r["case"]["decision"] != "auto_close" for r in res["records"] if r["case"] and r["case"]["verdict_status"] == "model_error"),
                                      "confusion_full_pipeline": confusion(res["records"], "full_pipeline")}
    os.makedirs(out_dir, exist_ok=True)
    slim = json.loads(json.dumps(result))
    for p in slim["profiles"].values():
        p.pop("records")                      # the per-scenario records are in sensor_eval_records.json, so the report JSON served by the API stays small
    with open(os.path.join(out_dir, "sensor_eval.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(slim, fh, indent=2, sort_keys=True)
        fh.write("\n")
    with open(os.path.join(out_dir, "sensor_eval_records.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump({p: v["records"] for p, v in result["profiles"].items()}, fh, indent=1, sort_keys=True)
        fh.write("\n")
    with open(os.path.join(out_dir, "SENSOR_EVAL_REPORT.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render(result))
    return result


ASSUMPTIONS = {
    "oracle": "The model is always right. This is the ceiling: what the pipeline does when the model cannot be blamed.",
    "noisy": "The model is wrong on 25% of alerts (deterministic per alert id): an attack called benign, or benign traffic called a PortScan.",
    "lazy_benign": "The model calls every alert benign (talked into it, or blind to the attack). This shows what the deterministic layers alone catch.",
}
LIMITS = [
    "SYNTHETIC: the traffic is generated by scripts in this repository; labels are by construction. It is not real Suricata output and not real network behaviour.",
    "FAKE MODEL: replies are scripted per profile. The profiles are assumptions about a model, not measurements of Gemini. Nothing here is real model accuracy.",
    "No frozen or holdout data was used. No real API (Gemini, AbuseIPDB) was called; threat intelligence is not part of this run.",
    "Sensor alerts carry no detector score, so by policy (R3 and E6) the full pipeline never auto-closes them: every benign alert is a workload cost. That is a design decision, visible in 'flagged rate'.",
    "Families such as quiet_attack look like ordinary traffic to every deterministic rule. They are caught only when the model catches them.",
    "Latency and throughput are in-process timings with an instant fake model on one machine. They are not capacity figures.",
    "Counts are small (see the support column). A rate computed from a handful of scenarios is not a stable estimate.",
]


def pct(v):
    return "n/a" if v is None else "%.1f%%" % (100 * v)


def num(v):
    return "n/a" if v is None else "%.3f" % v


def render(result):
    L = []
    add = L.append
    add("# Sensor pipeline evaluation (SYNTHETIC scenarios, SCRIPTED model)")
    add("")
    add("> **Read this first.** The traffic is synthetic, the model is a scripted fake whose behaviour is an assumption, and no real service was called. These numbers describe what the deterministic layers do "
        "under assumed model behaviour. They are **not** detection accuracy and must not be quoted as such. Real-model performance is not measured here.")
    add("")
    s = result["set"]
    add("Set `%s`: %d scenarios (%d attack, %d benign), SHA-256 `%s`. Generated %s. Week 5 `%s`, risk policy `%s`, evidence policy `%s`." % (
        s["id"], s["scenarios"], s["attacks"], s["benign"], s["sha256"], result["generated_utc"], result["versions"]["week5"], result["versions"]["risk_policy"], result["versions"]["evidence_policy"]))
    add("")
    add("Families: " + ", ".join("%s=%d" % kv for kv in s["families"].items()) + ".")
    add("")
    add("Positive = the alert is **not closed** (flagged for an analyst). A missed attack is an attack that was closed. Configurations: `sensor_passthrough` (everything flagged), `sensor_severity_rule` "
        "(Suricata severity 1-2 flagged, no model), `model_only` (the verdict alone), `model_plus_risk_policy` (verdict + Week 4 policy), `full_pipeline` (+ evidence policy veto = what the system actually stores). "
        "The two `*_escalate_only` rows count only the top-priority queue (`escalate`) as flagged. **Why:** a sensor alert has no detector score, so the system never auto-closes it; the plain rows therefore flag everything and the "
        "information is in WHICH queue a case lands in.")
    add("")
    if result["invariant_violations"]:
        add("## INVARIANT VIOLATIONS (defects)")
        add("")
        for v in result["invariant_violations"]:
            add("- " + v)
        add("")
    else:
        add("**Invariants held on every run:** no attack was auto-closed, no sensor alert was auto-closed, the evidence policy never lowered caution, and no action left `pending` without a human.")
        add("")
    for profile, p in result["profiles"].items():
        add("## Model profile `%s`" % profile)
        add("")
        add(p["assumption"])
        add("")
        rows = []
        for c in CONFIGS:
            m = p["configs"][c]
            rows.append("| %s | %d | %d | %d | %d | %s | %s | %s | %s | %s | %s |" % (c, m["tp"], m["fp"], m["fn"], m["tn"], num(m["precision"]), num(m["recall"]), num(m["f1"]), pct(m["specificity"]), pct(m["false_positive_rate"]), pct(m["flagged_rate"])))
        add("| configuration | TP | FP | FN (attacks closed) | TN | precision | recall | F1 | specificity | FPR | flagged rate (analyst workload) |")
        add("|---|---|---|---|---|---|---|---|---|---|---|")
        L.extend(rows)
        add("")
        add("Attacks closed by the full pipeline: %s. Attacks NOT in the escalate queue (priority view; they are in needs_review): %s." % (", ".join(p["configs"]["full_pipeline"]["missed_attack_scenarios"]) or "none", ", ".join(p["configs"]["full_pipeline_escalate_only"]["missed_attack_scenarios"]) or "none"))
        add("")
        add("Per class (full pipeline, priority view: flagged = escalate):")
        add("")
        add("| true class | support | escalated | not escalated | recall / specificity |")
        add("|---|---|---|---|---|")
        for cls, c in p["per_class"]["full_pipeline_escalate_only"].items():
            add("| %s | %d | %d | %d | %s |" % (cls, c["support"], c["flagged"], c["closed"], pct(c.get("recall", c.get("specificity")))))
        add("")
        add("Per family (full pipeline, priority view):")
        add("")
        add("| family | label | support | escalated |")
        add("|---|---|---|---|")
        for fam, c in p["per_family"]["full_pipeline_escalate_only"].items():
            add("| %s | %s | %d | %d |" % (fam, c["label"], c["support"], c["flagged"]))
        add("")
        o = p["ops"]
        add("Operations: %d alerts, %d jobs failed (%s), %d retried, attempts total %d, drain %.2fs (%s alerts/s), latency median %s s, p95 %s s. Tokens: %s. Cost: %s." % (
            o["alerts"], o["jobs_failed"], pct(o["job_failure_rate"]), o["alerts_retried"], o["attempts_total"], o["drain_seconds"], o["throughput_alerts_per_second"], num(o["latency_median_s"]), num(o["latency_p95_s"]),
            "unavailable (fake model)", "unavailable (no tokens, no verified pricing)"))
        add("")
    pf = result["provider_failure"]
    if pf:
        add("## Provider failure")
        add("")
        add("A model outage was injected for %.0f%% of alerts (%d alerts, deterministic), persistent through every retry (3 attempts)." % (100 * pf["injected_failure_fraction"], pf["alerts_with_injected_outage"]))
        add("")
        add("- Cases still created with `model_error` and routed to review: %s (%d alerts)." % ("yes" if pf["all_outage_cases_routed_to_review"] else "NO", pf["ops"]["model_errors_stored_as_needs_review"]))
        add("- Attacks hit by the outage: %d; of those, closed: %d." % (len(pf["attacks_hit_by_outage"]), len(pf["attacks_hit_and_closed"])))
        add("- Job retries: %d alerts retried, %d attempts in total. Failed jobs after retries: %d." % (pf["ops"]["alerts_retried"], pf["ops"]["attempts_total"], pf["ops"]["jobs_failed"]))
        add("")
    add("## Limits")
    add("")
    for line in result["limits"]:
        add("- " + line)
    add("")
    add("Reproduce: `python -m week5.evalrun.sensor_suite --out <folder>` (no network, no key, no database). Per-scenario records: `sensor_eval_records.json`.")
    return "\n".join(L) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description="Labelled sensor-pipeline evaluation on the synthetic scenario set (offline).")
    p.add_argument("--out", required=True, help="folder for sensor_eval.json, sensor_eval_records.json and SENSOR_EVAL_REPORT.md (use WEEK5_EVAL_REPORT_DIR to show it in the dashboard)")
    p.add_argument("--profiles", default=",".join(PROFILES))
    p.add_argument("--failure-fraction", type=float, default=0.2)
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args(argv)
    profiles = tuple(x.strip() for x in args.profiles.split(",") if x.strip())
    for x in profiles:
        if x not in PROFILES:
            raise SystemExit("unknown profile " + x)
    if not 0 <= args.failure_fraction < 1:
        raise SystemExit("--failure-fraction must be in [0, 1)")
    result = run(args.out, profiles, None, args.failure_fraction, args.seed)
    print("SYNTHETIC evaluation (scripted fake model). Wrote SENSOR_EVAL_REPORT.md, sensor_eval.json, sensor_eval_records.json to " + args.out)
    print("invariant violations: %d" % len(result["invariant_violations"]))
    return 1 if result["invariant_violations"] else 0


if __name__ == "__main__":
    sys.exit(main())
