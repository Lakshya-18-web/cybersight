"""Metrics for the final comparison. The definitions are the project's own and are REUSED, not re-implemented: eval_metrics (Week 2: verdict precision/recall/F1 under three no-verdict policies, confusion
matrices, FP reduction, attack-type and MITRE accuracy, reliability, tokens, cost, latency) through evaluate.build_table / check_inputs, and week4.evaluate_memory.routing_metrics (routing and auto-close behaviour).

What this module adds, and nothing else:
  - the raw detector's row (its decision is "malicious" for every alert, by the Week 2 definition),
  - a failure breakdown that keeps SYSTEM failures (no verdict: parse failure, model unavailable, system error) apart from CLASSIFICATION errors among valid verdicts,
  - throughput and wall-time figures,
  - the spread across the three runs of one configuration (mean, min, max, range) and how many alerts changed verdict between runs. No p-values and no "significant": three runs of a
    non-deterministic model cannot support one.
Tokens and cost are reported only when the provider reported tokens (a fake model reports none) and, for cost, only when the plan carries a pricing record; nothing is estimated.
"""
import numpy as np
import pandas as pd

import eval_metrics as em
import evaluate as ev

from .data import canonical

SCALARS = {
    "raw_detector": [("precision", ["verdict", "valid_only", "detector", "precision", "value"]), ("recall", ["verdict", "valid_only", "detector", "recall", "value"]),
                     ("f1", ["verdict", "valid_only", "detector", "f1"]), ("specificity", ["verdict", "valid_only", "detector", "specificity", "value"]),
                     ("false_positives", ["verdict", "valid_only", "detector_confusion", "fp"]), ("false_negatives", ["verdict", "valid_only", "detector_confusion", "fn"])],
}
MODEL_SCALARS = [("false_positive_rate", ["error_rates", "false_positive_rate", "value"]), ("false_negative_rate", ["error_rates", "false_negative_rate", "value"]),
                 ("false_negatives_valid_only", ["error_rates", "fn"]), ("alerts_needing_a_retry", ["retries", "alerts_needing_a_retry"]), ("model_calls_total", ["retries", "model_calls_total"]),
                 ("precision_valid_only", ["verdict", "valid_only", "llm", "precision", "value"]), ("recall_valid_only", ["verdict", "valid_only", "llm", "recall", "value"]),
                 ("f1_valid_only", ["verdict", "valid_only", "llm", "f1"]), ("specificity_valid_only", ["verdict", "valid_only", "llm", "specificity", "value"]),
                 ("precision_failures_wrong", ["verdict", "failures_wrong", "llm", "precision", "value"]), ("recall_failures_wrong", ["verdict", "failures_wrong", "llm", "recall", "value"]),
                 ("f1_failures_wrong", ["verdict", "failures_wrong", "llm", "f1"]), ("recall_failures_escalated", ["verdict", "failures_escalated", "llm", "recall", "value"]),
                 ("fp_reduction_pct_failures_escalated", ["fp_reduction", "failures_escalated", "fp_reduction_pct"]), ("attacks_missed_failures_escalated", ["fp_reduction", "failures_escalated", "attacks_missed_by_llm"]),
                 ("attack_type_accuracy_on_valid_attacks", ["attack_type", "on_attacks_with_valid_verdict", "value"]), ("mitre_accuracy", ["mitre", "accepted_all_attacks_failures_wrong", "value"]),
                 ("verdict_coverage", ["reliability", "successful_verdict_coverage", "value"]), ("final_parse_failure_rate", ["reliability", "final_parse_failure", "value"]),
                 ("model_error_rate", ["reliability", "model_error", "value"]), ("latency_median_s", ["latency", "per_alert_all_observations", "median"]),
                 ("latency_p95_s", ["latency", "per_alert_all_observations", "p95"]), ("throughput_alerts_per_s", ["throughput", "alerts_per_second"]),
                 ("total_tokens", ["tokens", "total_tokens"])]
FULL_SCALARS = [("auto_close_rate", ["routing", "auto_close_rate", "value"]), ("review_queue_rate", ["routing", "review_queue_rate_escalate_or_needs_review", "value"]),
                ("attacks_auto_closed_rate", ["routing", "true_attacks_auto_closed", "value"]), ("attacks_auto_closed_count", ["routing", "true_attacks_auto_closed", "numerator"]),
                ("benign_in_review_queue_rate", ["routing", "true_benign_in_review_queue", "value"])]


def dig(d, path):
    for key in path:
        if not isinstance(d, dict) or key not in d:
            return None
        d = d[key]
    return d


def scalars_for(config):
    return SCALARS["raw_detector"] if config == "raw_detector" else MODEL_SCALARS + (FULL_SCALARS if config == "full_system" else [])


def build_df(run, data):
    latest = {r["alert_id"]: r for r in run.records}
    ev.check_inputs(data.alerts, data.labels, latest, run.meta.get("threshold"), False)       # the Week 2 checks, unchanged
    df = ev.build_table(data.alerts, data.labels, latest, False)
    if run.config == "full_system":
        df["routing"] = [((latest[a].get("routing") or {}).get("decision") or "no_routing") for a in df["alert_id"]]
    return df, latest


def failure_breakdown(run, df):
    n = len(df)
    kinds = {}
    for r in run.records:
        kinds[r["failure_kind"]] = kinds.get(r["failure_kind"], 0) + 1
    valid = df[df["has_verdict"]]
    wrong_flag = int(((valid["pred_malicious"] == True) != valid["is_attack"]).sum())       # noqa: E712
    return {"alerts": n, "no_verdict_system_failures": {"parse_failure": kinds.get("parse_failure", 0), "model_unavailable": kinds.get("model_unavailable", 0), "system_error": kinds.get("system_error", 0)},
            "valid_verdicts": int(len(valid)), "classification_errors_among_valid_verdicts": wrong_flag,
            "of_which_false_positives": int(((valid["pred_malicious"] == True) & ~valid["is_attack"]).sum()),     # noqa: E712
            "of_which_false_negatives": int(((valid["pred_malicious"] == False) & valid["is_attack"]).sum()),     # noqa: E712
            "note": "System failures (no verdict) are never counted as classification errors here. Their effect on precision and recall is shown separately by the three no-verdict policies."}


def throughput(run, latest):
    walls = [r.get("wall_seconds") for r in run.records if r.get("wall_seconds") is not None]
    total = float(run.meta["wall_seconds"])
    return {"alerts": len(run.records), "run_wall_seconds": total, "alerts_per_second": (len(run.records) / total) if total > 0 else None,
            "per_alert_wall_median_s": float(np.median(walls)) if walls else None, "per_alert_wall_p95_s": float(np.percentile(walls, 95)) if walls else None, "concurrency": run.meta.get("concurrency")}


def rate(num, den):
    return {"numerator": int(num), "denominator": int(den), "value": (float(num) / den) if den else None}


def error_rates(df):
    """Binary errors among alerts that received a valid verdict. A missing verdict is NOT counted here (see failure_breakdown)."""
    valid = df[df["has_verdict"]]
    tp = int(((valid["pred_malicious"] == True) & valid["is_attack"]).sum())          # noqa: E712
    fp = int(((valid["pred_malicious"] == True) & ~valid["is_attack"]).sum())         # noqa: E712
    fn = int(((valid["pred_malicious"] == False) & valid["is_attack"]).sum())         # noqa: E712
    tn = int(((valid["pred_malicious"] == False) & ~valid["is_attack"]).sum())        # noqa: E712
    return {"valid_verdicts": int(len(valid)), "tp": tp, "fp": fp, "fn": fn, "tn": tn, "false_positive_rate": rate(fp, fp + tn), "false_negative_rate": rate(fn, fn + tp),
            "missed_attack_alert_ids": sorted(valid.loc[(valid["pred_malicious"] == False) & valid["is_attack"], "alert_id"].tolist())}      # noqa: E712


def per_class(df):
    """One row per TRUE class: how many alerts, how many the verdict called malicious, how often the attack type was exactly right, how many had no verdict and, for the full system, how each was routed."""
    out = {}
    for label, g in df.groupby("label", sort=True):
        valid = g[g["has_verdict"]]
        row = {"support": int(len(g)), "is_attack_class": bool(g["is_attack"].iloc[0]), "no_verdict": int((~g["has_verdict"]).sum()), "valid_verdicts": int(len(valid)),
               "called_malicious": int((valid["pred_malicious"] == True).sum()),         # noqa: E712
               "called_benign": int((valid["pred_malicious"] == False).sum())}          # noqa: E712
        if row["is_attack_class"]:
            row["recall_valid_only"] = rate(row["called_malicious"], row["valid_verdicts"])
            row["attack_type_exact"] = rate(int((valid["pred_attack_type"] == label).sum()), row["valid_verdicts"])
        else:
            row["specificity_valid_only"] = rate(row["called_benign"], row["valid_verdicts"])
        if "routing" in g.columns:
            row["routing"] = {k: int(v) for k, v in g["routing"].value_counts().items()}
        out[str(label)] = row
    return out


def retry_summary(df, run):
    attempts = df["attempts"].dropna()
    calls = df["model_calls"].dropna()
    return {"attempts_total": int(attempts.sum()) if len(attempts) else None, "model_calls_total": int(calls.sum()) if len(calls) else None,
            "alerts_needing_a_retry": int((attempts > 1).sum()) if len(attempts) else None, "malformed_first_try": int(df["malformed_first_try"].fillna(False).astype(bool).sum()),
            "note": "attempts count the parse retries the plan allows; they are not infrastructure retries (those are job attempts, measured by the load tests)."}


def run_metrics(run, data, pricing=None):
    df, latest = build_df(run, data)
    if run.config == "raw_detector":
        m = {"population": em.population_counts(df), "verdict": em.verdict_metrics(df)}
    else:
        m = em.build_metrics(df, ev.CLASSES, None)
        if run.meta.get("fake_model"):
            m["cost"] = {"available": False, "reason": "a fake model reports no tokens, so no cost exists"}
        elif pricing is not None:
            m["cost"] = em.cost(m["tokens"], pricing)
        else:
            m["cost"] = {"available": False, "reason": "the plan has no pricing record; no price is assumed"}
        if run.config == "full_system":
            import week4.evaluate_memory as wm
            m["routing"] = wm.routing_metrics(df)
            m["guard_signals"] = {}
            for r in run.records:
                for s in r.get("guard_signals") or []:
                    m["guard_signals"][s] = m["guard_signals"].get(s, 0) + 1
    m["failure_breakdown"] = failure_breakdown(run, df)
    if run.config != "raw_detector":
        m["error_rates"] = error_rates(df)
        m["per_class"] = per_class(df)
        m["retries"] = retry_summary(df, run)
    m["throughput"] = throughput(run, latest)
    m["run"] = {"run_id": run.meta["run_id"], "run_index": run.index, "started_utc": run.meta["started_utc"], "finished_utc": run.meta["finished_utc"], "fake_model": bool(run.meta.get("fake_model"))}
    return m, df


def spread(values):
    vals = [v for v in values if v is not None]
    if not vals:
        return {"n": 0, "mean": None, "min": None, "max": None, "range": None, "values": list(values)}
    return {"n": len(vals), "mean": float(np.mean(vals)), "min": float(min(vals)), "max": float(max(vals)), "range": float(max(vals) - min(vals)), "values": list(values)}


def verdict_agreement(dfs):
    """How many alerts received the same malicious / benign / no-verdict outcome in every run of one configuration."""
    if len(dfs) < 2:
        return None
    key = pd.DataFrame({i: df["pred_malicious"].map(lambda v: "none" if v is None or (isinstance(v, float) and np.isnan(v)) else str(bool(v))) for i, df in enumerate(dfs)})
    changed = int((key.nunique(axis=1) > 1).sum())
    return {"alerts": int(len(key)), "alerts_with_a_different_outcome_in_some_run": changed, "alerts_identical_in_all_runs": int(len(key) - changed),
            "share_identical": (len(key) - changed) / len(key) if len(key) else None}


def config_summary(config, per_run, dfs):
    out = {"runs": len(per_run), "scalars": {name: spread([dig(m, path) for m in per_run]) for name, path in scalars_for(config)}, "verdict_agreement_across_runs": verdict_agreement(dfs)}
    if config == "full_system":
        out["attacks_auto_closed_alert_ids_per_run"] = [dig(m, ["routing", "auto_closed_attack_alert_ids"]) for m in per_run]
    return out


def compute_all(plan, runs, data):
    """runs: the LoadedRun dict from validate_runs (all valid). -> {"per_run": {key: metrics}, "per_config": {config: summary}}."""
    per_run, per_config = {}, {}
    for config in plan["configs"]:
        ms, dfs = [], []
        for i in range(1, plan["runs_per_config"] + 1):
            run = runs["%s/run%d" % (config, i)]
            m, df = run_metrics(run, data, plan.get("pricing"))
            per_run[run.key] = m
            ms.append(m)
            dfs.append(df)
        per_config[config] = config_summary(config, ms, dfs)
    return {"per_run": per_run, "per_config": per_config}
