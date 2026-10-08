"""Week 2 Day 6: mean, spread and cross-run error analysis for the three locked-baseline DEV runs.

It reads only what the Day 4 evaluator already wrote for each run (evaluation.json and per_alert.csv) and each run's run_meta.json.
It reads no label file, no MITRE answer key and no frozen file, imports none of the label or evaluation modules, calls no model,
and writes only into its own output folder (default reports/week2_day6). It re-hashes every input file at the end and says so
if any changed.

  python src/day6_aggregate.py                      the three default runs, Day 5 final run as an extra reference column
  python src/day6_aggregate.py --no-reference

How the numbers are made (also written into the report):
  mean       arithmetic mean of the run values
  sd         sample standard deviation, n-1 in the denominator (n = 3 runs, so a crude estimate)
  min, max   smallest and largest run value;  range = max - min
Percent metrics are shown as percent and the sd and range as percentage points.

Per-alert error kinds (an alert counts toward a kind only in runs where it was evaluable):
  false_positive     true benign alert called malicious        (benign alerts, runs with a valid verdict)
  missed_attack      true attack called benign                 (attacks, runs with a valid verdict)
  attack_type_error  true attack, predicted attack_type is not the true class
  mitre_error        true attack, predicted technique is not an accepted id (the Day 4 column mitre_accepted)
  no_verdict         the alert ended in parse_failed or model_error
With k = runs in which the error occurred and m = runs in which the alert was evaluable:
  k = 0                 never wrong
  k = m (m >= 2)        persistent: wrong every time it could be judged
  k = 1 (m >= 2)        one-off: wrong in a single run only
  1 < k < m             recurring: wrong in some runs, not all
  m < 2                 insufficient: fewer than two judgeable runs, no pattern claimed
Nothing here changes a prompt, the parser or the schema; the analysis only describes.
"""
import os
import sys
import json
import math
import hashlib
import argparse
import datetime
import itertools
import collections

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RUNS = ["dev_flash_lite_v3_d6_rep1", "dev_flash_lite_v3_d6_rep2", "dev_flash_lite_v3_d6_rep3"]
DEFAULT_REFERENCE = "dev_flash_lite_v3_final"
DEFAULT_EVAL_ROOT = os.path.join(ROOT, "reports", "week2_eval")
DEFAULT_RUNS_ROOT = os.path.join(ROOT, "runs", "week2_baseline_v1")
DEFAULT_OUT = os.path.join(ROOT, "reports", "week2_day6")
POLICIES = ["valid_only", "failures_escalated", "failures_wrong"]
KINDS = ["false_positive", "missed_attack", "attack_type_error", "mitre_error", "no_verdict"]
CATEGORIES = ["never", "persistent", "recurring", "one_off", "insufficient"]
REPORT_NAME = "DAY6_THREE_RUN_REPORT.md"
OUTPUT_FILES = [REPORT_NAME, "three_run_metrics.csv", "three_run_summary.json", "per_alert_across_runs.csv", "error_patterns.csv"]


class AggregateError(Exception):
    pass


# ------------------------------------------------------------------------------------------------ small helpers
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def get_path(obj, path):
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            return None
        obj = obj[key]
    return obj


def mean_sd(values):
    n = len(values)
    mean = sum(values) / n
    sd = math.sqrt(sum((v - mean) ** 2 for v in values) / (n - 1)) if n > 1 else None
    return mean, sd


def stats_for(values):
    """Summary of the run values of one metric. Missing values (None) are left out and counted."""
    present = [v for v in values if v is not None]
    out = {"values": list(values), "n_present": len(present), "mean": None, "sd": None, "min": None, "max": None, "range": None}
    if present:
        out["mean"], out["sd"] = mean_sd(present)
        out["min"], out["max"] = min(present), max(present)
        out["range"] = out["max"] - out["min"]
    return out


def tf(value):
    text = str(value).strip().lower()
    if text in ("true", "1", "1.0"):
        return True
    if text in ("false", "0", "0.0"):
        return False
    return None


# ------------------------------------------------------------------------------------------------ headline metrics
def metric_specs():
    """(key, label, path in evaluation.json, unit). unit: frac (stored 0-1, shown as %), pct (stored 0-100), count, tokens, seconds, number."""
    specs = [
        ("coverage", "Successful verdict coverage", ("metrics", "reliability", "successful_verdict_coverage", "value"), "frac"),
        ("final_parse_failure", "Final parse-failure rate", ("metrics", "reliability", "final_parse_failure", "value"), "frac"),
        ("final_parse_failure_n", "Final parse failures (alerts)", ("metrics", "reliability", "final_parse_failure", "numerator"), "count"),
        ("first_try_malformed", "First-try malformed rate", ("metrics", "reliability", "first_try_malformed_of_all_alerts", "value"), "frac"),
        ("model_error_n", "Model errors (alerts)", ("metrics", "reliability", "model_error", "numerator"), "count"),
    ]
    for p in POLICIES:
        specs += [
            ("precision_" + p, "Precision [" + p + "]", ("metrics", "verdict", p, "llm", "precision", "value"), "frac"),
            ("recall_" + p, "Recall [" + p + "]", ("metrics", "verdict", p, "llm", "recall", "value"), "frac"),
            ("f1_" + p, "F1 [" + p + "]", ("metrics", "verdict", p, "llm", "f1"), "number"),
            ("specificity_" + p, "Specificity (benign dismissed) [" + p + "]", ("metrics", "verdict", p, "llm", "specificity", "value"), "frac"),
            ("fp_reduction_" + p, "FP reduction [" + p + "]", ("metrics", "fp_reduction", p, "fp_reduction_pct"), "pct"),
            ("attacks_missed_" + p, "Attacks missed by the LLM [" + p + "]", ("metrics", "fp_reduction", p, "attacks_missed_by_llm"), "count"),
        ]
    specs += [
        ("attack_type_valid", "Attack-type accuracy (attacks with a valid verdict)", ("metrics", "attack_type", "on_attacks_with_valid_verdict", "value"), "frac"),
        ("attack_type_all", "Attack-type accuracy (all attacks, no-verdict = wrong)", ("metrics", "attack_type", "all_attacks_failures_wrong", "value"), "frac"),
        ("mitre_valid", "MITRE accepted accuracy (attacks with a valid verdict)", ("metrics", "mitre", "accepted_on_attacks_with_valid_verdict", "value"), "frac"),
        ("mitre_all", "MITRE accepted accuracy (all attacks, no-verdict = wrong)", ("metrics", "mitre", "accepted_all_attacks_failures_wrong", "value"), "frac"),
        ("model_calls_total", "Model calls", ("metrics", "reliability", "model_calls_total"), "count"),
        ("model_calls_per_alert", "Model calls per alert", ("metrics", "reliability", "model_calls_per_alert_mean"), "number"),
        ("total_tokens", "Total tokens", ("metrics", "tokens", "total_tokens"), "tokens"),
        ("prompt_tokens", "Prompt tokens", ("metrics", "tokens", "prompt_tokens"), "tokens"),
        ("output_tokens", "Output tokens", ("metrics", "tokens", "output_tokens"), "tokens"),
        ("thinking_tokens", "Thinking tokens", ("metrics", "tokens", "thinking_tokens"), "tokens"),
        ("latency_alert_mean", "Latency per alert, mean (s)", ("metrics", "latency", "per_alert_all_observations", "mean"), "seconds"),
        ("latency_alert_median", "Latency per alert, median (s)", ("metrics", "latency", "per_alert_all_observations", "median"), "seconds"),
        ("latency_alert_p95", "Latency per alert, p95 (s)", ("metrics", "latency", "per_alert_all_observations", "p95"), "seconds"),
        ("latency_alert_max", "Latency per alert, max (s)", ("metrics", "latency", "per_alert_all_observations", "max"), "seconds"),
        ("latency_call_mean", "Latency per call, mean (s)", ("metrics", "latency", "per_call_all_observations", "mean"), "seconds"),
        ("latency_call_max", "Latency per call, max (s)", ("metrics", "latency", "per_call_all_observations", "max"), "seconds"),
    ]
    return specs


def display_value(value, unit):
    if value is None:
        return "n/a"
    if unit == "frac":
        return format(value * 100, ".2f") + "%"
    if unit == "pct":
        return format(value, ".2f") + "%"
    if unit == "count":
        return format(value, ",.2f").rstrip("0").rstrip(".") if isinstance(value, float) and value != int(value) else format(int(round(value)), ",")
    if unit == "tokens":
        return format(int(round(value)), ",")
    if unit == "seconds":
        return format(value, ".3f")
    return format(value, ".4f")


def display_spread(value, unit):
    """sd and range: percentage points for fractions."""
    if value is None:
        return "n/a"
    if unit == "frac":
        return format(value * 100, ".2f") + " pp"
    if unit == "pct":
        return format(value, ".2f") + " pp"
    return display_value(value, unit)


def headline_table(evals, ref_eval=None):
    rows = []
    for key, label, path, unit in metric_specs():
        values = [get_path(e, path) for e in evals]
        row = {"key": key, "label": label, "unit": unit, "ref": get_path(ref_eval, path) if ref_eval is not None else None}
        row.update(stats_for(values))
        rows.append(row)
    return rows


# ------------------------------------------------------------------------------------------------ loading and checks
def load_run(name, eval_root, runs_root):
    eval_dir = os.path.join(eval_root, name)
    paths = {"evaluation.json": os.path.join(eval_dir, "evaluation.json"), "per_alert.csv": os.path.join(eval_dir, "per_alert.csv"),
             "run_meta.json": os.path.join(runs_root, name, "run_meta.json")}
    for label, path in paths.items():
        if not os.path.exists(path):
            raise AggregateError("missing " + label + " for run " + name + ": " + path
                                 + (". Run python src/evaluate.py --run-name " + name if label != "run_meta.json" else ""))
    with open(paths["evaluation.json"], "r", encoding="utf-8") as f:
        evaluation = json.load(f)
    with open(paths["run_meta.json"], "r", encoding="utf-8") as f:
        meta = json.load(f)
    frame = pd.read_csv(paths["per_alert.csv"], dtype=str, keep_default_na=False)
    return {"name": name, "evaluation": evaluation, "meta": meta, "per_alert": frame, "paths": paths}


def check_runs(runs, expected_sha=None):
    """Return a list of problems. An empty list means the three runs are comparable."""
    problems = []
    if len(runs) < 2:
        problems.append("at least two runs are needed")
    first = runs[0]
    for r in runs:
        ev, meta = r["evaluation"], r["meta"]
        integ = ev.get("integrity", {})
        for key in ("run_unchanged", "protected_unchanged", "frozen_log_unchanged"):
            if integ.get(key) is not True:
                problems.append(r["name"] + ": evaluation integrity check '" + key + "' is not True")
        if ev.get("allow_partial"):
            problems.append(r["name"] + ": evaluated with --allow-partial; every run must be complete")
        if meta.get("status") != "complete":
            problems.append(r["name"] + ": run status is '" + str(meta.get("status")) + "', not complete")
        if meta.get("set") != "dev":
            problems.append(r["name"] + ": run set is '" + str(meta.get("set")) + "', not dev")
        if meta.get("frozen_access_log_unchanged") is not True or meta.get("week1_files_unchanged") is not True:
            problems.append(r["name"] + ": the run recorded a changed frozen access log or Week 1 file")
        if get_path(ev, ("metrics", "population", "alerts")) != len(meta.get("selected_alert_ids", [])):
            problems.append(r["name"] + ": evaluated population differs from the run's alert list")
        if meta.get("prompt_version") != "baseline_v3":
            problems.append(r["name"] + ": prompt version is '" + str(meta.get("prompt_version")) + "', not baseline_v3")
        if expected_sha and meta.get("prompt_sha256") != expected_sha:
            problems.append(r["name"] + ": prompt hash differs from the expected hash")
        if get_path(meta, ("langsmith", "payload_policy")) not in (None, "metadata_only"):
            problems.append(r["name"] + ": tracing was not metadata-only")
    for r in runs[1:]:
        for label, getter in [("prompt hash", lambda m: m.get("prompt_sha256")), ("model", lambda m: m.get("model")),
                              ("settings", lambda m: {k: v for k, v in (m.get("settings") or {}).items() if k != "requests_per_minute"}),
                              ("inputs", lambda m: m.get("inputs")), ("alert list", lambda m: m.get("selected_alert_ids"))]:
            if getter(r["meta"]) != getter(first["meta"]):
                problems.append(r["name"] + ": " + label + " differs from " + first["name"])
        if r["evaluation"].get("protected_file_sha256") != first["evaluation"].get("protected_file_sha256"):
            problems.append(r["name"] + ": the protected evaluation files differ from " + first["name"])
        a, b = first["per_alert"], r["per_alert"]
        if list(a["alert_id"]) != list(b["alert_id"]):
            problems.append(r["name"] + ": per_alert.csv lists different alerts than " + first["name"])
        elif list(a["label"]) != list(b["label"]):
            problems.append(r["name"] + ": per_alert.csv carries different true labels than " + first["name"])
    names = [r["name"] for r in runs]
    if len(set(names)) != len(names):
        problems.append("the same run was given twice")
    for r in runs:
        problems += reconcile(r)
    return problems


def reconcile(run):
    """Cross-check the counts rebuilt from per_alert.csv against the numbers the Day 4 evaluator wrote. A mismatch means this script
    and the evaluator disagree about the data, so no cross-run analysis is trusted. Checks are skipped for values the evaluation lacks."""
    problems = []
    ev, frame = run["evaluation"], run["per_alert"]
    is_attack = frame["is_attack"].map(lambda v: tf(v) is True)
    has_verdict = frame["has_verdict"].map(lambda v: tf(v) is True)
    mal = frame["pred_malicious"].map(lambda v: tf(v) is True)
    ben = frame["pred_malicious"].map(lambda v: tf(v) is False)
    valid_attacks = is_attack & has_verdict
    derived = {
        ("metrics", "verdict", "valid_only", "llm_confusion", "fp"): int((~is_attack & has_verdict & mal).sum()),
        ("metrics", "verdict", "valid_only", "llm_confusion", "fn"): int((is_attack & has_verdict & ben).sum()),
        ("metrics", "verdict", "valid_only", "llm_confusion", "tp"): int((is_attack & has_verdict & mal).sum()),
        ("metrics", "verdict", "valid_only", "llm_confusion", "tn"): int((~is_attack & has_verdict & ben).sum()),
        ("metrics", "attack_type", "on_attacks_with_valid_verdict", "denominator"): int(valid_attacks.sum()),
        ("metrics", "attack_type", "on_attacks_with_valid_verdict", "numerator"): int((valid_attacks & (frame["pred_attack_type"] == frame["label"])).sum()),
        ("metrics", "mitre", "accepted_on_attacks_with_valid_verdict", "numerator"): int((valid_attacks & frame["mitre_accepted"].map(lambda v: tf(v) is True)).sum()),
        ("metrics", "population", "ok"): int((frame["status"] == "ok").sum()),
    }
    for path, value in derived.items():
        expected = get_path(ev, path)
        if expected is not None and expected != value:
            problems.append(run["name"] + ": per_alert.csv gives " + str(value) + " but evaluation.json says " + str(expected) + " for " + "/".join(path[1:]))
    return problems


# ------------------------------------------------------------------------------------------------ per-alert analysis
def build_alert_rows(runs):
    """One dict per alert with each run's outcome and the error flags per kind."""
    k = len(runs)
    frames = [{row["alert_id"]: row for row in r["per_alert"].to_dict("records")} for r in runs]
    rows = []
    for alert_id in list(runs[0]["per_alert"]["alert_id"]):
        base = frames[0][alert_id]
        is_attack = tf(base["is_attack"]) is True
        item = {"alert_id": alert_id, "label": base["label"], "is_attack": is_attack, "runs": []}
        for i in range(k):
            row = frames[i][alert_id]
            has_verdict = tf(row["has_verdict"]) is True
            malicious = tf(row["pred_malicious"]) if has_verdict else None
            pred_type = row["pred_attack_type"] if has_verdict else None
            tech = row["pred_technique"] if has_verdict else None
            item["runs"].append({
                "status": row["status"], "has_verdict": has_verdict, "decision": None if malicious is None else ("malicious" if malicious else "benign"),
                "pred_type": pred_type, "pred_technique": tech, "first_try_error": row.get("first_try_error", ""), "error_code": row.get("error_code", ""),
                "type_correct": (pred_type == base["label"]) if (has_verdict and is_attack) else None,
                "mitre_accepted": tf(row["mitre_accepted"]) if (has_verdict and is_attack) else None,
            })
        item["flags"] = {}
        for kind in KINDS:
            evaluable, errors = [], []
            for run in item["runs"]:
                if kind == "no_verdict":
                    evaluable.append(True)
                    errors.append(not run["has_verdict"])
                    continue
                if not run["has_verdict"]:
                    continue
                if kind == "false_positive":
                    if is_attack:
                        continue
                    evaluable.append(True)
                    errors.append(run["decision"] == "malicious")
                elif kind == "missed_attack":
                    if not is_attack:
                        continue
                    evaluable.append(True)
                    errors.append(run["decision"] == "benign")
                elif kind == "attack_type_error":
                    if not is_attack:
                        continue
                    evaluable.append(True)
                    errors.append(run["type_correct"] is False)
                elif kind == "mitre_error":
                    if not is_attack:
                        continue
                    evaluable.append(True)
                    errors.append(run["mitre_accepted"] is False)
            if kind in ("false_positive",) and is_attack or kind in ("missed_attack", "attack_type_error", "mitre_error") and not is_attack:
                item["flags"][kind] = None
                continue
            item["flags"][kind] = {"m": len(evaluable), "k": sum(errors)}
        rows.append(item)
    return rows


def categorize(k, m):
    if m < 2:
        return "insufficient"
    if k == 0:
        return "never"
    if k == m:
        return "persistent"
    if k == 1:
        return "one_off"
    return "recurring"


def category_counts(rows):
    table = {}
    for kind in KINDS:
        counts = collections.Counter()
        applicable = 0
        for item in rows:
            flag = item["flags"][kind]
            if flag is None:
                continue
            applicable += 1
            counts[categorize(flag["k"], flag["m"])] += 1
        table[kind] = {"applicable_alerts": applicable, **{c: counts.get(c, 0) for c in CATEGORIES}}
        table[kind]["any_error"] = sum(table[kind][c] for c in ("persistent", "recurring", "one_off"))
    return table


def stochastic_variation(rows, n_runs):
    """How often the runs disagree with each other, whatever the truth is."""
    out = collections.Counter()
    out["alerts"] = len(rows)
    pair_same = {"decision": [0, 0], "attack_type": [0, 0], "technique": [0, 0]}
    for item in rows:
        runs = item["runs"]
        valid = [r for r in runs if r["has_verdict"]]
        if len({r["status"] for r in runs}) > 1:
            out["status_differs"] += 1
        if len(valid) >= 2:
            out["alerts_with_2plus_valid"] += 1
            d = len({r["decision"] for r in valid}) > 1
            t = len({r["pred_type"] for r in valid}) > 1
            q = len({r["pred_technique"] for r in valid}) > 1
            out["decision_differs"] += d
            out["attack_type_differs"] += t
            out["technique_differs"] += q
            out["any_field_differs"] += (d or t or q)
        for a, b in itertools.combinations(valid, 2):
            for name, key in (("decision", "decision"), ("attack_type", "pred_type"), ("technique", "pred_technique")):
                pair_same[name][1] += 1
                pair_same[name][0] += (a[key] == b[key])
        if sum(r["first_try_error"] != "" for r in runs) in (1, 2):
            out["first_try_malformed_in_some_runs_only"] += 1
    result = dict(out)
    result["pairwise_agreement"] = {k: (v[0] / v[1] if v[1] else None) for k, v in pair_same.items()}
    return result


def persistent_detail(rows):
    """Patterns inside the persistent errors: which classes, which wrong answers, and whether the wrong answer repeats."""
    per_class = collections.OrderedDict()
    confusions = collections.Counter()
    consistent_type = collections.Counter()
    mitre_split = collections.Counter()
    technique_choices = collections.Counter()
    for item in rows:
        if not item["is_attack"]:
            continue
        cls = per_class.setdefault(item["label"], {"attacks": 0, "never": 0, "persistent": 0, "recurring": 0, "one_off": 0, "insufficient": 0})
        flag = item["flags"]["attack_type_error"]
        cls["attacks"] += 1
        cat = categorize(flag["k"], flag["m"])
        cls[cat] += 1
        valid = [r for r in item["runs"] if r["has_verdict"]]
        if cat == "persistent":
            wrong = {r["pred_type"] for r in valid}
            consistent_type["same wrong type every run" if len(wrong) == 1 else "different wrong types across runs"] += 1
            for w in wrong:
                confusions[(item["label"], w)] += 1
        mflag = item["flags"]["mitre_error"]
        if categorize(mflag["k"], mflag["m"]) == "persistent":
            type_ok_all = all(r["type_correct"] for r in valid)
            mitre_split["technique wrong while attack type right in every run" if type_ok_all else "technique wrong and attack type wrong in at least one run"] += 1
            technique_choices[(item["label"], tuple(sorted({r["pred_technique"] for r in valid})))] += 1
    return {"per_class": per_class, "persistent_confusions": confusions, "persistent_type_consistency": consistent_type,
            "persistent_mitre_split": mitre_split, "persistent_mitre_choices": technique_choices}


def error_pattern_rows(rows):
    out = []
    for item in rows:
        for kind in KINDS:
            flag = item["flags"][kind]
            if flag is None or flag["k"] == 0:
                continue
            row = {"alert_id": item["alert_id"], "true_label": item["label"], "kind": kind, "runs_with_error": flag["k"],
                   "runs_evaluable": flag["m"], "category": categorize(flag["k"], flag["m"])}
            for i, run in enumerate(item["runs"], start=1):
                row["run%d_status" % i] = run["status"]
                row["run%d_decision" % i] = run["decision"] or ""
                row["run%d_attack_type" % i] = run["pred_type"] or ""
                row["run%d_technique" % i] = run["pred_technique"] or ""
                row["run%d_error_code" % i] = run["error_code"] or ""
            out.append(row)
    return out


def per_alert_table(rows):
    out = []
    for item in rows:
        row = {"alert_id": item["alert_id"], "true_label": item["label"], "is_attack": item["is_attack"]}
        for i, run in enumerate(item["runs"], start=1):
            row["run%d_status" % i] = run["status"]
            row["run%d_decision" % i] = run["decision"] or ""
            row["run%d_attack_type" % i] = run["pred_type"] or ""
            row["run%d_technique" % i] = run["pred_technique"] or ""
            row["run%d_first_try_error" % i] = run["first_try_error"]
            row["run%d_error_code" % i] = run["error_code"]
        for kind in KINDS:
            flag = item["flags"][kind]
            row[kind + "_category"] = "n/a" if flag is None else categorize(flag["k"], flag["m"])
            row[kind + "_k_of_m"] = "" if flag is None else str(flag["k"]) + "/" + str(flag["m"])
        out.append(row)
    return out


def parse_failure_detail(rows, runs):
    """Which alerts failed to parse, in how many runs, and the first-try problems that were recovered."""
    failed = [it for it in rows if it["flags"]["no_verdict"]["k"] > 0]
    by_count = collections.Counter(it["flags"]["no_verdict"]["k"] for it in failed)
    codes = collections.Counter()
    for it in failed:
        for run in it["runs"]:
            if not run["has_verdict"]:
                codes[run["error_code"] or run["status"]] += 1
    first_try = collections.Counter()
    for it in rows:
        n_bad = sum(1 for r in it["runs"] if r["first_try_error"] != "")
        first_try[n_bad] += 1
    return {"alerts_failed_in_at_least_one_run": len(failed), "failed_in_k_runs": dict(sorted(by_count.items())),
            "final_error_codes": dict(codes), "alerts_by_number_of_runs_with_first_try_problem": dict(sorted(first_try.items()))}


# ------------------------------------------------------------------------------------------------ report
def md_table(header, rows):
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"] * len(header)) + "|"]
    for r in rows:
        lines.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(lines)


def render_report(analysis):
    a = analysis
    names = a["run_names"]
    n = len(names)
    L = []
    add = L.append
    add("# Week 2, Day 6: three DEV runs of the locked baseline (baseline_v3)")
    add("")
    add("Generated " + a["generated_utc"] + " by `src/day6_aggregate.py`. DEV set only. The frozen set was not used. "
        "Nothing was tuned from these runs: the prompt, parser and schema are the ones used for the first run.")
    add("")
    add("## 1. What was run")
    add("")
    add("- Prompt: `" + a["prompt_version"] + "`, sha256 `" + str(a["prompt_sha256"]) + "`")
    add("- Model: `" + str(a["model"]) + "`; settings identical in every run: " + json.dumps(a["settings"], sort_keys=True))
    add("- Alerts: " + str(a["n_alerts"]) + " DEV alerts (" + str(a["n_attacks"]) + " true attacks, " + str(a["n_benign"]) + " true benign), the same list in every run")
    add("- Runs: " + ", ".join("`" + x + "`" for x in names))
    add("- Every run was scored with the Day 4 evaluator and passed its integrity checks (run files, protected files and frozen access log unchanged).")
    if a["reference_name"]:
        add("- Reference column: `" + a["reference_name"] + "` (the Day 5 run). It is shown for comparison only and is **not** in the mean or spread. "
            "baseline_v3 was chosen after looking at that run's dev results, so it is not an independent confirmation.")
    add("")
    add("**What the spread means.** The settings are identical (temperature and seed are fixed), so the differences between runs show only how much the "
        "model service varies when asked the same thing again. They do not measure how sensitive the result is to the prompt, and they say nothing about "
        "sampling uncertainty from having only " + str(a["n_alerts"]) + " alerts; the Wilson intervals in each run's evaluation report cover that. "
        "With " + str(n) + " runs the standard deviation is a rough estimate, so the minimum and maximum are shown too.")
    add("")
    add("## 2. Results per run, mean and spread")
    add("")
    add("mean = arithmetic mean of the " + str(n) + " runs; sd = sample standard deviation (n-1); range = max - min. Percent metrics: sd and range in percentage points.")
    add("")
    header = ["Metric"] + names + ["mean", "sd", "min", "max", "range"] + (["reference"] if a["reference_name"] else [])
    groups = [("Reliability", ["coverage", "final_parse_failure", "final_parse_failure_n", "first_try_malformed", "model_error_n"]),
              ("Detector-relative verdict quality, valid verdicts only (primary)", [k + "_valid_only" for k in ("precision", "recall", "f1", "specificity", "fp_reduction", "attacks_missed")]),
              ("Failures escalated (an alert with no verdict stays raised)", [k + "_failures_escalated" for k in ("precision", "recall", "f1", "specificity", "fp_reduction", "attacks_missed")]),
              ("Failures counted wrong (a failed alert is always an error)", [k + "_failures_wrong" for k in ("precision", "recall", "f1", "specificity", "fp_reduction", "attacks_missed")]),
              ("Attack type and MITRE", ["attack_type_valid", "attack_type_all", "mitre_valid", "mitre_all"]),
              ("Cost drivers", ["model_calls_total", "model_calls_per_alert", "total_tokens", "prompt_tokens", "output_tokens", "thinking_tokens"]),
              ("Latency (recorded call latencies; sleep gaps are not latency)", ["latency_alert_mean", "latency_alert_median", "latency_alert_p95", "latency_alert_max", "latency_call_mean", "latency_call_max"])]
    index = {r["key"]: r for r in a["headline"]}
    for title, keys in groups:
        add("### " + title)
        add("")
        rows = []
        for key in keys:
            r = index[key]
            u = r["unit"]
            row = [r["label"]] + [display_value(v, u) for v in r["values"]] + [display_value(r["mean"], u), display_spread(r["sd"], u), display_value(r["min"], u),
                                                                              display_value(r["max"], u), display_spread(r["range"], u)]
            if a["reference_name"]:
                row.append(display_value(r["ref"], u))
            rows.append(row)
        add(md_table(header, rows))
        add("")
    if a["missing_metrics"]:
        add("**Metrics that could not be read from at least one evaluation.json (shown as n/a, left out of the statistics):** " + ", ".join(a["missing_metrics"])
            + ". If a core metric is listed here, the evaluation.json layout differs from what this script expects; check the file before trusting the table.")
        add("")
    add("Notes on reading the table: on this dev set the detector alerts are 35% false alarms by construction, so precision is a property of the sample, "
        "and recall is relative to the detector (the detector raised every attack here). Specificity is the share of benign alerts the model dismissed. "
        "Cost is not computed in this report; use `python src/cost_tracking.py --run-name <run> --pricing-file pricing.json` with your own verified prices.")
    add("")
    add("## 3. Variation between the runs (stochastic)")
    add("")
    sv = a["variation"]
    add("Alerts where the runs disagree with each other, regardless of the truth. Among alerts with at least two valid verdicts (" + str(sv.get("alerts_with_2plus_valid", 0)) + "):")
    add("")
    add(md_table(["Disagreement", "Alerts", "Share of those alerts"], [
        ["is_malicious decision differs", sv.get("decision_differs", 0), pct_of(sv.get("decision_differs", 0), sv.get("alerts_with_2plus_valid", 0))],
        ["attack_type differs", sv.get("attack_type_differs", 0), pct_of(sv.get("attack_type_differs", 0), sv.get("alerts_with_2plus_valid", 0))],
        ["mitre_technique differs", sv.get("technique_differs", 0), pct_of(sv.get("technique_differs", 0), sv.get("alerts_with_2plus_valid", 0))],
        ["any of the three differs", sv.get("any_field_differs", 0), pct_of(sv.get("any_field_differs", 0), sv.get("alerts_with_2plus_valid", 0))],
    ]))
    add("")
    pw = sv["pairwise_agreement"]
    add("Pairwise agreement between two runs (mean over run pairs, alerts valid in both): decision " + fmt_frac(pw["decision"]) + ", attack_type "
        + fmt_frac(pw["attack_type"]) + ", technique " + fmt_frac(pw["technique"]) + ". Alerts whose final status differs between runs (ok in one, failed in another): "
        + str(sv.get("status_differs", 0)) + ". Alerts with a malformed first reply in some runs but not all: " + str(sv.get("first_try_malformed_in_some_runs_only", 0)) + ".")
    add("")
    add("## 4. Persistent, recurring and one-off errors")
    add("")
    add("Definitions are in the module docstring: k = runs with the error, m = runs in which the alert could be judged. "
        "**Persistent** = wrong every time it could be judged (m >= 2). **One-off** = wrong in one run only. **Recurring** = wrong in some runs, not all. "
        "Insufficient = fewer than two judgeable runs, no pattern claimed.")
    add("")
    cc = a["categories"]
    labels = {"false_positive": "False positive (benign called malicious)", "missed_attack": "Missed attack (attack called benign)",
              "attack_type_error": "Attack-type error (true attacks)", "mitre_error": "MITRE error (true attacks)", "no_verdict": "No verdict (parse failure or model error)"}
    add(md_table(["Error kind", "Alerts it applies to", "Persistent", "Recurring", "One-off", "Never wrong", "Insufficient", "Wrong in at least one run"],
                 [[labels[k], cc[k]["applicable_alerts"], cc[k]["persistent"], cc[k]["recurring"], cc[k]["one_off"], cc[k]["never"], cc[k]["insufficient"], cc[k]["any_error"]] for k in KINDS]))
    add("")
    pd_ = a["parse_failures"]
    add("### Parse failures across runs")
    add("")
    add("Alerts that ended without a verdict in at least one run: " + str(pd_["alerts_failed_in_at_least_one_run"]) + ". By number of runs in which they failed: "
        + (", ".join(str(k) + " run(s): " + str(v) for k, v in pd_["failed_in_k_runs"].items()) or "none") + ". Final error codes (run-alert pairs): "
        + (json.dumps(pd_["final_error_codes"], sort_keys=True) if pd_["final_error_codes"] else "none") + ". "
        "Alerts by number of runs with a malformed first reply: " + json.dumps(pd_["alerts_by_number_of_runs_with_first_try_problem"]) + ".")
    add("")
    det = a["persistent"]
    add("### Attack type, by true class")
    add("")
    add(md_table(["True class", "Attacks", "Never wrong", "Persistent", "Recurring", "One-off", "Insufficient"],
                 [[cls, v["attacks"], v["never"], v["persistent"], v["recurring"], v["one_off"], v["insufficient"]] for cls, v in det["per_class"].items()]))
    add("")
    top = det["persistent_confusions"].most_common(15)
    add("Most common wrong answers among persistent attack-type errors (true class -> predicted class: alerts):")
    add("")
    add(md_table(["True class", "Predicted class", "Alerts"], [[t, p, c] for (t, p), c in top]) if top else "None.")
    add("")
    add("When an attack-type error is persistent: " + (", ".join(str(v) + " alerts had the " + k for k, v in det["persistent_type_consistency"].items()) or "no persistent errors") + ".")
    add("")
    add("### MITRE")
    add("")
    add("Persistent MITRE errors: " + (", ".join(str(v) + " alerts: " + k for k, v in det["persistent_mitre_split"].items()) or "none") + ". "
        "A predicted technique counts as correct only if it is one of the accepted ids in the evaluation mapping, which is the evaluation contract, so "
        "a rejected technique is not necessarily wrong in an absolute sense.")
    add("")
    choices = det["persistent_mitre_choices"].most_common(12)
    if choices:
        add("Most common persistent technique choices (true class, technique(s) chosen every run: alerts):")
        add("")
        add(md_table(["True class", "Technique(s) chosen", "Alerts"], [[t, ", ".join(c), n_] for (t, c), n_ in choices]))
        add("")
    add("The per-alert detail is in `per_alert_across_runs.csv` and `error_patterns.csv`, so any row in this report can be traced to alert ids.")
    add("")
    add("## 5. Conclusions")
    add("")
    for line in a["conclusions"]:
        add("- " + line)
    add("")
    add("## 6. Limits")
    add("")
    for line in [
        "Three runs with identical settings measure repeatability of the service, not robustness to prompt changes or to new data.",
        "The dev set has " + str(a["n_alerts"]) + " alerts; per-class counts are small, so class-level patterns are indicative.",
        "Nothing in this report was used to change the prompt, parser or schema. Any change would be a new, separately evaluated version.",
        "No frozen-set number is in this report, and none should be inferred from it.",
        "Labels and the MITRE accepted ids reached this report only through the Day 4 evaluator outputs; they were never in a prompt or a trace.",
    ]:
        add("- " + line)
    add("")
    return "\n".join(L)


def pct_of(a, b):
    return "n/a" if not b else format(100.0 * a / b, ".1f") + "%"


def fmt_frac(v):
    return "n/a" if v is None else format(v * 100, ".1f") + "%"


def conclusions(a):
    out = []
    idx = {r["key"]: r for r in a["headline"]}

    def spread(key):
        r = idx[key]
        if r["mean"] is None:
            return None
        return r

    for key, text in [("f1_valid_only", "F1 (valid verdicts only)"), ("precision_valid_only", "precision (valid verdicts only)"),
                      ("recall_valid_only", "recall (valid verdicts only)"), ("fp_reduction_valid_only", "false-positive reduction (valid verdicts only)"),
                      ("attack_type_valid", "attack-type accuracy"), ("mitre_valid", "MITRE accepted accuracy"), ("final_parse_failure", "final parse-failure rate")]:
        r = spread(key)
        if r is None:
            continue
        u = r["unit"]
        if r["range"] == 0:
            out.append("The " + text + " was identical in all runs (" + display_value(r["mean"], u) + ").")
        else:
            out.append("The " + text + " averaged " + display_value(r["mean"], u) + " with a range of " + display_spread(r["range"], u) + " ("
                       + display_value(r["min"], u) + " to " + display_value(r["max"], u) + ").")
    cc = a["categories"]
    for kind, noun in [("attack_type_error", "an attack-type error"), ("mitre_error", "a MITRE error"), ("false_positive", "a false positive"), ("missed_attack", "a missed attack")]:
        c = cc[kind]
        if c["any_error"] == 0:
            out.append("No alert had " + noun + " in any run.")
            continue
        out.append("Of the " + str(c["any_error"]) + " alerts with " + noun + " in at least one run, " + str(c["persistent"]) + " ("
                   + pct_of(c["persistent"], c["any_error"]) + ") were persistent, " + str(c["recurring"]) + " recurring and " + str(c["one_off"]) + " one-off.")
    nv = cc["no_verdict"]
    out.append(str(nv["any_error"]) + " alerts ended without a verdict in at least one run (" + str(nv["persistent"]) + " in every run, " + str(nv["one_off"])
               + " in one run only); parse failures are " + ("mostly persistent for particular alerts." if nv["persistent"] > nv["one_off"] + nv["recurring"]
                                                              else "mostly intermittent: different alerts fail in different runs." if nv["any_error"] else "absent."))
    sv = a["variation"]
    two = sv.get("alerts_with_2plus_valid", 0)
    out.append("The runs disagreed on attack_type for " + str(sv.get("attack_type_differs", 0)) + " of " + str(two) + " alerts with at least two valid verdicts, and on the is_malicious decision for "
               + str(sv.get("decision_differs", 0)) + "; " + str(cc["attack_type_error"]["persistent"]) + " alerts had an attack-type error in every run in which they could be judged.")
    pc = a["persistent"]["per_class"]
    worst = [kv for kv in sorted(pc.items(), key=lambda kv: (-kv[1]["persistent"], kv[0])) if kv[1]["persistent"] > 0][:3]
    if worst:
        out.append("Persistent attack-type errors are concentrated in: " + ", ".join(c + " (" + str(v["persistent"]) + " of " + str(v["attacks"]) + ")" for c, v in worst) + ".")
    out.append("These patterns are descriptive. They are the input for Week 3 design decisions and are not a reason to edit baseline_v3 on Day 6.")
    return out


def analyze(runs, reference=None, expected_sha=None):
    problems = check_runs(runs, expected_sha)
    if problems:
        raise AggregateError("the runs cannot be compared:\n  - " + "\n  - ".join(problems))
    evals = [r["evaluation"] for r in runs]
    rows = build_alert_rows(runs)
    meta0 = runs[0]["meta"]
    analysis = {
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "run_names": [r["name"] for r in runs], "reference_name": reference["name"] if reference else None,
        "prompt_version": meta0.get("prompt_version"), "prompt_sha256": meta0.get("prompt_sha256"), "model": meta0.get("model"),
        "settings": {k: v for k, v in (meta0.get("settings") or {}).items() if k != "requests_per_minute"},
        "n_alerts": get_path(evals[0], ("metrics", "population", "alerts")), "n_attacks": get_path(evals[0], ("metrics", "population", "true_attacks")),
        "n_benign": get_path(evals[0], ("metrics", "population", "true_benign")),
        "headline": headline_table(evals, reference["evaluation"] if reference else None),
        "categories": category_counts(rows), "variation": stochastic_variation(rows, len(runs)), "persistent": persistent_detail(rows),
        "parse_failures": parse_failure_detail(rows, runs), "rows": rows,
    }
    analysis["missing_metrics"] = [r["key"] for r in analysis["headline"] if r["n_present"] < len(runs)]
    analysis["conclusions"] = conclusions(analysis)
    return analysis


# ------------------------------------------------------------------------------------------------ outputs
def metrics_csv_rows(analysis):
    out = []
    for r in analysis["headline"]:
        row = {"metric": r["key"], "label": r["label"], "unit": r["unit"]}
        for name, v in zip(analysis["run_names"], r["values"]):
            row[name] = v
        row.update({"mean": r["mean"], "sd": r["sd"], "min": r["min"], "max": r["max"], "range": r["range"], "reference": r["ref"]})
        out.append(row)
    return out


def summary_json(analysis, input_hashes, inputs_unchanged):
    return {
        "generated_utc": analysis["generated_utc"], "runs": analysis["run_names"], "reference_run_not_in_mean": analysis["reference_name"],
        "prompt_version": analysis["prompt_version"], "prompt_sha256": analysis["prompt_sha256"], "model": analysis["model"], "settings": analysis["settings"],
        "n_alerts": analysis["n_alerts"], "spread_method": "mean; sample sd with n-1; min; max; range = max - min (percentage points for fractions)",
        "headline": analysis["headline"], "error_categories": analysis["categories"], "variation": analysis["variation"],
        "parse_failures": analysis["parse_failures"],
        "persistent_per_class": analysis["persistent"]["per_class"],
        "persistent_confusions": [{"true": t, "predicted": p, "alerts": c} for (t, p), c in analysis["persistent"]["persistent_confusions"].most_common()],
        "persistent_type_consistency": dict(analysis["persistent"]["persistent_type_consistency"]),
        "persistent_mitre_split": dict(analysis["persistent"]["persistent_mitre_split"]),
        "conclusions": analysis["conclusions"], "input_file_sha256": input_hashes, "inputs_unchanged": inputs_unchanged,
    }


def write_outputs(analysis, out_dir, input_hashes, inputs_unchanged, force=False):
    existing = [f for f in OUTPUT_FILES if os.path.exists(os.path.join(out_dir, f))]
    if existing and not force:
        raise AggregateError("output files already exist in " + out_dir + ": " + ", ".join(existing) + ". Use --force to replace them, or --out-dir.")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, REPORT_NAME), "w", encoding="utf-8") as f:
        f.write(render_report(analysis))
    pd.DataFrame(metrics_csv_rows(analysis)).to_csv(os.path.join(out_dir, "three_run_metrics.csv"), index=False)
    pd.DataFrame(per_alert_table(analysis["rows"])).to_csv(os.path.join(out_dir, "per_alert_across_runs.csv"), index=False)
    pd.DataFrame(error_pattern_rows(analysis["rows"])).to_csv(os.path.join(out_dir, "error_patterns.csv"), index=False)
    with open(os.path.join(out_dir, "three_run_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary_json(analysis, input_hashes, inputs_unchanged), f, indent="  ", default=str)


def main(argv=None):
    p = argparse.ArgumentParser(description="Week 2 Day 6: mean, spread and cross-run error analysis of three evaluated DEV runs. Read-only on the runs.")
    p.add_argument("--runs", nargs="+", default=DEFAULT_RUNS, help="evaluated run names (default: the three Day 6 replicates)")
    p.add_argument("--reference-run", default=DEFAULT_REFERENCE, help="extra comparison column, not in the mean (default: the Day 5 final run)")
    p.add_argument("--no-reference", action="store_true")
    p.add_argument("--expected-sha256", default=None, help="optional: refuse unless every run used exactly this prompt hash")
    p.add_argument("--eval-root", default=DEFAULT_EVAL_ROOT)
    p.add_argument("--runs-root", default=DEFAULT_RUNS_ROOT)
    p.add_argument("--out-dir", default=DEFAULT_OUT)
    p.add_argument("--force", action="store_true", help="replace existing output files")
    args = p.parse_args(argv)
    try:
        runs = [load_run(n, args.eval_root, args.runs_root) for n in args.runs]
        reference = None
        if not args.no_reference and args.reference_run not in args.runs:
            try:
                reference = load_run(args.reference_run, args.eval_root, args.runs_root)
            except AggregateError as error:
                print("Note: no reference column (" + str(error)[:120] + ")")
        input_paths = sorted(set(path for r in runs + ([reference] if reference else []) for path in r["paths"].values()))
        before = {path: sha256_file(path) for path in input_paths}
        analysis = analyze(runs, reference, args.expected_sha256)
        after = {path: sha256_file(path) for path in input_paths}
        write_outputs(analysis, args.out_dir, before, before == after, args.force)
    except AggregateError as error:
        print("STOPPED: " + str(error))
        return 1
    print("Wrote " + ", ".join(OUTPUT_FILES) + " to " + args.out_dir)
    print("Inputs unchanged: " + str(before == after))
    if analysis["missing_metrics"]:
        print("WARNING: metrics not found in at least one evaluation.json: " + ", ".join(analysis["missing_metrics"]))
    for line in analysis["conclusions"]:
        print("- " + line)
    return 0 if before == after else 3


if __name__ == "__main__":
    sys.exit(main())
