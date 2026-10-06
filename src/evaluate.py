"""Day 4 evaluation harness: score a finished DEV baseline run against the DEV labels and the MITRE answer key.

EVALUATION ONLY. This is the one place that reads labels. It never calls a model, never changes the run it reads,
never opens the frozen evaluation set, and no agent-side module may import it (a test checks that).

  python src/evaluate.py --run-name dev_flash_lite_v1

Reads   runs/week2_baseline_v1/<run-name>/results.jsonl (and raw_responses.jsonl, run_meta.json if present)
        the DEV alerts, the DEV labels and the answer key (through eval_io / eval_labels, dev only)
Writes  reports/week2_eval/<run-name>/   evaluation.json, evaluation_metrics.csv, per_class.csv,
        attack_type_confusion.csv, per_alert.csv, EVALUATION_REPORT.md
"""
import os
import sys
import json
import hashlib
import argparse
import datetime

import pandas as pd

import config
import verdict_schema
import eval_metrics as em

CLASSES = ["BENIGN"] + sorted(c for c in verdict_schema.ATTACK_TYPES if c != "BENIGN")
ATTACK_CLASSES = [c for c in CLASSES if c != "BENIGN"]
RUNS_ROOT = os.path.join(config.PROJECT_ROOT, "runs", "week2_baseline_v1")
OUT_ROOT = os.path.join(config.REPORTS_DIR, "week2_eval")
LATENCY_WARNING_SECONDS = 600


class EvaluationInputError(Exception):
    pass


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        block = f.read(1 << 20)
        while block:
            h.update(block)
            block = f.read(1 << 20)
    return h.hexdigest()


def read_jsonl(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for number, line in enumerate(f, start=1):
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    raise EvaluationInputError(os.path.basename(path) + " line " + str(number) + " is not valid JSON")
    return rows


def snapshot(run_dir, protected, frozen_log):
    """SHA-256 of every file in the run folder and of the protected files, and the length of the frozen access log."""
    run_files = {}
    for folder, _, names in os.walk(run_dir):
        for name in sorted(names):
            full = os.path.join(folder, name)
            run_files[os.path.relpath(full, run_dir)] = sha256_file(full)
    other = {p: (sha256_file(p) if os.path.exists(p) else None) for p in protected}
    log_lines = None
    if frozen_log is not None:
        log_lines = 0
        if os.path.exists(frozen_log):
            with open(frozen_log, "r", encoding="utf-8") as f:
                log_lines = sum(1 for _ in f)
    return {"run_files": run_files, "protected_files": other, "frozen_access_log_lines": log_lines}


def load_run(run_dir):
    results_path = os.path.join(run_dir, "results.jsonl")
    if not os.path.exists(results_path):
        raise EvaluationInputError("no results.jsonl in " + run_dir)
    lines = read_jsonl(results_path)
    latest = {}
    for record in lines:
        latest[record["alert_id"]] = record
    calls = None
    raw_path = os.path.join(run_dir, "raw_responses.jsonl")
    if os.path.exists(raw_path):
        raw = read_jsonl(raw_path)
        calls = pd.DataFrame({"alert_id": [r.get("alert_id") for r in raw], "call_index": [r.get("call_index") for r in raw],
                              "latency_seconds": [r.get("latency_seconds") for r in raw], "timestamp_utc": [r.get("timestamp_utc") for r in raw]})
    meta = {}
    meta_path = os.path.join(run_dir, "run_meta.json")
    if os.path.exists(meta_path):
        with open(meta_path, "r", encoding="utf-8") as f:
            full = json.load(f)
        meta = {k: full[k] for k in ("run_name", "model", "provider", "prompt_version", "prompt_sha256", "git_commit") if k in full}
        if isinstance(full.get("sessions"), list):
            meta["sessions"] = len(full["sessions"])
    return latest, len(lines), calls, meta


def check_inputs(alerts, labels, latest, threshold, allow_partial):
    problems = []
    ids = list(alerts["alert_id"])
    if len(set(ids)) != len(ids):
        problems.append("the dev alert file has duplicate alert ids")
    if list(labels["alert_id"]) != ids:
        problems.append("dev labels and dev alerts do not list the same alert ids in the same order")
    needed = {"alert_id", "label", "is_attack", "mitre_technique_id", "mitre_accepted_ids"}
    missing_cols = sorted(needed - set(labels.columns))
    if missing_cols:
        problems.append("the dev label file is missing columns: " + ", ".join(missing_cols) + ". The MITRE mapping needed for scoring is not available.")
    else:
        unknown = sorted(set(labels["label"]) - set(CLASSES))
        if unknown:
            problems.append("labels that are not Week 1 classes: " + ", ".join(unknown))
        wrong = labels[(labels["label"] == "BENIGN") != (labels["is_attack"] == 0)]
        if len(wrong):
            problems.append(str(len(wrong)) + " labels disagree with is_attack")
        atk = labels[labels["is_attack"] == 1]
        no_key = atk[atk["mitre_accepted_ids"].isin(["NONE", "", None]) | atk["mitre_accepted_ids"].isna()]
        if len(no_key):
            problems.append(str(len(no_key)) + " attack alerts have no accepted MITRE ids in the answer key (classes: " + ", ".join(sorted(set(no_key["label"]))) + "). MITRE accuracy cannot be computed for them.")
    stray = sorted(set(latest) - set(ids))
    if stray:
        problems.append(str(len(stray)) + " result ids are not dev alert ids, for example " + ", ".join(stray[:3]) + ". This run is not a run on the dev set.")
    absent = [i for i in ids if i not in latest]
    if absent and not allow_partial:
        problems.append(str(len(absent)) + " dev alerts have no result (for example " + ", ".join(absent[:3]) + "). Finish the run, or pass --allow-partial.")
    if "detector_score" in alerts.columns and threshold is not None:
        below = alerts[alerts["detector_score"] < threshold - config.SCORE_CHECK_TOLERANCE]
        if len(below):
            problems.append(str(len(below)) + " dev alerts are below the accepted detector threshold, so they are not all detector alerts.")
    elif "detector_score" not in alerts.columns:
        problems.append("the dev alert file has no detector_score, so 'every dev alert is a detector alert' cannot be checked")
    for alert_id, r in latest.items():
        if r.get("status") not in ("ok", "parse_failed", "model_error"):
            problems.append("alert " + alert_id + " has an unknown status " + str(r.get("status")))
        if r.get("status") == "ok" and not isinstance(r.get("verdict"), dict):
            problems.append("alert " + alert_id + " is ok but has no verdict")
    if problems:
        raise EvaluationInputError("Cannot evaluate:\n- " + "\n- ".join(problems[:20]))


def build_table(alerts, labels, latest, allow_partial=False):
    labels = labels.set_index("alert_id")
    rows = []
    for alert_id in alerts["alert_id"]:
        if alert_id not in latest and allow_partial:
            continue
        lab = labels.loc[alert_id]
        r = latest.get(alert_id)
        accepted = [] if lab["mitre_accepted_ids"] in ("NONE", "") else str(lab["mitre_accepted_ids"]).split(";")
        v = (r or {}).get("verdict") if r and r.get("status") == "ok" else None
        log = (r or {}).get("attempt_log") or []
        rows.append({
            "alert_id": alert_id, "label": lab["label"], "is_attack": bool(lab["is_attack"]), "accepted_ids": accepted,
            "primary_id": lab["mitre_technique_id"], "status": (r or {}).get("status", "not_run"), "has_verdict": v is not None,
            "pred_malicious": None if v is None else bool(v["is_malicious"]), "pred_attack_type": None if v is None else v["attack_type"],
            "pred_technique": None if v is None else v["mitre_technique"], "pred_severity": None if v is None else v["severity"],
            "attempts": (r or {}).get("attempts"), "model_calls": (r or {}).get("model_calls"),
            "malformed_first_try": (r or {}).get("malformed_first_try"), "error_code": (r or {}).get("error_code"),
            "first_try_error": log[0].get("error_code") if log else None,
            "prompt_tokens": (r or {}).get("prompt_tokens"), "output_tokens": (r or {}).get("output_tokens"),
            "thinking_tokens": (r or {}).get("thinking_tokens"), "total_tokens": (r or {}).get("total_tokens"),
            "latency_seconds": (r or {}).get("latency_seconds"), "finish_reasons": (r or {}).get("finish_reasons") or [],
        })
    df = pd.DataFrame(rows)
    for col in ("attempts", "model_calls", "prompt_tokens", "output_tokens", "thinking_tokens", "total_tokens", "latency_seconds"):
        df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


# ------------------------------------------------------------------ report

def fv(v, digits=4):
    return "n/a" if v is None else format(v, "." + str(digits) + "f")


def fr(r):
    if r["value"] is None:
        return "n/a (" + str(r["numerator"]) + "/" + str(r["denominator"]) + ")"
    ci = "" if r["wilson95"] is None else ", 95% CI " + fv(r["wilson95"][0], 3) + " to " + fv(r["wilson95"][1], 3)
    return fv(r["value"]) + " (" + str(r["numerator"]) + "/" + str(r["denominator"]) + ci + ")"


def render_report(m, ctx):
    pop, rel, ver, dec, fpr = m["population"], m["reliability"], m["verdict"], m["decision_table"], m["fp_reduction"]
    L = []
    add = L.append
    add("# Week 2 Day 4: evaluation of baseline run `" + ctx["run_name"] + "` on the DEV set")
    add("")
    add("Evaluation only. Labels and the MITRE answer key were read by this harness and were never part of a model prompt. DEV set only; the frozen set was not opened. The Day 3 run was read, not changed.")
    add("")
    add("Every ratio shows its numerator, denominator and population. Nothing is reported on valid verdicts alone without the all-alerts view next to it.")
    add("")
    add("## 1. Population and run")
    add("")
    add("| item | value |")
    add("|---|---|")
    add("| dev alerts evaluated | " + str(pop["alerts"]) + " (" + str(pop["true_attacks"]) + " true attacks, " + str(pop["true_benign"]) + " detector false positives) |")
    add("| valid verdicts | " + str(pop["ok"]) + " |")
    add("| parse_failed (no valid verdict after retries) | " + str(pop["parse_failed"]) + " |")
    add("| model_error | " + str(pop["model_error"]) + " |")
    add("| not run | " + str(pop["not_run"]) + " |")
    for k, v in ctx["run_meta"].items():
        add("| run_meta: " + k + " | " + str(v) + " |")
    add("| results.jsonl lines / alerts | " + str(ctx["result_lines"]) + " / " + str(pop["alerts"]) + " |")
    add("")
    add("The detector's decision on every dev alert is \"malicious\" (every dev alert is a detector alert; checked against the accepted threshold). "
        "The dev set was sampled with " + fv(100.0 * pop["true_benign"] / pop["alerts"], 1) + "% false positives, so the detector's precision on it is "
        + fv(pop["true_attacks"] / pop["alerts"]) + " by construction. Its natural precision is " + ctx["detector_reference"] + ".")
    add("")
    add("## 2. Output reliability")
    add("")
    add("| metric | value | population |")
    add("|---|---|---|")
    for key, name in [("first_try_malformed", "first-try malformed"), ("first_try_malformed_of_all_alerts", "first-try malformed, over all alerts"),
                      ("retry_needed", "retry needed"), ("recovered_by_retry", "recovered by a retry"), ("final_parse_failure", "final parse failure"),
                      ("model_error", "model error"), ("successful_verdict_coverage", "successful verdict coverage")]:
        add("| " + name + " | " + fr(rel[key]) + " | " + rel[key]["population"] + " |")
    add("")
    add("Model calls: " + str(rel["model_calls_total"]) + " in total, " + fv(rel["model_calls_per_alert_mean"], 3) + " per alert.")
    add("")
    add("First-try error codes: " + (json.dumps(rel["first_try_error_codes"], sort_keys=True) or "{}") + ". Final error codes: " + json.dumps(rel["final_error_codes"], sort_keys=True)
        + ". Finish reasons over all calls: " + json.dumps(rel["finish_reason_counts"], sort_keys=True) + ".")
    add("")
    add("Alerts with no verdict, by true label: " + json.dumps(rel["no_verdict_by_true_label"], sort_keys=True) + ".")
    add("")
    add("## 3. What the baseline did with each detector alert")
    add("")
    add("| true kind | kept as malicious | dismissed as benign | no verdict | total |")
    add("|---|---|---|---|---|")
    for key, name in [("true_attacks", "true attacks"), ("true_benign_false_positives", "detector false positives")]:
        c = dec[key]
        add("| " + name + " | " + str(c["kept_as_malicious"]) + " | " + str(c["dismissed_as_benign"]) + " | " + str(c["no_verdict"]) + " | " + str(c["total"]) + " |")
    add("")
    add("## 4. Verdict metrics (positive class = malicious)")
    add("")
    add("Three denominators, because " + str(pop["alerts"] - pop["ok"]) + " alerts have no verdict:")
    add("")
    for policy, v in ver.items():
        add("- **" + policy + "**: " + v["definition"])
    add("")
    add("| view | alerts | precision | recall | F1 | specificity |")
    add("|---|---|---|---|---|---|")
    for policy, v in ver.items():
        add("| baseline, " + policy + " | " + str(v["alerts_in_population"]) + " | " + fr(v["llm"]["precision"]) + " | " + fr(v["llm"]["recall"]) + " | " + fv(v["llm"]["f1"]) + " | " + fr(v["llm"]["specificity"]) + " |")
        add("| detector, same alerts | " + str(v["alerts_in_population"]) + " | " + fr(v["detector"]["precision"]) + " | " + fr(v["detector"]["recall"]) + " | " + fv(v["detector"]["f1"]) + " | " + fr(v["detector"]["specificity"]) + " |")
    add("")
    add("Recall here is measured among alerts the detector already raised. Attacks the detector missed are not in the dev set, so this is not end-to-end recall.")
    add("")
    add("## 5. False positives against the detector")
    add("")
    add("| view | detector FP | baseline FP | FP removed | FP reduction | detector FP share of alerts | baseline FP share of alerts | alert volume reduction | attacks the baseline missed |")
    add("|---|---|---|---|---|---|---|---|---|")
    for policy, f in fpr.items():
        add("| " + policy + " | " + str(f["detector_fp"]) + " | " + str(f["llm_fp"]) + " | " + str(f["fp_removed"]) + " | " + fv(f["fp_reduction_pct"], 2) + "% | "
            + fv(f["detector_fp_share_of_alerts"]) + " | " + fv(f["llm_fp_share_of_alerts"]) + " | " + fv(f["alert_volume_reduction_pct"], 2) + "% | " + str(f["attacks_missed_by_llm"]) + " of " + str(ver[policy]["detector_confusion"]["tp"]) + " |")
    add("")
    add("The detector's false-positive rate among benign dev alerts is 1.0 by construction (every benign alert in the set is a detector false positive), so the reduction is the share of those the baseline dismissed. "
        "In the valid-only view the detector is compared on the same alerts as the baseline. The cost of the reduction is the attacks the baseline dismissed, in the last column.")
    add("")
    for policy, f in fpr.items():
        add("- " + policy + ": benign dismissal rate " + fr(f["benign_dismissal_rate"]))
    add("")
    at, mi = m["attack_type"], m["mitre"]
    add("## 6. Attack type (exact class match)")
    add("")
    add(at["definition"])
    add("")
    add("| measure | value | population |")
    add("|---|---|---|")
    for key in ("on_attacks_with_valid_verdict", "on_attacks_flagged_malicious", "all_attacks_failures_wrong", "coverage"):
        add("| " + key + " | " + fr(at[key]) + " | " + at[key]["population"] + " |")
    add("")
    add("## 7. MITRE technique accuracy")
    add("")
    add(mi["definition"])
    add("")
    add("| measure | value | population |")
    add("|---|---|---|")
    for key in ("accepted_on_attacks_with_valid_verdict", "accepted_on_attacks_flagged_malicious", "accepted_all_attacks_failures_wrong", "primary_on_attacks_with_valid_verdict", "coverage", "benign_alerts_given_NONE"):
        add("| " + key + " | " + fr(mi[key]) + " | " + mi[key]["population"] + " |")
    add("")
    add("## 8. Per class")
    add("")
    add("| class | alerts | valid | no verdict | rate | 95% CI | attack-type acc. | MITRE acc. |")
    add("|---|---|---|---|---|---|---|---|")
    for r in m["per_class"]:
        ci = "n/a" if r["wilson95"] is None else fv(r["wilson95"][0], 2) + " to " + fv(r["wilson95"][1], 2)
        add("| " + r["label"] + " | " + str(r["alerts"]) + " | " + str(r["valid_verdicts"]) + " | " + str(r["no_verdict"]) + " | " + fv(r["rate"]) + " (" + str(r["hits"]) + "/" + str(r["valid_verdicts"]) + ") | " + ci + " | "
            + fv(r.get("attack_type_accuracy")) + " | " + fv(r.get("mitre_accuracy")) + " |")
    add("")
    add("Rate = recall for attack classes (called malicious), and the dismissal rate for BENIGN (detector false positives dismissed). Accuracies are over the class's valid verdicts. Small classes have wide intervals.")
    add("")
    tk, co = m["tokens"], m["cost"]
    add("## 9. Tokens and cost")
    add("")
    add("| item | value |")
    add("|---|---|")
    for key in ("prompt_tokens", "output_tokens", "thinking_tokens", "total_tokens"):
        add("| " + key + " | " + str(tk[key]) + " |")
    add("| alerts with token counts / without | " + str(tk["alerts_with_token_counts"]) + " / " + str(tk["alerts_without_token_counts"]) + " |")
    add("| mean total tokens per alert (alerts with counts) | " + fv(tk["total_tokens_per_alert_mean"], 1) + " |")
    add("| prompt + output + thinking equals total | " + str(tk["parts_add_up_to_total"]) + " |")
    add("")
    if co["available"]:
        add("Estimated cost: " + format(co["total"], ".4f") + " " + co["currency"] + " (" + format(co["per_alert_mean"], ".6f") + " per alert). Prices used: input " + str(co["pricing"]["per_million_input_tokens"])
            + " and output " + str(co["pricing"]["per_million_output_tokens"]) + " per million tokens, thinking tokens billed as " + co["pricing"]["thinking_tokens_billed_as"]
            + ". Source: " + str(co["pricing"]["source"]) + ", as of " + str(co["pricing"]["as_of"]) + ". " + co["note"])
    else:
        add("Cost: **unavailable.** " + co["reason"])
    add("")
    la = m["latency"]
    add("## 10. Latency (seconds)")
    add("")
    add("Per alert = all model calls of that alert added up (including retries). Per call = one model request.")
    add("")
    if la["excluded_alert_ids"]:
        add("**Excluded observation:** alert " + ", ".join(la["excluded_alert_ids"]) + " with " + ", ".join(str(v) for v in la["excluded_values"])
            + " s. This is a documented recorded-latency exclusion. It is left in the raw files and in per_alert.csv (flagged), and excluded only from the statistics marked 'excluding anomaly'. No other alert was excluded.")
    else:
        add("No observation was excluded.")
    if ctx["latency_warning"]:
        add("")
        add("**Warning:** " + ctx["latency_warning"])
    add("")
    add("| scope | n | mean | median | p95 | min | max |")
    add("|---|---|---|---|---|---|---|")
    for key in ("per_alert_all_observations", "per_alert_excluding_anomaly", "per_call_all_observations", "per_call_excluding_anomaly"):
        if key in la:
            s = la[key]
            add("| " + key.replace("_", " ") + " | " + str(s["n"]) + " | " + fv(s["mean"], 2) + " | " + fv(s["median"], 2) + " | " + fv(s["p95"], 2) + " | " + fv(s["min"], 2) + " | " + fv(s["max"], 2) + " |")
    add("")
    add("p95 uses linear interpolation between ranked values.")
    add("")
    add("### Wall-clock gaps between consecutive model calls")
    add("")
    add("These timestamp gaps are diagnostic only. They are not model latency and are never excluded from latency statistics.")
    if ctx.get("wall_clock_gaps"):
        add("")
        add("| seconds | from alert | to alert |")
        add("|---:|---|---|")
        for gap in ctx["wall_clock_gaps"]:
            add("| " + fv(gap["seconds"], 1) + " | " + str(gap["from_alert_id"]) + " | " + str(gap["to_alert_id"]) + " |")
    else:
        add("")
        add("No call timestamps were available to calculate wall-clock gaps.")
    add("")
    add("## 11. Integrity")
    add("")
    for line in ctx["integrity_lines"]:
        add("- " + line)
    add("")
    return "\n".join(L) + "\n"


def flatten(prefix, value, rows):
    if isinstance(value, dict):
        if "numerator" in value and "denominator" in value:
            ci = value.get("wilson95") or [None, None]
            rows.append({"metric": prefix, "value": value["value"], "numerator": value["numerator"], "denominator": value["denominator"],
                         "ci_low": ci[0], "ci_high": ci[1], "population": value.get("population", "")})
            return
        for k, v in value.items():
            if k in ("definition", "pricing", "note", "reason"):
                continue
            flatten(prefix + "." + k if prefix else k, v, rows)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        rows.append({"metric": prefix, "value": value, "numerator": None, "denominator": None, "ci_low": None, "ci_high": None, "population": ""})


def detector_reference(threshold_info):
    parts = []
    if threshold_info:
        v = threshold_info.get("validation", {})
        if v.get("precision") is not None:
            parts.append(format(v["precision"], ".4f") + " on all validation alerts (threshold.json)")
    test_path = os.path.join(config.REPORTS_DIR, "test_metrics.json")
    if os.path.exists(test_path):
        with open(test_path, "r", encoding="utf-8") as f:
            t = json.load(f).get("at_accepted_threshold", {})
        if t.get("precision") is not None:
            parts.append(format(t["precision"], ".4f") + " on the test split (test_metrics.json)")
    return " and ".join(parts) if parts else "not available from the Week 1 reports in this checkout"


def wall_clock_gaps(calls, limit=5):
    """Largest gaps between consecutive persisted call timestamps. These are diagnostics only, never model latency."""
    if calls is None or "timestamp_utc" not in calls.columns:
        return []
    rows = calls.dropna(subset=["timestamp_utc"]).copy()
    if len(rows) < 2:
        return []
    rows["_time"] = pd.to_datetime(rows["timestamp_utc"], utc=True, errors="coerce")
    rows = rows.dropna(subset=["_time"]).sort_values("_time", kind="stable").reset_index(drop=True)
    gaps = []
    for i in range(1, len(rows)):
        gaps.append({"seconds": float((rows.loc[i, "_time"] - rows.loc[i - 1, "_time"]).total_seconds()),
                     "from_alert_id": rows.loc[i - 1, "alert_id"], "to_alert_id": rows.loc[i, "alert_id"]})
    return sorted(gaps, key=lambda x: x["seconds"], reverse=True)[:limit]


def run_evaluation(run_dir, alerts, labels, out_dir, threshold=None, threshold_info=None, exclude_latency=None, pricing=None,
                   allow_partial=False, force=False, protected=(), frozen_log=None, log=print):
    if os.path.exists(out_dir) and os.listdir(out_dir) and not force:
        raise EvaluationInputError(out_dir + " already has an evaluation. Use --force to replace it (the Day 3 run is never touched).")
    before = snapshot(run_dir, protected, frozen_log)
    latest, n_lines, calls, meta = load_run(run_dir)
    check_inputs(alerts, labels, latest, threshold, allow_partial)
    df = build_table(alerts, labels, latest, allow_partial)

    excluded, warning = [], None
    if exclude_latency is not None:
        excluded = em.find_latency_anomaly(df, exclude_latency)
        if len(excluded) != 1:
            raise EvaluationInputError("expected exactly one alert with latency " + str(exclude_latency) + " s, found " + str(len(excluded)) + ". Nothing was excluded; check the value.")
    else:
        top = df["latency_seconds"].max()
        if pd.notna(top) and top > LATENCY_WARNING_SECONDS:
            warning = "the largest per-alert latency is " + format(top, ".1f") + " s, which looks like an interruption. Pass --exclude-latency-seconds to exclude a documented anomaly. These statistics include it."
    metrics = em.build_metrics(df, CLASSES, pricing, excluded, calls)
    gaps = wall_clock_gaps(calls)

    os.makedirs(out_dir, exist_ok=True)
    after = snapshot(run_dir, protected, frozen_log)
    run_unchanged = before["run_files"] == after["run_files"]
    protected_unchanged = before["protected_files"] == after["protected_files"]
    log_unchanged = before["frozen_access_log_lines"] == after["frozen_access_log_lines"]
    integrity = [
        "Day 3 run folder unchanged during evaluation: " + str(run_unchanged) + " (" + str(len(before["run_files"])) + " files hashed before and after).",
        "Week 1 protected files unchanged during evaluation: " + str(protected_unchanged) + " (" + str(len(before["protected_files"])) + " files).",
        "Frozen access log line count unchanged: " + str(log_unchanged) + " (" + str(before["frozen_access_log_lines"]) + " lines).",
        "All dev alerts are detector alerts (score at or above the accepted threshold): " + ("checked" if threshold is not None else "NOT checked, no threshold given") + ".",
        "Labels and the answer key were used only in this evaluation; no model was called.",
    ]
    ctx = {"run_name": os.path.basename(os.path.normpath(run_dir)), "run_meta": meta, "result_lines": n_lines,
           "detector_reference": detector_reference(threshold_info), "latency_warning": warning, "wall_clock_gaps": gaps, "integrity_lines": integrity}
    out = {"generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "run": ctx["run_name"], "run_meta": meta,
           "run_file_sha256": before["run_files"], "protected_file_sha256": {os.path.relpath(k, config.PROJECT_ROOT) if os.path.isabs(k) else k: v for k, v in before["protected_files"].items()},
           "frozen_access_log_lines": before["frozen_access_log_lines"],
           "integrity": {"run_unchanged": run_unchanged, "protected_unchanged": protected_unchanged, "frozen_log_unchanged": log_unchanged},
           "latency_exclusion": {"requested_seconds": exclude_latency, "alert_ids": excluded}, "wall_clock_gaps": gaps, "allow_partial": allow_partial, "metrics": metrics}
    with open(os.path.join(out_dir, "evaluation.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True, default=str)
    rows = []
    flatten("", metrics, rows)
    pd.DataFrame(rows).to_csv(os.path.join(out_dir, "evaluation_metrics.csv"), index=False)
    pd.DataFrame(metrics["per_class"]).to_csv(os.path.join(out_dir, "per_class.csv"), index=False)
    em.attack_type_confusion(df, CLASSES).to_csv(os.path.join(out_dir, "attack_type_confusion.csv"))
    table = df.copy()
    table["detector_prediction"] = "malicious"
    table["attack_type_correct"] = table.apply(lambda r: (r["pred_attack_type"] == r["label"]) if r["has_verdict"] and r["is_attack"] else None, axis=1)
    table["mitre_accepted"] = table.apply(lambda r: em._in_accepted(r) if r["has_verdict"] and r["is_attack"] else None, axis=1)
    table["latency_excluded"] = table["alert_id"].isin(excluded)
    table["accepted_ids"] = table["accepted_ids"].apply(";".join)
    table["finish_reasons"] = table["finish_reasons"].apply(lambda x: ";".join(str(i) for i in x))
    table.to_csv(os.path.join(out_dir, "per_alert.csv"), index=False)
    with open(os.path.join(out_dir, "EVALUATION_REPORT.md"), "w", encoding="utf-8") as f:
        f.write(render_report(metrics, ctx))
    ok = run_unchanged and protected_unchanged and log_unchanged
    log("Integrity: run unchanged " + str(run_unchanged) + ", protected files unchanged " + str(protected_unchanged) + ", frozen log unchanged " + str(log_unchanged))
    return metrics, ok


def parse_args(argv):
    p = argparse.ArgumentParser(description="Score a DEV baseline run against the DEV labels.")
    p.add_argument("--run-name", required=True)
    p.add_argument("--runs-dir", default=RUNS_ROOT)
    p.add_argument("--out-dir", default=None, help="default reports/week2_eval/<run-name>")
    p.add_argument("--exclude-latency-seconds", type=float, default=None, help="exclude exactly one alert whose recorded latency equals this documented value")
    p.add_argument("--pricing-file", default=None, help="JSON with the exact Gemini prices, source and date; without it cost is reported as unavailable")
    p.add_argument("--allow-partial", action="store_true", help="evaluate only the alerts present in the run")
    p.add_argument("--force", action="store_true", help="replace an existing evaluation folder")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    import triage_inputs
    import eval_labels
    run_dir = os.path.join(args.runs_dir, args.run_name)
    if not os.path.isdir(run_dir):
        print("STOPPED: no run folder " + run_dir)
        return 1
    out_dir = args.out_dir or os.path.join(OUT_ROOT, args.run_name)
    pricing = None
    if args.pricing_file:
        with open(args.pricing_file, "r", encoding="utf-8") as f:
            pricing = json.load(f)
    threshold_info = None
    if os.path.exists(config.THRESHOLD_PATH):
        with open(config.THRESHOLD_PATH, "r", encoding="utf-8") as f:
            threshold_info = json.load(f)
    threshold = threshold_info["threshold"] if threshold_info else None
    protected = [config.DEV_ALERTS_PATH, config.DEV_LABELS_PATH, config.MITRE_MAP_PATH, config.MANIFEST_PATH, config.THRESHOLD_PATH, config.MODEL_PATH, config.FEATURE_LIST_PATH]
    try:
        alerts = triage_inputs.load_dev_alerts()
        labels = eval_labels.load_dev_labels()
        metrics, ok = run_evaluation(run_dir, alerts, labels, out_dir, threshold, threshold_info, args.exclude_latency_seconds, pricing,
                                     args.allow_partial, args.force, protected, config.FROZEN_ACCESS_LOG)
    except (EvaluationInputError, ValueError) as error:
        print("STOPPED: " + str(error))
        return 1
    v = metrics["verdict"]["failures_escalated"]
    print("Evaluated " + str(metrics["population"]["alerts"]) + " dev alerts: " + str(metrics["population"]["ok"]) + " valid verdicts, " + str(metrics["population"]["parse_failed"]) + " parse_failed.")
    print("Report: " + os.path.join(out_dir, "EVALUATION_REPORT.md"))
    return 0 if ok else 3


if __name__ == "__main__":
    sys.exit(main())
