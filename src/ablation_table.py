"""Week 3 Day 6: the ablation table. Reads only what the Week 2 evaluation harness and the runner already wrote; no model call, no label file, no answer key, no frozen file.

  python src/ablation_table.py --out-dir reports/week3_day6/ablation_table_v1 --reference "A rerun" \\
      --run "A rerun"  runs/week3_day6/RUN_A  reports/week3_day6/RUN_A \\
      --run "B"        runs/week3_day6/RUN_B  reports/week3_day6/RUN_B \\
      --run "A Day 5"  runs/week3_agent_v1/dev_agent_v1_flash_lite  reports/week2_eval/dev_agent_v1_flash_lite \\
      [--baseline-summary reports/week2_day6/three_run_summary.json]

Each --run is LABEL RUN_DIR EVAL_DIR. From RUN_DIR it reads run_meta.json. From EVAL_DIR (written by src/evaluate.py) it reads evaluation.json and, for the paired comparison, per_alert.csv.
per_alert.csv is the harness's own output (it carries the true label per alert); this script never opens the label files themselves and imports no label module.

What it reports (only measured values, each with its sample size; nothing is estimated, filled in or smoothed):
  * the setup of every run and whether it is comparable with the reference (model, prompt hash, generation settings, dev inputs, alert list);
  * for each of the evaluator's three views (valid_only, failures_escalated, failures_wrong): precision, recall, F1, specificity, FP reduction, attacks missed;
  * attack-type and MITRE accuracy, coverage, parse failures, calls, tokens, tool calls;
  * the difference of every arm from the reference (percentage points for fractions, plain differences for counts);
  * paired per-alert comparisons with the reference (alerts one gets right and the other wrong) and the same metrics on the alerts every arm answered;
  * the spread of repeated observations of the same arm and, if given, the baseline_v3 three-run spread, as yardsticks for how much a difference could be noise.
Incomplete or not-comparable runs are listed in their own section with their finished counts. They are never part of a difference.
The report is descriptive. The arms were fixed before any result existed, the full graph is what Day 7 locks regardless of this table, and nothing here is a significance claim.
The output folder must not exist yet; an existing report is never overwritten. Exit code 0 on success, 2 for a usage problem.
"""
import os
import sys
import json
import math
import argparse
import hashlib
import datetime

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ablation_config as ablation

VIEWS = ("failures_wrong", "failures_escalated", "valid_only")
VIEW_NOTES = {
    "failures_wrong": "all alerts; an alert with no verdict counts as wrong (worst case). The denominator is the same in every arm, so this is the view the plan names as primary.",
    "failures_escalated": "all alerts; an alert with no verdict stays escalated (counted as predicted malicious).",
    "valid_only": "only alerts that got a valid verdict. The set of alerts differs between arms, and parse failures are not spread evenly over the classes, so read this view with care.",
}
SETTING_KEYS = ("temperature", "max_output_tokens", "seed", "parse_retries", "timeout_seconds", "transport_retries")
BASELINE_KEYS = ("precision_valid_only", "recall_valid_only", "f1_valid_only", "specificity_valid_only", "attack_type_valid", "mitre_valid", "coverage", "final_parse_failure_n", "total_tokens", "model_calls_total")


# ------------------------------------------------------------------------------------------------ small helpers
def dig(data, path, default=None):
    node = data
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    return node


def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def ratio_cell(obj):
    """{value, num, den} from an evaluation ratio object, or None when it is missing."""
    if not isinstance(obj, dict) or "value" not in obj:
        return None
    return {"value": obj.get("value"), "num": obj.get("numerator"), "den": obj.get("denominator")}


def plain_cell(value):
    return None if value is None else {"value": value, "num": None, "den": None}


def fmt(cell, kind):
    if cell is None or cell.get("value") is None:
        return "n/a"
    v = cell["value"]
    if kind == "frac":
        text = format(v * 100, ".1f") + "%"
        return text + (" (" + str(cell["num"]) + "/" + str(cell["den"]) + ")" if cell.get("num") is not None else "")
    if kind == "pct":
        return format(v, ".1f") + "%"
    if kind == "number":
        return format(v, ".4f")
    if kind == "seconds":
        return format(v, ".2f")
    return format(v, ",.0f") if isinstance(v, (int, float)) and float(v).is_integer() else format(v, ",.1f")


def diff_value(cell, ref, kind):
    """Difference arm minus reference in the unit named by kind, or None if either is missing."""
    if cell is None or ref is None or cell.get("value") is None or ref.get("value") is None:
        return None
    d = cell["value"] - ref["value"]
    return d * 100 if kind == "frac" else d


def fmt_diff(d, kind):
    if d is None:
        return "n/a"
    sign = "+" if d > 0 else ("" if d == 0 else "-")
    a = abs(d)
    if kind in ("frac", "pct"):
        return sign + format(a, ".1f") + " pp"
    if kind == "number":
        return sign + format(a, ".4f")
    if kind == "seconds":
        return sign + format(a, ".2f")
    return sign + (format(a, ",.0f") if float(a).is_integer() else format(a, ",.1f"))


def mcnemar_exact(b, c):
    """Two-sided exact McNemar p-value from the two discordant counts. 1.0 when there are no discordant pairs. Descriptive only."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def sha_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------------------------------------ loading one run
METRIC_SPECS = []   # (key, label, kind, extractor(evaluation, meta) -> cell)


def _verdict(view, name, ratio=True):
    def get(ev, meta):
        obj = dig(ev, ("metrics", "verdict", view, "llm", name))
        return ratio_cell(obj) if ratio else plain_cell(obj)
    return get


for _view in VIEWS:
    METRIC_SPECS += [
        (_view + ".precision", "Precision", "frac", _verdict(_view, "precision")),
        (_view + ".recall", "Recall", "frac", _verdict(_view, "recall")),
        (_view + ".f1", "F1", "number", _verdict(_view, "f1", ratio=False)),
        (_view + ".specificity", "Specificity (benign dismissed)", "frac", _verdict(_view, "specificity")),
        (_view + ".fp_reduction", "FP reduction", "pct", (lambda v: lambda ev, meta: plain_cell(dig(ev, ("metrics", "fp_reduction", v, "fp_reduction_pct"))))(_view)),
        (_view + ".attacks_missed", "Attacks missed", "count", (lambda v: lambda ev, meta: plain_cell(dig(ev, ("metrics", "fp_reduction", v, "attacks_missed_by_llm"))))(_view)),
    ]
METRIC_SPECS += [
    ("attack_type_valid", "Attack-type accuracy (attacks with a valid verdict)", "frac", lambda ev, m: ratio_cell(dig(ev, ("metrics", "attack_type", "on_attacks_with_valid_verdict")))),
    ("attack_type_all", "Attack-type accuracy (all attacks, no verdict = wrong)", "frac", lambda ev, m: ratio_cell(dig(ev, ("metrics", "attack_type", "all_attacks_failures_wrong")))),
    ("mitre_valid", "MITRE accepted (attacks with a valid verdict)", "frac", lambda ev, m: ratio_cell(dig(ev, ("metrics", "mitre", "accepted_on_attacks_with_valid_verdict")))),
    ("mitre_all", "MITRE accepted (all attacks, no verdict = wrong)", "frac", lambda ev, m: ratio_cell(dig(ev, ("metrics", "mitre", "accepted_all_attacks_failures_wrong")))),
    ("coverage", "Valid-verdict coverage", "frac", lambda ev, m: ratio_cell(dig(ev, ("metrics", "reliability", "successful_verdict_coverage")))),
    ("parse_failures", "Final parse failures (alerts)", "count", lambda ev, m: plain_cell(dig(ev, ("metrics", "reliability", "final_parse_failure", "numerator")))),
    ("first_try_malformed", "First-try malformed (alerts)", "count", lambda ev, m: plain_cell(dig(ev, ("metrics", "reliability", "first_try_malformed", "numerator")))),
    ("model_errors", "Model errors (alerts)", "count", lambda ev, m: plain_cell(dig(ev, ("metrics", "reliability", "model_error", "numerator")))),
    ("model_calls", "Model calls", "count", lambda ev, m: plain_cell(dig(ev, ("metrics", "reliability", "model_calls_total")))),
    ("total_tokens", "Total tokens", "count", lambda ev, m: plain_cell(dig(ev, ("metrics", "tokens", "total_tokens")))),
    ("tokens_per_alert", "Tokens per alert (mean)", "count", lambda ev, m: plain_cell(dig(ev, ("metrics", "tokens", "total_tokens_per_alert_mean")))),
    ("tool_calls", "Tool calls", "count", lambda ev, m: plain_cell(dig(m, ("agent", "summary", "tool_calls")))),
    ("graph_seconds", "Graph seconds, all alerts (includes the request-rate wait)", "seconds", lambda ev, m: plain_cell(dig(m, ("agent", "summary", "graph_seconds_total")))),
    ("latency_alert_mean", "Model latency per alert, mean (s)", "seconds", lambda ev, m: plain_cell(dig(ev, ("metrics", "latency", "per_alert_all_observations", "mean")))),
]
SPEC_BY_KEY = {k: (label, kind, get) for k, label, kind, get in METRIC_SPECS}


def load_entry(label, run_dir, eval_dir):
    """Everything the table needs from one run, or a record saying why it cannot be used. Never raises for a bad run; the reason goes in entry['problems']."""
    entry = {"label": label, "run_dir": run_dir, "eval_dir": eval_dir, "problems": [], "complete": False, "comparable": None, "differences": []}
    try:
        meta = read_json(os.path.join(run_dir, "run_meta.json"))
        ev = read_json(os.path.join(eval_dir, "evaluation.json"))
    except (OSError, ValueError) as error:
        entry["problems"].append("could not read run_meta.json or evaluation.json: " + type(error).__name__)
        entry["run_name"] = os.path.basename(os.path.normpath(run_dir))
        return entry
    entry["meta"], entry["eval"] = meta, ev
    entry["run_name"] = meta.get("run_name")
    record = dig(meta, ("agent", "ablation"))
    if isinstance(record, dict):
        entry["arm"], entry["disabled"], entry["provenance"] = record.get("arm"), list(record.get("disabled") or []), "day6 arm run"
    else:
        entry["arm"], entry["disabled"], entry["provenance"] = None, [], "no ablation record in run_meta (a run made before Day 6)"
        specialists = dig(meta, ("agent", "specialists"))
        if isinstance(specialists, list) and set(specialists) == set(ablation.SPECIALISTS):
            entry["arm"] = "A"
            entry["provenance"] = "pre-Day-6 full-graph run (no ablation record; all three specialists listed)"
    if meta.get("fake_model"):
        entry["problems"].append("a --fake-model run is never a result")
    if ev.get("run") != os.path.basename(os.path.normpath(run_dir)):
        entry["problems"].append("the evaluation is for run '" + str(ev.get("run")) + "', not for " + os.path.basename(os.path.normpath(run_dir)))
    if dig(ev, ("run_meta", "prompt_sha256")) != meta.get("prompt_sha256"):
        entry["problems"].append("the evaluation's run_meta prompt hash differs from the run folder's run_meta.json")
    if not all(dig(ev, ("integrity",), {}).get(k) is True for k in ("run_unchanged", "protected_unchanged", "frozen_log_unchanged")):
        entry["problems"].append("the evaluation's integrity checks are not all true")
    population = dig(ev, ("metrics", "population"), {})
    entry["alerts_evaluated"], entry["alerts_expected"] = population.get("alerts"), meta.get("n_selected")
    reasons = []
    if meta.get("status") != "complete":
        reasons.append("run status is '" + str(meta.get("status")) + "'")
    if ev.get("allow_partial"):
        reasons.append("evaluated with --allow-partial")
    if population.get("alerts") != meta.get("n_selected"):
        reasons.append(str(population.get("alerts")) + " of " + str(meta.get("n_selected")) + " alerts evaluated")
    entry["incomplete_reasons"] = reasons
    entry["complete"] = not reasons and not entry["problems"]
    entry["setup"] = {"model": meta.get("model"), "prompt_version": meta.get("prompt_version"), "prompt_sha256": meta.get("prompt_sha256"),
                      "settings": {k: (meta.get("settings") or {}).get(k) for k in SETTING_KEYS}, "inputs": meta.get("inputs"),
                      "alert_list_sha256": sha_text(json.dumps(meta.get("selected_alert_ids"))), "n_selected": meta.get("n_selected")}
    entry["git"] = meta.get("git")
    entry["metrics"] = {key: get(ev, meta) for key, (label_, kind, get) in SPEC_BY_KEY.items()}
    entry["paths"] = dig(meta, ("agent", "summary", "path_counts"), {})
    per_alert = os.path.join(eval_dir, "per_alert.csv")
    entry["per_alert_path"] = per_alert if os.path.exists(per_alert) else None
    return entry


def check_comparable(entry, ref):
    """Fill entry['comparable'] and entry['differences'] against the reference."""
    diffs = []
    if "setup" in entry and "setup" in ref:
        a, b = entry["setup"], ref["setup"]
        for key in ("model", "prompt_sha256", "settings", "inputs", "alert_list_sha256", "n_selected"):
            if a.get(key) != b.get(key):
                diffs.append(key + ": " + json.dumps(a.get(key), sort_keys=True) + " vs reference " + json.dumps(b.get(key), sort_keys=True))
    else:
        diffs.append("setup unavailable")
    entry["differences"] = diffs
    entry["comparable"] = not diffs


# ------------------------------------------------------------------------------------------------ paired per-alert comparison
def _truthy(series):
    return series.astype(str).str.strip().str.lower().eq("true")


def load_per_alert(path):
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    need = ["alert_id", "label", "is_attack", "has_verdict", "pred_malicious", "pred_attack_type"]
    missing = [c for c in need if c not in df.columns]
    if missing:
        raise ValueError("per_alert.csv lacks columns: " + ", ".join(missing))
    out = pd.DataFrame({"alert_id": df["alert_id"], "is_attack": _truthy(df["is_attack"]), "has_verdict": _truthy(df["has_verdict"]),
                        "pred_malicious": _truthy(df["pred_malicious"]), "label": df["label"], "pred_attack_type": df["pred_attack_type"]})
    out["decision_correct"] = out["has_verdict"] & (out["pred_malicious"] == out["is_attack"])
    out["type_correct"] = out["has_verdict"] & out["is_attack"] & (out["pred_attack_type"] == out["label"])
    return out.set_index("alert_id")


def paired(arm_df, ref_df):
    """Discordant counts between an arm and the reference on the alerts both have."""
    common = arm_df.index.intersection(ref_df.index)
    a, r = arm_df.loc[common], ref_df.loc[common]
    out = {"alerts_compared": int(len(common))}
    d_b = int((r["decision_correct"] & ~a["decision_correct"]).sum())   # reference right, arm wrong
    d_c = int((~r["decision_correct"] & a["decision_correct"]).sum())   # reference wrong, arm right
    out["decision"] = {"reference_only_correct": d_b, "arm_only_correct": d_c, "both_correct": int((r["decision_correct"] & a["decision_correct"]).sum()),
                       "both_wrong": int((~r["decision_correct"] & ~a["decision_correct"]).sum()), "mcnemar_exact_p_descriptive": round(mcnemar_exact(d_b, d_c), 6),
                       "note": "decision correct = a valid verdict whose is_malicious equals the truth; no verdict counts as not correct"}
    attacks = r["is_attack"]
    t_b = int((r["type_correct"] & ~a["type_correct"] & attacks).sum())
    t_c = int((~r["type_correct"] & a["type_correct"] & attacks).sum())
    out["attack_type"] = {"attacks": int(attacks.sum()), "reference_only_correct": t_b, "arm_only_correct": t_c, "both_correct": int((r["type_correct"] & a["type_correct"] & attacks).sum()),
                          "both_wrong": int((~r["type_correct"] & ~a["type_correct"] & attacks).sum()), "mcnemar_exact_p_descriptive": round(mcnemar_exact(t_b, t_c), 6),
                          "note": "attack-type correct = a valid verdict whose attack_type equals the true class; no verdict counts as not correct"}
    return out


def metrics_on(df):
    """Precision, recall, F1, specificity and attack-type accuracy on the alerts of df that have a verdict (df is already restricted to the common set)."""
    v = df[df["has_verdict"]]
    tp = int((v["pred_malicious"] & v["is_attack"]).sum())
    fp = int((v["pred_malicious"] & ~v["is_attack"]).sum())
    fn = int((~v["pred_malicious"] & v["is_attack"]).sum())
    tn = int((~v["pred_malicious"] & ~v["is_attack"]).sum())
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    spec = tn / (tn + fp) if tn + fp else None
    attacks = v[v["is_attack"]]
    return {"alerts": int(len(v)), "attacks": int(len(attacks)), "benign": int((~v["is_attack"]).sum()),
            "precision": None if precision is None else {"value": precision, "num": tp, "den": tp + fp}, "recall": None if recall is None else {"value": recall, "num": tp, "den": tp + fn},
            "f1": None if f1 is None else {"value": f1, "num": None, "den": None}, "specificity": None if spec is None else {"value": spec, "num": tn, "den": tn + fp},
            "attack_type": None if len(attacks) == 0 else {"value": float(attacks["type_correct"].mean()), "num": int(attacks["type_correct"].sum()), "den": int(len(attacks))}}


# ------------------------------------------------------------------------------------------------ assembling the table
def build(entries, reference_label, baseline_summary=None):
    by_label = {e["label"]: e for e in entries}
    ref = by_label[reference_label]
    for e in entries:
        if e is ref:
            e["comparable"], e["differences"] = True, []
        else:
            check_comparable(e, ref)
    used = [e for e in entries if e["complete"] and e["comparable"]]
    excluded = [e for e in entries if e not in used]

    table = {"reference": reference_label, "views": {}, "other": {}}
    for view in VIEWS:
        rows = []
        for e in used:
            row = {"label": e["label"], "arm": e.get("arm"), "cells": {}, "deltas": {}}
            for key in [k for k, *_ in METRIC_SPECS if k.startswith(view + ".")]:
                label_, kind, _ = SPEC_BY_KEY[key]
                row["cells"][key] = e["metrics"][key]
                row["deltas"][key] = None if e is ref else diff_value(e["metrics"][key], ref["metrics"][key], kind)
            rows.append(row)
        table["views"][view] = rows
    other_keys = [k for k, *_ in METRIC_SPECS if "." not in k]
    table["other"] = [{"label": e["label"], "arm": e.get("arm"), "cells": {k: e["metrics"][k] for k in other_keys},
                       "deltas": {k: (None if e is ref else diff_value(e["metrics"][k], ref["metrics"][k], SPEC_BY_KEY[k][1])) for k in other_keys}} for e in used]

    pair_notes, pairs, frames = [], {}, {}
    for e in used:
        if e["per_alert_path"] is None:
            pair_notes.append(e["label"] + ": no per_alert.csv in " + e["eval_dir"] + ", so no paired comparison")
            continue
        try:
            frames[e["label"]] = load_per_alert(e["per_alert_path"])
        except (OSError, ValueError) as error:
            pair_notes.append(e["label"] + ": per_alert.csv could not be used (" + str(error)[:120] + ")")
    for e in used:
        if e is ref or e["label"] not in frames or reference_label not in frames:
            continue
        pairs[e["label"]] = paired(frames[e["label"]], frames[reference_label])
    common = None
    for df in frames.values():
        valid = set(df.index[df["has_verdict"]])
        common = valid if common is None else common & valid
    common_rows = []
    if common is not None and frames:
        ordered = sorted(common)
        for e in used:
            if e["label"] in frames:
                m = metrics_on(frames[e["label"]].loc[ordered])
                common_rows.append({"label": e["label"], "arm": e.get("arm"), "metrics": m})

    repeats = {}
    for arm in sorted({e.get("arm") for e in used if e.get("arm")}):
        group = [e for e in used if e.get("arm") == arm]
        if len(group) >= 2:
            gap = {}
            for key in ("failures_wrong.f1", "failures_wrong.recall", "failures_wrong.specificity", "attack_type_all", "mitre_all", "parse_failures", "total_tokens", "model_calls"):
                vals = [g["metrics"][key]["value"] for g in group if g["metrics"].get(key) and g["metrics"][key].get("value") is not None]
                if len(vals) >= 2:
                    gap[key] = {"min": min(vals), "max": max(vals), "range": max(vals) - min(vals), "n_observations": len(vals), "kind": SPEC_BY_KEY[key][1]}
            repeats[arm] = {"labels": [g["label"] for g in group], "gaps": gap}

    baseline = None
    if baseline_summary is not None:
        rows = {r.get("key"): r for r in baseline_summary.get("headline", []) if isinstance(r, dict)}
        baseline = {"source_runs": baseline_summary.get("runs"), "prompt_version": baseline_summary.get("prompt_version"), "n_alerts": baseline_summary.get("n_alerts"),
                    "rows": {k: {kk: rows[k].get(kk) for kk in ("label", "unit", "mean", "min", "max", "range", "n_present")} for k in BASELINE_KEYS if k in rows}}
    return {"table": table, "paired": pairs, "paired_notes": pair_notes, "common_valid": {"alerts": None if common is None else len(common), "rows": common_rows}, "repeats": repeats,
            "baseline_noise": baseline, "used": [e["label"] for e in used], "excluded": excluded}


# ------------------------------------------------------------------------------------------------ markdown
LIMITATIONS = [
    "Dev set only (300 alerts). Nothing here is an independent evaluation: the dev set was used while building the agent, and no number from it is a resume claim.",
    "One run per arm unless the repeats section says otherwise. With the same prompt and settings the baseline's three runs disagreed on 5 of 298 decisions and 21 attack types, so a difference of a few alerts is within what repeating a run can produce.",
    "Parse failures are not spread evenly over the classes, so the valid_only view compares different alert sets across arms. The failures_wrong view and the common-valid table keep the set fixed.",
    "A specialist that is switched off is shown to the model as 'disabled in this configuration'. The model sees that a source of evidence is absent, which a run that never had it would not say.",
    "Switching off the traffic analyst also removes the beaconing analyst (its repeat-contact gate reads the traffic evidence). Arm D is therefore enrichment only, not 'beaconing without traffic'.",
    "The McNemar p-values are descriptive and uncorrected for the number of arms. They are not significance claims.",
    "Gemini model behaviour can change between days under the same model name. Runs made on different days are not guaranteed to be on the same service state.",
]


def md_table(header, rows):
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"] * len(header)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return lines


def render(result, entries, generated):
    t = result["table"]
    L = ["# Week 3 Day 6: specialist ablation table (DEV set, descriptive)", "",
         "Generated " + generated + " from the runs and evaluations listed below. Only measured values appear. Every ratio shows its numerator and denominator. Differences are arm minus reference "
         "(percentage points for fractions). The arms were fixed before any result existed; Day 7 locks the full graph whatever this table shows.", "",
         "Reference: **" + t["reference"] + "**. Arms: " + "; ".join(k + " = " + v["label"] for k, v in ablation.ARMS.items()) + ".", ""]
    L += ["## 1. Runs", ""]
    rows = []
    for e in entries:
        meta = e.get("meta", {})
        git = e.get("git") or {}
        state = "used" if e["label"] in result["used"] else "NOT USED"
        rows.append([e["label"], str(e.get("arm") or "-"), "`" + str(e.get("run_name")) + "`", str(meta.get("status", "?")), str(e.get("alerts_evaluated")) + "/" + str(e.get("alerts_expected")),
                     str(meta.get("model")), str(meta.get("prompt_version")) + " " + str(meta.get("prompt_sha256"))[:10], str(git.get("commit")) + (" (dirty)" if git.get("dirty") else ""), state])
    L += md_table(["label", "arm", "run", "status", "alerts", "model", "prompt", "git", "in table"], rows) + [""]
    for e in entries:
        if e.get("provenance"):
            L.append("- " + e["label"] + ": " + e["provenance"])
    L.append("")
    for view in VIEWS:
        L += ["## 2" + "abc"[VIEWS.index(view)] + ". View `" + view + "`", "", VIEW_NOTES[view], ""]
        keys = [k for k, *_ in METRIC_SPECS if k.startswith(view + ".")]
        header = ["arm", "run"] + [SPEC_BY_KEY[k][0] for k in keys]
        rows = []
        for row in t["views"][view]:
            rows.append([str(row["arm"] or "-"), row["label"]] + [fmt(row["cells"][k], SPEC_BY_KEY[k][1]) for k in keys])
            if any(d is not None for d in row["deltas"].values()):
                rows.append(["", "&nbsp;&nbsp;vs reference"] + [fmt_diff(row["deltas"][k], SPEC_BY_KEY[k][1]) for k in keys])
        L += md_table(header, rows) + [""]
    L += ["## 3. Attack type, MITRE, reliability and cost", ""]
    keys = [k for k, *_ in METRIC_SPECS if "." not in k]
    header = ["arm", "run"] + [SPEC_BY_KEY[k][0] for k in keys]
    rows = []
    for row in t["other"]:
        rows.append([str(row["arm"] or "-"), row["label"]] + [fmt(row["cells"][k], SPEC_BY_KEY[k][1]) for k in keys])
        if any(d is not None for d in row["deltas"].values()):
            rows.append(["", "&nbsp;&nbsp;vs reference"] + [fmt_diff(row["deltas"][k], SPEC_BY_KEY[k][1]) for k in keys])
    L += md_table(header, rows) + [""]
    L += ["## 4. Paired comparison with the reference (same alerts)", "",
          "For each alert, whether the reference and the arm were each right. Only the alerts where they differ carry information about the arm. The p-value is an exact McNemar test, descriptive and uncorrected.", ""]
    if result["paired"]:
        rows = []
        for label, p in result["paired"].items():
            d, a = p["decision"], p["attack_type"]
            rows.append([label, str(p["alerts_compared"]), str(d["reference_only_correct"]), str(d["arm_only_correct"]), format(d["mcnemar_exact_p_descriptive"], ".3f"),
                         str(a["reference_only_correct"]), str(a["arm_only_correct"]), format(a["mcnemar_exact_p_descriptive"], ".3f")])
        L += md_table(["arm", "alerts", "decision: only reference right", "decision: only arm right", "p", "type: only reference right", "type: only arm right", "p"], rows) + [""]
    else:
        L += ["No paired comparison (fewer than two usable runs with a per_alert.csv).", ""]
    for note in result["paired_notes"]:
        L.append("- " + note)
    L += ["", "## 5. The same metrics on the alerts every arm answered", ""]
    cv = result["common_valid"]
    if cv["rows"]:
        L += ["Alerts with a valid verdict in every arm in the table: " + str(cv["alerts"]) + ". This removes the effect of different parse failures.", ""]
        rows = []
        for r in cv["rows"]:
            m = r["metrics"]
            rows.append([str(r["arm"] or "-"), r["label"], fmt(m["precision"], "frac"), fmt(m["recall"], "frac"), fmt(m["f1"], "number"), fmt(m["specificity"], "frac"), fmt(m["attack_type"], "frac")])
        L += md_table(["arm", "run", "precision", "recall", "F1", "specificity", "attack-type accuracy"], rows) + [""]
    else:
        L += ["Not available (no per_alert.csv).", ""]
    L += ["## 6. How much could repeating a run change a number?", ""]
    if result["repeats"]:
        L += ["Arms with more than one observation (two observations give a gap, not a spread estimate):", ""]
        for arm, info in result["repeats"].items():
            L.append("- arm " + arm + " (" + ", ".join(info["labels"]) + "): " + "; ".join(k + " range " + fmt_diff(v["range"] if v["kind"] not in ("frac",) else v["range"] * 100, v["kind"]).lstrip("+") for k, v in info["gaps"].items()))
        L.append("")
    else:
        L += ["No arm has a repeated observation in this table.", ""]
    if result["baseline_noise"]:
        b = result["baseline_noise"]
        L += ["Yardstick from the baseline (" + str(b["prompt_version"]) + ", " + str(len(b["source_runs"] or [])) + " runs of " + str(b["n_alerts"]) + " alerts). A different prompt, so only a rough guide to how much one prompt's numbers move between runs:", ""]
        rows = []
        for k, v in b["rows"].items():
            kind = v["unit"] if v["unit"] in ("frac", "pct", "number", "seconds") else "count"
            rng = (v["range"] * 100 if kind == "frac" else v["range"]) if v["range"] is not None else None
            rows.append([v["label"] or k, fmt({"value": v["mean"]}, kind), fmt({"value": v["min"]}, kind), fmt({"value": v["max"]}, kind), fmt_diff(rng, kind).lstrip("+") if rng is not None else "n/a"])
        L += md_table(["baseline metric", "mean", "min", "max", "range"], rows) + [""]
    L += ["## 7. Runs not in the tables", ""]
    if result["excluded"]:
        for e in result["excluded"]:
            reasons = list(e.get("incomplete_reasons") or []) + list(e.get("problems") or []) + (["not comparable: " + "; ".join(e["differences"])] if e.get("comparable") is False else [])
            L.append("- **" + e["label"] + "** (`" + str(e.get("run_name")) + "`): " + "; ".join(reasons))
    else:
        L.append("None: every listed run is complete and comparable.")
    L += ["", "## 8. Limits", ""] + ["- " + x for x in LIMITATIONS] + [""]
    return "\n".join(L)


# ------------------------------------------------------------------------------------------------ main
def parse_args(argv):
    p = argparse.ArgumentParser(description="Week 3 Day 6: the ablation table from finished runs and their evaluations. Reads harness outputs only.")
    p.add_argument("--run", nargs=3, action="append", metavar=("LABEL", "RUN_DIR", "EVAL_DIR"), required=True)
    p.add_argument("--reference", required=True, help="the LABEL of the reference run (arm A on the final code)")
    p.add_argument("--out-dir", required=True, help="a new folder; an existing one is refused")
    p.add_argument("--baseline-summary", default=None, help="reports/week2_day6/three_run_summary.json, for the baseline spread yardstick")
    args = p.parse_args(argv)
    labels = [r[0] for r in args.run]
    if len(set(labels)) != len(labels):
        p.error("run labels must be unique")
    if args.reference not in labels:
        p.error("--reference must be one of the run labels: " + ", ".join(labels))
    if os.path.exists(args.out_dir):
        p.error(args.out_dir + " already exists; this script never overwrites a report")
    return args


def main(argv=None, say=print):
    args = parse_args(argv)
    entries = [load_entry(label, run_dir, eval_dir) for label, run_dir, eval_dir in args.run]
    ref = next(e for e in entries if e["label"] == args.reference)
    if not ref["complete"]:
        raise SystemExit("STOPPED: the reference run is not complete and usable: " + "; ".join(list(ref.get("incomplete_reasons") or []) + list(ref.get("problems") or [])))
    baseline = None
    if args.baseline_summary:
        baseline = read_json(args.baseline_summary)
    result = build(entries, args.reference, baseline)
    generated = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    text = render(result, entries, generated)
    os.makedirs(args.out_dir)
    with open(os.path.join(args.out_dir, "ablation_table.md"), "w", encoding="utf-8") as f:
        f.write(text + "\n")
    excluded = [{"label": e["label"], "run_name": e.get("run_name"), "incomplete_reasons": e.get("incomplete_reasons"), "problems": e.get("problems"), "differences": e.get("differences")} for e in result["excluded"]]
    out = {"generated_utc": generated, "reference": args.reference, "used": result["used"], "excluded": excluded, "table": result["table"], "paired": result["paired"], "paired_notes": result["paired_notes"],
           "common_valid": result["common_valid"], "repeats": result["repeats"], "baseline_noise": result["baseline_noise"],
           "inputs": [{"label": e["label"], "run_dir": e["run_dir"], "eval_dir": e["eval_dir"]} for e in entries]}
    with open(os.path.join(args.out_dir, "ablation_table.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True, default=str)
    say("wrote " + os.path.join(args.out_dir, "ablation_table.md") + " and ablation_table.json; runs in the table: " + ", ".join(result["used"]) + ("; not used: " + ", ".join(e["label"] for e in result["excluded"]) if result["excluded"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
