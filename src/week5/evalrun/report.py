"""Write the machine-readable comparison (comparison.json, comparison_metrics.csv) and the human-readable report. A comparison is written ONLY from validated runs; otherwise the report says NOT COMPARABLE and lists why."""
import csv
import os

import eval_metrics as em

from . import CONFIGS, SCHEMA_RESULTS
from .collect import NONDETERMINISM, utc_now, write_json
from .metrics import dig, scalars_for
from .plan import plan_sha256

KEY_ROWS = [("precision_valid_only", "precision (valid verdicts only)"), ("recall_valid_only", "recall (valid verdicts only)"), ("f1_valid_only", "F1 (valid verdicts only)"),
            ("precision_failures_wrong", "precision (no-verdict counted wrong)"), ("recall_failures_wrong", "recall (no-verdict counted wrong)"), ("f1_failures_wrong", "F1 (no-verdict counted wrong)"),
            ("fp_reduction_pct_failures_escalated", "false-positive reduction % (no-verdict stays escalated)"), ("attacks_missed_failures_escalated", "attacks missed (no-verdict stays escalated)"),
            ("verdict_coverage", "verdict coverage"), ("final_parse_failure_rate", "final parse-failure rate"), ("model_error_rate", "model-error rate"),
            ("attack_type_accuracy_on_valid_attacks", "attack-type accuracy"), ("mitre_accuracy", "MITRE accuracy (all attacks; no-verdict wrong)"),
            ("auto_close_rate", "auto-close rate"), ("review_queue_rate", "review-queue rate"), ("attacks_auto_closed_count", "TRUE ATTACKS AUTO-CLOSED (count)"),
            ("false_positive_rate", "false-positive rate (valid verdicts)"), ("false_negative_rate", "false-negative rate (valid verdicts)"), ("false_negatives_valid_only", "false negatives = missed attacks (valid verdicts)"),
            ("alerts_needing_a_retry", "alerts needing a parse retry"), ("model_calls_total", "model calls (all)"),
            ("latency_median_s", "latency per alert, median (s)"), ("latency_p95_s", "latency per alert, p95 (s)"), ("throughput_alerts_per_s", "throughput (alerts/s)"), ("total_tokens", "total tokens")]
RAW_ROWS = [("precision", "precision"), ("recall", "recall"), ("f1", "F1"), ("specificity", "specificity"), ("false_positives", "false positives"), ("false_negatives", "false negatives")]


COUNTS = {"false_negatives_valid_only", "alerts_needing_a_retry", "model_calls_total", "attacks_missed_failures_escalated", "attacks_auto_closed_count", "total_tokens", "false_positives", "false_negatives"}


def f(v, digits=4, count=False):
    return "n/a" if v is None else (str(int(round(v))) if count else format(v, "." + str(digits) + "f"))


def cell(s, count=False):
    if s is None or s["n"] == 0:
        return "n/a"
    g = lambda x: f(x, 4, count)      # noqa: E731
    return g(s["mean"]) if s["n"] == 1 or s["range"] == 0 else "%s [%s to %s]" % (g(s["mean"]), g(s["min"]), g(s["max"]))


def table(rows, header):
    return "\n".join(["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"] + ["| " + " | ".join(str(c) for c in r) + " |" for r in rows])


def build_result(plan, validation, metrics=None, data_hashes=None):
    return {"schema": SCHEMA_RESULTS, "generated_utc": utc_now(), "plan": plan, "plan_sha256": plan_sha256(plan), "valid": validation["valid"], "problems": validation["problems"],
            "inputs": data_hashes, "runs": {k: {"status": r.status, "run_id": (r.meta or {}).get("run_id")} for k, r in validation["runs"].items()},
            "per_run": (metrics or {}).get("per_run"), "per_config": (metrics or {}).get("per_config"), "nondeterminism": list(NONDETERMINISM)}


def write_csv(result, path):
    rows = []
    if result["valid"]:
        for config in CONFIGS:
            for name, p in scalars_for(config):
                for key, m in result["per_run"].items():
                    if key.startswith(config + "/"):
                        rows.append({"config": config, "run": key.split("/")[1], "metric": name, "value": dig(m, p)})
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=("config", "run", "metric", "value"), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def render(result):
    plan, L = result["plan"], []
    add = L.append
    synthetic = plan["set"] == "fixture" or plan["model"]["fake"]
    add("# Week 5 final-evaluation comparison: raw detector vs single-LLM baseline vs full SOC-Triage system")
    add("")
    if synthetic:
        add("> **REHEARSAL. Synthetic fixture data and a fake model. These numbers exercise the tooling; they say NOTHING about the detector, the baseline or the system. Do not quote them.**")
        add("")
    add("Plan `%s` (SHA-256 `%s`), set **%s**, generated %s. Model: `%s` (temperature %s, max output tokens %s, seed %s, parse retries %s). Detector threshold %s." % (
        plan["plan_id"], result["plan_sha256"], plan["set"], result["generated_utc"], plan["model"]["name"], plan["model"]["temperature"], plan["model"]["max_output_tokens"],
        plan["model"]["seed"], plan["model"]["parse_retries"], plan["threshold"]))
    add("")
    add("## 1. Validity of the comparison")
    add("")
    if not result["valid"]:
        add("**NOT COMPARABLE.** No metric is reported because the runs fail these checks:")
        add("")
        for p in result["problems"]:
            add("- `%s` %s: %s" % (p["code"], p["run"] or "(all runs)", p["detail"]))
        add("")
        add("Run statuses: " + ", ".join("%s=%s" % (k, v["status"]) for k, v in result["runs"].items()))
        return "\n".join(L) + "\n"
    add("All checks passed: nine runs present and complete (three per configuration), no partial folders, file hashes intact, every record well-formed, every run covers exactly the evaluation set's alerts in the "
        "same order, the same input hashes (alerts, labels, flows) in every run, the plan's model and generation settings in every model-based run, the same detector threshold, the same risk policy, "
        "no fake run mixed in, and the raw detector identical in its three runs.")
    add("")
    add(table([(k, v["run_id"]) for k, v in result["runs"].items()], ("run", "unique run id")))
    add("")
    add("Inputs: " + ", ".join("%s=%s" % (k, v) for k, v in (result["inputs"] or {}).items() if k != "flows_sha256") + ".")
    add("")
    add("## 2. Definitions (the project's own, reused)")
    add("")
    add("Positive class = malicious. Every alert in the evaluation set is a detector alert, so the raw detector's decision on every alert is \"malicious\". Three denominator policies handle alerts that received no verdict:")
    add("")
    for k, v in em.POLICIES.items():
        add("- **%s**: %s" % (k, v))
    add("")
    add("A request that failed is never mixed with an ordinary classification error: section 5 lists system failures (parse failure, model unavailable, system error) separately from wrong verdicts. "
        "Recall is measured among alerts the detector already raised; attacks the detector missed are not in the set, so this is not end-to-end recall.")
    add("")
    add("## 3. Raw detector")
    add("")
    pc = result["per_config"]["raw_detector"]["scalars"]
    add(table([(label, cell(pc[name], name in COUNTS)) for name, label in RAW_ROWS], ("metric", "value (3 identical runs)")))
    add("")
    add("## 4. Comparison, mean of three runs [min to max when runs differ]")
    add("")
    rows = []
    for name, label in KEY_ROWS:
        cells = []
        for config in CONFIGS[1:]:
            sc = result["per_config"][config]["scalars"].get(name)
            cells.append(cell(sc, name in COUNTS) if sc is not None else "n/a")
        rows.append((label, *cells))
    add(table(rows, ("metric", "single-LLM baseline", "full system")))
    add("")
    add("Routing and auto-close rows exist only for the full system (the baseline has no routing). Tokens and cost appear only when the provider reported tokens; a fake model reports none. "
        "No significance test is given: three runs of a non-deterministic model cannot support one. Differences smaller than the spread between runs of the same configuration should be read as noise.")
    add("")
    add("## 5. Failures kept apart from classification errors")
    add("")
    rows = []
    for key, m in result["per_run"].items():
        fb = m["failure_breakdown"]
        s = fb["no_verdict_system_failures"]
        rows.append((key, fb["alerts"], fb["valid_verdicts"], s["parse_failure"], s["model_unavailable"], s["system_error"], fb["classification_errors_among_valid_verdicts"],
                     fb["of_which_false_positives"], fb["of_which_false_negatives"]))
    add(table(rows, ("run", "alerts", "valid verdicts", "parse failures", "model unavailable", "system errors", "wrong verdicts", "of which FP", "of which FN")))
    add("")
    add("## 6. Full system: routing")
    add("")
    rows = []
    for i in range(1, plan["runs_per_config"] + 1):
        r = result["per_run"]["full_system/run%d" % i]["routing"]
        rows.append(("run%d" % i, r["counts"]["auto_close"], r["counts"]["escalate"], r["counts"]["needs_review"], r["counts"]["no_routing"], "%d of %d" % (r["true_attacks_auto_closed"]["numerator"], r["true_attacks_auto_closed"]["denominator"]),
                     ", ".join(r["auto_closed_attack_alert_ids"]) or "none"))
    add(table(rows, ("run", "auto_close", "escalate", "needs_review", "no routing", "true attacks auto-closed", "which")))
    add("")
    add("An auto-closed attack is a missed attack; that column is the safety-critical one. Guard signals (full system): " + ", ".join(
        "%s=%s" % (k, v) for k, v in result["per_run"]["full_system/run1"].get("guard_signals", {}).items()) + ("." if result["per_run"]["full_system/run1"].get("guard_signals") else "none."))
    add("")
    add("## 7. Stability across the three runs")
    add("")
    rows = []
    for config in CONFIGS:
        a = result["per_config"][config]["verdict_agreement_across_runs"]
        rows.append((config, a["alerts_identical_in_all_runs"], a["alerts_with_a_different_outcome_in_some_run"], f(a["share_identical"])))
    add(table(rows, ("configuration", "alerts identical in all runs", "alerts that changed", "share identical")))
    add("")
    add("## 8. Per-class results (run 1 of each model-based configuration; the other runs are in comparison.json)")
    add("")
    for config in CONFIGS[1:]:
        add("**%s**" % config)
        add("")
        rows = []
        for label, c in result["per_run"]["%s/run1" % config]["per_class"].items():
            hit = c.get("recall_valid_only") or c.get("specificity_valid_only")
            rows.append((label, c["support"], "attack" if c["is_attack_class"] else "benign", c["no_verdict"], c["called_malicious"], c["called_benign"],
                         ("%s (%s/%s)" % (f(hit["value"]), hit["numerator"], hit["denominator"])) if hit and hit["value"] is not None else "n/a",
                         ("%s" % f(c["attack_type_exact"]["value"])) if c.get("attack_type_exact") and c["attack_type_exact"]["value"] is not None else "-",
                         ", ".join("%s=%s" % kv for kv in sorted((c.get("routing") or {}).items())) or "-"))
        add(table(rows, ("true class", "alerts", "kind", "no verdict", "called malicious", "called benign", "recall (attacks) or specificity (benign)", "attack-type exact", "routing")))
        add("")
    add("A small class has a wide uncertainty: read per-class numbers together with the support column, never alone.")
    add("")
    add("## 9. Sources of non-determinism and other limits")
    add("")
    for line in result["nondeterminism"]:
        add("- " + line)
    add("- The full system and the baseline share one model and one set of generation settings by plan; the full system also makes up to the plan's parse retries per alert and runs the Week 3/4 graph (tools, guard, risk policy).")
    add("- The full system ran with memory `%s` and identifier aliasing `%s` (see the plan); aliasing off keeps prompts byte-identical to the Week 3/4 dev runs, which is safe only because evaluation alert ids are trusted dataset ids." % (
        plan["configs"]["full_system"]["memory"], "on" if plan["configs"]["full_system"]["alias_ids"] else "off"))
    add("- Prompts and raw model replies are not stored in the run folders; their hashes are.")
    add("- Cost: %s." % ("not computed (fake model)" if plan["model"]["fake"] else ("computed from the plan's pricing record" if plan.get("pricing") else "not computed: the plan has no pricing record, and no price is assumed")))
    add("")
    return "\n".join(L) + "\n"


def write_all(result, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    write_json(os.path.join(out_dir, "comparison.json"), result)
    write_csv(result, os.path.join(out_dir, "comparison_metrics.csv"))
    with open(os.path.join(out_dir, "COMPARISON_REPORT.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render(result))
    return ["comparison.json", "comparison_metrics.csv", "COMPARISON_REPORT.md"]
