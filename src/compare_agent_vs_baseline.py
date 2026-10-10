"""Week 3 Day 5: put one evaluated agent run next to the locked baseline_v3 run, metric by metric.

  python src/evaluate.py --run-name dev_flash_lite_v3_final                                      # (Week 2; already done)
  python src/evaluate.py --run-name dev_agent_v1_flash_lite --runs-dir runs/week3_agent_v1       # score the agent run first
  python src/compare_agent_vs_baseline.py --agent-run dev_agent_v1_flash_lite

THIS SCRIPT READS NO LABELS. It reads only the two runs' evaluation.json (the numbers the Week 2 evaluator already computed, the only place labels are used)
and their run_meta.json. It never calls a model, never opens the frozen set, and does not read per_alert.csv (that file holds the true labels).

It refuses to compare unless the two runs are comparable:
  * both evaluations passed their integrity checks and were not --allow-partial; both runs are complete dev runs;
  * the baseline is a baseline_v3 run with the registered prompt hash, the agent run is an agent_v1 run with the registered agent prompt hash;
  * the agent run is a real run (not --fake-model), made by run_agent_dev;
  * same model, same generation settings (the request rate may differ), same input file hashes, same alert list, same protected evaluation files.
The table lists agent minus baseline for every metric, in the evaluator's own numbers. It does not call anything "better" or "improved": that needs more than one run each
(see the Week 2 Day 6 replicate spread) and is for the person reading the result to decide.

With --three-run-summary <file> (the Week 2 Day 6 three_run_summary.json) each row also shows the baseline's own three-run mean and min-max range, and whether the agent run's value
falls inside, above or below that range. That is the baseline's observed run-to-run spread, not a significance test. The summary is refused unless it is for the same
baseline_v3 prompt hash, model, settings and alert count, and its inputs were unchanged.

Writes reports/week3_day5/<agent-run>_vs_<baseline-run>/  COMPARISON_REPORT.md, comparison_metrics.csv, comparison.json
"""
import os
import sys
import csv
import json
import hashlib
import argparse
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
import prompt_registry
import day6_aggregate as agg
from agents import verdict_prompt

DEFAULT_BASELINE_RUN = "dev_flash_lite_v3_final"
EVAL_ROOT = os.path.join(config.REPORTS_DIR, "week2_eval")
BASELINE_RUNS_ROOT = os.path.join(config.PROJECT_ROOT, "runs", "week2_baseline_v1")
AGENT_RUNS_ROOT = os.path.join(config.PROJECT_ROOT, "runs", "week3_agent_v1")
OUT_ROOT = os.path.join(config.REPORTS_DIR, "week3_day5")
OUTPUT_FILES = ["COMPARISON_REPORT.md", "comparison_metrics.csv", "comparison.json"]
SETTING_KEYS = ["temperature", "max_output_tokens", "seed", "parse_retries"]   # compared; the request timeout, transport retries and rate are shown but not compared
SHOWN_KEYS = SETTING_KEYS + ["timeout_seconds", "transport_retries", "requests_per_minute"]


class ComparisonError(Exception):
    pass


def load_spread(path, agent):
    """The Day 6 three-run summary as {key: {mean, min, max, n_present}}, after checking it belongs to the same baseline_v3 setup as the agent run."""
    if not os.path.exists(path):
        raise ComparisonError("missing the three-run summary: " + path)
    with open(path, "r", encoding="utf-8") as f:
        summary = json.load(f)
    problems = []
    if summary.get("prompt_version") != prompt_registry.V3 or summary.get("prompt_sha256") != prompt_registry.get_prompt(prompt_registry.V3).sha256:
        problems.append("the three-run summary is not for baseline_v3 with the registered prompt hash")
    am = agent["meta"]
    if summary.get("model") != am.get("model"):
        problems.append("the three-run summary used model " + str(summary.get("model")) + ", the agent run " + str(am.get("model")))
    for key in SETTING_KEYS:
        if (summary.get("settings") or {}).get(key) != (am.get("settings") or {}).get(key):
            problems.append("setting " + key + " differs: three-run summary " + str((summary.get("settings") or {}).get(key)) + ", agent " + str((am.get("settings") or {}).get(key)))
    if summary.get("n_alerts") != len(am.get("selected_alert_ids", [])):
        problems.append("the three-run summary covers " + str(summary.get("n_alerts")) + " alerts, the agent run " + str(len(am.get("selected_alert_ids", []))))
    if summary.get("inputs_unchanged") is not True:
        problems.append("the three-run summary does not record unchanged inputs")
    if not isinstance(summary.get("headline"), list):
        problems.append("the three-run summary has no headline list")
    if problems:
        raise ComparisonError("the three-run summary cannot be used:\n- " + "\n- ".join(problems))
    spread = {}
    for item in summary["headline"]:
        if isinstance(item, dict) and "key" in item:
            spread[item["key"]] = {"mean": item.get("mean"), "min": item.get("min"), "max": item.get("max"), "n_present": item.get("n_present")}
    return {"runs": summary.get("runs"), "file_sha256": file_sha256(path), "metrics": spread}


def position(value, spread):
    """inside / above / below the baseline's three-run min-max range, or n/a."""
    if value is None or spread is None or spread.get("min") is None or spread.get("max") is None or not spread.get("n_present"):
        return "n/a"
    if value < spread["min"] - 1e-12:
        return "below range"
    if value > spread["max"] + 1e-12:
        return "above range"
    return "inside range"


def load_run(name, eval_root, runs_root):
    """evaluation.json and run_meta.json for one run. Nothing else is read."""
    eval_path = os.path.join(eval_root, name, "evaluation.json")
    meta_path = os.path.join(runs_root, name, "run_meta.json")
    for label, path, hint in (("evaluation.json", eval_path, "Run python src/evaluate.py --run-name " + name), ("run_meta.json", meta_path, "Check --runs-root / --baseline-runs-root")):
        if not os.path.exists(path):
            raise ComparisonError("missing " + label + " for run " + name + ": " + path + ". " + hint)
    with open(eval_path, "r", encoding="utf-8") as f:
        evaluation = json.load(f)
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    return {"name": name, "evaluation": evaluation, "meta": meta, "paths": {"evaluation.json": eval_path, "run_meta.json": meta_path}}


def file_sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def check_pair(baseline, agent):
    """A list of problems. An empty list means the two runs may be compared."""
    problems = []
    for role, run in (("baseline", baseline), ("agent", agent)):
        ev, meta, name = run["evaluation"], run["meta"], run["name"]
        integ = ev.get("integrity", {})
        for key in ("run_unchanged", "protected_unchanged", "frozen_log_unchanged"):
            if integ.get(key) is not True:
                problems.append(role + " " + name + ": evaluation integrity check '" + key + "' is not True")
        if ev.get("allow_partial"):
            problems.append(role + " " + name + ": evaluated with --allow-partial; both runs must be complete")
        if meta.get("status") != "complete":
            problems.append(role + " " + name + ": run status is '" + str(meta.get("status")) + "', not complete")
        if meta.get("set") != "dev":
            problems.append(role + " " + name + ": run set is '" + str(meta.get("set")) + "', not dev")
        if meta.get("frozen_access_log_unchanged") is not True or meta.get("week1_files_unchanged") is not True:
            problems.append(role + " " + name + ": the run recorded a changed frozen access log or Week 1 file")
        if agg.get_path(ev, ("metrics", "population", "alerts")) != len(meta.get("selected_alert_ids", [])):
            problems.append(role + " " + name + ": evaluated population differs from the run's alert list")
    bm, am = baseline["meta"], agent["meta"]
    if bm.get("prompt_version") != prompt_registry.V3 or bm.get("prompt_sha256") != prompt_registry.get_prompt(prompt_registry.V3).sha256:
        problems.append("baseline " + baseline["name"] + ": not a baseline_v3 run with the registered prompt hash")
    if am.get("runner") != "run_agent_dev":
        problems.append("agent " + agent["name"] + ": not made by run_agent_dev")
    if am.get("fake_model") is not False:
        problems.append("agent " + agent["name"] + ": fake_model is not False; a fake run cannot be compared")
    if am.get("prompt_version") != verdict_prompt.VERSION or am.get("prompt_sha256") != verdict_prompt.prompt_sha256():
        problems.append("agent " + agent["name"] + ": not an " + verdict_prompt.VERSION + " run with the registered agent prompt hash")
    if baseline["name"] == agent["name"]:
        problems.append("the same run was given twice")
    if bm.get("model") != am.get("model"):
        problems.append("the models differ: baseline " + str(bm.get("model")) + ", agent " + str(am.get("model")))
    if bm.get("provider") != am.get("provider"):
        problems.append("the providers differ")
    for key in SETTING_KEYS:
        if (bm.get("settings") or {}).get(key) != (am.get("settings") or {}).get(key):
            problems.append("setting " + key + " differs: baseline " + str((bm.get("settings") or {}).get(key)) + ", agent " + str((am.get("settings") or {}).get(key)))
    if bm.get("inputs") != am.get("inputs"):
        problems.append("the input file hashes differ")
    if bm.get("selected_alert_ids") != am.get("selected_alert_ids"):
        problems.append("the alert lists differ")
    if baseline["evaluation"].get("protected_file_sha256") != agent["evaluation"].get("protected_file_sha256"):
        problems.append("the protected evaluation files differ between the two evaluations")
    return problems


def delta(unit, b, a):
    """agent minus baseline, in the unit's own terms. None when either value is missing."""
    if b is None or a is None:
        return None
    return a - b


def display_delta(unit, d):
    if d is None:
        return "n/a"
    sign = "+" if d > 0 else ""
    if unit == "frac":
        return sign + format(d * 100, ".2f") + " pp"
    if unit == "pct":
        return sign + format(d, ".2f") + " pp"
    if unit in ("count", "tokens"):
        return sign + format(int(round(d)), ",") if float(d).is_integer() else sign + format(d, ",.2f")
    if unit == "seconds":
        return sign + format(d, ".3f")
    return sign + format(d, ".4f")


def metric_rows(baseline, agent, spread=None):
    rows = []
    for key, label, path, unit in agg.metric_specs():
        b, a = agg.get_path(baseline["evaluation"], path), agg.get_path(agent["evaluation"], path)
        d = delta(unit, b, a)
        row = {"key": key, "metric": label, "unit": unit, "baseline": b, "agent": a, "agent_minus_baseline": d,
               "baseline_display": agg.display_value(b, unit), "agent_display": agg.display_value(a, unit), "delta_display": display_delta(unit, d)}
        if spread is not None:
            s = spread["metrics"].get(key)
            row["baseline_3run_mean"] = None if s is None else s["mean"]
            row["baseline_3run_min"] = None if s is None else s["min"]
            row["baseline_3run_max"] = None if s is None else s["max"]
            row["baseline_3run_mean_display"] = agg.display_value(row["baseline_3run_mean"], unit)
            row["baseline_3run_range_display"] = "n/a" if s is None or s["min"] is None else agg.display_value(s["min"], unit) + " to " + agg.display_value(s["max"], unit)
            row["agent_vs_baseline_range"] = position(a, s)
        rows.append(row)
    return rows


def describe_run(run):
    m = run["meta"]
    return {"run": run["name"], "prompt_version": m.get("prompt_version"), "prompt_sha256": m.get("prompt_sha256"), "model": m.get("model"), "provider": m.get("provider"),
            "settings": {k: (m.get("settings") or {}).get(k) for k in SHOWN_KEYS}, "alerts": len(m.get("selected_alert_ids", [])),
            "git_commit": (m.get("git") or {}).get("commit"), "git_dirty": (m.get("git") or {}).get("dirty"), "sessions": len(m.get("sessions", [])),
            "evaluation_file_sha256": file_sha256(run["paths"]["evaluation.json"]), "run_meta_sha256": file_sha256(run["paths"]["run_meta.json"])}


def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"] * len(header)) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


def render_report(baseline, agent, rows, generated, spread=None):
    bd, ad = describe_run(baseline), describe_run(agent)
    lines = ["# Agent vs baseline: dev set comparison", "",
             "Generated " + generated + " by src/compare_agent_vs_baseline.py. Reads evaluation.json and run_meta.json only; no labels, no model call, no frozen set.", "",
             "## The two runs", "",
             md_table(["", "Baseline", "Agent"], [
                 ["Run", bd["run"], ad["run"]],
                 ["Prompt version", bd["prompt_version"], ad["prompt_version"]],
                 ["Prompt sha256", bd["prompt_sha256"], ad["prompt_sha256"]],
                 ["Model", bd["model"], ad["model"]],
                 ["Alerts", bd["alerts"], ad["alerts"]],
                 ["Temperature / max output tokens / seed", " / ".join(str(bd["settings"][k]) for k in ("temperature", "max_output_tokens", "seed")),
                  " / ".join(str(ad["settings"][k]) for k in ("temperature", "max_output_tokens", "seed"))],
                 ["Parse retries / transport retries", str(bd["settings"]["parse_retries"]) + " / " + str(bd["settings"]["transport_retries"]), str(ad["settings"]["parse_retries"]) + " / " + str(ad["settings"]["transport_retries"])],
                 ["Requests per minute (may differ)", bd["settings"]["requests_per_minute"], ad["settings"]["requests_per_minute"]],
                 ["Git commit at run time", str(bd["git_commit"]) + (" (dirty)" if bd["git_dirty"] else ""), str(ad["git_commit"]) + (" (dirty)" if ad["git_dirty"] else "")],
                 ["evaluation.json sha256", bd["evaluation_file_sha256"], ad["evaluation_file_sha256"]],
             ]), "",
             "What differs on purpose: the prompt, and the evidence the model is shown. The baseline sees the alert and a four-number context summary. "
             "The agent sees the alert and the specialist findings (traffic, beaconing timing when the routing gate opened, enrichment reference context). Model, settings and alert list are the same.", "",
             "## Comparability checks", "", "All passed: integrity of both evaluations, complete dev runs, registered prompt hashes, a real (not fake) agent run, same model, settings, inputs, alert list and protected files.", "",
             "## Metrics (agent minus baseline, in the evaluator's own numbers)", "",
             md_table(["Metric", "Baseline", "Agent", "Agent minus baseline"], [[r["metric"], r["baseline_display"], r["agent_display"], r["delta_display"]] for r in rows]), ""]
    if spread is not None:
        lines += ["## Against the baseline's three-run spread (Week 2 Day 6)", "",
                  "Baseline runs in the spread: " + ", ".join(str(n) for n in (spread.get("runs") or [])) + ". Summary file sha256 " + spread["file_sha256"] + ". "
                  "The range is the lowest and highest value those three baseline runs gave. Inside the range means the agent run is within what the baseline did on its own from run to run; "
                  "above or below means outside it. This is one agent run, so it is not a significance test, and for rows where a lower number is the goal, or where the number is only context (tokens, latency, calls), the direction means nothing by itself.", "",
                  md_table(["Metric", "Baseline 3-run mean", "Baseline 3-run range", "Agent (this run)", "Agent vs range"],
                           [[r["metric"], r["baseline_3run_mean_display"], r["baseline_3run_range_display"], r["agent_display"], r["agent_vs_baseline_range"]] for r in rows]), ""]
    summary = (agent["meta"].get("agent") or {}).get("summary")
    if summary:
        lines += ["## Agent run context (from the agent run's run_meta.json)", "",
                  "- Graph statuses: " + json.dumps(summary.get("graph_status_counts")), "- Error codes: " + json.dumps(summary.get("error_code_counts")),
                  "- Agent paths: " + json.dumps(summary.get("path_counts")), "- Tool calls: " + str(summary.get("tool_calls")),
                  "- Whole-alert time, tools and model, summed (s): " + str(summary.get("graph_seconds_total")) + ". The latency rows above count model-call time only, the same definition for both runs.", ""]
    lines += ["## How to read this", "",
              "- This is one run of each on the 300 dev alerts. It gives no estimate of run-to-run variation. Week 2 Day 6 measured the baseline's variation over three replicates; a difference inside that spread is not evidence of anything.",
              "- Percentages are of the evaluator's own denominators (see EVALUATION_REPORT.md of each run). Attack-type and MITRE accuracy have two versions: on attacks with a valid verdict, and on all attacks with a missing verdict counted wrong. Compare the same version.",
              "- Differences in coverage or parse failures change those denominators, so read them together with the first rows.",
              "- Dev set only. Nothing here uses the frozen set. A frozen-set result needs the final evaluation procedure.", ""]
    return "\n".join(lines)


def write_outputs(out_dir, baseline, agent, rows, force=False, spread=None):
    existing = [f for f in OUTPUT_FILES if os.path.exists(os.path.join(out_dir, f))]
    if existing and not force:
        raise ComparisonError("output files already exist in " + out_dir + ": " + ", ".join(existing) + ". Use --force to replace them, or --out-dir.")
    os.makedirs(out_dir, exist_ok=True)
    generated = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(os.path.join(out_dir, "COMPARISON_REPORT.md"), "w", encoding="utf-8") as f:
        f.write(render_report(baseline, agent, rows, generated, spread))
    with open(os.path.join(out_dir, "comparison_metrics.csv"), "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        extra = ["baseline_3run_mean", "baseline_3run_min", "baseline_3run_max", "agent_vs_baseline_range"] if spread is not None else []
        writer.writerow(["key", "metric", "unit", "baseline", "agent", "agent_minus_baseline"] + extra)
        for r in rows:
            writer.writerow([r["key"], r["metric"], r["unit"], r["baseline"], r["agent"], r["agent_minus_baseline"]] + [r[name] for name in extra])
    with open(os.path.join(out_dir, "comparison.json"), "w", encoding="utf-8") as f:
        json.dump({"generated_utc": generated, "baseline": describe_run(baseline), "agent": describe_run(agent), "metrics": rows,
                   "baseline_three_run_spread": None if spread is None else {"runs": spread["runs"], "file_sha256": spread["file_sha256"]}, "labels_read": False, "model_called": False, "frozen_set_opened": False},
                  f, indent=2, sort_keys=True, default=str)


def parse_args(argv):
    p = argparse.ArgumentParser(description="Compare one evaluated agent run with the locked baseline_v3 run (evaluation.json and run_meta.json only).")
    p.add_argument("--agent-run", required=True)
    p.add_argument("--baseline-run", default=DEFAULT_BASELINE_RUN)
    p.add_argument("--eval-root", default=EVAL_ROOT, help="folder holding <run>/evaluation.json (default reports/week2_eval)")
    p.add_argument("--baseline-runs-root", default=BASELINE_RUNS_ROOT)
    p.add_argument("--agent-runs-root", default=AGENT_RUNS_ROOT)
    p.add_argument("--out-dir", default=None, help="default reports/week3_day5/<agent-run>_vs_<baseline-run>")
    p.add_argument("--three-run-summary", default=None, help="the Week 2 Day 6 three_run_summary.json: adds the baseline's own mean and min-max range to every row")
    p.add_argument("--force", action="store_true", help="replace existing output files")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        baseline = load_run(args.baseline_run, args.eval_root, args.baseline_runs_root)
        agent = load_run(args.agent_run, args.eval_root, args.agent_runs_root)
        problems = check_pair(baseline, agent)
        if problems:
            raise ComparisonError("these runs cannot be compared:\n- " + "\n- ".join(problems))
        spread = load_spread(args.three_run_summary, agent) if args.three_run_summary else None
        rows = metric_rows(baseline, agent, spread)
        out_dir = args.out_dir or os.path.join(OUT_ROOT, args.agent_run + "_vs_" + args.baseline_run)
        write_outputs(out_dir, baseline, agent, rows, args.force, spread)
    except ComparisonError as error:
        print("STOPPED: " + str(error))
        return 2
    print("Compared " + args.agent_run + " with " + args.baseline_run + ". Output: " + out_dir)
    for r in rows[:5]:
        print("  " + r["metric"] + ": baseline " + r["baseline_display"] + ", agent " + r["agent_display"] + " (" + r["delta_display"] + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
