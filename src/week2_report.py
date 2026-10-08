"""Week 2 Day 7: lock the baseline, write WEEK2_REPORT.md and the locked-baseline record.

  python src/week2_report.py build --v2-run <name of the Day 5 baseline_v2 run>
  python src/week2_report.py verify

build   Collects the facts from files that already exist (run folders, Day 4 evaluation.json files, the Day 6 summary and manifest),
        runs the lock checks, and only if every check passes writes
          WEEK2_REPORT.md                      the final Week 2 report (repository root)
          reports/week2_baseline_lock.json     the locked-baseline record (hashes of the prompt, the baseline source files, the
                                               reference runs, the frozen access log and the Week 1 files)
        Every number in the report is read from those files. Nothing is typed in by hand and no metric is computed from labels here:
        the labels and the MITRE accepted ids reached the numbers only through the Day 4 evaluator. A failed check writes nothing.
verify  Read-only. Recomputes the hashes in the lock record and says whether anything changed since the lock. Exit code 0 = unchanged.

This module makes no model call, reads no label file, no MITRE key and no frozen file (it hashes the frozen access LOG, which is a
text record of accesses, and never opens the frozen data). It changes no run, no prompt and no Week 1 file.
"""
import os
import sys
import json
import hashlib
import argparse
import datetime

import config
import prompt_registry
import baseline_store as store
import run_baseline_dev as runner
import day6_aggregate as agg
import day6_replicates as rep

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPECTED_V3_SHA256 = "9403e7ea1937ff0f0f4b4fba548b58efa93bcc6296daa7326970adbaed1b61b7"
EXPECTED_V1_SHA256 = "0208c856dc1063ef5e249fcffdb28af803bd2899fa87977dde0ac4a23b06f172"
SELECTED = "baseline_v3"
V1_RUN = "dev_flash_lite_v1"
V3_RUN = "dev_flash_lite_v3_final"
D6_RUNS = list(agg.DEFAULT_RUNS)
COMMITS = {"Day 2": "ee44800", "Day 3": "30ab792", "Day 4": "cbb690f", "Day 5": "21a560d", "Day 6": "c78ec4a"}  # as reported by the project owner
LOCKED_SOURCE_FILES = ["src/baseline_prompt.py", "src/prompt_registry.py", "src/verdict_schema.py", "src/verdict_parser.py", "src/gemini_client.py"]
SETTING_KEYS = ["temperature", "max_output_tokens", "seed", "parse_retries"]
REPORT_NAME = "WEEK2_REPORT.md"
LOCK_RELATIVE = os.path.join("reports", "week2_baseline_lock.json")
RUN_FILES = ["results.jsonl", "raw_responses.jsonl", "run_meta.json", "prompt_snapshot.txt", "verdicts.csv"]

TABLE_KEYS = ["coverage", "final_parse_failure", "first_try_malformed", "precision_valid_only", "recall_valid_only", "f1_valid_only",
              "specificity_valid_only", "fp_reduction_valid_only", "f1_failures_escalated", "fp_reduction_failures_escalated", "f1_failures_wrong",
              "attack_type_valid", "attack_type_all", "mitre_valid", "mitre_all", "model_calls_total", "total_tokens", "latency_alert_mean", "latency_alert_max"]
D6_KEYS = ["coverage", "final_parse_failure", "first_try_malformed", "precision_valid_only", "recall_valid_only", "f1_valid_only", "specificity_valid_only",
           "fp_reduction_valid_only", "f1_failures_escalated", "f1_failures_wrong", "attack_type_valid", "attack_type_all", "mitre_valid", "mitre_all",
           "model_calls_total", "total_tokens", "latency_alert_mean", "latency_alert_p95", "latency_alert_max"]
WILSON = [("Precision (valid only)", ("metrics", "verdict", "valid_only", "llm", "precision", "wilson95")),
          ("Recall (valid only)", ("metrics", "verdict", "valid_only", "llm", "recall", "wilson95")),
          ("Specificity (valid only)", ("metrics", "verdict", "valid_only", "llm", "specificity", "wilson95")),
          ("Attack-type accuracy (valid verdicts)", ("metrics", "attack_type", "on_attacks_with_valid_verdict", "wilson95")),
          ("MITRE accepted accuracy (valid verdicts)", ("metrics", "mitre", "accepted_on_attacks_with_valid_verdict", "wilson95")),
          ("Final parse-failure rate", ("metrics", "reliability", "final_parse_failure", "wilson95"))]


class ReportError(Exception):
    pass


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalized_sha256(path):
    """sha256 of a text file with line endings normalized, so a Windows checkout and a Unix checkout agree."""
    with open(path, "rb") as f:
        data = f.read().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def count_lines(path):
    return runner.count_lines(path)


def norm_key(key):
    return str(key).replace("\\", "/")


def norm_files(files):
    kept = {}
    for key, digest in (files or {}).items():
        if norm_key(key) in RUN_FILES:
            kept[norm_key(key)] = digest
    return kept


def replicate_manifest_findings(facts):
    """Compare each Day 6 manifest entry with the replicate folder as it is now.
    A differing entry is accepted as historical only if the manifest itself did not mark it complete, the run's own run_meta.json says
    complete, and run_meta.json records a resume (two or more sessions). Anything else that differs is returned as bad."""
    manifest = facts["d6_manifest"] or {}
    entries = manifest.get("replicates", {})
    bad = []
    historical = []
    for i, r in enumerate(facts["d6"]):
        entry = entries.get(str(i + 1))
        if entry is None:
            continue
        recorded = norm_files(entry.get("run_file_sha256"))
        now = norm_files(facts["run_folder_sha256"].get(r["name"]))
        if recorded == now:
            continue
        sessions = len(r["meta"].get("sessions") or [])
        if entry.get("status") != "complete" and r["meta"].get("status") == "complete" and sessions >= 2:
            historical.append({"name": r["name"], "number": i + 1, "manifest_status": entry.get("status"), "sessions": sessions})
        else:
            bad.append(r["name"])
    return bad, historical


def resumed_replicate_notes(facts):
    bad, historical = replicate_manifest_findings(facts)
    notes = []
    for h in historical:
        notes.append("- **Resumed replicate.** `" + h["name"] + "` was interrupted and resumed (" + str(h["sessions"]) + " sessions in its `run_meta.json`; the project owner reports the interruption was an API failure). "
                     "The Day 6 manifest recorded it before the resume finished (manifest status `" + str(h["manifest_status"]) + "`), so that entry is kept unchanged as historical evidence. "
                     "Its final integrity is verified from the `run_file_sha256` in its post-completion `evaluation.json`, which matches the run folder now.")
    return notes


def replicate_evaluation_findings(facts):
    """Compare each Day 6 replicate folder with the run_file_sha256 its own Day 4 evaluation recorded after the run was complete."""
    bad = []
    for r in facts["d6"]:
        recorded = norm_files(r["evaluation"].get("run_file_sha256"))
        now = norm_files(facts["run_folder_sha256"].get(r["name"]))
        if not recorded or recorded != now:
            bad.append(r["name"])
    return bad


# ------------------------------------------------------------------------------------------------ collecting facts
def load_pair(name, runs_dir, eval_root, how):
    meta_path = os.path.join(runs_dir, name, "run_meta.json")
    eval_path = os.path.join(eval_root, name, "evaluation.json")
    if not os.path.exists(meta_path):
        raise ReportError("the " + how + " run '" + name + "' has no run_meta.json in " + runs_dir)
    if not os.path.exists(eval_path):
        raise ReportError("the " + how + " run '" + name + "' has no Day 4 evaluation. Run: python src/evaluate.py --run-name " + name)
    return {"name": name, "meta": read_json(meta_path), "evaluation": read_json(eval_path), "eval_path": eval_path}


def collect(args, week1_snapshot=None):
    runs_dir, eval_root, day6_dir = args.runs_dir, args.eval_root, args.day6_dir
    facts = {"generated_utc": utc_now(), "root": args.root}
    facts["v1"] = load_pair(args.v1_run, runs_dir, eval_root, "Day 3 baseline")
    facts["v2"] = load_pair(args.v2_run, runs_dir, eval_root, "Day 5 baseline_v2")
    facts["v3"] = load_pair(args.v3_run, runs_dir, eval_root, "Day 5 baseline_v3")
    facts["d6"] = [load_pair(n, runs_dir, eval_root, "Day 6 replicate") for n in args.d6_runs]
    summary_path = os.path.join(day6_dir, "three_run_summary.json")
    manifest_path = os.path.join(os.path.dirname(os.path.abspath(runs_dir)), "week2_day6", "replicates_manifest.json")
    if not os.path.exists(summary_path):
        raise ReportError("no Day 6 summary at " + summary_path + ". Run: python src/day6_aggregate.py")
    facts["d6_summary"] = read_json(summary_path)
    facts["d6_summary_path"] = summary_path
    facts["d6_manifest"] = read_json(manifest_path) if os.path.exists(manifest_path) else None
    facts["manifest_path"] = manifest_path
    facts["registry"] = {v: prompt_registry.get_prompt(v).sha256 for v in prompt_registry.list_versions()}
    facts["frozen_log_path"] = args.frozen_log
    facts["frozen_log_lines"] = count_lines(args.frozen_log)
    facts["frozen_log_sha256"] = normalized_sha256(args.frozen_log) if os.path.exists(args.frozen_log) else None
    facts["unlock_set"] = bool(os.environ.get(config.FROZEN_UNLOCK_ENV))
    facts["week1_now"] = (week1_snapshot or runner.week1_snapshot)()
    facts["source_sha256"] = {rel: normalized_sha256(os.path.join(args.root, rel)) for rel in LOCKED_SOURCE_FILES}
    facts["run_folder_sha256"] = {}
    for name in [args.v1_run, args.v2_run, args.v3_run] + list(args.d6_runs):
        facts["run_folder_sha256"][name] = {k: v for k, v in rep.folder_digest(os.path.join(runs_dir, name)).items() if k in RUN_FILES}
    facts["evaluation_sha256"] = {r["name"]: agg.sha256_file(r["eval_path"]) for r in [facts["v1"], facts["v2"], facts["v3"]] + facts["d6"]}
    facts["git"] = runner.git_info()
    facts["args"] = {"v1_run": args.v1_run, "v2_run": args.v2_run, "v3_run": args.v3_run, "d6_runs": list(args.d6_runs)}
    return facts


# ------------------------------------------------------------------------------------------------ the lock checks
def run_checks(facts):
    """Every check is (name, passed, detail). The report and the lock record are written only if all pass."""
    checks = []

    def add(name, ok, detail=""):
        checks.append({"name": name, "passed": bool(ok), "detail": detail})

    reg = facts["registry"]
    v1, v2, v3, d6 = facts["v1"], facts["v2"], facts["v3"], facts["d6"]
    add("baseline_v3 is the selected baseline and its registry hash is the pinned hash", reg.get(SELECTED) == EXPECTED_V3_SHA256, reg.get(SELECTED, "")[:16])
    add("baseline_v1 registry hash is the pinned hash", reg.get("baseline_v1") == EXPECTED_V1_SHA256, reg.get("baseline_v1", "")[:16])
    add("the Day 5 baseline_v3 run used the pinned hash", v3["meta"].get("prompt_sha256") == EXPECTED_V3_SHA256 and v3["meta"].get("prompt_version") == SELECTED)
    add("the Day 3 baseline run used the pinned v1 hash", v1["meta"].get("prompt_sha256") == EXPECTED_V1_SHA256)
    add("the baseline_v2 run used the registered baseline_v2 hash", v2["meta"].get("prompt_version") == "baseline_v2" and v2["meta"].get("prompt_sha256") == reg.get("baseline_v2"))
    add("all three Day 6 runs used the pinned baseline_v3 hash", all(r["meta"].get("prompt_sha256") == EXPECTED_V3_SHA256 and r["meta"].get("prompt_version") == SELECTED for r in d6))
    add("the Day 6 summary records the pinned hash", facts["d6_summary"].get("prompt_sha256") == EXPECTED_V3_SHA256)
    models = {r["meta"].get("model") for r in [v3] + d6}
    add("baseline_v3 runs (Day 5 and Day 6) used one model", len(models) == 1, ", ".join(sorted(str(m) for m in models)))
    settings = {json.dumps({k: (r["meta"].get("settings") or {}).get(k) for k in SETTING_KEYS}, sort_keys=True) for r in [v3] + d6}
    add("baseline_v3 runs used identical settings", len(settings) == 1)
    add("baseline_v3 runs used the same alert list and inputs",
        len({json.dumps(r["meta"].get("selected_alert_ids")) for r in [v3] + d6}) == 1 and len({json.dumps(r["meta"].get("inputs"), sort_keys=True) for r in [v3] + d6}) == 1)
    everything = [v1, v2, v3] + d6
    add("every run is a complete dev run", all(r["meta"].get("status") == "complete" and r["meta"].get("set") == "dev" for r in everything))
    add("every Day 4 evaluation passed its integrity checks (run, protected files, frozen log)",
        all(all((r["evaluation"].get("integrity") or {}).get(k) is True for k in ("run_unchanged", "protected_unchanged", "frozen_log_unchanged")) for r in everything))
    add("no evaluation was partial", not any(r["evaluation"].get("allow_partial") for r in everything))
    add("no run recorded a changed frozen access log or Week 1 file",
        all(r["meta"].get("frozen_access_log_unchanged") is True and r["meta"].get("week1_files_unchanged") is True for r in everything))
    logs = {r["evaluation"].get("frozen_access_log_lines") for r in everything}
    logs.discard(None)
    add("the frozen access log has the same number of lines now as in every evaluation (frozen set not opened)",
        (len(logs) == 1 and facts["frozen_log_lines"] in logs) if logs else False, "lines now " + str(facts["frozen_log_lines"]) + ", in evaluations " + str(sorted(logs)))
    add("the frozen unlock variable is not set in this shell", not facts["unlock_set"])
    mismatch = []
    week1_now = {norm_key(k): v for k, v in facts["week1_now"].items()}
    compared = 0
    for r in everything:
        recorded = {norm_key(k): v for k, v in (r["evaluation"].get("protected_file_sha256") or {}).items()}
        for key, digest in week1_now.items():
            if key in recorded:
                compared = compared + 1
                if recorded[key] != digest:
                    mismatch.append(r["name"] + ":" + key)
    add("the Week 1 files hash the same now as in every evaluation", not mismatch and compared > 0, ("changed: " + ", ".join(mismatch)) if mismatch else (str(compared) + " hash comparisons"))
    bad_evaluation = replicate_evaluation_findings(facts)
    add("the replicates match the run_file_sha256 recorded by their own post-completion Day 4 evaluation", not bad_evaluation,
        ("differs: " + ", ".join(bad_evaluation)) if bad_evaluation else "3 of 3 match")
    manifest = facts["d6_manifest"]
    if manifest is None:
        add("the Day 6 replicate manifest exists", False, facts["manifest_path"])
    else:
        entries = manifest.get("replicates", {})
        add("the Day 6 manifest holds the pinned hash and three replicate entries",
            manifest.get("prompt_sha256") == EXPECTED_V3_SHA256 and all(str(n) in entries for n in (1, 2, 3)))
        protected_ok = all(facts["run_folder_sha256"].get(name) == {k: v for k, v in digest.items() if k in RUN_FILES} for name, digest in manifest.get("protected_runs", {}).items()
                           if name in facts["run_folder_sha256"])
        add("the Day 3 and Day 5 run folders are unchanged since the Day 6 manifest was written", protected_ok)
        bad_manifest, historical = replicate_manifest_findings(facts)
        if bad_manifest:
            detail = "differs: " + ", ".join(bad_manifest)
        elif historical:
            detail = "; ".join(h["name"] + " entry predates its resume (manifest status " + str(h["manifest_status"]) + ", " + str(h["sessions"]) + " sessions), kept as historical" for h in historical)
        else:
            detail = "3 of 3 match"
        add("the replicates are unchanged since the Day 6 manifest recorded them", not bad_manifest, detail)
    add("the Day 6 summary lists exactly the three runs given", facts["d6_summary"].get("runs") == [r["name"] for r in d6])
    add("the Day 6 summary confirms its inputs were unchanged", facts["d6_summary"].get("inputs_unchanged") is True)
    return checks


# ------------------------------------------------------------------------------------------------ number formatting
def metric_index():
    return {key: (label, path, unit) for key, label, path, unit in agg.metric_specs()}


def value_of(evaluation, key):
    return agg.get_path(evaluation, metric_index()[key][1])


def fmt(value, key):
    return agg.display_value(value, metric_index()[key][2])


def diff_display(a, b, key):
    """b - a, in percentage points for fractions and percentages."""
    if a is None or b is None:
        return "n/a"
    unit = metric_index()[key][2]
    d = b - a
    if unit == "frac":
        return format(d * 100, "+.2f") + " pp"
    if unit == "pct":
        return format(d, "+.2f") + " pp"
    if unit in ("count", "tokens"):
        return format(d, "+,.0f")
    if unit == "seconds":
        return format(d, "+.3f")
    return format(d, "+.4f")


def wilson_display(evaluation, path):
    w = agg.get_path(evaluation, path)
    v = agg.get_path(evaluation, path[:-1] + ("value",))
    if not w or v is None:
        return "n/a"
    return format(v * 100, ".2f") + "% (" + format(w[0] * 100, ".1f") + "-" + format(w[1] * 100, ".1f") + ")"


def intervals_overlap(a, b):
    return not (a[1] < b[0] or b[1] < a[0])


def md_table(header, rows):
    return agg.md_table(header, rows)


def pct_of(a, b):
    return "n/a" if not b else format(100.0 * a / b, ".1f") + "%"


# ------------------------------------------------------------------------------------------------ the report
def render_report(facts, checks):
    v1, v2, v3, d6 = facts["v1"], facts["v2"], facts["v3"], facts["d6"]
    summary = facts["d6_summary"]
    idx = {r["key"]: r for r in summary["headline"]}
    idx_labels = metric_index()
    m3 = v3["meta"]
    settings = {k: (m3.get("settings") or {}).get(k) for k in SETTING_KEYS}
    pop = v3["evaluation"]["metrics"]["population"]
    L = []
    add = L.append
    add("# Week 2 report: single-LLM baseline, locked as baseline_v3")
    add("")
    add("Generated " + facts["generated_utc"] + " by `src/week2_report.py` from the project's own run and evaluation files. Every number below is read from those files; "
        "none was typed in. All results are on the 300-alert **dev** set. The frozen evaluation set was not used.")
    add("")
    add("## 1. Summary")
    add("")
    add("- **Selected baseline: `" + SELECTED + "`**, prompt sha256 `" + EXPECTED_V3_SHA256 + "`. It is **locked** as of this report.")
    add("- Model: `" + str(m3.get("model")) + "` (provider: " + str(m3.get("provider")) + "), settings " + json.dumps(settings, sort_keys=True) + ".")
    add("- Day 5 run `" + v3["name"] + "`: " + fmt(value_of(v3["evaluation"], "coverage"), "coverage") + " valid verdicts, F1 (valid verdicts only) "
        + fmt(value_of(v3["evaluation"], "f1_valid_only"), "f1_valid_only") + ", false-positive reduction " + fmt(value_of(v3["evaluation"], "fp_reduction_valid_only"), "fp_reduction_valid_only")
        + ", attack-type accuracy " + fmt(value_of(v3["evaluation"], "attack_type_valid"), "attack_type_valid") + ", MITRE accepted accuracy "
        + fmt(value_of(v3["evaluation"], "mitre_valid"), "mitre_valid") + ".")
    add("- Day 6, three fresh runs: F1 (valid verdicts only) mean " + agg.display_value(idx["f1_valid_only"]["mean"], "number") + ", range " + agg.display_spread(idx["f1_valid_only"]["range"], "number")
        + "; attack-type accuracy mean " + agg.display_value(idx["attack_type_valid"]["mean"], "frac") + ", range " + agg.display_spread(idx["attack_type_valid"]["range"], "frac")
        + ". Per-run values and the error analysis are in section 7.")
    add("- Frozen evaluation set: **closed**. Week 1 artifacts: **unchanged**. See section 8.")
    add("- Known limits: attack-type classification is weak, MITRE accepted accuracy is imperfect, Bot, DDoS and DoS Hulk are persistently confused, and parse failures remain possible (section 9).")
    add("")
    add("## 2. What Week 2 built")
    add("")
    add(md_table(["Day", "Commit", "Delivered"], [
        ["1", "n/a", "Verdict-input and label separation modules, model configuration for Gemini (no calls)"],
        ["2", COMMITS["Day 2"], "Five-field verdict schema (`is_malicious`, `attack_type`, `mitre_technique`, `severity`, `evidence`) and the strict parser with retries"],
        ["3", COMMITS["Day 3"], "Baseline runner: one plain Gemini call per dev alert, raw responses and results stored per run"],
        ["4", COMMITS["Day 4"], "Evaluation harness: detector-relative metrics under three denominator policies, Wilson intervals, per-alert output, integrity checks"],
        ["5", COMMITS["Day 5"], "Prompt registry (`baseline_v1`, `baseline_v2`, `baseline_v3`), cost tracking, optional metadata-only LangSmith tracing"],
        ["6", COMMITS["Day 6"], "Three fresh `baseline_v3` runs, mean and spread, cross-run error analysis"],
        ["7", "(this commit)", "Baseline lock record, this report, the `week2-baseline` tag"],
    ]))
    add("")
    add("Commit ids are as reported by the project owner; this script does not read the git history.")
    add("")
    add("## 3. The locked baseline")
    add("")
    add("| Item | Value |")
    add("|---|---|")
    add("| Prompt version | `" + SELECTED + "` |")
    add("| Prompt sha256 | `" + EXPECTED_V3_SHA256 + "` |")
    add("| `baseline_v1` sha256 (Day 3 reference) | `" + EXPECTED_V1_SHA256 + "` |")
    add("| `baseline_v2` sha256 | `" + facts["registry"].get("baseline_v2", "") + "` |")
    add("| Provider and model | " + str(m3.get("provider")) + ", `" + str(m3.get("model")) + "` |")
    add("| Settings | " + json.dumps(settings, sort_keys=True) + " |")
    add("| Alerts | " + str(pop["alerts"]) + " dev alerts (" + str(pop["true_attacks"]) + " true attacks, " + str(pop["true_benign"]) + " true benign) |")
    add("| Tools, memory, agents | none: one plain model call per alert |")
    add("")
    add("Locked source files (sha256 of the text with line endings normalized), recorded in `" + LOCK_RELATIVE.replace(os.sep, "/") + "`:")
    add("")
    add(md_table(["File", "sha256"], [[rel, "`" + facts["source_sha256"][rel] + "`"] for rel in LOCKED_SOURCE_FILES]))
    add("")
    add("`python src/week2_report.py verify` recomputes these hashes, the reference run hashes, the frozen access log and the Week 1 files, and fails if anything differs from the lock record. "
        "The test `tests/test_week2_day7.py` runs the same check, so an edit to a locked file fails the test suite.")
    add("")
    add("## 4. How the numbers are defined")
    add("")
    add("- The detector flagged every alert in the dev set, so the model's job is to dismiss false alarms and classify real attacks. Recall and precision are therefore relative to the detector "
        "(the detector raised every attack here) and precision is a property of this sample, which holds " + pct_of(pop["true_benign"], pop["alerts"]) + " false alarms by construction.")
    add("- Three denominator policies from the Day 4 harness: **valid only** (alerts with a valid verdict), **failures escalated** (an alert with no verdict stays raised) and "
        "**failures counted wrong** (a failed alert is always an error). The valid-only figures are the primary ones; the other two show what parse failures cost.")
    add("- Attack-type accuracy is an exact match with the true class. MITRE accepted accuracy counts a technique as correct if it is one of the accepted ids in the evaluation mapping; "
        "that mapping is the evaluation contract, so a rejected technique is not necessarily wrong in an absolute sense.")
    add("- 95% Wilson intervals describe sampling uncertainty on the 300 alerts within one run. Differences between runs are shown separately (section 7).")
    add("")
    add("## 5. Day 3 baseline (`baseline_v1`)")
    add("")
    add("Run `" + v1["name"] + "`, evaluated with the Day 4 harness. This is the reference every later change is compared with.")
    add("")
    keys5 = TABLE_KEYS
    add(md_table(["Metric", "baseline_v1"], [[idx_labels[k][0], fmt(value_of(v1["evaluation"], k), k)] for k in keys5]))
    add("")
    add("## 6. Day 5: `baseline_v1` vs `baseline_v2` vs `baseline_v3`")
    add("")
    add("One dev run of each (`" + v1["name"] + "`, `" + v2["name"] + "`, `" + v3["name"] + "`) on the same 300 alerts. v2 adds an output-format contract to v1; v3 adds general attack-class and MITRE guidance on top. "
        "Differences are shown as computed, not as claims: a single run cannot show that a small difference is real (see the intervals below and section 7).")
    add("")
    rows = []
    for k in keys5:
        a, b, c = value_of(v1["evaluation"], k), value_of(v2["evaluation"], k), value_of(v3["evaluation"], k)
        rows.append([idx_labels[k][0], fmt(a, k), fmt(b, k), fmt(c, k), diff_display(a, c, k), diff_display(b, c, k)])
    add(md_table(["Metric", "v1", "v2", "v3", "v3 - v1", "v3 - v2"], rows))
    add("")
    add("95% Wilson intervals for the primary rates, one run each (an overlap check is a rough guide, not a significance test):")
    add("")
    wrows = []
    for label, path in WILSON:
        w1, w2, w3 = (agg.get_path(r["evaluation"], path) for r in (v1, v2, v3))
        verdict = "n/a" if not (w1 and w3) else ("intervals overlap" if intervals_overlap(w1, w3) else "intervals do not overlap")
        wrows.append([label, wilson_display(v1["evaluation"], path), wilson_display(v2["evaluation"], path), wilson_display(v3["evaluation"], path), verdict])
    add(md_table(["Rate", "v1", "v2", "v3", "v1 vs v3"], wrows))
    add("")
    add("`baseline_v3` was selected from these dev results. Run `" + v3["name"] + "` is the run the choice was made on, so it is not an independent confirmation; that is why Day 6 repeated v3 in three fresh runs.")
    add("")
    add("## 7. Day 6: three fresh runs of `baseline_v3`")
    add("")
    add("Runs " + ", ".join("`" + r["name"] + "`" for r in d6) + ". Same prompt, model, settings, alert list and inputs; each run is its own folder and session. "
        "The settings were not varied, so the spread is how repeatable the service is for the same request. sd is the sample standard deviation (n-1); with three runs it is a rough estimate, so min and max are shown too.")
    add("")
    header = ["Metric"] + [r["name"].replace("dev_flash_lite_v3_", "") for r in d6] + ["mean", "sd", "min", "max", "range", "Day 5 run"]
    rows = []
    for k in D6_KEYS:
        r = idx[k]
        u = r["unit"]
        rows.append([r["label"]] + [agg.display_value(v, u) for v in r["values"]] + [agg.display_value(r["mean"], u), agg.display_spread(r["sd"], u), agg.display_value(r["min"], u),
                                                                                       agg.display_value(r["max"], u), agg.display_spread(r["range"], u), agg.display_value(r["ref"], u)])
    add(md_table(header, rows))
    add("")
    add("Each run's counts: " + "; ".join("`" + r["name"].replace("dev_flash_lite_v3_", "") + "`: " + str(r["meta"]["counts"]["ok"]) + " valid, " + str(r["meta"]["counts"]["parse_failed"]) + " parse failed, "
                                         + str(r["meta"]["counts"]["model_error"]) + " model errors, " + str(r["meta"].get("model_calls")) + " model calls, " + format(r["meta"].get("total_tokens") or 0, ",") + " tokens"
                                         for r in d6) + ".")
    add("")
    add("### Key error-analysis findings")
    add("")
    cats = summary["error_categories"]
    labels = {"false_positive": "False positive (benign called malicious)", "missed_attack": "Missed attack (attack called benign)", "attack_type_error": "Attack-type error (true attacks)",
              "mitre_error": "MITRE error (true attacks)", "no_verdict": "No verdict (parse failure)"}
    add("An alert is **persistent** if it was wrong in every run in which it could be judged, **one-off** if wrong in one run only, and **recurring** if wrong in some runs but not all. "
        "A run with no verdict is a missing answer, not a wrong one.")
    add("")
    add(md_table(["Error kind", "Alerts it applies to", "Wrong in at least one run", "Persistent", "Recurring", "One-off"],
                 [[labels[k], cats[k]["applicable_alerts"], cats[k]["any_error"], cats[k]["persistent"], cats[k]["recurring"], cats[k]["one_off"]] for k in labels]))
    add("")
    var = summary["variation"]
    add("- **Run-to-run variation versus repeated errors.** Among alerts with at least two valid verdicts (" + str(var.get("alerts_with_2plus_valid")) + "), the runs disagreed on attack_type for "
        + str(var.get("attack_type_differs")) + ", on mitre_technique for " + str(var.get("technique_differs")) + " and on the is_malicious decision for " + str(var.get("decision_differs"))
        + " alerts. Of the " + str(cats["attack_type_error"]["any_error"]) + " alerts with an attack-type error in any run, " + str(cats["attack_type_error"]["persistent"]) + " were persistent.")
    per_class = summary["persistent_per_class"]
    ranked = sorted([(c, v) for c, v in per_class.items() if v["persistent"] > 0], key=lambda kv: (-kv[1]["persistent"] / max(1, kv[1]["attacks"]), -kv[1]["persistent"], kv[0]))
    add("- **Persistent attack-type errors by true class** (persistent alerts of attacks in the class): " + "; ".join(c + " " + str(v["persistent"]) + " of " + str(v["attacks"]) for c, v in ranked) + ".")
    conf = summary["persistent_confusions"][:12]
    if conf:
        add("- **Most common persistent confusions** (true class to predicted class, alerts): " + "; ".join(x["true"] + " to " + x["predicted"] + " " + str(x["alerts"]) for x in conf) + ".")
    cons = summary["persistent_type_consistency"]
    if cons:
        add("- When an attack-type error is persistent: " + ", ".join(str(v) + " alerts had the " + k for k, v in cons.items()) + ".")
    ms = summary["persistent_mitre_split"]
    if ms:
        add("- **Persistent MITRE errors:** " + ", ".join(str(v) + " alerts: " + k for k, v in ms.items()) + ".")
    pf = summary["parse_failures"]
    add("- **Parse failures:** " + str(pf["alerts_failed_in_at_least_one_run"]) + " alerts ended without a verdict in at least one run; by number of runs in which they failed: "
        + (", ".join(str(k) + " run(s): " + str(v) for k, v in pf["failed_in_k_runs"].items()) or "none") + ". Final error codes (run-alert pairs): " + json.dumps(pf["final_error_codes"], sort_keys=True) + ".")
    add("- The per-alert detail behind these counts is in `reports/week2_day6/error_patterns.csv` and `reports/week2_day6/per_alert_across_runs.csv`.")
    add("")
    add("## 8. Closure statements and the checks behind them")
    add("")
    add("- **The frozen evaluation set remains CLOSED.** It was not opened in Week 2. Evidence: the frozen access log has " + str(facts["frozen_log_lines"]) + " lines now and the same count was recorded by every Day 4 evaluation "
        "and every run; the unlock variable is not set; no Week 2 module reads a frozen path. The frozen set is opened only through `eval_io.py` for the final evaluation.")
    add("- **Week 1 artifacts remain UNCHANGED.** The protected Week 1 files hash the same now as in every Day 4 evaluation of the runs above (the `week1-freeze` tag is the reference point).")
    add("- **`baseline_v3` is LOCKED after Day 7.** Its prompt hash, the baseline source files and the reference runs are recorded in `" + LOCK_RELATIVE.replace(os.sep, "/") + "`. "
        "Any change to the baseline is a new, separately named and separately evaluated version, never an edit of `baseline_v3`.")
    for note in resumed_replicate_notes(facts):
        add(note)
    add("")
    add(md_table(["Check", "Result", "Detail"], [[c["name"], "PASS" if c["passed"] else "FAIL", c["detail"]] for c in checks]))
    add("")
    add("## 9. Known limitations")
    add("")
    at = idx["attack_type_valid"]
    mt = idx["mitre_valid"]
    pfr = idx["final_parse_failure"]
    add("- **Attack-type classification remains weak.** Exact attack-type accuracy on alerts with a valid verdict averaged " + agg.display_value(at["mean"], "frac") + " over the three Day 6 runs (range "
        + agg.display_spread(at["range"], "frac") + "), and the errors repeat: " + str(cats["attack_type_error"]["persistent"]) + " of " + str(cats["attack_type_error"]["any_error"]) + " alerts with an error were wrong in every run.")
    add("- **MITRE accepted accuracy remains imperfect.** It averaged " + agg.display_value(mt["mean"], "frac") + " (range " + agg.display_spread(mt["range"], "frac") + "). The evaluation "
        "accepts only the ids in its mapping, so the figure measures agreement with that mapping.")
    persistent_named = [c for c in ("Bot", "DDoS", "DoS Hulk") if c in per_class]
    add("- **Persistent Bot, DDoS and DoS Hulk confusion.** Persistent attack-type errors: " + "; ".join(c + " " + str(per_class[c]["persistent"]) + " of " + str(per_class[c]["attacks"]) for c in persistent_named)
        + ". Section 7 lists the confusions. The data do not show why; with flow-level inputs these classes may not be separable, which these runs cannot settle.")
    add("- **Parse failures remain possible.** The final parse-failure rate averaged " + agg.display_value(pfr["mean"], "frac") + " (range " + agg.display_spread(pfr["range"], "frac")
        + "). Alerts without a verdict are reported under all three policies and are never dropped.")
    add("- **One dev set, 300 alerts.** Class-level counts are small. Results say nothing about the frozen set and no frozen-set number exists yet. Recall is detector-relative, and precision reflects the dev set's false-alarm share.")
    add("- **Three runs with fixed settings** measure repeatability of the service, not robustness to prompt changes or to new data.")
    add("- **Selection on dev.** `baseline_v3` was chosen using dev results; the Day 6 fresh runs check repeatability, not generalization.")
    add("- **Cost** is not stated: no verified pricing file was used. Token counts are in section 7.")
    add("")
    add("## 10. Reproduction")
    add("")
    add("```")
    add("python -m unittest tests.test_week2_day1 tests.test_week2_day2 tests.test_week2_day3 tests.test_week2_day4 tests.test_week2_day5 tests.test_week2_day6 tests.test_week2_day7 -v")
    add("python src/evaluate.py --run-name <run>            # per run, Day 4 harness")
    add("python src/day6_aggregate.py                        # three-run mean, spread and error analysis")
    add("python src/week2_report.py verify                   # nothing in the baseline changed since the lock")
    add("```")
    add("")
    add("## 11. Provenance")
    add("")
    add("Inputs read to build this report (sha256 of the evaluation files; run files are in the lock record):")
    add("")
    add(md_table(["Evaluation file", "sha256"], [["reports/week2_eval/" + name + "/evaluation.json", "`" + digest + "`"] for name, digest in facts["evaluation_sha256"].items()]))
    add("")
    add("Day 6 summary: `reports/week2_day6/three_run_summary.json` (`" + agg.sha256_file(facts["d6_summary_path"]) + "`).")
    add("")
    return "\n".join(L)


# ------------------------------------------------------------------------------------------------ the lock record
def lock_record(facts, checks):
    m3 = facts["v3"]["meta"]
    return {
        "locked_utc": facts["generated_utc"], "purpose": "Week 2 locked baseline record. baseline_v3 is locked; a change is a new version, never an edit.",
        "selected_baseline": SELECTED, "prompt_sha256": EXPECTED_V3_SHA256, "baseline_v1_sha256": EXPECTED_V1_SHA256,
        "registry_sha256": facts["registry"], "provider": m3.get("provider"), "model": m3.get("model"),
        "settings": {k: (m3.get("settings") or {}).get(k) for k in SETTING_KEYS},
        "inputs": m3.get("inputs"), "n_alerts": len(m3.get("selected_alert_ids", [])),
        "locked_source_files_sha256": facts["source_sha256"], "source_hash_note": "sha256 of the file with CRLF normalized to LF",
        "reference_runs": {"day3_baseline_v1": facts["args"]["v1_run"], "day5_baseline_v2": facts["args"]["v2_run"], "day5_baseline_v3": facts["args"]["v3_run"], "day6_replicates": facts["args"]["d6_runs"]},
        "run_files_sha256": facts["run_folder_sha256"], "evaluation_sha256": facts["evaluation_sha256"],
        "frozen_access_log": {"lines": facts["frozen_log_lines"], "sha256_normalized": facts["frozen_log_sha256"]},
        "week1_files_sha256": facts["week1_now"],
        "git_at_lock": {"commit": facts["git"].get("commit"), "dirty": facts["git"].get("dirty"), "note": "commit before the Day 7 commit; the week2-baseline tag is placed on the Day 7 commit"},
        "checks": checks,
    }


def verify_lock(lock, root, runs_dir, frozen_log, week1_snapshot=None):
    """Compare the lock record with the current files. Returns a list of (name, passed, detail). Read-only."""
    out = []

    def add(name, ok, detail=""):
        out.append((name, bool(ok), detail))

    reg = {v: prompt_registry.get_prompt(v).sha256 for v in prompt_registry.list_versions()}
    add("baseline_v3 prompt hash equals the locked hash", reg.get(lock["selected_baseline"]) == lock["prompt_sha256"] == EXPECTED_V3_SHA256)
    add("registered prompt hashes equal the locked ones", reg == lock["registry_sha256"])
    for rel, digest in lock["locked_source_files_sha256"].items():
        path = os.path.join(root, rel)
        add("locked source file " + rel, os.path.exists(path) and normalized_sha256(path) == digest)
    for name, files in lock["run_files_sha256"].items():
        now = {k: v for k, v in rep.folder_digest(os.path.join(runs_dir, name)).items() if k in RUN_FILES}
        add("reference run " + name, now == files)
    add("frozen access log unchanged (lines and hash)", count_lines(frozen_log) == lock["frozen_access_log"]["lines"]
        and (normalized_sha256(frozen_log) if os.path.exists(frozen_log) else None) == lock["frozen_access_log"]["sha256_normalized"])
    add("frozen unlock variable not set", not os.environ.get(config.FROZEN_UNLOCK_ENV))
    now1 = (week1_snapshot or runner.week1_snapshot)()
    add("Week 1 files unchanged", now1 == lock["week1_files_sha256"])
    return out


# ------------------------------------------------------------------------------------------------ commands
def build_parser():
    p = argparse.ArgumentParser(description="Week 2 Day 7: lock the baseline and write WEEK2_REPORT.md. No model calls.")
    p.add_argument("action", choices=["build", "verify"])
    p.add_argument("--v2-run", default=None, help="name of the Day 5 baseline_v2 run (required for build)")
    p.add_argument("--v1-run", default=V1_RUN)
    p.add_argument("--v3-run", default=V3_RUN)
    p.add_argument("--d6-runs", nargs="+", default=D6_RUNS)
    p.add_argument("--runs-dir", default=runner.RUNS_ROOT)
    p.add_argument("--eval-root", default=agg.DEFAULT_EVAL_ROOT)
    p.add_argument("--day6-dir", default=agg.DEFAULT_OUT)
    p.add_argument("--frozen-log", default=config.FROZEN_ACCESS_LOG)
    p.add_argument("--root", default=ROOT, help="repository root (where WEEK2_REPORT.md is written)")
    p.add_argument("--force", action="store_true", help="replace an existing report and lock record")
    return p


def do_build(args, week1_snapshot=None, say=print):
    if not args.v2_run:
        say("STOPPED: build needs --v2-run <name of the Day 5 baseline_v2 run>. List the runs with: dir runs\\week2_baseline_v1")
        return 1
    report_path = os.path.join(args.root, REPORT_NAME)
    lock_path = os.path.join(args.root, LOCK_RELATIVE)
    existing = [p for p in (report_path, lock_path) if os.path.exists(p)]
    if existing and not args.force:
        say("STOPPED: already exists: " + ", ".join(existing) + ". The baseline is locked once; use --force only to regenerate before the tag exists.")
        return 1
    try:
        facts = collect(args, week1_snapshot)
    except ReportError as error:
        say("STOPPED: " + str(error))
        return 1
    checks = run_checks(facts)
    for c in checks:
        say(("PASS  " if c["passed"] else "FAIL  ") + c["name"] + ((" [" + c["detail"] + "]") if c["detail"] else ""))
    if not all(c["passed"] for c in checks):
        say("A lock check failed. Nothing was written. Fix the cause (do not edit the checks) and run again.")
        return 1
    report = render_report(facts, checks)
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    with open(lock_path, "w", encoding="utf-8") as f:
        json.dump(lock_record(facts, checks), f, indent="  ")
    say("Wrote " + report_path + " and " + lock_path)
    return 0


def do_verify(args, week1_snapshot=None, say=print):
    lock_path = os.path.join(args.root, LOCK_RELATIVE)
    if not os.path.exists(lock_path):
        say("STOPPED: no lock record at " + lock_path + ". Run build first.")
        return 1
    results = verify_lock(read_json(lock_path), args.root, args.runs_dir, args.frozen_log, week1_snapshot)
    for name, ok, detail in results:
        say(("PASS  " if ok else "FAIL  ") + name + ((" [" + detail + "]") if detail else ""))
    ok = all(r[1] for r in results)
    say("Baseline unchanged since the lock." if ok else "SOMETHING CHANGED since the lock. Do not proceed until it is explained.")
    return 0 if ok else 1


def main(argv=None):
    args = build_parser().parse_args(argv)
    return do_build(args) if args.action == "build" else do_verify(args)


if __name__ == "__main__":
    sys.exit(main())
