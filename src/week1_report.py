"""Write WEEK1_REPORT.md, README.md and HANDOFF.md from the real run artifacts.

Every number comes from a file produced by an earlier step. A missing file is shown as NOT AVAILABLE
and the script exits with code 2 unless --allow-incomplete is given.

  python src/week1_report.py                  writes WEEK1_REPORT.md, HANDOFF.md and reports/README_proposed.md
  python src/week1_report.py --write-readme   writes README.md directly (replaces the current one)
"""
import os
import re
import sys
import json
import argparse
import datetime

import config

parser = argparse.ArgumentParser()
parser.add_argument("--allow-incomplete", action="store_true")
parser.add_argument("--write-readme", action="store_true")
args = parser.parse_args()

missing = []


def read_json(relative):
    path = os.path.join(config.PROJECT_ROOT, relative)
    if not os.path.exists(path):
        missing.append(relative)
        return None
    with open(path, "r") as f:
        return json.load(f)


def read_text(relative):
    path = os.path.join(config.PROJECT_ROOT, relative)
    if not os.path.exists(path):
        missing.append(relative)
        return None
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def pct(x):
    return "n/a" if x is None else "%.4f" % x


def na(text="NOT AVAILABLE"):
    return text


def find_line(text, pattern):
    if text is None:
        return None
    match = re.search(pattern, text, flags=re.MULTILINE)
    return match.group(1).strip() if match else None


def table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for r in rows:
        out.append("| " + " | ".join([str(c) for c in r]) + " |")
    return out


def main():
    cleaning = read_text("reports/cleaning_log.md")
    split_text = read_text("reports/split_report.md")
    baselines = read_json("reports/baseline_metrics.json")
    detector = read_json("reports/detector_metrics.json")
    best = read_json("models/best_params.json")
    ablation = read_text("reports/dest_port_ablation.md")
    threshold = read_json("models/threshold.json")
    manifest = read_json("eval/MANIFEST.json")
    repro = read_json("reports/reproducibility_report.json")
    spot = read_json("reports/spot_check_summary.json")
    test = read_json("reports/test_metrics.json")
    features = read_json("models/feature_list.json")

    raw_rows = find_line(cleaning, r"^Raw rows:\s*(\d+)")
    clean_rows = find_line(cleaning, r"^Saved (\d+) rows")
    feature_count = len(features) if features is not None else None
    decision = find_line(ablation, r"\*\*Decision:\s*([^*]+)\*\*")
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

    r = ["# Week 1 report: data, detector and frozen evaluation sets", "", "Generated " + today + " from the run artifacts listed in each section. "
         "Numbers come from those files. Sections 10 and 11 and the notes are fixed text.", ""]

    r += ["## 1. Outcome", ""]
    rows = [
        ["Cleaned data", (clean_rows + " flows" if clean_rows else na()), "reports/cleaning_log.md"],
        ["Detector (validation PR-AUC)", ("%.5f" % detector["pr_auc"] if detector else na()), "reports/detector_metrics.json"],
        ["Accepted threshold", (repr(threshold["threshold"]) if threshold else na()), "models/threshold.json"],
        ["Dev / frozen set sizes", (str(manifest["sizes"]["dev_target"]) + " / " + str(manifest["sizes"]["frozen_target"]) if manifest else na()), "eval/MANIFEST.json"],
        ["Reproducibility rerun", (repro["status"] + " (" + repro["mode"] + ")" if repro else na()), "reports/reproducibility_report.md"],
        ["30-alert dev spot check", (spot["status"] + ": " + str(spot["ok"]) + " OK, " + str(spot["unsure"]) + " unsure, " + str(spot["problem"]) + " problem" if spot else na()),
         "reports/spot_check_summary.json"],
        ["Test recall (reported once)", ("%.4f" % test["at_accepted_threshold"]["recall"] + (" - target met" if test["meets_recall_target"] else " - BELOW target, reported as is") if test else na()),
         "reports/test_metrics.md"],
    ]
    r += table(["item", "result", "source"], rows)

    r += ["", "## 2. Data and cleaning", "",
          "- Dataset: CIC-IDS2017 labelled flows, 8 CSV files, captured 3 to 7 July 2017.",
          "- Raw rows: " + (raw_rows if raw_rows else na()) + ". Rows after the 11 cleaning steps: " + (clean_rows if clean_rows else na()) + ".",
          "- Infiltration and Heartbleed were dropped (too few flows). Web Attack XSS and SQL injection were merged into one class.",
          "- Details and per-class counts after every step: reports/cleaning_log.md.", ""]

    r += ["## 3. Split and features", "",
          "- Time-ordered split inside every (source file, label) group: 60% train, 20% validation, 20% test, with 1% gap rows dropped at each boundary.",
          "- Leakage checks (rows accounted for, no row in two splits, time order, no identical feature vector across splits, every class in every split, no NaN or inf) are in reports/split_report.md.",
          "- Final model features: " + (str(feature_count) if feature_count is not None else na()) + " (after the Destination Port ablation).", ""]

    r += ["## 4. Detector", ""]
    if baselines and detector:
        rows = [[name, "%.5f" % baselines[name]["pr_auc"]] for name in baselines]
        rows.append(["xgboost", "%.5f" % detector["pr_auc"]])
        r += ["Validation PR-AUC (threshold-free):", ""] + table(["model", "PR-AUC"], rows)
    else:
        r += ["Baseline or detector metrics: " + na()]
    if best:
        r += ["", "XGBoost configuration chosen by random search on validation (" + str(best["selection"]["configs_tried"]) + " configs, 25% train subsample): depth "
              + str(best["max_depth"]) + ", learning rate " + str(best["learning_rate"]) + ", subsample " + str(best["subsample"]) + ", colsample "
              + str(best["colsample_bytree"]) + ", min child weight " + str(best["min_child_weight"]) + ", lambda " + str(best["reg_lambda"])
              + ", weighting " + str(best["weighting"]) + "."]
    if detector and detector.get("trees") is not None:
        r += ["Trees after early stopping on the full train split: " + str(detector["trees"]) + "."]
    r += ["Destination Port ablation: " + (decision if decision else na()) + " (reports/dest_port_ablation.md).", ""]

    r += ["## 5. Threshold and alerts", ""]
    if threshold:
        v = threshold["validation"]
        r += ["Accepted threshold " + repr(threshold["threshold"]) + ". Rule: highest threshold with pooled validation recall at least " + str(config.TARGET_RECALL)
              + " and validation false positive share at least " + str(config.FP_SHARE_MIN) + ".", ""]
        r += table(["validation metric", "value"], [
            ["recall", pct(v["recall"])], ["precision", pct(v["precision"])], ["alerts", v["alerts"]], ["false positives", v["fp"]],
            ["false positive share of alerts", pct(v["fp_share_of_alerts"])], ["worst attack class", str(v["worst_attack_class"]) + " (" + pct(v["worst_attack_recall"]) + ")"]])
    else:
        r += [na()]
    r += ["", "Note: the first Day 5 run used the rule 'highest threshold with pooled recall at least 0.95' and chose 0.9775605201721191. That kept pooled recall at "
          "0.9501 but left almost no false positives (2 on validation) and missed most of Bot (recall 0.0054) and several other small classes. "
          "It was replaced by the rule above. Numbers from that first run are from the Day 5 report of that run.", ""]

    r += ["## 6. Evaluation sets", ""]
    if manifest:
        classes = sorted(set(list(manifest["composition"]["dev"].keys()) + list(manifest["composition"]["frozen"].keys())))
        rows = [[c, manifest["composition"]["dev"].get(c, 0), manifest["composition"]["frozen"].get(c, 0)] for c in classes]
        rows.append(["total", sum(manifest["composition"]["dev"].values()), sum(manifest["composition"]["frozen"].values())])
        r += ["Both sets are " + str(int(manifest["sizes"]["fp_share"] * 100)) + "% detector false positives by design (BENIGN rows below). Built on Week 1, Day 6; seed "
              + str(manifest["seed"]) + ".", ""] + table(["class", "dev", "frozen"], rows)
        r += ["", "Content hashes (first 16 characters):", ""]
        r += table(["file", "rows", "content hash"], [[e["file"], e["rows"], (e["content_hash"] or e["file_sha256"])[:16]] for e in manifest["files"].values()])
    else:
        r += [na()]
    r += ["", "The frozen set is closed to tuning and development. It is opened only through src/eval_io.py for final evaluation runs, and every read is logged.", ""]

    r += ["## 7. Reproducibility", ""]
    if repro:
        r += ["Result: **" + repro["status"] + "** (" + repro["mode"] + " mode, isolated clone). The 25-config tuning search was not repeated; the clone reused models/best_params.json.", ""]
        r += table(["check", "result", "required"], [[c["name"], "PASS" if c["passed"] else ("FAIL" if c["required"] else "NOTE"), "yes" if c["required"] else "no"] for c in repro["checks"]])
        r += ["", "Environment: " + ", ".join([k + " " + str(v) for k, v in repro["environment"].items()]) + "."]
    else:
        r += [na()]
    r += [""]

    r += ["## 8. Spot check of 30 dev alerts", ""]
    if spot:
        r += ["Result: **" + spot["status"] + "**. " + str(spot["ok"]) + " OK, " + str(spot["unsure"]) + " unsure, " + str(spot["problem"]) + " problem. "
              + "Automatic check failures (each explained in the notes): " + (", ".join(spot["automatic_check_failures"]) if spot["automatic_check_failures"] else "none") + ". Cards: reports/spot_check_30.md."]
    else:
        r += [na()]
    r += [""]

    r += ["## 9. Test split results (reported once)", ""]
    if test:
        f = test["at_accepted_threshold"]
        r += ["Final detector on test.parquet at the accepted threshold. Nothing was tuned on these numbers. The frozen evaluation set was not opened.", ""]
        r += table(["metric", "test"], [["recall", pct(f["recall"])], ["precision", pct(f["precision"])], ["F1", pct(f["f1"])], ["alerts", f["tp"] + f["fp"]],
                                       ["false positives", f["fp"]], ["missed attacks", f["fn"]], ["PR-AUC", "%.5f" % test["pr_auc"]], ["ROC-AUC", "%.5f" % test["roc_auc"]]])
        r += ["", "Recall target " + str(config.TARGET_RECALL) + ": " + ("met." if test["meets_recall_target"] else "NOT met. Reported as it is; no retuning was done."), ""]
        rows = [[n, e["rows"], e["flagged"], pct(e["rate"]), "%.3f to %.3f" % (e["wilson95_low"], e["wilson95_high"])] for n, e in test["per_class"].items()]
        r += table(["class", "test rows", "flagged", "rate", "95% interval"], rows)
    else:
        r += [na()]
    r += [""]

    r += ["## 10. Deviations from the blueprint and judgment calls", "",
          "1. Threshold rule changed after the first Day 5 run (see section 5).",
          "2. Set sizes: the plan says dev about 300 and frozen 2,000 to 3,000, with per-class caps of 25 and 200 and a 30 to 50% false positive share. These cannot all hold at once with 11 attack classes, so the totals (300 and 2,500) and a 35% false positive share were the targets and the caps stayed as upper limits.",
          "3. One logged read of the frozen set during Day 6 QA. It was a loader test, not an evaluation.",
          "4. MITRE mapping: one primary technique per class with accepted alternates. DDoS and the two slow-DoS classes are judgment calls (eval/mitre_map.csv).",
          "5. The reproducibility rerun reused best_params.json instead of repeating the tuning search.",
          "6. 'Test metrics once' means the detector on the test split. The frozen evaluation set was not used for it.", ""]

    r += ["## 11. Limitations", "",
          "- Lab traffic on a fixed weekly schedule. Attacker and victim IPs and attack times are well known for CIC-IDS2017, so a language model may recognise attacks from them rather than from the traffic.",
          "- Known flow-construction and labelling problems in CIC-IDS2017 (for example Engelen, Rimmer, Joosen, 2021).",
          "- The evaluation sets have a built-in false positive share. Report false positive reduction together with the detector's natural precision.",
          "- The threshold is low, so the alert stream is large. It was chosen to keep small classes visible, not as an operating recommendation.",
          "- Small classes have few alerts and wide intervals.",
          "- Detector scores are given to the agent as part of each alert.", ""]

    r += ["## 12. Numbers that are safe for a resume", "",
          "Each number must be quoted with its source and with the caveats above. If a file is missing the number is not yet usable.", ""]
    safe = []
    if detector:
        safe.append(["Detector validation PR-AUC", "%.5f" % detector["pr_auc"], "reports/detector_metrics.json"])
    if test:
        safe.append(["Detector test recall at accepted threshold", pct(test["at_accepted_threshold"]["recall"]), "reports/test_metrics.json"])
        safe.append(["Detector test precision at accepted threshold", pct(test["at_accepted_threshold"]["precision"]), "reports/test_metrics.json"])
        safe.append(["Detector test PR-AUC", "%.5f" % test["pr_auc"], "reports/test_metrics.json"])
    if manifest:
        safe.append(["Evaluation sets (dev / frozen alerts)", str(sum(manifest["composition"]["dev"].values())) + " / " + str(sum(manifest["composition"]["frozen"].values())), "eval/MANIFEST.json"])
    r += table(["number", "value", "source"], safe if safe else [[na(), "", ""]])
    r += ["", "No LLM or agent numbers exist yet. They start in Week 2."]

    with open(config.WEEK1_REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(r) + "\n")

    handoff = [
        "# Week 2 hand-off", "",
        "## What is frozen",
        "- Threshold " + (repr(threshold["threshold"]) if threshold else "see models/threshold.json") + ", detector models/detector_xgb.json, features models/feature_list.json.",
        "- Evaluation sets in eval/ with hashes in eval/MANIFEST.json. Check them any time with: python src/verify_eval.py.",
        "- Git tag " + config.FREEZE_TAG + " marks this state.", "",
        "## Rules that continue",
        "- All tuning uses the dev set only. The frozen set is closed to tuning and development and is opened only through src/eval_io.py for final evaluation runs. Every frozen read is logged.",
        "- Labels and the MITRE answer key are for the evaluation harness only. Agent code must never import them. The Week 3 MITRE lookup tool needs its own ATT&CK reference.",
        "- Incident memory (Week 4) may be seeded from the train split only.",
        "- Every number on the resume must come from a run you can reproduce.", "",
        "## How to load the data",
        "```python",
        "import eval_io",
        "alerts = eval_io.load_alerts('dev')        # no labels, no file names",
        "flows = eval_io.load_flow_store('dev')     # unlabelled flows; alerts link by flow_row",
        "labels = eval_io.load_labels('dev')        # evaluation harness only",
        "```",
        "Alert columns: alert_id, flow_row, flow_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, detector_score and 12 flow features.", "",
        "## Things to plan for in Week 2",
        "- Leakage through IP addresses and timestamps: run an ablation that masks them.",
        "- Detector score is visible in each alert: run an ablation that hides it.",
        "- Report per-class results and intervals, not only pooled numbers. Small classes have few alerts.",
        "- The evaluation sets are 35% false positives by design. Compare against the raw detector on the same sets and quote the detector's natural precision beside any reduction claim.",
        "- Keep the dev-only rule when iterating on prompts.", "",
        "## Where things are",
        "- WEEK1_REPORT.md: results. eval/DATASET_CARD.md: how the sets were built. reports/: every step's report. DAY7_RUNBOOK.md: how Week 1 was closed.",
    ]
    with open(config.HANDOFF_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(handoff) + "\n")

    readme = [
        "# soc-triage", "",
        "Multi-agent triage of network security alerts, evaluated on CIC-IDS2017.", "",
        "## Status", "",
        "Week 1 of 5 is done: cleaned data, an XGBoost detector, a chosen alert threshold and frozen dev and frozen evaluation sets. "
        "No LLM or agent code exists yet (Week 2 starts with a single-LLM baseline). See WEEK1_REPORT.md for results and HANDOFF.md for what Week 2 builds on.", "",
        "## Layout", "",
        "```", "src/        pipeline scripts, one per step", "data/raw/   CIC-IDS2017 CSVs (not in git)", "data/processed/   cleaned data, splits, alert files (not in git)",
        "models/     feature list, tuned parameters, detector, threshold", "reports/    a report from every step", "eval/       dev and frozen sets, MITRE answer key, manifest, dataset card",
        "notebooks/  audit and detector analysis", "```", "",
        "## Reproduce Week 1", "",
        "1. pip install -r requirements.txt, put the 8 CSVs in data/raw/.",
        "2. Pipeline order: clean.py, split.py, features.py, train_baselines.py, tune_detector.py, train_detector.py (plus --no-dest-port and --adopt-no-dest-port), make_alerts.py --threshold " + repr(config.ACCEPTED_THRESHOLD) + ", build_eval_sets.py.",
        "3. Check the evaluation sets: python src/verify_eval.py.",
        "4. Rerun everything in an isolated clone and compare hashes: python src/reproduce_week1.py --mode full.", "",
        "## Evaluation rules", "",
        "- The frozen set is closed to tuning and development. It is opened only through src/eval_io.py for final evaluation runs, and each read is logged to eval/frozen_access.log.",
        "- Labels live in separate files read only by the evaluation harness.", "",
        "## Data", "",
        "CIC-IDS2017 from the Canadian Institute for Cybersecurity, University of New Brunswick. Sharafaldin, Lashkari, Ghorbani, ICISSP 2018. The dataset has known labelling issues; see eval/DATASET_CARD.md.", "",
    ]
    readme_path = config.README_PATH if args.write_readme else os.path.join(config.REPORTS_DIR, "README_proposed.md")
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write("\n".join(readme) + "\n")

    print("Wrote " + config.WEEK1_REPORT_PATH)
    print("Wrote " + config.HANDOFF_PATH)
    print("Wrote " + readme_path)
    unique = []
    for m in missing:
        if m not in unique:
            unique.append(m)
    if len(unique) > 0:
        print("")
        print("INCOMPLETE. These inputs were missing and are shown as NOT AVAILABLE:")
        for m in unique:
            print("- " + m)
        if not args.allow_incomplete:
            sys.exit(2)


if __name__ == "__main__":
    main()
