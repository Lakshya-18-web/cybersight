"""Rerun Week 1 in an isolated clone and compare the results with the real project.

Nothing in the real project is overwritten. The clone gets its own copy of src/, its own data/processed, models, reports and eval folders.
Only data/raw (and, in eval-only mode, the validation and test parquet files) are linked read-only into the clone.

The 25-config tuning search is NOT repeated: the clone reuses models/best_params.json from the real project.

Modes
  full       clean -> split -> features -> baselines -> detector (with and without Destination Port) -> alerts -> eval sets
  eval-only  only the Day 6 build, fed with the real Day 5 outputs (fast)

New files written in the real project: reports/reproducibility_report.md and .json. Nothing else.
"""
import os
import sys
import json
import shutil
import hashlib
import argparse
import platform
import subprocess
import time
import datetime
import pandas as pd

import config

parser = argparse.ArgumentParser()
parser.add_argument("--mode", required=True, choices=["full", "eval-only"])
parser.add_argument("--clone-dir", default=os.path.join(os.path.dirname(config.PROJECT_ROOT), "soc-triage-repro"),
                    help="scratch folder for the rerun (must be outside the project)")
parser.add_argument("--dry-run", action="store_true", help="print the plan and change nothing")
parser.add_argument("--clean-force", action="store_true", help="pass --force to clean.py (use only if Day 2 was run that way)")
parser.add_argument("--from-step", type=int, default=1, help="resume an existing clone at this step number")
parser.add_argument("--force-clone", action="store_true", help="delete an existing clone folder first (only if it was made by this script)")
parser.add_argument("--skip-flow-stores", action="store_true", help="leave the two large flow store files out of the eval comparison")
parser.add_argument("--delete-clone-on-pass", action="store_true")
args = parser.parse_args()

CLONE = os.path.abspath(args.clone_dir)
MARKER = ".soc_repro_clone"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def say(text=""):
    print(text, flush=True)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def frame_hash(df):
    return hashlib.sha256(pd.util.hash_pandas_object(df, index=False).values.tobytes()).hexdigest()


def parquet_hash(path):
    """Content hash that does not depend on file bytes. Streams the file when pyarrow is available."""
    h = hashlib.sha256()
    rows = 0
    try:
        import pyarrow.parquet as pq
        parquet = pq.ParquetFile(path)
        for batch in parquet.iter_batches(batch_size=250000):
            part = batch.to_pandas()
            h.update(pd.util.hash_pandas_object(part, index=False).values.tobytes())
            rows = rows + len(part)
    except ImportError:
        df = pd.read_parquet(path)
        h.update(pd.util.hash_pandas_object(df, index=False).values.tobytes())
        rows = len(df)
    return h.hexdigest(), rows


def versions():
    out = {"python": sys.version.split()[0], "platform": platform.platform()}
    for name in ["pandas", "numpy", "sklearn", "xgboost", "pyarrow"]:
        try:
            module = __import__(name)
            out[name] = getattr(module, "__version__", "unknown")
        except ImportError:
            out[name] = "not installed"
    return out


def read_json(path):
    with open(path, "r") as f:
        return json.load(f)


def real(path):
    return os.path.join(config.PROJECT_ROOT, path)


def clone_path(path):
    return os.path.join(CLONE, path)


def protected_files():
    """Files of the real project that this script must leave untouched."""
    names = ["eval/MANIFEST.json", "eval/DATASET_CARD.md", "eval/mitre_map.csv", "models/threshold.json", "models/detector_xgb.json",
             "models/feature_list.json", "models/best_params.json", "reports/threshold_report.md", "reports/eval_build_report.md",
             "reports/detector_metrics.json", "data/processed/alerts_val.parquet", "data/processed/alerts_test.parquet",
             "data/processed/alerts_val_labels.parquet", "data/processed/alerts_test_labels.parquet"]
    if os.path.exists(config.MANIFEST_PATH):
        for key, entry in read_json(config.MANIFEST_PATH)["files"].items():
            names.append("eval/" + entry["file"])
    seen = []
    for n in names:
        if n not in seen:
            seen.append(n)
    return seen


def snapshot():
    result = {}
    for name in protected_files():
        path = real(name)
        if os.path.exists(path):
            result[name] = sha256_file(path)
    return result


def link_or_copy(source, target):
    os.makedirs(os.path.dirname(target), exist_ok=True)
    try:
        os.symlink(source, target, target_is_directory=os.path.isdir(source))
        return "linked"
    except (OSError, NotImplementedError):
        if os.path.isdir(source):
            shutil.copytree(source, target)
        else:
            shutil.copy2(source, target)
        return "copied"


def plan_steps(adopt):
    if args.mode == "eval-only":
        return [("eval_sets", "build_eval_sets.py", [])]
    steps = [
        ("clean", "clean.py", ["--force"] if args.clean_force else []),
        ("split", "split.py", []),
        ("features", "features.py", []),
        ("baselines", "train_baselines.py", []),
        ("detector_with_port", "train_detector.py", []),
        ("detector_no_port", "train_detector.py", ["--no-dest-port"]),
    ]
    if adopt:
        steps.append(("adopt_no_port", "train_detector.py", ["--adopt-no-dest-port"]))
    steps.append(("alerts", "make_alerts.py", ["--threshold", repr(config.ACCEPTED_THRESHOLD)]))
    steps.append(("eval_sets", "build_eval_sets.py", []))
    return steps


def make_clone():
    if os.path.exists(CLONE):
        if args.from_step > 1:
            return
        if args.force_clone and os.path.exists(os.path.join(CLONE, MARKER)):
            shutil.rmtree(CLONE)
        else:
            say("STOPPED: " + CLONE + " already exists. Use --force-clone (only works on a folder this script made) or --from-step N to resume.")
            sys.exit(1)
    os.makedirs(CLONE)
    with open(os.path.join(CLONE, MARKER), "w") as f:
        f.write("made by reproduce_week1.py\n")
    shutil.copytree(os.path.join(config.PROJECT_ROOT, "src"), clone_path("src"), ignore=shutil.ignore_patterns("__pycache__"))
    for folder in ["data/processed", "models", "reports", "eval", "repro_logs"]:
        os.makedirs(clone_path(folder), exist_ok=True)
    how = []
    if args.mode == "full":
        how.append("data/raw " + link_or_copy(real("data/raw"), clone_path("data/raw")))
        shutil.copy2(real("models/best_params.json"), clone_path("models/best_params.json"))
        how.append("models/best_params.json copied (tuning is not repeated)")
    else:
        for name in ["models/threshold.json", "models/feature_list.json", "data/processed/alerts_val.parquet",
                     "data/processed/alerts_test.parquet", "data/processed/alerts_val_labels.parquet", "data/processed/alerts_test_labels.parquet"]:
            shutil.copy2(real(name), clone_path(name))
            how.append(name + " copied")
        for name in ["data/processed/val.parquet", "data/processed/test.parquet"]:
            how.append(name + " " + link_or_copy(real(name), clone_path(name)) + " (read-only use)")
    for line in how:
        say("  clone: " + line)


def run_step(number, key, script, extra):
    log_path = clone_path("repro_logs/%02d_%s.log" % (number, key))
    command = [sys.executable, os.path.join("src", script)] + extra
    say("[%02d] %s: %s" % (number, key, " ".join(command)))
    start = time.time()
    with open(log_path, "w", encoding="utf-8") as log:
        result = subprocess.run(command, cwd=CLONE, stdout=log, stderr=subprocess.STDOUT)
    seconds = round(time.time() - start, 1)
    say("     exit " + str(result.returncode) + ", " + str(seconds) + " s, log " + log_path)
    if result.returncode != 0:
        with open(log_path, "r", encoding="utf-8", errors="replace") as log:
            tail = log.read().splitlines()[-15:]
        for line in tail:
            say("     | " + line)
    return {"step": number, "name": key, "command": " ".join(extra), "returncode": result.returncode, "seconds": seconds}


def normalise(text):
    for root in [CLONE, config.PROJECT_ROOT]:
        text = text.replace(root, "<ROOT>").replace(root.replace("\\", "/"), "<ROOT>")
    return text


def compare():
    checks = []

    def add(name, passed, detail="", required=True):
        checks.append({"name": name, "passed": bool(passed), "required": required, "detail": detail})
        say("  " + ("PASS" if passed else ("FAIL" if required else "NOTE")) + ": " + name + (" (" + detail + ")" if detail else ""))

    if args.mode == "full":
        for name in ["flows_clean", "train", "val", "test"]:
            a, rows_a = parquet_hash(real("data/processed/" + name + ".parquet"))
            b, rows_b = parquet_hash(clone_path("data/processed/" + name + ".parquet"))
            add(name + ".parquet has identical content", a == b and rows_a == rows_b, str(rows_a) + " vs " + str(rows_b) + " rows")
        add("feature_list.json is identical", read_json(real("models/feature_list.json")) == read_json(clone_path("models/feature_list.json")))
        mine = read_json(real("reports/detector_metrics.json"))
        theirs = read_json(clone_path("reports/detector_metrics.json"))
        diff = abs(mine["pr_auc"] - theirs["pr_auc"])
        add("detector validation PR-AUC matches", diff <= config.MODEL_PR_AUC_TOLERANCE,
            "real " + "%.8f" % mine["pr_auc"] + ", clone " + "%.8f" % theirs["pr_auc"])
        add("detector uses the same number of trees", mine.get("trees") == theirs.get("trees"), str(mine.get("trees")) + " vs " + str(theirs.get("trees")))
        same_bytes = sha256_file(real("models/detector_xgb.json")) == sha256_file(clone_path("models/detector_xgb.json"))
        add("model file is byte-identical", same_bytes, "different bytes are acceptable if the alerts below match", required=False)
        for name in ["reports/cleaning_log.md", "reports/split_report.md"]:
            with open(real(name), "r", encoding="utf-8") as f:
                a = normalise(f.read())
            with open(clone_path(name), "r", encoding="utf-8") as f:
                b = normalise(f.read())
            add(name + " has the same text", a == b, "after replacing project paths", required=False)

    real_threshold = read_json(real("models/threshold.json"))
    clone_threshold = read_json(clone_path("models/threshold.json"))
    add("threshold is the accepted value", clone_threshold["threshold"] == real_threshold["threshold"], repr(clone_threshold["threshold"]))
    for key in ["validation_alerts_hash", "validation_labels_hash", "test_alerts_hash", "test_labels_hash"]:
        add("Day 5 " + key + " is identical", clone_threshold["alerts"][key] == real_threshold["alerts"][key])
    add("validation confusion counts are identical",
        all(clone_threshold["validation"][k] == real_threshold["validation"][k] for k in ["tp", "fp", "fn", "tn", "alerts"]))

    command = [sys.executable, os.path.join(config.PROJECT_ROOT, "src", "verify_eval.py"), "--dir", clone_path("eval"), "--manifest", config.MANIFEST_PATH]
    if args.skip_flow_stores:
        command.append("--skip-flow-stores")
    result = subprocess.run(command, cwd=config.PROJECT_ROOT, capture_output=True, text=True)
    with open(clone_path("repro_logs/verify_eval_against_real_manifest.log"), "w", encoding="utf-8") as f:
        f.write(result.stdout + result.stderr)
    add("rebuilt eval files match the real MANIFEST.json (verify_eval.py)", result.returncode == 0, "exit " + str(result.returncode))
    return checks


def write_reports(status, steps, checks, before, after, started, finished):
    unchanged = before == after
    changed = [name for name in before if before[name] != after.get(name)]
    summary = {
        "status": status, "mode": args.mode, "clone_dir": CLONE, "started_utc": started, "finished_utc": finished,
        "environment": versions(), "tuning_repeated": False, "best_params_reused": True,
        "steps": steps, "checks": checks, "protected_files_unchanged": unchanged, "protected_files_changed": changed,
        "manifest_sha256": sha256_file(config.MANIFEST_PATH),
    }
    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    with open(config.REPRO_REPORT_JSON, "w") as f:
        json.dump(summary, f, indent=2)
    lines = ["# Reproducibility report", "", "**Result: " + status + "**", "",
             "Mode: " + args.mode + ". Rerun in an isolated clone: " + CLONE,
             ("The 25-config tuning search was not repeated. The clone reused models/best_params.json." if args.mode == "full"
              else "Eval-only mode: only the Day 6 build was repeated, from the real Day 5 outputs. The earlier steps were not rerun."),
             "Started " + started + ", finished " + finished + ".", "", "## Environment", ""]
    for key, value in summary["environment"].items():
        lines.append("- " + key + ": " + str(value))
    lines += ["", "## Steps", "", "| # | step | exit | seconds |", "|---|---|---|---|"]
    for s in steps:
        lines.append("| " + str(s["step"]) + " | " + s["name"] + " | " + str(s["returncode"]) + " | " + str(s["seconds"]) + " |")
    lines += ["", "## Comparison with the real project", "", "| check | result | required | detail |", "|---|---|---|---|"]
    for c in checks:
        lines.append("| " + c["name"] + " | " + ("PASS" if c["passed"] else ("FAIL" if c["required"] else "NOTE")) + " | "
                     + ("yes" if c["required"] else "no") + " | " + c["detail"] + " |")
    lines += ["", "## Real project left untouched", "",
              "Checked " + str(len(before)) + " protected files (Day 5 and Day 6 outputs, model, threshold, manifest) by SHA-256 before and after: "
              + ("all unchanged." if unchanged else "CHANGED: " + ", ".join(changed))]
    with open(config.REPRO_REPORT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    if not os.path.exists(config.MANIFEST_PATH) or not os.path.exists(config.THRESHOLD_PATH):
        say("STOPPED: eval/MANIFEST.json or models/threshold.json is missing in the real project.")
        sys.exit(1)
    if read_json(config.THRESHOLD_PATH)["threshold"] != config.ACCEPTED_THRESHOLD:
        say("STOPPED: models/threshold.json does not hold the accepted threshold.")
        sys.exit(1)
    inside = CLONE == config.PROJECT_ROOT or CLONE.startswith(config.PROJECT_ROOT + os.sep) or config.PROJECT_ROOT.startswith(CLONE + os.sep)
    if inside:
        say("STOPPED: the clone folder must be outside the project (and not a parent of it): " + CLONE)
        sys.exit(1)

    adopt = "Destination Port" not in read_json(config.FEATURE_LIST_PATH)
    steps_plan = plan_steps(adopt)
    say("# Week 1 reproducibility run (" + args.mode + ")")
    say("Real project: " + config.PROJECT_ROOT)
    say("Clone: " + CLONE)
    say("Steps:")
    for i, (key, script, extra) in enumerate(steps_plan):
        say("  %02d %s %s" % (i + 1, script, " ".join(extra)))
    if args.mode == "full":
        say("Disk: the full mode rebuilds flows_clean and the splits, so expect several GB in the clone.")
    if args.dry_run:
        say("Dry run: nothing was created or changed.")
        return

    before = snapshot()
    started = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    make_clone()
    done = []
    failed = False
    for i, (key, script, extra) in enumerate(steps_plan):
        number = i + 1
        if number < args.from_step:
            continue
        result = run_step(number, key, script, extra)
        done.append(result)
        if result["returncode"] != 0:
            failed = True
            break

    checks = []
    if not failed:
        say("")
        say("Comparing the clone with the real project:")
        checks = compare()
    after = snapshot()
    finished = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    unchanged = before == after
    required_ok = all(c["passed"] for c in checks if c["required"])
    status = "PASS" if (not failed and required_ok and unchanged and len(checks) > 0) else "FAIL"
    if not unchanged:
        say("ALERT: protected files in the real project changed during this run: " + ", ".join([n for n in before if before[n] != after.get(n)]))
    write_reports(status, done, checks, before, after, started, finished)
    say("")
    say("Result: " + status + ". Report: reports/reproducibility_report.md")
    if status == "PASS" and args.delete_clone_on_pass:
        shutil.rmtree(CLONE)
        say("Clone deleted.")
    sys.exit(0 if status == "PASS" else 1)


if __name__ == "__main__":
    main()
