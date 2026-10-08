"""Week 2 Day 6: run the locked baseline_v3 three times on the DEV set, one separate run folder per replicate.

This is a thin, checked wrapper around the existing runner (run_baseline_dev.main). It adds no model behavior:
the prompt, model, settings, retry logic, parser, storage and guards are the runner's. What it adds is the discipline Day 6 needs:

  check    No model call, no file written. Confirms that the locked prompt is the one the reference run used, that the model and
           settings match, that the dev inputs are the ones the reference run used, that the frozen unlock is not set, and which
           replicate folders already exist.
  run      Runs one replicate (--replicate N) or all three in order (--all). Each replicate is a fresh run with its own folder,
           its own client and its own session. A finished replicate is never run again or overwritten.
  status   No model call. Shows each replicate, and re-checks that the protected runs, the frozen access log and the prompt hash
           are unchanged since the first replicate started.

Replicate run names (all under the usual runs folder, so evaluate.py --run-name works on them):
  dev_flash_lite_v3_d6_rep1, dev_flash_lite_v3_d6_rep2, dev_flash_lite_v3_d6_rep3

The settings are not varied between replicates (temperature and seed stay as locked), so the spread measured later is the service's
repeatability, not a sweep. The reference run (default dev_flash_lite_v3_final, the Day 5 run) supplies the locked prompt hash,
model, settings and alert list; no hash is hard-coded here. This module reads no labels, no answer key and no frozen file.
"""
import os
import sys
import json
import argparse
import datetime

import config
import prompt_registry
import baseline_store as store
import run_baseline_dev as runner

PROMPT_VERSION = "baseline_v3"
REFERENCE_RUN = "dev_flash_lite_v3_final"
PROTECTED_RUNS = ["dev_flash_lite_v1", "dev_flash_lite_v3_final"]
REPLICATES = {1: "dev_flash_lite_v3_d6_rep1", 2: "dev_flash_lite_v3_d6_rep2", 3: "dev_flash_lite_v3_d6_rep3"}
EXPECTED_ALERTS = 300
SETTING_KEYS = ["temperature", "max_output_tokens", "seed", "parse_retries"]


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def folder_digest(path):
    """sha256 of every file in a run folder, keyed by relative path. Empty if the folder does not exist."""
    out = {}
    if not os.path.isdir(path):
        return out
    for folder, _, files in os.walk(path):
        for name in sorted(files):
            full = os.path.join(folder, name)
            out[os.path.relpath(full, path).replace(os.sep, "/")] = store.file_sha256(full)
    return out


def manifest_path(runs_dir):
    return os.path.join(os.path.dirname(os.path.abspath(runs_dir)), "week2_day6", "replicates_manifest.json")


def run_status(runs_dir, name):
    path = os.path.join(runs_dir, name)
    meta_path = os.path.join(path, "run_meta.json")
    if not os.path.exists(path):
        return "absent"
    if not os.path.exists(meta_path):
        return "incomplete"
    return "complete" if store.read_json(meta_path).get("status") == "complete" else "incomplete"


# ------------------------------------------------------------------------------------------------ checks
def gather_context(runs_dir, reference_run, rpm):
    """Everything check_context needs, read from the reference run, the registry, the runner config and the dev loader."""
    ref_path = os.path.join(runs_dir, reference_run, "run_meta.json")
    ref_meta = store.read_json(ref_path) if os.path.exists(ref_path) else None
    sizes = runner.check_llm_config()
    model = sizes["small"]
    alerts, flows, hashes = runner.load_inputs()
    return {
        "ref_meta": ref_meta, "reference_run": reference_run, "spec": prompt_registry.get_prompt(PROMPT_VERSION),
        "model": model, "settings": runner.settings_for(model, rpm), "inputs": hashes, "alert_ids": list(alerts["alert_id"]),
        "unlock_set": bool(os.environ.get(config.FROZEN_UNLOCK_ENV)),
    }


def check_context(ctx, expected_sha=None, expected_alerts=EXPECTED_ALERTS):
    problems = []
    if ctx["unlock_set"]:
        problems.append(config.FROZEN_UNLOCK_ENV + " is set in this shell. Unset it. Day 6 uses the dev set only.")
    ref = ctx["ref_meta"]
    spec = ctx["spec"]
    if ref is None:
        problems.append("the reference run '" + ctx["reference_run"] + "' has no run_meta.json, so the locked prompt hash, model and settings cannot be confirmed")
        return problems
    if ref.get("status") != "complete" or ref.get("set") != "dev":
        problems.append("the reference run is not a complete dev run")
    if ref.get("prompt_version") != PROMPT_VERSION:
        problems.append("the reference run used prompt '" + str(ref.get("prompt_version")) + "', not " + PROMPT_VERSION)
    if spec.sha256 != ref.get("prompt_sha256"):
        problems.append("the baseline_v3 prompt in this repo (" + spec.sha256[:12] + "...) is not the one the reference run used ("
                        + str(ref.get("prompt_sha256"))[:12] + "...). The baseline is not locked. Stop and find out why before running.")
    if expected_sha and spec.sha256 != expected_sha:
        problems.append("the baseline_v3 prompt hash differs from --expected-sha256")
    if ctx["model"] != ref.get("model"):
        problems.append("the model now configured (" + str(ctx["model"]) + ") is not the one the reference run used (" + str(ref.get("model")) + ")")
    for key in SETTING_KEYS:
        if (ref.get("settings") or {}).get(key) != ctx["settings"].get(key):
            problems.append("setting " + key + " differs from the reference run")
    if ref.get("inputs") != ctx["inputs"]:
        problems.append("the dev input files differ from the ones the reference run used")
    ids = ctx["alert_ids"]
    if len(set(ids)) != len(ids) or not all(str(a).startswith("DEV-") for a in ids):
        problems.append("the alert ids are not unique DEV- ids")
    if ids != list(ref.get("selected_alert_ids", [])):
        problems.append("the dev alert list differs from the reference run's alert list")
    if expected_alerts is not None and len(ids) != expected_alerts:
        problems.append("expected " + str(expected_alerts) + " dev alerts, found " + str(len(ids)))
    return problems


def verify_run(runs_dir, name, ref_meta, spec, expected_alerts=EXPECTED_ALERTS):
    """After a replicate: it must be a complete dev run of the locked prompt on the reference alert list."""
    problems = []
    path = os.path.join(runs_dir, name, "run_meta.json")
    if not os.path.exists(path):
        return [name + ": no run_meta.json"]
    meta = store.read_json(path)
    counts = meta.get("counts") or {}
    if meta.get("status") != "complete":
        problems.append(name + ": status is '" + str(meta.get("status")) + "', not complete (use --resume, then run again)")
    if meta.get("set") != "dev":
        problems.append(name + ": not a dev run")
    if meta.get("prompt_version") != PROMPT_VERSION or meta.get("prompt_sha256") != spec.sha256:
        problems.append(name + ": prompt version or hash is not the locked baseline_v3")
    if meta.get("selected_alert_ids") != ref_meta.get("selected_alert_ids"):
        problems.append(name + ": alert list differs from the reference run")
    if expected_alerts is not None and sum(counts.values()) != expected_alerts:
        problems.append(name + ": " + str(sum(counts.values())) + " alerts finished, expected " + str(expected_alerts))
    if counts.get("model_error", 0) != 0:
        problems.append(name + ": " + str(counts.get("model_error")) + " alerts ended in model_error")
    if meta.get("frozen_access_log_unchanged") is not True or meta.get("week1_files_unchanged") is not True:
        problems.append(name + ": the run reports a changed frozen access log or Week 1 file")
    for key in SETTING_KEYS:
        if (meta.get("settings") or {}).get(key) != (ref_meta.get("settings") or {}).get(key):
            problems.append(name + ": setting " + key + " differs from the reference run")
    return problems


# ------------------------------------------------------------------------------------------------ manifest
def load_manifest(runs_dir):
    path = manifest_path(runs_dir)
    return store.read_json(path) if os.path.exists(path) else None


def new_manifest(runs_dir, ctx):
    return {
        "created_utc": utc_now(), "purpose": "Week 2 Day 6: three DEV runs of the locked baseline_v3",
        "reference_run": ctx["reference_run"], "prompt_version": PROMPT_VERSION, "prompt_sha256": ctx["spec"].sha256,
        "model": ctx["model"], "settings": {k: ctx["settings"][k] for k in SETTING_KEYS},
        "frozen_access_log_lines_at_start": runner.count_lines(config.FROZEN_ACCESS_LOG),
        "protected_runs": {name: folder_digest(os.path.join(runs_dir, name)) for name in PROTECTED_RUNS},
        "replicates": {},
    }


def save_manifest(runs_dir, manifest):
    path = manifest_path(runs_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    store.write_json_atomic(path, manifest)


# ------------------------------------------------------------------------------------------------ actions
def do_check(args, say=print):
    ctx = gather_context(args.runs_dir, args.reference_run, args.rpm)
    problems = check_context(ctx, args.expected_sha256, args.expected_alerts)
    say("Locked prompt: " + PROMPT_VERSION + " sha256 " + ctx["spec"].sha256)
    say("Reference run: " + args.reference_run + ", model " + str(ctx["model"]) + ", " + str(len(ctx["alert_ids"])) + " dev alerts")
    for n, name in REPLICATES.items():
        say("  replicate " + str(n) + ": " + name + " [" + run_status(args.runs_dir, name) + "]")
    if problems:
        for p in problems:
            say("PROBLEM: " + p)
        say("Preflight FAILED. Nothing was run.")
        return 1
    say("Preflight OK. Nothing was run and nothing was written.")
    return 0


def run_one(n, args, say=print):
    name = REPLICATES[n]
    ctx = gather_context(args.runs_dir, args.reference_run, args.rpm)
    problems = check_context(ctx, args.expected_sha256, args.expected_alerts)
    if problems:
        for p in problems:
            say("PROBLEM: " + p)
        say("Preflight FAILED. Nothing was run.")
        return 1
    status = run_status(args.runs_dir, name)
    if status == "complete":
        say("Replicate " + str(n) + " (" + name + ") is already complete. It is not run again. Evaluate it: python src/evaluate.py --run-name " + name)
        return 0
    if status == "incomplete" and not args.resume:
        say("STOPPED: " + name + " exists but is not complete. Continue it with: python src/day6_replicates.py run --replicate " + str(n) + " --resume")
        return 1
    if status == "absent" and args.resume:
        say("STOPPED: --resume was given but " + name + " does not exist.")
        return 1
    manifest = load_manifest(args.runs_dir) or new_manifest(args.runs_dir, ctx)
    if manifest["prompt_sha256"] != ctx["spec"].sha256:
        say("STOPPED: the prompt hash changed since the first replicate started. The baseline is not locked.")
        return 1
    entry = manifest["replicates"].setdefault(str(n), {"run_name": name, "sessions": []})
    entry["sessions"].append({"started_utc": utc_now(), "resume": bool(args.resume)})
    save_manifest(args.runs_dir, manifest)
    if args.resume:
        argv = ["--resume", "--run-name", name, "--prompt-version", PROMPT_VERSION]
    else:
        argv = ["--run-name", name, "--prompt-version", PROMPT_VERSION]
    argv += ["--runs-dir", args.runs_dir, "--rpm", str(args.rpm)]
    if args.langsmith:
        argv.append("--langsmith")
    say("Replicate " + str(n) + ": running " + name + " (" + PROMPT_VERSION + ", dev set, " + str(len(ctx["alert_ids"])) + " alerts).")
    try:
        code = runner.main(argv)
    except SystemExit as stop:
        code = stop.code if isinstance(stop.code, int) and stop.code != 0 else 1
        say(str(stop.code))
    problems = verify_run(args.runs_dir, name, ctx["ref_meta"], ctx["spec"], args.expected_alerts)
    entry["sessions"][-1]["finished_utc"] = utc_now()
    entry["sessions"][-1]["runner_exit_code"] = code
    entry["status"] = "complete" if not problems and code == 0 else "needs_attention"
    entry["verification_problems"] = problems
    entry["run_file_sha256"] = folder_digest(os.path.join(args.runs_dir, name))
    save_manifest(args.runs_dir, manifest)
    if problems:
        for p in problems:
            say("PROBLEM: " + p)
    if code != 0 or problems:
        say("Replicate " + str(n) + " needs attention (runner exit code " + str(code) + ").")
        return code if code != 0 else 1
    say("Replicate " + str(n) + " complete. Evaluate it: python src/evaluate.py --run-name " + name)
    return 0


def do_run(args, say=print):
    numbers = sorted(REPLICATES) if args.all else [args.replicate]
    for n in numbers:
        code = run_one(n, args, say)
        if code != 0:
            return code
    return 0


def do_status(args, say=print):
    manifest = load_manifest(args.runs_dir)
    ok = True
    say("Replicates:")
    for n, name in REPLICATES.items():
        say("  " + str(n) + ": " + name + " [" + run_status(args.runs_dir, name) + "]")
    if manifest is None:
        say("No Day 6 manifest yet (no replicate has been started).")
        return 0
    spec = prompt_registry.get_prompt(PROMPT_VERSION)
    same_prompt = manifest["prompt_sha256"] == spec.sha256
    say("baseline_v3 hash unchanged since the first replicate: " + str(same_prompt))
    ok = ok and same_prompt
    log_now = runner.count_lines(config.FROZEN_ACCESS_LOG)
    log_same = log_now == manifest["frozen_access_log_lines_at_start"]
    say("frozen access log unchanged (" + str(manifest["frozen_access_log_lines_at_start"]) + " -> " + str(log_now) + " lines): " + str(log_same))
    ok = ok and log_same
    for name, digest in manifest["protected_runs"].items():
        same = folder_digest(os.path.join(args.runs_dir, name)) == digest
        say("protected run " + name + " unchanged: " + str(same))
        ok = ok and same
    return 0 if ok else 1


def parse_args(argv):
    p = argparse.ArgumentParser(description="Week 2 Day 6: three DEV replicates of the locked baseline_v3. Dev set only.")
    p.add_argument("action", choices=["check", "run", "status"])
    p.add_argument("--replicate", type=int, choices=sorted(REPLICATES), help="which replicate to run (1, 2 or 3)")
    p.add_argument("--all", action="store_true", help="run the replicates that are not complete, in order")
    p.add_argument("--resume", action="store_true", help="continue an interrupted replicate")
    p.add_argument("--langsmith", action="store_true", help="metadata-only tracing, as in Day 5 (needs LANGSMITH_API_KEY)")
    p.add_argument("--rpm", type=float, default=runner.DEFAULT_RPM)
    p.add_argument("--runs-dir", default=runner.RUNS_ROOT)
    p.add_argument("--reference-run", default=REFERENCE_RUN)
    p.add_argument("--expected-sha256", default=None, help="optional: also require this exact baseline_v3 hash")
    p.add_argument("--expected-alerts", type=int, default=EXPECTED_ALERTS)
    args = p.parse_args(argv)
    if args.action == "run" and bool(args.replicate) == bool(args.all):
        p.error("run needs exactly one of --replicate N or --all")
    if args.action != "run" and (args.replicate or args.all or args.resume):
        p.error("--replicate, --all and --resume belong to the run action")
    if args.resume and args.all:
        p.error("--resume goes with one --replicate")
    if args.rpm <= 0:
        p.error("--rpm must be above 0")
    return args


def main(argv=None):
    args = parse_args(argv)
    if args.action == "check":
        return do_check(args)
    if args.action == "status":
        return do_status(args)
    return do_run(args)


if __name__ == "__main__":
    sys.exit(main())
