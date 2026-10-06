import os
import sys
import time
import argparse
import platform
import datetime
import subprocess

import pandas as pd

import config
import llm_config
import verdict_parser
import triage_inputs
import baseline_prompt
import baseline_store as store
import gemini_client

RUNS_ROOT = os.path.join(config.PROJECT_ROOT, "runs", "week2_baseline_v1")
GENERATION_SEED = 42
DEFAULT_RPM = 10.0
TRANSPORT_RETRIES = 4
BACKOFF_SECONDS = [4, 8, 16, 32]
MAX_CONSECUTIVE_MODEL_ERRORS = 5
STATUS_OK = "ok"
STATUS_PARSE_FAILED = "parse_failed"
STATUS_MODEL_ERROR = "model_error"
FINISHED_STATUSES = [STATUS_OK, STATUS_PARSE_FAILED]

SLEEP = time.sleep
CLOCK = time.monotonic


class ModelUnavailable(Exception):
    pass


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Throttle:
    def __init__(self, calls_per_minute):
        self.gap = 60.0 / calls_per_minute
        self.last = None

    def wait(self):
        now = CLOCK()
        if self.last is not None:
            pause = self.gap - (now - self.last)
            if pause > 0:
                SLEEP(pause)
                now = CLOCK()
        self.last = now


class RecordingCaller:
    def __init__(self, client, throttle, run_dir, session, model):
        self.client = client
        self.throttle = throttle
        self.run_dir = run_dir
        self.session = session
        self.model = model
        self.alert_id = None
        self.calls = []

    def start(self, alert_id):
        self.alert_id = alert_id
        self.calls = []

    def write_raw(self, prompt, record, errors, seconds, outcome):
        line = {
            "alert_id": self.alert_id,
            "session": self.session,
            "call_index": len(self.calls) + 1,
            "model": self.model,
            "outcome": outcome,
            "prompt": prompt,
            "reply": None,
            "finish_reason": None,
            "block_reason": None,
            "prompt_tokens": None,
            "output_tokens": None,
            "thinking_tokens": None,
            "total_tokens": None,
            "latency_seconds": round(seconds, 3),
            "transport_errors": errors,
            "timestamp_utc": utc_now(),
        }
        if record is not None:
            line["reply"] = record.text
            line["finish_reason"] = record.finish_reason
            line["block_reason"] = record.block_reason
            line["prompt_tokens"] = record.prompt_tokens
            line["output_tokens"] = record.output_tokens
            line["thinking_tokens"] = record.thinking_tokens
            line["total_tokens"] = record.total_tokens
        store.append_jsonl(self.run_dir.raw, line)
        return line

    def __call__(self, prompt):
        errors = []
        for attempt in range(TRANSPORT_RETRIES + 1):
            self.throttle.wait()
            started = CLOCK()
            try:
                record = self.client.generate(prompt)
            except gemini_client.TransientModelError as error:
                errors.append({"status": error.status, "message": str(error)})
                if attempt == TRANSPORT_RETRIES:
                    self.write_raw(prompt, None, errors, CLOCK() - started, "transport_failed")
                    raise ModelUnavailable("the model call failed " + str(attempt + 1) + " times: " + str(error))
                SLEEP(BACKOFF_SECONDS[min(attempt, len(BACKOFF_SECONDS) - 1)])
                continue
            except gemini_client.PermanentModelError as error:
                errors.append({"status": error.status, "message": str(error)})
                self.write_raw(prompt, None, errors, CLOCK() - started, "permanent_error")
                raise
            line = self.write_raw(prompt, record, errors, CLOCK() - started, "reply")
            self.calls.append(line)
            return record.text
        raise ModelUnavailable("no reply")


def log_from_calls(calls):
    log = []
    for i in range(len(calls)):
        result = verdict_parser.parse_verdict(calls[i]["reply"])
        log.append({"attempt": i + 1, "error_code": result.error_code, "error_detail": result.error_detail,
                    "repairs": list(result.repairs)})
    return log


def add_up(calls, name):
    total = 0
    seen = False
    for call in calls:
        if call[name] is not None:
            total = total + call[name]
            seen = True
    if seen:
        return total
    return None


def process_alert(alert_id, prompt, caller, session, max_parse_retries):
    caller.start(alert_id)
    record = {
        "alert_id": alert_id,
        "status": None,
        "verdict": None,
        "error_code": None,
        "error_detail": None,
        "attempts": 0,
        "malformed_first_try": None,
        "attempt_log": [],
        "repairs": [],
        "prompt_sha256": store.text_sha256(prompt),
        "session": session,
    }
    try:
        outcome = verdict_parser.parse_with_retries(caller, prompt, max_parse_retries)
    except ModelUnavailable as error:
        record["status"] = STATUS_MODEL_ERROR
        record["error_code"] = "model_unavailable"
        record["error_detail"] = str(error)
        record["attempt_log"] = log_from_calls(caller.calls)
    else:
        record["attempt_log"] = outcome.attempt_log
        record["repairs"] = outcome.repairs
        if outcome.verdict is not None:
            record["status"] = STATUS_OK
            record["verdict"] = outcome.verdict.model_dump()
        else:
            last = outcome.attempt_log[-1]
            record["status"] = STATUS_PARSE_FAILED
            record["error_code"] = last["error_code"]
            record["error_detail"] = last["error_detail"]
    record["attempts"] = len(caller.calls)
    if len(record["attempt_log"]) > 0:
        record["malformed_first_try"] = record["attempt_log"][0]["error_code"] is not None
    record["model_calls"] = len(caller.calls)
    record["prompt_tokens"] = add_up(caller.calls, "prompt_tokens")
    record["output_tokens"] = add_up(caller.calls, "output_tokens")
    record["thinking_tokens"] = add_up(caller.calls, "thinking_tokens")
    record["total_tokens"] = add_up(caller.calls, "total_tokens")
    record["latency_seconds"] = round(sum([c["latency_seconds"] for c in caller.calls]), 3)
    record["finish_reasons"] = [c["finish_reason"] for c in caller.calls]
    record["finished_utc"] = utc_now()
    return record


def run_alerts(todo_ids, prompts, run_dir, caller, session, max_parse_retries, say=print):
    consecutive = 0
    for i in range(len(todo_ids)):
        alert_id = todo_ids[i]
        started = CLOCK()
        record = process_alert(alert_id, prompts[alert_id], caller, session, max_parse_retries)
        store.append_jsonl(run_dir.results, record)
        say("[" + str(i + 1).rjust(len(str(len(todo_ids)))) + "/" + str(len(todo_ids)) + "] " + alert_id + " " + record["status"]
            + " calls=" + str(record["model_calls"]) + " " + "%.1fs" % (CLOCK() - started))
        if record["status"] == STATUS_MODEL_ERROR:
            consecutive = consecutive + 1
        else:
            consecutive = 0
        if consecutive >= MAX_CONSECUTIVE_MODEL_ERRORS:
            return "stopped_after_model_errors"
    return "finished"


def count_lines(path):
    if not os.path.exists(path):
        return 0
    with open(path, "r", encoding="utf-8") as f:
        return len([line for line in f.read().splitlines() if line.strip() != ""])


def git_info():
    info = {"commit": None, "dirty": None}
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=config.PROJECT_ROOT, timeout=20)
        if commit.returncode == 0:
            info["commit"] = commit.stdout.strip()
        status = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, cwd=config.PROJECT_ROOT, timeout=20)
        if status.returncode == 0:
            info["dirty"] = status.stdout.strip() != ""
    except Exception:
        pass
    return info


def package_versions():
    versions = {}
    for name in ["pydantic", "pandas", "google-genai"]:
        try:
            import importlib.metadata
            versions[name] = importlib.metadata.version(name)
        except Exception:
            versions[name] = None
    return versions


def week1_snapshot():
    paths = [config.DEV_ALERTS_PATH, config.FLOW_STORE_DEV_PATH, config.MANIFEST_PATH, config.THRESHOLD_PATH,
             config.MODEL_PATH, config.FEATURE_LIST_PATH]
    snapshot = {}
    for path in paths:
        if os.path.exists(path):
            snapshot[os.path.relpath(path, config.PROJECT_ROOT).replace(os.sep, "/")] = store.file_sha256(path)
    return snapshot


def load_inputs():
    alerts = triage_inputs.load_dev_alerts()
    flows = triage_inputs.load_dev_flow_store()
    hashes = {
        "dev_alerts_sha256": store.file_sha256(config.DEV_ALERTS_PATH),
        "flow_store_dev_sha256": store.file_sha256(config.FLOW_STORE_DEV_PATH),
    }
    manifest = store.read_json(config.MANIFEST_PATH)
    expected_alerts = manifest["files"]["dev_alerts"]["file_sha256"]
    expected_flows = manifest["files"]["flow_store_dev"]["file_sha256"]
    if hashes["dev_alerts_sha256"] != expected_alerts or hashes["flow_store_dev_sha256"] != expected_flows:
        raise SystemExit("STOPPED: the dev alert file or dev flow store does not match eval/MANIFEST.json. Run python src/verify_eval.py.")
    return alerts, flows, hashes


def check_llm_config():
    needed = ["models", "get_api_key", "TEMPERATURE", "MAX_OUTPUT_TOKENS", "MAX_RETRIES"]
    missing = [name for name in needed if not hasattr(llm_config, name)]
    if len(missing) > 0:
        raise SystemExit("STOPPED: llm_config.py has no " + ", ".join(missing) + ". Day 3 expects the Day 1 names.")
    provider = str(getattr(llm_config, "PROVIDER", "gemini")).lower()
    if "gemini" not in provider and "google" not in provider:
        raise SystemExit("STOPPED: llm_config.PROVIDER is '" + provider + "'. Day 3 is Gemini only.")
    sizes = llm_config.models()
    for size in ["small", "strong"]:
        if size not in sizes or not str(sizes[size]).lower().startswith("gemini"):
            raise SystemExit("STOPPED: the " + size + " model id is '" + str(sizes.get(size)) + "', not a Gemini model. Check llm_config.py and .env.")
    return sizes


def build_all_prompts(alerts, flows):
    flows = flows.copy()
    flows["timestamp"] = pd.to_datetime(flows["timestamp"])
    prompts = {}
    for i in range(len(alerts)):
        row = alerts.iloc[i]
        model_input, prompt = baseline_prompt.build_prompt_for_row(row, flows)
        prompts[row["alert_id"]] = prompt
    return prompts


def make_client(model, api_key, timeout_seconds):
    return gemini_client.GeminiClient(model, baseline_prompt.SYSTEM_PROMPT, llm_config.TEMPERATURE, llm_config.MAX_OUTPUT_TOKENS,
                                      GENERATION_SEED, api_key=api_key, timeout_seconds=timeout_seconds)


def settings_for(model, rpm):
    return {
        "temperature": llm_config.TEMPERATURE,
        "max_output_tokens": llm_config.MAX_OUTPUT_TOKENS,
        "seed": GENERATION_SEED,
        "timeout_seconds": getattr(llm_config, "REQUEST_TIMEOUT_SECONDS", 60),
        "parse_retries": llm_config.MAX_RETRIES,
        "transport_retries": TRANSPORT_RETRIES,
        "requests_per_minute": rpm,
    }


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Week 2 Day 3: baseline prompt v1, one plain Gemini call per DEV alert. Dev set only.")
    parser.add_argument("--model", choices=["small", "strong"], default="small")
    parser.add_argument("--limit", type=int, default=None, help="only the first N dev alerts (smoke test)")
    parser.add_argument("--run-name", default=None)
    parser.add_argument("--resume", action="store_true", help="continue an unfinished run; needs --run-name")
    parser.add_argument("--retry-model-errors", action="store_true", help="with --resume: run again the alerts that ended in model_error")
    parser.add_argument("--rpm", type=float, default=DEFAULT_RPM, help="model calls per minute, retries included")
    parser.add_argument("--dry-run", action="store_true", help="build and check every prompt, call nothing, write nothing")
    parser.add_argument("--runs-dir", default=RUNS_ROOT)
    args = parser.parse_args(argv)
    if args.resume and args.run_name is None:
        parser.error("--resume needs --run-name")
    if args.resume and args.limit is not None:
        parser.error("--limit cannot be used with --resume; the run keeps its original alert list")
    if args.retry_model_errors and not args.resume:
        parser.error("--retry-model-errors needs --resume")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be 1 or more")
    if args.rpm <= 0:
        parser.error("--rpm must be above 0")
    return args


def summarize(run_dir, ids):
    records = store.read_jsonl(run_dir.results)
    latest = store.latest_results(records)
    counts = {STATUS_OK: 0, STATUS_PARSE_FAILED: 0, STATUS_MODEL_ERROR: 0}
    missing = 0
    first_try_bad = 0
    calls = 0
    tokens = 0
    for alert_id in ids:
        if alert_id not in latest:
            missing = missing + 1
            continue
        r = latest[alert_id]
        counts[r["status"]] = counts[r["status"]] + 1
        if r.get("malformed_first_try"):
            first_try_bad = first_try_bad + 1
        calls = calls + r.get("model_calls", 0)
        if r.get("total_tokens"):
            tokens = tokens + r["total_tokens"]
    return {"latest": latest, "counts": counts, "not_run": missing, "malformed_first_try": first_try_bad,
            "model_calls": calls, "total_tokens": tokens}


def finalize(run_dir, ids, meta, session_info, ended_because, log_before, snapshot_before):
    summary = summarize(run_dir, ids)
    store.write_verdicts_csv(run_dir.verdicts_csv, ids, summary["latest"])
    log_after = count_lines(config.FROZEN_ACCESS_LOG)
    snapshot_after = week1_snapshot()
    session_info["finished_utc"] = utc_now()
    session_info["ended_because"] = ended_because
    meta["sessions"][-1] = session_info
    meta["counts"] = summary["counts"]
    meta["not_run"] = summary["not_run"]
    meta["malformed_first_try"] = summary["malformed_first_try"]
    meta["model_calls"] = summary["model_calls"]
    meta["total_tokens"] = summary["total_tokens"]
    meta["frozen_access_log_lines_before"] = log_before
    meta["frozen_access_log_lines_after"] = log_after
    meta["frozen_access_log_unchanged"] = log_before == log_after
    meta["week1_files_unchanged"] = snapshot_before == snapshot_after
    done = summary["not_run"] == 0 and summary["counts"][STATUS_MODEL_ERROR] == 0
    if done:
        meta["status"] = "complete"
    else:
        meta["status"] = "incomplete"
    store.write_json_atomic(run_dir.meta, meta)
    return summary, meta


def print_summary(summary, meta, ids):
    print("")
    print("Run " + meta["run_name"] + " (" + meta["status"] + ")")
    print("alerts in run: " + str(len(ids)) + ", ok: " + str(summary["counts"][STATUS_OK]) + ", parse_failed: " + str(summary["counts"][STATUS_PARSE_FAILED])
          + ", model_error: " + str(summary["counts"][STATUS_MODEL_ERROR]) + ", not run yet: " + str(summary["not_run"]))
    print("replies that needed a retry (malformed on the first try): " + str(summary["malformed_first_try"]))
    print("model calls: " + str(summary["model_calls"]) + ", total tokens: " + str(summary["total_tokens"]))
    print("frozen access log unchanged: " + str(meta["frozen_access_log_unchanged"]) + ", Week 1 files unchanged: " + str(meta["week1_files_unchanged"]))
    print("results: " + os.path.join(meta["run_dir"], "results.jsonl"))
    if meta["status"] != "complete":
        print("Not complete. Continue with: python src/run_baseline_dev.py --resume --run-name " + meta["run_name"]
              + " (add --retry-model-errors to run the model_error alerts again)")


def main(argv=None):
    args = parse_args(argv)
    if os.environ.get(config.FROZEN_UNLOCK_ENV):
        raise SystemExit("STOPPED: " + config.FROZEN_UNLOCK_ENV + " is set in this shell. Unset it. Day 3 uses the dev set only.")
    sizes = check_llm_config()
    model = sizes[args.model]
    if args.model == "strong":
        print("Note: the strong model may use output tokens for internal thinking, which counts against max_output_tokens.")

    alerts, flows, input_hashes = load_inputs()
    ids_all = list(alerts["alert_id"])
    if len(set(ids_all)) != len(ids_all) or not all([a.startswith("DEV-") for a in ids_all]):
        raise SystemExit("STOPPED: the alert ids are not unique DEV- ids. This is not the dev set.")

    run_dir = None
    meta = None
    if args.resume:
        run_dir = store.RunDir(os.path.join(args.runs_dir, args.run_name))
        if not os.path.exists(run_dir.meta):
            raise SystemExit("STOPPED: no run named " + args.run_name + " in " + args.runs_dir)
        meta = store.read_json(run_dir.meta)
        selected_ids = list(meta["selected_alert_ids"])
        alerts = alerts[alerts["alert_id"].isin(selected_ids)]
    else:
        if args.limit is not None:
            alerts = alerts.iloc[:args.limit]
        selected_ids = list(alerts["alert_id"])

    prompts = build_all_prompts(alerts, flows)
    print(str(len(prompts)) + " prompts built from " + str(len(selected_ids)) + " dev alerts; prompt " + baseline_prompt.PROMPT_VERSION
          + " sha256 " + baseline_prompt.prompt_sha256()[:12])

    if args.dry_run:
        first_id = selected_ids[0]
        print("")
        print("Dry run: no model call, no files written. Model that would be used: " + model)
        print("--- system prompt ---")
        print(baseline_prompt.SYSTEM_PROMPT)
        print("--- user prompt for " + first_id + " ---")
        print(prompts[first_id])
        return 0

    settings = settings_for(model, args.rpm)
    if meta is None:
        run_name = args.run_name
        if run_name is None:
            run_name = "dev_" + model + "_" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_dir = store.RunDir(os.path.join(args.runs_dir, run_name))
        if os.path.exists(run_dir.path):
            raise SystemExit("STOPPED: " + run_dir.path + " already exists. Use another --run-name, or --resume.")
        git = git_info()
        meta = {
            "run_name": run_name,
            "run_dir": run_dir.path,
            "set": "dev",
            "prompt_version": baseline_prompt.PROMPT_VERSION,
            "prompt_sha256": baseline_prompt.prompt_sha256(),
            "provider": "gemini",
            "model": model,
            "model_size": args.model,
            "settings": settings,
            "inputs": input_hashes,
            "n_selected": len(selected_ids),
            "limit": args.limit,
            "selected_alert_ids": selected_ids,
            "git": git,
            "python": platform.python_version(),
            "packages": package_versions(),
            "sessions": [],
            "status": "running",
        }
    else:
        if meta["model"] != model or meta["prompt_sha256"] != baseline_prompt.prompt_sha256() or meta["inputs"] != input_hashes:
            raise SystemExit("STOPPED: the model, prompt or input files differ from the run being resumed. Start a new run instead.")
        for key in ["temperature", "max_output_tokens", "seed", "parse_retries"]:
            if meta["settings"][key] != settings[key]:
                raise SystemExit("STOPPED: setting " + key + " differs from the run being resumed. Start a new run instead.")
        meta["settings"]["requests_per_minute"] = args.rpm

    api_key = llm_config.get_api_key()
    client = make_client(model, api_key, settings["timeout_seconds"])

    os.makedirs(run_dir.path, exist_ok=True)
    records = store.read_jsonl(run_dir.results, repair=True)
    latest = store.latest_results(records)
    todo = []
    for alert_id in selected_ids:
        if alert_id not in latest:
            todo.append(alert_id)
        elif args.retry_model_errors and latest[alert_id]["status"] == STATUS_MODEL_ERROR:
            todo.append(alert_id)
    session = len(meta["sessions"]) + 1
    session_info = {"session": session, "started_utc": utc_now(), "args": {"limit": args.limit, "rpm": args.rpm, "resume": args.resume,
                                                                           "retry_model_errors": args.retry_model_errors}}
    meta["sessions"].append(session_info)
    if session == 1:
        with open(run_dir.prompt_snapshot, "w", encoding="utf-8") as f:
            f.write("PROMPT " + baseline_prompt.PROMPT_VERSION + " sha256 " + baseline_prompt.prompt_sha256() + "\n\n=== system prompt ===\n"
                    + baseline_prompt.SYSTEM_PROMPT + "\n\n=== user prompt for " + selected_ids[0] + " ===\n" + prompts[selected_ids[0]] + "\n")
    store.write_json_atomic(run_dir.meta, meta)

    log_before = count_lines(config.FROZEN_ACCESS_LOG)
    snapshot_before = week1_snapshot()
    print("Run " + meta["run_name"] + ": " + str(len(todo)) + " alerts to do, " + str(len(selected_ids) - len(todo)) + " already done. Model " + model
          + ", " + str(args.rpm) + " calls per minute.")

    caller = RecordingCaller(client, Throttle(args.rpm), run_dir, session, model)
    ended = "finished"
    exit_code = 0
    try:
        ended = run_alerts(todo, prompts, run_dir, caller, session, llm_config.MAX_RETRIES)
        if ended != "finished":
            exit_code = 2
            print("STOPPED: " + str(MAX_CONSECUTIVE_MODEL_ERRORS) + " alerts in a row ended in model_error. Check the key, quota and network.")
    except gemini_client.PermanentModelError as error:
        ended = "permanent_error"
        exit_code = 2
        print("STOPPED: the model call was refused and will not work if repeated: " + str(error))
    except KeyboardInterrupt:
        ended = "interrupted"
        exit_code = 130
        print("Interrupted. Finished alerts are saved.")
    summary, meta = finalize(run_dir, selected_ids, meta, session_info, ended, log_before, snapshot_before)
    print_summary(summary, meta, selected_ids)
    if not meta["frozen_access_log_unchanged"] or not meta["week1_files_unchanged"]:
        print("WARNING: a Week 1 file or the frozen access log changed during the run. Check git status and eval/frozen_access.log before continuing.")
        exit_code = 3
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
