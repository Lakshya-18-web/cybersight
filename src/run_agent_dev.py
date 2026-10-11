"""Week 3 Day 5: run the agent graph WITH the verdict step on DEV alerts, and write a run folder the Week 2 evaluator can score.

  python src/run_agent_dev.py --run-name dev_agent_v1_flash_lite --limit 5      # a small real run first (needs GEMINI_API_KEY)
  python src/run_agent_dev.py --run-name dev_agent_v1_flash_lite                # all dev alerts
  python src/run_agent_dev.py --run-name dev_agent_v1_flash_lite --resume       # continue after an interruption
  python src/run_agent_dev.py --fake-model --limit 5 --run-name FAKE_smoke      # offline plumbing test: canned replies, no API, never evaluable

Week 3 Day 6 (specialist ablation): --arm A|B|C|D|E runs one pre-registered arm (agents/ablation.py): A full graph, B no beaconing, C no enrichment, D no traffic (so no beaconing: enrichment only),
E no specialists. An arm run defaults to runs/week3_day6 (runs/week3_day6_FAKE with --fake-model), records its configuration in run_meta.json (agent.ablation) and is resumed only with the same --arm.
Without --arm nothing changes from Day 5. The verdict prompt (agent_v1) and every setting are the same in every arm; a disabled specialist is shown to the model as not_run, "disabled in this configuration".

Dev set only. This script never reads labels (scoring is src/evaluate.py), never opens the frozen set, and does not touch src/prompt_registry.py or the baseline_v3 prompt.

What one alert goes through: traffic analyst, C2 beaconing analyst (when the routing gate opens), enrichment agent, then the verdict node, which makes the model call(s).
Model and settings are held equal to the locked baseline_v3 run (--baseline-run): the same model id, temperature, max output tokens, seed and parse retries. The run refuses to start if
they differ, or if the baseline run is not a baseline_v3 run with the registered prompt hash. The only intended difference is the prompt and the evidence the model is shown.

Run folder (same files as Week 2): results.jsonl, raw_responses.jsonl, run_meta.json, prompt_snapshot.txt, verdicts.csv. Safety:
  * a new run refuses an existing folder; results are appended one line per alert and fsync'd; --resume only continues a run whose model, prompt, settings, inputs and graph setup match;
  * the latest record per alert wins; --retry-model-errors re-runs only the alerts that ended in model_error (model call failures and graph errors);
  * a permanent model error (bad key, refused request) stops the run at once; 5 model-call failures in a row stop it too.
A --fake-model run is flagged fake_model=true in run_meta.json, defaults to a separate runs folder, and the comparison script refuses it.
"""
import os
import sys
import argparse
import platform
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
import llm_config
import triage_inputs
import prompt_registry
import baseline_store as store
import gemini_client
import run_baseline_dev as base
from agents import state as S
from agents import verdict_node as VN
from agents import verdict_prompt
import ablation_config as ablation
from agents.graph import build_graph, run_alert
from tools import FlowStore, build_registry

RUNS_ROOT = os.path.join(config.PROJECT_ROOT, "runs", "week3_agent_v1")
FAKE_RUNS_ROOT = os.path.join(config.PROJECT_ROOT, "runs", "week3_agent_v1_FAKE")
DAY6_RUNS_ROOT = os.path.join(config.PROJECT_ROOT, "runs", "week3_day6")
DAY6_FAKE_RUNS_ROOT = os.path.join(config.PROJECT_ROOT, "runs", "week3_day6_FAKE")
BASELINE_RUNS_ROOT = base.RUNS_ROOT
DEFAULT_BASELINE_RUN = "dev_flash_lite_v3_final"
BASELINE_PROMPT = prompt_registry.V3
RUNNER = "run_agent_dev"
FAKE_RPM = 100000.0
MODEL_ERROR_STATUS = base.STATUS_MODEL_ERROR
CODE_GRAPH_ERROR = "graph_error"
SETTING_KEYS = ["temperature", "max_output_tokens", "seed", "parse_retries"]


# ------------------------------------------------------------------------------------------------ fake model (offline plumbing only)
VALID_BENIGN = '{"is_malicious": false, "attack_type": "BENIGN", "mitre_technique": "NONE", "severity": "none", "evidence": "FAKE canned reply for plumbing tests."}'
VALID_ATTACK = '{"is_malicious": true, "attack_type": "PortScan", "mitre_technique": "T1046", "severity": "medium", "evidence": "FAKE canned reply for plumbing tests."}'
MALFORMED = "this is not json"
FAKE_SCRIPT = ["ok_benign", "ok_attack", "malformed_then_ok", "always_malformed", "transient_then_ok", "unavailable"]


class FakeClient:
    """Stands in for GeminiClient. Replies are canned and do NOT depend on the alert, so they are not verdicts of any kind; they only exercise the plumbing:
    a valid reply, a retry that recovers, retries that run out, a transport error that recovers, and a model that stays unreachable."""

    def __init__(self, script=None):
        self.script = list(script or FAKE_SCRIPT)
        self.scenario = self.script[0]
        self.calls_this_alert = 0

    def begin(self, alert_number):
        self.scenario = self.script[alert_number % len(self.script)]
        self.calls_this_alert = 0

    def _record(self, text):
        return gemini_client.CallRecord(text=text, finish_reason="STOP", block_reason=None, prompt_tokens=10, output_tokens=5, thinking_tokens=0, total_tokens=15)

    def generate(self, prompt):
        self.calls_this_alert += 1
        n, scenario = self.calls_this_alert, self.scenario
        if scenario == "ok_benign":
            return self._record(VALID_BENIGN)
        if scenario == "ok_attack":
            return self._record(VALID_ATTACK)
        if scenario == "malformed_then_ok":
            return self._record(MALFORMED if n == 1 else VALID_ATTACK)
        if scenario == "always_malformed":
            return self._record(MALFORMED)
        if scenario == "transient_then_ok":
            if n == 1:
                raise gemini_client.TransientModelError("fake transient error", 503)
            return self._record(VALID_BENIGN)
        if scenario == "unavailable":
            raise gemini_client.TransientModelError("fake transient error", 503)
        raise ValueError("unknown fake scenario " + str(scenario))


# ------------------------------------------------------------------------------------------------ baseline check
def check_baseline(runs_dir, baseline_run):
    """Read the locked baseline run's run_meta.json and return it. Raises SystemExit unless it is a baseline_v3 run with the registered hash."""
    path = os.path.join(runs_dir, baseline_run, "run_meta.json")
    if not os.path.exists(path):
        raise SystemExit("STOPPED: the baseline run " + baseline_run + " has no run_meta.json in " + runs_dir + ". The agent run must be held equal to it; pass --baseline-run and --baseline-runs-dir.")
    meta = store.read_json(path)
    expected = prompt_registry.get_prompt(BASELINE_PROMPT).sha256
    if meta.get("prompt_version") != BASELINE_PROMPT or meta.get("prompt_sha256") != expected:
        raise SystemExit("STOPPED: the baseline run " + baseline_run + " is not a " + BASELINE_PROMPT + " run with the registered prompt hash.")
    if meta.get("set") != "dev":
        raise SystemExit("STOPPED: the baseline run " + baseline_run + " is not a dev run.")
    return meta


def baseline_summary(meta, baseline_run):
    return {"run_name": baseline_run, "prompt_version": meta["prompt_version"], "prompt_sha256": meta["prompt_sha256"], "model": meta["model"],
            "settings": {k: (meta.get("settings") or {}).get(k) for k in SETTING_KEYS}, "status": meta.get("status")}


def check_equal_setup(baseline_meta, model, settings):
    problems = []
    if baseline_meta["model"] != model:
        problems.append("model: the baseline used " + str(baseline_meta["model"]) + " but this run would use " + str(model) + " (check SOC_SMALL_MODEL in .env)")
    for key in SETTING_KEYS:
        if (baseline_meta.get("settings") or {}).get(key) != settings[key]:
            problems.append(key + ": the baseline used " + str((baseline_meta.get("settings") or {}).get(key)) + " but this run would use " + str(settings[key]))
    if problems:
        raise SystemExit("STOPPED: this run is not held equal to the baseline run:\n- " + "\n- ".join(problems))


# ------------------------------------------------------------------------------------------------ one alert
def make_record(alert_id, final, caller, session, graph_seconds, spec):
    """The results.jsonl line for one alert: the Week 2 result fields (so evaluate.py reads it unchanged) plus the agent context. final may be None when the graph itself failed."""
    verdict = final.get("verdict") if isinstance(final, dict) else None
    record = {"alert_id": alert_id, "status": None, "verdict": None, "error_code": None, "error_detail": None, "attempts": 0, "malformed_first_try": None,
              "attempt_log": [], "repairs": [], "prompt_sha256": None, "session": session}
    if verdict is not None:
        for key in ("status", "verdict", "error_code", "error_detail", "attempts", "malformed_first_try", "attempt_log", "repairs", "prompt_sha256"):
            record[key] = verdict[key]
        record["agent_prompt_version"] = verdict["prompt_version"]
        record["agent_prompt_sha256"] = verdict["agent_prompt_sha256"]
        record["upstream"] = verdict["upstream"]
    else:
        record["status"] = MODEL_ERROR_STATUS
        record["error_code"] = CODE_GRAPH_ERROR
        record["error_detail"] = ("the graph ended with status " + str(final.get("status")) + " before the verdict step ran") if isinstance(final, dict) else "the graph raised before it finished"
        record["agent_prompt_version"] = spec.version
        record["agent_prompt_sha256"] = spec.sha256
        record["upstream"] = VN.upstream_health(final) if isinstance(final, dict) else None
    record["attempts"] = len(caller.calls)
    record["model_calls"] = len(caller.calls)
    record["prompt_tokens"] = base.add_up(caller.calls, "prompt_tokens")
    record["output_tokens"] = base.add_up(caller.calls, "output_tokens")
    record["thinking_tokens"] = base.add_up(caller.calls, "thinking_tokens")
    record["total_tokens"] = base.add_up(caller.calls, "total_tokens")
    record["latency_seconds"] = round(sum([c["latency_seconds"] for c in caller.calls]), 3)   # model-call time only: the same definition the baseline run uses
    record["graph_seconds"] = round(graph_seconds, 3)                                           # the whole alert, tools and model: what the agent costs end to end
    record["finish_reasons"] = [c["finish_reason"] for c in caller.calls]
    record["finished_utc"] = base.utc_now()
    if isinstance(final, dict):
        record["graph_status"] = final.get("status")
        record["graph_version"] = final.get("graph_version")
        record["trace"] = final.get("trace")
        record["routing"] = final.get("routing")
        record["tool_calls"] = len(final.get("evidence", []))
        record["graph_errors"] = final.get("errors")
    else:
        record["graph_status"] = "error"
    return record


def process_alert(alert_id, alert, graph, caller, client, number, session, spec):
    caller.start(alert_id)
    if hasattr(client, "begin"):
        client.begin(number)
    started = base.CLOCK()
    final = None
    try:
        final = run_alert(graph, alert, verdict_enabled=True)
    except gemini_client.PermanentModelError:
        raise
    except Exception as error:   # an unusable alert or a graph failure: recorded, never turned into a verdict
        record = make_record(alert_id, None, caller, session, base.CLOCK() - started, spec)
        record["error_detail"] = "the graph raised " + type(error).__name__
        return record
    return make_record(alert_id, final, caller, session, base.CLOCK() - started, spec)


def run_alerts(todo, alerts_by_id, order, graph, caller, client, session, spec, run_dir, say=print):
    consecutive = 0
    for i, alert_id in enumerate(todo):
        started = base.CLOCK()
        record = process_alert(alert_id, alerts_by_id[alert_id], graph, caller, client, order[alert_id], session, spec)
        store.append_jsonl(run_dir.results, record)
        if not os.path.exists(run_dir.prompt_snapshot):
            try:
                write_snapshot(run_dir, spec, alert_id, alerts_by_id[alert_id], graph)
            except Exception as error:   # the snapshot is a convenience copy of the prompt; the next alert tries again
                say("prompt snapshot not written yet (" + type(error).__name__ + ")")
        say("[" + str(i + 1).rjust(len(str(len(todo)))) + "/" + str(len(todo)) + "] " + alert_id + " " + record["status"] + (" (" + record["error_code"] + ")" if record["error_code"] else "")
            + " graph=" + str(record["graph_status"]) + " calls=" + str(record["model_calls"]) + " " + "%.1fs" % (base.CLOCK() - started))
        if record["status"] == MODEL_ERROR_STATUS and record["error_code"] in VN.MODEL_ERROR_CODES:
            consecutive += 1
        else:
            consecutive = 0
        if consecutive >= base.MAX_CONSECUTIVE_MODEL_ERRORS:
            return "stopped_after_model_errors"
    return "finished"


def write_snapshot(run_dir, spec, alert_id, alert, graph):
    """prompt_snapshot.txt: the agent prompt and the user prompt for the first alert. Built by running the tools only (the verdict step is off), so no model call is made."""
    state = run_alert(graph, alert, verdict_enabled=False)
    with open(run_dir.prompt_snapshot, "w", encoding="utf-8") as f:
        f.write(verdict_prompt.snapshot_text(spec, alert_id, verdict_prompt.build_user_prompt(state, spec)))


# ------------------------------------------------------------------------------------------------ summary
def agent_summary(run_dir, ids):
    latest = store.latest_results(store.read_jsonl(run_dir.results))
    graph_status, error_codes, paths = {}, {}, {}
    tool_calls = graph_seconds = 0
    for alert_id in ids:
        r = latest.get(alert_id)
        if r is None:
            continue
        graph_status[str(r.get("graph_status"))] = graph_status.get(str(r.get("graph_status")), 0) + 1
        if r.get("error_code"):
            error_codes[r["error_code"]] = error_codes.get(r["error_code"], 0) + 1
        path = ">".join(n for n in (r.get("trace") or []) if n != S.NODE_SUPERVISOR)
        paths[path] = paths.get(path, 0) + 1
        tool_calls += r.get("tool_calls") or 0
        graph_seconds += r.get("graph_seconds") or 0
    return {"graph_status_counts": dict(sorted(graph_status.items())), "error_code_counts": dict(sorted(error_codes.items())), "path_counts": dict(sorted(paths.items())),
            "tool_calls": tool_calls, "graph_seconds_total": round(graph_seconds, 3)}


# ------------------------------------------------------------------------------------------------ main
def parse_args(argv):
    parser = argparse.ArgumentParser(description="Week 3 Day 5: the agent graph with the verdict step, one run folder per run, DEV alerts only.")
    parser.add_argument("--run-name", default=None, help="name of the run folder (required with --resume)")
    parser.add_argument("--limit", type=int, default=None, help="only the first N dev alerts (smoke test)")
    parser.add_argument("--resume", action="store_true", help="continue an unfinished run; needs --run-name")
    parser.add_argument("--retry-model-errors", action="store_true", help="with --resume: run again the alerts that ended in model_error")
    parser.add_argument("--rpm", type=float, default=base.DEFAULT_RPM, help="model calls per minute, retries included (the baseline default)")
    parser.add_argument("--dry-run", action="store_true", help="run the tools for the first alert, print the verdict prompt, call no model, write nothing")
    parser.add_argument("--fake-model", action="store_true", help="offline plumbing test: canned replies instead of Gemini; the run is flagged fake and cannot be compared")
    parser.add_argument("--arm", choices=sorted(ablation.ARMS), default=None, help="Day 6 ablation arm: " + "; ".join(k + " = " + v["label"] for k, v in ablation.ARMS.items()))
    parser.add_argument("--runs-dir", default=None, help="default runs/week3_agent_v1 (runs/week3_agent_v1_FAKE with --fake-model); with --arm runs/week3_day6 (runs/week3_day6_FAKE)")
    parser.add_argument("--baseline-run", default=DEFAULT_BASELINE_RUN, help="the locked baseline_v3 run this run is held equal to")
    parser.add_argument("--baseline-runs-dir", default=BASELINE_RUNS_ROOT)
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
    if args.fake_model and args.run_name is not None and not args.run_name.startswith("FAKE"):
        parser.error("with --fake-model the run name must start with FAKE, so a fake run is never mistaken for a real one")
    if not args.fake_model and args.run_name is not None and args.run_name.startswith("FAKE"):
        parser.error("run names starting with FAKE are reserved for --fake-model runs")
    if args.runs_dir is None:
        if args.arm is not None:
            args.runs_dir = DAY6_FAKE_RUNS_ROOT if args.fake_model else DAY6_RUNS_ROOT
        else:
            args.runs_dir = FAKE_RUNS_ROOT if args.fake_model else RUNS_ROOT
    return args


def make_graph(registry, caller, spec, disabled=()):
    node = VN.make_verdict_node(caller, spec=spec, max_retries=llm_config.MAX_RETRIES, fatal=(gemini_client.PermanentModelError,), unavailable=(base.ModelUnavailable,))
    return build_graph(registry, verdict_node=node, disabled=disabled)


def ablation_record(arm):
    """The run_meta record of an ablation arm, or None for a run without --arm (the Day 5 format, unchanged)."""
    if arm is None:
        return None
    disabled = ablation.arm_disabled(arm)
    return {"arm": arm, "label": ablation.ARMS[arm]["label"], "disabled": list(disabled), "enabled": list(ablation.enabled_specialists(disabled)), "cascade_skipped": list(ablation.cascade_skipped(disabled)),
            "disabled_reason_shown_to_model": ablation.DISABLED_REASON}


def stored_arm(meta):
    """The arm a stored run was made with (None for a run without one, such as the Day 5 run)."""
    record = (meta.get("agent") or {}).get("ablation")
    return record.get("arm") if isinstance(record, dict) else None


def print_summary(summary, meta, ids, agent):
    print("")
    print("Run " + meta["run_name"] + " (" + meta["status"] + ")" + ("  [FAKE MODEL: plumbing test only, not evaluable]" if meta["fake_model"] else ""))
    print("alerts in run: " + str(len(ids)) + ", ok: " + str(summary["counts"][base.STATUS_OK]) + ", parse_failed: " + str(summary["counts"][base.STATUS_PARSE_FAILED])
          + ", model_error: " + str(summary["counts"][base.STATUS_MODEL_ERROR]) + ", not run yet: " + str(summary["not_run"]))
    print("graph statuses: " + str(agent["graph_status_counts"]) + ", error codes: " + str(agent["error_code_counts"]))
    print("replies that needed a retry (malformed on the first try): " + str(summary["malformed_first_try"]))
    if (meta.get("agent") or {}).get("ablation"):
        print("ablation arm: " + ablation.describe(meta["agent"]["ablation"]["disabled"]))
    print("model calls: " + str(summary["model_calls"]) + ", total tokens: " + str(summary["total_tokens"]) + ", tool calls: " + str(agent["tool_calls"]))
    print("frozen access log unchanged: " + str(meta["frozen_access_log_unchanged"]) + ", Week 1 files unchanged: " + str(meta["week1_files_unchanged"]))
    print("results: " + os.path.join(meta["run_dir"], "results.jsonl"))
    if meta["status"] != "complete":
        print("Not complete. Continue with: python src/run_agent_dev.py --resume --run-name " + meta["run_name"] + (" --fake-model" if meta["fake_model"] else "")
              + " (add --retry-model-errors to run the model_error alerts again)")


def main(argv=None):
    args = parse_args(argv)
    if os.environ.get(config.FROZEN_UNLOCK_ENV):
        raise SystemExit("STOPPED: " + config.FROZEN_UNLOCK_ENV + " is set in this shell. This runner uses the dev set only.")
    sizes = base.check_llm_config()
    model = sizes["small"]   # the baseline_v3 run used the small model; check_equal_setup confirms it against the baseline run's own record
    alerts, flows, input_hashes = base.load_inputs()
    ids_all = list(alerts["alert_id"])
    if len(set(ids_all)) != len(ids_all) or not all([a.startswith("DEV-") for a in ids_all]):
        raise SystemExit("STOPPED: the alert ids are not unique DEV- ids. This is not the dev set.")
    # the alert order is the dev alert file order, the same order the baseline run used

    meta = None
    run_dir = None
    if args.resume:
        run_dir = store.RunDir(os.path.join(args.runs_dir, args.run_name))
        if not os.path.exists(run_dir.meta):
            raise SystemExit("STOPPED: no run named " + args.run_name + " in " + args.runs_dir)
        meta = store.read_json(run_dir.meta)
        if meta.get("runner") != RUNNER:
            raise SystemExit("STOPPED: " + args.run_name + " was not made by " + RUNNER + ".")
        if meta.get("fake_model") != args.fake_model:
            raise SystemExit("STOPPED: fake_model is " + str(meta.get("fake_model")) + " for that run; pass --fake-model to match it.")
        selected_ids = list(meta["selected_alert_ids"])
        if stored_arm(meta) != args.arm:
            raise SystemExit("STOPPED: that run was made with ablation arm " + str(stored_arm(meta)) + " but this command says --arm " + str(args.arm) + ". Resume it with the same arm.")
    else:
        selected_ids = list(alerts["alert_id"])[:args.limit] if args.limit is not None else list(alerts["alert_id"])
    order = {alert_id: i for i, alert_id in enumerate(selected_ids)}

    spec = verdict_prompt.get_prompt()
    disabled = ablation.arm_disabled(args.arm) if args.arm is not None else ()
    settings = base.settings_for(model, args.rpm)
    baseline_meta = None
    if args.fake_model:
        if os.path.exists(os.path.join(args.baseline_runs_dir, args.baseline_run, "run_meta.json")):
            baseline_meta = check_baseline(args.baseline_runs_dir, args.baseline_run)
    else:
        baseline_meta = check_baseline(args.baseline_runs_dir, args.baseline_run)
        check_equal_setup(baseline_meta, model, settings)

    store_ = FlowStore.from_dev()
    registry = build_registry(flow_store=store_)   # no reputation lookup
    alerts_by_id = {}
    selected_set = set(selected_ids)
    for _, row in alerts.iterrows():
        if row["alert_id"] in selected_set:
            alerts_by_id[row["alert_id"]] = S.alert_record(row, store_.frame)
    print(str(len(alerts_by_id)) + " dev alerts selected; verdict prompt " + spec.version + " sha256 " + spec.sha256[:12] + "; model " + model
          + (" (FAKE: canned replies)" if args.fake_model else ""))

    if args.dry_run:
        first_id = selected_ids[0]
        graph_for_dry_run = build_graph(registry, disabled=disabled)
        state = run_alert(graph_for_dry_run, alerts_by_id[first_id], verdict_enabled=False)
        print("")
        print("Dry run: the tools ran, no model was called, nothing was written. Model that would be used: " + model)
        if args.arm is not None:
            print("Ablation arm " + ablation.describe(disabled) + "; specialists that run: " + (", ".join(ablation.effective_specialists(disabled)) or "none"))
        print("--- system prompt ---")
        print(spec.system_prompt)
        print("--- user prompt for " + first_id + " ---")
        print(verdict_prompt.build_user_prompt(state, spec))
        return 0

    if meta is None:
        run_name = args.run_name
        if run_name is None:
            stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            if args.arm is not None:
                run_name = ("FAKE_" if args.fake_model else "") + "dev_agent_v1_d6_" + args.arm + "_" + stamp
            else:
                run_name = ("FAKE_" if args.fake_model else "dev_agent_") + model + "_" + stamp
        run_dir = store.RunDir(os.path.join(args.runs_dir, run_name))
        if os.path.exists(run_dir.path):
            raise SystemExit("STOPPED: " + run_dir.path + " already exists. Use another --run-name, or --resume.")
        meta = {"run_name": run_name, "run_dir": run_dir.path, "set": "dev", "runner": RUNNER, "fake_model": args.fake_model,
                "prompt_version": spec.version, "prompt_sha256": spec.sha256, "provider": "gemini", "model": model, "model_size": "small", "settings": settings,
                "inputs": input_hashes, "n_selected": len(selected_ids), "limit": args.limit, "selected_alert_ids": selected_ids,
                "agent": {"graph_version": S.GRAPH_VERSION, "verdict_enabled": True, "specialists": list(ablation.effective_specialists(disabled)),
                          "reputation_lookup": "not_consulted", "max_supervisor_visits": S.MAX_SUPERVISOR_VISITS,
                          "baseline": baseline_summary(baseline_meta, args.baseline_run) if baseline_meta is not None else None},
                "git": base.git_info(), "python": platform.python_version(), "packages": base.package_versions(), "sessions": [], "status": "running"}
        if args.arm is not None:
            meta["agent"]["ablation"] = ablation_record(args.arm)
    else:
        if meta["model"] != model or meta["prompt_sha256"] != spec.sha256 or meta["inputs"] != input_hashes:
            raise SystemExit("STOPPED: the model, prompt or input files differ from the run being resumed. Start a new run instead.")
        for key in SETTING_KEYS:
            if meta["settings"][key] != settings[key]:
                raise SystemExit("STOPPED: setting " + key + " differs from the run being resumed. Start a new run instead.")
        if (meta.get("agent") or {}).get("graph_version") != S.GRAPH_VERSION:
            raise SystemExit("STOPPED: the graph version differs from the run being resumed. Start a new run instead.")
        meta["settings"]["requests_per_minute"] = args.rpm

    original_sleep = base.SLEEP
    if args.fake_model:
        client = FakeClient()
        base.SLEEP = lambda seconds: None   # fake mode only, restored below: no real waiting between simulated retries
        rpm = FAKE_RPM
    else:
        client = base.make_client_for(model, llm_config.get_api_key(), settings["timeout_seconds"], spec)
        rpm = args.rpm
    meta["settings"]["requests_per_minute"] = rpm

    os.makedirs(run_dir.path, exist_ok=True)
    latest = store.latest_results(store.read_jsonl(run_dir.results, repair=True))
    todo = []
    for alert_id in selected_ids:
        if alert_id not in latest:
            todo.append(alert_id)
        elif args.retry_model_errors and latest[alert_id]["status"] == MODEL_ERROR_STATUS:
            todo.append(alert_id)
    session = len(meta["sessions"]) + 1
    session_info = {"session": session, "started_utc": base.utc_now(), "args": {"limit": args.limit, "rpm": rpm, "resume": args.resume, "retry_model_errors": args.retry_model_errors}}
    meta["sessions"].append(session_info)
    store.write_json_atomic(run_dir.meta, meta)

    log_before = base.count_lines(config.FROZEN_ACCESS_LOG)
    snapshot_before = base.week1_snapshot()
    print("Run " + meta["run_name"] + ": " + str(len(todo)) + " alerts to do, " + str(len(selected_ids) - len(todo)) + " already done. Model " + model + ", " + str(rpm) + " calls per minute.")

    caller = base.RecordingCaller(client, base.Throttle(rpm), run_dir, session, model)
    graph = make_graph(registry, caller, spec, disabled)
    ended, exit_code = "finished", 0
    try:
        ended = run_alerts(todo, alerts_by_id, order, graph, caller, client, session, spec, run_dir)
        if ended != "finished":
            exit_code = 2
            print("STOPPED: " + str(base.MAX_CONSECUTIVE_MODEL_ERRORS) + " alerts in a row ended in a model-call failure. Check the key, quota and network.")
    except gemini_client.PermanentModelError as error:
        ended, exit_code = "permanent_error", 2
        print("STOPPED: the model call was refused and will not work if repeated: " + str(error))
    except KeyboardInterrupt:
        ended, exit_code = "interrupted", 130
        print("Interrupted. Finished alerts are saved.")
    finally:
        base.SLEEP = original_sleep
    summary, meta = base.finalize(run_dir, selected_ids, meta, session_info, ended, log_before, snapshot_before)
    agent = agent_summary(run_dir, selected_ids)
    meta["agent"]["summary"] = agent
    store.write_json_atomic(run_dir.meta, meta)
    print_summary(summary, meta, selected_ids, agent)
    if not meta["frozen_access_log_unchanged"] or not meta["week1_files_unchanged"]:
        print("WARNING: a Week 1 file or the frozen access log changed during the run. Check git status and eval/frozen_access.log before continuing.")
        exit_code = 3
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
