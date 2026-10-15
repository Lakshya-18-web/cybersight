"""Week 4: run graph v2 on the DEV alerts with incident memory OFF or ON, and write a run folder the Week 2 evaluator can score.

  python src/week4/run_memory_dev.py --memory off --run-name dev_v2_mem_off        # needs GEMINI_API_KEY (a real model run: ask first)
  python src/week4/run_memory_dev.py --memory on  --run-name dev_v2_mem_on         # needs memory_store/ (python -m week4.seed_memory seed)
  python src/week4/run_memory_dev.py --memory on --resume --run-name dev_v2_mem_on
  python src/week4/run_memory_dev.py --memory on --fake-model --limit 5 --run-name FAKE_smoke   # offline plumbing test: canned replies, no API, never evaluable
  python src/week4/run_memory_dev.py --memory on --dry-run                                     # tools + memory for the first alert, prints the prompt, no model, writes nothing

Everything that makes the two arms comparable is held equal: the dev alerts and their order, the model, temperature, seed, token limit, parse retries (checked against the locked baseline_v3 run,
exactly as run_agent_dev.py does) and the graph. The ONLY differences are the ones under test: memory off uses the Week 3 verdict prompt (agent_v1) and no memory step; memory on adds the memory
step and the agent_v2_memory prompt. The risk policy (config/risk_policy.json) is applied to BOTH arms after the graph, so routing rates are comparable.

Dev set only. This script never reads labels (scoring is src/week4/evaluate_memory.py), never opens the frozen set, refuses to start if the frozen unlock variable is set, and with memory on
checks at start that no stored memory record shares a flow with a dev alert (fail closed).

Run folder: results.jsonl, raw_responses.jsonl, run_meta.json, prompt_snapshot.txt, verdicts.csv (the Week 2 files) + states.jsonl (the finished graph state and routing of every alert, for case ingestion).
Safety rules are the Week 3 ones: a new run refuses an existing folder; results are appended and fsync'd; --resume continues only a run whose model, prompt, settings, inputs, memory store, policy and
graph match; a permanent model error stops the run at once; 5 model-call failures in a row stop it too. No credential is written anywhere.
"""
import argparse
import datetime
import os
import platform
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))      # src/

import baseline_store as store
import config
import gemini_client
import llm_config
import run_agent_dev as w3
import run_baseline_dev as base
import week4
from agents import state as S1
from agents import verdict_node as VN
from agents import verdict_prompt as VP
from tools import FlowStore, build_registry

from week4 import policy as policy_module
from week4.graph import build as B
from week4.graph import prompt as P2
from week4.graph import state as S2
from week4.graph import verdict as VD
from week4.graph.memory_node import make_memory_node
from week4.memory import isolation
from week4.memory import store as MS
from week4.memory.errors import MemoryDataError, MemoryIsolationError, MemoryStoreError

RUNS_ROOT = os.path.join(config.PROJECT_ROOT, "runs", "week4_memory")
FAKE_RUNS_ROOT = os.path.join(config.PROJECT_ROOT, "runs", "week4_memory_FAKE")
DEFAULT_MEMORY_DIR = os.path.join(config.PROJECT_ROOT, "memory_store")
DEFAULT_K = MS.DEFAULT_K
RUNNER = "run_memory_dev"
SETTING_KEYS = w3.SETTING_KEYS
STATES_FILE = "states.jsonl"
MODEL_ERROR_STATUS = base.STATUS_MODEL_ERROR


def spec_for(memory_enabled):
    return P2.get_prompt() if memory_enabled else VP.get_prompt()


def memory_summary(memory):
    """The small, plain-data view of a memory result stored in results.jsonl (the full result lives in states.jsonl)."""
    if not isinstance(memory, dict):
        return None
    return {"status": memory.get("status"), "k_returned": memory.get("k_returned"), "label_counts": memory.get("label_counts"), "nearest_distance": memory.get("nearest_distance"),
            "error_code": memory.get("error_code"), "manifest_sha256": (memory.get("store") or {}).get("manifest_sha256")}


def make_v2_graph(registry, caller, memory_enabled, memory_store=None, k=DEFAULT_K, disabled=()):
    node = VD.make_verdict_node(caller, memory_enabled, max_retries=llm_config.MAX_RETRIES, fatal=(gemini_client.PermanentModelError,), unavailable=(base.ModelUnavailable,))
    memory_node = make_memory_node(memory_store, k) if (memory_enabled and memory_store is not None) else None
    return B.build_graph(registry, verdict_node=node, memory_node=memory_node, disabled=disabled)


# ------------------------------------------------------------------------------------------------ one alert
def process_alert(alert_id, alert, graph, caller, client, number, session, spec, policy, memory_enabled):
    """-> (results record, states record or None). The model is the only network call; a graph failure is recorded, never turned into a verdict."""
    caller.start(alert_id)
    if hasattr(client, "begin"):
        client.begin(number)
    started = base.CLOCK()
    final = routed = None
    failure = None
    try:
        final = B.run_alert(graph, alert, memory_enabled=memory_enabled)
    except gemini_client.PermanentModelError:
        raise
    except Exception as error:
        failure = "the graph raised " + type(error).__name__
    record = w3.make_record(alert_id, final, caller, session, base.CLOCK() - started, spec)
    if failure:
        record["error_detail"] = failure
    record["memory_mode"] = "on" if memory_enabled else "off"
    record["memory"] = memory_summary(final.get("memory")) if final else None
    record["risk_routing"] = None
    record["proposed_actions"] = []
    record["routing_error"] = None
    if final is not None:
        try:
            routed = B.route_final(policy, final)
            record["risk_routing"] = routed["routing"]
            record["proposed_actions"] = routed["actions"]
        except Exception as error:   # the policy was validated at start; anything here is recorded, and the case is left without a routing decision (never auto-closed)
            record["routing_error"] = type(error).__name__
    state_record = {"alert_id": alert_id, "session": session, "state": final, "routed": routed} if final is not None else None
    return record, state_record


def run_alerts(todo, alerts_by_id, order, graph, caller, client, session, spec, policy, memory_enabled, run_dir, say=print):
    consecutive = 0
    states_path = os.path.join(run_dir.path, STATES_FILE)
    for i, alert_id in enumerate(todo):
        started = base.CLOCK()
        record, state_record = process_alert(alert_id, alerts_by_id[alert_id], graph, caller, client, order[alert_id], session, spec, policy, memory_enabled)
        store.append_jsonl(run_dir.results, record)
        if state_record is not None:
            store.append_jsonl(states_path, state_record)
        if not os.path.exists(run_dir.prompt_snapshot):
            try:
                write_snapshot(run_dir, spec, alert_id, alerts_by_id[alert_id], graph, memory_enabled)
            except Exception as error:
                say("prompt snapshot not written yet (" + type(error).__name__ + ")")
        routing = (record["risk_routing"] or {}).get("decision")
        say("[" + str(i + 1).rjust(len(str(len(todo)))) + "/" + str(len(todo)) + "] " + alert_id + " " + record["status"] + (" (" + record["error_code"] + ")" if record["error_code"] else "")
            + " graph=" + str(record["graph_status"]) + " memory=" + str((record["memory"] or {}).get("status")) + " route=" + str(routing)
            + " calls=" + str(record["model_calls"]) + " %.1fs" % (base.CLOCK() - started))
        if record["status"] == MODEL_ERROR_STATUS and record["error_code"] in VN.MODEL_ERROR_CODES:
            consecutive += 1
        else:
            consecutive = 0
        if consecutive >= base.MAX_CONSECUTIVE_MODEL_ERRORS:
            return "stopped_after_model_errors"
    return "finished"


def write_snapshot(run_dir, spec, alert_id, alert, graph, memory_enabled):
    """prompt_snapshot.txt for the first alert. The graph is run with the verdict step unconfigured, so no model call is made."""
    state = B.run_alert(graph, alert, memory_enabled=memory_enabled)
    builder = P2.build_user_prompt if memory_enabled else VP.build_user_prompt
    with open(run_dir.prompt_snapshot, "w", encoding="utf-8") as f:
        f.write(VP.snapshot_text(spec, alert_id, builder(state, spec)))


# ------------------------------------------------------------------------------------------------ summary
def v2_summary(run_dir, ids):
    latest = store.latest_results(store.read_jsonl(run_dir.results))
    out = w3.agent_summary(run_dir, ids)
    routing, memory_status, levels, proposals, overrides = {}, {}, {}, 0, 0
    for alert_id in ids:
        r = latest.get(alert_id)
        if r is None:
            continue
        rr = r.get("risk_routing")
        key = rr["decision"] if isinstance(rr, dict) else "no_routing"
        routing[key] = routing.get(key, 0) + 1
        if isinstance(rr, dict):
            levels[rr["risk_level"]] = levels.get(rr["risk_level"], 0) + 1
            overrides += 1 if rr.get("memory_raised_risk") else 0
        m = (r.get("memory") or {}).get("status") if r.get("memory") else "none"
        memory_status[str(m)] = memory_status.get(str(m), 0) + 1
        proposals += len(r.get("proposed_actions") or [])
    out.update(routing_counts=dict(sorted(routing.items())), risk_level_counts=dict(sorted(levels.items())), memory_status_counts=dict(sorted(memory_status.items())),
               proposed_actions=proposals, memory_raised_risk=overrides)
    return out


def print_summary(summary, meta, ids, agent):
    print("")
    print("Run " + meta["run_name"] + " (" + meta["status"] + ")  memory " + meta["agent"]["memory"]["mode"] + ("  [FAKE MODEL: plumbing test only, not evaluable]" if meta["fake_model"] else ""))
    print("alerts in run: " + str(len(ids)) + ", ok: " + str(summary["counts"][base.STATUS_OK]) + ", parse_failed: " + str(summary["counts"][base.STATUS_PARSE_FAILED])
          + ", model_error: " + str(summary["counts"][base.STATUS_MODEL_ERROR]) + ", not run yet: " + str(summary["not_run"]))
    print("graph statuses: " + str(agent["graph_status_counts"]) + ", error codes: " + str(agent["error_code_counts"]))
    print("routing: " + str(agent["routing_counts"]) + ", memory steps: " + str(agent["memory_status_counts"]) + ", proposed actions (never executed): " + str(agent["proposed_actions"]))
    print("model calls: " + str(summary["model_calls"]) + ", total tokens: " + str(summary["total_tokens"]))
    print("frozen access log unchanged: " + str(meta["frozen_access_log_unchanged"]) + ", Week 1 files unchanged: " + str(meta["week1_files_unchanged"]))
    print("results: " + os.path.join(meta["run_dir"], "results.jsonl"))
    if meta["status"] != "complete":
        print("Not complete. Continue with: python src/week4/run_memory_dev.py --memory " + meta["agent"]["memory"]["mode"] + " --resume --run-name " + meta["run_name"]
              + (" --fake-model" if meta["fake_model"] else "") + " (add --retry-model-errors to run the model_error alerts again)")


# ------------------------------------------------------------------------------------------------ main
def parse_args(argv):
    p = argparse.ArgumentParser(description="Week 4: graph v2 on the DEV alerts, incident memory off or on.")
    p.add_argument("--memory", choices=["off", "on"], required=True, help="the ablation switch: off = Week 3 behaviour, on = memory step + agent_v2_memory prompt")
    p.add_argument("--run-name", default=None, help="name of the run folder (required with --resume)")
    p.add_argument("--limit", type=int, default=None, help="only the first N dev alerts (smoke test)")
    p.add_argument("--resume", action="store_true", help="continue an unfinished run; needs --run-name")
    p.add_argument("--retry-model-errors", action="store_true", help="with --resume: run again the alerts that ended in model_error")
    p.add_argument("--rpm", type=float, default=base.DEFAULT_RPM, help="model calls per minute, retries included (the baseline default)")
    p.add_argument("--dry-run", action="store_true", help="run the tools (and memory) for the first alert, print the verdict prompt, call no model, write nothing")
    p.add_argument("--fake-model", action="store_true", help="offline plumbing test: canned replies instead of Gemini; the run is flagged fake and cannot be compared")
    p.add_argument("--runs-dir", default=None, help="default runs/week4_memory (runs/week4_memory_FAKE with --fake-model)")
    p.add_argument("--baseline-run", default=w3.DEFAULT_BASELINE_RUN, help="the locked baseline_v3 run this run is held equal to")
    p.add_argument("--baseline-runs-dir", default=w3.BASELINE_RUNS_ROOT)
    p.add_argument("--memory-dir", default=DEFAULT_MEMORY_DIR, help="the seeded memory store (python -m week4.seed_memory seed)")
    p.add_argument("--memory-backend", choices=["numpy", "chroma"], default="numpy")
    p.add_argument("--memory-k", type=int, default=DEFAULT_K, help="neighbours retrieved per alert (default %d, a size fixed in advance, not tuned)" % DEFAULT_K)
    p.add_argument("--policy", default=None, help="risk policy file (default config/risk_policy.json or $WEEK4_RISK_POLICY)")
    args = p.parse_args(argv)
    if args.resume and args.run_name is None:
        p.error("--resume needs --run-name")
    if args.resume and args.limit is not None:
        p.error("--limit cannot be used with --resume; the run keeps its original alert list")
    if args.retry_model_errors and not args.resume:
        p.error("--retry-model-errors needs --resume")
    if args.limit is not None and args.limit < 1:
        p.error("--limit must be 1 or more")
    if args.rpm <= 0:
        p.error("--rpm must be above 0")
    if not 1 <= args.memory_k <= 50:
        p.error("--memory-k must be from 1 to 50")
    if args.fake_model and args.run_name is not None and not args.run_name.startswith("FAKE"):
        p.error("with --fake-model the run name must start with FAKE, so a fake run is never mistaken for a real one")
    if not args.fake_model and args.run_name is not None and args.run_name.startswith("FAKE"):
        p.error("run names starting with FAKE are reserved for --fake-model runs")
    if args.runs_dir is None:
        args.runs_dir = FAKE_RUNS_ROOT if args.fake_model else RUNS_ROOT
    return args


def load_memory(args, memory_enabled):
    """(store or None, isolation evidence or None). Memory on needs a verified store and a clean train/dev check; anything else stops the run (fail closed)."""
    if not memory_enabled:
        return None, None
    try:
        loaded = MS.MemoryStore.load(args.memory_dir, backend=args.memory_backend, build_index=(args.memory_backend == "chroma"))
        from week4 import seed_memory
        evidence = isolation.check_run_isolation(loaded, seed_memory.dev_key_texts())
    except (MemoryStoreError, MemoryDataError, MemoryIsolationError) as error:
        raise SystemExit("STOPPED: incident memory is not usable, so a memory-on run cannot start: " + type(error).__name__ + ": " + str(error)
                         + "\nNothing was substituted. Seed it with: python -m week4.seed_memory seed")
    return loaded, evidence


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    memory_enabled = args.memory == "on"
    if os.environ.get(config.FROZEN_UNLOCK_ENV):
        raise SystemExit("STOPPED: " + config.FROZEN_UNLOCK_ENV + " is set in this shell. This runner uses the dev set only.")
    try:
        policy = policy_module.load_policy(args.policy)
    except policy_module.PolicyError as error:
        raise SystemExit("STOPPED: no usable risk policy, so no routing decision can be made (fail closed): " + str(error))
    sizes = base.check_llm_config()
    model = sizes["small"]
    alerts, flows, input_hashes = base.load_inputs()
    ids_all = list(alerts["alert_id"])
    if len(set(ids_all)) != len(ids_all) or not all([a.startswith("DEV-") for a in ids_all]):
        raise SystemExit("STOPPED: the alert ids are not unique DEV- ids. This is not the dev set.")
    memory_store, isolation_evidence = load_memory(args, memory_enabled)

    meta = run_dir = None
    if args.resume:
        run_dir = store.RunDir(os.path.join(args.runs_dir, args.run_name))
        if not os.path.exists(run_dir.meta):
            raise SystemExit("STOPPED: no run named " + args.run_name + " in " + args.runs_dir)
        meta = store.read_json(run_dir.meta)
        if meta.get("runner") != RUNNER:
            raise SystemExit("STOPPED: " + args.run_name + " was not made by " + RUNNER + ".")
        if meta.get("fake_model") != args.fake_model:
            raise SystemExit("STOPPED: fake_model is " + str(meta.get("fake_model")) + " for that run; pass --fake-model to match it.")
        if meta["agent"]["memory"]["mode"] != args.memory:
            raise SystemExit("STOPPED: that run was made with memory " + meta["agent"]["memory"]["mode"] + " but this command says --memory " + args.memory + ".")
        selected_ids = list(meta["selected_alert_ids"])
    else:
        selected_ids = ids_all[:args.limit] if args.limit is not None else ids_all
    order = {alert_id: i for i, alert_id in enumerate(selected_ids)}

    spec = spec_for(memory_enabled)
    settings = base.settings_for(model, args.rpm)
    baseline_meta = None
    if args.fake_model:
        if os.path.exists(os.path.join(args.baseline_runs_dir, args.baseline_run, "run_meta.json")):
            baseline_meta = w3.check_baseline(args.baseline_runs_dir, args.baseline_run)
    else:
        baseline_meta = w3.check_baseline(args.baseline_runs_dir, args.baseline_run)
        w3.check_equal_setup(baseline_meta, model, settings)

    flow_store = FlowStore.from_dev()
    registry = build_registry(flow_store=flow_store)   # no reputation lookup
    selected_set = set(selected_ids)
    alerts_by_id = {row["alert_id"]: S1.alert_record(row, flow_store.frame) for _, row in alerts.iterrows() if row["alert_id"] in selected_set}
    print(str(len(alerts_by_id)) + " dev alerts selected; memory " + args.memory + "; verdict prompt " + spec.version + " sha256 " + spec.sha256[:12] + "; model " + model
          + (" (FAKE: canned replies)" if args.fake_model else "") + "; risk policy " + policy.version + " " + policy.sha256[:12])

    if args.dry_run:
        first_id = selected_ids[0]
        dry_graph = B.build_graph(registry, memory_node=make_memory_node(memory_store, args.memory_k) if memory_store is not None else None)
        state = B.run_alert(dry_graph, alerts_by_id[first_id], memory_enabled=memory_enabled)
        print("\nDry run: the tools" + (" and the memory lookup" if memory_enabled else "") + " ran, no model was called, nothing was written. Model that would be used: " + model)
        print("--- system prompt ---")
        print(spec.system_prompt)
        print("--- user prompt for " + first_id + " ---")
        print((P2.build_user_prompt if memory_enabled else VP.build_user_prompt)(state, spec))
        return 0

    memory_meta = {"mode": args.memory, "k": args.memory_k, "backend": args.memory_backend if memory_enabled else None,
                   "manifest_sha256": memory_store.manifest_sha256 if memory_store else None, "isolation_check": isolation_evidence,
                   "store": memory_store.info() if memory_store else None}
    if meta is None:
        run_name = args.run_name
        if run_name is None:
            stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            run_name = ("FAKE_" if args.fake_model else "dev_v2_") + "mem_" + args.memory + "_" + stamp
        run_dir = store.RunDir(os.path.join(args.runs_dir, run_name))
        if os.path.exists(run_dir.path):
            raise SystemExit("STOPPED: " + run_dir.path + " already exists. Use another --run-name, or --resume.")
        meta = {"run_name": run_name, "run_dir": run_dir.path, "set": "dev", "runner": RUNNER, "fake_model": args.fake_model, "week4_version": week4.VERSION,
                "prompt_version": spec.version, "prompt_sha256": spec.sha256, "provider": "gemini", "model": model, "model_size": "small", "settings": settings,
                "inputs": input_hashes, "n_selected": len(selected_ids), "limit": args.limit, "selected_alert_ids": selected_ids,
                "agent": {"graph_version": S2.GRAPH_VERSION, "verdict_enabled": True, "specialists": list(w3.ablation.effective_specialists(())),
                          "reputation_lookup": "not_consulted", "max_supervisor_visits": S2.MAX_SUPERVISOR_VISITS, "memory": memory_meta,
                          "policy": {"version": policy.version, "sha256": policy.sha256},
                          "baseline": w3.baseline_summary(baseline_meta, args.baseline_run) if baseline_meta is not None else None},
                "git": base.git_info(), "python": platform.python_version(), "packages": base.package_versions(), "sessions": [], "status": "running"}
    else:
        agent = meta["agent"]
        if meta["model"] != model or meta["prompt_sha256"] != spec.sha256 or meta["inputs"] != input_hashes:
            raise SystemExit("STOPPED: the model, prompt or input files differ from the run being resumed. Start a new run instead.")
        for key in SETTING_KEYS:
            if meta["settings"][key] != settings[key]:
                raise SystemExit("STOPPED: setting " + key + " differs from the run being resumed. Start a new run instead.")
        if agent.get("graph_version") != S2.GRAPH_VERSION:
            raise SystemExit("STOPPED: the graph version differs from the run being resumed. Start a new run instead.")
        if agent["policy"]["sha256"] != policy.sha256:
            raise SystemExit("STOPPED: the risk policy differs from the run being resumed. Start a new run instead.")
        if (agent["memory"].get("manifest_sha256"), agent["memory"].get("k")) != (memory_meta["manifest_sha256"], memory_meta["k"]):
            raise SystemExit("STOPPED: the memory store or k differs from the run being resumed. Start a new run instead.")
        meta["settings"]["requests_per_minute"] = args.rpm

    original_sleep = base.SLEEP
    if args.fake_model:
        client = w3.FakeClient()
        base.SLEEP = lambda seconds: None   # fake mode only, restored below
        rpm = w3.FAKE_RPM
    else:
        client = base.make_client_for(model, llm_config.get_api_key(), settings["timeout_seconds"], spec)
        rpm = args.rpm
    meta["settings"]["requests_per_minute"] = rpm

    os.makedirs(run_dir.path, exist_ok=True)
    latest = store.latest_results(store.read_jsonl(run_dir.results, repair=True))
    todo = [a for a in selected_ids if a not in latest or (args.retry_model_errors and latest[a]["status"] == MODEL_ERROR_STATUS)]
    session = len(meta["sessions"]) + 1
    session_info = {"session": session, "started_utc": base.utc_now(), "args": {"limit": args.limit, "rpm": rpm, "resume": args.resume, "retry_model_errors": args.retry_model_errors}}
    meta["sessions"].append(session_info)
    store.write_json_atomic(run_dir.meta, meta)

    log_before = base.count_lines(config.FROZEN_ACCESS_LOG)
    snapshot_before = base.week1_snapshot()
    print("Run " + meta["run_name"] + ": " + str(len(todo)) + " alerts to do, " + str(len(selected_ids) - len(todo)) + " already done. Model " + model + ", " + str(rpm) + " calls per minute.")

    caller = base.RecordingCaller(client, base.Throttle(rpm), run_dir, session, model)
    graph = make_v2_graph(registry, caller, memory_enabled, memory_store, args.memory_k)
    ended, exit_code = "finished", 0
    try:
        ended = run_alerts(todo, alerts_by_id, order, graph, caller, client, session, spec, policy, memory_enabled, run_dir)
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
    agent = v2_summary(run_dir, selected_ids)
    meta["agent"]["summary"] = agent
    store.write_json_atomic(run_dir.meta, meta)
    print_summary(summary, meta, selected_ids, agent)
    if not meta["frozen_access_log_unchanged"] or not meta["week1_files_unchanged"]:
        print("WARNING: a Week 1 file or the frozen access log changed during the run. Check git status and eval/frozen_access.log before continuing.")
        exit_code = 3
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
