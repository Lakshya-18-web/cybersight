"""Week 3 Day 6: read-only audits that need NO model call, NO API key and NO label file.

  python src/week3_day6_audit.py replay    [--arm A] [--limit N] [--repeats 2] [--compare-run RUN_DIR] [--out-dir DIR]
  python src/week3_day6_audit.py artifacts --run-dir RUN_DIR [--out-dir DIR]

replay     Runs every DEV alert through the tool graph (traffic, beaconing, enrichment as the arm allows), with the verdict step replaced by a CAPTURE node that only
           builds the verdict prompt and stores it. No model is called. It checks, per alert and in total:
             * every tool call was valid (no tool errors), arguments are plain JSON types, and the specialists' statuses;
             * determinism: the evidence and the verdict prompt are byte-identical across --repeats replays;
             * tool time per alert (the real run's wall time is dominated by the request-rate limit, not by the tools);
             * with --compare-run: the verdict prompt hash, trace, routing, tool-call count and upstream statuses of every alert against what a real run recorded in its
               results.jsonl. Identical prompts mean the committed code sends what that run sent. A difference is listed, never hidden.
artifacts  Reads one finished run folder (results.jsonl, raw_responses.jsonl, run_meta.json) and checks that the records agree with each other: calls, attempts, tokens,
           prompt hashes, statuses, counts. It also tallies transport errors (timeouts, rate limits, server errors) from raw_responses.jsonl, and estimates how many requests were
           really made (replies plus failed transport attempts).

Safety: the audits read the dev alert file and dev flow store (through the runner's own checked loader) and run folders. They never read labels, the answer key or the frozen set,
never open a run folder for writing, and write nothing unless --out-dir names a NEW folder (an existing one is refused).
Exit code 0 when every check passed, 1 when any check failed, 2 for a usage problem.
"""
import os
import sys
import json
import argparse
import hashlib
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
import baseline_store as store
import gemini_client
import run_baseline_dev as base
from agents import state as S
import ablation_config as ablation
from agents import verdict_node as VN
from agents import verdict_prompt
from agents.graph import build_graph, run_alert
from tools import FlowStore, build_registry

IDENTITY_FIELDS = ("prompt_sha256", "trace", "routing", "tool_calls", "upstream", "graph_errors")
TIMEOUT_NAMES = [name for name in gemini_client.TRANSIENT_NAMES if "Timeout" in name]
TIMEOUT_STATUSES = (408, 504)
RESULT_STATUSES = (base.STATUS_OK, base.STATUS_PARSE_FAILED, base.STATUS_MODEL_ERROR)


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, default=repr, separators=(",", ":"))


def percentile(values, q):
    if not values:
        return None
    ordered = sorted(values)
    k = (len(ordered) - 1) * q
    low = int(k)
    high = min(low + 1, len(ordered) - 1)
    return round(ordered[low] + (ordered[high] - ordered[low]) * (k - low), 6)


class Checks:
    """A list of named checks, each True or False with a detail line."""

    def __init__(self):
        self.items = []

    def add(self, name, ok, detail=""):
        self.items.append({"check": name, "ok": bool(ok), "detail": detail})
        return ok

    @property
    def all_ok(self):
        return all(c["ok"] for c in self.items)

    def failed(self):
        return [c for c in self.items if not c["ok"]]


# ------------------------------------------------------------------------------------------------ replay
def non_native_types(value, path="arguments", out=None):
    """Paths of values in a tool-call argument structure that are not plain JSON types (for example a numpy integer or a pandas timestamp)."""
    out = [] if out is None else out
    if value is None or isinstance(value, (str, bool, int, float)) and type(value) in (str, bool, int, float):
        return out
    if isinstance(value, dict):
        for k, v in value.items():
            non_native_types(v, path + "." + str(k), out)
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            non_native_types(v, path + "[" + str(i) + "]", out)
    else:
        out.append(path + " is " + type(value).__module__ + "." + type(value).__name__)
    return out


def make_capture_node(spec, sink):
    """A stand-in for the verdict node. It builds the exact prompt the real node would build from the same state and stores it. It calls no model and makes no verdict."""
    def node(state):
        entry = {"prompt_error": None, "prompt_sha256": None}
        try:
            prompt = verdict_prompt.build_user_prompt(state, spec)
            entry["prompt_sha256"] = sha(prompt)
        except ValueError as error:
            entry["prompt_error"] = str(error)[:200]
        sink[state["alert_id"]] = entry
        record = {"status": "ok", "verdict": None, "capture_only": True, "upstream": VN.upstream_health(state)}
        return {"verdict": record, "trace": list(state["trace"]) + [S.NODE_VERDICT]}
    return node


def replay_once(alerts_by_id, order, graph, sink):
    rows = {}
    for alert_id in order:
        started = time.perf_counter()
        problem = None
        final = None
        try:
            final = run_alert(graph, alerts_by_id[alert_id], verdict_enabled=True)
        except Exception as error:   # reported, never hidden
            problem = type(error).__name__ + ": " + str(error)[:160]
        seconds = time.perf_counter() - started
        if final is None:
            rows[alert_id] = {"alert_id": alert_id, "error": problem, "seconds": seconds}
            continue
        evidence = final.get("evidence", [])
        failed_calls = [{"tool": e.get("tool"), "code": (e.get("error") or {}).get("code")} for e in evidence if not e.get("ok")]
        odd = []
        for e in evidence:
            odd += non_native_types(e.get("arguments"), "call " + str(e.get("index")) + " " + str(e.get("tool")))
        specialists = {"traffic": VN.upstream_health(final)["traffic"], "beacon": VN.upstream_health(final)["beacon"], "enrichment": VN.upstream_health(final)["enrichment"]}
        rows[alert_id] = {"alert_id": alert_id, "error": None, "seconds": seconds, "graph_status": final.get("status"), "trace": final.get("trace"), "routing": final.get("routing"),
                          "tool_calls": len(evidence), "failed_calls": failed_calls, "non_native_arguments": odd, "graph_errors": final.get("errors"),
                          "upstream": VN.upstream_health(final), "specialists": specialists, "evidence_sha256": sha(canonical(evidence)),
                          "prompt_sha256": sink.get(alert_id, {}).get("prompt_sha256"), "prompt_error": sink.get(alert_id, {}).get("prompt_error")}
    return rows


def compare_with_run(rows, run_dir):
    """Compare replay rows with the records a real run stored. Returns (summary dict, list of check tuples)."""
    latest = store.latest_results(store.read_jsonl(os.path.join(run_dir, "results.jsonl")))
    summary = {"run_dir": run_dir, "records": len(latest), "compared": 0, "skipped_no_record": 0, "skipped_graph_error": 0, "identical_all_fields": 0,
               "mismatch_by_field": {f: [] for f in IDENTITY_FIELDS}}
    for alert_id, row in rows.items():
        record = latest.get(alert_id)
        if record is None:
            summary["skipped_no_record"] += 1
            continue
        if record.get("error_code") == "graph_error":
            summary["skipped_graph_error"] += 1
            continue
        summary["compared"] += 1
        same = True
        for field in IDENTITY_FIELDS:
            ours, theirs = row.get(field), record.get(field)
            if field == "graph_errors":   # a real run adds the verdict step's own failure here; the capture replay makes no model call, so only the specialists' errors are compared
                ours, theirs = [e for e in (ours or []) if e.get("node") != S.NODE_VERDICT], [e for e in (theirs or []) if e.get("node") != S.NODE_VERDICT]
            if ours != theirs:
                summary["mismatch_by_field"][field].append(alert_id)
                same = False
        summary["identical_all_fields"] += 1 if same else 0
    summary["mismatch_counts"] = {f: len(v) for f, v in summary["mismatch_by_field"].items()}
    summary["mismatch_by_field"] = {f: v[:10] for f, v in summary["mismatch_by_field"].items()}
    return summary


def run_replay(args, say):
    checks = Checks()
    disabled = ablation.arm_disabled(args.arm)
    alerts, _flows, input_hashes = base.load_inputs()
    ids = list(alerts["alert_id"])
    if len(set(ids)) != len(ids) or not all(str(a).startswith("DEV-") for a in ids):
        raise SystemExit("STOPPED: the alert ids are not unique DEV- ids. This is not the dev set.")
    if args.limit is not None:
        ids = ids[:args.limit]
    store_ = FlowStore.from_dev()
    registry = build_registry(flow_store=store_)
    alerts_by_id = {}
    wanted = set(ids)
    for _, row in alerts.iterrows():
        if row["alert_id"] in wanted:
            alerts_by_id[row["alert_id"]] = S.alert_record(row, store_.frame)
    spec = verdict_prompt.get_prompt()
    say("replay: " + str(len(ids)) + " dev alerts, arm " + ablation.describe(disabled) + ", verdict prompt " + spec.version + " " + spec.sha256[:12] + ", " + str(args.repeats) + " replays, no model call")
    passes = []
    for _ in range(args.repeats):
        sink = {}
        graph = build_graph(registry, verdict_node=make_capture_node(spec, sink), disabled=disabled)
        passes.append(replay_once(alerts_by_id, ids, graph, sink))
    first = passes[0]

    crashed = [a for a, r in first.items() if r.get("error")]
    checks.add("every alert ran through the graph without raising", not crashed, "raised: " + ", ".join(crashed[:5]) if crashed else "")
    ran = {a: r for a, r in first.items() if not r.get("error")}
    tool_failures = {a: r["failed_calls"] for a, r in ran.items() if r["failed_calls"]}
    checks.add("no tool call failed", not tool_failures, str(len(tool_failures)) + " alert(s) with failed calls, first: " + str(list(tool_failures.items())[:3]) if tool_failures else "")
    odd = {a: r["non_native_arguments"] for a, r in ran.items() if r["non_native_arguments"]}
    checks.add("every tool-call argument is a plain JSON type", not odd, str(list(odd.items())[:3]) if odd else "")
    errors = {a: r["graph_errors"] for a, r in ran.items() if r["graph_errors"]}
    checks.add("no graph error was recorded", not errors, str(len(errors)) + " alert(s), first: " + str(list(errors.items())[:2]) if errors else "")
    bad_prompt = {a: r["prompt_error"] for a, r in ran.items() if r.get("prompt_error") or not r.get("prompt_sha256")}
    checks.add("a verdict prompt could be built for every alert", not bad_prompt, str(list(bad_prompt.items())[:3]) if bad_prompt else "")
    not_completed = {a: r["graph_status"] for a, r in ran.items() if r["graph_status"] != S.STATUS_COMPLETED}
    checks.add("every graph finished 'completed'", not not_completed, str(len(not_completed)) + " alert(s) did not, first: " + str(list(not_completed.items())[:3]) if not_completed else "")
    max_visits = max([sum(1 for n in (r["trace"] or []) if n == S.NODE_SUPERVISOR) for r in ran.values()] or [0])
    checks.add("no graph used more supervisor visits than the guard allows", max_visits <= S.MAX_SUPERVISOR_VISITS, "most visits: " + str(max_visits))

    if len(passes) > 1:
        differing = []
        for other in passes[1:]:
            for alert_id, row in first.items():
                o = other.get(alert_id, {})
                if row.get("evidence_sha256") != o.get("evidence_sha256") or row.get("prompt_sha256") != o.get("prompt_sha256") or row.get("trace") != o.get("trace"):
                    differing.append(alert_id)
        checks.add("evidence, trace and verdict prompt are identical across replays", not differing, "differ: " + ", ".join(sorted(set(differing))[:5]) if differing else "")

    secs = [r["seconds"] for r in ran.values()]
    status_counts = {}
    for name in ("traffic", "beacon", "enrichment"):
        counts = {}
        for r in ran.values():
            counts[r["specialists"][name]] = counts.get(r["specialists"][name], 0) + 1
        status_counts[name] = dict(sorted(counts.items()))
    paths = {}
    for r in ran.values():
        key = ">".join(n for n in (r["trace"] or []) if n != S.NODE_SUPERVISOR)
        paths[key] = paths.get(key, 0) + 1
    summary = {"mode": "replay", "arm": args.arm, "disabled": list(disabled), "alerts": len(ids), "repeats": args.repeats, "dev_inputs": input_hashes, "verdict_prompt_version": spec.version,
               "verdict_prompt_sha256": spec.sha256, "tool_calls_total": sum(r["tool_calls"] for r in ran.values()), "specialist_status_counts": status_counts,
               "path_counts": dict(sorted(paths.items())), "tool_seconds_per_alert": {"mean": round(sum(secs) / len(secs), 6) if secs else None, "p95": percentile(secs, 0.95), "max": round(max(secs), 6) if secs else None},
               "prompt_sha256_by_alert": {a: r.get("prompt_sha256") for a, r in first.items()}}
    if args.compare_run:
        compare = compare_with_run(first, args.compare_run)
        summary["compare"] = compare
        mism = {f: n for f, n in compare["mismatch_counts"].items() if n}
        checks.add("replayed alerts match the real run's recorded prompt hash, trace, routing, tool-call count and upstream statuses", compare["compared"] > 0 and not mism,
                   "compared " + str(compare["compared"]) + ", identical on every field: " + str(compare["identical_all_fields"]) + ("; mismatches by field: " + str(mism) if mism else ""))
    summary["checks"] = checks.items
    summary["all_checks_passed"] = checks.all_ok
    return summary, checks


# ------------------------------------------------------------------------------------------------ artifacts
def transport_summary(raw):
    """Tally the transport side of raw_responses.jsonl: outcomes, failed attempts, kinds (exception class name before the colon, HTTP status), timeouts, latency."""
    outcomes, kinds, statuses = {}, {}, {}
    failed_attempts = recovered_calls = timeouts = 0
    latencies = []
    for line in raw:
        outcome = line.get("outcome")
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
        errors = line.get("transport_errors") or []
        failed_attempts += len(errors)
        if outcome == "reply" and errors:
            recovered_calls += 1
        for error in errors:
            message = str(error.get("message") or "")
            kind = message.split(":", 1)[0].strip() if ":" in message else "unknown"
            kinds[kind] = kinds.get(kind, 0) + 1
            status = error.get("status")
            statuses[str(status)] = statuses.get(str(status), 0) + 1
            if kind in TIMEOUT_NAMES or status in TIMEOUT_STATUSES:
                timeouts += 1
        if isinstance(line.get("latency_seconds"), (int, float)):
            latencies.append(line["latency_seconds"])
    replies = outcomes.get("reply", 0)
    return {"lines": len(raw), "outcomes": dict(sorted(outcomes.items(), key=lambda kv: str(kv[0]))), "reply_calls": replies, "failed_transport_attempts": failed_attempts,
            "replies_that_needed_transport_retries": recovered_calls, "failed_attempts_by_exception_class": dict(sorted(kinds.items())),
            "failed_attempts_by_http_status": dict(sorted(statuses.items())), "timeout_like_failed_attempts": timeouts,
            "estimated_requests_made": replies + failed_attempts, "latency_seconds": {"max": max(latencies) if latencies else None, "p95": percentile(latencies, 0.95)}}


def run_artifacts(args, say):
    checks = Checks()
    run_dir = args.run_dir
    meta = store.read_json(os.path.join(run_dir, "run_meta.json"))
    rows = store.read_jsonl(os.path.join(run_dir, "results.jsonl"))
    raw = store.read_jsonl(os.path.join(run_dir, "raw_responses.jsonl"))
    latest = store.latest_results(rows)
    selected = list(meta.get("selected_alert_ids") or [])
    say("artifacts: " + str(meta.get("run_name")) + " (" + str(meta.get("status")) + "), " + str(len(selected)) + " selected alerts, " + str(len(rows)) + " result lines, " + str(len(raw)) + " raw lines")

    missing = [a for a in selected if a not in latest]
    checks.add("every selected alert has a result record", not missing, "missing: " + ", ".join(missing[:5]) if missing else "")
    bad_status = [a for a, r in latest.items() if r.get("status") not in RESULT_STATUSES]
    checks.add("every status is ok, parse_failed or model_error", not bad_status, ", ".join(bad_status[:5]) if bad_status else "")
    shape = []
    for a, r in latest.items():
        st = r.get("status")
        if st == base.STATUS_OK and not (isinstance(r.get("verdict"), dict) and r.get("error_code") is None):
            shape.append(a + " ok without a verdict, or with an error code")
        if st in (base.STATUS_PARSE_FAILED, base.STATUS_MODEL_ERROR) and (r.get("verdict") is not None or not r.get("error_code")):
            shape.append(a + " " + str(st) + " with a verdict or without an error code")
    checks.add("ok records hold a verdict; failures hold none and name an error code", not shape, "; ".join(shape[:4]) if shape else "")

    by_alert_session = {}
    for line in raw:
        if line.get("outcome") == "reply":
            by_alert_session.setdefault((line.get("alert_id"), line.get("session")), []).append(line)
    calls_bad, hash_bad, token_bad, attempts_bad = [], [], [], []
    for a, r in latest.items():
        calls = sorted(by_alert_session.get((a, r.get("session")), []), key=lambda l: l.get("call_index", 0))
        n = r.get("model_calls")
        if n != len(calls):
            calls_bad.append(a + " record " + str(n) + " vs raw " + str(len(calls)))
        if r.get("attempts") != n or len(r.get("attempt_log") or []) != n:
            attempts_bad.append(a)
        if calls and r.get("prompt_sha256") and sha(calls[0].get("prompt") or "") != r.get("prompt_sha256"):
            hash_bad.append(a)
        for key in ("prompt_tokens", "output_tokens", "total_tokens"):
            expected = sum(c.get(key) or 0 for c in calls) if any(c.get(key) is not None for c in calls) else None
            if r.get(key) != expected:
                token_bad.append(a + " " + key)
                break
    checks.add("model calls in each record equal the raw reply lines of the same session", not calls_bad, "; ".join(calls_bad[:4]) if calls_bad else "")
    checks.add("attempts, model_calls and attempt_log length agree in every record", not attempts_bad, ", ".join(attempts_bad[:5]) if attempts_bad else "")
    checks.add("the first raw prompt hashes to the record's prompt_sha256", not hash_bad, ", ".join(hash_bad[:5]) if hash_bad else "")
    checks.add("token counts in each record equal the sum over its raw reply lines", not token_bad, "; ".join(token_bad[:4]) if token_bad else "")

    counts = {s: sum(1 for r in latest.values() if r.get("status") == s) for s in RESULT_STATUSES}
    if isinstance(meta.get("counts"), dict):
        checks.add("run_meta counts equal the recomputed status counts", all(meta["counts"].get(s) == counts[s] for s in RESULT_STATUSES), "meta " + str(meta["counts"]) + " vs " + str(counts))
    if meta.get("total_tokens") is not None:
        recomputed = sum(r.get("total_tokens") or 0 for r in latest.values())
        checks.add("run_meta total_tokens equals the sum over records", meta["total_tokens"] == recomputed, str(meta["total_tokens"]) + " vs " + str(recomputed))
    if meta.get("model_calls") is not None:
        recomputed = sum(r.get("model_calls") or 0 for r in latest.values())
        checks.add("run_meta model_calls equals the sum over records", meta["model_calls"] == recomputed, str(meta["model_calls"]) + " vs " + str(recomputed))
    agent_summary = (meta.get("agent") or {}).get("summary")
    if isinstance(agent_summary, dict):
        tool_total = sum(r.get("tool_calls") or 0 for r in latest.values())
        checks.add("run_meta agent tool_calls equals the sum over records", agent_summary.get("tool_calls") == tool_total, str(agent_summary.get("tool_calls")) + " vs " + str(tool_total))

    upstream, graph_status, error_codes, first_try = {}, {}, {}, 0
    for r in latest.values():
        up = r.get("upstream")
        if isinstance(up, dict):
            key = "traffic=" + str(up.get("traffic")) + " beacon=" + str(up.get("beacon")) + " enrichment=" + str(up.get("enrichment"))
            upstream[key] = upstream.get(key, 0) + 1
        graph_status[str(r.get("graph_status"))] = graph_status.get(str(r.get("graph_status")), 0) + 1
        if r.get("error_code"):
            error_codes[r["error_code"]] = error_codes.get(r["error_code"], 0) + 1
        first_try += 1 if r.get("malformed_first_try") else 0
    unhealthy_ok = [a for a, r in latest.items() if r.get("status") == base.STATUS_OK and isinstance(r.get("upstream"), dict)
                    and any(r["upstream"].get(k) not in ("ok", "not_run", "disabled") for k in ("traffic", "beacon", "enrichment"))]
    transport = transport_summary(raw)
    summary = {"mode": "artifacts", "run_dir": run_dir, "run_name": meta.get("run_name"), "run_status": meta.get("status"), "alerts_selected": len(selected), "alerts_with_record": len(latest),
               "status_counts": counts, "error_code_counts": dict(sorted(error_codes.items())), "graph_status_counts": dict(sorted(graph_status.items())),
               "upstream_status_combinations": dict(sorted(upstream.items())), "valid_verdicts_with_a_failed_or_partial_specialist": unhealthy_ok,
               "malformed_first_try": first_try, "model_calls_in_records": sum(r.get("model_calls") or 0 for r in latest.values()),
               "model_error_alerts": sorted(a for a, r in latest.items() if r.get("status") == base.STATUS_MODEL_ERROR),
               "transport": transport, "checks": checks.items, "all_checks_passed": checks.all_ok}
    return summary, checks


# ------------------------------------------------------------------------------------------------ output
def render(summary):
    lines = ["", "=" * 78, "Week 3 Day 6 audit: " + summary["mode"], "=" * 78]
    for c in summary["checks"]:
        lines.append(("PASS  " if c["ok"] else "FAIL  ") + c["check"] + (("  [" + c["detail"] + "]") if c["detail"] else ""))
    lines.append("")
    skip = {"checks", "prompt_sha256_by_alert", "all_checks_passed"}
    for key, value in summary.items():
        if key not in skip:
            lines.append(key + ": " + json.dumps(value, sort_keys=True, default=str))
    lines.append("")
    lines.append("ALL CHECKS PASSED" if summary["all_checks_passed"] else "SOME CHECKS FAILED")
    lines.append("Read-only: no model was called, no label or frozen file was read, no run folder was changed.")
    return "\n".join(lines)


def write_out(out_dir, summary, text):
    if os.path.exists(out_dir):
        raise SystemExit("STOPPED: " + out_dir + " already exists. Choose a new --out-dir; an existing report folder is never overwritten.")
    os.makedirs(out_dir)
    stem = "audit_" + summary["mode"] + ("_" + summary["arm"] if summary.get("arm") else "")
    with open(os.path.join(out_dir, stem + ".json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True, default=str)
    with open(os.path.join(out_dir, stem + ".txt"), "w", encoding="utf-8") as f:
        f.write(text + "\n")


def parse_args(argv):
    p = argparse.ArgumentParser(description="Week 3 Day 6: read-only audits (no model call, no labels).")
    sub = p.add_subparsers(dest="mode", required=True)
    r = sub.add_parser("replay", help="replay the tool graph over the dev alerts and check tool calls, determinism and prompt identity")
    r.add_argument("--arm", choices=sorted(ablation.ARMS), default="A")
    r.add_argument("--limit", type=int, default=None)
    r.add_argument("--repeats", type=int, default=2)
    r.add_argument("--compare-run", default=None, help="a finished agent run folder to compare prompt hashes, traces and routing with")
    r.add_argument("--out-dir", default=None)
    a = sub.add_parser("artifacts", help="check one finished run folder for internal consistency and tally transport errors")
    a.add_argument("--run-dir", required=True)
    a.add_argument("--out-dir", default=None)
    args = p.parse_args(argv)
    if args.mode == "replay":
        if args.repeats < 1:
            p.error("--repeats must be 1 or more")
        if args.limit is not None and args.limit < 1:
            p.error("--limit must be 1 or more")
        if args.compare_run and not os.path.exists(os.path.join(args.compare_run, "results.jsonl")):
            p.error("--compare-run has no results.jsonl: " + args.compare_run)
    elif not os.path.exists(os.path.join(args.run_dir, "run_meta.json")):
        p.error("--run-dir has no run_meta.json: " + args.run_dir)
    if args.out_dir and os.path.exists(args.out_dir):
        p.error(args.out_dir + " already exists; the audit never overwrites a report folder")
    return args


def main(argv=None, say=print):
    args = parse_args(argv)
    if os.environ.get(config.FROZEN_UNLOCK_ENV):
        raise SystemExit("STOPPED: " + config.FROZEN_UNLOCK_ENV + " is set in this shell. These audits use the dev set only.")
    summary, checks = run_replay(args, say) if args.mode == "replay" else run_artifacts(args, say)
    text = render(summary)
    say(text)
    if args.out_dir:
        write_out(args.out_dir, summary, text)
        say("written to " + args.out_dir)
    return 0 if checks.all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
