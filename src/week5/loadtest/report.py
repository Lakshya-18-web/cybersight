"""Markdown report from a results dict (or a results JSON file). It validates the structure first and prints only what is in the file."""
import json

from . import metrics


def _num(x, nd=3):
    return "n/a" if x is None else ("%.*f" % (nd, x) if isinstance(x, float) else str(x))


def table(rows, header):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def render(results):
    problems = metrics.validate_results(results)
    if problems:
        raise ValueError("results file is not valid: " + "; ".join(problems))
    m, p, c, t, u = results["meta"], results["parameters"], results["counts"], results["throughput"], results["usage"]
    lines = ["# Load test report", "",
             "Run: %s to %s, mode `%s`, model `%s` (%s)." % (m["started_at"], m["finished_at"], m["mode"], m["model"], {True: "FAKE", False: "REAL"}.get(m["fake_model"], "unknown")),
             "Machine: Python %s, %s CPU(s). Week 5 version %s." % (m["python"], m["cpu_count"], m["week5_version"]), "",
             "## Parameters", "", table([(k, json.dumps(v)) for k, v in sorted(p.items())], ("parameter", "value")), "",
             "## Backend", "", table([(k, json.dumps(v)) for k, v in sorted((m.get("backend") or {}).items())], ("setting", "value")), "",
             "## Outcome", "", table([("submissions", c["submissions"]), ("jobs created", c["jobs_created"]), ("duplicates recognised", c["duplicates_recognised"]), ("succeeded", c["succeeded"]),
                                    ("failed", c["failed"]), ("timed out", c["timed_out"]), ("unfinished at drain timeout", c["unfinished_at_drain_timeout"]), ("retried jobs", c["retried_jobs"]),
                                    ("requests not accepted", c["rejected_or_failed_requests"]), ("HTTP statuses", json.dumps(c["http_status"]))], ("measure", "value")), "",
             "## Throughput", "", table([("accepted per second", _num(t["accepted_per_s"])), ("completed per second", _num(t["completed_per_s"])), ("makespan (s)", _num(t["makespan_s"])),
                                       ("submit window (s)", _num(t["submit_window_s"])), ("max jobs in flight observed", _num(t["max_in_flight_observed"]))], ("measure", "value")), "",
             "## Latency", ""]
    rows = []
    for name in ("api_submit_ms", "queue_wait_s", "processing_s", "end_to_end_s", "client_lag_s"):
        s = results["latency"][name]
        rows.append((name, s["unit"], s["n"], _num(s["min"], 4), _num(s["mean"], 4), _num(s["p50"], 4), _num(s["p90"], 4), _num(s["p95"], 4), _num(s["p99"], 4), _num(s["max"], 4), " ".join(s["low_sample"]) or "-"))
    lines += [table(rows, ("metric", "unit", "n", "min", "mean", "p50", "p90", "p95", "p99", "max", "low-sample percentiles")), ""]
    if results["per_node"]:
        lines += ["## Time per graph node (seconds per job)", "", table([(n, _num(v["seconds_per_job"]["mean"], 6), _num(v["seconds_per_job"]["p95"], 6), _num(v["calls_per_job"]["mean"], 2))
                                                                          for n, v in results["per_node"].items()], ("node", "mean", "p95", "calls per job")), ""]
    lines += ["## Verdict and routing outcomes (succeeded jobs)", "", "Verdict status: `%s`. Routing decision: `%s`. With a fake model these are plumbing results, not detection quality." % (
        json.dumps(results.get("outcomes", {}).get("verdict_status", {})), json.dumps(results.get("outcomes", {}).get("routing_decision", {}))), "",
              "## Errors", "", "By error code: `%s`. Non-success HTTP: `%s`." % (json.dumps(results["errors"]["by_error_code"]), json.dumps(results["errors"]["http_non_success"])), "",
              "## Model usage and cost", "", "Model calls: %s. Tokens: %s (%s). Cost: %s (%s)." % (u["model_calls"], "available" if u["tokens_available"] else "unavailable", u["tokens_note"] or "-",
                                                                                                    "unavailable" if u["cost_usd"] is None else u["cost_usd"], u["cost_note"]), "",
              "## How to read this", ""] + ["- " + n for n in results["honesty"]]
    return "\n".join(lines) + "\n"
