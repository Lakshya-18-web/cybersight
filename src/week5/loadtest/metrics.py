"""Statistics and result files for the load tester. Pure functions, no I/O except write_json / write_csv.

Percentiles use the NEAREST-RANK method: the p-th percentile of n sorted values is the value at rank ceil(p/100 * n). It always returns a value that was actually observed, and with fewer than 100
values the p99 is simply the maximum; summarize() says so (`n`) and flags percentiles that rest on too few samples (`low_sample`) so a table never looks more precise than it is.
Tokens and cost are never computed here: a provider that reports no token counts yields None, and cost stays None unless a priced, sourced token count exists (it does not for a fake model).
"""
import csv
import datetime
import json
import math

PERCENTILES = (50, 90, 95, 99)
RESULT_SCHEMA = "week5-loadtest-results-v1"
LOW_SAMPLE_BELOW = {90: 10, 95: 20, 99: 100}      # a percentile reported with fewer samples than this is flagged


def percentile(values, p):
    """Nearest-rank percentile (0 < p <= 100) of a non-empty list. None for an empty list."""
    if not values:
        return None
    if not 0 < p <= 100:
        raise ValueError("p must be in (0, 100]")
    ordered = sorted(values)
    rank = max(1, math.ceil(p / 100.0 * len(ordered)))
    return ordered[rank - 1]


def summarize(values, unit):
    """{n, unit, min, mean, p50, p90, p95, p99, max, low_sample: [..]} (every number rounded to 6 places). n == 0 gives null statistics."""
    vals = [float(v) for v in values if v is not None]
    n = len(vals)
    out = {"n": n, "unit": unit, "min": None, "mean": None, "p50": None, "p90": None, "p95": None, "p99": None, "max": None, "low_sample": []}
    if n == 0:
        return out
    out["min"], out["max"], out["mean"] = round(min(vals), 6), round(max(vals), 6), round(sum(vals) / n, 6)
    for p in PERCENTILES:
        out["p%d" % p] = round(percentile(vals, p), 6)
        if n < LOW_SAMPLE_BELOW.get(p, 0):
            out["low_sample"].append("p%d" % p)
    return out


def rate(count, seconds):
    return round(count / seconds, 4) if seconds and seconds > 0 else None


def seconds_between(later, earlier):
    """Seconds between two aware datetimes (or None when either is missing)."""
    if later is None or earlier is None:
        return None
    return (later - earlier).total_seconds()


def node_summary(jobs):
    """Per graph node: seconds per job and calls per job, over the jobs that carry timings (the instrumented engine). -> {node: {calls: summary, seconds: summary}}"""
    by_node = {}
    for j in jobs:
        nodes = ((j.get("timings") or {}).get("nodes")) or {}
        for name, entry in nodes.items():
            slot = by_node.setdefault(name, {"calls": [], "seconds": []})
            slot["calls"].append(entry.get("calls"))
            slot["seconds"].append(entry.get("seconds"))
    return {name: {"calls_per_job": summarize(v["calls"], "calls"), "seconds_per_job": summarize(v["seconds"], "seconds")} for name, v in sorted(by_node.items())}


def usage_summary(jobs):
    """Model calls and token totals over finished jobs. Tokens are None unless EVERY job reported them; the reason is carried through, never replaced by zero."""
    usages = [j.get("usage") or {} for j in jobs]
    calls = sum(u.get("model_calls") or 0 for u in usages)
    available = bool(usages) and all(u.get("tokens_available") for u in usages)
    notes = sorted({u.get("tokens_note") for u in usages if u.get("tokens_note")})
    tokens = {k: (sum(u.get(k) or 0 for u in usages) if available else None) for k in ("prompt_tokens", "output_tokens", "thinking_tokens", "total_tokens")}
    return {"model_calls": calls, "tokens_available": available, **tokens, "tokens_note": "; ".join(notes) if notes else (None if available else "no token counts were reported"),
            "cost_usd": None, "cost_note": "unavailable: cost needs real token counts and a priced, sourced pricing file; a fake model has neither"}


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path, obj):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")


def write_csv(path, rows, columns):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(columns), extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({c: ("" if row.get(c) is None else row.get(c)) for c in columns})


SUMMARY_COLUMNS = ("metric", "unit", "n", "min", "mean", "p50", "p90", "p95", "p99", "max", "low_sample")


def summary_rows(results):
    """Flat rows (one per latency metric) for the summary CSV."""
    rows = []
    lat = results["latency"]
    for name in sorted(lat):
        s = lat[name]
        rows.append(dict(s, metric=name, low_sample=" ".join(s.get("low_sample") or [])))
    for node, v in sorted(results.get("per_node", {}).items()):
        s = v["seconds_per_job"]
        rows.append(dict(s, metric="node:" + node, low_sample=" ".join(s.get("low_sample") or [])))
    return rows


def validate_results(results):
    """-> list of problems (empty when the structure is as documented). Used by the tests and by the report generator before it prints anything."""
    problems = []

    def need(container, key, where):
        if not isinstance(container, dict) or key not in container:
            problems.append("missing " + where + "." + key)
            return None
        return container[key]
    if results.get("schema") != RESULT_SCHEMA:
        problems.append("schema is not " + RESULT_SCHEMA)
    for key in ("meta", "parameters", "counts", "throughput", "latency", "per_node", "usage", "errors", "honesty"):
        need(results, key, "results")
    meta = results.get("meta") or {}
    for key in ("mode", "model", "fake_model", "started_at", "finished_at", "python", "cpu_count", "week5_version"):
        need(meta, key, "meta")
    for key in ("api_submit_ms", "queue_wait_s", "processing_s", "end_to_end_s"):
        s = need(results.get("latency") or {}, key, "latency")
        if isinstance(s, dict):
            for k in ("n", "unit", "min", "mean", "p50", "p90", "p95", "p99", "max", "low_sample"):
                need(s, k, "latency." + key)
    usage = results.get("usage") or {}
    if usage.get("tokens_available") is False and any(usage.get(k) not in (None,) for k in ("prompt_tokens", "output_tokens", "thinking_tokens", "total_tokens")):
        problems.append("tokens are reported although tokens_available is false")
    if usage.get("cost_usd") is not None and not usage.get("tokens_available"):
        problems.append("a cost is reported without real token counts")
    if (meta.get("fake_model") is True) and usage.get("tokens_available"):
        problems.append("a fake model cannot have token counts")
    return problems
