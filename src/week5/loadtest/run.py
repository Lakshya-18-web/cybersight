"""The load test itself: submit alerts at a chosen pattern, wait for the queue to drain, and turn the job records into a results dict (see metrics.RESULT_SCHEMA).

What is measured, exactly (all durations in seconds unless the name says ms):
  api_submit_ms   client-observed time of one POST /alerts (validation + store + hand-over to the queue). In-process mode excludes HTTP and the network; HTTP mode includes them.
  queue_wait_s    first_started_at - enqueued_at: from the job being stored to a worker starting its FIRST attempt (so it includes the workers' poll delay; waiting between a failed attempt and its retry is not in it).
  processing_s    finished_at - started_at of the final attempt: graph + model + case storage.
  end_to_end_s    finished_at - enqueued_at: everything, including retries and their back-off.
  All three come from the job store's own timestamps, not from the client's clock. Latency is computed over SUCCEEDED jobs; failures are counted separately by code.
  per_node        seconds the graph spent in each node, per job (instrumented engine only).
Open loop (rate > 0): submission i is scheduled at t0 + i / rate whatever the server does; client_lag_s records how late a submission actually left (so a slow client is visible, not hidden).
Closed loop (rate = 0): `concurrency` client threads submit as fast as the API answers.
Nothing is estimated: if a number cannot be measured it is None with a note.
"""
import os
import platform
import random
import threading
import time
from collections import Counter

import week5
from week5 import fixtures
from week5.jobs import parse_ts

from . import metrics

ROW_COLUMNS = ("seq", "alert_id", "http_status", "duplicate", "api_submit_ms", "client_lag_s", "job_id", "status", "attempts", "error_code", "queue_wait_s", "processing_s", "end_to_end_s")


class LoadConfig:
    def __init__(self, total=200, rate=0.0, concurrency=8, duplicates=0.0, seed=1, drain_timeout=120.0, poll_interval=0.05, sample_interval=0.1, label=""):
        if total < 1 or total > 1_000_000:
            raise ValueError("total must be from 1 to 1000000")
        if rate < 0 or concurrency < 1 or concurrency > 512 or not 0 <= duplicates <= 0.9:
            raise ValueError("rate must be >= 0, concurrency 1..512, duplicates 0..0.9")
        self.total, self.rate, self.concurrency, self.duplicates, self.seed = int(total), float(rate), int(concurrency), float(duplicates), int(seed)
        self.drain_timeout, self.poll_interval, self.sample_interval, self.label = float(drain_timeout), float(poll_interval), float(sample_interval), label

    def public(self):
        return {"total_alerts": self.total, "rate_per_s": self.rate, "pattern": "open loop" if self.rate > 0 else "closed loop", "client_threads": self.concurrency,
                "duplicate_fraction": self.duplicates, "seed": self.seed, "drain_timeout_s": self.drain_timeout, "label": self.label}


def build_submissions(config):
    """-> [(seq, alert)]. Unique alerts first, then duplicates of randomly chosen earlier ones (deterministic from the seed), interleaved."""
    unique = [fixtures.make_alert(i, "LT") for i in range(config.total)]
    rng = random.Random(config.seed)
    dup_n = int(round(config.total * config.duplicates))
    extra = [rng.choice(unique[: max(1, i + 1)]) for i in range(dup_n)]
    items = list(unique)
    for k, alert in enumerate(extra):
        items.insert(min(len(items), 2 * k + 3), alert)
    return list(enumerate(items))


class _Monitor(threading.Thread):
    def __init__(self, client, interval):
        super().__init__(daemon=True, name="lt-monitor")
        self.client, self.interval, self.stop_flag = client, interval, threading.Event()
        self.samples = []

    def run(self):
        t0 = time.monotonic()
        while not self.stop_flag.is_set():
            try:
                depth = self.client.queue_depth()
            except Exception:
                depth = None
            if depth is not None:
                self.samples.append((round(time.monotonic() - t0, 3), depth))
            self.stop_flag.wait(self.interval)


def run_load(config, client, backend_description=None, fake_model=True, model_name="FAKE:canned", mode=None):
    subs = build_submissions(config)
    rows, rows_lock, cursor = [], threading.Lock(), {"i": 0}
    t0 = time.monotonic()
    started_at = metrics.now_iso()
    monitor = _Monitor(client, config.sample_interval)
    monitor.start()

    def next_item():
        with rows_lock:
            if cursor["i"] >= len(subs):
                return None
            item = subs[cursor["i"]]
            cursor["i"] += 1
            return item

    def submit_loop():
        while True:
            item = next_item()
            if item is None:
                return
            seq, alert = item
            lag = 0.0
            if config.rate > 0:
                target = t0 + seq / config.rate
                wait = target - time.monotonic()
                if wait > 0:
                    time.sleep(wait)
                lag = max(0.0, time.monotonic() - target)
            began = time.monotonic()
            status, body = client.submit(alert)
            elapsed = time.monotonic() - began
            row = {"seq": seq, "alert_id": alert["alert_id"], "http_status": status, "api_submit_ms": round(elapsed * 1000.0, 3), "client_lag_s": round(lag, 6),
                   "duplicate": bool(body.get("duplicate")) if isinstance(body, dict) else False, "job_id": body.get("job_id") if isinstance(body, dict) else None}
            with rows_lock:
                rows.append(row)

    threads = [threading.Thread(target=submit_loop, daemon=True, name="lt-client-%d" % i) for i in range(config.concurrency)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    submit_done = time.monotonic()

    # ---- wait for the queue to drain
    accepted = {}
    for r in rows:
        if r["http_status"] in (200, 202) and r["job_id"]:
            accepted.setdefault(r["job_id"], None)
    deadline = time.monotonic() + config.drain_timeout
    pending = set(accepted)
    views = {}
    while pending and time.monotonic() < deadline:
        for job_id in list(pending):
            status, view = client.get_job(job_id)
            if status == 200 and view.get("status") in ("succeeded", "failed", "timed_out"):
                views[job_id] = view
                pending.discard(job_id)
        if pending:
            time.sleep(config.poll_interval)
    drained = time.monotonic()
    monitor.stop_flag.set()
    monitor.join(timeout=2)
    for job_id in pending:     # one last look so unfinished jobs are described by what they were doing
        status, view = client.get_job(job_id)
        if status == 200:
            views[job_id] = view
    finished_at = metrics.now_iso()

    return build_results(config, rows, views, set(pending), monitor.samples, t0, submit_done, drained, backend_description or {}, fake_model, model_name, mode or getattr(client, "mode", "unknown"),
                         started_at, finished_at)


def build_results(config, rows, views, unfinished, depth_samples, t0, submit_done, drained, backend_description, fake_model, model_name, mode, started_at, finished_at):
    by_status = Counter(r["http_status"] for r in rows)
    accepted_rows = [r for r in rows if r["http_status"] in (200, 202)]
    terminal = {jid: v for jid, v in views.items() if jid not in unfinished}
    succeeded = [v for v in terminal.values() if v["status"] == "succeeded"]
    for r in rows:
        v = views.get(r["job_id"]) if r["job_id"] else None
        if v:
            r.update(status=v["status"], attempts=v.get("attempts"), error_code=v.get("error_code"))
            enq, first, started, fin = parse_ts(v.get("enqueued_at")), parse_ts(v.get("first_started_at")), parse_ts(v.get("started_at")), parse_ts(v.get("finished_at"))
            r["queue_wait_s"] = _r(metrics.seconds_between(first, enq))
            if v["status"] == "succeeded":
                r["processing_s"] = _r(metrics.seconds_between(fin, started))
                r["end_to_end_s"] = _r(metrics.seconds_between(fin, enq))
    first_enq = min((parse_ts(v.get("enqueued_at")) for v in views.values() if v.get("enqueued_at")), default=None)
    last_fin = max((parse_ts(v.get("finished_at")) for v in terminal.values() if v.get("finished_at")), default=None)
    makespan = metrics.seconds_between(last_fin, first_enq)
    flags = {bool((v.get("result") or {}).get("fake_model")) for v in succeeded if (v.get("result") or {}).get("fake_model") is not None}
    if fake_model is None:      # HTTP mode: the server says whether each job used a fake model
        fake_model = True if flags == {True} else (False if flags == {False} else None)
    outcomes = {"verdict_status": dict(Counter((v.get("result") or {}).get("verdict_status") for v in succeeded)),
                "routing_decision": dict(Counter((v.get("result") or {}).get("routing_decision") for v in succeeded))}
    created = sum(1 for r in rows if r["http_status"] == 202)
    latency = {
        "api_submit_ms": metrics.summarize([r["api_submit_ms"] for r in accepted_rows], "ms"),
        "queue_wait_s": metrics.summarize([r.get("queue_wait_s") for r in rows if not r["duplicate"] and r.get("queue_wait_s") is not None], "seconds"),
        "processing_s": metrics.summarize([r.get("processing_s") for r in rows if not r["duplicate"] and r.get("processing_s") is not None], "seconds"),
        "end_to_end_s": metrics.summarize([r.get("end_to_end_s") for r in rows if not r["duplicate"] and r.get("end_to_end_s") is not None], "seconds"),
        "client_lag_s": metrics.summarize([r["client_lag_s"] for r in rows], "seconds"),
    }
    codes = Counter(v.get("error_code") for v in terminal.values() if v["status"] != "succeeded")
    results = {
        "schema": metrics.RESULT_SCHEMA,
        "meta": {"mode": mode, "model": model_name, "fake_model": bool(fake_model), "started_at": started_at, "finished_at": finished_at, "python": platform.python_version(),
                 "platform": platform.platform(), "cpu_count": os.cpu_count(), "week5_version": week5.VERSION, "backend": backend_description},
        "parameters": config.public(),
        "counts": {"submissions": len(rows), "http_status": {str(k): v for k, v in sorted(by_status.items())}, "jobs_created": created, "duplicates_recognised": sum(1 for r in rows if r["duplicate"]),
                   "rejected_or_failed_requests": sum(v for k, v in by_status.items() if k not in (200, 202)), "succeeded": len(succeeded),
                   "failed": sum(1 for v in terminal.values() if v["status"] == "failed"), "timed_out": sum(1 for v in terminal.values() if v["status"] == "timed_out"),
                   "unfinished_at_drain_timeout": len(unfinished), "retried_jobs": sum(1 for v in terminal.values() if (v.get("attempts") or 1) > 1)},
        "throughput": {"submit_window_s": round(submit_done - t0, 4), "accepted_per_s": metrics.rate(len(accepted_rows), submit_done - t0), "makespan_s": _r(makespan),
                       "completed_per_s": metrics.rate(len(succeeded), makespan), "max_in_flight_observed": max((d for _t, d in depth_samples), default=None),
                       "note": "completed_per_s = succeeded jobs / (last finish - first enqueue), from the job store's timestamps"},
        "latency": latency,
        "outcomes": {k: {str(a): b for a, b in sorted(v.items(), key=lambda kv: str(kv[0]))} for k, v in outcomes.items()},
        "per_node": metrics.node_summary(succeeded),
        "usage": metrics.usage_summary(succeeded),
        "errors": {"by_error_code": {str(k): v for k, v in sorted(codes.items(), key=lambda kv: str(kv[0]))}, "http_non_success": {str(k): v for k, v in sorted(by_status.items()) if k not in (200, 202)}},
        "queue_depth_samples": [list(s) for s in _thin(depth_samples, 200)],
        "honesty": honesty_notes(fake_model, mode),
    }
    results["_rows"] = rows
    return results


def honesty_notes(fake_model, mode):
    notes = ["Percentiles are nearest-rank; a percentile with too few samples is listed in low_sample and equals (or nearly equals) the maximum."]
    if fake_model:
        notes.append("The model is a FAKE with a SIMULATED delay. These numbers describe this software's own overhead plus that delay. They say nothing about Gemini's real latency, quota or cost.")
        notes.append("No token counts and no cost are reported: a fake model has none, and nothing was estimated.")
    if mode == "inprocess":
        notes.append("In-process mode calls the API handlers directly (no HTTP, no network, no database) and runs the workers as threads of one Python process, so it cannot show true parallel speed-up of CPU work.")
    if mode == "http":
        notes.append("HTTP mode includes the network and the server's framework. Latency of the server's own database and broker is included only if the server was configured with them.")
    notes.append("Results are for one machine and one run; repeat it (different seeds) before drawing conclusions, and never compare runs made with different settings.")
    return notes


def _r(x):
    return None if x is None else round(x, 6)


def _thin(samples, limit):
    if len(samples) <= limit:
        return samples
    step = len(samples) / float(limit)
    return [samples[int(i * step)] for i in range(limit)]
