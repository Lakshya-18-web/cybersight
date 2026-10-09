"""Run graph v0 on a few DEV alerts. Offline and deterministic: no LLM call, no reputation call, no labels, no frozen set.

    python src/run_graph_dev.py --n 5 --out runs/week3_graph_v0/dev_smoke_5

Takes the first N alerts in alert_id order. Writes results.jsonl (one final state per alert) and summary.json into --out,
which must not already hold results. Day 3 limit: at most 20 alerts; the full dev set belongs to Day 5.
"""
import os
import sys
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
import triage_inputs
from agents import state as S
from agents.graph import build_graph, run_alert
from tools import FlowStore, build_registry

MAX_ALERTS_DAY3 = 20
DEFAULT_OUT = os.path.join("runs", "week3_graph_v0", "dev_smoke_5")


def select_alerts(alerts, n):
    """The first n alerts by alert_id, so the same n always gives the same alerts."""
    return alerts.sort_values("alert_id", kind="stable").head(n)


def run_many(graph, alert_rows, store):
    finals = []
    for _, row in alert_rows.iterrows():
        finals.append(run_alert(graph, S.alert_record(row, store.frame)))
    return finals


def summarize(finals):
    by_status = {}
    for f in finals:
        by_status[f["status"]] = by_status.get(f["status"], 0) + 1
    return {"graph_version": S.GRAPH_VERSION, "alerts": len(finals), "alert_ids": [f["alert_id"] for f in finals], "status_counts": dict(sorted(by_status.items())),
            "tool_calls": sum(len(f["evidence"]) for f in finals), "errors": sum(len(f["errors"]) for f in finals),
            "llm_calls": 0, "reputation_calls": 0, "set": "dev", "frozen_set_opened": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--n", type=int, default=5, help="number of dev alerts (1 to " + str(MAX_ALERTS_DAY3) + ")")
    parser.add_argument("--out", default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    if args.n < 1 or args.n > MAX_ALERTS_DAY3:
        parser.error("--n must be between 1 and " + str(MAX_ALERTS_DAY3) + " on Day 3")
    out = args.out if os.path.isabs(args.out) else os.path.join(config.PROJECT_ROOT, args.out)
    if os.path.exists(os.path.join(out, "results.jsonl")):
        parser.error("results already exist in " + out + "; choose a new --out so a run is never overwritten")
    alerts = triage_inputs.load_dev_alerts()
    store = FlowStore.from_dev()
    graph = build_graph(build_registry(flow_store=store))   # reputation stays off
    finals = run_many(graph, select_alerts(alerts, args.n), store)
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "results.jsonl"), "w", encoding="utf-8") as f:
        for final in finals:
            f.write(json.dumps(final, sort_keys=True, default=str) + "\n")
    summary = summarize(finals)
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
    for final in finals:
        print(final["alert_id"], final["status"], "trace=" + ">".join(final["trace"]), "tool_calls=" + str(len(final["evidence"])), "errors=" + str(len(final["errors"])))
        for finding in final["traffic_findings"]["findings"]:
            print("    -", finding["statement"])
    print(json.dumps(summary, sort_keys=True))
    print("saved to", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
