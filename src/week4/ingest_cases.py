"""Put the cases of a finished Week 4 dev run into the case database (proposed actions land as 'pending', nothing is executed).

  python src/week4/ingest_cases.py --run-dir runs/week4_memory/dev_v2_mem_on            # needs WEEK4_DATABASE_URL (the case-store login role)
  python src/week4/ingest_cases.py --run-dir runs/week4_memory/dev_v2_mem_on --dry-run  # builds and validates every payload, writes nothing

Reads results.jsonl-adjacent states.jsonl (the finished graph state and routing of each alert). A real dev run is stored with alert_set 'dev'; a --fake-model run is stored as 'synthetic'.
A run whose meta says it is not a dev run is refused: the frozen set never enters the case store. Re-running the same ingest is safe: the idempotency key (run, alert set, alert, memory mode)
makes every case 'duplicate' the second time, and a changed resubmission is reported as 'conflict' and stored nowhere. Exit code 0 only when every case was created or already present.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))      # src/

import baseline_store as store

from week4 import cases

STATES_FILE = "states.jsonl"


class IngestError(Exception):
    pass


def load_run(run_dir):
    """(meta, {alert_id: state record}) with the latest state per alert. Raises IngestError for anything that is not a usable Week 4 dev run."""
    meta_path = os.path.join(run_dir, "run_meta.json")
    if not os.path.isfile(meta_path):
        raise IngestError("no run_meta.json in " + run_dir)
    meta = store.read_json(meta_path)
    if meta.get("runner") != "run_memory_dev":
        raise IngestError("that run was not made by run_memory_dev.py")
    if meta.get("set") != "dev":
        raise IngestError("only dev runs can be ingested (this run says set=" + str(meta.get("set")) + ")")
    states_path = os.path.join(run_dir, STATES_FILE)
    if not os.path.isfile(states_path):
        raise IngestError("no " + STATES_FILE + " in " + run_dir)
    latest = {}
    for rec in store.read_jsonl(states_path):
        latest[rec["alert_id"]] = rec
    return meta, latest


def build_payloads(run_dir):
    """[(alert_id, payload)] in run order. Raises IngestError / CaseBuildError for a run that cannot be turned into cases."""
    meta, latest = load_run(run_dir)
    alert_set = "synthetic" if meta.get("fake_model") else "dev"
    out = []
    for alert_id in meta["selected_alert_ids"]:
        rec = latest.get(alert_id)
        if rec is None or not isinstance(rec.get("state"), dict) or not isinstance(rec.get("routed"), dict):
            continue    # no finished graph state for this alert (a graph failure or not run yet): there is no case to store
        out.append((alert_id, cases.build_case_payload(rec["state"], rec["routed"], meta["run_name"], alert_set=alert_set, model=meta.get("model"))))
    return out, meta


def ingest_run(repo, run_dir, dry_run=False, say=print):
    """-> {outcomes: {created, duplicate, conflict, invalid, ...}, skipped_without_state, total, problems: [..]}"""
    payloads, meta = build_payloads(run_dir)
    counts, problems = {}, []
    for alert_id, payload in payloads:
        if dry_run:
            outcome = "validated"
        else:
            result = repo.ingest_case(payload)
            outcome = result["outcome"]
            if outcome not in ("created", "duplicate"):
                problems.append(alert_id + ": " + outcome + " " + str(result.get("detail") or "")[:200])
        counts[outcome] = counts.get(outcome, 0) + 1
    skipped = len(meta["selected_alert_ids"]) - len(payloads)
    say("run " + meta["run_name"] + ": " + json.dumps(counts, sort_keys=True) + ", alerts without a finished graph state: " + str(skipped))
    return {"outcomes": counts, "skipped_without_state": skipped, "total": len(payloads), "problems": problems, "run_name": meta["run_name"]}


def main(argv=None):
    p = argparse.ArgumentParser(description="Ingest the cases of a Week 4 dev run into the case database.")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--driver", choices=["psql", "psycopg"], default=None)
    args = p.parse_args(argv)
    try:
        if args.dry_run:
            result = ingest_run(None, args.run_dir, dry_run=True)
        else:
            from week4.db import drivers
            from week4.db.repository import PgRepository
            dsn = os.environ.get("WEEK4_DATABASE_URL")
            kind = args.driver
            if kind is None:
                try:
                    import psycopg  # noqa: F401
                    kind = "psycopg"
                except ImportError:
                    kind = "psql"
            if not dsn and kind == "psycopg":
                raise IngestError("WEEK4_DATABASE_URL is not set")
            try:
                result = ingest_run(PgRepository(drivers.make_driver(kind, dsn)), args.run_dir)
            except drivers.DbError as error:
                raise IngestError("database error: " + drivers.redact_dsn(str(error)))
    except (IngestError, cases.CaseBuildError) as error:
        print("STOPPED: " + str(error))
        return 2
    for problem in result["problems"]:
        print("PROBLEM " + problem)
    return 0 if not result["problems"] else 1


if __name__ == "__main__":
    sys.exit(main())
