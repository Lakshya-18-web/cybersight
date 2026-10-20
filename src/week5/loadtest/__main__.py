"""python -m week5.loadtest run|report   (see docs/WEEK5_LOAD_TESTING.md)

  run --mode inprocess  [--total 200] [--rate 0] [--concurrency 8] [--workers 2] [--model-delay 0.05] [--jitter 0] [--failure-mix unavailable=0.1] [--duplicates 0.1] [--out-dir loadtest_out]
  run --mode http --base-url http://127.0.0.1:8000 [--token-env WEEK5_LOADTEST_TOKEN] [--allow-remote]
  report --results loadtest_out/results.json [--out loadtest_out/report.md]

The model is ALWAYS the fake in this tool. A live Gemini run is deliberately not offered here: it would spend money and quota, and it needs an explicit decision (see the docs).
"""
import argparse
import json
import os
import sys

from . import backend as backend_module
from . import client as client_module
from . import metrics, report, run as run_module


def _write_outputs(results, out_dir, prefix):
    os.makedirs(out_dir, exist_ok=True)
    rows = results.pop("_rows", [])
    metrics.write_json(os.path.join(out_dir, prefix + "results.json"), results)
    metrics.write_csv(os.path.join(out_dir, prefix + "jobs.csv"), sorted(rows, key=lambda r: r["seq"]), run_module.ROW_COLUMNS)
    metrics.write_csv(os.path.join(out_dir, prefix + "summary.csv"), metrics.summary_rows(results), metrics.SUMMARY_COLUMNS)
    with open(os.path.join(out_dir, prefix + "report.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(report.render(results))
    return [prefix + n for n in ("results.json", "jobs.csv", "summary.csv", "report.md")]


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m week5.loadtest", description="Week 5 load tester (fake model only)")
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run")
    r.add_argument("--mode", choices=("inprocess", "http"), default="inprocess")
    r.add_argument("--total", type=int, default=200)
    r.add_argument("--rate", type=float, default=0.0, help="alerts per second, open loop; 0 = closed loop")
    r.add_argument("--concurrency", type=int, default=8)
    r.add_argument("--duplicates", type=float, default=0.0)
    r.add_argument("--seed", type=int, default=1)
    r.add_argument("--drain-timeout", type=float, default=120.0)
    r.add_argument("--label", default="")
    r.add_argument("--out-dir", default="loadtest_out")
    r.add_argument("--prefix", default="")
    r.add_argument("--workers", type=int, default=2)
    r.add_argument("--model-delay", type=float, default=0.05)
    r.add_argument("--jitter", type=float, default=0.0)
    r.add_argument("--failure-mix", default="")
    r.add_argument("--max-attempts", type=int, default=3)
    r.add_argument("--api-rate-limit", type=int, default=0, help="requests per minute per user enforced by the API (0 = off)")
    r.add_argument("--base-url", default="")
    r.add_argument("--token-env", default="WEEK5_LOADTEST_TOKEN")
    r.add_argument("--allow-remote", action="store_true")
    g = sub.add_parser("report")
    g.add_argument("--results", required=True)
    g.add_argument("--out", default="")
    args = p.parse_args(argv)
    try:
        if args.command == "report":
            with open(args.results, encoding="utf-8") as fh:
                text = report.render(json.load(fh))
            if args.out:
                with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
            else:
                sys.stdout.write(text)
            return 0
        config = run_module.LoadConfig(args.total, args.rate, args.concurrency, args.duplicates, args.seed, args.drain_timeout, label=args.label)
        if args.mode == "http":
            if not args.base_url:
                raise ValueError("--base-url is required in http mode")
            client = client_module.HttpClient(args.base_url, args.token_env, args.allow_remote)
            results = run_module.run_load(config, client, {"base_url_host": args.base_url.split("//")[-1].split("/")[0].split(":")[0]}, fake_model=None, model_name="reported by the server (see per-job results)", mode="http")
        else:
            ids = ["LT-%06d" % i for i in range(config.total)]
            table = backend_module.scenario_table(ids, backend_module.parse_mix(args.failure_mix), config.seed)
            backend = backend_module.InProcessBackend(args.workers, args.model_delay, args.jitter, args.max_attempts, scenarios=table, seed=config.seed, api_rate_per_minute=args.api_rate_limit)
            backend.start()
            try:
                results = run_module.run_load(config, client_module.InProcessClient(backend), dict(backend.describe(), failure_mix=args.failure_mix or "none"), True, "FAKE:canned", "inprocess")
            finally:
                backend.stop()
        files = _write_outputs(results, args.out_dir, args.prefix)
        print("wrote " + ", ".join(os.path.join(args.out_dir, f) for f in files))
        c = results["counts"]
        print("submissions %d, succeeded %d, failed %d, timed out %d, unfinished %d" % (c["submissions"], c["succeeded"], c["failed"], c["timed_out"], c["unfinished_at_drain_timeout"]))
        return 0
    except (ValueError, OSError) as error:
        print("STOPPED: " + str(error))
        return 2


if __name__ == "__main__":
    sys.exit(main())
