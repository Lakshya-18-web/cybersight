"""python -m week5.security.injection run [--out-dir DIR] [--only PI-A01,PI-E02]   |   list

Runs the prompt-injection suite against a fresh in-memory backend with a scripted fake model. No network, database, key or real data. Exit code 0 only when every gate passes."""
import argparse
import csv
import os
import sys

from week5.loadtest import metrics as lt_metrics

from . import harness, report

CSV_COLUMNS = ("id", "kind", "category", "title", "goal", "expected_class", "expected_layer", "observed_class", "observed_layer", "goal_achieved", "mismatch", "residual_risk", "http_statuses", "echo", "leak",
               "audit_relevant", "audit_ok", "guard_signals", "routing_decisions", "elapsed_s")


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m week5.security.injection")
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run")
    r.add_argument("--out-dir", default="")
    r.add_argument("--only", default="")
    sub.add_parser("list")
    args = p.parse_args(argv)
    if args.command == "list":
        for pl in harness.load_payloads():
            print("%-8s %-12s %-16s %s" % (pl["id"], pl["kind"][:11], pl["category"], pl["title"]))
        return 0
    try:
        results = harness.run_suite(only=[x for x in args.only.split(",") if x] or None)
    except ValueError as error:
        print("STOPPED: " + str(error))
        return 2
    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        lt_metrics.write_json(os.path.join(args.out_dir, "results.json"), results)
        with open(os.path.join(args.out_dir, "results.csv"), "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore", lineterminator="\n")
            w.writeheader()
            for rec in results["records"]:
                w.writerow({k: (" ".join(map(str, v)) if isinstance(v, list) else v) for k, v in rec.items() if k in CSV_COLUMNS})
        with open(os.path.join(args.out_dir, "report.md"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(report.render(results))
    m = results["metrics"]
    print("payloads %d (adversarial %d, controls %d); succeeded %d; neutralised %d; blocked at intake %d; fail-closed parse %d; infra failures %d" % (
        m["counts"]["payloads"], m["counts"]["adversarial"], m["counts"]["benign_controls"], m["counts"]["by_observed_class"].get("succeeded", 0), m["counts"]["by_observed_class"].get("neutralised", 0),
        m["counts"]["by_observed_class"].get("blocked_at_intake", 0), m["counts"]["by_observed_class"].get("fail_closed_parse", 0), m["infra_failures"]))
    for g in results["gates"]:
        print(("PASS  " if g["pass"] else "FAIL  ") + g["gate"])
    return 0 if results["overall_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
