"""python -m week5.evalrun <command>

  rehearse   --out-root DIR [--plan-id ID]       the whole pipeline on SYNTHETIC data with FAKE models (default; safe, free, offline)
  plan       --set fixture|dev|frozen --plan-id ID --out FILE [--memory off|on] [--alias-ids] [--engine langgraph|instrumented]
  authorization-template --plan FILE --out FILE  a blank authorisation file bound to the plan's hash (it is invalid until a person fills it in)
  gate-status --plan FILE --run-key KEY          say whether the protected-set gate would open; reads no protected data
  collect    --plan FILE --config C --run N --out-root DIR [--live] [--i-understand-this-opens-the-frozen-set]
  validate   --plan FILE --out-root DIR          structural and cross-run checks (no labels needed)
  score      --plan FILE --out-root DIR [--i-understand-this-opens-the-frozen-set]   validate against the data, compute metrics, write the report

Nothing here runs a frozen-set evaluation by itself. See docs/WEEK5_FINAL_EVALUATION.md.
"""
import argparse
import json
import os
import sys

from . import CONFIGS
from . import gate, pipeline, plan as plan_module
from .collect import write_json
from .validate import validate_runs

ACK = "--i-understand-this-opens-the-frozen-set"


def _read_plan(path):
    with open(path, "r", encoding="utf-8") as fh:
        plan = json.load(fh)
    problems = plan_module.validate_plan(plan)
    if problems:
        raise SystemExit("STOPPED: invalid plan: " + "; ".join(problems))
    return plan


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m week5.evalrun", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("rehearse")
    r.add_argument("--out-root", required=True)
    r.add_argument("--plan-id", default="rehearsal")
    pl = sub.add_parser("plan")
    pl.add_argument("--set", choices=("fixture", "dev", "frozen"), default="fixture")
    pl.add_argument("--plan-id", required=True)
    pl.add_argument("--out", required=True)
    pl.add_argument("--memory", choices=("off", "on"), default="off")
    pl.add_argument("--alias-ids", action="store_true", help="evaluate with identifier aliasing on (default off: prompts identical to the Week 3/4 dev runs)")
    pl.add_argument("--engine", choices=("langgraph", "instrumented"), default="langgraph")
    at = sub.add_parser("authorization-template")
    at.add_argument("--plan", required=True)
    at.add_argument("--out", required=True)
    gs = sub.add_parser("gate-status")
    gs.add_argument("--plan", required=True)
    gs.add_argument("--run-key", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--plan", required=True)
    c.add_argument("--config", required=True, choices=CONFIGS)
    c.add_argument("--run", required=True, type=int)
    c.add_argument("--out-root", required=True)
    c.add_argument("--live", action="store_true")
    c.add_argument(ACK, dest="ack", action="store_true")
    v = sub.add_parser("validate")
    v.add_argument("--plan", required=True)
    v.add_argument("--out-root", required=True)
    s = sub.add_parser("score")
    s.add_argument("--plan", required=True)
    s.add_argument("--out-root", required=True)
    s.add_argument(ACK, dest="ack", action="store_true")
    args = p.parse_args(argv)
    try:
        if args.command == "rehearse":
            result, files, out_dir = pipeline.rehearse(args.out_root, args.plan_id)
            print("REHEARSAL (synthetic data, fake models). Comparison valid: %s. Wrote %s to %s" % (result["valid"], ", ".join(files), out_dir))
            return 0 if result["valid"] else 1
        if args.command == "plan":
            plan = plan_module.make_plan(args.plan_id, args.set, memory=args.memory, alias_ids=args.alias_ids, engine=args.engine)
            write_json(args.out, plan)
            print("plan written: %s\nplan sha256: %s" % (args.out, plan_module.plan_sha256(plan)))
            return 0
        plan = _read_plan(args.plan)
        if args.command == "authorization-template":
            if plan["set"] != "frozen":
                raise SystemExit("STOPPED: only a frozen-set plan needs an authorisation")
            write_json(args.out, {"schema": gate.SCHEMA_AUTH, "statement": gate.STATEMENT, "authorized_by": "", "authorized_at": "", "expires_at": "", "plan_sha256": plan_module.plan_sha256(plan),
                                  "set": "frozen", "allowed_runs": plan_module.run_keys(plan) + ["score/all"]})
            print("template written: %s (authorized_by, authorized_at, expires_at are blank on purpose; a person must fill them in, and may remove runs from allowed_runs)" % args.out)
            return 0
        if args.command == "gate-status":
            reasons = gate.decide(
                plan, plan_module.plan_sha256(plan), args.run_key, acknowledged=True, ledger_path=os.path.join(os.path.dirname(os.path.abspath(args.plan)), gate.LEDGER_NAME))
            print("gate: OPEN for %s" % args.run_key if not reasons else "gate: CLOSED\n- " + "\n- ".join(reasons))
            return 0 if not reasons else 3
        if args.command == "collect":
            out = pipeline.collect_one(plan, args.config, args.run, args.out_root, live=args.live, acknowledged=args.ack)
            print("run recorded: " + out)
            return 0
        if args.command == "validate":
            rep = validate_runs(plan, args.out_root)
            for pr in rep["problems"]:
                print("%s %s: %s" % (pr["code"], pr["run"] or "-", pr["detail"]))
            print("valid" if rep["valid"] else "NOT VALID (%d problems)" % len(rep["problems"]))
            return 0 if rep["valid"] else 1
        result, files, out_dir = pipeline.score(plan, args.out_root, acknowledged=args.ack)
        print("comparison valid: %s. Wrote %s to %s" % (result["valid"], ", ".join(files), out_dir))
        return 0 if result["valid"] else 1
    except (gate.GateDenied, pipeline.PipelineError, ValueError) as error:
        print("STOPPED: " + str(error))
        return 3


if __name__ == "__main__":
    sys.exit(main())
