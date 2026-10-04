"""Check that Week 1 is complete, optionally commit it, and create the week1-freeze tag.

  python src/tag_week1_freeze.py                      checks only, changes nothing
  python src/tag_week1_freeze.py --stage-and-commit   adds a fixed list of Week 1 paths and commits them (needs --yes)
  python src/tag_week1_freeze.py --tag --yes          creates the annotated tag (the working tree must be clean)

The script never pushes. Days 2 to 6 were not committed before Day 7, so the first commit is large; the list of paths it adds is printed first.
data/raw, data/processed and eval/flow_store_*.parquet are never added.
"""
import os
import sys
import json
import hashlib
import argparse
import subprocess

import config

parser = argparse.ArgumentParser()
parser.add_argument("--stage-and-commit", action="store_true")
parser.add_argument("--tag", action="store_true")
parser.add_argument("--yes", action="store_true", help="confirm that you want the commit or tag created")
parser.add_argument("--message", default=None, help="commit message (the Claude attribution lines are appended unless --no-trailer)")
parser.add_argument("--no-trailer", action="store_true")
parser.add_argument("--allow-eval-only-repro", action="store_true", help="accept a reproducibility run made in eval-only mode")
args = parser.parse_args()

ROOT = config.PROJECT_ROOT
STAGE_PATHS = ["src", "notebooks", "reports", "models", "eval", "README.md", "WEEK1_REPORT.md", "HANDOFF.md", "DAY7_RUNBOOK.md",
               "requirements.txt", ".gitignore"]
TRAILER = ("Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>\n"
           "Claude-Session: https://claude.ai/code/session_012J2oPbKhbdQCkDtd13R2kx")
results = []


def check(name, passed, detail=""):
    print("- " + ("PASS" if passed else "FAIL") + ": " + name + (" (" + detail + ")" if detail else ""))
    results.append(bool(passed))


def git(*parts, check_ok=True):
    result = subprocess.run(["git"] + list(parts), cwd=ROOT, capture_output=True, text=True)
    if check_ok and result.returncode != 0:
        print("git " + " ".join(parts) + " failed:\n" + result.stdout + result.stderr)
        sys.exit(1)
    return result


def read_json(relative):
    path = os.path.join(ROOT, relative)
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return json.load(f)


def ensure_gitignore():
    path = os.path.join(ROOT, ".gitignore")
    current = ""
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            current = f.read()
    present = [line.strip() for line in current.splitlines()]
    absent = [line for line in config.GITIGNORE_REQUIRED if line not in present]
    return path, current, absent


def main():
    inside = git("rev-parse", "--is-inside-work-tree", check_ok=False)
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        print("STOPPED: " + ROOT + " is not a git repository.")
        sys.exit(1)
    print("# Week 1 freeze check")
    print("")
    print("Branch: " + git("rev-parse", "--abbrev-ref", "HEAD", check_ok=False).stdout.strip())

    print("")
    print("## Completeness")
    needed = ["WEEK1_REPORT.md", "README.md", "HANDOFF.md", "eval/MANIFEST.json", "eval/DATASET_CARD.md", "reports/test_metrics.md",
              "reports/test_eval.lock", "reports/reproducibility_report.md", "reports/spot_check_30.md"]
    for name in needed:
        check(name + " exists", os.path.exists(os.path.join(ROOT, name)))
    repro = read_json("reports/reproducibility_report.json")
    check("reproducibility run passed in full mode", repro is not None and repro.get("status") == "PASS"
          and (repro.get("mode") == "full" or args.allow_eval_only_repro), str(repro.get("mode")) if repro else "missing")
    spot = read_json("reports/spot_check_summary.json")
    check("spot check passed on 30 dev alerts", spot is not None and spot.get("status") == "PASS" and spot.get("alerts_checked") == config.SPOT_CHECK_TOTAL)
    threshold = read_json("models/threshold.json")
    check("threshold is the accepted value", threshold is not None and threshold.get("threshold") == config.ACCEPTED_THRESHOLD)
    verify = subprocess.run([sys.executable, os.path.join(ROOT, "src", "verify_eval.py"), "--skip-flow-stores"], cwd=ROOT, capture_output=True, text=True)
    check("verify_eval.py passes", verify.returncode == 0)

    print("")
    print("## Git hygiene")
    path, current, absent = ensure_gitignore()
    check(".gitignore has the required lines", len(absent) == 0, "missing: " + ", ".join(absent) if absent else "")
    tracked_bad = git("ls-files", "data", "eval/flow_store_dev.parquet", "eval/flow_store_frozen.parquet", check_ok=False).stdout.split()
    check("no raw data, processed data or flow store is tracked", len(tracked_bad) == 0, ", ".join(tracked_bad[:5]))
    existing_tag = git("tag", "-l", config.FREEZE_TAG, check_ok=False).stdout.strip()
    check("tag " + config.FREEZE_TAG + " does not exist yet", existing_tag == "")
    status = git("status", "--porcelain", check_ok=False).stdout.splitlines()
    print("Working tree: " + ("clean" if len(status) == 0 else str(len(status)) + " changed or untracked paths"))

    if args.stage_and_commit:
        if not args.yes:
            print("STOPPED: add --yes to stage and commit.")
            sys.exit(1)
        completeness = results[:len(needed) + 4]
        if not all(completeness):
            print("STOPPED: the completeness checks above must pass before committing.")
            sys.exit(1)
        if len(absent) > 0:
            with open(path, "a", encoding="utf-8") as f:
                if current != "" and not current.endswith("\n"):
                    f.write("\n")
                f.write("\n".join(absent) + "\n")
            print("Added to .gitignore: " + ", ".join(absent))
        paths = [p for p in STAGE_PATHS if os.path.exists(os.path.join(ROOT, p))]
        print("Staging: " + ", ".join(paths))
        git("add", "--", *paths)
        staged = git("diff", "--cached", "--name-only").stdout.splitlines()
        banned = [s for s in staged if s.startswith("data/") or s.startswith("eval/flow_store_")]
        if len(banned) > 0:
            git("reset", "-q")
            print("STOPPED: refused to commit data files: " + ", ".join(banned[:5]))
            sys.exit(1)
        print(str(len(staged)) + " files staged.")
        message = args.message or "Week 1: data, detector, threshold and frozen evaluation sets"
        if not args.no_trailer:
            message = message + "\n\n" + TRAILER
        git("commit", "-m", message)
        print("Committed: " + git("rev-parse", "--short", "HEAD").stdout.strip())
        status = git("status", "--porcelain", check_ok=False).stdout.splitlines()
        print("Working tree: " + ("clean" if len(status) == 0 else str(len(status)) + " changed or untracked paths"))

    if args.tag:
        if not args.yes:
            print("STOPPED: add --yes to create the tag.")
            sys.exit(1)
        if len(status) > 0:
            print("STOPPED: the working tree is not clean, so the tag would not describe a committed state. Commit first (--stage-and-commit --yes).")
            sys.exit(1)
        if existing_tag != "":
            print("STOPPED: the tag already exists.")
            sys.exit(1)
        if not all(results):
            print("STOPPED: at least one check failed.")
            sys.exit(1)
        with open(os.path.join(ROOT, "eval", "MANIFEST.json"), "rb") as f:
            manifest_sha = hashlib.sha256(f.read()).hexdigest()
        test = read_json("reports/test_metrics.json")
        message = ("Week 1 freeze\n\nthreshold " + repr(config.ACCEPTED_THRESHOLD) + "\nMANIFEST.json sha256 " + manifest_sha
                   + "\nreproducibility " + repro["status"] + " (" + repro["mode"] + ")\nspot check " + spot["status"]
                   + "\ntest recall " + ("%.4f" % test["at_accepted_threshold"]["recall"] if test else "n/a"))
        git("tag", "-a", config.FREEZE_TAG, "-m", message)
        print("Created tag " + config.FREEZE_TAG + " at " + git("rev-parse", "--short", "HEAD").stdout.strip() + ".")
        print("Not pushed. To publish it yourself: git push origin " + config.FREEZE_TAG)
        return

    print("")
    if args.stage_and_commit:
        print("Committed. The checks above ran before the commit (the .gitignore line is added by it). Now run, as a separate command:")
        print("  python src/tag_week1_freeze.py --tag --yes")
        sys.exit(0)
    print("All checks passed." if all(results) else "Some checks failed. Nothing was changed.")
    print("Next: --stage-and-commit --yes, then --tag --yes.")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
