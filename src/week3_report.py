"""Week 3 Day 7: lock agent system v1, write WEEK3_REPORT.md and the lock record. Follows the Week 2 Day 7 precedent (src/week2_report.py). No model call.

  python src/week3_report.py build  --suite-log reports/week3_day7/full_suite_<commit>.txt --timeout-decision known-limitation
  python src/week3_report.py verify

build   Collects the facts from files that already exist (the five Day 6 arm runs and their Day 4/Week 2 evaluations, the Day 5 historical run, the committed ablation table, the audit
        reports, the Week 2 baseline lock, the full-suite log), runs the lock checks, and only if every check passes writes
          WEEK3_REPORT.md                       the final Week 3 report (repository root)
          reports/week3_agent_lock.json         the lock record (hashes of the agent and tool sources, the five locked Week 2 files, every run folder and evaluation used,
                                                the ablation table, the audit reports, the suite log, the report itself, the frozen access log and the Week 1 files)
        Every number in the report is read from those files. Nothing is typed in by hand and no metric is computed from labels here: the labels and the MITRE accepted ids
        reached the numbers only through the Week 2 evaluator (src/evaluate.py). A failed check writes nothing.
        build refuses to run without --timeout-decision: how timeouts are handled is a recorded decision, not a default.
verify  Read-only. Recomputes every hash and every headline number in the lock record, re-runs the Week 2 baseline verification, and says whether anything changed since the lock.
        Exit code 0 = unchanged.

This module makes no model call, reads no label file, no MITRE key and no frozen file (it hashes the frozen access LOG, a text record of accesses, and never opens the frozen data).
It reads per-alert files only through ablation_table.load_entry (run_meta.json, evaluation.json) and raw_responses.jsonl (transport errors only). It changes no run, no prompt and no source file.
"""
import os
import re
import sys
import json
import glob
import argparse
import datetime
import subprocess

import config
import baseline_store as store
import run_baseline_dev as runner
import day6_aggregate as agg
import day6_replicates as rep
import week2_report as w2
import ablation_config as ablation
import ablation_table as at
import week3_day6_audit as audit
from agents import state as S
from agents import supervisor
from agents import verdict_prompt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = "week3_agent_lock_v1"
REPORT_NAME = "WEEK3_REPORT.md"
LOCK_RELATIVE = os.path.join("reports", "week3_agent_lock.json")
EXPECTED_AGENT_PROMPT_SHA256 = "8df5e3fee15280d6b409e2a1fd1d01a505cfbe449421d9dafa1f8a30ee99f4c7"
AGENT_PROMPT_VERSION = "agent_v1"
EXPECTED_MODEL = "gemini-3.5-flash-lite"
ARMS = ("A", "B", "C", "D", "E")
REFERENCE = "A"
RUN_PREFIX = "day6_arm_"
EVAL_PREFIX = "eval_"
DAY5_RUN = "dev_agent_v1_flash_lite"
DAY5_COMMIT_NOTE = "e75b34e (dirty)"
SETTING_KEYS = ("temperature", "max_output_tokens", "seed", "parse_retries", "timeout_seconds", "transport_retries", "requests_per_minute")
RUN_FILES = list(w2.RUN_FILES)
LOCKED_WEEK2_SOURCES = list(w2.LOCKED_SOURCE_FILES)
FIXED_SOURCES = ["src/run_agent_dev.py", "src/run_graph_dev.py", "src/ablation_config.py", "src/ablation_table.py", "src/week3_day6_audit.py", "src/week3_report.py",
                 "src/evaluate.py", "src/eval_metrics.py", "src/eval_io.py", "src/eval_labels.py", "src/compare_agent_vs_baseline.py", "src/config.py", "src/triage_inputs.py",
                 "src/baseline_store.py", "src/run_baseline_dev.py", "src/week2_report.py", "src/day6_aggregate.py", "src/day6_replicates.py"]
TIMEOUT_DECISIONS = ("known-limitation",)
MIN_TESTS_IN_SUITE_LOG = 1017
N_ALERTS = 300   # the dev alert list every run answers (tests that use a small fixture patch this)
DAY7_TEST_MARKER = "test_week3_day7"   # the module name; unittest -v prints it as "(test_week3_day7.Class.test)" or "(tests.test_week3_day7.Class.test)" depending on how discovery was started
DAY7_TEST_LINE = re.compile(r"\((?:\w+\.)*" + re.escape(DAY7_TEST_MARKER) + r"\.\w+")


class ReportError(Exception):
    pass


# ------------------------------------------------------------------------------------------------ small helpers
def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def sha_file(path):
    return agg.sha256_file(path)


def norm_sha_file(path):
    return w2.normalized_sha256(path)


def norm_sha_text(text):
    import hashlib
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def rel(root, path):
    return os.path.relpath(path, root).replace(os.sep, "/")


def jsonable(value):
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def git_text(root, *args):
    try:
        p = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout.strip() if p.returncode == 0 else None


def tracked_state(root, relpath):
    """'tracked', 'untracked' or 'unknown' (not a git repository, or git is unavailable)."""
    try:
        p = subprocess.run(["git", "-C", root, "ls-files", "--error-unmatch", "--", relpath], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if git_text(root, "rev-parse", "--is-inside-work-tree") != "true":
        return "unknown"
    return "tracked" if p.returncode == 0 else "untracked"


def source_files(root):
    names = set(LOCKED_WEEK2_SOURCES)
    names |= {rel(root, p) for p in glob.glob(os.path.join(root, "src", "agents", "*.py"))}
    names |= {rel(root, p) for p in glob.glob(os.path.join(root, "src", "tools", "*.py"))}
    names |= {n for n in FIXED_SOURCES if os.path.exists(os.path.join(root, n))}
    return sorted(names)


def parse_suite_log(path):
    """The unittest summary lines in a log: tests run, seconds, OK/FAILED, skipped, and whether the Day 7 tests appear in it (a -v log lists every test)."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    ran = re.findall(r"^Ran (\d+) tests? in ([0-9.]+)s", text, re.M)
    ok = re.findall(r"^OK(?: \((.*?)\))?\s*$", text, re.M)
    failed = re.findall(r"^FAILED \((.*?)\)\s*$", text, re.M)
    skipped = None
    if ok and ok[-1]:
        m = re.search(r"skipped=(\d+)", ok[-1])
        skipped = int(m.group(1)) if m else 0
    elif ok:
        skipped = 0
    return {"ran": int(ran[-1][0]) if ran else None, "seconds": float(ran[-1][1]) if ran else None, "ok": bool(ok) and not failed, "failed": failed[-1] if failed else None,
            "skipped": skipped, "mentions_day7_tests": DAY7_TEST_LINE.search(text) is not None}


def arm_run_name(arm):
    return RUN_PREFIX + arm


def meta_of(entry):
    return entry["meta"]


def sessions_of(entry):
    return entry["meta"].get("sessions") or []


def counts_of(entry):
    return entry["meta"].get("counts") or {}


def error_codes_of(entry):
    return dict(((entry["meta"].get("agent") or {}).get("summary") or {}).get("error_code_counts") or {})


def tool_calls_of(entry):
    return ((entry["meta"].get("agent") or {}).get("summary") or {}).get("tool_calls")


def path_counts_of(entry):
    return dict(((entry["meta"].get("agent") or {}).get("summary") or {}).get("path_counts") or {})


# ------------------------------------------------------------------------------------------------ collecting facts
def audit_files(args, root):
    """(key, description, relative path) of every audit report the lock needs."""
    day6, day7 = args.audit_root_day6, args.audit_root_day7
    out = []
    for arm in ARMS:
        out.append(("day6_replay_" + arm, "Day 6 replay audit, arm " + arm, os.path.join(day6, "audit_replay_" + arm, "audit_replay_" + arm + ".json")))
    out.append(("day6_replay_A_vs_day5", "Day 6 replay audit, arm A against the Day 5 run", os.path.join(day6, "audit_replay_A_vs_day5", "audit_replay_A.json")))
    out.append(("day6_artifacts_day5", "Day 6 artifacts audit of the Day 5 run", os.path.join(day6, "audit_artifacts_day5", "audit_artifacts.json")))
    for arm in ARMS:
        out.append(("day7_replay_vs_run_" + arm, "Day 7 replay audit of the committed code against the real arm " + arm + " run", os.path.join(day7, "audit_replay_vs_run_" + arm, "audit_replay_" + arm + ".json")))
        out.append(("day7_artifacts_" + arm, "Day 7 artifacts audit of the real arm " + arm + " run", os.path.join(day7, "audit_artifacts_" + arm, "audit_artifacts.json")))
    return out


def load_run_folder(root, run_rel):
    return {k: v for k, v in rep.folder_digest(os.path.join(root, run_rel)).items() if k in RUN_FILES}


def collect(args, week1_snapshot=None):
    root = os.path.abspath(args.root)
    facts = {"generated_utc": utc_now(), "root": root, "args": {k: v for k, v in vars(args).items() if k not in ("action",)}}
    entries = {}
    for arm in ARMS:
        run_rel = os.path.join(args.runs_dir, arm_run_name(arm))
        eval_rel = os.path.join(args.eval_root, EVAL_PREFIX + arm)
        e = at.load_entry(arm, os.path.join(root, run_rel), os.path.join(root, eval_rel))
        if "meta" not in e:
            raise ReportError("arm " + arm + ": " + "; ".join(e["problems"]))
        e["run_rel"], e["eval_rel"] = rel(root, os.path.join(root, run_rel)), rel(root, os.path.join(root, eval_rel))
        entries[arm] = e
    facts["arms"] = entries
    for key, label, run_rel, eval_rel in (("day5", "Day 5 (historical)", args.day5_run, args.day5_eval),
                                          ("baseline", "baseline_v3", os.path.join(args.baseline_runs_dir, w2.V3_RUN), os.path.join(args.baseline_eval_root, w2.V3_RUN))):
        e = at.load_entry(label, os.path.join(root, run_rel), os.path.join(root, eval_rel))
        if "meta" not in e:
            raise ReportError(label + ": " + "; ".join(e["problems"]))
        e["run_rel"], e["eval_rel"] = rel(root, os.path.join(root, run_rel)), rel(root, os.path.join(root, eval_rel))
        facts[key] = e
    runs = dict(entries)
    runs["day5"] = facts["day5"]
    facts["run_digest"] = {k: load_run_folder(root, e["run_rel"]) for k, e in runs.items()}
    facts["eval_sha256"] = {k: sha_file(os.path.join(root, e["eval_rel"], "evaluation.json")) for k, e in list(runs.items()) + [("baseline", facts["baseline"])]}
    facts["transport"] = {}
    for k, e in runs.items():
        raw = os.path.join(root, e["run_rel"], "raw_responses.jsonl")
        facts["transport"][k] = audit.transport_summary(store.read_jsonl(raw)) if os.path.exists(raw) else None
    table_json = os.path.join(root, args.table_dir, "ablation_table.json")
    table_md = os.path.join(root, args.table_dir, "ablation_table.md")
    if not os.path.exists(table_json) or not os.path.exists(table_md):
        raise ReportError("no ablation table in " + args.table_dir + " (ablation_table.json and ablation_table.md)")
    facts["table"] = read_json(table_json)
    with open(table_md, "r", encoding="utf-8") as f:
        facts["table_md"] = f.read()
    facts["table_paths"] = {"json": rel(root, table_json), "md": rel(root, table_md)}
    facts["table_sha256"] = {"json": sha_file(table_json), "md": sha_file(table_md)}
    facts["audits"] = []
    for key, description, relpath in audit_files(args, root):
        full = os.path.join(root, relpath)
        row = {"key": key, "description": description, "path": relpath.replace(os.sep, "/"), "exists": os.path.exists(full)}
        if row["exists"]:
            row["sha256"] = sha_file(full)
            row["data"] = read_json(full)
        facts["audits"].append(row)
    suite_path = os.path.join(root, args.suite_log)
    facts["suite"] = None
    if os.path.exists(suite_path):
        facts["suite"] = dict(parse_suite_log(suite_path), path=rel(root, suite_path), sha256=sha_file(suite_path))
    lock_path = os.path.join(root, w2.LOCK_RELATIVE)
    if not os.path.exists(lock_path):
        raise ReportError("no Week 2 baseline lock at " + lock_path)
    facts["week2_lock"] = read_json(lock_path)
    facts["week2_lock_sha256"] = sha_file(lock_path)
    report2 = os.path.join(root, w2.REPORT_NAME)
    facts["week2_report_sha256"] = norm_sha_file(report2) if os.path.exists(report2) else None
    frozen = args.frozen_log
    facts["frozen_log"] = {"lines": w2.count_lines(frozen), "sha256_normalized": w2.normalized_sha256(frozen) if os.path.exists(frozen) else None}
    facts["unlock_set"] = bool(os.environ.get(config.FROZEN_UNLOCK_ENV))
    facts["week1_now"] = (week1_snapshot or runner.week1_snapshot)()
    facts["week2_verify"] = w2.verify_lock(facts["week2_lock"], root, os.path.join(root, args.baseline_runs_dir), frozen, week1_snapshot)
    facts["sources"] = {name: norm_sha_file(os.path.join(root, name)) for name in source_files(root)}
    facts["git"] = {"commit": git_text(root, "rev-parse", "HEAD"), "branch": git_text(root, "branch", "--show-current"),
                    "modified_tracked": [l[3:] for l in (git_text(root, "status", "--porcelain") or "").splitlines() if l and not l.startswith("??")],
                    "untracked_entries": len([l for l in (git_text(root, "status", "--porcelain") or "").splitlines() if l.startswith("??")])}
    facts["tracked"] = {}
    wanted = [e["run_rel"] + "/run_meta.json" for e in runs.values()] + [e["eval_rel"] + "/evaluation.json" for e in list(runs.values()) + [facts["baseline"]]]
    wanted += list(facts["table_paths"].values()) + [a["path"] for a in facts["audits"] if a["exists"]] + [w2.LOCK_RELATIVE.replace(os.sep, "/"), w2.REPORT_NAME]
    if facts["suite"]:
        wanted.append(facts["suite"]["path"])
    for p in wanted:
        facts["tracked"][p] = tracked_state(root, p)
    return facts


# ------------------------------------------------------------------------------------------------ the lock checks
def table_cells_match(facts):
    """The committed ablation table must carry exactly the numbers the evaluations give now."""
    bad = []
    table = facts["table"].get("table") or {}
    for view in at.VIEWS:
        for row in (table.get("views") or {}).get(view, []):
            e = facts["arms"].get(row.get("label"))
            if e is None:
                bad.append(view + ":" + str(row.get("label")))
                continue
            for key, cell in row.get("cells", {}).items():
                if jsonable(cell) != jsonable(e["metrics"].get(key)):
                    bad.append(view + ":" + str(row.get("label")) + ":" + key)
    for row in table.get("other") or []:
        e = facts["arms"].get(row.get("label"))
        if e is None:
            bad.append("other:" + str(row.get("label")))
            continue
        for key, cell in row.get("cells", {}).items():
            if jsonable(cell) != jsonable(e["metrics"].get(key)):
                bad.append("other:" + str(row.get("label")) + ":" + key)
    return bad


def run_checks(facts):
    """Every check is (name, passed, detail). The report and the lock record are written only if all pass."""
    checks = []

    def add(name, ok, detail=""):
        checks.append({"name": name, "passed": bool(ok), "detail": detail})

    arms = facts["arms"]
    day5, baseline = facts["day5"], facts["baseline"]
    runs = list(arms.values()) + [day5]
    # the system and its settings
    code_hash = verdict_prompt.prompt_sha256()
    add("the agent_v1 prompt in the code has the pinned hash", code_hash == EXPECTED_AGENT_PROMPT_SHA256, code_hash[:16])
    add("the graph version is v0.1", S.GRAPH_VERSION == "v0.1" and all(r["meta"].get("agent", {}).get("graph_version") == "v0.1" for r in runs))
    add("every arm run and the Day 5 run used prompt agent_v1 with the pinned hash",
        all(r["meta"].get("prompt_version") == AGENT_PROMPT_VERSION and r["meta"].get("prompt_sha256") == EXPECTED_AGENT_PROMPT_SHA256 for r in runs))
    models = {r["meta"].get("model") for r in runs}
    add("every run used one model, " + EXPECTED_MODEL, models == {EXPECTED_MODEL}, ", ".join(sorted(str(m) for m in models)))
    settings = {json.dumps({k: (r["meta"].get("settings") or {}).get(k) for k in SETTING_KEYS}, sort_keys=True) for r in runs}
    add("every arm run and the Day 5 run used identical generation, retry, timeout and rate settings", len(settings) == 1)
    add("every arm run and the Day 5 run used the same dev inputs and the same 300-alert list",
        len({json.dumps(r["meta"].get("inputs"), sort_keys=True) for r in runs}) == 1 and len({json.dumps(r["meta"].get("selected_alert_ids")) for r in runs}) == 1
        and all(r["meta"].get("n_selected") == N_ALERTS for r in runs))
    add("every arm run is a complete real dev run (not a fake-model run)", all(r["meta"].get("status") == "complete" and r["meta"].get("set") == "dev" and not r["meta"].get("fake_model") for r in runs))
    shape = []
    for arm, e in arms.items():
        record = (e["meta"].get("agent") or {}).get("ablation") or {}
        want = list(ablation.arm_disabled(arm))
        specialists = (e["meta"].get("agent") or {}).get("specialists")
        if record.get("arm") != arm or list(record.get("disabled") or []) != want or specialists != list(ablation.effective_specialists(want)):
            shape.append(arm)
    add("each arm run recorded the ablation arm, switched-off specialists and effective specialists that ablation_config defines for it", not shape, ("differs: " + ", ".join(shape)) if shape else "5 of 5")
    bad_counts = [a for a, e in arms.items() if not (sum(counts_of(e).get(k, 0) for k in ("ok", "parse_failed", "model_error")) == N_ALERTS and counts_of(e).get("model_error", 0) == 0)]
    add("every arm run ended with " + str(N_ALERTS) + " final results and no model_error alert", not bad_counts, ("differs: " + ", ".join(bad_counts)) if bad_counts else "5 of 5")
    # evaluations
    add("every arm evaluation is complete, for its own run, with the run's prompt hash and true integrity checks",
        all(e["complete"] for e in arms.values()) and day5["complete"], "; ".join(a + ": " + "; ".join(e["problems"] + e.get("incomplete_reasons", [])) for a, e in arms.items() if not e["complete"]))
    add("the Day 5 and baseline_v3 evaluations are complete and for their own runs", day5["complete"] and baseline["complete"])
    add("no evaluation was partial", not any(e["eval"].get("allow_partial") for e in runs + [baseline]))
    mismatch = []
    for key, e in list(arms.items()) + [("day5", day5)]:
        recorded = w2.norm_files(e["eval"].get("run_file_sha256"))
        if not recorded or recorded != w2.norm_files(facts["run_digest"][key]):
            mismatch.append(key)
    add("every run folder matches the run_file_sha256 its own evaluation recorded", not mismatch, ("differs: " + ", ".join(mismatch)) if mismatch else "6 of 6 match")
    logs = {e["eval"].get("frozen_access_log_lines") for e in runs + [baseline]}
    logs.discard(None)
    add("the frozen access log has the same number of lines now as in every evaluation (frozen set not opened)", len(logs) == 1 and facts["frozen_log"]["lines"] in logs,
        "lines now " + str(facts["frozen_log"]["lines"]) + ", in evaluations " + str(sorted(logs)))
    add("no run recorded a changed frozen access log or Week 1 file", all(r["meta"].get("frozen_access_log_unchanged") is True and r["meta"].get("week1_files_unchanged") is True for r in runs))
    add("the frozen unlock variable is not set in this shell", not facts["unlock_set"])
    week1_now = {w2.norm_key(k): v for k, v in facts["week1_now"].items()}
    compared, differing = 0, []
    for key, e in list(arms.items()) + [("day5", day5)]:
        recorded = {w2.norm_key(k): v for k, v in (e["eval"].get("protected_file_sha256") or {}).items()}
        for name, digest in week1_now.items():
            if name in recorded:
                compared += 1
                if recorded[name] != digest:
                    differing.append(key + ":" + name)
    add("the Week 1 files hash the same now as in every evaluation", not differing and compared > 0, ("changed: " + ", ".join(differing)) if differing else str(compared) + " hash comparisons")
    # the ablation table
    table = facts["table"]
    add("the ablation table has reference A, all five arms in A to E order, and no excluded run", table.get("reference") == REFERENCE and table.get("used") == list(ARMS) and not table.get("excluded"),
        "used " + str(table.get("used")) + ", excluded " + str(len(table.get("excluded") or [])))
    wanted_inputs = {a: (arm_run_name(a), EVAL_PREFIX + a) for a in ARMS}
    got_inputs = {i.get("label"): (os.path.basename(os.path.normpath(str(i.get("run_dir")).replace("\\", "/"))), os.path.basename(os.path.normpath(str(i.get("eval_dir")).replace("\\", "/")))) for i in table.get("inputs") or []}
    add("the ablation table was built from exactly the five arm runs and their evaluation folders", got_inputs == wanted_inputs)
    bad_cells = table_cells_match(facts)
    add("every number in the committed ablation table equals what the evaluations give now", not bad_cells, ("differs: " + ", ".join(bad_cells[:6])) if bad_cells else "all cells match")
    # audits
    missing = [a["path"] for a in facts["audits"] if not a["exists"]]
    add("every required audit report exists", not missing, ("missing: " + ", ".join(missing)) if missing else str(len(facts["audits"])) + " of " + str(len(facts["audits"])))
    failed = [a["path"] for a in facts["audits"] if a["exists"] and a["data"].get("all_checks_passed") is not True]
    add("every audit report says all its checks passed", not missing and not failed, ("failed: " + ", ".join(failed)) if failed else "")
    replay_bad = []
    for arm in ARMS:
        for key, run_name in (("day6_replay_" + arm, None), ("day7_replay_vs_run_" + arm, arm_run_name(arm))):
            a = next((x for x in facts["audits"] if x["key"] == key), None)
            if not a or not a["exists"]:
                continue
            d = a["data"]
            if d.get("mode") != "replay" or d.get("arm") != arm or d.get("alerts") != N_ALERTS:
                replay_bad.append(key)
            if run_name:
                c = d.get("compare") or {}
                names_run = os.path.basename(os.path.normpath(str(c.get("run_dir", "")).replace("\\", "/")))
                mism = {f: n for f, n in (c.get("mismatch_counts") or {}).items() if n}
                if names_run != run_name or c.get("compared") != N_ALERTS or c.get("identical_all_fields") != c.get("compared") or mism:
                    replay_bad.append(key)
    add("the committed code reproduces every arm run: " + str(N_ALERTS) + " alerts replayed per arm; prompt hash, trace, routing, tool-call counts and upstream statuses identical to the real run", not replay_bad,
        ("differs: " + ", ".join(replay_bad)) if replay_bad else "5 of 5")
    a5 = next((x for x in facts["audits"] if x["key"] == "day6_replay_A_vs_day5"), None)
    c5 = ((a5 or {}).get("data") or {}).get("compare") or {}
    add("arm A's replay matches the Day 5 run on every compared field", bool(a5 and a5["exists"] and c5.get("compared") and c5.get("identical_all_fields") == c5.get("compared")),
        "compared " + str(c5.get("compared")) + ", identical " + str(c5.get("identical_all_fields")))
    art_bad = []
    for arm in ARMS:
        a = next((x for x in facts["audits"] if x["key"] == "day7_artifacts_" + arm), None)
        if a and a["exists"] and (a["data"].get("mode") != "artifacts" or a["data"].get("run_name") != arm_run_name(arm)):
            art_bad.append(arm)
    add("each Day 7 artifacts audit is for its own arm run", not art_bad, ("differs: " + ", ".join(art_bad)) if art_bad else "5 of 5")
    # the Week 2 baseline
    failed2 = [r[0] for r in facts["week2_verify"] if not r[1]]
    add("the Week 2 baseline verification passes (" + str(len(facts["week2_verify"])) + " checks: locked prompt, five locked source files, reference runs, frozen log, Week 1 files)", not failed2,
        ("failed: " + ", ".join(failed2)) if failed2 else str(len(facts["week2_verify"])) + " of " + str(len(facts["week2_verify"])))
    locked = facts["week2_lock"].get("locked_source_files_sha256", {})
    now5 = {n: facts["sources"].get(n) for n in LOCKED_WEEK2_SOURCES}
    add("the five locked Week 2 source files hash the same as in the Week 2 lock record", now5 == locked and len(locked) == 5)
    recorded_eval = (facts["week2_lock"].get("evaluation_sha256") or {}).get(w2.V3_RUN)
    add("the baseline_v3 evaluation used in the comparison is the one the Week 2 lock recorded", recorded_eval is not None and recorded_eval == facts["eval_sha256"]["baseline"])
    # tests evidence
    suite = facts["suite"]
    add("a full-suite log exists, shows OK, " + str(MIN_TESTS_IN_SUITE_LOG) + " or more tests, and lists the Day 7 tests",
        bool(suite and suite["ok"] and (suite["ran"] or 0) >= MIN_TESTS_IN_SUITE_LOG and suite["mentions_day7_tests"]),
        "no log" if not suite else "ran " + str(suite["ran"]) + ", " + ("OK" if suite["ok"] else "not OK") + ", Day 7 tests listed: " + str(suite["mentions_day7_tests"]))
    return checks


# ------------------------------------------------------------------------------------------------ rendering helpers
def cell(entry, key):
    label, kind, _ = at.SPEC_BY_KEY[key]
    return at.fmt(entry["metrics"].get(key), kind)


def delta(entry, ref, key):
    label, kind, _ = at.SPEC_BY_KEY[key]
    return at.fmt_diff(at.diff_value(entry["metrics"].get(key), ref["metrics"].get(key), kind), kind)


def rnd(value):
    return "n/a" if not isinstance(value, (int, float)) else "{:.2f}".format(value)


def md_table(header, rows):
    return agg.md_table(header, rows)


def label_of(key):
    return at.SPEC_BY_KEY[key][0]


def nested(md, extra=2):
    """Push the headings of an embedded markdown file down so they nest under the section that holds it."""
    return "\n".join(("#" * extra + line) if line.startswith("#") else line for line in md.splitlines())


def transport_rows(facts):
    rows = []
    for key in list(ARMS) + ["day5"]:
        e = facts["arms"].get(key) or facts["day5"]
        t = facts["transport"].get(key) or {}
        sessions = sessions_of(e)
        ended = [str(s.get("ended_because")) for s in sessions if isinstance(s, dict)]
        rows.append([("arm " + key) if key in ARMS else "Day 5 (historical)", t.get("lines", "n/a"), (t.get("outcomes") or {}).get("reply", 0), (t.get("outcomes") or {}).get("transport_failed", 0),
                     t.get("failed_transport_attempts", "n/a"), json.dumps(t.get("failed_attempts_by_http_status") or {}), json.dumps(t.get("failed_attempts_by_exception_class") or {}),
                     t.get("timeout_like_failed_attempts", "n/a"), len(sessions), "; ".join(ended) if ended else "n/a",
                     counts_of(e).get("model_error", "n/a")])
    return rows


def totals_by_status(facts):
    total = {}
    for key in list(ARMS) + ["day5"]:
        for status, n in ((facts["transport"].get(key) or {}).get("failed_attempts_by_http_status") or {}).items():
            total[status] = total.get(status, 0) + n
    return dict(sorted(total.items()))


def render_report(facts, checks, timeout_decision="known-limitation"):
    arms, day5, base = facts["arms"], facts["day5"], facts["baseline"]
    ref = arms[REFERENCE]
    L = []
    add = L.append
    add("# Week 3 report: agent system v1 (LangGraph supervisor, three specialists, verdict node), locked on the dev set")
    add("")
    add("Generated " + facts["generated_utc"] + " by `python src/week3_report.py build`. Every number below was read from the files listed in section 12; nothing was typed in by hand.")
    add("Git at lock time: branch `" + str(facts["git"]["branch"]) + "`, commit `" + str(facts["git"]["commit"]) + "` (the commit before the Day 7 commit; the `week3-agents` tag goes on the Day 7 commit). All paths are relative to the repository root.")
    add("")
    add("**Status:** all " + str(len(checks)) + " lock checks passed when this report was built (section 13). The report is part of the lock: `python src/week3_report.py verify` fails if this file or anything it cites changes.")
    add("")
    add("**What is, and is not, claimed.** Everything here is measured on the 300-alert DEV set, which was used while the agent was being built. No number in this report is an independent evaluation, "
        "the frozen evaluation set was not opened (section 11), every arm was run once, and nothing here says the agent is universally better than the baseline. The Day 6 ablation is descriptive.")
    add("")
    add("## 1. What is locked")
    add("")
    add("- **Agent system v1:** graph `" + S.GRAPH_VERSION + "` (supervisor, traffic analyst, C2 beaconing analyst, enrichment agent, verdict node) with verdict prompt `" + AGENT_PROMPT_VERSION + "` (sha256 `" + verdict_prompt.prompt_sha256() + "`), model `"
        + str(ref["meta"].get("model")) + "`.")
    add("- **Reference run:** Day 6 arm A (`" + ref["run_rel"] + "`), the full graph run on the final code. The Day 5 run is kept as history (section 5), not as the reference.")
    add("- **Unchanged and checked:** the Week 2 baseline lock (`" + w2.LOCK_RELATIVE.replace(os.sep, "/") + "`), including the five hash-locked Week 2 source files, still verifies (section 11).")
    add("")
    add("## 2. Architecture and data flow")
    add("")
    add("One alert goes through a deterministic supervisor loop; no LLM decides the routing. Only the verdict node calls a model.")
    add("")
    add("```")
    add("alert -> supervisor -> traffic_analyst -> supervisor -> [c2_beacon_analyst] -> supervisor -> enrichment_agent -> supervisor -> verdict_node -> supervisor -> end")
    add("```")
    add("")
    add("- **State:** a typed dictionary (`alert`, `evidence`, one findings slot per agent, `routing` with a reason for every decision, `errors`, `trace`, `verdict`, `status`). Each agent returns an update and always goes back to the supervisor.")
    add("- **Supervisor** (`src/agents/supervisor.py`): re-derives its decision from the state at every visit. The traffic analyst runs first. The beaconing analyst runs only on repeat contact, i.e. at least "
        + str(supervisor.REPEAT_CONTACT_MIN_FLOWS) + " flows from the alert source to the alert destination in the traffic analyst's own evidence (a routing gate that saves work, not a detection threshold). Then the enrichment agent, then the verdict node. "
        "Every agent runs at most once. A loop guard ends the graph after " + str(S.MAX_SUPERVISOR_VISITS) + " supervisor visits. If the graph ends before the verdict node ran, no verdict is invented.")
    add("- **Traffic analyst:** queries the flow store (local, offline) for the source and destination and summarises who the source talks to.")
    add("- **C2 beaconing analyst:** looks for regular intervals to one destination and port and may flag a `beacon_candidate`.")
    add("- **Enrichment agent:** adds IP-range, port and service context and, only when a `beacon_candidate` was flagged, a few MITRE ATT&CK reference entries (reference material, not a determination). The optional reputation lookup is never called in graph v0.1; its absence is recorded in the evidence as `not_consulted`.")
    add("- **Verdict node:** one model call per alert with the collected evidence and the `" + AGENT_PROMPT_VERSION + "` prompt; the reply must be the same five-field verdict as the Week 2 baseline (`is_malicious`, `attack_type`, `mitre_technique`, `severity`, `evidence`), "
        "validated by the locked Week 2 parser, with up to " + str((ref["meta"].get("settings") or {}).get("parse_retries")) + " parse retries. A reply that still fails validation is a final parse failure and is scored, not dropped.")
    add("- **Paths taken in arm A:** " + "; ".join("`" + p + "` on " + str(n) + " alerts" for p, n in sorted(path_counts_of(ref).items(), key=lambda kv: -kv[1])) + ".")
    add("")
    add("## 3. Configuration (from arm A's `run_meta.json`)")
    add("")
    meta = ref["meta"]
    rows = [["model", meta.get("model")], ["verdict prompt", AGENT_PROMPT_VERSION + " `" + str(meta.get("prompt_sha256")) + "`"], ["graph version", (meta.get("agent") or {}).get("graph_version")],
            ["specialists", ", ".join((meta.get("agent") or {}).get("specialists") or [])]]
    for k in SETTING_KEYS:
        rows.append([k, (meta.get("settings") or {}).get(k)])
    rows += [["alerts", meta.get("n_selected")], ["dev alerts sha256", "`" + str((meta.get("inputs") or {}).get("dev_alerts_sha256")) + "`"],
             ["dev flow store sha256", "`" + str((meta.get("inputs") or {}).get("flow_store_dev_sha256")) + "`"], ["python", meta.get("python")], ["packages", json.dumps(meta.get("packages"))],
             ["git commit recorded by the run", json.dumps(meta.get("git")) + " (the Day 6 code was committed after the runs; section 9, limitation 5)"]]
    add(md_table(["setting", "value"], rows))
    add("")
    add("## 4. Primary result: agent arm A against the locked baseline (dev set, 300 alerts)")
    add("")
    add("The primary view is `failures_wrong`: all 300 alerts count, and an alert with no valid verdict counts as wrong. Its denominator is the same for every run, so runs are comparable. "
        "`valid_only` drops alerts without a verdict, so its alert set differs between runs; read it with care. `failures_escalated` treats a missing verdict as 'escalated'.")
    add("")
    add("Baseline = `" + w2.V3_RUN + "`, the locked Week 2 baseline_v3 run (one run; its three-run spread is in section 6). Agent = arm A, one run. Day 5 = the earlier agent run, history only.")
    add("")
    keys = []
    for view in at.VIEWS:
        keys += [view + "." + n for n in ("precision", "recall", "f1", "specificity", "fp_reduction", "attacks_missed")]
    keys += ["attack_type_all", "attack_type_valid", "mitre_all", "mitre_valid", "coverage", "parse_failures", "first_try_malformed", "model_errors", "model_calls", "total_tokens", "tokens_per_alert", "tool_calls", "graph_seconds", "latency_alert_mean"]
    rows = []
    for key in keys:
        view = key.split(".")[0] if "." in key else ""
        rows.append([("`" + view + "` " if view else "") + label_of(key), cell(base, key), cell(ref, key), delta(ref, base, key), cell(day5, key)])
    add(md_table(["metric", "baseline_v3 (locked)", "agent arm A", "A minus baseline", "agent Day 5 (historical)"], rows))
    add("")
    add("Cells show the value and, for ratios, numerator/denominator. The baseline has no tool calls (it uses none), so that row is n/a. The Wilson 95% intervals for every ratio are in each run's `evaluation.json`.")
    add("")
    add("**Numbers that may be quoted (dev set, single run, with the denominators):** with failed verdicts counted as wrong, arm A has precision " + cell(ref, "failures_wrong.precision") + ", recall " + cell(ref, "failures_wrong.recall")
        + ", specificity " + cell(ref, "failures_wrong.specificity") + "; attack-type accuracy " + cell(ref, "attack_type_all") + " and MITRE accepted " + cell(ref, "mitre_all")
        + " over all attacks; " + cell(ref, "coverage") + " of alerts got a valid verdict (" + cell(ref, "parse_failures") + " final parse failures). The same baseline numbers are in the third column. Quote them as dev-set results, never as an independent test.")
    add("")
    add("## 5. Day 5 (historical) against Day 6 arm A (final code)")
    add("")
    add("The Day 5 run (`" + day5["run_rel"] + "`, recorded git `" + json.dumps(day5["meta"].get("git")) + "`) was collected on the Day 5 code, before the Day 6 retry and audit changes, and was not rerun. Arm A is the same full graph on the final code.")
    add("")
    a5 = next((x for x in facts["audits"] if x["key"] == "day6_replay_A_vs_day5"), None)
    c5 = ((a5 or {}).get("data") or {}).get("compare") or {}
    add("A replay of arm A against the Day 5 run (`" + (a5["path"] if a5 else "n/a") + "`, sha256 `" + (a5["sha256"] if a5 and a5.get("sha256") else "n/a") + "`) compared " + str(c5.get("compared"))
        + " alerts and found " + str(c5.get("identical_all_fields")) + " identical on the verdict prompt hash, trace, routing, tool-call count and upstream statuses. The two runs therefore built the same prompts; any difference between their results comes from the model's replies, "
        "which are not exactly repeatable even with temperature 0 and a fixed seed.")
    add("")
    rows = [["valid verdicts / parse failures / model errors", "/".join(str(counts_of(day5).get(k)) for k in ("ok", "parse_failed", "model_error")), "/".join(str(counts_of(ref).get(k)) for k in ("ok", "parse_failed", "model_error"))],
            ["model calls", cell(day5, "model_calls"), cell(ref, "model_calls")], ["total tokens", cell(day5, "total_tokens"), cell(ref, "total_tokens")],
            ["tool calls", cell(day5, "tool_calls"), cell(ref, "tool_calls")], ["graph seconds", cell(day5, "graph_seconds"), cell(ref, "graph_seconds")]]
    for key in ("failures_wrong.precision", "failures_wrong.recall", "failures_wrong.f1", "failures_wrong.specificity", "attack_type_all", "mitre_all"):
        rows.append(["`failures_wrong` " + label_of(key) if key.startswith("failures_wrong") else label_of(key), cell(day5, key), cell(ref, key)])
    add(md_table(["", "Day 5 (historical)", "Day 6 arm A (final code)"], rows))
    add("")
    add("## 6. Ablation, arms A to E (descriptive; one run per arm)")
    add("")
    add("The arms are defined in `src/ablation_config.py`. Day 7 locks the full graph (arm A); this table describes what switching parts off did and does not change that choice. Switching a specialist off is shown to the model as 'disabled in this configuration'.")
    add("")
    add(md_table(["arm", "what runs", "specialists that ran"], [[a, ablation.ARMS[a]["label"], ", ".join((arms[a]["meta"].get("agent") or {}).get("specialists") or []) or "none"] for a in ARMS]))
    add("")
    for view in at.VIEWS:
        add("### `" + view + "`" + (" (primary)" if view == "failures_wrong" else ""))
        add("")
        add(at.VIEW_NOTES[view])
        add("")
        cols = ["precision", "recall", "f1", "specificity", "fp_reduction", "attacks_missed"]
        rows = []
        for a in ARMS:
            row = ["arm " + a]
            for c in cols:
                key = view + "." + c
                row.append(cell(arms[a], key) + ("" if a == REFERENCE else " (" + delta(arms[a], ref, key) + ")"))
            rows.append(row)
        add(md_table(["run"] + [label_of(view + "." + c) for c in cols], rows))
        add("")
    add("### Other measures")
    add("")
    other = ["attack_type_all", "attack_type_valid", "mitre_all", "mitre_valid", "coverage", "parse_failures", "first_try_malformed", "model_calls", "total_tokens", "tokens_per_alert", "tool_calls", "graph_seconds", "latency_alert_mean"]
    rows = []
    for a in ARMS:
        rows.append(["arm " + a] + [cell(arms[a], k) + ("" if a == REFERENCE else " (" + delta(arms[a], ref, k) + ")") for k in other])
    add(md_table(["run"] + [label_of(k) for k in other], rows))
    add("")
    add("Differences in brackets are arm minus arm A (percentage points for fractions, plain differences otherwise). They are not significance claims.")
    add("")
    add("### The committed ablation table, verbatim")
    add("")
    add("`" + facts["table_paths"]["md"] + "` (sha256 `" + facts["table_sha256"]["md"] + "`; its numbers equal the evaluations, check in section 13) holds the paired per-alert comparisons, the common-valid-alert table, the baseline three-run spread and its own limitations. It is reproduced here unchanged:")
    add("")
    add(nested(facts["table_md"].rstrip()))
    add("")
    add("## 7. Parse failures are uneven across arms")
    add("")
    rows = []
    for a in ARMS:
        e = arms[a]
        rows.append(["arm " + a, counts_of(e).get("ok"), counts_of(e).get("parse_failed"), json.dumps(error_codes_of(e)), cell(e, "first_try_malformed"), cell(e, "total_tokens"), cell(e, "tokens_per_alert")])
    add(md_table(["run", "valid verdicts", "final parse failures", "by error code", "first-try malformed (alerts)", "total tokens", "tokens per alert"], rows))
    add("")
    common = (facts["table"].get("common_valid") or {}).get("alerts")
    zero = [a for a in ARMS if counts_of(arms[a]).get("parse_failed") == 0]
    worst = max(ARMS, key=lambda a: counts_of(arms[a]).get("parse_failed") or 0)
    add("Final parse failures per arm are " + ", ".join(a + " " + str(counts_of(arms[a]).get("parse_failed")) for a in ARMS) + ". They are real results: they count as wrong in `failures_wrong` and are absent from `valid_only`, "
        "so `valid_only` compares different alert sets across arms. The table's common-valid view uses the " + str(common) + " alerts every arm answered. "
        "Arm " + worst + " has the most final parse failures and " + (", ".join("arm " + a for a in zero) if zero else "no arm") + " had none. Tokens per alert, arm " + worst + " against the arms without failures: "
        + cell(arms[worst], "tokens_per_alert") + " against " + (", ".join(a + " " + cell(arms[a], "tokens_per_alert") for a in zero) if zero else "n/a") + ". "
        "With one run per arm, and a baseline that differed from itself across identical-prompt runs (baseline spread in the table above), a difference of a few parse failures is not evidence that one arm is more reliable, "
        "and these data cannot say why the failures are uneven (prompt length, the amount of evidence, or chance). This report draws no causal conclusion.")
    add("")
    ref_settings = arms[REFERENCE]["meta"].get("settings")
    add("## 8. Reliability: calls, tokens, tool calls, latency and every observed transport error")
    add("")
    add("Transport errors are read from each run's `raw_responses.jsonl` (the harness records every failed attempt). Nothing is excluded.")
    add("")
    add(md_table(["run", "raw rows", "reply rows", "transport_failed rows", "failed attempts", "by HTTP status", "by exception", "timeout-like failed attempts", "sessions", "session ended because", "final model-error alerts"], transport_rows(facts)))
    add("")
    add("Observed failed attempts over all six runs, by HTTP status: " + json.dumps(totals_by_status(facts)) + " (429 = rate limit or quota, 503 = service unavailable). The client makes up to 5 attempts per call "
        "(first try plus 4 transport retries, backoff 4, 8, 16 and 32 s). A `transport_failed` row is a call whose 5 attempts all failed; the final results of the arm runs contain "
        + ", ".join(a + " " + str(counts_of(arms[a]).get("model_error")) for a in ARMS) + " model-error alerts (arms A to E), so no alert is missing from the scored results. "
        "The sessions column is read from each run's `run_meta.json`; a run with more than one session was resumed after it stopped. "
        "Failed attempts are counted in the totals above but not in the model calls.")
    add("")
    rows = []
    for a in ARMS:
        e = arms[a]
        t = facts["transport"].get(a) or {}
        rows.append(["arm " + a, cell(e, "model_calls"), (t.get("estimated_requests_made") if t else "n/a"), cell(e, "total_tokens"), cell(e, "tool_calls"), cell(e, "graph_seconds"), cell(e, "latency_alert_mean"),
                     rnd((t.get("latency_seconds") or {}).get("p95")), rnd((t.get("latency_seconds") or {}).get("max"))])
    add(md_table(["run", "model calls (replies)", "estimated requests (replies + failed attempts)", "total tokens", "tool calls", "graph seconds", "model latency per alert, mean (s)", "per-call latency p95 (s)", "per-call latency max (s)"], rows))
    add("")
    add("`graph seconds` include the requests-per-minute wait (" + str((ref_settings or {}).get("requests_per_minute")) + " per minute), so they are not model latency. Tool calls are local and offline; arm E makes none by design.")
    add("")
    add("## 9. Limitations (known, not fixed in v1)")
    add("")
    for i, text in enumerate(at.LIMITATIONS, 1):
        add(str(i) + ". " + text + " (carried over from the ablation table)")
    n = len(at.LIMITATIONS)
    add(str(n + 1) + ". **Arms B and D change more than one thing.** In graph v0.1 the enrichment agent looks up ATT&CK reference entries only when the beaconing analyst flagged a `beacon_candidate` (`src/agents/enrichment_agent.py`, `wants_mitre`). "
        "Switching off the beaconing analyst (B) therefore also removes those reference entries from the verdict prompt, and arm D (no traffic analyst, so no beaconing either) loses them too. "
        "The beaconing analyst ran on " + str(sum(v for p, v in path_counts_of(ref).items() if "c2_beacon_analyst" in p)) + " of 300 alerts in arm A. A difference for B or D cannot be attributed to the beaconing analyst alone.")
    add(str(n + 2) + ". **One run per arm.** No arm was repeated, so run-to-run variation of the agent is unmeasured. The baseline's three identical-prompt runs are the only measured yardstick and they differ from one another (baseline spread in the table above).")
    add(str(n + 3) + ". **Parse failures are uneven** across arms (section 7) and the valid-only view is not like-for-like.")
    add(str(n + 4) + ". **Dev set only.** Every number here is from the dev set that guided development. The frozen set has not been used.")
    add(str(n + 5) + ". **The Day 6 runs recorded git `" + json.dumps(ref["meta"].get("git")) + "`:** they ran on the Day 5 commit plus Day 6 changes that were committed afterwards. Run-time code identity is not recorded in the runs. "
        "It is established after the fact by the Day 7 replay audits: for every arm, the committed code, replayed on all 300 alerts, reproduces the real run's verdict prompt hash, trace, routing, tool-call counts and upstream statuses (section 13). "
        "That proves the committed code builds the same model inputs; it cannot prove byte-identical code at run time.")
    add(str(n + 6) + ". **The Day 5 run** is historical (section 5).")
    add(str(n + 7) + ". **Model service drift.** The same model name can behave differently on different days; the arms were run at different times (see the session records in each `run_meta.json`) and are not guaranteed to see the same service state.")
    add("")
    add("### Timeout handling: recorded decision")
    add("")
    add("**Decision: known limitation, recorded at build time with `--timeout-decision " + str(timeout_decision) + "`.** The Gemini client uses a 60 s request timeout and up to 5 attempts per call with 4, 8, 16 and 32 s backoff, so a failing call can take about 6 minutes. "
        "There is no per-alert time limit; a run stops after " + str(runner.MAX_CONSECUTIVE_MODEL_ERRORS) + " alerts in a row end in a model error. A timeout and a 5xx error both end as `model_unavailable` and differ only in the stored error text; the harness keeps the raw exception class and HTTP status of every failed attempt (section 8). "
        "In the six runs reported here, timeout-class failed attempts: " + str(sum((facts["transport"].get(k) or {}).get("timeout_like_failed_attempts", 0) for k in list(ARMS) + ["day5"])) + "; failed attempts by HTTP status: " + json.dumps(totals_by_status(facts)) + ". "
        "The Gemini client file is one of the five hash-locked Week 2 files, so no change to it is part of this lock. Proposed for Week 4, not implemented: a structured `error_kind` on failed calls, a per-alert time cap, and honouring a server-provided retry delay for HTTP 429.")
    add("")
    add("## 10. Reproducibility")
    add("")
    add("- The Week 2 baseline lock and every run folder, evaluation, the ablation table, the audit reports and the suite log are hashed in `" + LOCK_RELATIVE.replace(os.sep, "/") + "`.")
    add("- The runs call a live model; a rerun gives similar, not identical, replies. What is reproducible is everything downstream of the saved replies: the evaluation (`python src/evaluate.py ...`), the table (`python src/ablation_table.py ...`) and this report.")
    add("- The model inputs are reproducible without a model: the replay audits rebuild every arm's prompts on all 300 alerts and compare them with the real runs.")
    add("")
    add("## 11. Frozen-set and baseline protection")
    add("")
    w2results = facts["week2_verify"]
    add("`python src/week2_report.py verify` logic was re-run inside this build: " + str(sum(1 for r in w2results if r[1])) + " of " + str(len(w2results)) + " checks passed.")
    add("")
    add(md_table(["Week 2 check", "result"], [[r[0], "PASS" if r[1] else "FAIL"] for r in w2results]))
    add("")
    add("Frozen access log: " + str(facts["frozen_log"]["lines"]) + " lines, sha256 (line endings normalised) `" + str(facts["frozen_log"]["sha256_normalized"]) + "`; the same line count is recorded by every evaluation. "
        "The frozen unlock variable is not set. The Week 1 files hash the same as in every evaluation (section 13).")
    add("")
    add("## 12. Evidence: paths and SHA-256 hashes")
    add("")
    add("`git` is the file's state in the repository when this report was built: `tracked`, or `untracked` (a local file that the Day 7 evidence commit adds, or that is only hashed in the lock). Run folders are protected by the hashes in the lock whether or not they are tracked.")
    add("")
    rows = []
    for key in list(ARMS) + ["day5"]:
        e = arms.get(key) or day5
        rows.append([("arm " + key) if key in ARMS else "Day 5 (historical)", "`" + e["run_rel"] + "/`", "`" + facts["run_digest"][key].get("results.jsonl", "n/a")[:16] + "`", "`" + facts["run_digest"][key].get("run_meta.json", "n/a")[:16] + "`",
                     facts["tracked"].get(e["run_rel"] + "/run_meta.json", "unknown")])
    add(md_table(["run", "folder", "results.jsonl sha256 (first 16)", "run_meta.json sha256 (first 16)", "git (run_meta.json)"], rows))
    add("")
    rows = []
    for key, e in [(a, arms[a]) for a in ARMS] + [("day5", day5), ("baseline", base)]:
        path = e["eval_rel"] + "/evaluation.json"
        rows.append([("arm " + key) if key in ARMS else ("Day 5 (historical)" if key == "day5" else "baseline_v3"), "`" + path + "`", "`" + facts["eval_sha256"][key] + "`", facts["tracked"].get(path, "unknown")])
    for k in ("json", "md"):
        p = facts["table_paths"][k]
        rows.append(["ablation table (" + k + ")", "`" + p + "`", "`" + facts["table_sha256"][k] + "`", facts["tracked"].get(p, "unknown")])
    for a in facts["audits"]:
        rows.append([a["description"], "`" + a["path"] + "`", "`" + a.get("sha256", "missing") + "`", facts["tracked"].get(a["path"], "unknown")])
    if facts["suite"]:
        rows.append(["full-suite log", "`" + facts["suite"]["path"] + "`", "`" + facts["suite"]["sha256"] + "`", facts["tracked"].get(facts["suite"]["path"], "unknown")])
    rows.append(["Week 2 baseline lock", "`" + w2.LOCK_RELATIVE.replace(os.sep, "/") + "`", "`" + facts["week2_lock_sha256"] + "`", facts["tracked"].get(w2.LOCK_RELATIVE.replace(os.sep, "/"), "unknown")])
    add(md_table(["evidence", "path", "sha256", "git"], rows))
    add("")
    add("Source files hashed in the lock (line endings normalised): " + str(len(facts["sources"])) + " files, listed with their hashes in the lock record. The five locked Week 2 files: "
        + ", ".join("`" + n + "`" for n in LOCKED_WEEK2_SOURCES) + ".")
    add("")
    add("## 13. Acceptance criteria and checks")
    add("")
    add("The lock was written only because all of these passed in `build`:")
    add("")
    add(md_table(["#", "check", "result", "detail"], [[i, c["name"], "PASS" if c["passed"] else "FAIL", c["detail"]] for i, c in enumerate(checks, 1)]))
    add("")
    suite = facts["suite"]
    add("Full test suite (`" + (suite["path"] if suite else "n/a") + "`): " + (("ran " + str(suite["ran"]) + " tests in " + str(suite["seconds"]) + " s, " + ("OK" if suite["ok"] else "NOT OK") + ", skipped " + str(suite["skipped"])) if suite else "n/a")
        + ". The log was made before the lock record existed, so the real-lock tests in `tests/test_week3_day7.py` were skipped in it; they run once the lock exists.")
    add("")
    add("**Commands that reproduce the verification (read-only, no model call):**")
    add("")
    add("```")
    add("python -m unittest discover -s tests -t .")
    add("python src/week2_report.py verify")
    add("python src/week3_report.py verify")
    add("git status --short")
    add("```")
    add("")
    add("**Tag:** the annotated tag `week3-agents` is created on the Day 7 commit only after the commands above pass and the project owner approves.")
    return "\n".join(L) + "\n"


# ------------------------------------------------------------------------------------------------ the lock record
def lock_record(facts, checks, report_text, args):
    arms, day5, base = facts["arms"], facts["day5"], facts["baseline"]
    ref = arms[REFERENCE]
    runs = dict(arms)
    runs["day5"] = day5
    suite = facts["suite"]
    return {
        "schema": SCHEMA, "locked_utc": facts["generated_utc"],
        "purpose": "Week 3 agent system v1 lock record. The full graph (arm A) is the locked system; a change is a new version, never an edit.",
        "timeout_decision": args.timeout_decision,
        "system": {"graph_version": S.GRAPH_VERSION, "prompt_version": AGENT_PROMPT_VERSION, "prompt_sha256": EXPECTED_AGENT_PROMPT_SHA256, "model": ref["meta"].get("model"),
                   "settings": {k: (ref["meta"].get("settings") or {}).get(k) for k in SETTING_KEYS}, "reference_arm": REFERENCE, "reference_run": ref["meta"].get("run_name"),
                   "specialists": (ref["meta"].get("agent") or {}).get("specialists"), "inputs": ref["meta"].get("inputs"), "n_alerts": ref["meta"].get("n_selected")},
        "git_at_lock": {"commit": facts["git"]["commit"], "branch": facts["git"]["branch"], "modified_tracked_files": facts["git"]["modified_tracked"], "untracked_entries": facts["git"]["untracked_entries"],
                        "note": "commit before the Day 7 commit; the week3-agents tag is placed on the Day 7 commit"},
        "source_files_sha256": facts["sources"], "source_hash_note": "sha256 of the file with CRLF normalized to LF",
        "week2": {"lock_file": w2.LOCK_RELATIVE.replace(os.sep, "/"), "lock_file_sha256": facts["week2_lock_sha256"], "report_sha256_normalized": facts["week2_report_sha256"],
                  "baseline_run": w2.V3_RUN, "baseline_evaluation_sha256": facts["eval_sha256"]["baseline"]},
        "runs": {k: {"run_dir": e["run_rel"], "evaluation_dir": e["eval_rel"], "run_name": e["meta"].get("run_name"), "run_files_sha256": facts["run_digest"][k], "evaluation_sha256": facts["eval_sha256"][k],
                     "git_recorded_by_run": e["meta"].get("git"), "counts": e["meta"].get("counts"), "model_calls": e["meta"].get("model_calls"), "total_tokens": e["meta"].get("total_tokens")}
                 for k, e in runs.items()},
        "arm_metrics": {a: jsonable(arms[a]["metrics"]) for a in ARMS},
        "day5_metrics": jsonable(day5["metrics"]), "baseline_metrics": jsonable(base["metrics"]),
        "ablation_table": {"json": facts["table_paths"]["json"], "json_sha256": facts["table_sha256"]["json"], "md": facts["table_paths"]["md"], "md_sha256": facts["table_sha256"]["md"]},
        "audit_reports_sha256": {a["path"]: a["sha256"] for a in facts["audits"]},
        "transport": {k: facts["transport"][k] for k in runs},
        "suite": {"log": suite["path"], "log_sha256": suite["sha256"], "tests_run": suite["ran"], "seconds": suite["seconds"], "ok": suite["ok"], "skipped": suite["skipped"]},
        "frozen_access_log": {"lines": facts["frozen_log"]["lines"], "sha256_normalized": facts["frozen_log"]["sha256_normalized"]},
        "week1_files_sha256": facts["week1_now"],
        "report": {"path": REPORT_NAME, "sha256_normalized": norm_sha_text(report_text)},
        "checks": checks,
    }


def verify_lock(lock, args, week1_snapshot=None):
    """Compare the lock record with the current files. Returns a list of (name, passed, detail). Read-only."""
    root = os.path.abspath(args.root)
    out = []

    def add(name, ok, detail=""):
        out.append((name, bool(ok), detail))

    def file_sha(path, normalized=False):
        full = os.path.join(root, path)
        if not os.path.exists(full):
            return None
        return norm_sha_file(full) if normalized else sha_file(full)

    add("the lock record has the expected schema", lock.get("schema") == SCHEMA)
    add("the agent_v1 prompt hash in the code equals the locked hash", verdict_prompt.prompt_sha256() == lock["system"]["prompt_sha256"] == EXPECTED_AGENT_PROMPT_SHA256)
    for path, digest in lock["source_files_sha256"].items():
        add("source file " + path, file_sha(path, True) == digest)
    for name in LOCKED_WEEK2_SOURCES:
        add("locked Week 2 source file " + name + " is in the lock", name in lock["source_files_sha256"])
    for key, run in lock["runs"].items():
        now = load_run_folder(root, run["run_dir"])
        add("run " + key + " folder files", now == run["run_files_sha256"])
        add("evaluation of " + key, file_sha(run["evaluation_dir"] + "/evaluation.json") == run["evaluation_sha256"])
    add("baseline evaluation", file_sha(os.path.join(args.baseline_eval_root, w2.V3_RUN, "evaluation.json")) == lock["week2"]["baseline_evaluation_sha256"])
    add("Week 2 baseline lock file unchanged", file_sha(lock["week2"]["lock_file"]) == lock["week2"]["lock_file_sha256"])
    add("WEEK2_REPORT.md unchanged", file_sha(w2.REPORT_NAME, True) == lock["week2"]["report_sha256_normalized"])
    t = lock["ablation_table"]
    add("ablation table json", file_sha(t["json"]) == t["json_sha256"])
    add("ablation table md", file_sha(t["md"]) == t["md_sha256"])
    for path, digest in lock["audit_reports_sha256"].items():
        add("audit report " + path, file_sha(path) == digest)
    add("full-suite log " + lock["suite"]["log"], file_sha(lock["suite"]["log"]) == lock["suite"]["log_sha256"])
    add("WEEK3_REPORT.md unchanged since the lock", file_sha(lock["report"]["path"], True) == lock["report"]["sha256_normalized"])
    # recompute the headline numbers from the evaluations as they are now
    moved = []
    for arm in ARMS:
        run = lock["runs"][arm]
        e = at.load_entry(arm, os.path.join(root, run["run_dir"]), os.path.join(root, run["evaluation_dir"]))
        if "meta" not in e or jsonable(e["metrics"]) != lock["arm_metrics"][arm]:
            moved.append(arm)
    add("every arm's headline numbers recomputed from its run and evaluation equal the locked numbers", not moved, ("differs: " + ", ".join(moved)) if moved else "5 of 5")
    frozen = args.frozen_log
    add("frozen access log unchanged (lines and hash)", w2.count_lines(frozen) == lock["frozen_access_log"]["lines"]
        and (w2.normalized_sha256(frozen) if os.path.exists(frozen) else None) == lock["frozen_access_log"]["sha256_normalized"])
    add("frozen unlock variable not set", not os.environ.get(config.FROZEN_UNLOCK_ENV))
    now1 = (week1_snapshot or runner.week1_snapshot)()
    add("Week 1 files unchanged", now1 == lock["week1_files_sha256"])
    week2 = w2.verify_lock(read_json(os.path.join(root, lock["week2"]["lock_file"])), root, os.path.join(root, args.baseline_runs_dir), frozen, week1_snapshot)
    failed = [r[0] for r in week2 if not r[1]]
    add("the Week 2 baseline verification still passes (" + str(len(week2)) + " checks)", not failed, ("failed: " + ", ".join(failed)) if failed else "")
    return out


# ------------------------------------------------------------------------------------------------ commands
def build_parser():
    p = argparse.ArgumentParser(description="Week 3 Day 7: lock agent system v1 and write WEEK3_REPORT.md. No model calls.")
    p.add_argument("action", choices=["build", "verify"])
    p.add_argument("--root", default=ROOT, help="repository root (where WEEK3_REPORT.md is written)")
    p.add_argument("--runs-dir", default=os.path.join("runs", "week3_day6"), help="folder (under root) holding the five arm runs")
    p.add_argument("--eval-root", default=os.path.join("reports", "week3_day6"), help="folder (under root) holding eval_A .. eval_E")
    p.add_argument("--day5-run", default=os.path.join("runs", "week3_agent_v1", DAY5_RUN))
    p.add_argument("--day5-eval", default=os.path.join("reports", "week2_eval", DAY5_RUN))
    p.add_argument("--baseline-runs-dir", default=os.path.join("runs", "week2_baseline_v1"))
    p.add_argument("--baseline-eval-root", default=os.path.join("reports", "week2_eval"))
    p.add_argument("--table-dir", default=os.path.join("reports", "week3_day6", "ablation_comparison"))
    p.add_argument("--audit-root-day6", default=os.path.join("reports", "week3_day6"))
    p.add_argument("--audit-root-day7", default=os.path.join("reports", "week3_day7"))
    p.add_argument("--suite-log", default=None, help="the full-suite log (python -m unittest discover -s tests -t . -v), saved under root; required for build")
    p.add_argument("--timeout-decision", choices=TIMEOUT_DECISIONS, default=None, help="the recorded decision on timeout handling; required for build")
    p.add_argument("--frozen-log", default=config.FROZEN_ACCESS_LOG)
    p.add_argument("--force", action="store_true", help="replace an existing report and lock record (only before the week3-agents tag exists)")
    return p


def do_build(args, week1_snapshot=None, say=print):
    if not args.timeout_decision:
        say("STOPPED: build needs --timeout-decision known-limitation. How timeouts are handled is a recorded decision; see section 9 of the report it writes.")
        return 1
    if not args.suite_log:
        say("STOPPED: build needs --suite-log <the full-suite log saved under the repository root>.")
        return 1
    root = os.path.abspath(args.root)
    report_path = os.path.join(root, REPORT_NAME)
    lock_path = os.path.join(root, LOCK_RELATIVE)
    existing = [p for p in (report_path, lock_path) if os.path.exists(p)]
    if existing and not args.force:
        say("STOPPED: already exists: " + ", ".join(existing) + ". The agent system is locked once; use --force only to regenerate before the week3-agents tag exists.")
        return 1
    try:
        facts = collect(args, week1_snapshot)
    except ReportError as error:
        say("STOPPED: " + str(error))
        return 1
    except (OSError, ValueError, KeyError) as error:
        say("STOPPED: a file could not be read (" + type(error).__name__ + ": " + str(error)[:200] + ")")
        return 1
    checks = run_checks(facts)
    for c in checks:
        say(("PASS  " if c["passed"] else "FAIL  ") + c["name"] + ((" [" + c["detail"] + "]") if c["detail"] else ""))
    if not all(c["passed"] for c in checks):
        say("A lock check failed. Nothing was written. Fix the cause (do not edit the checks) and run again.")
        return 1
    report = render_report(facts, checks, args.timeout_decision)
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    with open(lock_path, "w", encoding="utf-8") as f:
        json.dump(lock_record(facts, checks, report, args), f, indent="  ", sort_keys=True)
    say("Wrote " + report_path + " and " + lock_path)
    return 0


def do_verify(args, week1_snapshot=None, say=print):
    root = os.path.abspath(args.root)
    lock_path = os.path.join(root, LOCK_RELATIVE)
    if not os.path.exists(lock_path):
        say("STOPPED: no lock record at " + lock_path + ". Run build first.")
        return 1
    results = verify_lock(read_json(lock_path), args, week1_snapshot)
    for name, ok, detail in results:
        say(("PASS  " if ok else "FAIL  ") + name + ((" [" + detail + "]") if detail else ""))
    ok = all(r[1] for r in results)
    say("Agent system v1 unchanged since the lock." if ok else "SOMETHING CHANGED since the lock. Do not proceed until it is explained.")
    return 0 if ok else 1


def main(argv=None):
    args = build_parser().parse_args(argv)
    return do_build(args) if args.action == "build" else do_verify(args)


if __name__ == "__main__":
    sys.exit(main())
