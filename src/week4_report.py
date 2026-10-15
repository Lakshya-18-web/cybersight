"""Week 4 Day 7: lock agent system v2 (incident memory, risk routing, approval API), write WEEK4_REPORT.md, the lock record and the artifact manifest. No model call.

  python src/week4_report.py build  --off-run dev_v2_mem_off --on-run dev_v2_mem_on --suite-log reports/week4_day7/full_suite.txt
  python src/week4_report.py verify [--recompute]

build   Collects facts from files that already exist (the two dev runs and their comparison from src/week4/evaluate_memory.py, the memory store and its manifest, the migrations, the risk policy,
        every Week 4 source file, the full-suite log), runs the lock checks, and ONLY if every check passes writes
          WEEK4_REPORT.md                            the report (repository root). Every number is read from the comparison files; none is typed in or computed from labels here.
          reports/week4_memory_lock.json             the lock record (source hashes, split boundaries, run and comparison hashes, metrics, test evidence, policy and prompt hashes)
          reports/week4_artifact_manifest.json       SHA-256 and size of every artifact the lock depends on
        A failed check writes nothing. build refuses to replace an existing lock without --force (use it only before the week4-memory tag exists).
verify  Read-only. Recomputes every hash and headline number, re-checks the memory store, the split boundaries and the frozen access log, and re-verifies that the Week 3 lock still holds. Exit 0 = unchanged.
        With --recompute it also re-scores the two runs against the dev labels and requires the same comparison as the one locked.

Never touched here: the Week 3 lock (reports/week3_agent_lock.json), WEEK3_REPORT.md and every Week 3 or Week 2 locked file are only READ and hashed. The frozen set is never opened (its access LOG is hashed).
"""
import argparse
import datetime
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import baseline_store as store
import config
import run_baseline_dev as runner
import week2_report as w2
import week3_report as w3r
from agents import verdict_prompt as VP

import week4
from week4 import evaluate_memory as E
from week4 import hashing, policy as policy_module
from week4.db import migrate
from week4.graph import prompt as P2
from week4.graph import state as S2
from week4.memory import isolation, store as MS
from week4.memory.errors import MemoryDataError, MemoryIsolationError, MemoryStoreError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = "week4_memory_lock_v1"
REPORT_NAME = "WEEK4_REPORT.md"
LOCK_RELATIVE = "reports/week4_memory_lock.json"
MANIFEST_RELATIVE = "reports/week4_artifact_manifest.json"
WEEK3_LOCK_RELATIVE = "reports/week3_agent_lock.json"
MIN_TESTS_IN_SUITE_LOG = 1097          # the Week 3 suite alone; the Week 4 tests come on top of it
RUN_FILES = ["results.jsonl", "raw_responses.jsonl", "run_meta.json", "prompt_snapshot.txt", "verdicts.csv", "states.jsonl"]
MEMORY_FILES = ["manifest.json", "records.jsonl", "vectors.npy"]
COMPARISON_FILES = ["comparison.json", "COMPARISON_REPORT.md", "comparison_metrics.csv", "per_alert.csv"]
SECRET_PATTERNS = [re.compile(p) for p in (r"AIza[0-9A-Za-z_\-]{20,}", r"postgres(?:ql)?://[^\s:@/]+:[^\s@/]+@", r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*[\"']?[A-Za-z0-9/+_\-]{12,}",
                                                 r"-----BEGIN [A-Z ]*PRIVATE KEY-----")]
SECRET_ALLOW = ("${", "changeme", "<", "example", "REPLACE", "your-", "xxxx", "://user:pw@")
TEST_PATTERNS = (0, 3)    # test files hold deliberate fake credentials (redaction tests), so only real-key shapes (Google API key, private key) are searched there


class ReportError(Exception):
    pass


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def read_text(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def rel(root, path):
    return os.path.relpath(path, root).replace(os.sep, "/")


def jsonable(value):
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def raw_sha(path):
    return hashing.sha256_bytes(open_bytes(path))


def open_bytes(path):
    with open(path, "rb") as f:
        return f.read()


# ------------------------------------------------------------------------------------------------ the full-suite log
def decode_log(raw):
    """Text of a log written by PowerShell (UTF-16 with a BOM, with '>' redirection on Windows PowerShell 5) or by anything else (UTF-8, with or without a BOM)."""
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    if len(raw) >= 4 and raw[1:2] == b"\x00" and raw[3:4] == b"\x00":     # UTF-16 LE without a BOM
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("utf-8", errors="replace")


def parse_suite_log(path, test_modules=()):
    """Unittest summary lines of a log, plus which of the given test modules are named in it (a -v log lists every test as 'name (module.Class.test)')."""
    text = decode_log(open_bytes(path)).replace("\r\n", "\n")
    ran = re.findall(r"^Ran (\d+) tests? in ([0-9.]+)s", text, re.M)
    ok = re.findall(r"^OK(?: \((.*?)\))?\s*$", text, re.M)
    failed = re.findall(r"^FAILED \((.*?)\)\s*$", text, re.M)
    skipped = None
    if ok and ok[-1]:
        m = re.search(r"skipped=(\d+)", ok[-1])
        skipped = int(m.group(1)) if m else 0
    elif ok:
        skipped = 0
    named = sorted(m for m in test_modules if re.search(r"\((?:\w+\.)*" + re.escape(m) + r"\.\w+", text))
    return {"ran": int(ran[-1][0]) if ran else None, "seconds": float(ran[-1][1]) if ran else None, "ok": bool(ok) and not failed, "failed": failed[-1] if failed else None, "skipped": skipped,
            "modules_named": named}


# ------------------------------------------------------------------------------------------------ files
def week4_source_files(root):
    names = set()
    for sub, suffixes in (("src/week4", (".py", ".sql")),):
        names |= set(hashing.list_files(root, sub, suffixes))
    for pattern in ("src/week4_report.py", "config/risk_policy.json", "docker-compose.yml", "requirements-week4.txt", ".env.week4.example", "docs/WEEK4_*.md", "tests/test_week4_*.py", "tests/week4_support.py"):
        names |= {rel(root, p) for p in glob.glob(os.path.join(root, *pattern.split("/")))}
    return sorted(names)


def folder_digest(root, folder_rel, names=None):
    """{file name: raw sha256} for the files in a folder (all files, or the listed names that exist)."""
    base = os.path.join(root, *folder_rel.split("/"))
    found = names if names is not None else sorted(n for n in os.listdir(base) if os.path.isfile(os.path.join(base, n)))
    return {n: raw_sha(os.path.join(base, n)) for n in found if os.path.isfile(os.path.join(base, n))}


def secret_hits(root, relpaths):
    """Files (text only) that look like they hold a credential. Placeholders and ${VAR} references are allowed."""
    hits = []
    for relpath in relpaths:
        full = os.path.join(root, *relpath.split("/"))
        if not os.path.isfile(full) or not hashing.is_text(full):
            continue
        text = decode_log(open_bytes(full))
        for i, pattern in enumerate(SECRET_PATTERNS):
            if relpath.startswith("tests/") and i not in TEST_PATTERNS:
                continue
            for m in pattern.finditer(text):
                if not any(a in m.group(0) for a in SECRET_ALLOW):
                    hits.append(relpath + ": " + pattern.pattern[:30])
                    break
    return hits


# ------------------------------------------------------------------------------------------------ facts
def default_comparison_dir(args):
    return args.comparison_dir or "reports/week4_eval/" + args.off_run + "_vs_" + args.on_run


def collect(args, week1_snapshot=None, week3_verifier=None):
    root = os.path.abspath(args.root)
    f = {"generated_utc": utc_now(), "root": root}
    runs = {}
    for key, name in (("memory_off", args.off_run), ("memory_on", args.on_run)):
        run_rel = args.runs_dir.rstrip("/").replace("\\", "/") + "/" + name
        full = os.path.join(root, *run_rel.split("/"))
        if not os.path.isfile(os.path.join(full, "run_meta.json")):
            raise ReportError("no run_meta.json in " + run_rel)
        runs[key] = {"run_rel": run_rel, "name": name, "meta": read_json(os.path.join(full, "run_meta.json")), "files_sha256": folder_digest(root, run_rel, [n for n in RUN_FILES])}
    f["runs"] = runs
    cmp_rel = default_comparison_dir(args).replace("\\", "/")
    cmp_full = os.path.join(root, *cmp_rel.split("/"))
    missing = [n for n in COMPARISON_FILES if not os.path.isfile(os.path.join(cmp_full, n))]
    if missing:
        raise ReportError("the comparison folder " + cmp_rel + " lacks: " + ", ".join(missing) + ". Run src/week4/evaluate_memory.py first.")
    f["comparison_rel"] = cmp_rel
    f["comparison"] = read_json(os.path.join(cmp_full, "comparison.json"))
    f["comparison_files_sha256"] = folder_digest(root, cmp_rel, COMPARISON_FILES)

    mem_rel = args.memory_dir.replace("\\", "/")
    f["memory_rel"] = mem_rel
    mem_full = os.path.join(root, *mem_rel.split("/"))
    f["memory"] = {"files_sha256": {}, "info": None, "problems": [], "dev_overlap_check": None}
    try:
        loaded = MS.MemoryStore.load(mem_full)
        f["memory"]["files_sha256"] = folder_digest(root, mem_rel, MEMORY_FILES)
        f["memory"]["info"] = loaded.info()
        f["memory"]["problems"] = loaded.verify_isolation()
        f["memory"]["allowlist_sha256"] = loaded.manifest["allowlist_sha256"]
    except (MemoryStoreError, MemoryDataError, MemoryIsolationError, OSError) as error:
        f["memory"]["problems"] = ["the memory store cannot be loaded and verified: " + type(error).__name__ + ": " + str(error)[:200]]
    train = args.train_path
    f["train"] = {"path": rel(root, train) if train.startswith(root) else os.path.basename(train), "exists": os.path.isfile(train), "sha256": raw_sha(train) if os.path.isfile(train) else None}

    pol = policy_module.load_policy(os.path.join(root, "config", "risk_policy.json"))
    f["policy"] = {"version": pol.version, "sha256": pol.sha256}
    f["prompts"] = {"agent_v1": VP.prompt_sha256(), "agent_v2_memory": P2.get_prompt().sha256}
    f["graph_version"] = S2.GRAPH_VERSION
    mig_dir = os.path.join(root, "src", "week4", "db", "migrations")
    f["migrations"] = [{"version": m["version"], "name": m["name"], "checksum": m["checksum"]} for m in migrate.discover(mig_dir)]
    f["sources"] = hashing.tree_hashes(root, week4_source_files(root))

    lock3_path = os.path.join(root, *WEEK3_LOCK_RELATIVE.split("/"))
    if not os.path.isfile(lock3_path):
        raise ReportError("the Week 3 lock record " + WEEK3_LOCK_RELATIVE + " is missing; Week 4 builds on it and must not exist without it")
    lock3 = read_json(lock3_path)
    f["week3"] = {"lock_file": WEEK3_LOCK_RELATIVE, "lock_file_sha256": raw_sha(lock3_path),
                  "report_sha256_normalized": hashing.normalized_sha256(os.path.join(root, "WEEK3_REPORT.md")) if os.path.isfile(os.path.join(root, "WEEK3_REPORT.md")) else None,
                  "locked_sources_now": {p: hashing.normalized_sha256(os.path.join(root, *p.split("/"))) if os.path.isfile(os.path.join(root, *p.split("/"))) else None
                                         for p in lock3["source_files_sha256"]},
                  "locked_sources_in_lock": lock3["source_files_sha256"], "prompt_sha256": lock3["system"]["prompt_sha256"], "graph_version": lock3["system"]["graph_version"]}
    verifier = week3_verifier or default_week3_verifier
    f["week3_verify"] = verifier(root, week1_snapshot)

    frozen = args.frozen_log
    f["frozen_log"] = {"lines": w2.count_lines(frozen), "sha256_normalized": w2.normalized_sha256(frozen) if os.path.exists(frozen) else None}
    f["unlock_set"] = bool(os.environ.get(config.FROZEN_UNLOCK_ENV))
    f["week1_now"] = (week1_snapshot or runner.week1_snapshot)()

    modules = sorted(os.path.splitext(os.path.basename(p))[0] for p in glob.glob(os.path.join(root, "tests", "test_week4_*.py")))
    f["test_modules"] = modules
    suite_path = os.path.join(root, *args.suite_log.split("/")) if args.suite_log else None
    f["suite"] = None
    if suite_path and os.path.isfile(suite_path):
        f["suite"] = dict(parse_suite_log(suite_path, modules), path=rel(root, suite_path), sha256=raw_sha(suite_path))
    f["pg_suite"] = None
    if args.pg_suite_log:
        pg_path = os.path.join(root, *args.pg_suite_log.split("/"))
        if os.path.isfile(pg_path):
            f["pg_suite"] = dict(parse_suite_log(pg_path, modules), path=rel(root, pg_path), sha256=raw_sha(pg_path))
    f["secret_hits"] = secret_hits(root, list(f["sources"]) + [rel(root, os.path.join(root, *cmp_rel.split("/"), n)) for n in COMPARISON_FILES] +
                                   [runs[k]["run_rel"] + "/" + n for k in runs for n in ("run_meta.json", "results.jsonl", "states.jsonl")])
    f["git"] = {"commit": w3r.git_text(root, "rev-parse", "HEAD"), "branch": w3r.git_text(root, "branch", "--show-current"),
                "modified_tracked": [l[3:] for l in (w3r.git_text(root, "status", "--porcelain") or "").splitlines() if l and not l.startswith("??")],
                "untracked_entries": len([l for l in (w3r.git_text(root, "status", "--porcelain") or "").splitlines() if l.startswith("??")])}
    return f


def default_week3_verifier(root, week1_snapshot=None):
    """The Week 3 verification (read-only) as [(name, passed, detail)]. It needs the Week 3 runs and evaluations to be present, as they are in the repository."""
    args = w3r.build_parser().parse_args(["verify", "--root", root])
    lock = w3r.read_json(os.path.join(root, w3r.LOCK_RELATIVE))
    return w3r.verify_lock(lock, args, week1_snapshot)


# ------------------------------------------------------------------------------------------------ checks
def run_checks(f, args=None):
    checks = []

    def add(name, passed, detail=""):
        checks.append({"name": name, "passed": bool(passed), "detail": detail})
    off, on = f["runs"]["memory_off"]["meta"], f["runs"]["memory_on"]["meta"]
    try:
        E.check_comparable(off, on)
        add("the two runs are comparable (real, complete, dev, same model/settings/inputs/alerts/graph/policy/baseline; memory off + agent_v1 vs memory on + agent_v2_memory; clean isolation check; frozen log unchanged)", True)
    except E.ComparisonError as error:
        add("the two runs are comparable", False, str(error).replace("\n", " ")[:300])
    cmp_ = f["comparison"]
    prov = cmp_.get("provenance", {})
    add("the comparison is of exactly these two runs", (prov.get("memory_off_run", {}).get("run_name"), prov.get("memory_on_run", {}).get("run_name")) == (off.get("run_name"), on.get("run_name")))
    add("the comparison was not made with --allow-partial", cmp_.get("allow_partial") is False)
    add("the comparison schema is the expected one", cmp_.get("schema") == E.SCHEMA)
    add("the comparison covers every alert of both runs", all(cmp_["arms"][a]["population"]["alerts"] == off["n_selected"] for a in ("memory_off", "memory_on")), "n_selected=" + str(off.get("n_selected")))
    mem = f["memory"]
    add("the memory store loads, matches its manifest and passes the train-only checks", mem["info"] is not None and not mem["problems"], "; ".join(mem["problems"])[:300])
    on_mem = (on.get("agent") or {}).get("memory", {})
    add("the memory store on disk is the one the memory-on run used (manifest hash)", mem["info"] is not None and on_mem.get("manifest_sha256") == mem["info"]["manifest_sha256"])
    add("the memory store was built from the current train.parquet (hash)", f["train"]["exists"] and mem["info"] is not None and mem["info"]["train_sha256"] == f["train"]["sha256"],
        "train file present: " + str(f["train"]["exists"]))
    add("the memory-on run recorded a clean train/dev isolation check (0 overlapping flows)", (on_mem.get("isolation_check") or {}).get("dev_overlap") == 0)
    add("the memory is seeded from the train split only (manifest says so)", mem["info"] is not None and mem["info"]["vector_spec"] == "vec-v1" and prov.get("split", {}).get("memory_seeded_from", "").startswith("train split only"))
    add("the risk policy in the runs is the policy file now", all((m.get("agent") or {}).get("policy", {}).get("sha256") == f["policy"]["sha256"] for m in (off, on)))
    add("the prompts in the runs are the registered prompts", off.get("prompt_sha256") == f["prompts"]["agent_v1"] and on.get("prompt_sha256") == f["prompts"]["agent_v2_memory"])
    add("agent_v1 is still the Week 3 locked prompt", f["prompts"]["agent_v1"] == f["week3"]["prompt_sha256"])
    add("the graph version in the runs is the code's graph version", all((m.get("agent") or {}).get("graph_version") == f["graph_version"] for m in (off, on)))
    changed = sorted(p for p, h in f["week3"]["locked_sources_in_lock"].items() if f["week3"]["locked_sources_now"].get(p) != h)
    add("every file locked by Week 3 is unchanged (" + str(len(f["week3"]["locked_sources_in_lock"])) + " files)", not changed, ", ".join(changed[:5]))
    failed3 = [c[0] for c in f["week3_verify"] if not c[1]]
    add("the Week 3 verification still passes (" + str(len(f["week3_verify"])) + " checks)", bool(f["week3_verify"]) and not failed3, ", ".join(failed3[:3]))
    add("the migrations are numbered without gaps and checksummed (" + str(len(f["migrations"])) + ")", len(f["migrations"]) >= 1)
    add("the frozen unlock variable is not set", not f["unlock_set"])
    add("both runs recorded an unchanged frozen access log and unchanged Week 1 files", all(m.get("frozen_access_log_unchanged") is True and m.get("week1_files_unchanged") is True for m in (off, on)))
    add("the frozen access log has no line added since the runs ended (line count equals the one the runs recorded)", all(m.get("frozen_access_log_lines_after") == f["frozen_log"]["lines"] for m in (off, on)),
        "log lines now: " + str(f["frozen_log"]["lines"]))
    add("no credential-like text in any locked artifact", not f["secret_hits"], "; ".join(f["secret_hits"][:3]))
    suite = f["suite"]
    add("the full-suite log exists", suite is not None)
    if suite is not None:
        add("the full suite passed with no failures", suite["ok"] and suite["failed"] is None, str(suite["failed"] or ""))
        add("the suite ran at least the Week 3 suite plus the Week 4 tests (>= %d)" % MIN_TESTS_IN_SUITE_LOG, (suite["ran"] or 0) >= MIN_TESTS_IN_SUITE_LOG + 1, "ran " + str(suite["ran"]))
        add("the log names every Week 4 test module (run it with -v)", set(suite["modules_named"]) == set(f["test_modules"]) and bool(f["test_modules"]),
            "missing: " + ", ".join(sorted(set(f["test_modules"]) - set(suite["modules_named"]))))
    return checks


# ------------------------------------------------------------------------------------------------ outputs
def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def render_report(f, checks):
    cmp_ = f["comparison"]
    P = cmp_["provenance"]
    off, on = f["runs"]["memory_off"]["meta"], f["runs"]["memory_on"]["meta"]
    comparison_text = E.render_report(cmp_)
    body = comparison_text.split("\n", 2)[2].replace("\n## ", "\n### ")   # drop the comparison's own title; its sections become subsections
    suite = f["suite"]
    pg = f["pg_suite"]
    lines = ["# Week 4 report: incident memory, risk routing and the approval API (agent system v2)", "",
             "Locked by `src/week4_report.py`. Every number below is read from the dev runs, their comparison and the test logs; none was typed in. No model was called to write this report.", "",
             "## 1. What was built", "",
             "- **Case database** (PostgreSQL): versioned migrations %s; cases, alert references, verdicts, evidence, routing decisions, proposed containment actions, approval decisions, simulated executions and a hash-chained audit log; "
             "constraints, indexes and foreign keys; idempotent ingest; one-time approval transitions; least-privilege role. Migration checksums are in the lock record." % ", ".join(m["version"] + "_" + m["name"] for m in f["migrations"]),
             "- **Incident memory**: a numpy (optionally ChromaDB) index of %d training incidents (label + numeric flow fingerprint only), seeded from the train split only, with a manifest and an allowlist." % (f["memory"]["info"] or {}).get("n_records", 0),
             "- **Graph v2** (`%s`): the Week 3 graph plus one optional memory step, a memory on/off switch, and a memory-aware verdict prompt (`agent_v2_memory`) used only when memory is on. With memory off the Week 3 code path and prompt (`agent_v1`) run unchanged." % f["graph_version"],
             "- **Risk routing** (`%s`, sha256 `%s`): transparent rules decide auto_close / escalate / needs_review with stated reasons; memory can only raise caution; proposed actions come from the verdict alone." % (f["policy"]["version"], f["policy"]["sha256"]),
             "- **Approval workflow**: proposed actions are 'pending' until an authorised approver approves or rejects them once; rejected or unapproved actions can never be executed; execution is simulated and recorded only. No real containment exists in the code.",
             "- **Approval API** (FastAPI over a framework-free handler layer): cases, pending approvals, approve/reject with idempotency keys, decision history, memory provenance and evidence; authentication and role checks; dev-only open mode that only listens on loopback.", "",
             "## 2. Split isolation", "",
             "- Memory seeded from: %s. Train file sha256 `%s`; memory manifest `%s`; allowlist sha256 `%s`; %d records; per-class cap %d; seed %d; k=%d." % (P["split"]["memory_seeded_from"], P["split"]["train_sha256"], P["split"]["memory_manifest_sha256"], f["memory"].get("allowlist_sha256", ""), P["split"]["memory_records"], P["split"]["memory_per_class_cap"], P["split"]["memory_seed"], P["split"]["memory_k"]),
             "- Evaluation set: dev alerts only. Input hashes: `%s`." % json.dumps(P["inputs"], sort_keys=True),
             "- Isolation check before the memory-on run: %s." % json.dumps(P["split"]["isolation_check"], sort_keys=True),
             "- Frozen set: not opened by either run or by the comparison (frozen access log: %d lines, sha256 `%s`, unchanged)." % (f["frozen_log"]["lines"], f["frozen_log"]["sha256_normalized"]),
             "- How this is tested: `tests/test_week4_memory.py` (train-only ingestion and retrieval), `tests/test_week4_runner.py` (fail-closed start, overlap refusal), `tests/test_week4_evaluate.py` (no frozen or label import on the agent side).", "",
             "## 3. Memory off vs memory on (dev set)", "",
             "Run folders: `%s` and `%s`. The comparison below is `%s/COMPARISON_REPORT.md`, reproduced from `comparison.json`." % (f["runs"]["memory_off"]["run_rel"], f["runs"]["memory_on"]["run_rel"], f["comparison_rel"]), "",
             body, "",
             "## 4. Tests", ""]
    if suite:
        lines += ["- Full suite (`%s`, sha256 `%s`): %s tests, %s, skipped %s, %.1f s." % (suite["path"], suite["sha256"], suite["ran"], "OK" if suite["ok"] else "FAILED", suite["skipped"], suite["seconds"] or 0.0)]
    if pg:
        lines += ["- Suite with PostgreSQL integration enabled (`%s`, sha256 `%s`): %s tests, %s, skipped %s." % (pg["path"], pg["sha256"], pg["ran"], "OK" if pg["ok"] else "FAILED", pg["skipped"])]
    else:
        lines += ["- No PostgreSQL-enabled suite log was supplied to this lock, so the lock does not claim the database integration tests were run against the final code."]
    lines += ["- Week 4 test modules: " + ", ".join("`%s`" % m for m in f["test_modules"]) + ".", "",
              "## 5. Lock checks", "", md_table(["check", "result"], [[c["name"], "PASS" if c["passed"] else "FAIL" + (" (" + c["detail"] + ")" if c["detail"] else "")] for c in checks]), "",
              "## 6. What this lock does not show", "",
              "- Behaviour of components that need infrastructure absent from the build machine is only as verified as the logs above state: Docker Compose start-up, the psycopg driver, the FastAPI application wrapper and the ChromaDB backend are exercised only where the corresponding tests were not skipped.",
              "- Approvals are human decisions; none are recorded in these runs.",
              "- The risk-policy numbers are defaults fixed before the runs and were not tuned; they are part of the locked system and a change is a new policy version.", "",
              "## 7. Reproduce", "",
              "```", "git switch week4-memory   # or the commit the lock names", "python -m week4.seed_memory seed",
              "python src/week4/run_memory_dev.py --memory off --run-name %s" % off["run_name"], "python src/week4/run_memory_dev.py --memory on  --run-name %s" % on["run_name"],
              "python src/week4/evaluate_memory.py --off-run %s --on-run %s" % (off["run_name"], on["run_name"]),
              "python src/week4_report.py verify --recompute", "```", "",
              "Git at lock time: commit `%s`, branch `%s`, %d modified tracked file(s), %d untracked entr(ies). Week 3 (`week3-agents`) and Week 2 locks were only read." % (f["git"]["commit"], f["git"]["branch"], len(f["git"]["modified_tracked"]), f["git"]["untracked_entries"])]
    return "\n".join(lines) + "\n"


def lock_record(f, checks, report_text, manifest_sha):
    cmp_ = f["comparison"]
    return {
        "schema": SCHEMA, "locked_utc": f["generated_utc"], "week4_version": week4.VERSION,
        "purpose": "Week 4 agent system v2 lock record. Memory off reproduces Week 3 behaviour; a change to memory, policy, prompts or approval logic is a new version, never an edit.",
        "system": {"graph_version": f["graph_version"], "prompts": f["prompts"], "policy": f["policy"], "model": cmp_["provenance"]["model"], "settings": cmp_["provenance"]["settings"],
                   "memory_manifest_sha256": cmp_["provenance"]["split"]["memory_manifest_sha256"], "migrations": f["migrations"]},
        "split_boundaries": {"memory_seeded_from": cmp_["provenance"]["split"]["memory_seeded_from"], "train_sha256": f["memory"]["info"]["train_sha256"], "allowlist_sha256": f["memory"]["allowlist_sha256"],
                             "memory_dir": f["memory_rel"], "memory_files_sha256": f["memory"]["files_sha256"], "isolation_check": cmp_["provenance"]["split"]["isolation_check"], "dev_inputs": cmp_["provenance"]["inputs"],
                             "frozen_access_log": f["frozen_log"], "week1_files_sha256": f["week1_now"]},
        "runs": {k: {"run_dir": v["run_rel"], "run_name": v["name"], "files_sha256": v["files_sha256"], "counts": v["meta"].get("counts"), "model_calls": v["meta"].get("model_calls"),
                     "total_tokens": v["meta"].get("total_tokens")} for k, v in f["runs"].items()},
        "comparison": {"dir": f["comparison_rel"], "files_sha256": f["comparison_files_sha256"], "arms": jsonable(cmp_["arms"]), "paired": jsonable(cmp_["paired"])},
        "source_files_sha256": f["sources"], "source_hash_note": "sha256 of the file with CRLF normalized to LF",
        "week3": {"lock_file": f["week3"]["lock_file"], "lock_file_sha256": f["week3"]["lock_file_sha256"], "report_sha256_normalized": f["week3"]["report_sha256_normalized"],
                  "locked_sources_sha256": f["week3"]["locked_sources_in_lock"], "verify_checks": len(f["week3_verify"])},
        "suite": {k: f["suite"][k] for k in ("path", "sha256", "ran", "seconds", "ok", "skipped", "modules_named")},
        "pg_suite": ({k: f["pg_suite"][k] for k in ("path", "sha256", "ran", "seconds", "ok", "skipped")} if f["pg_suite"] else None),
        "git_at_lock": f["git"], "artifact_manifest": {"path": MANIFEST_RELATIVE, "sha256": manifest_sha},
        "report": {"path": REPORT_NAME, "sha256_normalized": hashing.sha256_bytes(report_text.replace("\r\n", "\n").encode("utf-8"))},
        "checks": checks,
    }


def artifact_manifest(f, root):
    files = {}
    for p in f["sources"]:
        files[p] = f["sources"][p]
    for key, v in f["runs"].items():
        for n, h in v["files_sha256"].items():
            files[v["run_rel"] + "/" + n] = h
    for n, h in f["comparison_files_sha256"].items():
        files[f["comparison_rel"] + "/" + n] = h
    for n, h in f["memory"]["files_sha256"].items():
        files[f["memory_rel"] + "/" + n] = h
    for key in ("suite", "pg_suite"):
        if f[key]:
            files[f[key]["path"]] = f[key]["sha256"]
    out = {}
    for p, h in sorted(files.items()):
        full = os.path.join(root, *p.split("/"))
        out[p] = {"sha256": h, "bytes": os.path.getsize(full)}
    return {"schema": "week4_artifact_manifest_v1", "note": "sha256 of source and text files is taken after CRLF->LF normalisation; run, comparison, memory and log files are hashed as stored", "files": out}


# ------------------------------------------------------------------------------------------------ verify
def verify_lock(lock, args, week1_snapshot=None, week3_verifier=None, recompute=None):
    root = os.path.abspath(args.root)
    out = []

    def add(name, ok, detail=""):
        out.append((name, bool(ok), detail))

    def sha_of(relpath, normalized=False):
        full = os.path.join(root, *relpath.split("/"))
        if not os.path.isfile(full):
            return None
        return hashing.normalized_sha256(full) if normalized else raw_sha(full)
    add("the lock record has the expected schema", lock.get("schema") == SCHEMA)
    add("the code's agent_v1 / agent_v2_memory prompt hashes equal the locked hashes", (VP.prompt_sha256(), P2.get_prompt().sha256) == (lock["system"]["prompts"]["agent_v1"], lock["system"]["prompts"]["agent_v2_memory"]))
    add("graph version equals the locked one", S2.GRAPH_VERSION == lock["system"]["graph_version"])
    try:
        pol = policy_module.load_policy(os.path.join(root, "config", "risk_policy.json"))
        add("risk policy unchanged", (pol.version, pol.sha256) == (lock["system"]["policy"]["version"], lock["system"]["policy"]["sha256"]))
    except policy_module.PolicyError as error:
        add("risk policy unchanged", False, str(error))
    current = week4_source_files(root)
    changed = [p for p, h in lock["source_files_sha256"].items() if sha_of(p, True) != h]
    add("every locked Week 4 source file is unchanged (" + str(len(lock["source_files_sha256"])) + ")", not changed, ", ".join(changed[:5]))
    added = sorted(set(current) - set(lock["source_files_sha256"]))
    add("no Week 4 source file has been added since the lock", not added, ", ".join(added[:5]))
    mig = [{"version": m["version"], "name": m["name"], "checksum": m["checksum"]} for m in migrate.discover(os.path.join(root, "src", "week4", "db", "migrations"))]
    add("migration files and checksums unchanged", mig == lock["system"]["migrations"])
    for key, run in lock["runs"].items():
        now = folder_digest(root, run["run_dir"], list(run["files_sha256"]))
        add("run " + key + " files unchanged", now == run["files_sha256"])
    add("comparison files unchanged", folder_digest(root, lock["comparison"]["dir"], list(lock["comparison"]["files_sha256"])) == lock["comparison"]["files_sha256"])
    cmp_path = os.path.join(root, *lock["comparison"]["dir"].split("/"), "comparison.json")
    now_cmp = read_json(cmp_path) if os.path.isfile(cmp_path) else {}
    add("the headline numbers in comparison.json equal the locked numbers", jsonable(now_cmp.get("arms")) == lock["comparison"]["arms"] and jsonable(now_cmp.get("paired")) == lock["comparison"]["paired"])
    sb = lock["split_boundaries"]
    mem_rel = sb["memory_dir"]
    mem_now = folder_digest(root, mem_rel, MEMORY_FILES) if os.path.isdir(os.path.join(root, *mem_rel.split("/"))) else {}
    add("memory store files unchanged (manifest, records, vectors)", mem_now == sb["memory_files_sha256"])
    try:
        loaded = MS.MemoryStore.load(os.path.join(root, *mem_rel.split("/")))
        add("memory store loads and passes the train-only checks", not loaded.verify_isolation() and loaded.manifest_sha256 == lock["system"]["memory_manifest_sha256"])
    except (MemoryStoreError, MemoryDataError, MemoryIsolationError, OSError) as error:
        add("memory store loads and passes the train-only checks", False, type(error).__name__)
    train = args.train_path
    add("train.parquet hash equals the locked train hash", os.path.isfile(train) and raw_sha(train) == sb["train_sha256"])
    add("Week 3 lock file unchanged", sha_of(lock["week3"]["lock_file"]) == lock["week3"]["lock_file_sha256"])
    add("WEEK3_REPORT.md unchanged", sha_of("WEEK3_REPORT.md", True) == lock["week3"]["report_sha256_normalized"])
    changed3 = [p for p, h in lock["week3"]["locked_sources_sha256"].items() if sha_of(p, True) != h]
    add("every Week 3 locked source file is unchanged", not changed3, ", ".join(changed3[:5]))
    verifier = week3_verifier or default_week3_verifier
    w3 = verifier(root, week1_snapshot)
    failed3 = [c[0] for c in w3 if not c[1]]
    add("the Week 3 verification still passes (" + str(len(w3)) + " checks)", bool(w3) and not failed3, ", ".join(failed3[:3]))
    for key in ("suite", "pg_suite"):
        if lock.get(key):
            add("test log " + lock[key]["path"] + " unchanged", sha_of(lock[key]["path"]) == lock[key]["sha256"])
    add("WEEK4_REPORT.md unchanged since the lock", sha_of(lock["report"]["path"], True) == lock["report"]["sha256_normalized"])
    add("artifact manifest unchanged", sha_of(lock["artifact_manifest"]["path"]) == lock["artifact_manifest"]["sha256"])
    manifest_path = os.path.join(root, *lock["artifact_manifest"]["path"].split("/"))
    if os.path.isfile(manifest_path):
        entries = read_json(manifest_path)["files"]
        bad = [p for p, e in entries.items() if sha_of(p, p in lock["source_files_sha256"] or p == lock["report"]["path"]) != e["sha256"]]
        add("every artifact in the manifest still has its recorded SHA-256 (" + str(len(entries)) + ")", not bad, ", ".join(bad[:5]))
    frozen = args.frozen_log
    add("frozen access log unchanged (lines and hash)", w2.count_lines(frozen) == sb["frozen_access_log"]["lines"] and (w2.normalized_sha256(frozen) if os.path.exists(frozen) else None) == sb["frozen_access_log"]["sha256_normalized"])
    add("frozen unlock variable not set", not os.environ.get(config.FROZEN_UNLOCK_ENV))
    add("Week 1 files unchanged", (week1_snapshot or runner.week1_snapshot)() == sb["week1_files_sha256"])
    if recompute is not None:
        same, detail = recompute(root, lock)
        add("re-scoring both runs against the dev labels gives the locked comparison", same, detail)
    return out


def recompute_comparison(root, lock, args=None):
    """Re-score the two runs from their files and the dev labels, and compare with the locked comparison.json (generated_utc ignored). Reads dev labels only."""
    import eval_labels
    import triage_inputs
    runs_dir = os.path.join(root, *os.path.dirname(lock["runs"]["memory_off"]["run_dir"]).split("/"))
    off_dir = os.path.join(root, *lock["runs"]["memory_off"]["run_dir"].split("/"))
    on_dir = os.path.join(root, *lock["runs"]["memory_on"]["run_dir"].split("/"))
    threshold = store.read_json(config.THRESHOLD_PATH)["threshold"] if os.path.exists(config.THRESHOLD_PATH) else None
    try:
        result = E.compare_runs(off_dir, on_dir, triage_inputs.load_dev_alerts(), eval_labels.load_dev_labels(), threshold)
    except (E.ComparisonError, ValueError) as error:
        return False, str(error)[:200]
    result.pop("_tables")
    locked = read_json(os.path.join(root, *lock["comparison"]["dir"].split("/"), "comparison.json"))
    a = {k: jsonable(result[k]) for k in ("arms", "paired", "provenance")}
    b = {k: jsonable(locked[k]) for k in ("arms", "paired", "provenance")}
    return a == b, "" if a == b else "the recomputed numbers differ from comparison.json"


# ------------------------------------------------------------------------------------------------ commands
def build_parser():
    p = argparse.ArgumentParser(description="Week 4 Day 7: lock agent system v2 and write WEEK4_REPORT.md. No model calls.")
    p.add_argument("action", choices=["build", "verify"])
    p.add_argument("--root", default=ROOT)
    p.add_argument("--runs-dir", default="runs/week4_memory")
    p.add_argument("--off-run", default=None)
    p.add_argument("--on-run", default=None)
    p.add_argument("--comparison-dir", default=None, help="default reports/week4_eval/<off>_vs_<on>")
    p.add_argument("--memory-dir", default="memory_store")
    p.add_argument("--train-path", default=config.TRAIN_PATH)
    p.add_argument("--suite-log", default=None, help="full-suite log saved under the root: python -m unittest discover -s tests -t . -v  (UTF-8 or UTF-16)")
    p.add_argument("--pg-suite-log", default=None, help="optional: the same suite run with WEEK4_TEST_PG=1 against a real PostgreSQL")
    p.add_argument("--frozen-log", default=config.FROZEN_ACCESS_LOG)
    p.add_argument("--force", action="store_true")
    p.add_argument("--recompute", action="store_true", help="verify: re-score the runs against the dev labels")
    return p


def do_build(args, week1_snapshot=None, say=print, week3_verifier=None):
    if not (args.off_run and args.on_run):
        say("STOPPED: build needs --off-run and --on-run.")
        return 1
    if not args.suite_log:
        say("STOPPED: build needs --suite-log <the full-suite log saved under the repository root>.")
        return 1
    root = os.path.abspath(args.root)
    targets = [os.path.join(root, REPORT_NAME), os.path.join(root, *LOCK_RELATIVE.split("/")), os.path.join(root, *MANIFEST_RELATIVE.split("/"))]
    existing = [p for p in targets if os.path.exists(p)]
    if existing and not args.force:
        say("STOPPED: already exists: " + ", ".join(existing) + ". The system is locked once; use --force only before the week4-memory tag exists.")
        return 1
    try:
        facts = collect(args, week1_snapshot, week3_verifier)
    except ReportError as error:
        say("STOPPED: " + str(error))
        return 1
    except (OSError, ValueError, KeyError, migrate.MigrationError, policy_module.PolicyError) as error:
        say("STOPPED: a file could not be read (" + type(error).__name__ + ": " + str(error)[:200] + ")")
        return 1
    checks = run_checks(facts, args)
    for c in checks:
        say(("PASS  " if c["passed"] else "FAIL  ") + c["name"] + ((" [" + c["detail"] + "]") if c["detail"] else ""))
    if not all(c["passed"] for c in checks):
        say("A lock check failed. Nothing was written. Fix the cause (do not edit the checks) and run again.")
        return 1
    report = render_report(facts, checks)
    with open(targets[0], "w", encoding="utf-8", newline="\n") as fh:
        fh.write(report)
    os.makedirs(os.path.dirname(targets[1]), exist_ok=True)
    manifest = artifact_manifest(facts, root)
    manifest["files"][REPORT_NAME] = {"sha256": hashing.normalized_sha256(targets[0]), "bytes": os.path.getsize(targets[0])}
    with open(targets[2], "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    lock = lock_record(facts, checks, report, raw_sha(targets[2]))
    with open(targets[1], "w", encoding="utf-8", newline="\n") as fh:
        json.dump(lock, fh, indent=2, sort_keys=True)
        fh.write("\n")
    say("Wrote " + ", ".join(rel(root, t) for t in targets))
    return 0


def do_verify(args, week1_snapshot=None, say=print, week3_verifier=None):
    root = os.path.abspath(args.root)
    lock_path = os.path.join(root, *LOCK_RELATIVE.split("/"))
    if not os.path.isfile(lock_path):
        say("STOPPED: no lock record at " + lock_path + ". Run build first.")
        return 1
    lock = read_json(lock_path)
    recompute = (lambda r, l: recompute_comparison(r, l, args)) if args.recompute else None
    results = verify_lock(lock, args, week1_snapshot, week3_verifier, recompute)
    for name, ok, detail in results:
        say(("PASS  " if ok else "FAIL  ") + name + ((" [" + detail + "]") if detail else ""))
    ok = all(r[1] for r in results)
    say("Agent system v2 unchanged since the lock." if ok else "SOMETHING CHANGED since the lock. Do not proceed until it is explained.")
    return 0 if ok else 1


def main(argv=None):
    args = build_parser().parse_args(argv)
    return do_build(args) if args.action == "build" else do_verify(args)


if __name__ == "__main__":
    sys.exit(main())
