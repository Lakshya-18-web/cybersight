"""Week 3 Day 7: the agent-system lock generator (src/week3_report.py).

Offline. No model call, no network, no label file, no frozen set. The tests build a small synthetic repository in a temporary folder (20 alerts instead of 300; the generator's
N_ALERTS is patched to match): five ablation arm runs and their evaluations, a Day 5 run, a baseline_v3 run, the ablation table, the audit reports, a Week 2 lock that the real
Week 2 verification accepts, and a fake suite log. They prove the lock logic: that build writes the report and the lock only when every check passes, that every check can fail,
that verify notices a changed file, and that the report carries its caveats and every transport error. They say nothing about how well any arm judges alerts; the numbers in the
real report come from the real runs on the project owner's machine.
The last class checks the real lock and is skipped until reports/week3_agent_lock.json exists (and in a checkout that does not hold the runs).
"""
import io
import os
import ast
import contextlib
import sys
import json
import shutil
import hashlib
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

import config
import prompt_registry
import baseline_store as store
import day6_replicates as rep
import week2_report as w2
import ablation_config as ablation
import ablation_table as table
import week3_report as w3
from agents import state as S
from agents import verdict_prompt

from tests import test_week3_day6 as d6

N = 20
WEEK1 = {"data/dev_alerts.csv": "11" * 32, "models/model.json": "22" * 32}


def write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def read_text(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def sha(path):
    return hashlib.sha256(read_bytes(path)).hexdigest()


def norm_sha(path):
    return hashlib.sha256(read_bytes(path).replace(b"\r\n", b"\n")).hexdigest()


ROWS = {"A": d6.REF_ROWS, "B": d6.B_ROWS, "C": lambda: d6.with_changes({0: d6.MISS}), "D": d6.base_rows, "E": d6.base_rows}
ARM_PATHS = {"A": {"traffic_analyst>c2_beacon_analyst>enrichment_agent>verdict_node": 6, "traffic_analyst>enrichment_agent>verdict_node": 14},
             "B": {"traffic_analyst>enrichment_agent>verdict_node": 20}, "C": {"traffic_analyst>c2_beacon_analyst>verdict_node": 6, "traffic_analyst>verdict_node": 14},
             "D": {"enrichment_agent>verdict_node": 20}, "E": {"verdict_node": 20}}
SETTINGS = {"temperature": 0.0, "max_output_tokens": 1024, "seed": 42, "parse_retries": 2, "timeout_seconds": 60, "transport_retries": 4, "requests_per_minute": 10.0}
RUN_FILE_NAMES = ["results.jsonl", "raw_responses.jsonl", "run_meta.json", "prompt_snapshot.txt"]


def jsonl(lines):
    return "".join(json.dumps(x) + "\n" for x in lines)


def raw_for(arm, extra_failures=()):
    lines = [{"outcome": "reply", "transport_errors": [], "latency_seconds": 1.0 + 0.1 * i} for i in range(N)]
    for status in extra_failures:
        lines.append({"outcome": "transport_failed", "latency_seconds": None,
                      "transport_errors": [{"message": "ClientError: " + str(status) + " RESOURCE_EXHAUSTED" if status == 429 else "ServerError: " + str(status) + " UNAVAILABLE", "status": status}] * 5})
    return lines


# the transport failures the real Day 6 runs showed: B, D and E one call that failed five times with 429, E in addition one with 503
FAILURES = {"A": [], "B": [[429]], "C": [], "D": [[429]], "E": [[429], [503]]}


class Fixture:
    """A synthetic repository root. Everything is written in dependency order so each hash is of the final file."""

    def __init__(self, tmp):
        self.root = os.path.join(tmp, "repo")
        self.frozen = os.path.join(self.root, "eval", "frozen_access.log")
        self.week1 = lambda: dict(WEEK1)
        write_text(self.frozen, "2025-01-01 frozen opened for final test\n")
        self.runs = {}
        os.makedirs(self.root, exist_ok=True)
        self.write_sources()
        for arm in w3.ARMS:
            self.make_run(arm, os.path.join("runs", "week3_day6", "day6_arm_" + arm), os.path.join("reports", "week3_day6", "eval_" + arm), ablation.arm_disabled(arm), ROWS[arm](), FAILURES[arm])
        self.make_run("day5", os.path.join("runs", "week3_agent_v1", w3.DAY5_RUN), os.path.join("reports", "week2_eval", w3.DAY5_RUN), (), d6.with_changes({0: d6.MISS, 5: d6.NO_VERDICT}), [],
                      git={"commit": "e75b34e", "dirty": True})
        self.make_run("baseline", os.path.join("runs", "week2_baseline_v1", w2.V3_RUN), os.path.join("reports", "week2_eval", w2.V3_RUN), None, d6.with_changes({2: d6.MISS, 11: d6.FALSE_POSITIVE}), [])
        self.make_table()
        self.make_audits()
        self.make_week2_lock()
        self.make_suite()

    # ---- pieces
    def p(self, *parts):
        return os.path.join(self.root, *parts)

    def write_sources(self):
        for name in w2.LOCKED_SOURCE_FILES + ["src/agents/supervisor.py", "src/tools/registry.py", "src/run_agent_dev.py", "src/week3_report.py"]:
            write_text(self.p(*name.split("/")), "# " + name + "\nVALUE = 1\n")

    def make_run(self, key, run_rel, eval_rel, disabled, rows, failures, git=None):
        run_dir, eval_dir = self.p(run_rel), self.p(eval_rel)
        ids = [r["alert_id"] for r in d6.base_rows()]
        ok = sum(1 for r in rows if r["has_verdict"])
        counts = {"ok": ok, "parse_failed": N - ok, "model_error": 0}
        summary = {"tool_calls": 0 if disabled is not None and len(ablation.effective_specialists(disabled)) == 0 else 100, "graph_seconds_total": 12.5,
                   "path_counts": ARM_PATHS.get(key, ARM_PATHS["A"]), "error_code_counts": ({"empty_reply": N - ok} if N - ok else {})}
        agent = {"graph_version": S.GRAPH_VERSION, "summary": summary}
        if disabled is not None:
            agent["specialists"] = list(ablation.effective_specialists(disabled))
            if key in w3.ARMS:
                agent["ablation"] = {"arm": key, "disabled": list(ablation.normalize(disabled))}
        sessions = [{"started_utc": "2025-01-0" + str(i + 1), "ended_because": "complete" if i == len(failures) else "5 alerts in a row ended in model_error"} for i in range(len(failures) + 1)]
        meta = {"run_name": os.path.basename(run_rel), "status": "complete", "set": "dev", "fake_model": False, "n_selected": N, "selected_alert_ids": ids, "model": w3.EXPECTED_MODEL,
                "prompt_version": w3.AGENT_PROMPT_VERSION if disabled is not None else "baseline_v3", "prompt_sha256": w3.EXPECTED_AGENT_PROMPT_SHA256 if disabled is not None else w2.EXPECTED_V3_SHA256,
                "settings": dict(SETTINGS), "inputs": {"dev_alerts_sha256": "a", "flow_store_dev_sha256": "b"}, "git": git or {"commit": "ce619c4", "dirty": True}, "counts": counts,
                "model_calls": N + 2 * (N - ok), "total_tokens": 1000 * N, "sessions": sessions, "python": "3.12", "packages": {"x": "1"},
                "frozen_access_log_unchanged": True, "week1_files_unchanged": True}
        if disabled is not None:
            meta["agent"] = agent
        raw = raw_for(key, [s for f in failures for s in f])
        write_text(os.path.join(run_dir, "results.jsonl"), jsonl([{"alert_id": i, "status": "ok"} for i in ids]))
        write_text(os.path.join(run_dir, "raw_responses.jsonl"), jsonl(raw))
        write_text(os.path.join(run_dir, "prompt_snapshot.txt"), "prompt\n")
        os.makedirs(run_dir, exist_ok=True)
        store.write_json_atomic(os.path.join(run_dir, "run_meta.json"), meta)
        evaluation = d6.evaluation_for(os.path.basename(run_rel), rows, meta["prompt_sha256"])
        evaluation["run_file_sha256"] = {k: v for k, v in rep.folder_digest(run_dir).items() if k in w2.RUN_FILES}
        evaluation["protected_file_sha256"] = dict(WEEK1)
        evaluation["frozen_access_log_lines"] = 1
        os.makedirs(eval_dir, exist_ok=True)
        store.write_json_atomic(os.path.join(eval_dir, "evaluation.json"), evaluation)
        import pandas as pd
        pd.DataFrame([{k: ("" if v is None else v) for k, v in r.items()} for r in rows]).to_csv(os.path.join(eval_dir, "per_alert.csv"), index=False)
        self.runs[key] = {"run_rel": run_rel, "eval_rel": eval_rel, "run_dir": run_dir, "eval_dir": eval_dir}

    def make_table(self):
        out = self.p("reports", "week3_day6", "ablation_comparison")
        args = ["--out-dir", out, "--reference", "A"]
        for arm in w3.ARMS:
            args += ["--run", arm, self.runs[arm]["run_dir"], self.runs[arm]["eval_dir"]]
        code = table.main(args, say=lambda *a: None)
        assert code == 0, "the fixture's ablation table did not build"

    def make_audits(self):
        for key, description, relpath in w3.audit_files(self.args(), self.root):
            arm = key[-1] if key[-1] in w3.ARMS and not key.endswith("day5") else None
            if key.startswith("day6_artifacts") or key.startswith("day7_artifacts"):
                data = {"mode": "artifacts", "run_name": ("day5" if False else (w3.arm_run_name(arm) if arm else w3.DAY5_RUN)), "all_checks_passed": True}
            elif key == "day6_replay_A_vs_day5":
                data = {"mode": "replay", "arm": "A", "alerts": N, "all_checks_passed": True,
                        "compare": {"run_dir": self.runs["day5"]["run_rel"], "compared": N, "identical_all_fields": N, "mismatch_counts": {"x": 0}}}
            else:
                data = {"mode": "replay", "arm": arm, "alerts": N, "all_checks_passed": True}
                if key.startswith("day7_replay_vs_run"):
                    data["compare"] = {"run_dir": self.runs[arm]["run_rel"], "compared": N, "identical_all_fields": N, "mismatch_counts": {"prompt_sha256": 0, "trace": 0}}
            write_text(self.p(relpath), json.dumps(data, indent=2))

    def make_week2_lock(self):
        reg = {v: prompt_registry.get_prompt(v).sha256 for v in prompt_registry.list_versions()}
        base = self.runs["baseline"]
        lock = {"selected_baseline": w2.SELECTED, "prompt_sha256": w2.EXPECTED_V3_SHA256, "registry_sha256": reg,
                "locked_source_files_sha256": {n: norm_sha(self.p(*n.split("/"))) for n in w2.LOCKED_SOURCE_FILES},
                "run_files_sha256": {w2.V3_RUN: {k: v for k, v in rep.folder_digest(base["run_dir"]).items() if k in w2.RUN_FILES}},
                "evaluation_sha256": {w2.V3_RUN: sha(os.path.join(base["eval_dir"], "evaluation.json"))},
                "frozen_access_log": {"lines": w2.count_lines(self.frozen), "sha256_normalized": norm_sha(self.frozen)}, "week1_files_sha256": dict(WEEK1)}
        write_text(self.p("reports", "week2_baseline_lock.json"), json.dumps(lock, indent=2))
        write_text(self.p("WEEK2_REPORT.md"), "# Week 2 report\n")

    def make_suite(self, tests=1017, ok=True, with_day7=True, module="tests.test_week3_day7"):
        body = ("test_something (" + module + ".Something.test_something) ... ok\n" if with_day7 else "test_something (tests.test_week3_day6.Other.test_x) ... ok\n")
        body += "\n" + "-" * 70 + "\nRan " + str(tests) + " tests in 205.898s\n\n" + ("OK\n" if ok else "FAILED (failures=2)\n")
        write_text(self.p("reports", "week3_day7", "full_suite.txt"), body)

    # ---- running
    def argv(self, action="build", extra=()):
        argv = [action, "--root", self.root, "--frozen-log", self.frozen]
        if action == "build":
            argv += ["--suite-log", os.path.join("reports", "week3_day7", "full_suite.txt"), "--timeout-decision", "known-limitation"]
        return argv + list(extra)

    def args(self, action="build", extra=()):
        return w3.build_parser().parse_args(self.argv(action, extra))

    def run(self, action="build", extra=(), argv=None):
        said = []
        args = w3.build_parser().parse_args(argv if argv is not None else self.argv(action, extra))
        with mock.patch.object(w3, "N_ALERTS", N):
            code = (w3.do_build if args.action == "build" else w3.do_verify)(args, self.week1, say=lambda *a: said.append(" ".join(str(x) for x in a)))
        return code, said

    def exists(self, *parts):
        return os.path.exists(self.p(*parts))

    def report(self):
        return read_text(self.p("WEEK3_REPORT.md"))

    def lock(self):
        return json.loads(read_text(self.p("reports", "week3_agent_lock.json")))

    def edit_json(self, relpath, change):
        data = json.loads(read_text(self.p(*relpath.split("/"))))
        change(data)
        write_text(self.p(*relpath.split("/")), json.dumps(data, indent=2))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop(config.FROZEN_UNLOCK_ENV, None)
        self.fx = Fixture(self.tmp.name)

    def assertNothingWritten(self):
        self.assertFalse(self.fx.exists("WEEK3_REPORT.md"))
        self.assertFalse(self.fx.exists("reports", "week3_agent_lock.json"))


class BuildTests(Base):
    def test_build_passes_and_writes_the_report_and_the_lock(self):
        code, said = self.fx.run()
        self.assertEqual(code, 0, "\n".join(said))
        self.assertTrue(self.fx.exists("WEEK3_REPORT.md"))
        lock = self.fx.lock()
        self.assertEqual(lock["schema"], w3.SCHEMA)
        self.assertTrue(all(c["passed"] for c in lock["checks"]))
        self.assertGreaterEqual(len(lock["checks"]), 25)
        self.assertEqual(sorted(lock["arm_metrics"]), list(w3.ARMS))
        self.assertEqual(lock["timeout_decision"], "known-limitation")
        self.assertEqual(lock["system"]["prompt_sha256"], w3.EXPECTED_AGENT_PROMPT_SHA256)
        self.assertEqual(lock["system"]["reference_arm"], "A")
        for name in w2.LOCKED_SOURCE_FILES:
            self.assertIn(name, lock["source_files_sha256"])

    def test_the_report_numbers_and_denominators_are_the_evaluation_numbers(self):
        self.fx.run()
        text = self.fx.report()
        self.assertIn("90.0% (9/10)", text)      # arm A recall, failures_wrong
        self.assertIn("80.0% (8/10)", text)      # arm B recall
        self.assertIn("`failures_wrong`", text)
        self.assertIn("(primary)", text)

    def test_the_report_states_every_caveat(self):
        self.fx.run()
        text = self.fx.report()
        for phrase in ("descriptive", "one run per arm", "Arms B and D change more than one thing", "wants_mitre", "Parse failures are uneven", "Dev set only",
                       "Day 5 (historical)", "known limitation", "independent evaluation", "Run-time code identity is not recorded", "Model service drift"):
            self.assertIn(phrase.lower(), text.lower(), phrase)

    def test_the_report_lists_every_observed_transport_error(self):
        self.fx.run()
        text = self.fx.report()
        self.assertIn('{"429": 15, "503": 5}', text)          # B, D and E: 5 failed attempts of 429 each (15); E also 5 of 503
        rows = [l for l in text.splitlines() if l.startswith("| arm E") and "503" in l]
        self.assertTrue(rows, "arm E's 503 row is missing")
        lock = self.fx.lock()
        self.assertEqual(lock["transport"]["E"]["failed_attempts_by_http_status"], {"429": 5, "503": 5})
        self.assertEqual(lock["transport"]["B"]["failed_attempts_by_http_status"], {"429": 5})
        self.assertEqual(lock["transport"]["A"]["failed_attempts_by_http_status"], {})
        self.assertEqual(lock["transport"]["day5"]["failed_transport_attempts"], 0)
        self.assertEqual(lock["transport"]["E"]["timeout_like_failed_attempts"], 0)

    def test_the_report_has_one_top_heading_and_the_table_is_nested_under_section_6(self):
        self.fx.run()
        text = self.fx.report()
        self.assertEqual([l for l in text.splitlines() if l.startswith("# ")].__len__(), 1)
        self.assertIn("### The committed ablation table, verbatim", text)
        self.assertTrue(read_text(self.fx.p("reports", "week3_day6", "ablation_comparison", "ablation_table.md")).splitlines()[0].startswith("# "))

    def test_the_report_does_not_claim_the_arm_with_fewest_parse_failures_is_better_by_cause(self):
        self.fx.run()
        text = self.fx.report()
        self.assertIn("draws no causal conclusion", text)
        self.assertNotIn("shortest prompts", text)

    def test_the_timeout_decision_is_required_and_recorded(self):
        argv = self.fx.argv()
        i = argv.index("--timeout-decision")
        code, said = self.fx.run(argv=argv[:i] + argv[i + 2:])
        self.assertEqual(code, 1)
        self.assertTrue(any("--timeout-decision" in s for s in said))
        self.assertNothingWritten()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            w3.build_parser().parse_args(argv[:i] + ["--timeout-decision", "ignore"] + argv[i + 2:])

    def test_the_suite_log_is_required(self):
        argv = self.fx.argv()
        i = argv.index("--suite-log")
        code, said = self.fx.run(argv=argv[:i] + argv[i + 2:])
        self.assertEqual(code, 1)
        self.assertTrue(any("--suite-log" in s for s in said))
        self.assertNothingWritten()

    def test_an_existing_lock_is_not_overwritten_without_force(self):
        self.assertEqual(self.fx.run()[0], 0)
        before = sha(self.fx.p("reports", "week3_agent_lock.json")), sha(self.fx.p("WEEK3_REPORT.md"))
        code, said = self.fx.run()
        self.assertEqual(code, 1)
        self.assertTrue(any("already exists" in s for s in said))
        self.assertEqual(before, (sha(self.fx.p("reports", "week3_agent_lock.json")), sha(self.fx.p("WEEK3_REPORT.md"))))
        self.assertEqual(self.fx.run(extra=["--force"])[0], 0)

    def test_a_log_that_prints_the_module_without_the_tests_prefix_is_accepted(self):
        self.fx.make_suite(module="test_week3_day7")
        code, said = self.fx.run()
        self.assertEqual(code, 0, "\n".join(said))

    def test_a_missing_arm_run_stops_cleanly(self):
        shutil.rmtree(self.fx.runs["C"]["run_dir"])
        code, said = self.fx.run()
        self.assertEqual(code, 1)
        self.assertTrue(any(s.startswith("STOPPED") for s in said))
        self.assertNothingWritten()

    def test_a_missing_ablation_table_stops_cleanly(self):
        shutil.rmtree(self.fx.p("reports", "week3_day6", "ablation_comparison"))
        code, said = self.fx.run()
        self.assertEqual(code, 1)
        self.assertTrue(any("no ablation table" in s for s in said))
        self.assertNothingWritten()

    def test_build_changes_no_input_file(self):
        before = {}
        for folder, _, files in os.walk(self.fx.root):
            for name in files:
                full = os.path.join(folder, name)
                before[full] = sha(full)
        self.assertEqual(self.fx.run()[0], 0)
        for full, digest in before.items():
            self.assertEqual(sha(full), digest, full)


class EveryCheckCanFail(Base):
    """Each case breaks one thing and expects build to stop with a named FAIL and write nothing."""

    def expect_fail(self, fragment):
        code, said = self.fx.run()
        self.assertEqual(code, 1, "\n".join(said))
        failing = [s for s in said if s.startswith("FAIL")]
        self.assertTrue(any(fragment.lower() in s.lower() for s in failing), "no FAIL mentions " + fragment + ":\n" + "\n".join(said))
        self.assertNothingWritten()

    def edit_meta(self, key, change):
        self.fx.edit_json(self.fx.runs[key]["run_rel"].replace(os.sep, "/") + "/run_meta.json", change)

    def edit_eval(self, key, change):
        self.fx.edit_json(self.fx.runs[key]["eval_rel"].replace(os.sep, "/") + "/evaluation.json", change)

    def test_a_different_prompt_hash_in_one_arm(self):
        def change(m):
            m["prompt_sha256"] = "0" * 64
        self.edit_meta("C", change)
        self.expect_fail("pinned hash")

    def test_a_different_model_in_one_arm(self):
        self.edit_meta("B", lambda m: m.update({"model": "other-model"}))
        self.expect_fail("one model")

    def test_different_settings_in_one_arm(self):
        self.edit_meta("D", lambda m: m["settings"].update({"timeout_seconds": 30}))
        self.expect_fail("identical generation")

    def test_a_different_alert_list_in_one_arm(self):
        self.edit_meta("E", lambda m: m.update({"selected_alert_ids": list(reversed(m["selected_alert_ids"]))}))
        self.expect_fail("same dev inputs")

    def test_a_fake_model_run(self):
        self.edit_meta("A", lambda m: m.update({"fake_model": True}))
        self.expect_fail("complete real dev run")

    def test_an_incomplete_run(self):
        self.edit_meta("B", lambda m: m.update({"status": "stopped"}))
        self.expect_fail("complete real dev run")

    def test_a_wrong_ablation_record(self):
        self.edit_meta("C", lambda m: m["agent"]["ablation"].update({"arm": "B"}))
        self.expect_fail("ablation arm")

    def test_a_model_error_alert_left_in_a_final_result(self):
        self.edit_meta("D", lambda m: m["counts"].update({"model_error": 1, "ok": m["counts"]["ok"] - 1}))
        self.expect_fail("no model_error")

    def test_a_partial_evaluation(self):
        self.edit_eval("B", lambda e: e.update({"allow_partial": True}))
        self.expect_fail("complete")

    def test_an_evaluation_with_a_false_integrity_check(self):
        self.edit_eval("C", lambda e: e["integrity"].update({"run_unchanged": False}))
        self.expect_fail("complete")

    def test_a_run_folder_changed_after_its_evaluation(self):
        with open(os.path.join(self.fx.runs["A"]["run_dir"], "results.jsonl"), "a", encoding="utf-8") as f:
            f.write('{"alert_id": "extra"}\n')
        self.expect_fail("run_file_sha256")

    def test_the_frozen_access_log_gained_a_line(self):
        with open(self.fx.frozen, "a", encoding="utf-8") as f:
            f.write("2025-02-02 another access\n")
        self.expect_fail("frozen access log")

    def test_the_unlock_variable_set(self):
        os.environ[config.FROZEN_UNLOCK_ENV] = "1"
        self.expect_fail("unlock variable")

    def test_a_week1_file_changed(self):
        self.fx.week1 = lambda: dict(WEEK1, **{"data/dev_alerts.csv": "ff" * 32})
        self.expect_fail("week 1 files")

    def test_a_tampered_table_cell(self):
        def change(t):
            row = t["table"]["views"]["failures_wrong"][1]
            key = next(iter(row["cells"]))
            row["cells"][key] = {"value": 0.123, "num": 1, "den": 8}
        self.fx.edit_json("reports/week3_day6/ablation_comparison/ablation_table.json", change)
        self.expect_fail("ablation table")

    def test_a_table_built_from_other_runs(self):
        self.fx.edit_json("reports/week3_day6/ablation_comparison/ablation_table.json", lambda t: t["inputs"][1].update({"run_dir": "runs/week3_day6/day6_arm_B_smoke"}))
        self.expect_fail("exactly the five arm runs")

    def test_a_table_with_an_excluded_run(self):
        self.fx.edit_json("reports/week3_day6/ablation_comparison/ablation_table.json", lambda t: t.update({"excluded": [{"label": "X", "reasons": ["bad"]}]}))
        self.expect_fail("no excluded run")

    def test_a_missing_audit_report(self):
        os.remove(self.fx.p("reports", "week3_day7", "audit_replay_vs_run_C", "audit_replay_C.json"))
        self.expect_fail("audit report exists")

    def test_an_audit_that_failed(self):
        self.fx.edit_json("reports/week3_day7/audit_artifacts_B/audit_artifacts.json", lambda a: a.update({"all_checks_passed": False}))
        self.expect_fail("all its checks passed")

    def test_a_replay_that_does_not_reproduce_the_run(self):
        self.fx.edit_json("reports/week3_day7/audit_replay_vs_run_D/audit_replay_D.json", lambda a: a["compare"]["mismatch_counts"].update({"routing": 2}))
        self.expect_fail("reproduces every arm run")

    def test_a_replay_audit_of_the_wrong_run(self):
        self.fx.edit_json("reports/week3_day7/audit_replay_vs_run_E/audit_replay_E.json", lambda a: a["compare"].update({"run_dir": "runs/week3_day6/day6_arm_D"}))
        self.expect_fail("reproduces every arm run")

    def test_a_replay_that_compared_too_few_alerts(self):
        def change(a):
            a["compare"].update({"compared": N - 3, "identical_all_fields": N - 3})
        self.fx.edit_json("reports/week3_day7/audit_replay_vs_run_A/audit_replay_A.json", change)
        self.expect_fail("reproduces every arm run")

    def test_arm_a_not_matching_day5(self):
        self.fx.edit_json("reports/week3_day6/audit_replay_A_vs_day5/audit_replay_A.json", lambda a: a["compare"].update({"identical_all_fields": N - 1}))
        self.expect_fail("matches the Day 5 run")

    def test_an_artifacts_audit_for_the_wrong_arm(self):
        self.fx.edit_json("reports/week3_day7/audit_artifacts_C/audit_artifacts.json", lambda a: a.update({"run_name": "day6_arm_D"}))
        self.expect_fail("artifacts audit is for its own arm")

    def test_a_changed_locked_week2_source_file(self):
        with open(self.fx.p("src", "gemini_client.py"), "a", encoding="utf-8") as f:
            f.write("CHANGED = 1\n")
        code, said = self.fx.run()
        self.assertEqual(code, 1)
        self.assertTrue(any(s.startswith("FAIL") and "locked" in s.lower() for s in said), "\n".join(said))
        self.assertNothingWritten()

    def test_a_changed_baseline_evaluation(self):
        self.edit_eval("baseline", lambda e: e.update({"note": "edited"}))
        code, said = self.fx.run()
        self.assertEqual(code, 1)
        self.assertTrue(any(s.startswith("FAIL") for s in said))
        self.assertNothingWritten()

    def test_a_missing_suite_log(self):
        os.remove(self.fx.p("reports", "week3_day7", "full_suite.txt"))
        self.expect_fail("full-suite log")

    def test_a_failed_suite_log(self):
        self.fx.make_suite(ok=False)
        self.expect_fail("full-suite log")

    def test_a_suite_log_with_too_few_tests(self):
        self.fx.make_suite(tests=900)
        self.expect_fail("full-suite log")

    def test_a_suite_log_that_does_not_list_the_day7_tests(self):
        self.fx.make_suite(with_day7=False)
        self.expect_fail("full-suite log")


class VerifyTests(Base):
    def setUp(self):
        super().setUp()
        self.assertEqual(self.fx.run()[0], 0)

    def verify(self):
        return self.fx.run("verify")

    def test_verify_passes_right_after_build_and_is_read_only(self):
        before = {}
        for folder, _, files in os.walk(self.fx.root):
            for name in files:
                full = os.path.join(folder, name)
                before[full] = sha(full)
        code, said = self.verify()
        self.assertEqual(code, 0, "\n".join(said))
        self.assertIn("Agent system v1 unchanged since the lock.", said[-1])
        after = {}
        for folder, _, files in os.walk(self.fx.root):
            for name in files:
                full = os.path.join(folder, name)
                after[full] = sha(full)
        self.assertEqual(before, after)

    def test_verify_without_a_lock_stops(self):
        os.remove(self.fx.p("reports", "week3_agent_lock.json"))
        code, said = self.verify()
        self.assertEqual(code, 1)
        self.assertTrue(any("no lock record" in s for s in said))

    def test_verify_ignores_line_ending_differences_in_text_sources_and_the_report(self):
        for name in ("src/agents/supervisor.py", "WEEK3_REPORT.md"):
            path = self.fx.p(*name.split("/"))
            data = read_bytes(path).replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            with open(path, "wb") as f:
                f.write(data)
        code, said = self.verify()
        self.assertEqual(code, 0, "\n".join(said))

    def assertChanged(self, fragment=None):
        code, said = self.verify()
        self.assertEqual(code, 1, "verify did not notice the change")
        self.assertIn("SOMETHING CHANGED", said[-1])
        if fragment:
            self.assertTrue(any(s.startswith("FAIL") and fragment.lower() in s.lower() for s in said), "\n".join(said))

    def test_a_changed_report(self):
        with open(self.fx.p("WEEK3_REPORT.md"), "a", encoding="utf-8") as f:
            f.write("\nEdited.\n")
        self.assertChanged("WEEK3_REPORT.md")

    def test_a_changed_agent_source(self):
        with open(self.fx.p("src", "agents", "supervisor.py"), "a", encoding="utf-8") as f:
            f.write("X = 2\n")
        self.assertChanged("supervisor.py")

    def test_a_changed_locked_week2_file(self):
        with open(self.fx.p("src", "verdict_parser.py"), "a", encoding="utf-8") as f:
            f.write("X = 2\n")
        self.assertChanged("verdict_parser.py")

    def test_a_changed_run_file(self):
        with open(os.path.join(self.fx.runs["B"]["run_dir"], "results.jsonl"), "a", encoding="utf-8") as f:
            f.write("{}\n")
        self.assertChanged("run B")

    def test_a_changed_evaluation(self):
        path = os.path.join(self.fx.runs["C"]["eval_dir"], "evaluation.json")
        data = json.loads(read_text(path))
        data["metrics"]["population"]["alerts"] = 19
        write_text(path, json.dumps(data))
        self.assertChanged("evaluation of C")

    def test_a_changed_table(self):
        with open(self.fx.p("reports", "week3_day6", "ablation_comparison", "ablation_table.md"), "a", encoding="utf-8") as f:
            f.write("\nEdited.\n")
        self.assertChanged("ablation table md")

    def test_a_changed_audit_report(self):
        self.fx.edit_json("reports/week3_day6/audit_replay_B/audit_replay_B.json", lambda a: a.update({"note": "x"}))
        self.assertChanged("audit report")

    def test_a_changed_suite_log(self):
        with open(self.fx.p("reports", "week3_day7", "full_suite.txt"), "a", encoding="utf-8") as f:
            f.write("extra\n")
        self.assertChanged("full-suite log")

    def test_a_changed_week2_lock_or_report(self):
        with open(self.fx.p("WEEK2_REPORT.md"), "a", encoding="utf-8") as f:
            f.write("x\n")
        self.assertChanged("WEEK2_REPORT.md")

    def test_a_changed_frozen_log(self):
        with open(self.fx.frozen, "a", encoding="utf-8") as f:
            f.write("x\n")
        self.assertChanged("frozen access log")

    def test_the_unlock_variable(self):
        os.environ[config.FROZEN_UNLOCK_ENV] = "1"
        self.assertChanged("unlock variable")

    def test_a_changed_week1_file(self):
        self.fx.week1 = lambda: dict(WEEK1, **{"models/model.json": "00" * 32})
        self.assertChanged("Week 1")

    def test_headline_numbers_are_recomputed_not_just_hashed(self):
        lock = self.fx.lock()
        lock["arm_metrics"]["A"]["failures_wrong.recall"] = {"value": 0.5, "num": 5, "den": 10}
        write_text(self.fx.p("reports", "week3_agent_lock.json"), json.dumps(lock))
        self.assertChanged("headline numbers")


class SuiteLogParsingTests(unittest.TestCase):
    def parse(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "log.txt")
            write_text(path, text)
            return w3.parse_suite_log(path)

    def test_a_clean_run(self):
        r = self.parse("Ran 1017 tests in 205.898s\n\nOK\n")
        self.assertEqual((r["ran"], r["ok"], r["skipped"], r["failed"]), (1017, True, 0, None))
        self.assertAlmostEqual(r["seconds"], 205.898)

    def test_skips_are_counted(self):
        r = self.parse("Ran 1040 tests in 20.0s\n\nOK (skipped=7)\n")
        self.assertEqual((r["ok"], r["skipped"]), (True, 7))

    def test_a_failed_run_is_not_ok(self):
        r = self.parse("Ran 12 tests in 1.0s\n\nFAILED (failures=1, errors=2)\n")
        self.assertFalse(r["ok"])
        self.assertEqual(r["failed"], "failures=1, errors=2")

    def test_no_summary_is_not_ok(self):
        r = self.parse("Traceback...\n")
        self.assertFalse(r["ok"])
        self.assertIsNone(r["ran"])

    def test_the_day7_marker_is_found_in_a_verbose_log(self):
        self.assertTrue(self.parse("test_a (tests.test_week3_day7.BuildTests.test_a) ... ok\nRan 1 test in 0.1s\n\nOK\n")["mentions_day7_tests"])
        self.assertFalse(self.parse("Ran 1 test in 0.1s\n\nOK\n")["mentions_day7_tests"])

    def test_the_log_format_of_the_real_suite_run_is_accepted(self):
        """The saved log reports/week3_day7/full_suite_792d7bf.txt: 1092 tests, OK (skipped=3), verbose names with the module printed as test_week3_day7 (no 'tests.' prefix)."""
        log = ("test_a_changed_report (test_week3_day7.VerifyTests.test_a_changed_report) ... ok\n"
               "test_a_clean_run (test_week3_day7.SuiteLogParsingTests.test_a_clean_run) ... ok\n"
               "test_the_real_lock_verifies (test_week3_day7.RealLockTests.test_the_real_lock_verifies) ... skipped 'no lock'\n"
               "\n" + "-" * 70 + "\nRan 1092 tests in 577.987s\n\nOK (skipped=3)\n")
        r = self.parse(log)
        self.assertEqual((r["ran"], r["ok"], r["skipped"], r["failed"], r["mentions_day7_tests"]), (1092, True, 3, None, True))
        self.assertAlmostEqual(r["seconds"], 577.987)

    def test_both_module_spellings_are_accepted(self):
        for name in ("test_week3_day7.SuiteLogParsingTests", "tests.test_week3_day7.SuiteLogParsingTests", "pkg.tests.test_week3_day7.VerifyTests.test_x"):
            self.assertTrue(self.parse("test_x (" + name + ".test_x) ... ok\nRan 1 test in 0.1s\n\nOK\n")["mentions_day7_tests"], name)

    def test_only_a_listed_day7_test_counts_not_a_mention(self):
        tail = "Ran 1 test in 0.1s\n\nOK\n"
        for text in ("test_x (tests.test_week3_day6.TableTests.test_x) ... ok\n",                                  # Day 6 only
                     "test_x (tests.test_week3_day7_other.Foo.test_x) ... ok\n",                                   # a different module that starts the same
                     'File "C:\\repo\\tests\\test_week3_day7.py", line 3, in test_x\n',                          # a path in a traceback
                     "see test_week3_day7 for details\n",                                                           # prose
                     "test_x (test_week3_day7) ... ok\n"):                                                          # no class, not a test id
            self.assertFalse(self.parse(text + tail)["mentions_day7_tests"], text)

    def test_the_other_suite_requirements_are_unchanged_for_the_real_format(self):
        verbose = "test_a (test_week3_day7.VerifyTests.test_a) ... ok\n\n"
        self.assertFalse(self.parse(verbose + "Ran 1092 tests in 5.0s\n\nFAILED (failures=1)\n")["ok"])
        self.assertFalse(self.parse(verbose + "Traceback...\n")["ok"])
        self.assertEqual(self.parse(verbose + "Ran 1016 tests in 5.0s\n\nOK\n")["ran"], 1016)


class HelperTests(unittest.TestCase):
    def test_nested_pushes_headings_down_and_leaves_other_lines(self):
        self.assertEqual(w3.nested("# A\ntext\n## B\n| x |"), "### A\ntext\n#### B\n| x |")

    def test_the_timeout_decision_has_one_allowed_value(self):
        self.assertEqual(w3.TIMEOUT_DECISIONS, ("known-limitation",))

    def test_audit_files_cover_every_arm_the_day5_comparison_and_the_artifacts(self):
        args = w3.build_parser().parse_args(["build"])
        keys = [k for k, _, _ in w3.audit_files(args, ROOT)]
        self.assertEqual(len(keys), len(set(keys)))
        for arm in w3.ARMS:
            for prefix in ("day6_replay_", "day7_replay_vs_run_", "day7_artifacts_"):
                self.assertIn(prefix + arm, keys)
        self.assertIn("day6_replay_A_vs_day5", keys)
        self.assertIn("day6_artifacts_day5", keys)

    def test_the_pinned_constants_agree_with_the_code(self):
        self.assertEqual(verdict_prompt.prompt_sha256(), w3.EXPECTED_AGENT_PROMPT_SHA256)
        self.assertEqual(w3.ARMS, tuple(sorted(ablation.ARMS)))
        self.assertEqual(w3.LOCKED_WEEK2_SOURCES, w2.LOCKED_SOURCE_FILES)

    def test_the_default_paths_match_the_day6_layout(self):
        args = w3.build_parser().parse_args(["verify"])
        self.assertEqual(args.runs_dir, os.path.join("runs", "week3_day6"))
        self.assertEqual(args.eval_root, os.path.join("reports", "week3_day6"))
        self.assertEqual(args.table_dir, os.path.join("reports", "week3_day6", "ablation_comparison"))
        self.assertEqual(args.day5_eval, os.path.join("reports", "week2_eval", "dev_agent_v1_flash_lite"))


class BoundaryDay7Tests(unittest.TestCase):
    def setUp(self):
        self.source = read_text(os.path.join(ROOT, "src", "week3_report.py"))
        self.imports = set()
        for node in ast.walk(ast.parse(self.source)):
            if isinstance(node, ast.Import):
                self.imports |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                self.imports.add(node.module.split(".")[0])

    def test_no_network_model_data_or_label_imports(self):
        forbidden = {"requests", "urllib", "urllib3", "http", "socket", "httpx", "google", "genai", "pandas", "numpy", "xgboost", "sklearn", "joblib", "pyarrow",
                     "gemini_client", "eval_labels", "evaluate", "eval_metrics", "eval_io", "langgraph", "langsmith", "dotenv"}
        self.assertFalse(self.imports & forbidden, sorted(self.imports & forbidden))

    def test_it_never_names_a_label_a_key_or_the_frozen_data(self):
        for text in ('".env', "dotenv", "GEMINI_API_KEY", "mitre_accepted", "labels.parquet", "frozen_test", ".parquet", "genai.Client"):
            self.assertNotIn(text, self.source, text)

    def test_it_only_opens_files_for_reading_except_its_two_outputs(self):
        writes = [l.strip() for l in self.source.splitlines() if 'open(' in l and ('"w"' in l or "'w'" in l or '"a"' in l)]
        self.assertEqual(len(writes), 2, writes)
        self.assertTrue(all("report_path" in l or "lock_path" in l for l in writes), writes)

    def test_importing_it_makes_no_model_call_and_reads_no_environment_secret(self):
        self.assertFalse(hasattr(w3, "genai"))
        self.assertNotIn("os.environ[", self.source)


def real_lock_available():
    return (os.path.exists(os.path.join(ROOT, "reports", "week3_agent_lock.json")) and os.path.isdir(os.path.join(ROOT, "runs", "week3_day6"))
            and os.path.exists(os.path.join(ROOT, "WEEK3_REPORT.md")))


@unittest.skipUnless(real_lock_available(), "no reports/week3_agent_lock.json (or no runs) in this checkout; the Day 7 lock has not been built here")
class RealLockTests(unittest.TestCase):
    def test_the_real_lock_verifies(self):
        said = []
        code = w3.do_verify(w3.build_parser().parse_args(["verify"]), say=lambda *a: said.append(" ".join(str(x) for x in a)))
        self.assertEqual(code, 0, "\n".join(said))

    def test_the_real_lock_records_every_check_as_passed(self):
        lock = json.loads(read_text(os.path.join(ROOT, "reports", "week3_agent_lock.json")))
        self.assertEqual(lock["schema"], w3.SCHEMA)
        self.assertTrue(lock["checks"])
        self.assertTrue(all(c["passed"] for c in lock["checks"]))
        self.assertEqual(lock["system"]["prompt_sha256"], w3.EXPECTED_AGENT_PROMPT_SHA256)

    def test_the_real_report_carries_the_required_caveats(self):
        text = read_text(os.path.join(ROOT, "WEEK3_REPORT.md")).lower()
        for phrase in ("descriptive", "one run per arm", "arms b and d change more than one thing", "parse failures are uneven", "known limitation", "429"):
            self.assertIn(phrase, text, phrase)


if __name__ == "__main__":
    unittest.main()
