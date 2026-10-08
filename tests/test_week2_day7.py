import io
import os
import re
import sys
import ast
import json
import shutil
import hashlib
import tempfile
import unittest
import contextlib
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

import config
import baseline_prompt
import prompt_registry as registry
import day6_aggregate as agg
import day6_replicates as rep
import week2_report as w7

from tests import test_week2_day3 as d3
from tests import test_week2_day6 as d6t

LOCKED_V3_SHA256 = "9403e7ea1937ff0f0f4b4fba548b58efa93bcc6296daa7326970adbaed1b61b7"
V1_SHA256 = "0208c856dc1063ef5e249fcffdb28af803bd2899fa87977dde0ac4a23b06f172"
DAY7_MODULES = ["week2_report.py"]
V1, V2, V3 = "dev_flash_lite_v1", "dev_flash_lite_v2_final", "dev_flash_lite_v3_final"
D6 = list(agg.DEFAULT_RUNS)
ALL_NAMES = [V1, V2, V3] + D6
WEEK1 = {"eval/MANIFEST.json": "m1", "eval/dev_labels.parquet": "l1"}
LOG_TEXT = "2026-09-01T00:00:00Z\tframe\ta\tone\n2026-09-02T00:00:00Z\tframe\tb\ttwo\n"


def week1_now():
    return dict(WEEK1)


def read_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def append_text(path, text):
    with open(path, "a", encoding="utf-8", newline="") as f:
        f.write(text)


def read_source(name):
    return read_text(os.path.join(ROOT, "src", name))


def tweak(i, evaluation, meta):
    name = ALL_NAMES[i]
    evaluation["frozen_access_log_lines"] = 2
    evaluation["metrics"]["verdict"]["valid_only"]["llm"]["precision"]["wilson95"] = [0.7, 0.9]
    meta["provider"] = "gemini"
    meta["counts"] = {"ok": 9, "parse_failed": 2, "model_error": 0}
    meta["model_calls"] = 11 + i
    meta["total_tokens"] = 12345 + i
    if name == V1:
        meta["prompt_version"], meta["prompt_sha256"] = "baseline_v1", V1_SHA256
    elif name == V2:
        meta["prompt_version"], meta["prompt_sha256"] = "baseline_v2", registry.get_prompt("baseline_v2").sha256


class ProjectCase(unittest.TestCase):
    """A synthetic project: six evaluated runs, the Day 6 summary and manifest, a frozen access log and a copy of the locked source files."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = self.tmp
        self.eval_root, self.runs_dir = d6t.write_fixture(self.tmp, names=ALL_NAMES, precisions=[0.5, 0.6, 0.7, 0.8, 0.9, 1.0], tweak=tweak)
        for name in ALL_NAMES:
            for fname in w7.RUN_FILES:
                if fname != "run_meta.json":
                    write_text(os.path.join(self.runs_dir, name, fname), name + "|" + fname + "\n")
        self.log = os.path.join(self.tmp, "eval", "frozen_access.log")
        write_text(self.log, LOG_TEXT)
        for rel in w7.LOCKED_SOURCE_FILES:
            dst = os.path.join(self.tmp, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(os.path.join(ROOT, rel), dst)
        for name in ALL_NAMES:
            self.sync_evaluation(name)
        self.day6_dir = os.path.join(self.tmp, "reports", "week2_day6")
        self.write_summary()
        self.write_manifest()
        self.said = []

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_summary(self, inputs_unchanged=True):
        runs = [agg.load_run(n, self.eval_root, self.runs_dir) for n in D6]
        analysis = agg.analyze(runs, reference=agg.load_run(V3, self.eval_root, self.runs_dir))
        os.makedirs(self.day6_dir, exist_ok=True)
        with open(os.path.join(self.day6_dir, "three_run_summary.json"), "w", encoding="utf-8") as f:
            json.dump(agg.summary_json(analysis, {}, inputs_unchanged), f, default=str)

    def write_manifest(self):
        manifest = {"prompt_sha256": LOCKED_V3_SHA256,
                    "replicates": {str(i + 1): {"status": "complete", "run_file_sha256": rep.folder_digest(os.path.join(self.runs_dir, n))} for i, n in enumerate(D6)},
                    "protected_runs": {n: rep.folder_digest(os.path.join(self.runs_dir, n)) for n in rep.PROTECTED_RUNS}}
        path = rep.manifest_path(self.runs_dir)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(manifest, f)

    def argv(self, action="build", v2=V2, extra=()):
        a = [action, "--runs-dir", self.runs_dir, "--eval-root", self.eval_root, "--day6-dir", self.day6_dir, "--frozen-log", self.log, "--root", self.tmp]
        if v2:
            a += ["--v2-run", v2]
        return a + list(extra)

    def run_action(self, action="build", v2=V2, extra=(), snapshot=week1_now):
        args = w7.build_parser().parse_args(self.argv(action, v2, extra))
        self.said = []
        fn = w7.do_build if action == "build" else w7.do_verify
        return fn(args, snapshot, say=self.said.append)

    @property
    def out(self):
        return "\n".join(self.said)

    @property
    def report_path(self):
        return os.path.join(self.tmp, w7.REPORT_NAME)

    @property
    def lock_path(self):
        return os.path.join(self.tmp, w7.LOCK_RELATIVE)

    def written(self):
        return os.path.exists(self.report_path) or os.path.exists(self.lock_path)

    def edit_meta(self, name, **changes):
        path = os.path.join(self.runs_dir, name, "run_meta.json")
        meta = json.loads(read_text(path))
        meta.update(changes)
        write_text(path, json.dumps(meta))

    def edit_eval(self, name, fn):
        path = os.path.join(self.eval_root, name, "evaluation.json")
        ev = json.loads(read_text(path))
        fn(ev)
        write_text(path, json.dumps(ev))

    def sync_evaluation(self, name):
        digest = rep.folder_digest(os.path.join(self.runs_dir, name))
        self.edit_eval(name, lambda ev: ev.update({"run_file_sha256": digest}))

    def edit_manifest(self, fn):
        path = rep.manifest_path(self.runs_dir)
        manifest = json.loads(read_text(path))
        fn(manifest)
        write_text(path, json.dumps(manifest))

    def resume_first_replicate(self, manifest_status="needs_attention", sessions=2, sync=True):
        append_text(os.path.join(self.runs_dir, D6[0], "results.jsonl"), "resumed\n")
        self.edit_meta(D6[0], sessions=[{"session": n + 1} for n in range(sessions)])
        if sync:
            self.sync_evaluation(D6[0])
        self.edit_manifest(lambda m: m["replicates"]["1"].update({"status": manifest_status}))

    def backslash_week1_keys(self):
        for name in ALL_NAMES:
            self.edit_eval(name, lambda ev: ev.update({"protected_file_sha256": {k.replace("/", "\\"): v for k, v in ev.get("protected_file_sha256", {}).items()}}))

    def built(self):
        self.assertEqual(self.run_action("build"), 0, self.out)
        return read_text(self.report_path), json.loads(read_text(self.lock_path))


class BuildTests(ProjectCase):
    def test_a_consistent_project_builds_and_every_check_passes(self):
        report, lock = self.built()
        self.assertEqual([c for c in lock["checks"] if not c["passed"]], [])
        self.assertGreaterEqual(len(lock["checks"]), 20)
        self.assertNotIn("FAIL  ", self.out)

    def test_the_report_states_the_closure_and_lock_facts(self):
        report, _ = self.built()
        self.assertIn(LOCKED_V3_SHA256, report)
        self.assertIn("baseline_v3", report)
        self.assertIn("frozen evaluation set remains CLOSED", report)
        self.assertIn("Week 1 artifacts remain UNCHANGED", report)
        self.assertIn("baseline_v3` is LOCKED after Day 7", report)
        self.assertIn("gemini-test", report)

    def test_the_report_lists_the_known_limitations(self):
        report, _ = self.built()
        for text in ["Attack-type classification remains weak", "MITRE accepted accuracy remains imperfect", "Persistent Bot, DDoS and DoS Hulk confusion",
                     "Parse failures remain possible"]:
            self.assertIn(text, report)

    def test_the_report_has_every_required_section(self):
        report, _ = self.built()
        for title in ["## 1. Summary", "## 2. What Week 2 built", "## 3. The locked baseline", "## 5. Day 3 baseline", "## 6. Day 5", "## 7. Day 6",
                      "### Key error-analysis findings", "## 8. Closure statements", "## 9. Known limitations", "## 10. Reproduction", "## 11. Provenance"]:
            self.assertIn(title, report)

    def test_numbers_in_the_report_come_from_the_files(self):
        report, _ = self.built()
        v3 = json.loads(read_text(os.path.join(self.eval_root, V3, "evaluation.json")))
        self.assertIn(w7.fmt(w7.value_of(v3, "precision_valid_only"), "precision_valid_only"), report)
        self.assertIn(format(12345 + 3, ","), report)  # a Day 6 run's token count, read from run_meta.json
        summary = json.loads(read_text(os.path.join(self.day6_dir, "three_run_summary.json")))
        precision = [r for r in summary["headline"] if r["key"] == "precision_valid_only"][0]
        self.assertIn(agg.display_value(precision["mean"], precision["unit"]), report)

    def test_changing_a_metric_changes_the_report(self):
        first, _ = self.built()
        os.remove(self.report_path)
        os.remove(self.lock_path)
        self.edit_eval(V1, lambda ev: ev["metrics"]["verdict"]["valid_only"]["llm"]["precision"].update({"value": 0.123456}))
        self.assertEqual(self.run_action("build"), 0, self.out)
        self.assertNotEqual(first, read_text(self.report_path))
        self.assertIn("12.35%", read_text(self.report_path))

    def test_the_commit_table_uses_the_reported_commits(self):
        report, _ = self.built()
        for commit in w7.COMMITS.values():
            self.assertIn(commit, report)

    def test_the_report_makes_no_week_3_claims_and_no_cost_claim(self):
        report, _ = self.built()
        low = report.lower()
        for word in ["langgraph", "chromadb", "multi-agent architecture", "$"]:
            self.assertNotIn(word, low)

    def test_the_lock_record_holds_the_locked_configuration(self):
        _, lock = self.built()
        self.assertEqual(lock["selected_baseline"], "baseline_v3")
        self.assertEqual(lock["prompt_sha256"], LOCKED_V3_SHA256)
        self.assertEqual(lock["baseline_v1_sha256"], V1_SHA256)
        self.assertEqual(lock["model"], "gemini-test")
        self.assertEqual(lock["provider"], "gemini")
        self.assertEqual(lock["settings"], {"temperature": 0.0, "max_output_tokens": 1024, "seed": 42, "parse_retries": 2})
        self.assertEqual(sorted(lock["locked_source_files_sha256"]), sorted(w7.LOCKED_SOURCE_FILES))
        self.assertEqual(lock["reference_runs"]["day6_replicates"], D6)
        self.assertEqual(sorted(lock["run_files_sha256"]), sorted(ALL_NAMES))
        self.assertEqual(lock["frozen_access_log"]["lines"], 2)
        self.assertEqual(lock["week1_files_sha256"], WEEK1)
        self.assertEqual(lock["registry_sha256"]["baseline_v3"], LOCKED_V3_SHA256)

    def test_lock_record_run_files_cover_only_the_run_artifacts(self):
        _, lock = self.built()
        for files in lock["run_files_sha256"].values():
            self.assertTrue(set(files) <= set(w7.RUN_FILES))
            self.assertIn("run_meta.json", files)

    def test_an_existing_report_is_not_overwritten_without_force(self):
        self.built()
        before = read_text(self.report_path)
        self.assertEqual(self.run_action("build"), 1)
        self.assertIn("already exists", self.out)
        self.assertEqual(read_text(self.report_path), before)
        self.assertEqual(self.run_action("build", extra=["--force"]), 0, self.out)

    def test_build_needs_the_v2_run_name(self):
        self.assertEqual(self.run_action("build", v2=None), 1)
        self.assertIn("--v2-run", self.out)
        self.assertFalse(self.written())

    def test_build_stops_when_a_run_is_missing(self):
        self.assertEqual(self.run_action("build", v2="no_such_run"), 1)
        self.assertIn("STOPPED", self.out)
        self.assertFalse(self.written())

    def test_build_stops_when_there_is_no_evaluation(self):
        os.remove(os.path.join(self.eval_root, V2, "evaluation.json"))
        self.assertEqual(self.run_action("build"), 1)
        self.assertIn("evaluate.py", self.out)
        self.assertFalse(self.written())

    def test_build_stops_when_the_day_6_summary_is_missing(self):
        os.remove(os.path.join(self.day6_dir, "three_run_summary.json"))
        self.assertEqual(self.run_action("build"), 1)
        self.assertIn("day6_aggregate.py", self.out)
        self.assertFalse(self.written())

    def test_the_selected_baseline_and_hashes_are_pinned_in_the_module(self):
        self.assertEqual(w7.EXPECTED_V3_SHA256, LOCKED_V3_SHA256)
        self.assertEqual(w7.EXPECTED_V1_SHA256, V1_SHA256)
        self.assertEqual(w7.SELECTED, "baseline_v3")
        self.assertEqual(registry.get_prompt("baseline_v3").sha256, LOCKED_V3_SHA256)


class Day6ResumeAndWeek1KeyTests(ProjectCase):
    def test_week1_keys_recorded_with_backslashes_are_compared(self):
        self.backslash_week1_keys()
        report, lock = self.built()
        check = [c for c in lock["checks"] if c["name"].startswith("the Week 1 files hash the same")][0]
        self.assertTrue(check["passed"])
        self.assertTrue(check["detail"].endswith(" hash comparisons"))
        self.assertGreater(int(check["detail"].split()[0]), 0)

    def test_a_changed_week1_hash_under_a_backslash_key_blocks_the_lock(self):
        self.backslash_week1_keys()
        self.edit_eval(V2, lambda ev: ev["protected_file_sha256"].update({"eval\\MANIFEST.json": "other"}))
        self.assertEqual(self.run_action("build"), 1)
        self.assertIn("changed: " + V2 + ":eval/MANIFEST.json", self.out)
        self.assertFalse(self.written())

    def test_week1_keys_that_never_match_still_block_the_lock(self):
        for name in ALL_NAMES:
            self.edit_eval(name, lambda ev: ev.update({"protected_file_sha256": {"elsewhere\\x": "1"}}))
        self.assertEqual(self.run_action("build"), 1)
        self.assertIn("0 hash comparisons", self.out)
        self.assertFalse(self.written())

    def test_a_resumed_replicate_with_a_stale_manifest_entry_builds(self):
        self.resume_first_replicate()
        before = read_text(rep.manifest_path(self.runs_dir))
        report, lock = self.built()
        self.assertEqual([c for c in lock["checks"] if not c["passed"]], [])
        self.assertIn("kept as historical", self.out)
        self.assertEqual(read_text(rep.manifest_path(self.runs_dir)), before)

    def test_the_report_documents_the_resumed_replicate(self):
        self.resume_first_replicate()
        report, _ = self.built()
        self.assertIn("**Resumed replicate.** `" + D6[0] + "`", report)
        self.assertIn("2 sessions", report)
        self.assertIn("needs_attention", report)
        self.assertIn("post-completion `evaluation.json`", report)

    def test_the_report_has_no_resume_note_when_nothing_was_resumed(self):
        report, _ = self.built()
        self.assertNotIn("Resumed replicate", report)

    def test_a_stale_manifest_entry_without_a_recorded_resume_blocks_the_lock(self):
        self.resume_first_replicate(sessions=1)
        self.assertEqual(self.run_action("build"), 1)
        self.assertIn("FAIL  the replicates are unchanged since the Day 6 manifest", self.out)
        self.assertFalse(self.written())

    def test_a_changed_replicate_that_the_manifest_called_complete_blocks_the_lock(self):
        self.resume_first_replicate(manifest_status="complete")
        self.assertEqual(self.run_action("build"), 1)
        self.assertIn("FAIL  the replicates are unchanged since the Day 6 manifest", self.out)
        self.assertFalse(self.written())

    def test_a_replicate_changed_after_its_evaluation_blocks_the_lock(self):
        self.resume_first_replicate(sync=False)
        self.assertEqual(self.run_action("build"), 1)
        self.assertIn("FAIL  the replicates match the run_file_sha256 recorded by their own post-completion Day 4 evaluation", self.out)
        self.assertFalse(self.written())

    def test_an_evaluation_without_run_hashes_blocks_the_lock(self):
        self.edit_eval(D6[2], lambda ev: ev.pop("run_file_sha256"))
        self.assertEqual(self.run_action("build"), 1)
        self.assertIn("differs: " + D6[2], self.out)
        self.assertFalse(self.written())

    def test_a_manifest_missing_a_replicate_entry_blocks_the_lock(self):
        self.edit_manifest(lambda m: m["replicates"].pop("3"))
        self.assertEqual(self.run_action("build"), 1)
        self.assertIn("FAIL  the Day 6 manifest holds the pinned hash and three replicate entries", self.out)
        self.assertFalse(self.written())

    def test_a_manifest_with_another_prompt_hash_blocks_the_lock(self):
        self.edit_manifest(lambda m: m.update({"prompt_sha256": "0" * 64}))
        self.assertEqual(self.run_action("build"), 1)
        self.assertIn("FAIL  the Day 6 manifest holds the pinned hash and three replicate entries", self.out)
        self.assertFalse(self.written())

    def test_verify_still_passes_after_a_resumed_replicate_was_locked(self):
        self.resume_first_replicate()
        self.built()
        self.assertEqual(self.run_action("verify"), 0, self.out)


class FailedCheckTests(ProjectCase):
    def assert_refused(self, expected_text):
        self.assertEqual(self.run_action("build"), 1)
        self.assertIn("FAIL", self.out)
        self.assertIn(expected_text, self.out)
        self.assertIn("Nothing was written", self.out)
        self.assertFalse(self.written())

    def test_a_replicate_with_another_prompt_hash_blocks_the_lock(self):
        self.edit_meta(D6[1], prompt_sha256="0" * 64)
        self.assert_refused("all three Day 6 runs used the pinned baseline_v3 hash")

    def test_the_day_5_run_with_another_prompt_hash_blocks_the_lock(self):
        self.edit_meta(V3, prompt_sha256="0" * 64)
        self.assert_refused("the Day 5 baseline_v3 run used the pinned hash")

    def test_a_different_model_in_one_replicate_blocks_the_lock(self):
        self.edit_meta(D6[2], model="gemini-other")
        self.assert_refused("used one model")

    def test_different_settings_block_the_lock(self):
        self.edit_meta(D6[0], settings={"temperature": 0.5, "max_output_tokens": 1024, "seed": 42, "parse_retries": 2})
        self.assert_refused("identical settings")

    def test_an_incomplete_run_blocks_the_lock(self):
        self.edit_meta(D6[0], status="incomplete")
        self.assert_refused("complete dev run")

    def test_a_failed_evaluation_integrity_flag_blocks_the_lock(self):
        self.edit_eval(V3, lambda ev: ev["integrity"].update({"protected_unchanged": False}))
        self.assert_refused("integrity checks")

    def test_a_partial_evaluation_blocks_the_lock(self):
        self.edit_eval(V2, lambda ev: ev.update({"allow_partial": True}))
        self.assert_refused("no evaluation was partial")

    def test_a_run_that_recorded_a_changed_week1_file_blocks_the_lock(self):
        self.edit_meta(D6[1], week1_files_unchanged=False)
        self.assert_refused("changed frozen access log or Week 1 file")

    def test_a_longer_frozen_access_log_blocks_the_lock(self):
        append_text(self.log, "2026-10-01T00:00:00Z\tframe\tc\tthree\n")
        self.assert_refused("frozen access log has the same number of lines")

    def test_the_unlock_variable_blocks_the_lock(self):
        with mock.patch.dict(os.environ, {config.FROZEN_UNLOCK_ENV: "x"}):
            self.assert_refused("unlock variable is not set")

    def test_a_changed_week1_file_blocks_the_lock(self):
        def changed():
            return {"eval/MANIFEST.json": "other", "eval/dev_labels.parquet": "l1"}
        self.assertEqual(self.run_action("build", snapshot=changed), 1)
        self.assertIn("Week 1 files hash the same", self.out)
        self.assertFalse(self.written())

    def test_an_empty_week1_comparison_blocks_the_lock(self):
        self.assertEqual(self.run_action("build", snapshot=lambda: {"unrelated": "x"}), 1)
        self.assertFalse(self.written())

    def test_a_replicate_edited_after_day_6_blocks_the_lock(self):
        append_text(os.path.join(self.runs_dir, D6[0], "results.jsonl"), "{}\n")
        self.assert_refused("replicates are unchanged")

    def test_a_protected_run_edited_after_day_6_blocks_the_lock(self):
        append_text(os.path.join(self.runs_dir, V1, "results.jsonl"), "{}\n")
        self.assert_refused("run folders are unchanged")

    def test_a_missing_manifest_blocks_the_lock(self):
        os.remove(rep.manifest_path(self.runs_dir))
        self.assert_refused("manifest exists")

    def test_a_summary_with_changed_inputs_blocks_the_lock(self):
        self.write_summary(inputs_unchanged=False)
        self.assert_refused("inputs were unchanged")

    def test_a_summary_for_other_runs_blocks_the_lock(self):
        path = os.path.join(self.day6_dir, "three_run_summary.json")
        summary = json.loads(read_text(path))
        summary["runs"] = list(reversed(summary["runs"]))
        write_text(path, json.dumps(summary))
        self.assert_refused("lists exactly the three runs")

    def test_runs_over_different_alert_lists_block_the_lock(self):
        self.edit_meta(D6[0], selected_alert_ids=["DEV-0001"])
        self.assert_refused("same alert list")


class VerifyTests(ProjectCase):
    def setUp(self):
        super().setUp()
        self.built()

    def test_verify_passes_on_an_unchanged_project(self):
        self.assertEqual(self.run_action("verify"), 0, self.out)
        self.assertIn("Baseline unchanged since the lock", self.out)
        self.assertNotIn("FAIL", self.out)

    def test_verify_is_read_only(self):
        before = {p: read_text(p) for p in (self.report_path, self.lock_path)}
        self.run_action("verify")
        self.assertEqual({p: read_text(p) for p in before}, before)

    def test_verify_without_a_lock_record_stops(self):
        os.remove(self.lock_path)
        self.assertEqual(self.run_action("verify"), 1)
        self.assertIn("Run build first", self.out)

    def test_verify_detects_an_edited_locked_source_file(self):
        append_text(os.path.join(self.tmp, "src", "baseline_prompt.py"), "\n# edit\n")
        self.assertEqual(self.run_action("verify"), 1)
        self.assertIn("FAIL  locked source file src/baseline_prompt.py", self.out)
        self.assertIn("SOMETHING CHANGED", self.out)

    def test_verify_ignores_line_ending_conversion_of_a_source_file(self):
        path = os.path.join(self.tmp, "src", "verdict_parser.py")
        with open(path, "rb") as f:
            data = f.read().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        with open(path, "wb") as f:
            f.write(data)
        self.assertEqual(self.run_action("verify"), 0, self.out)

    def test_verify_detects_an_edited_reference_run(self):
        append_text(os.path.join(self.runs_dir, V3, "raw_responses.jsonl"), "x\n")
        self.assertEqual(self.run_action("verify"), 1)
        self.assertIn("FAIL  reference run " + V3, self.out)

    def test_verify_detects_a_deleted_reference_run_file(self):
        os.remove(os.path.join(self.runs_dir, D6[1], "verdicts.csv"))
        self.assertEqual(self.run_action("verify"), 1)

    def test_verify_detects_a_new_frozen_access_log_line(self):
        append_text(self.log, "2026-10-09T00:00:00Z\tframe\td\tfour\n")
        self.assertEqual(self.run_action("verify"), 1)
        self.assertIn("FAIL  frozen access log unchanged", self.out)

    def test_verify_detects_an_edited_frozen_access_log_with_the_same_length(self):
        write_text(self.log, LOG_TEXT.replace("one", "ONE"))
        self.assertEqual(self.run_action("verify"), 1)

    def test_verify_detects_a_changed_week1_file(self):
        self.assertEqual(self.run_action("verify", snapshot=lambda: {"eval/MANIFEST.json": "x", "eval/dev_labels.parquet": "l1"}), 1)
        self.assertIn("FAIL  Week 1 files unchanged", self.out)

    def test_verify_detects_the_unlock_variable(self):
        with mock.patch.dict(os.environ, {config.FROZEN_UNLOCK_ENV: "x"}):
            self.assertEqual(self.run_action("verify"), 1)

    def test_verify_detects_a_changed_registered_prompt_hash(self):
        lock = json.loads(read_text(self.lock_path))
        lock["registry_sha256"]["baseline_v3"] = "0" * 64
        write_text(self.lock_path, json.dumps(lock))
        self.assertEqual(self.run_action("verify"), 1)

    def test_verify_rejects_a_lock_record_with_another_locked_hash(self):
        lock = json.loads(read_text(self.lock_path))
        lock["prompt_sha256"] = "0" * 64
        write_text(self.lock_path, json.dumps(lock))
        self.assertEqual(self.run_action("verify"), 1)
        self.assertIn("FAIL  baseline_v3 prompt hash equals the locked hash", self.out)


class HelperTests(unittest.TestCase):
    def test_normalized_sha256_ignores_crlf(self):
        d = tempfile.mkdtemp()
        try:
            a, b = os.path.join(d, "a.txt"), os.path.join(d, "b.txt")
            with open(a, "wb") as f:
                f.write(b"one\ntwo\n")
            with open(b, "wb") as f:
                f.write(b"one\r\ntwo\r\n")
            self.assertEqual(w7.normalized_sha256(a), w7.normalized_sha256(b))
            self.assertEqual(w7.normalized_sha256(a), hashlib.sha256(b"one\ntwo\n").hexdigest())
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_intervals_overlap(self):
        self.assertTrue(w7.intervals_overlap([0.1, 0.5], [0.4, 0.9]))
        self.assertFalse(w7.intervals_overlap([0.1, 0.3], [0.4, 0.9]))

    def test_diff_display_uses_percentage_points_and_handles_missing(self):
        self.assertEqual(w7.diff_display(0.5, 0.6, "precision_valid_only"), "+10.00 pp")
        self.assertEqual(w7.diff_display(None, 0.6, "precision_valid_only"), "n/a")

    def test_default_run_names_match_the_day_6_modules(self):
        self.assertEqual(w7.D6_RUNS, agg.DEFAULT_RUNS)
        self.assertEqual(w7.V1_RUN, rep.PROTECTED_RUNS[0])
        self.assertEqual(w7.V3_RUN, rep.PROTECTED_RUNS[1])

    def test_the_parser_has_no_model_or_frozen_options(self):
        text = w7.build_parser().format_help().lower()
        options = set(a.option_strings[0] for a in w7.build_parser()._actions if a.option_strings)
        self.assertEqual(options, {"-h", "--v2-run", "--v1-run", "--v3-run", "--d6-runs", "--runs-dir", "--eval-root", "--day6-dir", "--frozen-log", "--root", "--force"})
        for word in ["api key", "labels", "--model", "--limit"]:
            self.assertNotIn(word, text)

    def test_main_runs_build_and_verify_through_argv(self):
        t = ProjectCase("run_action")
        t.setUp()
        try:
            with mock.patch.object(w7.runner, "week1_snapshot", week1_now), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(w7.main(t.argv("build")), 0)
                self.assertEqual(w7.main(t.argv("verify")), 0)
        finally:
            t.tearDown()


# ------------------------------------------------------------------------------------------------ separation
class Day7SeparationTests(unittest.TestCase):
    ALLOWED_TOP_LEVEL = {"os", "sys", "json", "hashlib", "argparse", "datetime", "config", "prompt_registry", "baseline_store", "run_baseline_dev",
                         "day6_aggregate", "day6_replicates"}
    FORBIDDEN_IMPORTS = ["eval_io", "eval_labels", "eval_metrics", "evaluate", "triage_inputs", "llm_config", "gemini_client", "langsmith", "langchain",
                         "langgraph", "chromadb", "requests", "urllib", "socket", "http", "anthropic", "openai", "numpy", "scipy", "sklearn", "pandas",
                         "subprocess", "shutil", "google"]

    def names(self, module):
        return d3.SeparationTests.names_used(d3.SeparationTests(), module)

    def test_day7_never_touches_labels_answer_key_or_frozen_data(self):
        for name in DAY7_MODULES:
            used, modules = self.names(name)
            self.assertEqual(sorted(used & d3.SeparationTests.FORBIDDEN_NAMES), [], name)
            self.assertEqual(sorted(modules & set(self.FORBIDDEN_IMPORTS)), [], name)
            text = read_source(name)
            for forbidden in ["dev_labels.parquet", "mitre_map", "frozen_alerts", "frozen_labels", "flow_store_frozen", "labels.parquet", "eval/MANIFEST"]:
                self.assertNotIn(forbidden, text)
            self.assertNotIn(config.FROZEN_UNLOCK_VALUE, text)
            self.assertNotIn("AIza", text)

    def test_the_only_frozen_reference_is_the_access_log_and_the_unlock_check(self):
        text = read_source("week2_report.py")
        frozen = set(re.findall(r"config\.(\w*FROZEN\w*)", text))
        self.assertEqual(frozen, {"FROZEN_ACCESS_LOG", "FROZEN_UNLOCK_ENV"})

    def test_no_new_dependency_is_introduced(self):
        tree = ast.parse(read_source("week2_report.py"))
        tops = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                tops.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                tops.add((node.module or "").split(".")[0])
        self.assertTrue(tops <= self.ALLOWED_TOP_LEVEL, str(sorted(tops - self.ALLOWED_TOP_LEVEL)))

    def test_day7_makes_no_model_call_and_creates_no_git_tag(self):
        text = read_source("week2_report.py")
        for forbidden in ["generate_content", "make_client", "get_api_key", "git tag", "git commit", "git add", "os.system", "subprocess", "Popen"]:
            self.assertNotIn(forbidden, text)

    def test_day7_adds_no_week_3_code(self):
        low = read_source("week2_report.py").lower()
        for forbidden in ["langgraph", "chromadb", "retriev", "orchestrat", "supervisor", "week 3 design", "week3"]:
            self.assertNotIn(forbidden, low)

    def test_day7_writes_only_the_report_and_the_lock_record(self):
        text = read_source("week2_report.py")
        targets = re.findall(r"open\(([^,)]*), \"w\"", text)
        self.assertEqual(sorted(targets), ["lock_path", "report_path"])

    def test_the_locked_hash_and_prompt_text_are_unchanged(self):
        self.assertEqual(registry.get_prompt("baseline_v3").sha256, LOCKED_V3_SHA256)
        self.assertEqual(registry.get_prompt("baseline_v1").sha256, V1_SHA256)
        self.assertEqual(baseline_prompt.prompt_sha256(), V1_SHA256)

    def test_the_locked_source_files_exist(self):
        for rel in w7.LOCKED_SOURCE_FILES:
            self.assertTrue(os.path.exists(os.path.join(ROOT, rel)), rel)


# ------------------------------------------------------------------------------------------------ the real lock record
LOCK = os.path.join(ROOT, w7.LOCK_RELATIVE)


@unittest.skipUnless(os.path.exists(LOCK), "no reports/week2_baseline_lock.json yet (it is created by 'python src/week2_report.py build')")
class RealLockRecordTests(unittest.TestCase):
    """After Day 7 the lock record is part of the repository, so an edit to a locked file, a reference run or a Week 1 file fails the suite."""

    def lock(self):
        with open(LOCK, encoding="utf-8") as f:
            return json.load(f)

    def test_the_lock_record_names_baseline_v3_and_the_pinned_hash(self):
        lock = self.lock()
        self.assertEqual(lock["selected_baseline"], "baseline_v3")
        self.assertEqual(lock["prompt_sha256"], LOCKED_V3_SHA256)
        self.assertTrue(all(c["passed"] for c in lock["checks"]))

    def test_the_locked_prompt_and_source_files_still_match(self):
        lock = self.lock()
        self.assertEqual(registry.get_prompt("baseline_v3").sha256, lock["prompt_sha256"])
        for rel, digest in lock["locked_source_files_sha256"].items():
            self.assertEqual(w7.normalized_sha256(os.path.join(ROOT, rel)), digest, rel)

    def test_the_week1_files_and_frozen_access_log_still_match(self):
        lock = self.lock()
        self.assertEqual(w7.runner.week1_snapshot(), lock["week1_files_sha256"])
        self.assertEqual(w7.count_lines(config.FROZEN_ACCESS_LOG), lock["frozen_access_log"]["lines"])
        self.assertEqual(w7.normalized_sha256(config.FROZEN_ACCESS_LOG), lock["frozen_access_log"]["sha256_normalized"])

    def test_the_report_exists_and_carries_the_locked_hash(self):
        path = os.path.join(ROOT, w7.REPORT_NAME)
        self.assertTrue(os.path.exists(path))
        self.assertIn(LOCKED_V3_SHA256, read_text(path))

    def test_the_reference_runs_still_match_when_the_run_folders_are_present(self):
        if not os.path.isdir(w7.runner.RUNS_ROOT):
            self.skipTest("runs/ is not in this checkout")
        results = w7.verify_lock(self.lock(), ROOT, w7.runner.RUNS_ROOT, config.FROZEN_ACCESS_LOG)
        self.assertEqual([r for r in results if not r[1]], [])


if __name__ == "__main__":
    unittest.main()
